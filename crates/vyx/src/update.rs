use std::{
    collections::HashSet,
    env,
    ffi::OsStr,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail, ensure};
use bytes::Bytes;
use futures_util::{Stream, StreamExt};
use reqwest::{Client, Response, StatusCode, Url, header};
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::{Builder as TempFileBuilder, NamedTempFile};
use tokio::{io::AsyncWriteExt, sync::watch, task::JoinHandle, time};

const API_URL: &str = "https://api.github.com/repos/Mondrethos/vyx/releases/latest";
const RELEASE_BASE: &str = "https://github.com/Mondrethos/vyx/releases/download";
const CHECKSUMS_NAME: &str = "SHA256SUMS";
const USER_AGENT: &str = concat!("vyx/", env!("CARGO_PKG_VERSION"));
const MAX_METADATA: usize = 64 * 1024;
const MAX_CHECKSUMS: usize = 64 * 1024;
const MAX_EXECUTABLE: u64 = 128 * 1024 * 1024;
const MAX_CACHE: usize = 4096;
const MAX_REDIRECTS: usize = 5;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const CHECK_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
const CACHE_FILE: &str = "update-check.json";
const CACHE_LOCK: &str = "update-check.lock";

/// Downloads and atomically installs the newest eligible release of this binary.
///
/// This command deliberately does not signal or restart an existing vyx worker. The
/// currently running process also continues executing its already-mapped image.
pub async fn install_latest() -> Result<()> {
    let current = current_version()?;
    let asset_name = platform_asset()?;
    let api_client = api_client()?;
    let Some(release) = discover_release(&api_client, asset_name).await? else {
        println!("vyx v{current} is up to date; no newer stable release was found.");
        return Ok(());
    };
    if release.version <= current {
        println!(
            "vyx v{current} is up to date (latest published stable release: {}).",
            release.tag
        );
        return Ok(());
    }

    // Resolve the native executable before creating a same-directory staging file.
    // There is intentionally no alternate install destination or privilege escalation.
    let reported_executable = env::current_exe().context("resolve the running vyx executable")?;
    let executable = fs::canonicalize(&reported_executable).with_context(|| {
        format!(
            "resolve native executable path {}",
            reported_executable.display()
        )
    })?;
    ensure!(
        fs::symlink_metadata(&executable)
            .with_context(|| format!("inspect executable {}", executable.display()))?
            .file_type()
            .is_file(),
        "refusing to replace a non-file executable path: {}",
        executable.display()
    );

    let download_client = download_client()?;
    let checksums = fetch_asset_bytes(
        &download_client,
        &release.checksums,
        MAX_CHECKSUMS,
        "release checksums",
    )
    .await?;
    let expected_digest = parse_checksums(&checksums, asset_name)?;
    let response =
        fetch_asset_response(&download_client, &release.executable, "release executable").await?;
    let stream = response
        .bytes_stream()
        .map(|chunk| chunk.context("read release executable"));
    let installed = install_stream(
        &executable,
        stream,
        release.executable.size,
        expected_digest,
    )
    .await?;

    match installed {
        InstallCommit::Durable => {
            println!("Updated vyx from v{current} to {}.", release.tag);
            println!(
                "Existing vyx workers keep their current code until you Quit and restart vyx."
            );
        }
        InstallCommit::DurabilityUncertain(error) => {
            eprintln!(
                "Updated vyx from v{current} to {}, but synchronizing the executable directory failed: {error:#}",
                release.tag
            );
            eprintln!(
                "The new executable is installed, but its crash durability is uncertain. Existing vyx workers keep their current code until you Quit and restart vyx."
            );
        }
    }
    Ok(())
}

/// A silent, passive release monitor. It never downloads or installs an executable.
pub struct UpdateMonitor {
    receiver: watch::Receiver<Option<String>>,
    task: Option<JoinHandle<()>>,
    available: Option<String>,
}

impl UpdateMonitor {
    pub fn new() -> Self {
        let (sender, receiver) = watch::channel(None);
        let disabled = env::var_os("VYX_NO_UPDATE_CHECK").as_deref() == Some(OsStr::new("1"));
        let task = if disabled {
            None
        } else {
            tokio::runtime::Handle::try_current()
                .ok()
                .map(|runtime| runtime.spawn(monitor_releases(sender)))
        };
        Self {
            receiver,
            task,
            available: None,
        }
    }

    /// Waits until the visible availability value actually changes.
    ///
    /// `watch::Receiver::changed` is cancellation safe. A disabled, shut down, or
    /// unexpectedly stopped monitor remains pending rather than creating a busy loop in
    /// the application's event select.
    pub async fn changed(&mut self) {
        loop {
            if self.receiver.changed().await.is_err() {
                std::future::pending::<()>().await;
            }
            let next = self.receiver.borrow_and_update().clone();
            if next != self.available {
                self.available = next;
                return;
            }
        }
    }

    pub fn available(&self) -> Option<&str> {
        self.available.as_deref()
    }

    pub async fn shutdown(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
            let _ = task.await;
        }
    }
}

impl Default for UpdateMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for UpdateMonitor {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

#[derive(Debug)]
struct Release {
    tag: String,
    version: Version,
    executable: ReleaseAsset,
    checksums: ReleaseAsset,
}

#[derive(Debug)]
struct ReleaseAsset {
    url: Url,
    size: u64,
}

#[derive(Deserialize)]
struct ApiRelease {
    tag_name: String,
    draft: bool,
    prerelease: bool,
    assets: Vec<ApiAsset>,
}

#[derive(Deserialize)]
struct ApiAsset {
    name: String,
    size: u64,
    browser_download_url: String,
}

fn current_version() -> Result<Version> {
    Version::parse(env!("CARGO_PKG_VERSION")).context("parse the installed vyx version")
}

fn platform_asset() -> Result<&'static str> {
    match (env::consts::OS, env::consts::ARCH) {
        ("linux", "x86_64") => Ok("vyx-x86_64-unknown-linux-musl"),
        ("linux", "aarch64") => Ok("vyx-aarch64-unknown-linux-musl"),
        ("macos", "x86_64") => Ok("vyx-x86_64-apple-darwin"),
        ("macos", "aarch64") => Ok("vyx-aarch64-apple-darwin"),
        (os, arch) => bail!("vyx updates are not published for {os}/{arch}"),
    }
}

fn api_client() -> Result<Client> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    Client::builder()
        .user_agent(USER_AGENT)
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .build()
        .context("initialize the GitHub release client")
}

fn download_client() -> Result<Client> {
    Client::builder()
        .user_agent(USER_AGENT)
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if attempt.previous().len() >= MAX_REDIRECTS {
                attempt.error("too many release download redirects")
            } else if attempt.url().scheme() != "https" {
                attempt.error("release download redirected away from HTTPS")
            } else if !approved_download_host(attempt.url()) {
                attempt.error("release download redirected outside GitHub")
            } else {
                attempt.follow()
            }
        }))
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(DOWNLOAD_TIMEOUT)
        .build()
        .context("initialize the GitHub download client")
}

fn approved_download_host(url: &Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    (host == "github.com" || host.ends_with(".githubusercontent.com"))
        && url.port_or_known_default() == Some(443)
        && url.username().is_empty()
        && url.password().is_none()
}
async fn discover_release(client: &Client, asset_name: &str) -> Result<Option<Release>> {
    let response = client
        .get(API_URL)
        .header(header::ACCEPT, "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .send()
        .await
        .context("query the latest vyx release")?;
    ensure!(
        response.status() == StatusCode::OK,
        "GitHub release discovery failed: HTTP {}",
        response.status()
    );
    let metadata = read_bounded(response, MAX_METADATA, "release metadata").await?;
    let release: ApiRelease =
        serde_json::from_slice(&metadata).context("parse GitHub release metadata")?;
    select_release(release, asset_name)
}
fn select_release(release: ApiRelease, asset_name: &str) -> Result<Option<Release>> {
    if release.draft || release.prerelease {
        return Ok(None);
    }
    let version = parse_release_tag(&release.tag_name)?;
    if !version.pre.is_empty() {
        return Ok(None);
    }
    ensure!(
        version.build.is_empty(),
        "GitHub returned a release tag with build metadata"
    );

    let executable = select_asset(
        &release.assets,
        &release.tag_name,
        asset_name,
        MAX_EXECUTABLE,
    )?;
    let checksums = select_asset(
        &release.assets,
        &release.tag_name,
        CHECKSUMS_NAME,
        MAX_CHECKSUMS as u64,
    )?;
    Ok(Some(Release {
        tag: release.tag_name,
        version,
        executable,
        checksums,
    }))
}

fn parse_release_tag(tag: &str) -> Result<Version> {
    ensure!(tag.len() <= 64, "GitHub returned an overlong release tag");
    let raw = tag
        .strip_prefix('v')
        .context("GitHub release tag must start with 'v'")?;
    let version = Version::parse(raw).context("GitHub release tag is not semantic versioning")?;
    ensure!(
        tag == format!("v{version}"),
        "GitHub release tag is not in canonical semantic-version form"
    );
    Ok(version)
}

fn newer_stable_tag(tag: &str, current: &Version) -> Result<Option<String>> {
    let version = parse_release_tag(tag)?;
    if !version.pre.is_empty() || !version.build.is_empty() || version <= *current {
        return Ok(None);
    }
    Ok(Some(tag.to_owned()))
}

fn select_asset(
    assets: &[ApiAsset],
    tag: &str,
    name: &str,
    maximum_size: u64,
) -> Result<ReleaseAsset> {
    let mut matches = assets.iter().filter(|asset| asset.name == name);
    let asset = matches
        .next()
        .with_context(|| format!("release {tag} is missing asset {name}"))?;
    ensure!(
        matches.next().is_none(),
        "release {tag} contains duplicate asset {name}"
    );
    ensure!(
        asset.size > 0 && asset.size <= maximum_size,
        "release asset {name} has an invalid size"
    );

    let expected = format!("{RELEASE_BASE}/{tag}/{name}");
    ensure!(
        asset.browser_download_url == expected,
        "release asset {name} has an unexpected download URL"
    );
    let url = Url::parse(&expected).context("construct the release asset URL")?;
    ensure!(
        url.scheme() == "https"
            && url.host_str() == Some("github.com")
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none(),
        "release asset URL is not an approved GitHub HTTPS URL"
    );
    Ok(ReleaseAsset {
        url,
        size: asset.size,
    })
}

async fn read_bounded(response: Response, limit: usize, description: &str) -> Result<Vec<u8>> {
    ensure!(
        response
            .content_length()
            .is_none_or(|size| size <= limit as u64),
        "{description} exceeds the {limit}-byte limit"
    );
    let mut bytes = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.with_context(|| format!("read {description}"))?;
        ensure!(
            bytes.len().saturating_add(chunk.len()) <= limit,
            "{description} exceeds the {limit}-byte limit"
        );
        bytes.extend_from_slice(&chunk);
    }
    ensure!(!bytes.is_empty(), "GitHub returned empty {description}");
    Ok(bytes)
}

async fn fetch_asset_bytes(
    client: &Client,
    asset: &ReleaseAsset,
    limit: usize,
    description: &str,
) -> Result<Vec<u8>> {
    let response = fetch_asset_response(client, asset, description).await?;
    let bytes = read_bounded(response, limit, description).await?;
    ensure!(
        bytes.len() as u64 == asset.size,
        "{description} size does not match GitHub release metadata"
    );
    Ok(bytes)
}

async fn fetch_asset_response(
    client: &Client,
    asset: &ReleaseAsset,
    description: &str,
) -> Result<Response> {
    let response = client
        .get(asset.url.clone())
        .timeout(DOWNLOAD_TIMEOUT)
        .send()
        .await
        .with_context(|| format!("download {description}"))?;
    ensure!(
        response.status() == StatusCode::OK,
        "GitHub {description} download failed: HTTP {}",
        response.status()
    );
    ensure!(
        response.url().scheme() == "https" && approved_download_host(response.url()),
        "GitHub {description} download ended at an unapproved URL"
    );
    ensure!(
        response
            .content_length()
            .is_none_or(|size| size == asset.size),
        "{description} size does not match GitHub release metadata"
    );
    Ok(response)
}

fn parse_checksums(bytes: &[u8], selected_asset: &str) -> Result<[u8; 32]> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_CHECKSUMS,
        "invalid SHA256SUMS size"
    );
    let text = std::str::from_utf8(bytes).context("SHA256SUMS is not UTF-8")?;
    let mut lines = text.split('\n').peekable();
    let mut seen = HashSet::new();
    let mut selected = None;

    while let Some(raw_line) = lines.next() {
        if raw_line.is_empty() && lines.peek().is_none() {
            break;
        }
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        ensure!(!line.is_empty(), "SHA256SUMS contains an empty line");
        ensure!(line.len() >= 67, "SHA256SUMS contains a malformed line");
        ensure!(
            line.as_bytes()[..64].is_ascii(),
            "SHA256SUMS contains a malformed digest"
        );
        let (digest, remainder) = line.split_at(64);
        let name = remainder
            .strip_prefix("  ")
            .context("SHA256SUMS must use two spaces before each filename")?;
        ensure!(
            valid_asset_basename(name),
            "SHA256SUMS contains an invalid filename"
        );
        ensure!(
            seen.insert(name.to_owned()),
            "SHA256SUMS contains duplicate entry for {name}"
        );
        let digest = decode_sha256(digest)?;
        if name == selected_asset {
            selected = Some(digest);
        }
    }

    selected.with_context(|| format!("SHA256SUMS is missing {selected_asset}"))
}

fn valid_asset_basename(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'/' && byte != b'\\' && byte != b':')
}

fn decode_sha256(value: &str) -> Result<[u8; 32]> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "SHA256SUMS contains a non-lowercase SHA-256 digest"
    );
    let mut digest = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        digest[index] = (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]);
    }
    Ok(digest)
}

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => unreachable!("digest characters were validated"),
    }
}

#[derive(Debug)]
enum InstallCommit {
    Durable,
    DurabilityUncertain(anyhow::Error),
}

async fn install_stream<S>(
    target: &Path,
    stream: S,
    expected_size: u64,
    expected_digest: [u8; 32],
) -> Result<InstallCommit>
where
    S: Stream<Item = Result<Bytes>>,
{
    ensure!(
        expected_size > 0 && expected_size <= MAX_EXECUTABLE,
        "release executable has an invalid size"
    );
    let directory = target
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .context("the running executable has no parent directory")?;
    let staged = stage_stream(directory, stream, expected_size, expected_digest).await?;
    replace_staged(staged, target)?;

    match sync_directory(directory).await {
        Ok(()) => Ok(InstallCommit::Durable),
        Err(error) => Ok(InstallCommit::DurabilityUncertain(error)),
    }
}

async fn stage_stream<S>(
    directory: &Path,
    stream: S,
    expected_size: u64,
    expected_digest: [u8; 32],
) -> Result<NamedTempFile>
where
    S: Stream<Item = Result<Bytes>>,
{
    let staged = TempFileBuilder::new()
        .prefix(".vyx-update-")
        .tempfile_in(directory)
        .with_context(|| format!("create update staging file in {}", directory.display()))?;
    staged
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))
        .context("secure update staging file")?;
    let output = staged
        .as_file()
        .try_clone()
        .context("open update staging file for writing")?;
    let mut output = tokio::fs::File::from_std(output);
    let mut hasher = Sha256::new();
    let mut received = 0_u64;
    futures_util::pin_mut!(stream);

    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        received = received
            .checked_add(chunk.len() as u64)
            .context("release executable size overflow")?;
        ensure!(
            received <= expected_size && received <= MAX_EXECUTABLE,
            "release executable exceeds its declared size"
        );
        output
            .write_all(&chunk)
            .await
            .context("write update staging file")?;
        hasher.update(&chunk);
    }
    ensure!(
        received == expected_size,
        "release executable size does not match GitHub release metadata"
    );
    let actual_digest: [u8; 32] = hasher.finalize().into();
    ensure!(
        actual_digest == expected_digest,
        "release executable SHA-256 does not match SHA256SUMS"
    );

    output.flush().await.context("flush update staging file")?;
    staged
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o755))
        .context("make staged update executable")?;
    output
        .sync_all()
        .await
        .context("synchronize staged update executable")?;
    drop(output);
    Ok(staged)
}

fn replace_staged(staged: NamedTempFile, target: &Path) -> Result<()> {
    match staged.persist(target) {
        Ok(file) => {
            drop(file);
            Ok(())
        }
        Err(error) => {
            let source = error.error;
            drop(error.file);
            Err(source).with_context(|| format!("replace executable {}", target.display()))
        }
    }
}

async fn sync_directory(directory: &Path) -> Result<()> {
    let directory_file =
        File::open(directory).with_context(|| format!("open directory {}", directory.display()))?;
    tokio::fs::File::from_std(directory_file)
        .sync_all()
        .await
        .with_context(|| format!("synchronize directory {}", directory.display()))
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CheckCache {
    checked_at: u64,
    latest: Option<String>,
}

struct CacheLease {
    _lock: File,
    directory: PathBuf,
    path: PathBuf,
    state: CheckCache,
}

enum CacheAccess {
    Locked(CacheLease),
    Busy(CheckCache),
}

async fn monitor_releases(sender: watch::Sender<Option<String>>) {
    let Ok(current) = current_version() else {
        return;
    };
    let Ok(asset_name) = platform_asset() else {
        return;
    };
    let Ok(client) = api_client() else {
        return;
    };
    let mut published = None;

    loop {
        let access = match tokio::task::spawn_blocking(open_cache).await {
            Ok(Ok(access)) => access,
            _ => return,
        };
        match access {
            CacheAccess::Busy(cache) => {
                if !publish_available(&sender, &mut published, cache.latest.as_deref(), &current) {
                    return;
                }
                time::sleep(CHECK_INTERVAL).await;
            }
            CacheAccess::Locked(mut lease) => {
                if !publish_available(
                    &sender,
                    &mut published,
                    lease.state.latest.as_deref(),
                    &current,
                ) {
                    return;
                }
                let now = unix_time();
                let wait = time_until_check(lease.state.checked_at, now);
                if !wait.is_zero() {
                    drop(lease);
                    time::sleep(wait).await;
                    continue;
                }
                let discovered = discover_release(&client, asset_name).await;
                lease.state.checked_at = unix_time();
                match discovered {
                    Ok(Some(release)) => lease.state.latest = Some(release.tag),
                    Ok(None) => lease.state.latest = None,
                    Err(_) => {}
                }
                if !publish_available(
                    &sender,
                    &mut published,
                    lease.state.latest.as_deref(),
                    &current,
                ) {
                    return;
                }
                let _ = tokio::task::spawn_blocking(move || write_cache(lease)).await;
                time::sleep(CHECK_INTERVAL).await;
            }
        }
    }
}

fn publish_available(
    sender: &watch::Sender<Option<String>>,
    published: &mut Option<String>,
    candidate: Option<&str>,
    current: &Version,
) -> bool {
    let next = candidate
        .and_then(|tag| newer_stable_tag(tag, current).ok())
        .flatten();
    if *published == next {
        return true;
    }
    *published = next.clone();
    sender.send(next).is_ok()
}

fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn time_until_check(checked_at: u64, now: u64) -> Duration {
    if checked_at > now.saturating_add(CHECK_INTERVAL.as_secs()) {
        return Duration::ZERO;
    }
    CHECK_INTERVAL.saturating_sub(Duration::from_secs(now.saturating_sub(checked_at)))
}

fn open_cache() -> Result<CacheAccess> {
    let base = directories::BaseDirs::new().context("resolve the platform cache directory")?;
    let directory = base.cache_dir().join("vyx");
    fs::create_dir_all(&directory)
        .with_context(|| format!("create update cache directory {}", directory.display()))?;
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("secure update cache directory {}", directory.display()))?;
    let path = directory.join(CACHE_FILE);
    let lock_path = directory.join(CACHE_LOCK);
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .open(&lock_path)
        .with_context(|| format!("open update cache lock {}", lock_path.display()))?;
    lock.set_permissions(fs::Permissions::from_mode(0o600))
        .context("secure update cache lock")?;

    match lock.try_lock().map_err(io::Error::from) {
        Ok(()) => Ok(CacheAccess::Locked(CacheLease {
            _lock: lock,
            directory,
            state: read_cache(&path).unwrap_or_default(),
            path,
        })),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
            Ok(CacheAccess::Busy(read_cache(&path).unwrap_or_default()))
        }
        Err(error) => Err(error).context("lock update cache"),
    }
}

fn read_cache(path: &Path) -> Result<CheckCache> {
    let file = File::open(path).with_context(|| format!("open update cache {}", path.display()))?;
    let mut bytes = Vec::new();
    file.take((MAX_CACHE + 1) as u64)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read update cache {}", path.display()))?;
    ensure!(bytes.len() <= MAX_CACHE, "update cache is too large");
    serde_json::from_slice(&bytes).context("parse update cache")
}

fn write_cache(lease: CacheLease) -> Result<()> {
    let bytes = serde_json::to_vec(&lease.state).context("serialize update cache")?;
    ensure!(
        bytes.len() <= MAX_CACHE,
        "serialized update cache is too large"
    );
    let mut staged = TempFileBuilder::new()
        .prefix(".update-check-")
        .tempfile_in(&lease.directory)
        .with_context(|| {
            format!(
                "create staged update cache in {}",
                lease.directory.display()
            )
        })?;
    staged
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))
        .context("secure staged update cache")?;
    staged
        .write_all(&bytes)
        .context("write staged update cache")?;
    staged
        .as_file()
        .sync_all()
        .context("synchronize staged update cache")?;
    match staged.persist(&lease.path) {
        Ok(file) => drop(file),
        Err(error) => {
            let source = error.error;
            drop(error.file);
            return Err(source).context("replace update cache");
        }
    }
    File::open(&lease.directory)
        .with_context(|| format!("open update cache directory {}", lease.directory.display()))?
        .sync_all()
        .context("synchronize update cache directory")
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::stream;

    #[test]
    fn semantic_precedence_only_offers_newer_stable_versions() {
        let current = Version::parse("1.9.0").unwrap();
        assert_eq!(
            newer_stable_tag("v1.10.0", &current).unwrap().as_deref(),
            Some("v1.10.0")
        );
        assert_eq!(newer_stable_tag("v1.9.0", &current).unwrap(), None);
        assert_eq!(newer_stable_tag("v1.8.99", &current).unwrap(), None);
        assert_eq!(newer_stable_tag("v2.0.0-rc.1", &current).unwrap(), None);
        assert!(newer_stable_tag("1.10.0", &current).is_err());
        assert!(newer_stable_tag("v1.10.0+local", &current).is_ok_and(|v| v.is_none()));
    }

    #[test]
    fn checksum_selection_rejects_missing_malformed_and_duplicate_entries() {
        let name = "vyx-x86_64-unknown-linux-musl";
        let digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let valid = format!("{digest}  vyx-aarch64-apple-darwin\n{digest}  {name}\n");
        assert_eq!(
            parse_checksums(valid.as_bytes(), name).unwrap(),
            decode_sha256(digest).unwrap()
        );

        let malformed = [
            format!("{}  {name}\n", digest.to_ascii_uppercase()),
            format!("{digest} {name}\n"),
            format!("x{}  {name}\n", &digest[1..]),
            format!("{}  {name}\n", "é".repeat(32)),
            format!("{digest}  releases/{name}\n"),
            format!("{digest}  another-asset\n"),
            format!("{digest}  {name}\n{digest}  {name}\n"),
        ];
        for value in malformed {
            assert!(parse_checksums(value.as_bytes(), name).is_err(), "{value}");
        }
    }

    #[tokio::test]
    async fn checksum_mismatch_retains_the_old_executable() {
        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("vyx");
        fs::write(&executable, b"old executable").unwrap();
        let replacement = Bytes::from_static(b"new executable");
        let stream = stream::iter([Ok(replacement.clone())]);
        let wrong_digest = [0_u8; 32];

        install_stream(&executable, stream, replacement.len() as u64, wrong_digest)
            .await
            .unwrap_err();
        assert_eq!(fs::read(&executable).unwrap(), b"old executable");
    }
}
