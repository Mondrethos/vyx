//! Explicit, cancellation-aware GitHub release downloads. No network at startup.
use std::{collections::BTreeSet, ffi::CString, fs::{File, OpenOptions}, future::Future,
    io::{self, Read, Write}, os::{fd::AsRawFd, unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt}},
    path::{Path, PathBuf}, time::Duration};

use anyhow::{Context, Result, bail, ensure};
use reqwest::{Client, StatusCode, Url};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::watch;

use super::{contract::parse_json, package::{Manifest, Package, MAX_PACKAGE_BYTES}, registry::{self, Snapshot}, runtime::WorkerExecutable};
use crate::update;

pub const OFFICIAL_REPOSITORY: &str = "Mondrethos/vyx";
const INDEX: &str = "vyx-extensions.json";
const MAX_INDEX: usize = 256 * 1024;
const MAX_METADATA: usize = 1024 * 1024;
const MAX_RUNTIME: usize = 128 * 1024 * 1024;
const RUNTIME_RECORD: &str = "runtime.json";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseSource { pub repository: String, pub tag: String, pub asset: String }

impl ReleaseSource {
    pub fn validate(&self) -> Result<()> {
        ensure!(parse_repository(&self.repository)? == self.repository, "release repository must use canonical owner/repo form");
        ensure!(safe_component(&self.tag, 128), "invalid GitHub release tag");
        ensure!(safe_component(&self.asset, 255), "invalid release asset basename");
        Ok(())
    }
    pub fn is_official(&self) -> bool { self.repository == OFFICIAL_REPOSITORY && self.validate().is_ok() }
    fn url(&self) -> Result<Url> {
        self.validate()?;
        Ok(Url::parse(&format!("https://github.com/{}/releases/download/{}/{}", self.repository, self.tag, self.asset))?)
    }
}

pub fn parse_repository(input: &str) -> Result<String> {
    let input = input.trim();
    let repository = if input.starts_with("https://") {
        let url = Url::parse(input).context("expected owner/repo or https://github.com/owner/repo")?;
        ensure!(url.host_str() == Some("github.com") && url.port_or_known_default() == Some(443)
            && url.username().is_empty() && url.password().is_none() && url.query().is_none() && url.fragment().is_none(),
            "repository must be an unauthenticated github.com HTTPS URL");
        url.path().trim_matches('/').to_owned()
    } else { input.to_owned() };
    let parts: Vec<_> = repository.split('/').collect();
    ensure!(parts.len() == 2 && parts.iter().all(|part| safe_component(part, 100)), "expected GitHub owner/repo, without paths or credentials");
    if repository.eq_ignore_ascii_case(OFFICIAL_REPOSITORY) { Ok(OFFICIAL_REPOSITORY.into()) } else { Ok(repository) }
}

fn safe_component(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum && value.as_bytes()[0].is_ascii_alphanumeric()
        && value.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

#[derive(Clone, Debug)]
pub struct CatalogEntry { pub manifest: Manifest, pub digest: String, pub source: ReleaseSource, pub bytes: u64 }
#[derive(Clone, Debug)]
pub struct RuntimeRelease { pub source: ReleaseSource, pub digest: String, pub bytes: u64, pub version: String, pub target: String }

#[derive(Deserialize)]
struct ApiRelease { tag_name: String, draft: bool, prerelease: bool, assets: Vec<ApiAsset> }
#[derive(Deserialize)]
struct ApiAsset { name: String, size: u64, browser_download_url: String }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Index { schema_version: u32, extensions: Vec<IndexEntry> }
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IndexEntry { manifest: Manifest, asset: String, sha256: String, size: u64 }

async fn cancellable<T>(mut cancel: watch::Receiver<bool>, work: impl Future<Output = Result<T>>) -> Result<T> {
    ensure!(!*cancel.borrow(), "download cancelled");
    tokio::select! {
        biased;
        _ = async { loop { if cancel.changed().await.is_err() || *cancel.borrow_and_update() { break; } } } => bail!("download cancelled"),
        result = tokio::time::timeout(Duration::from_secs(5 * 60), work) => result.context("GitHub download timed out; retry explicitly")?,
    }
}

async fn release(repository: &str, tag: Option<&str>) -> Result<ApiRelease> {
    let suffix = tag.map(|tag| format!("tags/{tag}")).unwrap_or_else(|| "latest".into());
    let url = format!("https://api.github.com/repos/{repository}/releases/{suffix}");
    let response = update::api_client()?.get(url).header("Accept", "application/vnd.github+json").send().await.context("contact GitHub releases")?;
    check_status(response.status(), "release metadata")?;
    let release: ApiRelease = parse_json(&update::read_bounded(response, MAX_METADATA, "GitHub release metadata").await?)?;
    ensure!(!release.draft && !release.prerelease, "select a published stable GitHub release");
    ensure!(safe_component(&release.tag_name, 128), "GitHub release has an unsupported tag");
    ensure!(tag.is_none_or(|tag| tag == release.tag_name), "GitHub returned a different release tag");
    Ok(release)
}

fn check_status(status: StatusCode, description: &str) -> Result<()> {
    match status {
        StatusCode::OK => Ok(()),
        StatusCode::FORBIDDEN | StatusCode::TOO_MANY_REQUESTS => bail!("GitHub refused {description} (HTTP {status}); unauthenticated API limits may apply; retry after the rate limit resets"),
        StatusCode::NOT_FOUND => bail!("GitHub {description} was not found; check the public repository, release tag and published assets"),
        _ => bail!("GitHub {description} failed: HTTP {status}"),
    }
}

fn asset_size(release: &ApiRelease, source: &ReleaseSource, maximum: usize) -> Result<u64> {
    source.validate()?;
    ensure!(source.tag == release.tag_name, "asset release tag mismatch");
    let mut matches = release.assets.iter().filter(|asset| asset.name == source.asset);
    let asset = matches.next().with_context(|| format!("release {} is missing {}; the publisher must upload it", source.tag, source.asset))?;
    ensure!(matches.next().is_none(), "duplicate GitHub release asset");
    ensure!(asset.size > 0 && asset.size <= maximum as u64, "release asset exceeds its size limit");
    ensure!(asset.browser_download_url == source.url()?.as_str(), "GitHub asset URL does not match its repository, tag and basename");
    Ok(asset.size)
}

async fn fetch(client: &Client, source: &ReleaseSource, size: u64, maximum: usize) -> Result<Vec<u8>> {
    ensure!(size > 0 && size <= maximum as u64, "release download exceeds size limit");
    let response = client.get(source.url()?).send().await.with_context(|| format!("download {}", source.asset))?;
    check_status(response.status(), &source.asset)?;
    ensure!(response.url().scheme() == "https" && update::approved_download_host(response.url()), "release download ended outside approved GitHub HTTPS hosts");
    ensure!(response.content_length().is_none_or(|actual| actual == size), "download length differs from reviewed GitHub metadata");
    let bytes = update::read_bounded(response, size as usize, &source.asset).await?;
    ensure!(bytes.len() as u64 == size, "download length differs from reviewed GitHub metadata");
    Ok(bytes)
}

fn catalog(repository: &str, release: &ApiRelease, bytes: &[u8]) -> Result<Vec<CatalogEntry>> {
    ensure!(bytes.len() <= MAX_INDEX, "extension index exceeds 256 KiB");
    let index: Index = parse_json(bytes)?;
    ensure!(index.schema_version == 1, "unsupported extension index schema");
    ensure!(index.extensions.len() <= 64, "extension index exceeds 64 entries");
    let mut ids = BTreeSet::new();
    let mut assets = BTreeSet::new();
    index.extensions.into_iter().map(|entry| {
        entry.manifest.validate()?;
        update::decode_sha256(&entry.sha256)?;
        ensure!(ids.insert(entry.manifest.id.clone()) && assets.insert(entry.asset.clone()), "duplicate extension ID or asset in release index");
        let source = ReleaseSource { repository: repository.into(), tag: release.tag_name.clone(), asset: entry.asset };
        ensure!(!entry.manifest.id.starts_with("com.vyx.") || source.is_official(), "reserved com.vyx.* identity in an unofficial repository");
        ensure!(asset_size(release, &source, MAX_PACKAGE_BYTES)? == entry.size, "extension index size disagrees with GitHub release metadata");
        Ok(CatalogEntry { manifest: entry.manifest, digest: entry.sha256, source, bytes: entry.size })
    }).collect()
}

pub async fn browse(repository: String, cancel: watch::Receiver<bool>) -> Result<Vec<CatalogEntry>> {
    cancellable(cancel, async move {
        let repository = parse_repository(&repository)?;
        let release = release(&repository, None).await?;
        let source = ReleaseSource { repository: repository.clone(), tag: release.tag_name.clone(), asset: INDEX.into() };
        let size = asset_size(&release, &source, MAX_INDEX)?;
        let bytes = fetch(&update::download_client()?, &source, size, MAX_INDEX).await?;
        catalog(&repository, &release, &bytes)
    }).await
}

fn downloaded(entry: CatalogEntry, bytes: Vec<u8>) -> Result<Snapshot> {
    ensure!(bytes.len() as u64 == entry.bytes, "package size differs from reviewed index");
    ensure!(format!("{:x}", Sha256::digest(&bytes)) == entry.digest, "package SHA-256 differs from reviewed index; discard this download");
    // Compare the exact advertised manifest before display sanitization.
    let parsed = Package::parse(&bytes)?;
    let manifest_len = u32::from_le_bytes(bytes[8..12].try_into()?) as usize;
    let original: Manifest = parse_json(&bytes[16..16 + manifest_len])?;
    ensure!(original == entry.manifest, "downloaded manifest differs from reviewed release index");
    drop(parsed);
    Snapshot::downloaded(bytes.into(), entry.source)
}

pub async fn download(entry: CatalogEntry, cancel: watch::Receiver<bool>) -> Result<Snapshot> {
    cancellable(cancel, async move {
        entry.source.validate()?;
        entry.manifest.validate()?;
        update::decode_sha256(&entry.digest)?;
        let release = release(&entry.source.repository, Some(&entry.source.tag)).await?;
        ensure!(asset_size(&release, &entry.source, MAX_PACKAGE_BYTES)? == entry.bytes, "GitHub package metadata changed; browse and review again");
        let bytes = fetch(&update::download_client()?, &entry.source, entry.bytes, MAX_PACKAGE_BYTES).await?;
        downloaded(entry, bytes)
    }).await
}

fn target() -> Result<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => Ok("x86_64-unknown-linux-musl"),
        ("linux", "aarch64") => Ok("aarch64-unknown-linux-musl"),
        ("macos", "x86_64") => Ok("x86_64-apple-darwin"),
        ("macos", "aarch64") => Ok("aarch64-apple-darwin"),
        (os, arch) => bail!("extension runtime is not published for {os}/{arch}"),
    }
}

fn validate_runtime(release: &RuntimeRelease) -> Result<[u8; 32]> {
    release.source.validate()?;
    ensure!(release.source.is_official() && release.version == env!("CARGO_PKG_VERSION")
        && release.source.tag == format!("v{}", env!("CARGO_PKG_VERSION")) && release.target == target()?
        && release.source.asset == format!("vyx-extension-worker-{}", target()?),
        "runtime must be the official release for this exact Vyx version and platform");
    ensure!(release.bytes > 0 && release.bytes <= MAX_RUNTIME as u64, "runtime exceeds 128 MiB");
    update::decode_sha256(&release.digest)
}

pub async fn runtime_release(cancel: watch::Receiver<bool>) -> Result<RuntimeRelease> {
    cancellable(cancel, async {
        let version = env!("CARGO_PKG_VERSION").to_owned();
        let target = target()?.to_owned();
        let tag = format!("v{version}");
        let release = release(OFFICIAL_REPOSITORY, Some(&tag)).await?;
        let source = ReleaseSource { repository: OFFICIAL_REPOSITORY.into(), tag, asset: format!("vyx-extension-worker-{target}") };
        let bytes = asset_size(&release, &source, MAX_RUNTIME)?;
        let sums = ReleaseSource { asset: "SHA256SUMS".into(), ..source.clone() };
        let size = asset_size(&release, &sums, 64 * 1024)?;
        let checksums = fetch(&update::download_client()?, &sums, size, 64 * 1024).await?;
        let digest = update::parse_checksums(&checksums, &source.asset)?;
        Ok(RuntimeRelease { source, digest: digest.iter().map(|byte| format!("{byte:02x}")).collect(), bytes, version, target })
    }).await
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RuntimeRecord { protocol_version: u32, source: ReleaseSource, digest: String, bytes: u64, version: String, target: String }
impl RuntimeRecord {
    fn release(&self) -> RuntimeRelease {
        RuntimeRelease { source: self.source.clone(), digest: self.digest.clone(), bytes: self.bytes, version: self.version.clone(), target: self.target.clone() }
    }
}

fn runtime_directory(data_dir: &Path, create: bool) -> Result<Option<File>> {
    let data = OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC).open(data_dir)?;
    let metadata = data.metadata()?;
    ensure!(metadata.uid() == registry::effective_uid() && metadata.mode() & 0o022 == 0, "runtime data directory is not private to this user");
    let mut directory = data;
    for component in ["extensions", "runtime"] {
        directory = if create { registry::private_directory(&directory, component)? } else {
            match registry::open_at(&directory, component, libc::O_RDONLY | libc::O_DIRECTORY, 0) {
                Ok(file) => {
                    let metadata = file.metadata()?;
                    ensure!(metadata.uid() == registry::effective_uid() && metadata.mode() & 0o7777 == 0o700, "runtime directory must have mode 0700 and be owned by this user");
                    file
                },
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(error) => return Err(error).context("open private runtime cache"),
            }
        };
    }
    Ok(Some(directory))
}

fn verify_worker(directory: &File, name: &str, size: u64, digest: [u8; 32]) -> Result<()> {
    let mut file = registry::open_at(directory, name, libc::O_RDONLY, 0)?;
    let before = file.metadata()?;
    ensure!(before.is_file() && before.uid() == registry::effective_uid() && before.mode() & 0o7777 == 0o700
        && before.nlink() == 1 && before.len() == size && size <= MAX_RUNTIME as u64, "runtime cache binary has unsafe metadata; explicitly reinstall the runtime");
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 { break; }
        total += read as u64;
        ensure!(total <= size, "runtime binary grew during verification");
        hasher.update(&buffer[..read]);
    }
    let after = file.metadata()?;
    ensure!(total == size && before.len() == after.len() && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec() && before.ctime() == after.ctime() && before.ctime_nsec() == after.ctime_nsec(), "runtime binary changed during verification");
    ensure!(<[u8; 32]>::from(hasher.finalize()) == digest, "runtime cache SHA-256 mismatch; explicitly reinstall the runtime");
    Ok(())
}

pub fn cached_runtime(data_dir: &Path) -> Result<Option<WorkerExecutable>> {
    let Some(directory) = runtime_directory(data_dir, false)? else { return Ok(None); };
    let file = match registry::open_at(&directory, RUNTIME_RECORD, libc::O_RDONLY, 0) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("open runtime cache metadata"),
    };
    let record: RuntimeRecord = parse_json(&registry::read_bounded(file, 4096, true)?)?;
    if record.version != env!("CARGO_PKG_VERSION") || record.target != target()? || record.protocol_version != 2 { return Ok(None); }
    let digest = validate_runtime(&record.release())?;
    let name = format!("worker-{}", record.digest);
    verify_worker(&directory, &name, record.bytes, digest)?;
    Ok(Some(WorkerExecutable { path: data_dir.canonicalize()?.join("extensions/runtime").join(name), sha256: digest }))
}

fn publish_runtime(data_dir: &Path, release: RuntimeRelease, bytes: Vec<u8>) -> Result<WorkerExecutable> {
    let digest = validate_runtime(&release)?;
    ensure!(bytes.len() as u64 == release.bytes && <[u8; 32]>::from(Sha256::digest(&bytes)) == digest, "downloaded runtime SHA-256 or size mismatch");
    let directory = runtime_directory(data_dir, true)?.context("runtime cache directory missing")?;
    let name = format!("worker-{}", release.digest);
    let binary = registry::Temporary::new(&directory)?;
    (&binary.file).write_all(&bytes)?;
    binary.file.set_permissions(std::fs::Permissions::from_mode(0o700))?;
    binary.file.sync_all()?;
    rename(&directory, &binary.name, &name)?;
    directory.sync_all().context("runtime binary published but directory durability is uncertain; retry installation")?;
    let record = RuntimeRecord { protocol_version: 2, source: release.source, digest: release.digest, bytes: release.bytes, version: release.version, target: release.target };
    let metadata = registry::Temporary::new(&directory)?;
    (&metadata.file).write_all(&serde_json::to_vec(&record)?)?;
    metadata.file.sync_all()?;
    rename(&directory, &metadata.name, RUNTIME_RECORD)?;
    directory.sync_all().context("runtime metadata published but durability is uncertain; retry installation")?;
    verify_worker(&directory, &name, record.bytes, digest)?;
    Ok(WorkerExecutable { path: data_dir.canonicalize()?.join("extensions/runtime").join(name), sha256: digest })
}

fn rename(directory: &File, from: &str, to: &str) -> Result<()> {
    let from = CString::new(from)?;
    let to = CString::new(to)?;
    // SAFETY: both names are validated single components and the directory owns its fd.
    ensure!(unsafe { libc::renameat(directory.as_raw_fd(), from.as_ptr(), directory.as_raw_fd(), to.as_ptr()) } == 0, "publish runtime cache: {}", io::Error::last_os_error());
    Ok(())
}

pub async fn install_runtime(data_dir: PathBuf, release: RuntimeRelease, cancel: watch::Receiver<bool>) -> Result<WorkerExecutable> {
    let bytes = cancellable(cancel.clone(), async {
        validate_runtime(&release)?;
        // Revalidate official checksums, not just a host-supplied descriptor.
        let current = runtime_release(cancel.clone()).await?;
        ensure!(current.source == release.source && current.digest == release.digest && current.bytes == release.bytes,
            "runtime release changed since review; review the official release again");
        fetch(&update::download_client()?, &release.source, release.bytes, MAX_RUNTIME).await
    }).await?;
    ensure!(!*cancel.borrow(), "runtime installation cancelled before publication");
    // Once publication starts, await its real outcome. Cancellation may leave a
    // verified cache, but never activates an extension or executes native bytes.
    tokio::task::spawn_blocking(move || publish_runtime(&data_dir, release, bytes)).await.context("runtime cache publisher failed")?
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::TcpListener};

    fn fixture_package() -> (Vec<u8>, CatalogEntry) {
        let manifest: Manifest = serde_json::from_value(json!({
            "schemaVersion":1,"apiVersion":1,"id":"org.example.demo","name":"Demo",
            "description":"Example","version":"1.0.0","permissions":["hosts.read"],
            "commands":[{"id":"open","title":"Open","description":"Open"}]
        })).unwrap();
        let encoded = serde_json::to_vec(&manifest).unwrap();
        let mut bytes = super::super::package::MAGIC.to_vec();
        bytes.extend((encoded.len() as u32).to_le_bytes());
        bytes.extend(8u32.to_le_bytes());
        bytes.extend(encoded);
        bytes.extend(b"\0asm\x01\0\0\0");
        let entry = CatalogEntry { manifest, digest: format!("{:x}", Sha256::digest(&bytes)),
            source: ReleaseSource { repository: "example/extensions".into(), tag: "v1.0.0".into(), asset: "demo.vyxext".into() },
            bytes: bytes.len() as u64 };
        (bytes, entry)
    }

    #[test]
    fn repository_and_asset_identity_cannot_choose_hosts_or_paths() {
        assert_eq!(parse_repository("https://github.com/mondrethos/Vyx").unwrap(), OFFICIAL_REPOSITORY);
        for invalid in ["https://user@github.com/a/b", "http://github.com/a/b", "https://github.com.evil/a/b",
            "https://github.com/a/b?token=x", "a/b/c", "../repo", "a/%2e%2e", "https://github.com:8443/a/b"] {
            assert!(parse_repository(invalid).is_err(), "{invalid}");
        }
        let (_, entry) = fixture_package();
        for invalid in ["../binary", "x/y", "x?secret", "x#fragment", "x\\y", "."] {
            let mut source = entry.source.clone();
            source.asset = invalid.into();
            assert!(source.validate().is_err(), "{invalid}");
        }
    }

    #[test]
    fn catalog_requires_same_release_sizes_unique_id_and_exact_download_manifest() {
        let (bytes, entry) = fixture_package();
        let api = ApiRelease { tag_name: entry.source.tag.clone(), draft: false, prerelease: false,
            assets: vec![ApiAsset { name: entry.source.asset.clone(), size: entry.bytes,
                browser_download_url: entry.source.url().unwrap().to_string() }] };
        let item = json!({"manifest":entry.manifest,"asset":entry.source.asset,"sha256":entry.digest,"size":entry.bytes});
        let index = json!({"schemaVersion":1,"extensions":[item.clone()]});
        assert_eq!(catalog(&entry.source.repository, &api, &serde_json::to_vec(&index).unwrap()).unwrap()[0].digest, entry.digest);
        let duplicated = json!({"schemaVersion":1,"extensions":[item.clone(),item]});
        assert!(catalog(&entry.source.repository, &api, &serde_json::to_vec(&duplicated).unwrap()).is_err());
        let snapshot = downloaded(entry.clone(), bytes.clone()).unwrap();
        assert_eq!(snapshot.source, Some(entry.source.clone()));
        let mut wrong = entry.clone();
        wrong.manifest.permissions.clear();
        assert!(downloaded(wrong, bytes.clone()).is_err());
        let mut wrong = entry.clone();
        wrong.digest = "0".repeat(64);
        assert!(downloaded(wrong, bytes.clone()).is_err());
        let mut wrong = entry.clone();
        wrong.bytes += 1;
        assert!(downloaded(wrong, bytes).is_err());
        let mut api = api;
        api.assets[0].browser_download_url = "https://evil.example/demo.vyxext".into();
        assert!(asset_size(&api, &entry.source, MAX_PACKAGE_BYTES).is_err());
        assert!(catalog(&entry.source.repository, &api, &vec![b' '; MAX_INDEX + 1]).is_err());
    }

    fn fixture_client() -> Client {
        let _ = rustls::crypto::ring::default_provider().install_default();
        update::download_client_builder().no_proxy().timeout(Duration::from_secs(5)).build().unwrap()
    }

    async fn http_fixture(response: &'static [u8]) -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/fixture", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 4096];
            socket.read(&mut request).await.unwrap();
            socket.write_all(response).await.unwrap();
        });
        (url, task)
    }

    #[tokio::test]
    async fn http_downloads_bound_announced_and_chunked_bodies_and_reject_redirects() {
        for response in [
            b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\noversized".as_slice(),
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n9\r\noversized\r\n0\r\n\r\n".as_slice(),
        ] {
            let (url, task) = http_fixture(response).await;
            let response = fixture_client().get(url).send().await.unwrap();
            assert!(update::read_bounded(response, 8, "fixture").await.is_err());
            task.await.unwrap();
        }
        let (url, task) = http_fixture(b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/forbidden\r\nContent-Length: 0\r\n\r\n").await;
        assert!(fixture_client().get(url).send().await.is_err());
        tokio::time::timeout(Duration::from_secs(5), task).await.unwrap().unwrap();
        assert!(!update::approved_download_host(&Url::parse("https://github.com.evil.example/x").unwrap()));
        assert!(!update::approved_download_host(&Url::parse("https://user@github.com/x").unwrap()));
    }

    #[tokio::test]
    async fn cancellation_drops_blocked_http_body_without_waiting_for_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/blocked", listener.local_addr().unwrap());
        let (started, ready) = tokio::sync::oneshot::channel();
        let fixture = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0; 4096];
            socket.read(&mut request).await.unwrap();
            socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n").await.unwrap();
            started.send(()).unwrap();
            let mut buffer = [0; 1];
            assert_eq!(socket.read(&mut buffer).await.unwrap(), 0);
        });
        let (sender, cancel) = watch::channel(false);
        let job = tokio::spawn(cancellable(cancel, async move {
            let response = fixture_client().get(url).send().await?;
            update::read_bounded(response, 100, "blocked fixture").await
        }));
        tokio::time::timeout(Duration::from_secs(5), ready).await.unwrap().unwrap();
        sender.send(true).unwrap();
        assert!(tokio::time::timeout(Duration::from_secs(2), job).await.unwrap().unwrap().is_err());
        tokio::time::timeout(Duration::from_secs(2), fixture).await.unwrap().unwrap();
    }

    fn runtime_fixture(bytes: &[u8]) -> RuntimeRelease {
        RuntimeRelease {
            source: ReleaseSource { repository: OFFICIAL_REPOSITORY.into(),
                tag: format!("v{}", env!("CARGO_PKG_VERSION")), asset: format!("vyx-extension-worker-{}", target().unwrap()) },
            digest: format!("{:x}", Sha256::digest(bytes)), bytes: bytes.len() as u64,
            version: env!("CARGO_PKG_VERSION").into(), target: target().unwrap().into(),
        }
    }

    #[test]
    fn runtime_cache_is_private_verified_offline_and_scoped_to_version() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(cached_runtime(directory.path()).unwrap().is_none());
        let bytes = b"fixture native bytes, never executed";
        let release = runtime_fixture(bytes);
        let worker = publish_runtime(directory.path(), release.clone(), bytes.to_vec()).unwrap();
        let cached = cached_runtime(directory.path()).unwrap().unwrap();
        assert_eq!(cached.path, worker.path);
        assert_eq!(cached.sha256, worker.sha256);
        assert!(publish_runtime(directory.path(), release.clone(), b"wrong bytes".to_vec()).is_err());
        std::fs::write(&worker.path, vec![b'x'; bytes.len()]).unwrap();
        assert!(cached_runtime(directory.path()).is_err());
        publish_runtime(directory.path(), release.clone(), bytes.to_vec()).unwrap();
        std::fs::set_permissions(&worker.path, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(cached_runtime(directory.path()).is_err());
        publish_runtime(directory.path(), release.clone(), bytes.to_vec()).unwrap();
        std::fs::remove_file(&worker.path).unwrap();
        std::os::unix::fs::symlink("/bin/sh", &worker.path).unwrap();
        assert!(cached_runtime(directory.path()).is_err());
        let mut invalid = release.clone();
        invalid.source.repository = "someone/vyx".into();
        assert!(validate_runtime(&invalid).is_err());
        let mut invalid = release.clone();
        invalid.version = "0.0.0".into();
        assert!(validate_runtime(&invalid).is_err());
        let record = RuntimeRecord { protocol_version: 2, source: release.source, digest: release.digest,
            bytes: release.bytes, version: "0.0.0".into(), target: release.target };
        std::fs::write(directory.path().join("extensions/runtime/runtime.json"), serde_json::to_vec(&record).unwrap()).unwrap();
        assert!(cached_runtime(directory.path()).unwrap().is_none());
    }
}
