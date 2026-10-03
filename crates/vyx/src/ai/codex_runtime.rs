//! The optional trusted, tool-free Codex distribution. Never discovers a user's Codex CLI/home.
//! Linux namespaces hide ambient files; shared networking is not an egress sandbox.
use std::{
    ffi::CString,
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    time::Duration,
};
#[cfg(target_os = "linux")]
use std::{
    io::{Seek, SeekFrom},
    process::Stdio,
};

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::{
    io::BufReader,
    process::{Child, ChildStdin, ChildStdout},
};
#[cfg(target_os = "linux")]
use tokio::{io::AsyncReadExt, process::Command};
use zeroize::Zeroizing;

use super::model::Profile;
use crate::{update, vault::Secret};

const REVISION: &str = "36650394c5b38c2990ccf2a3457165ca3e9d9726";
const REPOSITORY: &str = "Mondrethos/vyx";
const MAX_HELPER: usize = 512 * 1024 * 1024;
const MAX_AUTH: usize = 64 * 1024;
const RECORD: &str = "runtime.json";
const ATTRIBUTIONS: [(&str, &str); 2] = [
    (
        "LICENSE",
        "d17f227e4df5da1600391338865ce0f3055211760a36688f816941d58232d8dc",
    ),
    (
        "NOTICE",
        "9d71575ecfd9a843fc1677b0efb08053c6ba9fd686a0de1a6f5382fd3c220915",
    ),
];

#[derive(Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Capabilities {
    protocol_version: u32,
    helper: String,
    source_revision: String,
    tool_policy: String,
    configuration: String,
}
impl Capabilities {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.protocol_version == 1
                && self.helper == "vyx-codex"
                && self.source_revision == REVISION
                && self.tool_policy == "deny-all"
                && self.configuration == "vyx-fixed-v1",
            "not the pinned tool-free Vyx Codex helper; stock Codex is not supported"
        );
        Ok(())
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Record {
    protocol_version: u32,
    helper: String,
    source_revision: String,
    tool_policy: String,
    configuration: String,
    vyx_version: String,
    target: String,
    sha256: String,
    bytes: u64,
    origin: String,
}
impl Record {
    fn validate(&self) -> Result<[u8; 32]> {
        ensure!(
            self.protocol_version == 1
                && self.helper == "vyx-codex"
                && self.source_revision == REVISION
                && self.tool_policy == "deny-all"
                && self.configuration == "vyx-fixed-v1"
                && self.vyx_version == env!("CARGO_PKG_VERSION")
                && self.target == target()?
                && matches!(self.origin.as_str(), "release" | "source-build"),
            "Codex helper metadata is not for this Vyx version, platform and isolation boundary; explicitly reinstall the helper"
        );
        ensure!(
            self.bytes > 0 && self.bytes <= MAX_HELPER as u64,
            "Codex helper exceeds its size limit"
        );
        update::decode_sha256(&self.sha256)
    }
}

pub(super) struct Session {
    pub input: ChildStdin,
    /// The protocol client must use bounded JSONL reads, never `lines()`/`read_line()`.
    pub output: BufReader<ChildStdout>,
    child: Option<Child>,
    scratch: Option<TempDir>,
}
impl Session {
    /// Reads only the Vyx-owned volatile auth file; never searches an ambient account.
    pub fn credentials(&self) -> Result<Option<Secret>> {
        read_credentials(
            self.scratch
                .as_ref()
                .context("Codex session is already closed")?
                .path(),
        )
    }

    /// A callback for the protocol reader while it exclusively borrows our pipes.
    /// It owns no credentials and does not extend the volatile directory's lifetime.
    pub fn credential_reader(
        &self,
    ) -> impl Fn() -> Result<Option<Secret>> + Send + Sync + 'static + use<> {
        let path = self
            .scratch
            .as_ref()
            .map(|scratch| scratch.path().to_owned());
        move || read_credentials(path.as_deref().context("Codex session is already closed")?)
    }

    pub async fn shutdown(&mut self) -> Result<()> {
        if let Some(child) = &mut self.child {
            kill_tree(child);
            tokio::time::timeout(Duration::from_secs(5), child.wait())
                .await
                .context(
                    "Codex helper did not terminate; background reaper retains cleanup ownership",
                )?
                .context("reap Codex helper")?;
            self.child = None;
        }
        // Credentials must have been exported before shutdown; only encrypted native state persists.
        self.scratch.take();
        Ok(())
    }
}
fn read_credentials(scratch: &Path) -> Result<Option<Secret>> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(scratch.join("auth.json"))
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("open Vyx-owned Codex credentials"),
    };
    check_file(&file, 0o600, MAX_AUTH as u64)?;
    let mut text = Zeroizing::new(String::new());
    file.take(MAX_AUTH as u64 + 1)
        .read_to_string(&mut text)
        .context("read Vyx-owned Codex credentials")?;
    ensure!(
        text.len() <= MAX_AUTH,
        "Codex credentials exceed their size limit"
    );
    serde_json::from_str::<serde::de::IgnoredAny>(&text)
        .context("Codex returned invalid credential storage")?;
    Ok(Some(Secret::new(std::mem::take(&mut *text))))
}
impl Drop for Session {
    fn drop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        kill_tree(&mut child);
        let scratch = self.scratch.take();
        // Reaping must also work when the Tokio task/runtime itself is cancelled. Do not
        // block its UI thread on waitpid; keep scratch alive until the killed tree exits.
        let _ = std::thread::Builder::new()
            .name("vyx-codex-reaper".into())
            .spawn(move || {
                if let Some(pid) = child.id() {
                    let mut status = 0;
                    loop {
                        // SAFETY: this is our own terminated child. Tokio may already have reaped it.
                        let result = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, 0) };
                        if result >= 0
                            || io::Error::last_os_error().kind() != io::ErrorKind::Interrupted
                        {
                            break;
                        }
                    }
                }
                drop(child);
                drop(scratch);
            });
    }
}
fn kill_tree(child: &mut Child) {
    if let Some(pid) = child.id() {
        // The wrapper has its own process group. Killing it also kills namespace PID 1
        // through --die-with-parent, which tears down all descendants in that namespace.
        // SAFETY: the unreaped Child owns this PID; negative PID selects its process group.
        unsafe {
            libc::kill(-(pid as libc::pid_t), libc::SIGKILL);
        }
    }
    let _ = child.start_kill();
}

fn target() -> Result<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => Ok("x86_64-unknown-linux-musl"),
        ("linux", "aarch64") => Ok("aarch64-unknown-linux-musl"),
        _ => bail!(
            "the isolated Vyx Codex helper currently requires Linux x86_64/aarch64 and bubblewrap; no unsandboxed fallback is available"
        ),
    }
}
fn uid() -> u32 {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() }
}
fn open_at(directory: &File, name: &str, flags: i32, mode: libc::mode_t) -> io::Result<File> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid helper cache component",
        ));
    }
    let name = CString::new(name)?;
    // SAFETY: live directory fd and NUL-terminated single component; return fd is owned.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            // Variadic arguments are promoted to unsigned int; mode_t is narrower on macOS.
            mode as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn check_file(file: &File, mode: u32, maximum: u64) -> Result<()> {
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.uid() == uid()
            && metadata.mode() & 0o7777 == mode
            && metadata.nlink() == 1
            && metadata.len() <= maximum,
        "Vyx Codex storage has unsafe ownership, permissions, type, links or size"
    );
    Ok(())
}
fn private_directory(parent: &File, name: &str, create: bool) -> Result<File> {
    if create {
        let component = CString::new(name)?;
        // SAFETY: fixed single-component name and live directory descriptor.
        let result = unsafe { libc::mkdirat(parent.as_raw_fd(), component.as_ptr(), 0o700) };
        if result != 0 && io::Error::last_os_error().kind() != io::ErrorKind::AlreadyExists {
            return Err(io::Error::last_os_error()).context("create private Codex runtime cache");
        }
    }
    let directory = open_at(parent, name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
    let metadata = directory.metadata()?;
    ensure!(
        metadata.is_dir() && metadata.uid() == uid() && metadata.mode() & 0o7777 == 0o700,
        "Vyx Codex cache directories must be owned by this user with mode 0700"
    );
    Ok(directory)
}
fn directory(data_dir: &Path, create: bool) -> Result<File> {
    let mut directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(data_dir)
        .context("open Vyx data directory")?;
    let metadata = directory.metadata()?;
    ensure!(
        metadata.uid() == uid() && metadata.mode() & 0o022 == 0,
        "Vyx data directory is writable by another user"
    );
    for component in ["ai", "runtime", "codex"] {
        directory = private_directory(&directory, component, create)?;
    }
    Ok(directory)
}
fn read_record(file: File) -> Result<Record> {
    check_file(&file, 0o600, 4096)?;
    let mut bytes = Vec::new();
    file.take(4097).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 4096,
        "Codex runtime metadata exceeds its size limit"
    );
    let record: Record =
        serde_json::from_slice(&bytes).context("read Vyx Codex helper metadata")?;
    record.validate()?;
    Ok(record)
}
fn resolve(profile: &Profile, data_dir: &Path) -> Result<(File, Record)> {
    target()?;
    if let Some(path) = profile.codex_path.as_ref() {
        let path = Path::new(path);
        ensure!(path.is_absolute(), "select an absolute Vyx helper path");
        let parent = path.parent().context("helper has no parent directory")?;
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(parent)?;
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .context("helper filename must be UTF-8")?;
        let record = read_record(open_at(&directory, &format!("{name}.json"), libc::O_RDONLY, 0)
            .context("selected helper needs the matching Vyx build metadata sidecar; stock Codex is not accepted")?)?;
        return Ok((open_at(&directory, name, libc::O_RDONLY, 0)?, record));
    }
    let directory = directory(data_dir, false).context("Codex helper missing. Choose Install isolated Codex helper (review) in Vyx AI settings. Chat never downloads it.")?;
    let record = read_record(open_at(&directory, RECORD, libc::O_RDONLY, 0).context(
        "Codex helper missing. Choose Install isolated Codex helper (review) in Vyx AI settings.",
    )?)?;
    let file = open_at(
        &directory,
        &format!("helper-{}", record.sha256),
        libc::O_RDONLY,
        0,
    )?;
    Ok((file, record))
}

/// Installed-metadata presence only: the record and helper file resolve. Launch still performs
/// every digest, revision, and configuration check.
pub(super) fn installed(profile: &Profile, data_dir: &Path) -> bool {
    resolve(profile, data_dir).is_ok()
}

#[cfg(target_os = "linux")]
fn memfd(name: &str) -> Result<File> {
    let name = CString::new(name)?;
    // SAFETY: a valid NUL-terminated name; successful fd ownership transfers to File.
    let fd =
        unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING) };
    if fd < 0 {
        return Err(io::Error::last_os_error()).context("create private helper snapshot");
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}
#[cfg(target_os = "linux")]
fn seal(file: &mut File, mode: u32) -> Result<()> {
    file.set_permissions(std::fs::Permissions::from_mode(mode))?;
    file.seek(SeekFrom::Start(0))?;
    // SAFETY: the file is our sealing-enabled memfd and no writable mappings exist.
    ensure!(
        unsafe {
            libc::fcntl(
                file.as_raw_fd(),
                libc::F_ADD_SEALS,
                libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL,
            )
        } == 0,
        "seal helper snapshot: {}",
        io::Error::last_os_error()
    );
    Ok(())
}
#[cfg(target_os = "linux")]
fn snapshot(mut source: File, record: &Record) -> Result<File> {
    let expected = record.validate()?;
    check_file(&source, 0o700, MAX_HELPER as u64)?;
    let before = source.metadata()?;
    ensure!(
        before.len() == record.bytes,
        "Codex helper size mismatch; explicitly reinstall it"
    );
    let mut snapshot = memfd("vyx-codex-helper")?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut count = 0;
    loop {
        let read = source.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        count += read as u64;
        ensure!(
            count <= record.bytes,
            "Codex helper changed during verification"
        );
        hasher.update(&buffer[..read]);
        snapshot.write_all(&buffer[..read])?;
    }
    let after = source.metadata()?;
    ensure!(
        count == record.bytes
            && before.len() == after.len()
            && before.mtime() == after.mtime()
            && before.mtime_nsec() == after.mtime_nsec()
            && before.ctime() == after.ctime()
            && before.ctime_nsec() == after.ctime_nsec()
            && <[u8; 32]>::from(hasher.finalize()) == expected,
        "Codex helper SHA-256 or stable-file verification failed; explicitly reinstall it"
    );
    seal(&mut snapshot, 0o500)?;
    static_elf(&mut snapshot)?;
    Ok(snapshot)
}
#[cfg(target_os = "linux")]
fn static_elf(file: &mut File) -> Result<()> {
    let mut header = [0u8; 64];
    file.read_exact(&mut header)?;
    ensure!(
        &header[..4] == b"\x7fELF" && header[4] == 2 && header[5] == 1,
        "Vyx helper must be a little-endian 64-bit ELF executable"
    );
    let machine = u16::from_le_bytes([header[18], header[19]]);
    ensure!(
        machine
            == if cfg!(target_arch = "x86_64") {
                62
            } else {
                183
            },
        "Codex helper architecture mismatch"
    );
    let offset = u64::from_le_bytes(header[32..40].try_into()?);
    let size = u16::from_le_bytes(header[54..56].try_into()?) as u64;
    let count = u16::from_le_bytes(header[56..58].try_into()?) as u64;
    ensure!(
        size == 56
            && count > 0
            && count <= 128
            && offset
                .checked_add(size * count)
                .is_some_and(|end| end <= file.metadata().map(|m| m.len()).unwrap_or(0)),
        "invalid ELF program header table"
    );
    for index in 0..count {
        file.seek(SeekFrom::Start(offset + index * size))?;
        let mut program = [0u8; 56];
        file.read_exact(&mut program)?;
        let kind = u32::from_le_bytes(program[..4].try_into()?);
        // Static PIE can have PT_DYNAMIC; dependency entries are still forbidden.
        ensure!(
            kind != 3,
            "Codex helper requires a dynamic loader; only static builds are supported"
        );
        if kind == 2 {
            let offset = u64::from_le_bytes(program[8..16].try_into()?);
            let bytes = u64::from_le_bytes(program[32..40].try_into()?);
            ensure!(
                bytes <= 1024 * 1024 && bytes % 16 == 0,
                "invalid ELF dynamic table"
            );
            file.seek(SeekFrom::Start(offset))?;
            for _ in 0..bytes / 16 {
                let mut entry = [0u8; 16];
                file.read_exact(&mut entry)?;
                let tag = u64::from_le_bytes(entry[..8].try_into()?);
                ensure!(
                    tag != 1,
                    "Codex helper requires a shared library; only static builds are supported"
                );
                if tag == 0 {
                    break;
                }
            }
        }
    }
    file.seek(SeekFrom::Start(0))?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn system_file(path: &Path, maximum: usize, require_root_owner: bool) -> Result<Vec<u8>> {
    // System trust/resolver files may be root-maintained symlinks; snapshot their
    // regular-file targets, never mount their parent directories or mutable paths.
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file()
            && (!require_root_owner || metadata.uid() == 0)
            && metadata.mode() & 0o022 == 0
            && metadata.len() <= maximum as u64,
        "unsafe system trust/resolver file"
    );
    let mut bytes = Vec::new();
    file.take(maximum as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= maximum,
        "system trust/resolver file exceeds limit"
    );
    Ok(bytes)
}
#[cfg(target_os = "linux")]
fn data_snapshot(name: &str, bytes: &[u8]) -> Result<File> {
    let mut file = memfd(name)?;
    file.write_all(bytes)?;
    seal(&mut file, 0o400)?;
    Ok(file)
}
#[cfg(target_os = "linux")]
fn trust_bundle() -> Result<File> {
    for candidate in [
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/cert.pem",
    ] {
        match system_file(Path::new(candidate), 2 * 1024 * 1024, true) {
            Ok(bytes) => return data_snapshot("vyx-codex-ca", &bytes),
            Err(error)
                if error
                    .downcast_ref::<io::Error>()
                    .is_some_and(|error| error.kind() == io::ErrorKind::NotFound) => {}
            Err(error) => return Err(error).context("snapshot system TLS trust bundle"),
        }
    }
    bail!(
        "Vyx Codex helper requires a system CA certificate bundle; TLS verification is never disabled"
    )
}
#[cfg(target_os = "linux")]
fn resolver() -> Result<File> {
    // systemd-resolved legitimately owns this as a service UID, not root. Only
    // numeric nameserver addresses are copied; DNS cannot bypass TLS hostname
    // verification against the separately root-owned trust bundle.
    let bytes = system_file(Path::new("/etc/resolv.conf"), 64 * 1024, false)?;
    let mut result = String::new();
    for line in std::str::from_utf8(&bytes)?.lines() {
        let mut fields = line.split_whitespace();
        if fields.next() == Some("nameserver") {
            if let Some(address) = fields
                .next()
                .and_then(|value| value.parse::<std::net::IpAddr>().ok())
            {
                use std::fmt::Write;
                writeln!(&mut result, "nameserver {address}")?;
            }
        }
    }
    ensure!(
        !result.is_empty(),
        "system resolver has no supported nameserver; cannot launch Codex with implicit DNS fallback"
    );
    data_snapshot("vyx-codex-dns", result.as_bytes())
}
#[cfg(target_os = "linux")]
fn scratch(auth: Option<&Secret>) -> Result<TempDir> {
    let directory = tempfile::Builder::new()
        .prefix("vyx-codex-")
        .tempdir_in("/dev/shm")
        .context("create volatile Codex state in /dev/shm (tmpfs is required; no disk fallback)")?;
    let file = File::open(directory.path())?;
    let mut filesystem = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: live directory fd and writable statfs storage.
    ensure!(
        unsafe { libc::fstatfs(file.as_raw_fd(), filesystem.as_mut_ptr()) } == 0,
        "inspect Codex state filesystem"
    );
    ensure!(
        unsafe { filesystem.assume_init() }.f_type as u64 == 0x01021994,
        "Codex credential scratch must be tmpfs; no plaintext disk fallback"
    );
    if let Some(auth) = auth {
        ensure!(
            auth.expose().len() <= MAX_AUTH,
            "Codex credentials exceed their size limit"
        );
        serde_json::from_str::<serde::de::IgnoredAny>(auth.expose())
            .context("invalid Vyx-owned Codex credentials")?;
        let mut output = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(directory.path().join("auth.json"))?;
        output.write_all(auth.expose().as_bytes())?;
    }
    Ok(directory)
}
#[cfg(target_os = "linux")]
fn spawn(
    helper: &File,
    trust: &File,
    dns: &File,
    state: TempDir,
    operation: &str,
    network: bool,
) -> Result<Session> {
    let bwrap = ["/usr/bin/bwrap", "/bin/bwrap"].into_iter().find(|path| Path::new(path).is_file())
        .context("install bubblewrap to use the isolated Vyx Codex helper; no unsandboxed fallback is available")?;
    let executable = File::open(bwrap)?;
    let metadata = executable.metadata()?;
    ensure!(
        metadata.uid() == 0 && metadata.mode() & 0o022 == 0,
        "bubblewrap must be root-owned and not writable by other users"
    );
    // Use bubblewrap's explicit data-fd API for anonymous, sealed snapshots.
    // It copies them into readonly private mounts and consumes file offsets,
    // including on the earlier identity probe.
    for mut source in [helper, trust, dns] {
        source.seek(SeekFrom::Start(0))?;
    }
    let mut command = Command::new(bwrap);
    command
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .process_group(0);
    command.args([
        "--unshare-user",
        "--unshare-all",
        "--disable-userns",
        "--assert-userns-disabled",
        "--die-with-parent",
        "--new-session",
        "--clearenv",
        "--cap-drop",
        "ALL",
        "--hostname",
        "vyx-codex",
    ]);
    if network {
        command.arg("--share-net");
    }
    command
        .args([
            "--perms",
            "0500",
            "--ro-bind-data",
            &helper.as_raw_fd().to_string(),
            "/vyx-codex",
        ])
        .args([
            "--dir",
            "/home",
            "--dir",
            "/work",
            "--dir",
            "/proc",
            "--dir",
            "/proc/self",
            "--symlink",
            "/vyx-codex",
            "/proc/self/exe",
            "--dir",
            "/etc",
            "--dir",
            "/etc/ssl",
            "--dir",
            "/etc/ssl/certs",
        ])
        .args([
            "--perms",
            "0400",
            "--ro-bind-data",
            &trust.as_raw_fd().to_string(),
            "/etc/ssl/certs/ca-certificates.crt",
        ])
        .args([
            "--perms",
            "0400",
            "--ro-bind-data",
            &dns.as_raw_fd().to_string(),
            "/etc/resolv.conf",
        ])
        .arg("--bind")
        .arg(state.path())
        .arg("/state")
        .args([
            "--tmpfs",
            "/tmp",
            "--setenv",
            "HOME",
            "/home",
            "--setenv",
            "CODEX_HOME",
            "/state",
            "--setenv",
            "TMPDIR",
            "/tmp",
            "--setenv",
            "PATH",
            "/nonexistent",
            "--setenv",
            "VYX_CODEX_SANDBOX",
            "1",
            "--setenv",
            "RUST_LOG",
            "off",
            "--setenv",
            "OTEL_SDK_DISABLED",
            "true",
            "--setenv",
            "SSL_CERT_FILE",
            "/etc/ssl/certs/ca-certificates.crt",
            "--setenv",
            "CODEX_CA_CERTIFICATE",
            "/etc/ssl/certs/ca-certificates.crt",
            "--chdir",
            "/work",
            "--remount-ro",
            "/",
            "/vyx-codex",
            operation,
        ]);
    let fds = [helper.as_raw_fd(), trust.as_raw_fd(), dns.as_raw_fd()];
    // SAFETY: this closure only makes async-signal-safe syscalls between fork and exec.
    unsafe {
        command.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                return Err(io::Error::last_os_error());
            }
            let limits = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            if libc::setrlimit(libc::RLIMIT_CORE, &limits) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 4u32) != 0 {
                return Err(io::Error::last_os_error());
            }
            for fd in fds {
                if libc::fcntl(fd, libc::F_SETFD, 0) != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    let mut child = command.spawn().context(
        "start isolated Vyx Codex helper (Linux user namespaces and bubblewrap are required)",
    )?;
    let input = child.stdin.take().context("Codex stdin missing")?;
    let output = BufReader::new(child.stdout.take().context("Codex stdout missing")?);
    Ok(Session {
        input,
        output,
        child: Some(child),
        scratch: Some(state),
    })
}

#[cfg(target_os = "linux")]
async fn verify_capabilities(helper: &File, trust: &File, dns: &File) -> Result<()> {
    let mut probe = spawn(
        helper,
        trust,
        dns,
        scratch(None)?,
        "--vyx-capabilities",
        false,
    )?;
    let result = tokio::time::timeout(Duration::from_secs(10), async {
        let mut bytes = Vec::new();
        (&mut probe.output).take(4097).read_to_end(&mut bytes).await?;
        ensure!(bytes.len() <= 4096, "Codex helper capability response exceeds its limit");
        let status = probe.child.as_mut().context("Codex probe child missing")?.wait().await?;
        ensure!(status.success(), "Vyx Codex capability probe failed under confinement; check bubblewrap/user namespace support and reinstall the helper");
        let capabilities: Capabilities = serde_json::from_slice(&bytes).context("invalid Vyx Codex capability response")?;
        capabilities.validate()
    }).await.context("Vyx Codex capability probe timed out")?;
    probe.shutdown().await?;
    result
}

pub(super) async fn launch(profile: &Profile, data_dir: &Path) -> Result<Session> {
    target()?;
    #[cfg(target_os = "linux")]
    {
        let (file, record) = resolve(profile, data_dir)?;
        let helper = snapshot(file, &record)?;
        let trust = trust_bundle()?;
        let dns = resolver()?;
        // Probe only the same sealed bytes that will be used for this session. No
        // account material is supplied until identity and confinement have succeeded.
        verify_capabilities(&helper, &trust, &dns).await?;
        spawn(
            &helper,
            &trust,
            &dns,
            scratch(profile.codex_auth.as_ref())?,
            "app-server",
            true,
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (profile, data_dir);
        unreachable!("target rejects unsupported platforms")
    }
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
fn asset<'a>(release: &'a ApiRelease, name: &str, maximum: usize) -> Result<&'a ApiAsset> {
    let mut matches = release.assets.iter().filter(|asset| asset.name == name);
    let asset = matches.next().with_context(|| format!("official release is missing optional {name}; install a release that publishes the Vyx Codex helper"))?;
    ensure!(
        matches.next().is_none() && asset.size > 0 && asset.size <= maximum as u64,
        "invalid or duplicate Codex release asset"
    );
    ensure!(
        asset.browser_download_url
            == format!(
                "https://github.com/{REPOSITORY}/releases/download/{}/{name}",
                release.tag_name
            ),
        "Codex asset URL does not match the official release"
    );
    Ok(asset)
}
async fn download(asset: &ApiAsset, maximum: usize) -> Result<Vec<u8>> {
    let response = update::download_client()?
        .get(&asset.browser_download_url)
        .send()
        .await
        .context("download optional Vyx Codex helper")?;
    ensure!(
        response.status() == reqwest::StatusCode::OK,
        "Codex helper download failed: HTTP {}",
        response.status()
    );
    ensure!(
        response.url().scheme() == "https" && update::approved_download_host(response.url()),
        "Codex helper download left approved GitHub HTTPS hosts"
    );
    ensure!(
        response
            .content_length()
            .is_none_or(|length| length == asset.size),
        "Codex helper download length differs from release metadata"
    );
    let bytes = update::read_bounded(response, maximum, "optional Codex helper").await?;
    ensure!(
        bytes.len() as u64 == asset.size,
        "Codex helper download length differs from release metadata"
    );
    Ok(bytes)
}
fn verify_attributions(directory: &File) -> Result<()> {
    for (name, expected) in ATTRIBUTIONS {
        let file = open_at(directory, name, libc::O_RDONLY, 0)?;
        check_file(&file, 0o600, 64 * 1024)?;
        let mut bytes = Vec::new();
        file.take(64 * 1024 + 1).read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() <= 64 * 1024
                && <[u8; 32]>::from(Sha256::digest(&bytes)) == update::decode_sha256(expected)?,
            "Codex helper is missing its pinned upstream attribution files"
        );
    }
    Ok(())
}
fn publish_file(directory: &File, name: &str, bytes: &[u8], mode: u32) -> Result<()> {
    // A descriptor-relative directory path prevents parent path replacement from
    // redirecting either the temporary file or the atomic same-directory rename.
    let path = PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()));
    let mut temporary = tempfile::Builder::new()
        .prefix(".publish-")
        .tempfile_in(&path)?;
    temporary.write_all(bytes)?;
    temporary
        .as_file()
        .set_permissions(std::fs::Permissions::from_mode(mode))?;
    temporary.as_file().sync_all()?;
    temporary
        .persist(path.join(name))
        .map_err(|error| error.error)
        .context("publish optional Codex helper")?;
    directory.sync_all().context(
        "Codex helper published but directory durability is uncertain; retry installation",
    )?;
    Ok(())
}

/// Explicit user action only. No startup/chat/profile path calls this function.
pub(super) async fn install(data_dir: &Path) -> Result<String> {
    let platform = target()?;
    #[cfg(target_os = "linux")]
    {
        let existing = (|| -> Result<File> {
            let directory = directory(data_dir, false)?;
            verify_attributions(&directory)?;
            let record = read_record(open_at(&directory, RECORD, libc::O_RDONLY, 0)?)?;
            snapshot(
                open_at(
                    &directory,
                    &format!("helper-{}", record.sha256),
                    libc::O_RDONLY,
                    0,
                )?,
                &record,
            )
        })();
        if let Ok(helper) = existing {
            verify_capabilities(&helper, &trust_bundle()?, &resolver()?).await?;
            return Ok("The matching isolated Vyx Codex helper is already installed. No download or account access was needed.".into());
        }
    }
    let tag = format!("v{}", env!("CARGO_PKG_VERSION"));
    let response = update::api_client()?
        .get(format!(
            "https://api.github.com/repos/{REPOSITORY}/releases/tags/{tag}"
        ))
        .header("Accept", "application/vnd.github+json")
        .send()
        .await
        .context("contact official Vyx release")?;
    ensure!(
        response.status() == reqwest::StatusCode::OK,
        "official Vyx release lookup failed: HTTP {}",
        response.status()
    );
    let release: ApiRelease = serde_json::from_slice(
        &update::read_bounded(response, 1024 * 1024, "Codex release metadata").await?,
    )?;
    ensure!(
        release.tag_name == tag && !release.draft && !release.prerelease,
        "Codex helper requires the published stable release for this exact Vyx version"
    );
    let name = format!("vyx-codex-{platform}");
    let helper = asset(&release, &name, MAX_HELPER)?;
    let sums = asset(&release, "SHA256SUMS", 64 * 1024)?;
    let sums = download(sums, 64 * 1024).await?;
    let digest = update::parse_checksums(&sums, &name)?;
    let bytes = download(helper, MAX_HELPER).await?;
    ensure!(
        <[u8; 32]>::from(Sha256::digest(&bytes)) == digest,
        "Codex helper SHA-256 does not match the official release"
    );
    let mut attributions = Vec::with_capacity(ATTRIBUTIONS.len());
    for (name, expected) in ATTRIBUTIONS {
        let asset_name = format!("vyx-codex-{name}");
        let attribution = download(asset(&release, &asset_name, 64 * 1024)?, 64 * 1024).await?;
        let expected = update::decode_sha256(expected)?;
        ensure!(
            update::parse_checksums(&sums, &asset_name)? == expected
                && <[u8; 32]>::from(Sha256::digest(&attribution)) == expected,
            "Codex helper attribution file does not match the pinned upstream release"
        );
        attributions.push((name, attribution));
    }
    let record = Record {
        protocol_version: 1,
        helper: "vyx-codex".into(),
        source_revision: REVISION.into(),
        tool_policy: "deny-all".into(),
        configuration: "vyx-fixed-v1".into(),
        vyx_version: env!("CARGO_PKG_VERSION").into(),
        target: platform.into(),
        sha256: digest.iter().map(|byte| format!("{byte:02x}")).collect(),
        bytes: bytes.len() as u64,
        origin: "release".into(),
    };
    record.validate()?;
    #[cfg(target_os = "linux")]
    {
        // Validate the new bytes before replacing any working active metadata.
        let mut helper = memfd("vyx-codex-install")?;
        helper.write_all(&bytes)?;
        seal(&mut helper, 0o500)?;
        static_elf(&mut helper)?;
        verify_capabilities(&helper, &trust_bundle()?, &resolver()?).await?;
    }
    let data_dir = data_dir.to_owned();
    // Publication is cancellation-safe: immutable binary first, atomic metadata last.
    // An interrupted install never changes the existing active metadata to partial bytes.
    tokio::task::spawn_blocking(move || -> Result<()> {
        let directory = directory(&data_dir, true)?;
        publish_file(
            &directory,
            &format!("helper-{}", record.sha256),
            &bytes,
            0o700,
        )?;
        for (name, attribution) in attributions {
            publish_file(&directory, name, &attribution, 0o600)?;
        }
        publish_file(&directory, RECORD, &serde_json::to_vec(&record)?, 0o600)
    })
    .await
    .context("Codex helper publisher failed")??;
    Ok("Optional Vyx Codex helper installed. No account was accessed or connected.".into())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn service_owned_dns_does_not_relax_tls_ownership_or_file_bounds() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("resolver");
        let contents = b"nameserver 127.0.0.53\n";
        std::fs::write(&path, contents).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(system_file(&path, 64, false).unwrap(), contents);
        if uid() != 0 {
            assert!(
                system_file(&path, 64, true).is_err(),
                "TLS trust must remain root-owned"
            );
        }
        assert!(system_file(&path, 4, false).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(
            system_file(&path, 64, false).is_err(),
            "writable-by-others resolver must be rejected"
        );
        assert!(
            system_file(temporary.path(), 64, false).is_err(),
            "only regular files may be snapshotted"
        );
    }
}
