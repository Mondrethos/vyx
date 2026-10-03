//! Local-only, descriptor-relative extension packages and digest-bound grants.
//!
//! Callers must cancel running generations before mutating their registry entry.
//! A publication failure is not a rollback: inspect its outcome and offer Retry.
use std::{
    collections::BTreeSet,
    ffi::CString,
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    os::{fd::{AsRawFd, FromRawFd}, unix::fs::{MetadataExt, OpenOptionsExt}},
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{contract::{Permission, parse_json}, distribution::ReleaseSource, package::{Manifest, Package, MAX_PACKAGE_BYTES, valid_extension_id}};

pub const MAX_ENTRIES: usize = 64;
pub const MAX_REGISTRY_BYTES: usize = 256 * 1024;
const MAX_DEVELOPMENT_PATH_BYTES: usize = 1024;
const REGISTRY_FILE: &str = "registry.json";

#[derive(Clone, Debug)]
pub struct Snapshot {
    pub bytes: Arc<[u8]>,
    pub manifest: Manifest,
    pub digest: String,
    pub source: Option<ReleaseSource>,
    provenance: Option<(String, ReleaseSource)>,
}

/// A development watcher may call this from a blocking thread. It receives only
/// an immutable, unverified snapshot; path trust and activation remain host-owned.
/// Reserved first-party identities cannot be loaded through development mode.
pub fn read_development(path: &Path) -> Result<Snapshot> {
    parse_snapshot(read_source_bytes(path)?, None)
}

#[derive(Clone, Debug)]
pub struct Entry {
    pub id: String,
    pub digest: String,
    pub enabled: bool,
    pub approved_permissions: Vec<Permission>,
    pub manifest: Manifest,
    pub source: Option<ReleaseSource>,
    /// Source path of an individually reviewed development package. It is
    /// reattached only while that file still has exactly this digest.
    pub development_path: Option<PathBuf>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PersistenceOutcome {
    /// The old registry was not replaced. A disabled/revoked entry nevertheless
    /// remains disabled in memory; its revocation may not survive restart.
    BeforePublishFailure(String),
    /// Registry replacement happened, but directory durability or subsequent
    /// cleanup failed. Nothing may activate until reconciliation succeeds.
    PublishedUncertain(String),
    Durable,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredEntry {
    id: String,
    digest: String,
    enabled: bool,
    approved_permissions: Vec<Permission>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source: Option<ReleaseSource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    development_path: Option<PathBuf>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredRegistry {
    format_version: u32,
    entries: Vec<StoredEntry>,
}

impl Default for StoredRegistry {
    fn default() -> Self { Self { format_version: 1, entries: Vec::new() } }
}

pub struct Registry {
    directory: File,
    packages: File,
    // One publisher per local registry; held until the Registry is dropped.
    _lock: File,
    entries: Vec<Entry>,
    pending: Option<StoredRegistry>,
    pending_package: Option<Snapshot>,
    garbage: Vec<String>,
    blocked: bool,
    #[cfg(test)]
    fail_at: Option<FailurePoint>,
}

impl Drop for Registry {
    fn drop(&mut self) {
        // CLOEXEC closes inherited descriptors only after exec. Releasing this
        // publisher must not wait for a concurrent fork/exec child to do so.
        // SAFETY: this registry still owns the valid locked descriptor.
        unsafe { libc::flock(self._lock.as_raw_fd(), libc::LOCK_UN); }
    }
}

impl Registry {
    pub fn open(data_dir: &Path) -> Result<Self> {
        let data = OpenOptions::new().read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(data_dir).context("open extension data directory")?;
        let metadata = data.metadata()?;
        ensure!(metadata.uid() == effective_uid() && metadata.mode() & 0o022 == 0,
            "extension data directory must be owned by this user and not writable by others");
        let directory = private_directory(&data, "extensions")?;
        let lock = open_at(&directory, "registry.lock", libc::O_RDWR | libc::O_CREAT, 0o600)?;
        check_file(&lock, true, 0)?;
        // SAFETY: the descriptor is valid and remains owned for the lock's lifetime.
        ensure!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "extension registry is already open by another publisher");
        let packages = private_directory(&directory, "packages")?;
        let mut registry = Self {
            directory, packages, _lock: lock,
            entries: Vec::new(), pending: None, pending_package: None, garbage: Vec::new(), blocked: false,
            #[cfg(test)] fail_at: None,
        };
        let (mut stored, missing) = registry.read_stored()?;
        let mut changed = missing;
        for entry in &mut stored.entries {
            if entry.id.starts_with("com.vyx.") && entry.source.is_none() {
                changed |= entry.enabled || !entry.approved_permissions.is_empty();
                entry.enabled = false;
                entry.approved_permissions.clear();
            }
        }
        registry.entries = registry.materialize(&stored)?;
        if changed {
            match registry.persist(stored)? {
                PersistenceOutcome::Durable => {},
                PersistenceOutcome::BeforePublishFailure(message) |
                PersistenceOutcome::PublishedUncertain(message) => bail!("initialize extension registry: {message}"),
            }
        }
        Ok(registry)
    }

    pub fn entries(&self) -> &[Entry] { &self.entries }

    /// Check before every activation. Pending persistence disables all entries.
    pub fn is_blocked(&self) -> bool { self.blocked }

    /// Reads and hashes a fresh immutable package snapshot. The digest must be
    /// currently owned by this registry; this does not itself authorize execution.
    pub fn load(&self, digest: &str) -> Result<Snapshot> {
        ensure!(!self.blocked, "extension registry requires persistence Retry before activation");
        let entry = self.entries.iter().find(|entry| entry.digest == digest).context("package is not installed")?;
        self.load_package(digest, entry.source.clone())
    }

    /// User-selected development/install sources may be 0644, but cannot be
    /// symlinks, nonregular files, foreign-owned, or writable by another user.
    /// The returned bytes never change when the source is subsequently rebuilt.
    pub fn read_source(&self, path: &Path) -> Result<Snapshot> {
        parse_snapshot(read_source_bytes(path)?, None)
    }

    /// Installing never enables a package and never invokes author code.
    pub fn install(&mut self, path: &Path) -> Result<PersistenceOutcome> {
        let snapshot = self.read_source(path)?;
        self.install_snapshot(snapshot, None)
    }

    /// `development_path` remembers an individually reviewed development source
    /// in the same publication; ordinary installs pass `None`.
    pub fn install_snapshot(&mut self, snapshot: Snapshot, development_path: Option<&Path>) -> Result<PersistenceOutcome> {
        self.require_ready()?;
        let snapshot = snapshot.revalidate()?;
        ensure!(!self.entries.iter().any(|entry| entry.id == snapshot.manifest.id),
            "extension is already installed; use explicit update review");
        ensure!(self.entries.len() < MAX_ENTRIES, "extension registry is full");
        if let Some(path) = development_path { validate_development_path(path, snapshot.source.as_ref())?; }
        let mut stored = self.stored();
        stored.entries.push(StoredEntry { id: snapshot.manifest.id.clone(), digest: snapshot.digest.clone(),
            enabled: false, approved_permissions: Vec::new(), source: snapshot.source.clone(),
            development_path: development_path.map(Path::to_path_buf) });
        self.pending_package = Some(snapshot);
        self.persist(stored)
    }

    /// The reviewed digest and the complete permission set are explicit consent.
    pub fn enable(&mut self, id: &str, reviewed_digest: &str, permissions: Vec<Permission>) -> Result<PersistenceOutcome> {
        self.require_ready()?;
        let index = self.index(id)?;
        ensure!(self.entries[index].digest == reviewed_digest, "reviewed package changed");
        ensure!(!id.starts_with("com.vyx.") || self.entries[index].source.as_ref().is_some_and(ReleaseSource::is_official),
            "legacy Vyx extension requires a reviewed official-store update before enabling");
        let snapshot = self.load_package(reviewed_digest, self.entries[index].source.clone())?;
        validate_grants(&snapshot.manifest, &permissions, true)?;
        let mut stored = self.stored();
        stored.entries[index].enabled = true;
        stored.entries[index].approved_permissions = permissions;
        self.persist(stored)
    }

    pub fn disable(&mut self, id: &str) -> Result<PersistenceOutcome> {
        self.disable_or_revoke(id, false)
    }

    /// In-memory revocation happens before any write. On any failed outcome the
    /// UI must warn that unsaved revocation may not survive restart and offer Retry.
    pub fn revoke(&mut self, id: &str) -> Result<PersistenceOutcome> {
        self.disable_or_revoke(id, true)
    }

    fn disable_or_revoke(&mut self, id: &str, revoke: bool) -> Result<PersistenceOutcome> {
        let index = self.index(id)?;
        self.entries[index].enabled = false;
        if revoke { self.entries[index].approved_permissions.clear(); }
        // Permit security-reducing operations even while another save is pending.
        let mut stored = self.pending.clone().unwrap_or_else(|| self.stored());
        if let Some(entry) = stored.entries.iter_mut().find(|entry| entry.id == id) {
            entry.enabled = false;
            if revoke { entry.approved_permissions.clear(); }
        }
        self.persist(stored)
    }

    /// Updates require review even when ID, version and permissions are unchanged.
    /// Callers display both snapshots and added/removed permissions before calling.
    /// The entry remembers exactly `development_path`: `None` clears it.
    pub fn update(&mut self, id: &str, reviewed_current_digest: &str, snapshot: Snapshot,
        permissions: Vec<Permission>, enabled: bool, development_path: Option<&Path>) -> Result<PersistenceOutcome>
    {
        self.require_ready()?;
        let index = self.index(id)?;
        let current = &self.entries[index];
        ensure!(current.digest == reviewed_current_digest, "installed package changed since review");
        let snapshot = snapshot.revalidate()?;
        ensure!(snapshot.manifest.id == id, "update changes extension identity");
        ensure!(snapshot.digest != current.digest || snapshot.source != current.source,
            "package digest and release source have not changed");
        ensure!(snapshot.digest != current.digest || current.source.is_none(),
            "same-digest release source substitution is not allowed");
        validate_grants(&snapshot.manifest, &permissions, enabled)?;
        if let Some(path) = development_path { validate_development_path(path, snapshot.source.as_ref())?; }
        let mut stored = self.stored();
        self.garbage.push(stored.entries[index].digest.clone());
        stored.entries[index] = StoredEntry { id: id.to_owned(), digest: snapshot.digest.clone(),
            enabled, approved_permissions: permissions, source: snapshot.source.clone(),
            development_path: development_path.map(Path::to_path_buf) };
        // Do not leave an old worker launchable after an explicit update request.
        self.entries[index].enabled = false;
        self.pending_package = Some(snapshot);
        self.persist(stored)
    }

    /// Remembers the source of an unchanged package after its explicit development
    /// review. Enablement and grants are unchanged; an identical path writes nothing.
    pub fn set_development_path(&mut self, id: &str, reviewed_digest: &str, path: &Path) -> Result<PersistenceOutcome> {
        self.require_ready()?;
        let index = self.index(id)?;
        let entry = &self.entries[index];
        ensure!(entry.digest == reviewed_digest, "reviewed package changed");
        validate_development_path(path, entry.source.as_ref())?;
        if entry.development_path.as_deref() == Some(path) { return Ok(PersistenceOutcome::Durable); }
        let mut stored = self.stored();
        stored.entries[index].development_path = Some(path.to_owned());
        self.persist(stored)
    }

    pub fn remove(&mut self, id: &str) -> Result<PersistenceOutcome> {
        self.require_ready()?;
        let index = self.index(id)?;
        let mut stored = self.stored();
        self.garbage.push(stored.entries.remove(index).digest);
        self.entries[index].enabled = false;
        self.persist(stored)
    }

    /// Re-read the actual on-disk registry after an uncertain publication before
    /// retrying the desired mutation. Never infer that a failed write rolled back.
    pub fn retry(&mut self) -> Result<PersistenceOutcome> {
        let desired = self.pending.clone().context("no registry persistence operation needs Retry")?;
        let (actual, missing) = self.read_stored()?;
        ensure!(!missing, "published registry disappeared; activation remains blocked");
        // A pending removal can already have removed obsolete package files.
        // Validate all retained disk references, but do not activate disk grants.
        for entry in &actual.entries {
            if desired.entries.iter().any(|retained| retained.digest == entry.digest) {
                self.validate_entry(entry)?;
            }
        }
        self.persist(desired)
    }

    fn require_ready(&self) -> Result<()> {
        ensure!(!self.blocked && self.pending.is_none(), "resolve pending registry persistence with Retry first");
        Ok(())
    }

    fn index(&self, id: &str) -> Result<usize> {
        self.entries.iter().position(|entry| entry.id == id).context("extension is not installed")
    }

    fn stored(&self) -> StoredRegistry {
        StoredRegistry { format_version: 1, entries: self.entries.iter().map(|entry| StoredEntry {
            id: entry.id.clone(), digest: entry.digest.clone(), enabled: entry.enabled,
            approved_permissions: entry.approved_permissions.clone(), source: entry.source.clone(),
            development_path: entry.development_path.clone(),
        }).collect() }
    }


    fn load_package(&self, digest: &str, source: Option<ReleaseSource>) -> Result<Snapshot> {
        ensure!(valid_digest(digest), "invalid package digest");
        let file = open_at(&self.packages, &format!("{digest}.vyxext"), libc::O_RDONLY, 0)?;
        let snapshot = stored_snapshot(read_bounded(file, MAX_PACKAGE_BYTES, true)?.into(), source)?;
        ensure!(snapshot.digest == digest, "installed package digest mismatch");
        Ok(snapshot)
    }

    fn read_stored(&self) -> Result<(StoredRegistry, bool)> {
        let file = match open_at(&self.directory, REGISTRY_FILE, libc::O_RDONLY, 0) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok((StoredRegistry::default(), true)),
            Err(error) => return Err(error).context("open local extension registry"),
        };
        let mut stored: StoredRegistry = parse_json(&read_bounded(file, MAX_REGISTRY_BYTES, true)?)?;
        ensure!(stored.format_version == 1, "unsupported extension registry format");
        ensure!(stored.entries.len() <= MAX_ENTRIES, "too many installed extensions");
        let mut ids = BTreeSet::new();
        let mut digests = BTreeSet::new();
        for entry in &mut stored.entries {
            // A malformed remembered path only forfeits remembered approval; it
            // must not make the registry unusable.
            if entry.development_path.as_deref().is_some_and(|path| validate_development_path(path, entry.source.as_ref()).is_err()) {
                entry.development_path = None;
            }
        }
        for entry in &stored.entries {
            ensure!(valid_extension_id(&entry.id) && valid_digest(&entry.digest), "invalid registry identity or digest");
            if let Some(source) = &entry.source { source.validate()?; }
            ensure!(ids.insert(&entry.id) && digests.insert(&entry.digest), "duplicate registry entry");
            ensure!(entry.approved_permissions.iter().collect::<BTreeSet<_>>().len() == entry.approved_permissions.len(),
                "duplicate approved permission");
        }
        Ok((stored, false))
    }

    fn validate_entry(&self, entry: &StoredEntry) -> Result<Snapshot> {
        let snapshot = self.load_package(&entry.digest, entry.source.clone())?;
        ensure!(snapshot.manifest.id == entry.id, "registry and package identity mismatch");
        ensure!(!entry.id.starts_with("com.vyx.") || entry.source.as_ref().is_some_and(ReleaseSource::is_official)
            || (!entry.enabled && entry.approved_permissions.is_empty() && entry.source.is_none()),
            "reserved extension identity requires official release provenance");
        validate_grants(&snapshot.manifest, &entry.approved_permissions, entry.enabled)?;
        Ok(snapshot)
    }

    fn materialize(&self, stored: &StoredRegistry) -> Result<Vec<Entry>> {
        stored.entries.iter().map(|entry| {
            let snapshot = self.validate_entry(entry)?;
            Ok(Entry { id: entry.id.clone(), digest: entry.digest.clone(), enabled: entry.enabled,
                approved_permissions: entry.approved_permissions.clone(), manifest: snapshot.manifest,
                source: snapshot.source, development_path: entry.development_path.clone() })
        }).collect()
    }

    fn publish_package(&self, snapshot: &Snapshot) -> Result<()> {
        let name = format!("{}.vyxext", snapshot.digest);
        match open_at(&self.packages, &name, libc::O_RDONLY, 0) {
            Ok(existing) => {
                let bytes = read_bounded(existing, MAX_PACKAGE_BYTES, true)?;
                ensure!(bytes.as_slice() == snapshot.bytes.as_ref(), "existing immutable package is corrupt");
                // A previous attempt may have linked it without syncing the directory.
                self.packages.sync_all()?;
                return Ok(());
            },
            Err(error) if error.kind() == io::ErrorKind::NotFound => {},
            Err(error) => return Err(error.into()),
        }
        let temporary = Temporary::new(&self.packages)?;
        (&temporary.file).write_all(&snapshot.bytes)?;
        temporary.file.sync_all()?;
        let from = CString::new(temporary.name.as_str())?;
        let to = CString::new(name)?;
        // linkat is atomic and never replaces an existing immutable package.
        // SAFETY: descriptors and NUL-terminated single-component names are valid.
        let result = unsafe { libc::linkat(self.packages.as_raw_fd(), from.as_ptr(), self.packages.as_raw_fd(), to.as_ptr(), 0) };
        if result != 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::AlreadyExists { return Err(error.into()); }
            let existing = self.load_package(&snapshot.digest, snapshot.source.clone())?;
            ensure!(existing.bytes == snapshot.bytes, "immutable package collision");
        }
        temporary.remove()?;
        self.packages.sync_all()?;
        Ok(())
    }

    fn persist(&mut self, desired: StoredRegistry) -> Result<PersistenceOutcome> {
        // Validate before writing; existing grants remain unavailable on a failed
        // revocation even if re-reading its package fails here.
        self.pending = Some(desired.clone());
        self.blocked = true;
        self.disable_memory();
        if let Some(snapshot) = &self.pending_package {
            if let Err(error) = self.publish_package(snapshot) {
                return Ok(PersistenceOutcome::BeforePublishFailure(format!("publish immutable package: {error:#}")));
            }
            self.pending_package = None;
        }
        let validated = match self.materialize(&desired) {
            Ok(entries) => entries,
            Err(error) => return Ok(PersistenceOutcome::BeforePublishFailure(format!("validate registry publication: {error:#}"))),
        };
        let bytes = serde_json::to_vec(&desired)?;
        ensure!(bytes.len() <= MAX_REGISTRY_BYTES, "extension registry size limit exceeded");
        let result = self.publish_registry(&bytes);
        match result {
            PersistenceOutcome::Durable => {
                // Retired package deletion happens only after durable registry
                // replacement; a crash can leave harmless unowned package bytes.
                let mut failure = None;
                for digest in &self.garbage {
                    if desired.entries.iter().any(|entry| &entry.digest == digest) { continue; }
                    if let Err(error) = unlink_at(&self.packages, &format!("{digest}.vyxext")) {
                        if error.kind() != io::ErrorKind::NotFound { failure = Some(error); break; }
                    }
                }
                if let Some(error) = failure.or_else(|| self.packages.sync_all().err()) {
                    self.disable_memory();
                    return Ok(PersistenceOutcome::PublishedUncertain(format!("registry published; retired package cleanup requires Retry: {error}")));
                }
                self.entries = validated;
                self.pending = None;
                self.garbage.clear();
                self.blocked = false;
                Ok(PersistenceOutcome::Durable)
            },
            failure => { self.disable_memory(); Ok(failure) },
        }
    }

    fn disable_memory(&mut self) {
        for entry in &mut self.entries { entry.enabled = false; }
    }

    fn publish_registry(&self, bytes: &[u8]) -> PersistenceOutcome {
        let before = || -> Result<()> {
            #[cfg(test)]
            ensure!(self.fail_at != Some(FailurePoint::BeforeRename), "injected pre-publication failure");
            let temporary = Temporary::new(&self.directory)?;
            (&temporary.file).write_all(bytes)?;
            temporary.file.sync_all()?;
            // Validate the current descriptor, not a path metadata precheck.
            match open_at(&self.directory, REGISTRY_FILE, libc::O_RDONLY, 0) {
                Ok(file) => check_file(&file, true, MAX_REGISTRY_BYTES)?,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {},
                Err(error) => return Err(error.into()),
            }
            let from = CString::new(temporary.name.as_str())?;
            let to = CString::new(REGISTRY_FILE)?;
            // SAFETY: same-directory descriptors and names remain valid.
            if unsafe { libc::renameat(self.directory.as_raw_fd(), from.as_ptr(), self.directory.as_raw_fd(), to.as_ptr()) } != 0 {
                return Err(io::Error::last_os_error().into());
            }
            Ok(())
        };
        if let Err(error) = before() {
            return PersistenceOutcome::BeforePublishFailure(format!("registry not replaced: {error:#}"));
        }
        #[cfg(test)]
        if self.fail_at == Some(FailurePoint::AfterRename) {
            return PersistenceOutcome::PublishedUncertain("injected post-publication failure".into());
        }
        match self.directory.sync_all() {
            Ok(()) => PersistenceOutcome::Durable,
            Err(error) => PersistenceOutcome::PublishedUncertain(format!("registry replaced but directory sync failed: {error}")),
        }
    }
}

fn read_source_bytes(path: &Path) -> Result<Arc<[u8]>> {
    let file = OpenOptions::new().read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path).context("open extension package source")?;
    Ok(read_bounded(file, MAX_PACKAGE_BYTES, false)?.into())
}

fn parse_snapshot(bytes: Arc<[u8]>, source: Option<ReleaseSource>) -> Result<Snapshot> {
    let snapshot = stored_snapshot(bytes, source)?;
    ensure!(!snapshot.manifest.id.starts_with("com.vyx.")
        || snapshot.source.as_ref().is_some_and(ReleaseSource::is_official),
        "com.vyx.* identities require an official GitHub release download");
    Ok(snapshot)
}

fn stored_snapshot(bytes: Arc<[u8]>, source: Option<ReleaseSource>) -> Result<Snapshot> {
    if let Some(source) = &source { source.validate()?; }
    let package = Package::parse(&bytes)?;
    let manifest = package.manifest;
    let digest = package.digest;
    let provenance = source.clone().map(|source| (digest.clone(), source));
    Ok(Snapshot { bytes, manifest, digest, source, provenance })
}

impl Snapshot {
    // The download path must verify both the release metadata and immutable bytes
    // before recording provenance; author packages never deserialize this type.
    pub(super) fn downloaded(bytes: Arc<[u8]>, source: ReleaseSource) -> Result<Self> {
        parse_snapshot(bytes, Some(source))
    }

    fn revalidate(self) -> Result<Self> {
        let snapshot = parse_snapshot(self.bytes, self.source)?;
        ensure!(self.provenance == snapshot.provenance, "package release provenance was changed");
        ensure!(self.digest == snapshot.digest && self.manifest == snapshot.manifest,
            "reviewed package metadata was changed");
        Ok(snapshot)
    }
}

fn validate_grants(manifest: &Manifest, permissions: &[Permission], enabled: bool) -> Result<()> {
    let granted: BTreeSet<_> = permissions.iter().collect();
    let requested: BTreeSet<_> = manifest.permissions.iter().collect();
    ensure!(granted.len() == permissions.len(), "duplicate approved permission");
    ensure!(granted.is_subset(&requested), "permission was not requested by this package");
    ensure!(!enabled || granted == requested, "every requested permission needs explicit approval");
    Ok(())
}

fn valid_digest(digest: &str) -> bool {
    digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// A remembered development source is an absolute UTF-8 path of at most 1024 bytes
/// without control or bidirectional characters, and only for a local package.
fn validate_development_path(path: &Path, source: Option<&ReleaseSource>) -> Result<()> {
    ensure!(source.is_none(), "a downloaded package cannot remember a development path");
    let text = path.to_str().context("development path must be UTF-8")?;
    ensure!(path.is_absolute(), "development path must be absolute");
    ensure!(text.len() <= MAX_DEVELOPMENT_PATH_BYTES, "development path exceeds {MAX_DEVELOPMENT_PATH_BYTES} bytes");
    ensure!(!text.chars().any(|c| c.is_control()
        || matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')),
        "development path contains control or bidirectional characters");
    Ok(())
}

pub(super) fn effective_uid() -> u32 {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() }
}

fn check_file(file: &File, private: bool, maximum: usize) -> Result<()> {
    let metadata = file.metadata()?;
    ensure!(metadata.is_file(), "extension storage is not a regular file");
    ensure!(metadata.uid() == effective_uid(), "extension file is not owned by this user");
    if private {
        ensure!(metadata.mode() & 0o7777 == 0o600, "extension storage file must have mode 0600");
        ensure!(metadata.nlink() == 1, "extension storage file must not have additional hard links");
    } else {
        ensure!(metadata.mode() & 0o022 == 0, "extension source is writable by another user");
    }
    ensure!(metadata.len() <= maximum as u64, "extension file exceeds size limit");
    Ok(())
}

pub(super) fn read_bounded(mut file: File, maximum: usize, private: bool) -> Result<Vec<u8>> {
    check_file(&file, private, maximum)?;
    let before = file.metadata()?;
    let mut bytes = Vec::with_capacity(before.len() as usize);
    (&mut file).take(maximum as u64 + 1).read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    ensure!(bytes.len() <= maximum, "extension file grew beyond size limit");
    ensure!(before.len() == after.len() && before.len() == bytes.len() as u64
        && before.mtime() == after.mtime() && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime() && before.ctime_nsec() == after.ctime_nsec(),
        "extension source changed while being read; retry the immutable snapshot");
    Ok(bytes)
}

pub(super) fn open_at(directory: &File, name: &str, flags: i32, mode: libc::mode_t) -> io::Result<File> {
    let name = component(name)?;
    // O_NONBLOCK avoids blocking on hostile FIFOs before descriptor validation.
    // SAFETY: directory owns its fd; name is NUL terminated; a successful call
    // returns a new owned fd, immediately transferred to File.
    let fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK, mode) };
    if fd < 0 { return Err(io::Error::last_os_error()); }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn component(name: &str) -> io::Result<CString> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "not a single path component"));
    }
    CString::new(name).map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))
}

pub(super) fn private_directory(parent: &File, name: &str) -> Result<File> {
    let component = component(name)?;
    // SAFETY: parent owns its descriptor and the name remains valid.
    let created = unsafe { libc::mkdirat(parent.as_raw_fd(), component.as_ptr(), 0o700) } == 0;
    if !created && io::Error::last_os_error().kind() != io::ErrorKind::AlreadyExists {
        return Err(io::Error::last_os_error().into());
    }
    let directory = open_at(parent, name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
    let metadata = directory.metadata()?;
    ensure!(metadata.is_dir() && metadata.uid() == effective_uid() && metadata.mode() & 0o7777 == 0o700,
        "extension directory must be owned by this user with mode 0700");
    // Also reconcile a directory left visible by an earlier failed startup sync.
    directory.sync_all()?;
    parent.sync_all()?;
    Ok(directory)
}

fn unlink_at(directory: &File, name: &str) -> io::Result<()> {
    let name = component(name)?;
    // SAFETY: live directory descriptor and valid single-component name.
    if unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(super) struct Temporary<'a> { pub(super) directory: &'a File, pub(super) name: String, pub(super) file: File }
impl<'a> Temporary<'a> {
    pub(super) fn new(directory: &'a File) -> Result<Self> {
        let name = format!(".publish-{}", Uuid::new_v4());
        let file = open_at(directory, &name, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL, 0o600)?;
        check_file(&file, true, 0)?;
        Ok(Self { directory, name, file })
    }
    fn remove(self) -> Result<()> { unlink_at(self.directory, &self.name)?; Ok(()) }
}
impl Drop for Temporary<'_> {
    fn drop(&mut self) { let _ = unlink_at(self.directory, &self.name); }
}

#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum FailurePoint { BeforeRename, AfterRename }

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::{ffi::OsStrExt, fs::{PermissionsExt, symlink}}};
    use serde_json::json;

    struct Directory(std::path::PathBuf);
    impl Directory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("vyx-registry-{}", Uuid::new_v4()));
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }
        fn package(&self, id: &str, version: &str, permissions: &[&str]) -> std::path::PathBuf {
            let path = self.0.join(format!("{id}-{version}.vyxext"));
            let manifest = serde_json::to_vec(&json!({"schemaVersion":1,"apiVersion":1,
                "id":id,"name":"Example","description":"Example","version":version,
                "permissions":permissions,"commands":[{"id":"open","title":"Open","description":"Open"}]})).unwrap();
            let mut bytes = super::super::package::MAGIC.to_vec();
            bytes.extend((manifest.len() as u32).to_le_bytes());
            bytes.extend(8u32.to_le_bytes());
            bytes.extend(manifest);
            bytes.extend(b"\0asm\x01\0\0\0");
            fs::write(&path, bytes).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            path
        }
    }
    impl Drop for Directory { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); } }

    #[test]
    fn installation_grants_and_updates_are_digest_bound() {
        let directory = Directory::new();
        let path = directory.package("org.example.test", "1.0.0", &["hosts.read"]);
        let mut registry = Registry::open(&directory.0).unwrap();
        assert_eq!(registry.install(&path).unwrap(), PersistenceOutcome::Durable);
        let digest = registry.entries()[0].digest.clone();
        assert!(!registry.entries()[0].enabled);
        assert!(registry.enable("org.example.test", &digest, Vec::new()).is_err());
        let grants = registry.entries()[0].manifest.permissions.clone();
        assert_eq!(registry.enable("org.example.test", &digest, grants.clone()).unwrap(), PersistenceOutcome::Durable);
        drop(registry);
        let mut registry = Registry::open(&directory.0).unwrap();
        assert!(registry.entries()[0].enabled);
        let next = directory.package("org.example.test", "1.1.0", &["hosts.read", "sessions.read"]);
        assert!(registry.install(&next).is_err());
        let snapshot = registry.read_source(&next).unwrap();
        assert!(registry.update("org.example.test", &digest, snapshot.clone(), grants, true, None).is_err());
        let new_grants = snapshot.manifest.permissions.clone();
        assert_eq!(registry.update("org.example.test", &digest, snapshot.clone(), new_grants, true, None).unwrap(), PersistenceOutcome::Durable);
        assert!(registry.load(&digest).is_err());
        assert!(registry.entries()[0].enabled);
        assert_eq!(registry.load(&snapshot.digest).unwrap().bytes, snapshot.bytes);
        assert!(!directory.0.join(format!("extensions/packages/{digest}.vyxext")).exists());
        assert_eq!(registry.remove("org.example.test").unwrap(), PersistenceOutcome::Durable);
        assert!(registry.entries().is_empty());
    }

    #[test]
    fn failure_outcomes_preserve_revocation_and_reconcile_actual_disk() {
        for failure in [FailurePoint::BeforeRename, FailurePoint::AfterRename] {
            let directory = Directory::new();
            let path = directory.package("org.example.test", "1.0.0", &["hosts.read"]);
            let mut registry = Registry::open(&directory.0).unwrap();
            registry.install(&path).unwrap();
            let digest = registry.entries()[0].digest.clone();
            registry.enable("org.example.test", &digest, registry.entries()[0].manifest.permissions.clone()).unwrap();
            registry.fail_at = Some(failure);
            let outcome = registry.revoke("org.example.test").unwrap();
            assert!(matches!((&outcome, failure),
                (PersistenceOutcome::BeforePublishFailure(_), FailurePoint::BeforeRename) |
                (PersistenceOutcome::PublishedUncertain(_), FailurePoint::AfterRename)));
            assert!(!registry.entries()[0].enabled);
            assert!(registry.entries()[0].approved_permissions.is_empty());
            assert!(registry.load(&digest).is_err());
            let (actual, _) = registry.read_stored().unwrap();
            assert_eq!(actual.entries[0].enabled, failure == FailurePoint::BeforeRename);
            registry.fail_at = None;
            assert_eq!(registry.retry().unwrap(), PersistenceOutcome::Durable);
            drop(registry);
            let registry = Registry::open(&directory.0).unwrap();
            assert!(!registry.entries()[0].enabled);
            assert!(registry.entries()[0].approved_permissions.is_empty());
        }
    }

    #[test]
    fn source_snapshots_are_immutable_and_forged_metadata_is_rejected() {
        let directory = Directory::new();
        let path = directory.package("org.example.test", "1.0.0", &[]);
        let mut registry = Registry::open(&directory.0).unwrap();
        let snapshot = read_development(&path).unwrap();
        let digest = snapshot.digest.clone();
        fs::write(&path, b"incomplete rebuild").unwrap();
        let mut forged = snapshot.clone();
        forged.source = Some(official_source());
        assert!(registry.install_snapshot(forged, None).is_err());
        registry.install_snapshot(snapshot, None).unwrap();
        assert!(registry.entries()[0].source.is_none());
        assert!(registry.load(&digest).is_ok());
        assert!(registry.read_source(&path).is_err());
    }

    #[test]
    fn rejects_links_fifo_corruption_permissions_and_second_publisher() {
        let directory = Directory::new();
        let path = directory.package("org.example.test", "1.0.0", &[]);
        let mut registry = Registry::open(&directory.0).unwrap();
        assert!(Registry::open(&directory.0).is_err());
        let link = directory.0.join("source-link");
        symlink(&path, &link).unwrap();
        assert!(registry.install(&link).is_err());
        let fifo = directory.0.join("fifo");
        let fifo_c = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: valid path, test-owned directory.
        assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);
        assert!(registry.install(&fifo).is_err());
        registry.install(&path).unwrap();
        let digest = registry.entries()[0].digest.clone();
        let stored = directory.0.join(format!("extensions/packages/{digest}.vyxext"));
        fs::set_permissions(&stored, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(registry.load(&digest).is_err());
        fs::set_permissions(&stored, fs::Permissions::from_mode(0o600)).unwrap();
        fs::hard_link(&stored, directory.0.join("hard-link")).unwrap();
        assert!(registry.load(&digest).is_err());
        fs::remove_file(directory.0.join("hard-link")).unwrap();
        fs::write(&stored, b"corrupt").unwrap();
        assert!(registry.load(&digest).is_err());
        drop(registry);
        assert!(Registry::open(&directory.0).is_err());
    }

    fn official_source() -> ReleaseSource {
        ReleaseSource { repository: super::super::distribution::OFFICIAL_REPOSITORY.into(),
            tag: "v1.0.0".into(), asset: "com.vyx.test.vyxext".into() }
    }

    #[test]
    fn fresh_registry_is_empty_and_official_download_is_removable_not_granted() {
        let directory = Directory::new();
        let path = directory.package("com.vyx.test", "1.0.0", &["hosts.read"]);
        let mut registry = Registry::open(&directory.0).unwrap();
        assert!(registry.entries().is_empty());
        assert!(registry.install(&path).is_err());
        assert!(read_development(&path).is_err());
        let snapshot = Snapshot::downloaded(fs::read(&path).unwrap().into(), official_source()).unwrap();
        registry.install_snapshot(snapshot.clone(), None).unwrap();
        assert!(!registry.entries()[0].enabled);
        assert!(registry.entries()[0].approved_permissions.is_empty());
        let mut other = official_source();
        other.tag = "v1.1.0".into();
        let changed = Snapshot::downloaded(snapshot.bytes, other).unwrap();
        assert!(registry.update("com.vyx.test", &snapshot.digest, changed, vec![], false, None).is_err());
        drop(registry);
        let mut registry = Registry::open(&directory.0).unwrap();
        assert_eq!(registry.entries()[0].source, Some(official_source()));
        assert_eq!(registry.remove("com.vyx.test").unwrap(), PersistenceOutcome::Durable);
    }

    #[test]
    fn legacy_reserved_package_is_preserved_disabled_until_official_update() {
        let directory = Directory::new();
        let path = directory.package("com.vyx.test", "1.0.0", &["hosts.read"]);
        let registry = Registry::open(&directory.0).unwrap();
        let snapshot = stored_snapshot(fs::read(path).unwrap().into(), None).unwrap();
        registry.publish_package(&snapshot).unwrap();
        let old = serde_json::json!({"formatVersion":1,"entries":[{
            "id":"com.vyx.test","digest":snapshot.digest,"enabled":true,"approvedPermissions":["hosts.read"]}]});
        assert_eq!(registry.publish_registry(&serde_json::to_vec(&old).unwrap()), PersistenceOutcome::Durable);
        drop(registry);
        let mut registry = Registry::open(&directory.0).unwrap();
        assert!(!registry.entries()[0].enabled);
        assert!(registry.entries()[0].approved_permissions.is_empty());
        assert_eq!(registry.load(&snapshot.digest).unwrap().bytes, snapshot.bytes);
        assert!(registry.enable("com.vyx.test", &snapshot.digest, vec![Permission::HostsRead]).is_err());
        let official = Snapshot::downloaded(snapshot.bytes, official_source()).unwrap();
        registry.update("com.vyx.test", &snapshot.digest, official, vec![], false, None).unwrap();
        assert_eq!(registry.entries()[0].source, Some(official_source()));
    }

    #[test]
    fn dropping_publisher_releases_lease_despite_inherited_descriptor() {
        let directory = Directory::new();
        let registry = Registry::open(&directory.0).unwrap();
        let inherited = registry._lock.try_clone().unwrap();
        drop(registry);
        let next = Registry::open(&directory.0).unwrap();
        assert!(Registry::open(&directory.0).is_err());
        drop(next);
        drop(inherited);
    }

    #[test]
    fn registry_rejects_unknown_fields_duplicate_ids_and_excessive_size() {
        let directory = Directory::new();
        let registry = Registry::open(&directory.0).unwrap();
        let path = directory.0.join("extensions/registry.json");
        drop(registry);
        for bytes in [br#"{"formatVersion":1,"entries":[],"extra":true}"#.to_vec(),
            br#"{"formatVersion":1,"formatVersion":1,"entries":[]}"#.to_vec(),
            vec![b' '; MAX_REGISTRY_BYTES + 1]] {
            fs::write(&path, bytes).unwrap();
            assert!(Registry::open(&directory.0).is_err());
        }
        fs::remove_file(&path).unwrap();
        symlink(directory.0.join("outside"), &path).unwrap();
        assert!(Registry::open(&directory.0).is_err());
    }

    #[test]
    fn directory_symlinks_and_broad_permissions_fail_closed() {
        let directory = Directory::new();
        let outside = Directory::new();
        let extensions = directory.0.join("extensions");
        symlink(&outside.0, &extensions).unwrap();
        assert!(Registry::open(&directory.0).is_err());
        fs::remove_file(&extensions).unwrap();
        fs::create_dir(&extensions).unwrap();
        fs::set_permissions(&extensions, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(Registry::open(&directory.0).is_err());
        fs::set_permissions(&extensions, fs::Permissions::from_mode(0o700)).unwrap();
        symlink(&outside.0, extensions.join("packages")).unwrap();
        assert!(Registry::open(&directory.0).is_err());
    }

    #[test]
    fn immutable_package_publication_never_clobbers_existing_bytes() {
        let directory = Directory::new();
        let path = directory.package("org.example.test", "1.0.0", &[]);
        let mut registry = Registry::open(&directory.0).unwrap();
        let snapshot = registry.read_source(&path).unwrap();
        let stored = directory.0.join(format!("extensions/packages/{}.vyxext", snapshot.digest));
        fs::write(&stored, b"do not overwrite").unwrap();
        fs::set_permissions(&stored, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(registry.install_snapshot(snapshot, None).unwrap(), PersistenceOutcome::BeforePublishFailure(_)));
        assert_eq!(fs::read(stored).unwrap(), b"do not overwrite");
        assert!(registry.entries().is_empty());
    }

    #[test]
    fn installed_package_count_and_duplicate_registry_identity_are_bounded() {
        let directory = Directory::new();
        let mut registry = Registry::open(&directory.0).unwrap();
        for index in 0..MAX_ENTRIES {
            let path = directory.package(&format!("org.example.test{index}"), "1.0.0", &[]);
            assert_eq!(registry.install(&path).unwrap(), PersistenceOutcome::Durable);
        }
        let extra = directory.package("org.example.excess", "1.0.0", &[]);
        assert!(registry.install(&extra).is_err());
        let mut stored = registry.stored();
        stored.entries[1] = stored.entries[0].clone();
        let bytes = serde_json::to_vec(&stored).unwrap();
        drop(registry);
        fs::write(directory.0.join("extensions/registry.json"), bytes).unwrap();
        assert!(Registry::open(&directory.0).is_err());
    }

    #[test]
    fn development_path_and_digest_publish_together_through_retry() {
        for failure in [FailurePoint::BeforeRename, FailurePoint::AfterRename] {
            let directory = Directory::new();
            let path = directory.package("org.example.test", "1.0.0", &["hosts.read"]);
            let mut registry = Registry::open(&directory.0).unwrap();
            registry.install(&path).unwrap();
            let digest = registry.entries()[0].digest.clone();
            let next = directory.package("org.example.test", "1.1.0", &["hosts.read"]);
            let snapshot = read_development(&next).unwrap();
            registry.fail_at = Some(failure);
            let outcome = registry.update("org.example.test", &digest, snapshot.clone(), Vec::new(), false, Some(&next)).unwrap();
            assert!(matches!((&outcome, failure),
                (PersistenceOutcome::BeforePublishFailure(_), FailurePoint::BeforeRename) |
                (PersistenceOutcome::PublishedUncertain(_), FailurePoint::AfterRename)));
            // The disk holds the old digest without a path, or both reviewed values.
            let (actual, _) = registry.read_stored().unwrap();
            let published = failure == FailurePoint::AfterRename;
            assert_eq!(actual.entries[0].digest == snapshot.digest, published);
            assert_eq!(actual.entries[0].development_path.as_deref() == Some(next.as_path()), published);
            assert!(registry.set_development_path("org.example.test", &digest, &path).is_err());
            registry.fail_at = None;
            assert_eq!(registry.retry().unwrap(), PersistenceOutcome::Durable);
            drop(registry);
            let registry = Registry::open(&directory.0).unwrap();
            assert_eq!(registry.entries()[0].digest, snapshot.digest);
            assert_eq!(registry.entries()[0].development_path.as_deref(), Some(next.as_path()));
        }
    }

    #[test]
    fn ordinary_replacement_clears_remembered_path_but_revocation_keeps_it() {
        let directory = Directory::new();
        let path = directory.package("org.example.test", "1.0.0", &["hosts.read"]);
        let mut registry = Registry::open(&directory.0).unwrap();
        registry.install_snapshot(read_development(&path).unwrap(), Some(&path)).unwrap();
        let digest = registry.entries()[0].digest.clone();
        registry.enable("org.example.test", &digest, vec![Permission::HostsRead]).unwrap();
        assert_eq!(registry.revoke("org.example.test").unwrap(), PersistenceOutcome::Durable);
        assert_eq!(registry.entries()[0].development_path.as_deref(), Some(path.as_path()));
        let next = directory.package("org.example.test", "1.1.0", &["hosts.read"]);
        let snapshot = registry.read_source(&next).unwrap();
        assert_eq!(registry.update("org.example.test", &digest, snapshot, Vec::new(), false, None).unwrap(), PersistenceOutcome::Durable);
        drop(registry);
        let registry = Registry::open(&directory.0).unwrap();
        assert!(registry.entries()[0].development_path.is_none());
    }

    #[test]
    fn invalid_development_paths_are_rejected_without_blocking_the_registry() {
        let directory = Directory::new();
        let path = directory.package("org.example.test", "1.0.0", &[]);
        let mut registry = Registry::open(&directory.0).unwrap();
        let snapshot = read_development(&path).unwrap();
        for invalid in [PathBuf::from("relative.vyxext"), PathBuf::from(format!("/{}", "a".repeat(MAX_DEVELOPMENT_PATH_BYTES))),
            PathBuf::from(std::ffi::OsStr::from_bytes(b"/tmp/\xff.vyxext")), PathBuf::from("/tmp/bell\u{7}.vyxext"),
            PathBuf::from("/tmp/\u{202e}txt.vyxext")] {
            assert!(registry.install_snapshot(snapshot.clone(), Some(&invalid)).is_err());
            assert!(!registry.is_blocked());
        }
        let downloaded = Snapshot::downloaded(snapshot.bytes.clone(), official_source()).unwrap();
        assert!(registry.install_snapshot(downloaded, Some(&path)).is_err());
        assert_eq!(registry.install_snapshot(snapshot, Some(&path)).unwrap(), PersistenceOutcome::Durable);
        // A malformed stored path only forfeits remembered approval.
        let mut stored = registry.stored();
        stored.entries[0].development_path = Some(PathBuf::from("relative.vyxext"));
        drop(registry);
        fs::write(directory.0.join("extensions/registry.json"), serde_json::to_vec(&stored).unwrap()).unwrap();
        let registry = Registry::open(&directory.0).unwrap();
        assert!(registry.entries()[0].development_path.is_none());
    }

    #[test]
    fn remembered_development_reattaches_only_exact_bytes_and_never_restores_grants() {
        use super::super::manager::Manager;
        let directory = Directory::new();
        let path = directory.package("org.example.test", "1.0.0", &["hosts.read"]);
        let mut manager = Manager::open(&directory.0).unwrap();
        // An unreviewed local install never acquires remembered approval.
        manager.registry.install(&path).unwrap();
        drop(manager);
        let mut manager = Manager::open(&directory.0).unwrap();
        assert!(manager.development.is_empty());
        let digest = manager.registry.entries()[0].digest.clone();
        // Uncertain persistence attaches nothing until a durable Retry.
        manager.registry.fail_at = Some(FailurePoint::AfterRename);
        assert!(matches!(manager.registry.set_development_path("org.example.test", &digest, &path).unwrap(),
            PersistenceOutcome::PublishedUncertain(_)));
        manager.attach_remembered();
        assert!(manager.development.is_empty());
        manager.registry.fail_at = None;
        assert_eq!(manager.registry.retry().unwrap(), PersistenceOutcome::Durable);
        manager.attach_remembered();
        assert_eq!(manager.development["org.example.test"].digest, digest);
        // The identical reviewed path needs no write, so a failing publisher is never reached.
        manager.registry.fail_at = Some(FailurePoint::BeforeRename);
        assert_eq!(manager.registry.set_development_path("org.example.test", &digest, &path).unwrap(), PersistenceOutcome::Durable);
        manager.registry.fail_at = None;
        manager.registry.enable("org.example.test", &digest, vec![Permission::HostsRead]).unwrap();
        assert_eq!(manager.registry.revoke("org.example.test").unwrap(), PersistenceOutcome::Durable);
        drop(manager);
        let manager = Manager::open(&directory.0).unwrap();
        assert_eq!(manager.development["org.example.test"].digest, digest);
        assert!(!manager.registry.entries()[0].enabled);
        assert!(manager.registry.entries()[0].approved_permissions.is_empty());
        drop(manager);
        // Changed or missing bytes stay installed and remembered, but unattached.
        fs::rename(directory.package("org.example.test", "2.0.0", &["hosts.read"]), &path).unwrap();
        let manager = Manager::open(&directory.0).unwrap();
        assert!(manager.development.is_empty());
        assert_eq!(manager.registry.entries()[0].development_path.as_deref(), Some(path.as_path()));
        drop(manager);
        fs::remove_file(&path).unwrap();
        assert!(Manager::open(&directory.0).unwrap().development.is_empty());
    }
}
