use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{
        Arc, RwLock, TryLockError,
        atomic::{AtomicBool, Ordering},
    },
};

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use tempfile::TempPath;

use crate::auth;

pub(crate) const MAX_VAULT_BYTES: u64 = 16 * 1024 * 1024;
const LOCK_FILE: &str = ".lock";
const VAULT_FILE: &str = "vault.vyx";
pub(crate) const UPLOAD_PREFIX: &str = ".vyx-upload-";

pub(crate) struct LockedDirectory {
    path: PathBuf,
    _lock: File,
}

impl LockedDirectory {
    pub(crate) fn acquire(path: &Path) -> Result<Self> {
        fs::create_dir_all(path).context("creating data directory")?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .context("setting data directory permissions")?;

        let lock_path = path.join(LOCK_FILE);
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .open(&lock_path)
            .context("opening store lock")?;
        lock.set_permissions(fs::Permissions::from_mode(0o600))
            .context("setting store lock permissions")?;
        lock.try_lock()
            .map_err(io::Error::from)
            .context("the data directory is already in use")?;

        Ok(Self {
            path: path.to_path_buf(),
            _lock: lock,
        })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

struct Published {
    etag: Option<String>,
    durability_uncertain: bool,
}

pub(crate) struct ServerStore {
    directory: LockedDirectory,
    auth_digest: [u8; 32],
    published: RwLock<Published>,
    durability_ready: AtomicBool,
    #[cfg(test)]
    faults: TestFaults,
}

pub(crate) struct CapturedVault {
    pub(crate) file: File,
    pub(crate) etag: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Precondition {
    NoneMatchAny,
    Match(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CommitSuccess {
    Created(String),
    Replaced(String),
}

#[derive(Debug)]
pub(crate) enum CommitError {
    PreconditionFailed,
    InvalidStage,
    Io(io::Error),
    DurabilityUncertain(io::Error),
}

pub(crate) struct StagedUpload {
    pub(crate) file: File,
    pub(crate) path: TempPath,
    pub(crate) etag: String,
    pub(crate) length: u64,
}

impl ServerStore {
    pub(crate) fn open(data_dir: &Path) -> Result<Arc<Self>> {
        let directory = LockedDirectory::acquire(data_dir)?;
        let auth_digest = auth::load_digest(directory.path())?;
        remove_stale_uploads(directory.path())?;

        auth::sync_auth_file(directory.path()).context("synchronizing authentication state")?;
        let etag = load_vault(directory.path())?;
        sync_directory(directory.path()).context("synchronizing data directory")?;

        Ok(Arc::new(Self {
            directory,
            auth_digest,
            published: RwLock::new(Published {
                etag,
                durability_uncertain: false,
            }),
            durability_ready: AtomicBool::new(true),
            #[cfg(test)]
            faults: TestFaults::default(),
        }))
    }

    pub(crate) fn auth_digest(&self) -> [u8; 32] {
        self.auth_digest
    }

    pub(crate) fn data_dir(&self) -> &Path {
        self.directory.path()
    }

    pub(crate) fn is_ready(&self) -> bool {
        if !self.durability_ready.load(Ordering::Acquire) {
            return false;
        }
        match self.published.try_read() {
            Ok(published) => !published.durability_uncertain,
            Err(TryLockError::WouldBlock) => true,
            Err(TryLockError::Poisoned(_)) => false,
        }
    }

    pub(crate) fn ensure_ready(&self) -> io::Result<()> {
        let mut published = self.published.write().map_err(|_| poisoned_store_lock())?;
        self.retry_uncertain_locked(&mut published)
    }

    pub(crate) fn capture(&self) -> io::Result<Option<CapturedVault>> {
        let mut retried = false;
        loop {
            let published = self.published.read().map_err(|_| poisoned_store_lock())?;
            if published.durability_uncertain {
                drop(published);
                if retried {
                    return Err(io::Error::other("vault durability remains uncertain"));
                }
                self.ensure_ready()?;
                retried = true;
                continue;
            }

            let Some(etag) = published.etag.clone() else {
                return Ok(None);
            };
            let file = File::open(self.directory.path().join(VAULT_FILE))?;
            return Ok(Some(CapturedVault { file, etag }));
        }
    }

    pub(crate) fn commit(
        &self,
        staged: StagedUpload,
        precondition: Precondition,
    ) -> std::result::Result<CommitSuccess, CommitError> {
        if staged.length == 0 || staged.length > MAX_VAULT_BYTES || !is_hex_digest(&staged.etag) {
            return Err(CommitError::InvalidStage);
        }

        let mut published = self
            .published
            .write()
            .map_err(|_| CommitError::Io(poisoned_store_lock()))?;
        self.retry_uncertain_locked(&mut published)
            .map_err(CommitError::Io)?;

        let created = match (&published.etag, &precondition) {
            (None, Precondition::NoneMatchAny) => true,
            (Some(current), Precondition::Match(expected)) if current == expected => false,
            _ => return Err(CommitError::PreconditionFailed),
        };

        staged.file.sync_all().map_err(CommitError::Io)?;
        drop(staged.file);

        #[cfg(test)]
        self.faults.before_rename();

        staged
            .path
            .persist(self.directory.path().join(VAULT_FILE))
            .map_err(|error| CommitError::Io(error.error))?;
        published.etag = Some(staged.etag.clone());

        if let Err(error) = self.sync_directory_for_commit() {
            published.durability_uncertain = true;
            self.durability_ready.store(false, Ordering::Release);
            return Err(CommitError::DurabilityUncertain(error));
        }
        published.durability_uncertain = false;
        self.durability_ready.store(true, Ordering::Release);

        if created {
            Ok(CommitSuccess::Created(staged.etag))
        } else {
            Ok(CommitSuccess::Replaced(staged.etag))
        }
    }

    fn retry_uncertain_locked(&self, published: &mut Published) -> io::Result<()> {
        if !published.durability_uncertain {
            return Ok(());
        }

        File::open(self.directory.path().join(VAULT_FILE))?.sync_all()?;
        self.sync_directory_for_commit()?;
        published.durability_uncertain = false;
        self.durability_ready.store(true, Ordering::Release);
        Ok(())
    }

    fn sync_directory_for_commit(&self) -> io::Result<()> {
        #[cfg(test)]
        if self
            .faults
            .fail_next_directory_sync
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(io::Error::other(
                "injected directory synchronization failure",
            ));
        }
        sync_directory(self.directory.path())
    }

    #[cfg(test)]
    pub(crate) fn fail_next_directory_sync(&self) {
        self.faults
            .fail_next_directory_sync
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    #[cfg(test)]
    pub(crate) fn pause_next_before_rename(
        &self,
        entered: std::sync::mpsc::SyncSender<()>,
        resume: std::sync::mpsc::Receiver<()>,
    ) {
        *self
            .faults
            .pause_before_rename
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Pause { entered, resume });
    }
}

fn poisoned_store_lock() -> io::Error {
    io::Error::other("vault store lock is poisoned")
}

pub(crate) fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(test)]
pub(crate) fn etag_for_bytes(bytes: &[u8]) -> String {
    encode_digest(Sha256::digest(bytes).into())
}

fn load_vault(data_dir: &Path) -> Result<Option<String>> {
    let path = data_dir.join(VAULT_FILE);
    let mut file = match File::open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("opening stored vault"),
    };
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .context("setting stored vault permissions")?;
    let metadata = file.metadata().context("reading stored vault metadata")?;
    if !metadata.is_file() || metadata.len() == 0 {
        bail!("stored vault is not a non-empty regular file");
    }
    if metadata.len() > MAX_VAULT_BYTES {
        bail!("stored vault exceeds the 16 MiB limit");
    }

    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).context("reading stored vault")?;
        if read == 0 {
            break;
        }
        total += read as u64;
        if total > MAX_VAULT_BYTES {
            bail!("stored vault exceeds the 16 MiB limit");
        }
        hasher.update(&buffer[..read]);
    }
    file.sync_all().context("synchronizing stored vault")?;
    Ok(Some(encode_digest(hasher.finalize().into())))
}

fn remove_stale_uploads(data_dir: &Path) -> Result<()> {
    for entry in fs::read_dir(data_dir).context("scanning data directory")? {
        let entry = entry.context("reading data directory entry")?;
        let name = entry.file_name();
        if name
            .as_encoded_bytes()
            .starts_with(UPLOAD_PREFIX.as_bytes())
            && entry
                .file_type()
                .context("reading upload stage file type")?
                .is_file()
        {
            fs::remove_file(entry.path()).context("removing stale upload stage")?;
        }
    }
    Ok(())
}

pub(crate) fn encode_digest(bytes: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for byte in bytes {
        encoded.push(HEX[usize::from(byte >> 4)] as char);
        encoded.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    encoded
}

fn is_hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
#[derive(Default)]
struct TestFaults {
    fail_next_directory_sync: std::sync::atomic::AtomicBool,
    pause_before_rename: std::sync::Mutex<Option<Pause>>,
}

#[cfg(test)]
struct Pause {
    entered: std::sync::mpsc::SyncSender<()>,
    resume: std::sync::mpsc::Receiver<()>,
}

#[cfg(test)]
impl TestFaults {
    fn before_rename(&self) {
        let pause = self
            .pause_before_rename
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(pause) = pause {
            let _ = pause.entered.send(());
            let _ = pause.resume.recv();
        }
    }
}

#[cfg(test)]
pub(crate) fn stage_bytes(data_dir: &Path, bytes: &[u8]) -> StagedUpload {
    use std::io::Write;

    let mut temporary = tempfile::Builder::new()
        .prefix(UPLOAD_PREFIX)
        .tempfile_in(data_dir)
        .unwrap();
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))
        .unwrap();
    temporary.write_all(bytes).unwrap();
    let (file, path) = temporary.into_parts();
    StagedUpload {
        file,
        path,
        etag: etag_for_bytes(bytes),
        length: bytes.len() as u64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn concurrent_compare_and_swap_has_one_winner() {
        let temporary = tempfile::tempdir().unwrap();
        auth::initialize(temporary.path()).unwrap();
        let store = ServerStore::open(temporary.path()).unwrap();
        let first = stage_bytes(temporary.path(), b"first");
        let second = stage_bytes(temporary.path(), b"second");
        let barrier = Arc::new(std::sync::Barrier::new(3));

        let one = {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                store.commit(first, Precondition::NoneMatchAny)
            })
        };
        let two = {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                store.commit(second, Precondition::NoneMatchAny)
            })
        };
        barrier.wait();

        let results = [one.join().unwrap(), two.join().unwrap()];
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(CommitError::PreconditionFailed)))
                .count(),
            1
        );
        let stored = fs::read(temporary.path().join(VAULT_FILE)).unwrap();
        assert!(stored == b"first" || stored == b"second");
    }

    #[test]
    fn startup_removes_only_owned_upload_stages() {
        let temporary = tempfile::tempdir().unwrap();
        auth::initialize(temporary.path()).unwrap();
        fs::write(temporary.path().join(".vyx-upload-abandoned"), b"partial").unwrap();
        fs::write(temporary.path().join("unrelated.tmp"), b"keep").unwrap();

        let _store = ServerStore::open(temporary.path()).unwrap();
        assert!(!temporary.path().join(".vyx-upload-abandoned").exists());
        assert!(temporary.path().join("unrelated.tmp").exists());
    }
}
