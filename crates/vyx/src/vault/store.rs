use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

use anyhow::{Context, Result, anyhow, bail};
use tempfile::{Builder as TempFileBuilder, NamedTempFile};
use tokio::sync::{mpsc, oneshot, watch};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{
    crypto::{Crypto, MAX_ENVELOPE},
    model::{LocalState, Secret, SyncState, Vault},
};

const STATE_FILE: &str = "state.vyx";
const LOCK_FILE: &str = ".lock";
const CONFLICTS_DIRECTORY: &str = "conflicts";

type StoreEdit = Box<dyn FnOnce(&mut LocalState) -> Result<()> + Send + 'static>;

pub struct Directory {
    path: PathBuf,
    directory_file: File,
    _lock: File,
    initialization: Mutex<()>,
    #[cfg(test)]
    faults: TestFaults,
}

impl Directory {
    pub fn open(path: PathBuf) -> Result<Arc<Self>> {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true).mode(0o700);
        builder
            .create(&path)
            .with_context(|| format!("create data directory {}", path.display()))?;
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("inspect data directory {}", path.display()))?;
        if !metadata.file_type().is_dir() {
            bail!("data path is not a directory: {}", path.display());
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("secure data directory {}", path.display()))?;

        let directory_file =
            File::open(&path).with_context(|| format!("open data directory {}", path.display()))?;
        let lock_path = path.join(LOCK_FILE);
        if let Ok(metadata) = fs::symlink_metadata(&lock_path) {
            if !metadata.file_type().is_file() {
                bail!("lock path is not a regular file: {}", lock_path.display());
            }
        }
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .open(&lock_path)
            .with_context(|| format!("open lock file {}", lock_path.display()))?;
        lock.set_permissions(fs::Permissions::from_mode(0o600))
            .with_context(|| format!("secure lock file {}", lock_path.display()))?;
        lock.try_lock().map_err(|error| {
            let error = io::Error::from(error);
            if error.kind() == io::ErrorKind::WouldBlock {
                anyhow!("data directory is already in use: {}", path.display())
            } else {
                anyhow!(error).context(format!("lock data directory {}", path.display()))
            }
        })?;
        if cleanup_staged_files(&path, ".state.vyx.tmp-")? {
            directory_file
                .sync_all()
                .context("persist staged state cleanup")?;
        }
        let conflicts_path = path.join(CONFLICTS_DIRECTORY);
        if let Ok(metadata) = fs::symlink_metadata(&conflicts_path) {
            if metadata.file_type().is_dir()
                && cleanup_staged_files(&conflicts_path, ".conflict.tmp-")?
            {
                sync_directory_path(&conflicts_path).context("persist staged conflict cleanup")?;
            }
        }

        let state_path = path.join(STATE_FILE);
        if let Ok(metadata) = fs::symlink_metadata(&state_path) {
            if !metadata.file_type().is_file() {
                bail!("state path is not a regular file: {}", state_path.display());
            }
            fs::set_permissions(&state_path, fs::Permissions::from_mode(0o600))
                .with_context(|| format!("secure state file {}", state_path.display()))?;
        }

        Ok(Arc::new(Self {
            path,
            directory_file,
            _lock: lock,
            initialization: Mutex::new(()),
            #[cfg(test)]
            faults: TestFaults::default(),
        }))
    }

    pub fn exists(&self) -> bool {
        fs::symlink_metadata(self.state_path()).is_ok()
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn read_envelope(&self) -> Result<Vec<u8>> {
        read_bounded_regular_file(&self.state_path(), MAX_ENVELOPE)
            .context("read encrypted local state")
    }

    pub async fn create(self: &Arc<Self>, passphrase: Secret) -> Result<Store> {
        let directory = Arc::clone(self);
        let initialized = tokio::task::spawn_blocking(move || {
            let _initialization = directory
                .initialization
                .lock()
                .map_err(|_| anyhow!("vault initialization lock is poisoned"))?;
            if directory.exists() {
                bail!("refusing to overwrite existing state file");
            }

            let crypto = Crypto::create(&passphrase).context("create vault identity")?;
            let mut state = LocalState {
                vault: Vault::new(),
                sync: None,
            };
            state.vault.normalize();
            state.validate()?;
            let envelope = crypto.encrypt_local(&state)?;
            let outcome = atomic_install_new(&directory, &directory.state_path(), &envelope)?;
            drop(_initialization);
            initialize_after_write(directory, crypto, state, outcome)
        })
        .await
        .context("vault creation worker stopped")??;

        Ok(Store::start(initialized))
    }

    pub async fn unlock(self: &Arc<Self>, passphrase: Secret) -> Result<Store> {
        let directory = Arc::clone(self);
        let initialized = tokio::task::spawn_blocking(move || {
            let envelope = directory.read_envelope()?;
            let crypto = Crypto::unlock(&envelope, &passphrase).context("unlock vault identity")?;
            let mut state = crypto
                .decrypt_local(&envelope)
                .context("decrypt local state")?;
            state.vault.normalize();
            state.validate()?;
            File::open(directory.state_path())?
                .sync_all()
                .context("synchronize recovered local state")?;
            directory
                .sync()
                .context("synchronize recovered local directory")?;
            Ok::<_, anyhow::Error>(InitializedStore {
                directory,
                crypto,
                state,
                uncertain: false,
            })
        })
        .await
        .context("vault unlock worker stopped")??;

        Ok(Store::start(initialized))
    }

    pub async fn restore(
        self: &Arc<Self>,
        envelope: Vec<u8>,
        passphrase: Secret,
        sync: Option<SyncState>,
    ) -> Result<Store> {
        if envelope.len() > MAX_ENVELOPE {
            bail!("encrypted vault exceeds the {MAX_ENVELOPE}-byte limit");
        }

        let directory = Arc::clone(self);
        let initialized = tokio::task::spawn_blocking(move || {
            let _initialization = directory
                .initialization
                .lock()
                .map_err(|_| anyhow!("vault initialization lock is poisoned"))?;
            if directory.exists() {
                bail!("refusing to overwrite existing state file");
            }

            let crypto = Crypto::unlock(&envelope, &passphrase).context("unlock restored vault")?;
            let mut vault = crypto
                .decrypt_vault(&envelope)
                .context("restore VaultDocument")?;
            vault.normalize();
            vault.validate()?;
            let mut sync = sync;
            if let Some(sync) = &mut sync {
                if sync.base_etag.is_some() {
                    sync.base_snapshot_id = Some(vault.snapshot_id);
                    sync.base_content_sha256 = Some(vault.content_sha256()?);
                }
            }
            let state = LocalState { vault, sync };
            state.validate()?;
            let local_envelope = crypto.encrypt_local(&state)?;
            let outcome = atomic_install_new(&directory, &directory.state_path(), &local_envelope)?;
            drop(_initialization);
            initialize_after_write(directory, crypto, state, outcome)
        })
        .await
        .context("vault restore worker stopped")??;

        Ok(Store::start(initialized))
    }

    fn state_path(&self) -> PathBuf {
        self.path.join(STATE_FILE)
    }

    fn sync(&self) -> Result<()> {
        #[cfg(test)]
        self.faults.maybe_fail_directory_sync()?;
        self.directory_file
            .sync_all()
            .with_context(|| format!("sync data directory {}", self.path.display()))
    }

    fn maybe_fail_before_rename(&self) -> Result<()> {
        #[cfg(test)]
        self.faults.maybe_fail_before_rename()?;
        Ok(())
    }
}

struct InitializedStore {
    directory: Arc<Directory>,
    crypto: Crypto,
    state: LocalState,
    uncertain: bool,
}

fn initialize_after_write(
    directory: Arc<Directory>,
    crypto: Crypto,
    state: LocalState,
    outcome: AtomicWrite,
) -> Result<InitializedStore> {
    match outcome {
        AtomicWrite::Durable => Ok(InitializedStore {
            directory,
            crypto,
            state,
            uncertain: false,
        }),
        AtomicWrite::Uncertain(_sync_error) => {
            let envelope = directory.read_envelope()?;
            let mut actual = crypto
                .decrypt_local(&envelope)
                .context("reload local state after uncertain directory sync")?;
            actual.vault.normalize();
            actual.validate()?;
            Ok(InitializedStore {
                directory,
                crypto,
                state: actual,
                uncertain: true,
            })
        }
    }
}

#[derive(Clone)]
pub struct Store {
    core: Arc<StoreCore>,
}

struct StoreCore {
    directory: Arc<Directory>,
    commands: mpsc::UnboundedSender<Command>,
    snapshots: watch::Sender<Arc<LocalState>>,
    uncertain: Arc<AtomicBool>,
}

impl Store {
    fn start(initialized: InitializedStore) -> Self {
        let initial = Arc::new(initialized.state);
        let (snapshots, _) = watch::channel(Arc::clone(&initial));
        let uncertain = Arc::new(AtomicBool::new(initialized.uncertain));
        let writer = Arc::new(Mutex::new(Writer {
            directory: Arc::clone(&initialized.directory),
            crypto: initialized.crypto,
            current: initial,
            snapshots: snapshots.clone(),
            uncertain: Arc::clone(&uncertain),
        }));
        let (commands, mut receiver) = mpsc::unbounded_channel();

        tokio::spawn(async move {
            while let Some(command) = receiver.recv().await {
                let writer = Arc::clone(&writer);
                let _ = tokio::task::spawn_blocking(move || {
                    let result = writer.lock();
                    match result {
                        Ok(mut writer) => writer.execute(command),
                        Err(_) => command.fail(anyhow!("vault writer lock is poisoned")),
                    }
                })
                .await;
            }
        });

        Self {
            core: Arc::new(StoreCore {
                directory: initialized.directory,
                commands,
                snapshots,
                uncertain,
            }),
        }
    }

    pub fn snapshot(&self) -> Arc<LocalState> {
        Arc::clone(&self.core.snapshots.borrow())
    }

    pub fn subscribe(&self) -> watch::Receiver<Arc<LocalState>> {
        self.core.snapshots.subscribe()
    }

    pub fn data_dir(&self) -> &Path {
        self.core.directory.path()
    }

    pub fn is_uncertain(&self) -> bool {
        self.core.uncertain.load(Ordering::Acquire)
    }

    pub async fn commit<F>(&self, vault_changed: bool, edit: F) -> Result<Arc<LocalState>>
    where
        F: FnOnce(&mut LocalState) -> Result<()> + Send + 'static,
    {
        let (result, response) = oneshot::channel();
        self.core
            .commands
            .send(Command::Commit {
                vault_changed,
                edit: Box::new(edit),
                result,
            })
            .map_err(|_| anyhow!("vault writer is unavailable"))?;
        response.await.context("vault writer stopped")?
    }

    pub async fn retry_save(&self) -> Result<()> {
        let (result, response) = oneshot::channel();
        self.core
            .commands
            .send(Command::RetrySave { result })
            .map_err(|_| anyhow!("vault writer is unavailable"))?;
        response.await.context("vault writer stopped")?
    }

    pub async fn drain(&self) -> Result<()> {
        let (result, response) = oneshot::channel();
        self.core
            .commands
            .send(Command::Drain { result })
            .map_err(|_| anyhow!("vault writer is unavailable"))?;
        response.await.context("vault writer stopped")?
    }

    pub async fn export_vault(&self, vault: Vault) -> Result<Vec<u8>> {
        let (result, response) = oneshot::channel();
        self.core
            .commands
            .send(Command::ExportVault { vault, result })
            .map_err(|_| anyhow!("vault writer is unavailable"))?;
        response.await.context("vault writer stopped")?
    }

    pub async fn decode_vault(&self, envelope: Vec<u8>) -> Result<Vault> {
        if envelope.len() > MAX_ENVELOPE {
            bail!("encrypted vault exceeds the {MAX_ENVELOPE}-byte limit");
        }
        let (result, response) = oneshot::channel();
        self.core
            .commands
            .send(Command::DecodeVault { envelope, result })
            .map_err(|_| anyhow!("vault writer is unavailable"))?;
        response.await.context("vault writer stopped")?
    }

    pub async fn preserve_conflict(&self, vault: Vault) -> Result<PathBuf> {
        let (result, response) = oneshot::channel();
        self.core
            .commands
            .send(Command::PreserveConflict { vault, result })
            .map_err(|_| anyhow!("vault writer is unavailable"))?;
        response.await.context("vault writer stopped")?
    }
}

enum Command {
    Commit {
        vault_changed: bool,
        edit: StoreEdit,
        result: oneshot::Sender<Result<Arc<LocalState>>>,
    },
    RetrySave {
        result: oneshot::Sender<Result<()>>,
    },
    Drain {
        result: oneshot::Sender<Result<()>>,
    },
    ExportVault {
        vault: Vault,
        result: oneshot::Sender<Result<Vec<u8>>>,
    },
    DecodeVault {
        envelope: Vec<u8>,
        result: oneshot::Sender<Result<Vault>>,
    },
    PreserveConflict {
        vault: Vault,
        result: oneshot::Sender<Result<PathBuf>>,
    },
}

impl Command {
    fn fail(self, error: anyhow::Error) {
        match self {
            Self::Commit { result, .. } => {
                let _ = result.send(Err(error));
            }
            Self::RetrySave { result } | Self::Drain { result } => {
                let _ = result.send(Err(error));
            }
            Self::ExportVault { result, .. } => {
                let _ = result.send(Err(error));
            }
            Self::DecodeVault { result, .. } => {
                let _ = result.send(Err(error));
            }
            Self::PreserveConflict { result, .. } => {
                let _ = result.send(Err(error));
            }
        }
    }
}

struct Writer {
    directory: Arc<Directory>,
    crypto: Crypto,
    current: Arc<LocalState>,
    snapshots: watch::Sender<Arc<LocalState>>,
    uncertain: Arc<AtomicBool>,
}

impl Writer {
    fn execute(&mut self, command: Command) {
        match command {
            Command::Commit {
                vault_changed,
                edit,
                result,
            } => {
                let _ = result.send(self.commit(vault_changed, edit));
            }
            Command::RetrySave { result } => {
                let _ = result.send(self.retry_save());
            }
            Command::Drain { result } => {
                let _ = result.send(Ok(()));
            }
            Command::ExportVault { vault, result } => {
                let _ = result.send(self.export_vault(vault));
            }
            Command::DecodeVault { envelope, result } => {
                let _ = result.send(self.decode_vault(envelope));
            }
            Command::PreserveConflict { vault, result } => {
                let _ = result.send(self.preserve_conflict(vault));
            }
        }
    }

    fn commit(&mut self, vault_changed: bool, edit: StoreEdit) -> Result<Arc<LocalState>> {
        if self.uncertain.load(Ordering::Acquire) {
            bail!("Save durability uncertain; Retry save before making another change");
        }

        let mut next = (*self.current).clone();
        edit(&mut next)?;
        if vault_changed {
            next.vault.snapshot_id = Uuid::new_v4();
        }
        next.vault.normalize();
        next.validate()?;
        let envelope = self.crypto.encrypt_local(&next)?;

        match atomic_replace(&self.directory, &self.directory.state_path(), &envelope)? {
            AtomicWrite::Durable => {
                let next = Arc::new(next);
                self.publish(Arc::clone(&next));
                Ok(next)
            }
            AtomicWrite::Uncertain(sync_error) => {
                self.uncertain.store(true, Ordering::Release);
                let reload = self.reload_actual();
                match reload {
                    Ok(actual) => self.publish(actual),
                    Err(reload_error) => {
                        return Err(reload_error).context(format!(
                            "Save durability uncertain after directory sync failed ({sync_error:#})"
                        ));
                    }
                }
                bail!("Save durability uncertain: {sync_error:#}")
            }
        }
    }

    fn retry_save(&mut self) -> Result<()> {
        if !self.uncertain.load(Ordering::Acquire) {
            return Ok(());
        }

        let actual = self.reload_actual()?;
        let state_file = File::open(self.directory.state_path())
            .context("open uncertain local state for synchronization")?;
        state_file
            .sync_all()
            .context("synchronize uncertain local state")?;
        self.directory.sync()?;
        self.publish(actual);
        self.uncertain.store(false, Ordering::Release);
        Ok(())
    }

    fn export_vault(&self, mut vault: Vault) -> Result<Vec<u8>> {
        if self.uncertain.load(Ordering::Acquire) {
            bail!("Save durability uncertain; Retry save before uploading");
        }
        vault.normalize();
        vault.validate()?;
        self.crypto.encrypt_vault(&vault)
    }

    fn decode_vault(&self, envelope: Vec<u8>) -> Result<Vault> {
        if envelope.len() > MAX_ENVELOPE {
            bail!("encrypted vault exceeds the {MAX_ENVELOPE}-byte limit");
        }
        let mut vault = self.crypto.decrypt_vault(&envelope)?;
        vault.normalize();
        vault.validate()?;
        Ok(vault)
    }

    fn preserve_conflict(&self, mut vault: Vault) -> Result<PathBuf> {
        vault.normalize();
        vault.validate()?;
        let conflicts = self.directory.path().join(CONFLICTS_DIRECTORY);
        ensure_private_directory(&conflicts)?;
        self.directory
            .sync()
            .context("persist conflicts directory")?;

        let destination = conflicts.join(format!("{}.vyx", vault.snapshot_id));
        if fs::symlink_metadata(&destination).is_ok() {
            verify_existing_conflict(&self.crypto, &destination, &vault)?;
            sync_existing_conflict(&destination, &conflicts)?;
            return Ok(destination);
        }

        let envelope = self.crypto.encrypt_vault(&vault)?;
        let staged = stage_file(&conflicts, ".conflict.tmp-", &envelope)?;
        self.directory.maybe_fail_before_rename()?;
        match staged.persist_noclobber(&destination) {
            Ok(_file) => {}
            Err(error) if error.error.kind() == io::ErrorKind::AlreadyExists => {
                drop(error.file);
                verify_existing_conflict(&self.crypto, &destination, &vault)?;
                sync_existing_conflict(&destination, &conflicts)?;
                return Ok(destination);
            }
            Err(error) => {
                return Err(error.error).with_context(|| {
                    format!("install conflict snapshot {}", destination.display())
                });
            }
        }

        sync_directory_path(&conflicts)
            .with_context(|| format!("persist conflict snapshot {}", destination.display()))?;
        Ok(destination)
    }

    fn reload_actual(&self) -> Result<Arc<LocalState>> {
        let envelope = self.directory.read_envelope()?;
        let mut actual = self
            .crypto
            .decrypt_local(&envelope)
            .context("reload encrypted local state")?;
        actual.vault.normalize();
        actual.validate()?;
        Ok(Arc::new(actual))
    }

    fn publish(&mut self, state: Arc<LocalState>) {
        self.current = Arc::clone(&state);
        self.snapshots.send_replace(state);
    }
}

fn verify_existing_conflict(crypto: &Crypto, path: &Path, expected: &Vault) -> Result<()> {
    let envelope = read_bounded_regular_file(path, MAX_ENVELOPE)
        .with_context(|| format!("read existing conflict snapshot {}", path.display()))?;
    let mut existing = crypto
        .decrypt_vault(&envelope)
        .with_context(|| format!("decrypt existing conflict snapshot {}", path.display()))?;
    existing.normalize();
    existing.validate()?;
    if !vaults_are_identical(&existing, expected)? {
        bail!(
            "conflict snapshot already exists with different content: {}",
            path.display()
        );
    }
    Ok(())
}

fn vaults_are_identical(left: &Vault, right: &Vault) -> Result<bool> {
    let mut left = left.clone();
    let mut right = right.clone();
    left.normalize();
    right.normalize();
    left.validate()?;
    right.validate()?;
    let left = Zeroizing::new(serde_json::to_vec(&left)?);
    let right = Zeroizing::new(serde_json::to_vec(&right)?);
    Ok(left.as_slice() == right.as_slice())
}

fn sync_existing_conflict(path: &Path, directory: &Path) -> Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("secure conflict snapshot {}", path.display()))?;
    File::open(path)
        .with_context(|| format!("open conflict snapshot {}", path.display()))?
        .sync_all()
        .with_context(|| format!("sync conflict snapshot {}", path.display()))?;
    sync_directory_path(directory)
        .with_context(|| format!("sync conflicts directory {}", directory.display()))
}

fn ensure_private_directory(path: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    match builder.create(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let metadata = fs::symlink_metadata(path)
                .with_context(|| format!("inspect directory {}", path.display()))?;
            if !metadata.file_type().is_dir() {
                bail!("path is not a directory: {}", path.display());
            }
        }
        Err(error) => {
            return Err(error).with_context(|| format!("create directory {}", path.display()));
        }
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("secure directory {}", path.display()))
}

fn atomic_install_new(directory: &Directory, path: &Path, bytes: &[u8]) -> Result<AtomicWrite> {
    if fs::symlink_metadata(path).is_ok() {
        bail!("refusing to overwrite existing file: {}", path.display());
    }
    let staged = stage_file(directory.path(), ".state.vyx.tmp-", bytes)?;
    directory.maybe_fail_before_rename()?;
    match staged.persist_noclobber(path) {
        Ok(_file) => {}
        Err(error) if error.error.kind() == io::ErrorKind::AlreadyExists => {
            drop(error.file);
            bail!("refusing to overwrite existing file: {}", path.display());
        }
        Err(error) => {
            return Err(error.error)
                .with_context(|| format!("install new file {}", path.display()));
        }
    }
    match directory.sync() {
        Ok(()) => Ok(AtomicWrite::Durable),
        Err(error) => Ok(AtomicWrite::Uncertain(error)),
    }
}

fn atomic_replace(directory: &Directory, path: &Path, bytes: &[u8]) -> Result<AtomicWrite> {
    let staged = stage_file(directory.path(), ".state.vyx.tmp-", bytes)?;
    directory.maybe_fail_before_rename()?;
    match staged.persist(path) {
        Ok(_file) => {}
        Err(error) => {
            return Err(error.error)
                .with_context(|| format!("replace encrypted state {}", path.display()));
        }
    }
    match directory.sync() {
        Ok(()) => Ok(AtomicWrite::Durable),
        Err(error) => Ok(AtomicWrite::Uncertain(error)),
    }
}

fn stage_file(directory: &Path, prefix: &str, bytes: &[u8]) -> Result<NamedTempFile> {
    if bytes.len() > MAX_ENVELOPE {
        bail!("encrypted envelope exceeds the {MAX_ENVELOPE}-byte limit");
    }
    let mut staged = TempFileBuilder::new()
        .prefix(prefix)
        .tempfile_in(directory)
        .with_context(|| format!("create staged file in {}", directory.display()))?;
    staged
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))
        .context("secure staged file")?;
    staged
        .write_all(bytes)
        .context("write staged encrypted data")?;
    staged
        .as_file()
        .sync_all()
        .context("sync staged encrypted data")?;
    Ok(staged)
}
fn cleanup_staged_files(directory: &Path, prefix: &str) -> Result<bool> {
    let mut removed = false;
    for entry in fs::read_dir(directory)
        .with_context(|| format!("inspect directory {}", directory.display()))?
    {
        let entry =
            entry.with_context(|| format!("inspect directory entry in {}", directory.display()))?;
        let name = entry.file_name();
        if !name.to_string_lossy().starts_with(prefix) {
            continue;
        }
        let file_type = entry
            .file_type()
            .with_context(|| format!("inspect staged file {}", entry.path().display()))?;
        if !file_type.is_file() && !file_type.is_symlink() {
            bail!(
                "staged-file path is not a regular file: {}",
                entry.path().display()
            );
        }
        fs::remove_file(entry.path())
            .with_context(|| format!("remove stale staged file {}", entry.path().display()))?;
        removed = true;
    }
    Ok(removed)
}

fn read_bounded_regular_file(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    let path_metadata =
        fs::symlink_metadata(path).with_context(|| format!("inspect file {}", path.display()))?;
    if !path_metadata.file_type().is_file() {
        bail!("path is not a regular file: {}", path.display());
    }
    if path_metadata.len() > maximum as u64 {
        bail!("file exceeds the {maximum}-byte limit: {}", path.display());
    }

    let file = File::open(path).with_context(|| format!("open file {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect open file {}", path.display()))?;
    if !metadata.is_file() {
        bail!("path is not a regular file: {}", path.display());
    }
    if metadata.len() > maximum as u64 {
        bail!("file exceeds the {maximum}-byte limit: {}", path.display());
    }

    let mut bytes = Vec::with_capacity((metadata.len() as usize).min(maximum));
    file.take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read file {}", path.display()))?;
    if bytes.len() > maximum {
        bail!("file exceeds the {maximum}-byte limit: {}", path.display());
    }
    Ok(bytes)
}

fn sync_directory_path(path: &Path) -> Result<()> {
    File::open(path)
        .with_context(|| format!("open directory {}", path.display()))?
        .sync_all()
        .with_context(|| format!("sync directory {}", path.display()))
}

enum AtomicWrite {
    Durable,
    Uncertain(anyhow::Error),
}

#[cfg(test)]
#[derive(Default)]
struct TestFaults {
    fail_before_rename: std::sync::atomic::AtomicUsize,
    fail_directory_sync: std::sync::atomic::AtomicUsize,
}

#[cfg(test)]
impl TestFaults {
    fn fail_before_rename_once(&self) {
        self.fail_before_rename.fetch_add(1, Ordering::Relaxed);
    }

    fn fail_directory_sync_once(&self) {
        self.fail_directory_sync.fetch_add(1, Ordering::Relaxed);
    }

    fn maybe_fail_before_rename(&self) -> Result<()> {
        if consume_fault(&self.fail_before_rename) {
            bail!("injected failure before rename");
        }
        Ok(())
    }

    fn maybe_fail_directory_sync(&self) -> Result<()> {
        if consume_fault(&self.fail_directory_sync) {
            bail!("injected directory sync failure");
        }
        Ok(())
    }
}

#[cfg(test)]
fn consume_fault(counter: &std::sync::atomic::AtomicUsize) -> bool {
    counter
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_sub(1)
        })
        .is_ok()
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc as std_mpsc;

    use super::*;
    use crate::vault::model::Category;

    fn passphrase() -> Secret {
        Secret::new("sixteen character test passphrase")
    }

    #[test]
    fn atomic_replace_preserves_old_file_before_rename_and_reports_postrename_uncertainty() {
        let temporary = tempfile::tempdir().unwrap();
        let directory = Directory::open(temporary.path().join("vault")).unwrap();
        let state_path = directory.state_path();
        fs::write(&state_path, b"old").unwrap();
        fs::set_permissions(&state_path, fs::Permissions::from_mode(0o600)).unwrap();

        directory.faults.fail_before_rename_once();
        assert!(atomic_replace(&directory, &state_path, b"not-installed").is_err());
        assert_eq!(fs::read(&state_path).unwrap(), b"old");

        directory.faults.fail_directory_sync_once();
        assert!(matches!(
            atomic_replace(&directory, &state_path, b"installed"),
            Ok(AtomicWrite::Uncertain(_))
        ));
        assert_eq!(fs::read(&state_path).unwrap(), b"installed");
        assert_eq!(
            fs::metadata(directory.path()).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(directory.path().join(LOCK_FILE))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(&state_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn accepted_commits_survive_cancellation_serialize_and_recover_uncertainty() {
        let temporary = tempfile::tempdir().unwrap();
        let directory = Directory::open(temporary.path().join("vault")).unwrap();
        directory.faults.fail_directory_sync_once();
        let store = directory.create(passphrase()).await.unwrap();
        assert!(store.is_uncertain());
        store.retry_save().await.unwrap();
        assert!(!store.is_uncertain());

        let (first_entered, first_started) = oneshot::channel();
        let (release_first, wait_first) = std_mpsc::channel();
        let first_store = store.clone();
        let first = tokio::spawn(async move {
            first_store
                .commit(true, move |state| {
                    let _ = first_entered.send(());
                    wait_first.recv().unwrap();
                    state.vault.categories.push(Category {
                        id: Uuid::new_v4(),
                        label: "first".into(),
                        parent_id: None,
                    });
                    Ok(())
                })
                .await
        });
        first_started.await.unwrap();
        first.abort();

        let (second_entered, second_started) = oneshot::channel();
        let (release_second, wait_second) = std_mpsc::channel();
        let second_store = store.clone();
        let second = tokio::spawn(async move {
            second_store
                .commit(true, move |state| {
                    let _ = second_entered.send(());
                    wait_second.recv().unwrap();
                    state.vault.categories.push(Category {
                        id: Uuid::new_v4(),
                        label: "second".into(),
                        parent_id: None,
                    });
                    Ok(())
                })
                .await
        });

        release_first.send(()).unwrap();
        second_started.await.unwrap();
        second.abort();
        release_second.send(()).unwrap();
        store.drain().await.unwrap();
        assert_eq!(store.snapshot().vault.categories.len(), 2);

        directory.faults.fail_directory_sync_once();
        let error = store
            .commit(true, |state| {
                state.vault.categories.push(Category {
                    id: Uuid::new_v4(),
                    label: "uncertain".into(),
                    parent_id: None,
                });
                Ok(())
            })
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("Save durability uncertain"));
        assert!(store.is_uncertain());
        assert_eq!(store.snapshot().vault.categories.len(), 3);
        assert!(store.commit(false, |_| Ok(())).await.is_err());

        store.retry_save().await.unwrap();
        assert!(!store.is_uncertain());
        store.commit(false, |_| Ok(())).await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn export_restore_and_conflict_backup_require_semantically_identical_content() {
        let temporary = tempfile::tempdir().unwrap();
        let first_directory = Directory::open(temporary.path().join("first")).unwrap();
        let first = first_directory.create(passphrase()).await.unwrap();
        let saved = first
            .commit(true, |state| {
                state.vault.categories.push(Category {
                    id: Uuid::new_v4(),
                    label: "kept".into(),
                    parent_id: None,
                });
                Ok(())
            })
            .await
            .unwrap();
        let envelope = first.export_vault(saved.vault.clone()).await.unwrap();
        assert_eq!(
            first
                .decode_vault(envelope.clone())
                .await
                .unwrap()
                .content_sha256()
                .unwrap(),
            saved.vault.content_sha256().unwrap()
        );

        let backup = first.preserve_conflict(saved.vault.clone()).await.unwrap();
        assert_eq!(
            first.preserve_conflict(saved.vault.clone()).await.unwrap(),
            backup
        );
        let mut different = saved.vault.clone();
        different.categories[0].label = "different".into();
        assert!(first.preserve_conflict(different).await.is_err());

        let second_directory = Directory::open(temporary.path().join("second")).unwrap();
        let etag = format!("\"{}\"", "0".repeat(64));
        let second = second_directory
            .restore(
                envelope,
                passphrase(),
                Some(SyncState {
                    url: "http://127.0.0.1:8080".into(),
                    token: Secret::new("a".repeat(64)),
                    base_etag: Some(etag.clone()),
                    base_snapshot_id: None,
                    base_content_sha256: None,
                    pending_upload: None,
                }),
            )
            .await
            .unwrap();
        assert_eq!(
            second.snapshot().vault.content_sha256().unwrap(),
            saved.vault.content_sha256().unwrap()
        );
        let restored = second.snapshot();
        let checkpoint = restored.sync.as_ref().unwrap();
        let expected_content_sha256 = saved.vault.content_sha256().unwrap();
        assert_eq!(checkpoint.base_etag.as_deref(), Some(etag.as_str()));
        assert_eq!(checkpoint.base_snapshot_id, Some(saved.vault.snapshot_id));
        assert_eq!(
            checkpoint.base_content_sha256.as_deref(),
            Some(expected_content_sha256.as_str())
        );
    }
}
