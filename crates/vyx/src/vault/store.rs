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

use anyhow::{Context, Result, anyhow, bail, ensure};
use tempfile::{Builder as TempFileBuilder, NamedTempFile};
use tokio::sync::{mpsc, oneshot, watch};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{
    crypto::{Crypto, MAX_ENVELOPE, MAX_RECOVERY_FILE},
    model::{LocalState, Secret, SyncState, Vault},
};

const STATE_FILE: &str = "state.vyx";
const LOCK_FILE: &str = ".lock";
const CONFLICTS_DIRECTORY: &str = "conflicts";
const RECOVERY_LOCAL_ONLY: &str =
    "Recovery is available only for local-only vaults; synchronized vaults cannot be reset here.";
const RECOVERY_SAVE_WARNING: &str = "Recovery file saved, but durability could not be confirmed. Keep another verified copy before relying on it.";

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
        #[cfg(test)]
        if consume_fault(&self.faults.fail_envelope_read) {
            bail!("injected encrypted state read failure");
        }
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
            let mut state = LocalState::new(Vault::new(), None);
            state.normalize();
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
            state.normalize();
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

    pub async fn recover(self: &Arc<Self>, file: PathBuf, new: Secret) -> Result<Store> {
        let directory = Arc::clone(self);
        let initialized = tokio::task::spawn_blocking(move || {
            let initialization = directory
                .initialization
                .lock()
                .map_err(|_| anyhow!("vault initialization lock is poisoned"))?;
            let envelope = directory.read_envelope()?;
            let recovery = read_recovery_file(&file)?;
            let (_, state) = Crypto::recover_local(&envelope, &recovery)?;
            ensure!(state.sync.is_none(), RECOVERY_LOCAL_ONLY);
            ensure!(
                new.expose().chars().count() >= 16,
                "New passphrase must contain at least 16 characters"
            );
            let crypto = Crypto::create(&new).context("create replacement vault identity")?;
            let envelope = crypto.encrypt_local(&state)?;
            let outcome = atomic_replace(&directory, &directory.state_path(), &envelope)?;
            drop(initialization);
            // The authenticated state is already known. Never reread after committing a reset:
            // an IO failure here must not turn installed credentials into an ordinary failure.
            Ok::<_, anyhow::Error>(InitializedStore {
                directory,
                crypto,
                state,
                uncertain: matches!(outcome, AtomicWrite::Uncertain(_)),
            })
        })
        .await
        .context("vault recovery worker stopped")??;
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
            let state = LocalState::new(vault, sync);
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

    fn sync_recovery_directory(&self, path: &Path) -> Result<()> {
        #[cfg(test)]
        if consume_fault(&self.faults.fail_recovery_directory_sync) {
            bail!("injected recovery directory sync failure");
        }
        sync_directory_path(path)
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
            actual.normalize();
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
                match command {
                    Command::Shutdown { result } => {
                        receiver.close();
                        drop(receiver);
                        let destroyed = tokio::task::spawn_blocking(move || drop(writer))
                            .await
                            .context("vault writer shutdown worker stopped")
                            .map(|()| ());
                        let _ = result.send(destroyed);
                        return;
                    }
                    command => {
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
                }
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

    pub async fn verify_passphrase(&self, passphrase: Secret) -> Result<()> {
        let (result, response) = oneshot::channel();
        self.core
            .commands
            .send(Command::VerifyPassphrase { passphrase, result })
            .map_err(|_| anyhow!("vault writer is unavailable"))?;
        response.await.context("vault writer stopped")?
    }

    pub async fn change_passphrase(
        &self,
        current: Secret,
        new: Secret,
    ) -> Result<Option<String>> {
        let (result, response) = oneshot::channel();
        self.core
            .commands
            .send(Command::ChangePassphrase {
                current,
                new,
                result,
            })
            .map_err(|_| anyhow!("vault writer is unavailable"))?;
        response.await.context("vault writer stopped")?
    }

    pub async fn save_recovery_file(
        &self,
        current: Secret,
        destination: PathBuf,
    ) -> Result<Option<String>> {
        let (result, response) = oneshot::channel();
        self.core
            .commands
            .send(Command::SaveRecoveryFile {
                current,
                destination,
                result,
            })
            .map_err(|_| anyhow!("vault writer is unavailable"))?;
        response.await.context("vault writer stopped")?
    }

    pub async fn recover_passphrase(&self, file: PathBuf, new: Secret) -> Result<Option<String>> {
        let (result, response) = oneshot::channel();
        self.core
            .commands
            .send(Command::RecoverPassphrase { file, new, result })
            .map_err(|_| anyhow!("vault writer is unavailable"))?;
        response.await.context("vault writer stopped")?
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

    pub async fn shutdown(&self) -> Result<()> {
        let (result, response) = oneshot::channel();
        self.core
            .commands
            .send(Command::Shutdown { result })
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
    VerifyPassphrase {
        passphrase: Secret,
        result: oneshot::Sender<Result<()>>,
    },
    ChangePassphrase {
        current: Secret,
        new: Secret,
        result: oneshot::Sender<Result<Option<String>>>,
    },
    SaveRecoveryFile {
        current: Secret,
        destination: PathBuf,
        result: oneshot::Sender<Result<Option<String>>>,
    },
    RecoverPassphrase {
        file: PathBuf,
        new: Secret,
        result: oneshot::Sender<Result<Option<String>>>,
    },
    RetrySave {
        result: oneshot::Sender<Result<()>>,
    },
    Drain {
        result: oneshot::Sender<Result<()>>,
    },
    Shutdown {
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
            Self::VerifyPassphrase { result, .. }
            | Self::RetrySave { result }
            | Self::Drain { result }
            | Self::Shutdown { result } => {
                let _ = result.send(Err(error));
            }
            Self::ChangePassphrase { result, .. }
            | Self::SaveRecoveryFile { result, .. }
            | Self::RecoverPassphrase { result, .. } => {
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
            Command::VerifyPassphrase { passphrase, result } => {
                let _ = result.send(self.verify_passphrase(passphrase));
            }
            Command::ChangePassphrase {
                current,
                new,
                result,
            } => {
                let _ = result.send(self.change_passphrase(current, new));
            }
            Command::SaveRecoveryFile {
                current,
                destination,
                result,
            } => {
                let _ = result.send(self.save_recovery_file(current, destination));
            }
            Command::RecoverPassphrase { file, new, result } => {
                let _ = result.send(self.recover_passphrase(file, new));
            }
            Command::RetrySave { result } => {
                let _ = result.send(self.retry_save());
            }
            Command::Drain { result } => {
                let _ = result.send(Ok(()));
            }
            Command::Shutdown { result } => {
                let _ = result.send(Err(anyhow!("vault writer shutdown was not intercepted")));
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

    fn verify_passphrase(&self, passphrase: Secret) -> Result<()> {
        let envelope = self.directory.read_envelope()?;
        self.crypto
            .verify_passphrase(&envelope, &passphrase)
            .context("verify vault passphrase")
    }

    fn change_passphrase(&mut self, current: Secret, new: Secret) -> Result<Option<String>> {
        self.verify_passphrase(current)?;
        self.replace_passphrase(new)
    }

    fn save_recovery_file(&self, current: Secret, destination: PathBuf) -> Result<Option<String>> {
        self.verify_passphrase(current)?;
        self.require_local_recovery()?;
        let parent = recovery_destination_parent(&self.directory, &destination)?;
        let destination = parent.join(destination.file_name().context("Missing recovery filename")?);
        ensure!(
            fs::symlink_metadata(&destination).is_err(),
            "refusing to overwrite existing file: {}",
            destination.display()
        );
        let envelope = self.directory.read_envelope()?;
        let state = self.crypto.decrypt_local(&envelope)?;
        ensure!(state.sync.is_none(), RECOVERY_LOCAL_ONLY);
        ensure!(
            state == *self.current,
            "On-disk vault does not match the active vault"
        );
        let recovery = self.crypto.export_recovery(state.vault.id)?;
        let staged = stage_file(&parent, ".vyx-recovery.tmp-", &recovery)?;
        let verified = read_recovery_file(staged.path())?;
        let (candidate, recovered) = Crypto::recover_local(&envelope, &verified)?;
        ensure!(
            candidate.same_identity(&self.crypto) && recovered == state,
            "Recovery file verification failed"
        );
        self.directory.maybe_fail_before_rename()?;
        match staged.persist_noclobber(&destination) {
            Ok(_file) => {}
            Err(error) => {
                return Err(error.error)
                    .with_context(|| format!("install recovery file {}", destination.display()));
            }
        }
        Ok(self
            .directory
            .sync_recovery_directory(&parent)
            .err()
            .map(|_| RECOVERY_SAVE_WARNING.to_owned()))
    }

    fn require_local_recovery(&self) -> Result<()> {
        ensure!(self.current.sync.is_none(), RECOVERY_LOCAL_ONLY);
        ensure!(
            !self.uncertain.load(Ordering::Acquire),
            "Save durability uncertain; Retry save before using recovery"
        );
        Ok(())
    }

    fn recover_passphrase(&mut self, file: PathBuf, new: Secret) -> Result<Option<String>> {
        self.require_local_recovery()?;
        let envelope = self.directory.read_envelope()?;
        let recovery = read_recovery_file(&file)?;
        let (candidate, state) = Crypto::recover_local(&envelope, &recovery)?;
        ensure!(state.sync.is_none(), RECOVERY_LOCAL_ONLY);
        ensure!(
            state.vault.id == self.current.vault.id
                && candidate.wrapped_identity() == self.crypto.wrapped_identity()
                && candidate.same_identity(&self.crypto),
            "Recovery file does not unlock this vault"
        );
        self.replace_passphrase(new)
    }

    fn replace_passphrase(&mut self, new: Secret) -> Result<Option<String>> {
        ensure!(
            new.expose().chars().count() >= 16,
            "New passphrase must contain at least 16 characters"
        );
        if self.current.sync.is_some() {
            bail!("Disable sync before changing the vault passphrase");
        }
        if self.uncertain.load(Ordering::Acquire) {
            bail!("Save durability uncertain; Retry save before changing the vault passphrase");
        }

        let crypto = Crypto::create(&new).context("create replacement vault identity")?;
        let envelope = crypto.encrypt_local(&self.current)?;
        match atomic_replace(&self.directory, &self.directory.state_path(), &envelope)? {
            AtomicWrite::Durable => {
                self.crypto = crypto;
                Ok(None)
            }
            AtomicWrite::Uncertain(sync_error) => {
                self.crypto = crypto;
                self.uncertain.store(true, Ordering::Release);
                Ok(Some(format!(
                    "Passphrase changed, but its durability is uncertain ({sync_error:#}); Retry save before closing vyx"
                )))
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
        // AI history is device-local: retention and storage caps apply on every save, and
        // temporary conversations are dropped by `normalize` before anything is encrypted.
        next.ai.prune_history(crate::ai::now());
        next.normalize();
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
        actual.normalize();
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
    #[cfg(test)]
    if consume_fault(&directory.faults.fail_read_after_replace) {
        directory.faults.fail_envelope_read.fetch_add(1, Ordering::Relaxed);
    }
    match directory.sync() {
        Ok(()) => Ok(AtomicWrite::Durable),
        Err(error) => Ok(AtomicWrite::Uncertain(error)),
    }
}

fn stage_file(directory: &Path, prefix: &str, bytes: &[u8]) -> Result<NamedTempFile> {
    if bytes.len() > MAX_ENVELOPE {
        bail!("staged file exceeds the {MAX_ENVELOPE}-byte limit");
    }
    let mut staged = TempFileBuilder::new()
        .prefix(prefix)
        .tempfile_in(directory)
        .with_context(|| format!("create staged file in {}", directory.display()))?;
    staged
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))
        .context("secure staged file")?;
    ensure!(
        staged.as_file().metadata()?.permissions().mode() & 0o777 == 0o600,
        "staged file permissions are not private"
    );
    staged
        .write_all(bytes)
        .context("write staged data")?;
    staged
        .as_file()
        .sync_all()
        .context("sync staged data")?;
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

fn recovery_destination_parent(directory: &Directory, destination: &Path) -> Result<PathBuf> {
    ensure!(destination.is_absolute(), "Recovery file path must be absolute");
    ensure!(destination.file_name().is_some(), "Missing recovery filename");
    ensure!(
        fs::symlink_metadata(destination).is_err(),
        "refusing to overwrite existing file: {}",
        destination.display()
    );
    let parent = destination
        .parent()
        .context("Missing recovery file parent")?
        .canonicalize()
        .context("resolve recovery file parent directory")?;
    ensure!(parent.is_dir(), "Recovery file parent is not a directory");
    let vault = directory.path().canonicalize().context("resolve vault directory")?;
    ensure!(
        !parent.starts_with(vault),
        "Recovery file must be outside the vault directory"
    );
    Ok(parent)
}

fn read_recovery_file(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("open recovery file {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect recovery file {}", path.display()))?;
    ensure!(metadata.is_file(), "Recovery path is not a regular file");
    ensure!(
        metadata.len() <= MAX_RECOVERY_FILE as u64,
        "Recovery file exceeds the {MAX_RECOVERY_FILE}-byte limit"
    );
    // Read into a fixed allocation that is zeroized even after a partial IO failure.
    // The extra byte detects growth beyond the limit after the metadata check.
    let mut bytes = Zeroizing::new(vec![0; MAX_RECOVERY_FILE + 1]);
    let mut length = 0;
    while length < bytes.len() {
        match file.read(&mut bytes[length..]) {
            Ok(0) => break,
            Ok(count) => length += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                return Err(error).with_context(|| format!("read recovery file {}", path.display()));
            }
        }
    }
    bytes.truncate(length);
    ensure!(
        bytes.len() <= MAX_RECOVERY_FILE,
        "Recovery file exceeds the {MAX_RECOVERY_FILE}-byte limit"
    );
    Ok(bytes)
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
    fail_recovery_directory_sync: std::sync::atomic::AtomicUsize,
    fail_read_after_replace: std::sync::atomic::AtomicUsize,
    fail_envelope_read: std::sync::atomic::AtomicUsize,
}

#[cfg(test)]
impl TestFaults {
    fn fail_before_rename_once(&self) {
        self.fail_before_rename.fetch_add(1, Ordering::Relaxed);
    }

    fn fail_directory_sync_once(&self) {
        self.fail_directory_sync.fetch_add(1, Ordering::Relaxed);
    }

    fn fail_recovery_directory_sync_once(&self) {
        self.fail_recovery_directory_sync.fetch_add(1, Ordering::Relaxed);
    }

    fn fail_read_after_replace_once(&self) {
        self.fail_read_after_replace.fetch_add(1, Ordering::Relaxed);
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
    use crate::ai::{AiData, Conversation, Message, Profile, ProviderKind, Role, Usage};

    fn passphrase() -> Secret {
        Secret::new("sixteen character test passphrase")
    }

    fn replacement_passphrase() -> Secret {
        Secret::new("replacement passphrase for tests")
    }

    fn ai_data() -> AiData {
        let mut data = AiData::default();
        let mut profile = Profile::new(ProviderKind::OpenAi);
        profile.credential = Some(Secret::new("local-only-ai-api-key"));
        profile.temperature = Some(0.8455124082255701);
        let mut conversation = Conversation::new(Some(&profile), false);
        conversation.push(Message::new(Role::User, "local-only-chat-history")).unwrap();
        let mut answer = Message::new(Role::Assistant, "retained answer");
        answer.usage = Some(Usage { input_tokens: 30, output_tokens: 20, cost_usd: Some(0.01) });
        conversation.push(answer).unwrap();
        data.put_profile(profile).unwrap();
        data.conversations.push(conversation);
        data
    }

    async fn populated_store(directory: &Arc<Directory>) -> Store {
        use crate::vault::model::{
            Auth, Credential, Host, HostAuth, HostTransport, KnownHost, Snippet,
        };

        let store = directory.create(passphrase()).await.unwrap();
        store
            .commit(true, |state| {
                state.vault.categories.push(Category {
                    id: Uuid::from_u128(1),
                    label: "production".into(),
                    parent_id: None,
                });
                state.vault.credentials.push(Credential {
                    id: Uuid::from_u128(2),
                    label: "saved credential".into(),
                    username: "test".into(),
                    auth: Auth::Password {
                        password: Secret::new("retained credential secret"),
                    },
                });
                state.vault.hosts.push(Host {
                    id: Uuid::from_u128(3),
                    label: "saved server".into(),
                    hostname: "127.0.0.1".into(),
                    port: 2222,
                    category_id: Some(Uuid::from_u128(1)),
                    transport: HostTransport::Direct,
                    auth: HostAuth::Credential {
                        credential_id: Uuid::from_u128(2),
                    },
                });
                state.vault.snippets.push(Snippet {
                    id: Uuid::from_u128(4),
                    label: "saved snippet".into(),
                    command: "printf recovery-content".into(),
                });
                state.vault.known_hosts.push(KnownHost {
                    hostname: "127.0.0.1".into(),
                    port: 2222,
                    public_key_openssh: "ssh-ed25519 retained-test-key".into(),
                });
                state.ai = ai_data();
                Ok(())
            })
            .await
            .unwrap();
        store
    }

    #[tokio::test(flavor = "current_thread")]
    async fn recovery_reset_preserves_state_and_rotates_credentials() {
        let temporary = tempfile::tempdir().unwrap();
        let directory = Directory::open(temporary.path().join("vault")).unwrap();
        let store = populated_store(&directory).await;
        let recovery_path = temporary.path().join("emergency.recovery");
        store.save_recovery_file(passphrase(), recovery_path.clone()).await.unwrap();
        let recovery = read_recovery_file(&recovery_path).unwrap();
        // An ordinary save does not rotate the exported identity.
        let saved = store.commit(true, |state| {
            state.vault.snippets[0].command = "printf modified-after-export".into();
            Ok(())
        }).await.unwrap();
        let historical_envelope = directory.read_envelope().unwrap();
        assert_eq!(
            Crypto::recover_local(&historical_envelope, &recovery).unwrap().1,
            *saved
        );
        store.shutdown().await.unwrap();

        let reset = directory.recover(recovery_path.clone(), replacement_passphrase()).await.unwrap();
        assert_eq!(reset.snapshot().as_ref(), saved.as_ref());
        reset.shutdown().await.unwrap();
        assert!(directory.unlock(passphrase()).await.is_err());
        let reset = directory.unlock(replacement_passphrase()).await.unwrap();
        assert_eq!(reset.snapshot().as_ref(), saved.as_ref());
        assert!(Crypto::recover_local(&directory.read_envelope().unwrap(), &recovery).is_err());
        let historical = Crypto::unlock(&historical_envelope, &passphrase()).unwrap();
        assert_eq!(historical.decrypt_local(&historical_envelope).unwrap(), *saved);
        assert_eq!(Crypto::recover_local(&historical_envelope, &recovery).unwrap().1, *saved);

        let next_path = temporary.path().join("replacement.recovery");
        reset.save_recovery_file(replacement_passphrase(), next_path.clone()).await.unwrap();
        let next_recovery = read_recovery_file(&next_path).unwrap();
        assert_eq!(
            Crypto::recover_local(&directory.read_envelope().unwrap(), &next_recovery).unwrap().1,
            *saved
        );
        let retained = reset.snapshot();
        let mut subscription = reset.subscribe();
        assert_eq!(reset.recover_passphrase(next_path, passphrase()).await.unwrap(), None);
        // Recovery retains the very same in-memory snapshot and watch stream.
        assert!(Arc::ptr_eq(&retained, &reset.snapshot()));
        assert!(!subscription.has_changed().unwrap());
        assert_eq!(subscription.borrow_and_update().as_ref(), saved.as_ref());
        reset.verify_passphrase(passphrase()).await.unwrap();
        assert!(reset.verify_passphrase(replacement_passphrase()).await.is_err());
        assert!(Crypto::recover_local(&directory.read_envelope().unwrap(), &next_recovery).is_err());
        reset.shutdown().await.unwrap();
        let reopened = directory.unlock(passphrase()).await.unwrap();
        assert_eq!(reopened.snapshot().as_ref(), saved.as_ref());
        reopened.shutdown().await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn recovery_export_refuses_clobber_and_unsafe_paths() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().unwrap();
        let directory = Directory::open(temporary.path().join("vault")).unwrap();
        let store = directory.create(passphrase()).await.unwrap();
        let original = directory.read_envelope().unwrap();
        let regular = temporary.path().join("existing");
        fs::write(&regular, b"existing file contents").unwrap();
        let folder = temporary.path().join("folder");
        fs::create_dir(&folder).unwrap();
        let link = temporary.path().join("link");
        symlink(&regular, &link).unwrap();
        let dangling = temporary.path().join("dangling");
        symlink(temporary.path().join("missing-target"), &dangling).unwrap();
        let alias = temporary.path().join("vault-alias");
        symlink(directory.path(), &alias).unwrap();
        let wrong_password = temporary.path().join("wrong-password.recovery");
        assert!(store.save_recovery_file(Secret::new("wrong passphrase"), wrong_password.clone()).await.is_err());
        assert!(!wrong_password.exists());
        for destination in [
            PathBuf::new(),
            PathBuf::from("relative.recovery"),
            directory.path().join("inside.recovery"),
            alias.join("inside.recovery"),
            temporary.path().join("missing-parent/emergency.recovery"),
            regular.clone(),
            folder.clone(),
            link.clone(),
            dangling.clone(),
        ] {
            assert!(store.save_recovery_file(passphrase(), destination).await.is_err());
            assert_eq!(directory.read_envelope().unwrap(), original);
            assert_eq!(fs::read(&regular).unwrap(), b"existing file contents");
        }
        assert!(folder.is_dir());
        assert!(fs::symlink_metadata(&link).unwrap().file_type().is_symlink());
        assert!(fs::symlink_metadata(&dangling).unwrap().file_type().is_symlink());
        assert!(!directory.path().join("inside.recovery").exists());
        assert!(!temporary.path().join("missing-parent").exists());
        let recovery_path = temporary.path().join("valid.recovery");
        store.save_recovery_file(passphrase(), recovery_path.clone()).await.unwrap();
        assert_eq!(fs::metadata(&recovery_path).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(
            Crypto::recover_local(&original, &read_recovery_file(&recovery_path).unwrap()).unwrap().1,
            *store.snapshot()
        );
        assert_eq!(directory.read_envelope().unwrap(), original);

        let recovery_link = temporary.path().join("recovery-link");
        symlink(&recovery_path, &recovery_link).unwrap();
        let oversized = temporary.path().join("oversized.recovery");
        fs::write(&oversized, vec![b'x'; MAX_RECOVERY_FILE + 1]).unwrap();
        let malformed = temporary.path().join("malformed.recovery");
        fs::write(&malformed, b"{\"secret\":\"recognizable-fake-secret\"").unwrap();
        let foreign = temporary.path().join("foreign.recovery");
        let foreign_crypto = Crypto::create(&passphrase()).unwrap();
        fs::write(&foreign, &*foreign_crypto.export_recovery(Uuid::new_v4()).unwrap()).unwrap();
        let truncated = temporary.path().join("truncated.recovery");
        let valid = read_recovery_file(&recovery_path).unwrap();
        fs::write(&truncated, &valid[..valid.len() / 2]).unwrap();
        let fifo = temporary.path().join("fifo");
        let fifo_c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        // O_NONBLOCK plus descriptor validation must reject this without a writer.
        assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);
        for file in [
            recovery_link,
            oversized,
            malformed,
            foreign,
            truncated,
            fifo,
            folder,
            temporary.path().join("missing"),
        ] {
            let error = store.recover_passphrase(file.clone(), replacement_passphrase()).await.unwrap_err();
            assert!(!format!("{error:#}").contains("recognizable-fake-secret"));
            assert!(directory.recover(file, replacement_passphrase()).await.is_err());
            assert_eq!(directory.read_envelope().unwrap(), original);
        }
        let copied = temporary.path().join("copied.recovery");
        fs::copy(&recovery_path, &copied).unwrap();
        fs::set_permissions(&copied, fs::Permissions::from_mode(0o644)).unwrap();
        store.recover_passphrase(copied, replacement_passphrase()).await.unwrap();
        store.verify_passphrase(replacement_passphrase()).await.unwrap();
        store.shutdown().await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn recovery_export_distinguishes_installed_warning_from_failure() {
        let temporary = tempfile::tempdir().unwrap();
        let directory = Directory::open(temporary.path().join("vault")).unwrap();
        let store = directory.create(passphrase()).await.unwrap();
        let original = directory.read_envelope().unwrap();
        let destination = temporary.path().join("emergency.recovery");
        directory.faults.fail_before_rename_once();
        assert!(store.save_recovery_file(passphrase(), destination.clone()).await.is_err());
        assert!(!destination.exists());
        assert_eq!(directory.read_envelope().unwrap(), original);
        directory.faults.fail_recovery_directory_sync_once();
        assert!(store.save_recovery_file(passphrase(), destination.clone()).await.unwrap().is_some());
        assert!(!store.is_uncertain());
        let installed = read_recovery_file(&destination).unwrap();
        assert_eq!(Crypto::recover_local(&original, &installed).unwrap().1, *store.snapshot());
        assert!(store.save_recovery_file(passphrase(), destination.clone()).await.is_err());
        assert_eq!(*read_recovery_file(&destination).unwrap(), *installed);
        assert_eq!(directory.read_envelope().unwrap(), original);
        assert!(
            fs::read_dir(temporary.path()).unwrap().all(|entry|
                !entry.unwrap().file_name().to_string_lossy().starts_with(".vyx-recovery.tmp-"))
        );
        store.shutdown().await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn recovery_reset_preserves_atomic_failure_semantics() {
        for writer_reset in [false, true] {
            let temporary = tempfile::tempdir().unwrap();
            let directory = Directory::open(temporary.path().join("vault")).unwrap();
            let store = populated_store(&directory).await;
            let saved = store.snapshot();
            let recovery_path = temporary.path().join("emergency.recovery");
            store.save_recovery_file(passphrase(), recovery_path.clone()).await.unwrap();
            let recovery = read_recovery_file(&recovery_path).unwrap();
            let original = directory.read_envelope().unwrap();
            assert!(store.recover_passphrase(recovery_path.clone(), Secret::new("too short")).await.is_err());
            if !writer_reset {
                store.shutdown().await.unwrap();
                assert!(directory.recover(recovery_path.clone(), Secret::new("too short")).await.is_err());
            }
            directory.faults.fail_before_rename_once();
            if writer_reset {
                assert!(store.recover_passphrase(recovery_path.clone(), replacement_passphrase()).await.is_err());
                assert!(Arc::ptr_eq(&store.snapshot(), &saved));
                store.verify_passphrase(passphrase()).await.unwrap();
            } else {
                assert!(directory.recover(recovery_path.clone(), replacement_passphrase()).await.is_err());
            }
            assert_eq!(directory.read_envelope().unwrap(), original);
            assert!(Crypto::unlock(&original, &replacement_passphrase()).is_err());
            assert_eq!(Crypto::unlock(&original, &passphrase()).unwrap().decrypt_local(&original).unwrap(), *saved);
            assert_eq!(Crypto::recover_local(&original, &recovery).unwrap().1, *saved);
            directory.faults.fail_directory_sync_once();
            directory.faults.fail_read_after_replace_once();
            let reset = if writer_reset {
                assert!(store.recover_passphrase(recovery_path.clone(), replacement_passphrase()).await.unwrap().is_some());
                store
            } else {
                directory.recover(recovery_path.clone(), replacement_passphrase()).await.unwrap()
            };
            assert!(reset.is_uncertain());
            assert_eq!(reset.snapshot().as_ref(), saved.as_ref());
            // The reset succeeded without consuming the armed post-install read failure.
            assert!(directory.read_envelope().is_err());
            let installed = directory.read_envelope().unwrap();
            assert!(Crypto::recover_local(&installed, &recovery).is_err());
            assert!(Crypto::unlock(&installed, &passphrase()).is_err());
            reset.verify_passphrase(replacement_passphrase()).await.unwrap();
            assert!(reset.commit(true, |_| Ok(())).await.is_err());
            assert!(reset.recover_passphrase(recovery_path, passphrase()).await.is_err());
            let blocked_export = temporary.path().join("uncertain.recovery");
            assert!(reset.save_recovery_file(replacement_passphrase(), blocked_export.clone()).await.is_err());
            assert!(!blocked_export.exists());
            assert_eq!(directory.read_envelope().unwrap(), installed);
            reset.retry_save().await.unwrap();
            assert!(!reset.is_uncertain());
            reset.commit(false, |_| Ok(())).await.unwrap();
            reset.shutdown().await.unwrap();
            assert!(directory.unlock(passphrase()).await.is_err());
            let reopened = directory.unlock(replacement_passphrase()).await.unwrap();
            assert_eq!(reopened.snapshot().as_ref(), saved.as_ref());
            reopened.shutdown().await.unwrap();
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn accepted_recovery_reset_survives_dropped_response() {
        let temporary = tempfile::tempdir().unwrap();
        let directory = Directory::open(temporary.path().join("vault")).unwrap();
        let store = directory.create(passphrase()).await.unwrap();
        let file = temporary.path().join("emergency.recovery");
        store.save_recovery_file(passphrase(), file.clone()).await.unwrap();
        let saved = store.snapshot();
        let (result, response) = oneshot::channel();
        store.core.commands.send(Command::RecoverPassphrase {
            file: file.clone(),
            new: replacement_passphrase(),
            result,
        }).unwrap();
        drop(response);
        store.drain().await.unwrap();
        assert!(Arc::ptr_eq(&saved, &store.snapshot()));
        store.verify_passphrase(replacement_passphrase()).await.unwrap();
        assert!(store.verify_passphrase(passphrase()).await.is_err());
        let installed = directory.read_envelope().unwrap();
        assert!(store.recover_passphrase(file, passphrase()).await.is_err());
        assert_eq!(directory.read_envelope().unwrap(), installed);
        store.shutdown().await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn recovery_never_resets_configured_sync() {
        let temporary = tempfile::tempdir().unwrap();
        let directory = Directory::open(temporary.path().join("vault")).unwrap();
        let store = directory.create(passphrase()).await.unwrap();
        let file = temporary.path().join("emergency.recovery");
        store.save_recovery_file(passphrase(), file.clone()).await.unwrap();
        let configured = store.commit(false, |state| {
            state.sync = Some(SyncState {
                url: "https://sync.example.test".into(),
                token: Secret::new("configured-but-paused"),
                base_etag: Some(format!("\"{}\"", "0".repeat(64))),
                base_snapshot_id: Some(state.vault.snapshot_id),
                base_content_sha256: Some(state.vault.content_sha256()?),
                pending_upload: None,
            });
            Ok(())
        }).await.unwrap();
        let original = directory.read_envelope().unwrap();
        assert!(store.recover_passphrase(file.clone(), replacement_passphrase()).await.is_err());
        let forbidden_export = temporary.path().join("sync.recovery");
        assert!(store.save_recovery_file(passphrase(), forbidden_export.clone()).await.is_err());
        assert!(!forbidden_export.exists());
        assert_eq!(store.snapshot().as_ref(), configured.as_ref());
        assert_eq!(directory.read_envelope().unwrap(), original);
        store.shutdown().await.unwrap();
        assert!(directory.recover(file.clone(), replacement_passphrase()).await.is_err());
        assert_eq!(directory.read_envelope().unwrap(), original);
        let reopened = directory.unlock(passphrase()).await.unwrap();
        assert_eq!(reopened.snapshot().as_ref(), configured.as_ref());
        reopened.shutdown().await.unwrap();
        let missing = Directory::open(temporary.path().join("missing-vault")).unwrap();
        assert!(missing.recover(file, replacement_passphrase()).await.is_err());
        assert!(!missing.exists());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn recovery_cannot_authorize_live_state_with_a_historical_payload() {
        let temporary = tempfile::tempdir().unwrap();
        let directory = Directory::open(temporary.path().join("vault")).unwrap();
        let store = populated_store(&directory).await;
        let file = temporary.path().join("historical.recovery");
        store.save_recovery_file(passphrase(), file.clone()).await.unwrap();
        let historical = directory.read_envelope().unwrap();
        store.change_passphrase(passphrase(), replacement_passphrase()).await.unwrap();
        let live = store.commit(true, |state| {
            state.vault.snippets[0].command = "printf live-state".into();
            Ok(())
        }).await.unwrap();
        let legitimate = directory.read_envelope().unwrap();
        // VYX v1 has a four-byte magic, four-byte wrapper length, then wrapper/payload.
        let payload_offset = |bytes: &[u8]| {
            8 + u32::from_be_bytes(bytes[4..8].try_into().unwrap()) as usize
        };
        let mut spliced = legitimate[..payload_offset(&legitimate)].to_vec();
        spliced.extend_from_slice(&historical[payload_offset(&historical)..]);
        fs::write(directory.state_path(), &spliced).unwrap();
        let recovery = read_recovery_file(&file).unwrap();
        let (candidate, old_state) = Crypto::recover_local(&spliced, &recovery).unwrap();
        let current_crypto = Crypto::unlock(&legitimate, &replacement_passphrase()).unwrap();
        assert_eq!(candidate.wrapped_identity(), current_crypto.wrapped_identity());
        assert_eq!(old_state.vault.id, live.vault.id);
        assert!(!candidate.same_identity(&current_crypto));
        assert!(store.recover_passphrase(file, passphrase()).await.is_err());
        assert!(Arc::ptr_eq(&store.snapshot(), &live));
        assert_eq!(directory.read_envelope().unwrap(), spliced);
        fs::write(directory.state_path(), &legitimate).unwrap();
        store.verify_passphrase(replacement_passphrase()).await.unwrap();
        assert!(store.verify_passphrase(passphrase()).await.is_err());
        assert_eq!(store.decode_vault(store.export_vault(live.vault.clone()).await.unwrap()).await.unwrap(), live.vault);
        store.shutdown().await.unwrap();
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
        store
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
        assert!(store.is_uncertain());
        assert_eq!(store.snapshot().vault.categories.len(), 3);
        assert!(store.commit(false, |_| Ok(())).await.is_err());

        store.retry_save().await.unwrap();
        assert!(!store.is_uncertain());
        store.commit(false, |_| Ok(())).await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn passphrase_change_preserves_state_and_old_exports_but_rejects_old_credentials() {
        let temporary = tempfile::tempdir().unwrap();
        let directory = Directory::open(temporary.path().join("vault")).unwrap();
        let store = directory.create(passphrase()).await.unwrap();
        let saved = store
            .commit(true, |state| {
                state.vault.categories.push(Category {
                    id: Uuid::from_u128(1),
                    label: "retained".into(),
                    parent_id: None,
                });
                state.ai = ai_data();
                Ok(())
            })
            .await
            .unwrap();
        let old_export = store.export_vault(saved.vault.clone()).await.unwrap();
        let original_bytes = directory.read_envelope().unwrap();

        store.verify_passphrase(passphrase()).await.unwrap();
        assert!(
            store
                .verify_passphrase(Secret::new("wrong current passphrase"))
                .await
                .is_err()
        );
        assert!(
            store
                .change_passphrase(
                    Secret::new("wrong current passphrase"),
                    replacement_passphrase(),
                )
                .await
                .is_err()
        );
        assert_eq!(directory.read_envelope().unwrap(), original_bytes);
        assert_eq!(store.snapshot().as_ref(), saved.as_ref());

        assert!(
            store
                .change_passphrase(passphrase(), Secret::new("too short"))
                .await
                .is_err()
        );
        assert_eq!(directory.read_envelope().unwrap(), original_bytes);

        assert_eq!(
            store
                .change_passphrase(passphrase(), replacement_passphrase())
                .await
                .unwrap(),
            None
        );
        assert_eq!(store.snapshot().as_ref(), saved.as_ref());
        store
            .verify_passphrase(replacement_passphrase())
            .await
            .unwrap();
        assert!(store.verify_passphrase(passphrase()).await.is_err());

        store.shutdown().await.unwrap();
        assert!(directory.unlock(passphrase()).await.is_err());
        let reopened = directory.unlock(replacement_passphrase()).await.unwrap();
        assert_eq!(reopened.snapshot().as_ref(), saved.as_ref());
        reopened.shutdown().await.unwrap();

        let backup_directory = Directory::open(temporary.path().join("old-export")).unwrap();
        assert!(
            backup_directory
                .restore(old_export.clone(), replacement_passphrase(), None)
                .await
                .is_err()
        );
        let restored = backup_directory
            .restore(old_export, passphrase(), None)
            .await
            .unwrap();
        assert_eq!(restored.snapshot().vault, saved.vault);
        assert!(restored.snapshot().ai.is_default());
        restored.shutdown().await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn configured_sync_prevents_passphrase_change_without_touching_state() {
        let temporary = tempfile::tempdir().unwrap();
        let directory = Directory::open(temporary.path().join("vault")).unwrap();
        let store = directory.create(passphrase()).await.unwrap();
        let configured = store
            .commit(false, |state| {
                state.sync = Some(SyncState {
                    url: "https://sync.example.test".into(),
                    token: Secret::new("configured-but-disabled"),
                    base_etag: None,
                    base_snapshot_id: None,
                    base_content_sha256: None,
                    pending_upload: None,
                });
                Ok(())
            })
            .await
            .unwrap();
        let original_bytes = directory.read_envelope().unwrap();

        store
            .change_passphrase(passphrase(), replacement_passphrase())
            .await
            .unwrap_err();
        assert_eq!(directory.read_envelope().unwrap(), original_bytes);
        assert_eq!(store.snapshot().as_ref(), configured.as_ref());
        store.verify_passphrase(passphrase()).await.unwrap();
        store.shutdown().await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn passphrase_change_adopts_only_an_installed_identity_and_recovers_uncertainty() {
        let temporary = tempfile::tempdir().unwrap();
        let directory = Directory::open(temporary.path().join("vault")).unwrap();
        let store = populated_store(&directory).await;
        let saved = store.snapshot();
        let original_bytes = directory.read_envelope().unwrap();

        directory.faults.fail_before_rename_once();
        assert!(
            store
                .change_passphrase(passphrase(), replacement_passphrase())
                .await
                .is_err()
        );
        assert_eq!(directory.read_envelope().unwrap(), original_bytes);
        store.verify_passphrase(passphrase()).await.unwrap();
        assert!(
            store
                .verify_passphrase(replacement_passphrase())
                .await
                .is_err()
        );

        directory.faults.fail_directory_sync_once();
        store
            .change_passphrase(passphrase(), replacement_passphrase())
            .await
            .unwrap()
            .unwrap();
        assert!(store.is_uncertain());
        store
            .verify_passphrase(replacement_passphrase())
            .await
            .unwrap();
        assert!(store.verify_passphrase(passphrase()).await.is_err());

        let installed_bytes = directory.read_envelope().unwrap();
        store
            .change_passphrase(
                replacement_passphrase(),
                Secret::new("another replacement passphrase"),
            )
            .await
            .unwrap_err();
        assert_eq!(directory.read_envelope().unwrap(), installed_bytes);

        store.retry_save().await.unwrap();
        assert!(!store.is_uncertain());
        store.shutdown().await.unwrap();
        let reopened = directory.unlock(replacement_passphrase()).await.unwrap();
        assert_eq!(reopened.snapshot().as_ref(), saved.as_ref());
        reopened.shutdown().await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn shutdown_drains_earlier_work_and_later_commands_fail() {
        let temporary = tempfile::tempdir().unwrap();
        let directory = Directory::open(temporary.path().join("vault")).unwrap();
        let store = directory.create(passphrase()).await.unwrap();
        let (entered, started) = oneshot::channel();
        let (release, wait) = std_mpsc::channel();
        let commit_store = store.clone();
        let commit = tokio::spawn(async move {
            commit_store
                .commit(true, move |state| {
                    let _ = entered.send(());
                    wait.recv().unwrap();
                    state.vault.categories.push(Category {
                        id: Uuid::from_u128(2),
                        label: "before shutdown".into(),
                        parent_id: None,
                    });
                    Ok(())
                })
                .await
        });
        started.await.unwrap();

        let shutdown_store = store.clone();
        let shutdown = tokio::spawn(async move { shutdown_store.shutdown().await });
        tokio::task::yield_now().await;
        release.send(()).unwrap();
        commit.await.unwrap().unwrap();
        shutdown.await.unwrap().unwrap();
        assert_eq!(store.snapshot().vault.categories[0].label, "before shutdown");

        let stopped = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            store.verify_passphrase(passphrase()),
        )
        .await
        .expect("a command after shutdown must not hang");
        assert!(stopped.is_err());
        assert!(store.retry_save().await.is_err());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn export_restore_and_conflict_backup_require_semantically_identical_content() {
        use crate::vault::model::{Host, HostAuth, HostTransport, TailscaleIdentity};

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
                let keyless = Host {
                    id: Uuid::new_v4(),
                    label: "keyless".into(),
                    hostname: "server.example.ts.net".into(),
                    port: 22,
                    category_id: None,
                    transport: HostTransport::Tailscale,
                    auth: HostAuth::Tailscale {
                        username: "alice".into(),
                        tailscale: TailscaleIdentity {
                            tailnet_id: "stable-tailnet".into(),
                            node_id: "stable-node".into(),
                        },
                    },
                };
                state.vault.hosts.push(keyless.clone());
                state.vault.hosts.push(Host {
                    id: Uuid::new_v4(),
                    label: "standard SSH".into(),
                    port: 2222,
                    auth: HostAuth::Password {
                        username: "bob".into(),
                        password: Secret::new("retained secret"),
                    },
                    ..keyless
                });
                state.ai = ai_data();
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
        assert_eq!(restored.vault, saved.vault);
        assert!(restored.ai.is_default());
        let checkpoint = restored.sync.as_ref().unwrap();
        let expected_content_sha256 = saved.vault.content_sha256().unwrap();
        assert_eq!(checkpoint.base_etag.as_deref(), Some(etag.as_str()));
        assert_eq!(checkpoint.base_snapshot_id, Some(saved.vault.snapshot_id));
        assert_eq!(
            checkpoint.base_content_sha256.as_deref(),
            Some(expected_content_sha256.as_str())
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn ai_commits_filter_temporary_and_expired_history_without_changing_the_synced_vault() {
        let temporary = tempfile::tempdir().unwrap();
        let directory = Directory::open(temporary.path().join("vault")).unwrap();
        let store = directory.create(passphrase()).await.unwrap();
        let original = store.snapshot();
        let retained = ai_data();
        let mut expected = retained.clone();
        expected.config.retention_days = Some(1);
        let expected_id = retained.conversations[0].id;
        let saved = store.commit(false, move |state| {
            state.ai = retained;
            state.ai.config.retention_days = Some(1);
            let mut temporary = Conversation::new(None, true);
            temporary.push(Message::new(Role::User, "temporary-content-never-saved"))?;
            state.ai.conversations.push(temporary);
            let mut expired = Conversation::new(None, false);
            expired.created_at = 0;
            expired.updated_at = 0;
            expired.messages.push(Message::new(Role::User, "expired-content"));
            state.ai.conversations.push(expired);
            Ok(())
        }).await.unwrap();
        assert_eq!(saved.ai, expected);
        assert_eq!(saved.vault, original.vault);
        assert_eq!(saved.vault.snapshot_id, original.vault.snapshot_id);
        let bytes = directory.read_envelope().unwrap();
        for secret in ["local-only-ai-api-key", "local-only-chat-history", "temporary-content-never-saved"] {
            assert!(!bytes.windows(secret.len()).any(|bytes| bytes == secret.as_bytes()));
        }
        store.shutdown().await.unwrap();
        let reopened = directory.unlock(passphrase()).await.unwrap();
        assert_eq!(reopened.snapshot().as_ref(), saved.as_ref());
        let deleted = reopened.commit(false, move |state| {
            assert!(state.ai.remove_conversation(expected_id));
            Ok(())
        }).await.unwrap();
        assert!(deleted.ai.conversations.is_empty());
        assert_eq!(deleted.ai.profiles, expected.profiles);
        assert_eq!(deleted.vault, original.vault);
        reopened.shutdown().await.unwrap();
        let reopened = directory.unlock(passphrase()).await.unwrap();
        assert_eq!(reopened.snapshot().as_ref(), deleted.as_ref());
        reopened.shutdown().await.unwrap();
    }
}
