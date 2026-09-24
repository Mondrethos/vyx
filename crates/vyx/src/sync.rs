use std::{
    future::pending,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use tokio::{sync::Notify, task::JoinHandle, time::Instant};
use uuid::Uuid;

use crate::{
    remote::{PreconditionFailed, Remote, RemoteRead, canonical_origin, validate_token},
    screen::safe_text,
    vault::{LocalState, PendingUpload, Secret, Store, SyncState, Vault, sha256},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SyncStatus {
    LocalOnly,
    Syncing,
    Synced,
    Pending,
    Conflict,
    Error(String),
}
impl SyncStatus {
    pub fn label(&self) -> &str {
        match self {
            Self::LocalOnly => "Local only",
            Self::Syncing => "Syncing",
            Self::Synced => "Synced",
            Self::Pending => "Pending",
            Self::Conflict => "Conflict",
            Self::Error(_) => "Sync error",
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuestionKind {
    Upload,
    Recreate,
    Conflict,
}
#[derive(Clone, Debug)]
pub struct SyncQuestion {
    pub summary: String,
    pub kind: QuestionKind,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncChoice {
    KeepLocal,
    UseServer,
    Cancel,
}

#[derive(Clone)]
struct Identity {
    snapshot_id: Uuid,
    content_sha256: String,
    etag: String,
}
struct RemoteSnapshot {
    vault: Vault,
    identity: Identity,
}
enum Observation {
    Missing,
    Known(Identity),
    Full(RemoteSnapshot),
}
impl Observation {
    fn identity(&self) -> Option<&Identity> {
        match self {
            Self::Missing => None,
            Self::Known(identity) => Some(identity),
            Self::Full(remote) => Some(&remote.identity),
        }
    }
}
struct QuestionContext {
    question: SyncQuestion,
    local_snapshot: Uuid,
    remote: Option<RemoteSnapshot>,
}
enum Outcome {
    Complete,
    Question(QuestionContext),
}
struct Resolution {
    context: QuestionContext,
    choice: SyncChoice,
}

/// Owns the network task, so dropping a UI select waiter never drops an upload.
pub struct SyncController {
    store: Store,
    dirty: Arc<Notify>,
    status: SyncStatus,
    deadline: Option<Instant>,
    active: Option<JoinHandle<Result<Outcome>>>,
    question: Option<QuestionContext>,
    question_shown: bool,
    suppressed: bool,
    generation: Arc<AtomicU64>,
}

impl SyncController {
    pub fn new(store: Store, dirty: Arc<Notify>) -> Self {
        let status = local_status(&store.snapshot());
        Self {
            store,
            dirty,
            status,
            deadline: None,
            active: None,
            question: None,
            question_shown: false,
            suppressed: false,
            generation: Arc::new(AtomicU64::new(0)),
        }
    }
    pub fn status(&self) -> SyncStatus {
        if self.store.is_uncertain() {
            return SyncStatus::Error(
                "Save durability uncertain; Retry save before synchronizing".into(),
            );
        }
        match &self.status {
            SyncStatus::Syncing
            | SyncStatus::Pending
            | SyncStatus::Conflict
            | SyncStatus::Error(_) => self.status.clone(),
            _ => local_status(&self.store.snapshot()),
        }
    }
    pub fn request(&mut self, explicit: bool) {
        if explicit {
            self.suppressed = false;
            self.question = None;
            self.question_shown = false;
        }
        if self.suppressed || self.store.snapshot().sync.is_none() || self.store.is_uncertain() {
            return;
        }
        self.deadline = Some(Instant::now());
        if self.active.is_none() {
            self.status = SyncStatus::Pending;
        }
        self.dirty.notify_one();
    }
    pub fn edited(&mut self) {
        if self.suppressed
            || self.question.is_some()
            || self.store.is_uncertain()
            || !is_dirty(&self.store.snapshot())
        {
            return;
        }
        self.deadline = Some(Instant::now() + Duration::from_secs(2));
        if self.active.is_none() && self.question.is_none() {
            self.status = SyncStatus::Pending;
        }
        self.dirty.notify_one();
    }
    pub async fn tick(&mut self) {
        if let Some(active) = self.active.as_mut() {
            let result = active.await;
            self.active = None;
            match result {
                Ok(Ok(Outcome::Complete)) => {
                    self.status = local_status(&self.store.snapshot());
                    if !is_dirty(&self.store.snapshot()) {
                        self.deadline = None;
                    }
                }
                Ok(Ok(Outcome::Question(question))) => {
                    self.status = if question.question.kind == QuestionKind::Conflict {
                        SyncStatus::Conflict
                    } else {
                        SyncStatus::Pending
                    };
                    self.question = Some(question);
                    self.question_shown = false;
                    self.deadline = None;
                }
                Ok(Err(error)) => {
                    self.status = SyncStatus::Error(safe_text(&format!("{error:#}")));
                    self.deadline = None;
                }
                Err(error) => {
                    self.status = SyncStatus::Error(if error.is_cancelled() {
                        "Synchronization canceled".into()
                    } else {
                        "Synchronization worker stopped".into()
                    });
                    self.deadline = None;
                }
            }
            self.dirty.notify_one();
        } else if let Some(deadline) = self.deadline {
            tokio::time::sleep_until(deadline).await;
            self.deadline = None;
            self.launch(None);
        } else {
            pending::<()>().await;
        }
    }
    pub fn take_question(&mut self) -> Option<SyncQuestion> {
        if self.question_shown {
            return None;
        }
        let question = self.question.as_ref()?.question.clone();
        self.question_shown = true;
        Some(question)
    }
    pub fn answer(&mut self, choice: SyncChoice) {
        let Some(context) = self.question.take() else {
            return;
        };
        self.question_shown = false;
        self.deadline = None;
        if choice == SyncChoice::Cancel {
            self.suppressed = true;
            self.status = if context.question.kind == QuestionKind::Conflict {
                SyncStatus::Conflict
            } else {
                SyncStatus::Pending
            };
            self.dirty.notify_one();
        } else {
            self.launch(Some(Resolution { context, choice }));
        }
    }
    pub async fn configure(&mut self, url: String, token: Secret) -> Result<()> {
        let url = canonical_origin(&url)?;
        validate_token(token.expose())?;
        self.stop_active().await;
        self.store
            .commit(false, move |state| {
                if let Some(sync) = &mut state.sync {
                    if sync.url == url {
                        sync.token = token;
                        return Ok(());
                    }
                }
                state.sync = Some(SyncState {
                    url,
                    token,
                    base_etag: None,
                    base_snapshot_id: None,
                    base_content_sha256: None,
                    pending_upload: None,
                });
                Ok(())
            })
            .await?;
        self.suppressed = false;
        self.status = local_status(&self.store.snapshot());
        self.request(true);
        Ok(())
    }
    pub async fn disable(&mut self) -> Result<()> {
        self.stop_active().await;
        self.store
            .commit(false, |state| {
                state.sync = None;
                Ok(())
            })
            .await?;
        self.status = SyncStatus::LocalOnly;
        self.dirty.notify_one();
        Ok(())
    }
    pub async fn shutdown(&mut self) -> Result<()> {
        self.stop_active().await;
        self.store.drain().await
    }
    async fn stop_active(&mut self) {
        self.generation.fetch_add(1, Ordering::AcqRel);
        self.deadline = None;
        self.question = None;
        self.question_shown = false;
        if let Some(active) = self.active.take() {
            active.abort();
            let _ = active.await;
        }
    }
    fn launch(&mut self, resolution: Option<Resolution>) {
        let snapshot = self.store.snapshot();
        let Some(sync) = &snapshot.sync else {
            self.status = SyncStatus::LocalOnly;
            return;
        };
        if self.store.is_uncertain() {
            self.status = SyncStatus::Error("Save durability uncertain; Retry save".into());
            return;
        }
        let guard = Guard {
            url: sync.url.clone(),
            token: sync.token.clone(),
            generation: Arc::clone(&self.generation),
            epoch: self.generation.load(Ordering::Acquire),
        };
        let store = self.store.clone();
        self.active = Some(tokio::spawn(async move {
            synchronize(store, Arc::new(guard), resolution).await
        }));
        self.status = SyncStatus::Syncing;
        self.dirty.notify_one();
    }
}

fn local_status(state: &LocalState) -> SyncStatus {
    if state.sync.is_none() {
        SyncStatus::LocalOnly
    } else if is_dirty(state) {
        SyncStatus::Pending
    } else {
        SyncStatus::Synced
    }
}
fn is_dirty(state: &LocalState) -> bool {
    state
        .sync
        .as_ref()
        .is_some_and(|sync| sync.base_snapshot_id != Some(state.vault.snapshot_id))
}

struct Guard {
    url: String,
    token: Secret,
    generation: Arc<AtomicU64>,
    epoch: u64,
}
impl Guard {
    fn check(&self, state: &LocalState) -> Result<()> {
        ensure!(
            self.generation.load(Ordering::Acquire) == self.epoch,
            "Synchronization settings changed"
        );
        ensure!(
            state
                .sync
                .as_ref()
                .is_some_and(|sync| sync.url == self.url && sync.token == self.token),
            "Synchronization settings changed"
        );
        Ok(())
    }
}
#[derive(Debug)]
struct LocalChanged;
impl std::fmt::Display for LocalChanged {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Local vault changed during synchronization")
    }
}
impl std::error::Error for LocalChanged {}
fn check_snapshot(state: &LocalState, expected: Uuid) -> Result<()> {
    if state.vault.snapshot_id != expected {
        return Err(LocalChanged.into());
    }
    Ok(())
}

async fn content_hash(state: Arc<LocalState>) -> Result<String> {
    tokio::task::spawn_blocking(move || state.vault.content_sha256())
        .await
        .context("snapshot hashing worker stopped")?
}

async fn fetch(
    store: &Store,
    guard: &Guard,
    remote: &Remote,
    unconditional: bool,
) -> Result<Observation> {
    let state = store.snapshot();
    guard.check(&state)?;
    let sync = state.sync.as_ref().context("Sync is disabled")?;
    let conditional = if unconditional {
        None
    } else {
        sync.base_etag.as_deref()
    };
    match remote.get(conditional).await? {
        RemoteRead::Missing => Ok(Observation::Missing),
        RemoteRead::Unchanged => Ok(Observation::Known(Identity {
            snapshot_id: sync.base_snapshot_id.context("Missing base snapshot")?,
            content_sha256: sync
                .base_content_sha256
                .clone()
                .context("Missing base digest")?,
            etag: sync.base_etag.clone().context("Missing base ETag")?,
        })),
        RemoteRead::Found(download) => {
            let vault = store.decode_vault(download.envelope).await.context("Cannot decrypt or validate the server vault; a different vault must be restored into a separate --data-dir")?;
            ensure!(
                vault.id == state.vault.id,
                "This server contains a different vault; restore it into a separate --data-dir"
            );
            let (vault, hash) = tokio::task::spawn_blocking(move || {
                let hash = vault.content_sha256()?;
                Ok::<_, anyhow::Error>((vault, hash))
            })
            .await
            .context("server snapshot hashing worker stopped")??;
            let identity = Identity {
                snapshot_id: vault.snapshot_id,
                content_sha256: hash,
                etag: download.etag,
            };
            Ok(Observation::Full(RemoteSnapshot { vault, identity }))
        }
    }
}

fn validate_evidence(
    state: &LocalState,
    identity: &Identity,
    current_hash: Option<&str>,
) -> Result<()> {
    let sync = state.sync.as_ref().context("Sync is disabled")?;
    if identity.snapshot_id == state.vault.snapshot_id {
        ensure!(
            current_hash == Some(identity.content_sha256.as_str()),
            "Server reused the current snapshot ID with different content"
        );
    }
    if Some(identity.snapshot_id) == sync.base_snapshot_id {
        ensure!(
            sync.base_content_sha256.as_deref() == Some(identity.content_sha256.as_str()),
            "Server reused the base snapshot ID with different content"
        );
    }
    if let Some(upload) = &sync.pending_upload {
        if upload.snapshot_id == identity.snapshot_id {
            ensure!(
                upload.content_sha256 == identity.content_sha256,
                "Server reused a pending snapshot ID with different content"
            );
        }
        if identity.etag[1..65] == upload.envelope_sha256 {
            ensure!(
                upload.snapshot_id == identity.snapshot_id
                    && upload.content_sha256 == identity.content_sha256,
                "Pending upload evidence does not match the server document"
            );
        }
    }
    Ok(())
}

async fn checkpoint(
    store: &Store,
    guard: Arc<Guard>,
    identity: Identity,
    clear_pending: bool,
) -> Result<Arc<LocalState>> {
    store
        .commit(false, move |state| {
            guard.check(state)?;
            let sync = state.sync.as_mut().context("Sync is disabled")?;
            sync.base_etag = Some(identity.etag);
            sync.base_snapshot_id = Some(identity.snapshot_id);
            sync.base_content_sha256 = Some(identity.content_sha256);
            if clear_pending {
                sync.pending_upload = None;
            }
            Ok(())
        })
        .await
}

async fn adopt(
    store: &Store,
    guard: Arc<Guard>,
    remote: RemoteSnapshot,
    expected: Uuid,
) -> Result<()> {
    store
        .commit(false, move |state| {
            guard.check(state)?;
            check_snapshot(state, expected)?;
            state.vault = remote.vault;
            let sync = state.sync.as_mut().context("Sync is disabled")?;
            sync.base_etag = Some(remote.identity.etag);
            sync.base_snapshot_id = Some(remote.identity.snapshot_id);
            sync.base_content_sha256 = Some(remote.identity.content_sha256);
            sync.pending_upload = None;
            Ok(())
        })
        .await?;
    Ok(())
}

async fn upload(
    store: &Store,
    guard: Arc<Guard>,
    remote: &Remote,
    base: Option<&str>,
    state: Arc<LocalState>,
) -> Result<Identity> {
    guard.check(&state)?;
    let content_sha256 = content_hash(Arc::clone(&state)).await?;
    let envelope = store.export_vault(state.vault.clone()).await?;
    let envelope_sha256 = sha256(&envelope);
    let identity = Identity {
        snapshot_id: state.vault.snapshot_id,
        content_sha256: content_sha256.clone(),
        etag: format!("\"{envelope_sha256}\""),
    };
    let pending = PendingUpload {
        snapshot_id: identity.snapshot_id,
        content_sha256,
        envelope_sha256,
    };
    let check_guard = Arc::clone(&guard);
    store
        .commit(false, move |latest| {
            check_guard.check(latest)?;
            check_snapshot(latest, pending.snapshot_id)?;
            latest
                .sync
                .as_mut()
                .context("Sync is disabled")?
                .pending_upload = Some(pending);
            Ok(())
        })
        .await?;
    remote.put(envelope, base).await?;
    checkpoint(store, guard, identity.clone(), true).await?;
    Ok(identity)
}

fn question(state: &LocalState, kind: QuestionKind, remote: Option<RemoteSnapshot>) -> Outcome {
    let summary = match &remote {
        Some(remote) => format!("Both devices changed. This device: {} hosts, {} credentials, {} snippets. Server: {} hosts, {} credentials, {} snippets. The discarded snapshot is encrypted and preserved before replacement.", state.vault.hosts.len(), state.vault.credentials.len(), state.vault.snippets.len(), remote.vault.hosts.len(), remote.vault.credentials.len(), remote.vault.snippets.len()),
        None if kind == QuestionKind::Recreate => "The previously populated server is empty. Recreate its vault from this device? Local data will be preserved.".into(),
        None => "The server is empty. Upload this encrypted vault? The server cannot decrypt or recover it.".into(),
    };
    Outcome::Question(QuestionContext {
        question: SyncQuestion { summary, kind },
        local_snapshot: state.vault.snapshot_id,
        remote,
    })
}

async fn synchronize(
    store: Store,
    guard: Arc<Guard>,
    resolution: Option<Resolution>,
) -> Result<Outcome> {
    let remote = Remote::new(&guard.url, &guard.token)?;
    let mut allow_empty = false;
    let mut observed = None;
    let mut retried_cas = false;
    if let Some(resolution) = resolution {
        let current = store.snapshot();
        guard.check(&current)?;
        if current.vault.snapshot_id == resolution.context.local_snapshot {
            if let Some(disputed) = resolution.context.remote {
                match resolution.choice {
                    SyncChoice::KeepLocal => {
                        store.preserve_conflict(disputed.vault).await.context(
                            "Cannot preserve the server snapshot; neither copy was replaced",
                        )?;
                        match upload(
                            &store,
                            Arc::clone(&guard),
                            &remote,
                            Some(&disputed.identity.etag),
                            current,
                        )
                        .await
                        {
                            Ok(identity) => observed = Some(Observation::Known(identity)),
                            Err(error) if error.is::<LocalChanged>() => (),
                            Err(error) if error.is::<PreconditionFailed>() => retried_cas = true,
                            Err(error) => return Err(error),
                        }
                    }
                    SyncChoice::UseServer => {
                        store
                            .preserve_conflict(current.vault.clone())
                            .await
                            .context(
                                "Cannot preserve this device's snapshot; neither copy was replaced",
                            )?;
                        match adopt(
                            &store,
                            Arc::clone(&guard),
                            disputed,
                            current.vault.snapshot_id,
                        )
                        .await
                        {
                            Ok(()) => return Ok(Outcome::Complete),
                            Err(error) if error.is::<LocalChanged>() => (),
                            Err(error) => return Err(error),
                        }
                    }
                    SyncChoice::Cancel => return Ok(Outcome::Complete),
                }
            } else {
                allow_empty = resolution.choice == SyncChoice::KeepLocal;
            }
        }
    }
    let mut observed = match observed {
        Some(value) => value,
        None => fetch(&store, &guard, &remote, false).await?,
    };
    // Bounded reconciliation, not a periodic retry loop. Each iteration either
    // persists new equality evidence, uploads a newer edit, or refetches once.
    for _ in 0..16 {
        let current = store.snapshot();
        guard.check(&current)?;
        let settings = current.sync.as_ref().context("Sync is disabled")?;
        if matches!(observed, Observation::Missing) {
            if !allow_empty {
                let kind = if settings.base_etag.is_some() {
                    QuestionKind::Recreate
                } else {
                    QuestionKind::Upload
                };
                return Ok(question(&current, kind, None));
            }
            match upload(&store, Arc::clone(&guard), &remote, None, current).await {
                Ok(identity) => {
                    observed = Observation::Known(identity);
                    allow_empty = false;
                    continue;
                }
                Err(error) if error.is::<LocalChanged>() => continue,
                Err(error) if error.is::<PreconditionFailed>() && !retried_cas => {
                    retried_cas = true;
                    allow_empty = false;
                    observed = fetch(&store, &guard, &remote, true).await?;
                    continue;
                }
                Err(error) => return Err(error),
            }
        }
        let identity = observed.identity().context("Missing remote identity")?;
        let current_hash = if identity.snapshot_id == current.vault.snapshot_id {
            Some(content_hash(Arc::clone(&current)).await?)
        } else {
            None
        };
        validate_evidence(&current, identity, current_hash.as_deref())?;
        let matches_pending = settings.pending_upload.as_ref().is_some_and(|upload| {
            upload.snapshot_id == identity.snapshot_id
                && upload.content_sha256 == identity.content_sha256
        });
        if matches_pending {
            checkpoint(&store, Arc::clone(&guard), identity.clone(), true).await?;
            continue;
        }
        if identity.snapshot_id == current.vault.snapshot_id {
            if settings.base_etag.as_deref() != Some(identity.etag.as_str())
                || settings.base_snapshot_id != Some(identity.snapshot_id)
                || settings.pending_upload.is_some()
            {
                let latest = checkpoint(&store, Arc::clone(&guard), identity.clone(), true).await?;
                if latest.vault.snapshot_id != identity.snapshot_id {
                    continue;
                }
            }
            return Ok(Outcome::Complete);
        }
        let matches_base = settings.base_snapshot_id == Some(identity.snapshot_id)
            && settings.base_content_sha256.as_deref() == Some(identity.content_sha256.as_str());
        if matches_base {
            if settings.base_etag.as_deref() != Some(identity.etag.as_str()) {
                checkpoint(&store, Arc::clone(&guard), identity.clone(), false).await?;
                continue;
            }
            let base = identity.etag.clone();
            match upload(&store, Arc::clone(&guard), &remote, Some(&base), current).await {
                Ok(identity) => {
                    observed = Observation::Known(identity);
                    continue;
                }
                Err(error) if error.is::<LocalChanged>() => continue,
                Err(error) if error.is::<PreconditionFailed>() && !retried_cas => {
                    retried_cas = true;
                    observed = fetch(&store, &guard, &remote, true).await?;
                    continue;
                }
                Err(error) => return Err(error),
            }
        }
        match observed {
            Observation::Full(snapshot)
                if !is_dirty(&current) && settings.pending_upload.is_none() =>
            {
                match adopt(
                    &store,
                    Arc::clone(&guard),
                    snapshot,
                    current.vault.snapshot_id,
                )
                .await
                {
                    Ok(()) => return Ok(Outcome::Complete),
                    Err(error) if error.is::<LocalChanged>() => {
                        observed = fetch(&store, &guard, &remote, true).await?;
                    }
                    Err(error) => return Err(error),
                }
            }
            Observation::Full(snapshot) => {
                return Ok(question(&current, QuestionKind::Conflict, Some(snapshot)));
            }
            _ => {
                observed = fetch(&store, &guard, &remote, true).await?;
            }
        }
    }
    bail!(
        "The vault kept changing during synchronization; saved edits remain pending. Synchronize again when ready"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{Directory, Snippet};

    async fn device() -> (tempfile::TempDir, Store, Arc<Guard>) {
        let directory = tempfile::tempdir().unwrap();
        let owner = Directory::open(directory.path().join("client")).unwrap();
        let store = owner
            .create(Secret::new("test-only-vault-passphrase"))
            .await
            .unwrap();
        let token = Secret::new("a".repeat(64));
        let guard = Arc::new(Guard {
            url: "http://127.0.0.1:8080".into(),
            token: token.clone(),
            generation: Arc::new(AtomicU64::new(0)),
            epoch: 0,
        });
        store
            .commit(false, move |state| {
                state.sync = Some(SyncState {
                    url: "http://127.0.0.1:8080".into(),
                    token,
                    base_etag: None,
                    base_snapshot_id: None,
                    base_content_sha256: None,
                    pending_upload: None,
                });
                Ok(())
            })
            .await
            .unwrap();
        (directory, store, guard)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_missing_remote_stays_pending_through_cancel() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        tokio::time::timeout(Duration::from_secs(10), async {
            let _ = rustls::crypto::ring::default_provider().install_default();
            let (_directory, store, _guard) = device().await;
            let initial = store.snapshot().vault.clone();
            let envelope = store.export_vault(initial.clone()).await.unwrap();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let origin = format!("http://{}", listener.local_addr().unwrap());
            let server = tokio::spawn(async move {
                for present in [true, false] {
                    let (mut socket, _) = listener.accept().await.unwrap();
                    let mut headers = Vec::new();
                    while !headers.ends_with(b"\r\n\r\n") {
                        headers.push(socket.read_u8().await.unwrap());
                        assert!(headers.len() < 8192);
                    }
                    if present {
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nETag: \"{}\"\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            sha256(&envelope), envelope.len(),
                        );
                        socket.write_all(response.as_bytes()).await.unwrap();
                        socket.write_all(&envelope).await.unwrap();
                    } else {
                        socket.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
                    }
                }
            });
            let mut controller = SyncController::new(store.clone(), Arc::new(Notify::new()));
            controller.configure(origin, Secret::new("a".repeat(64))).await.unwrap();
            controller.tick().await;
            controller.tick().await;
            assert_eq!(controller.status(), SyncStatus::Synced);
            controller.request(true);
            controller.tick().await;
            controller.tick().await;
            assert_eq!(controller.take_question().unwrap().kind, QuestionKind::Recreate);
            assert_eq!(controller.status(), SyncStatus::Pending);
            controller.answer(SyncChoice::Cancel);
            assert_eq!(controller.status(), SyncStatus::Pending);
            assert_eq!(store.snapshot().vault.content_sha256().unwrap(), initial.content_sha256().unwrap());
            controller.shutdown().await.unwrap();
            server.await.unwrap();
        }).await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn acknowledging_an_older_upload_keeps_the_newer_edit_dirty() {
        let (_directory, store, guard) = device().await;
        let submitted = store.snapshot();
        let identity = Identity {
            snapshot_id: submitted.vault.snapshot_id,
            content_sha256: submitted.vault.content_sha256().unwrap(),
            etag: format!("\"{}\"", "1".repeat(64)),
        };
        let (entered, ready) = tokio::sync::oneshot::channel();
        let (resume, paused) = std::sync::mpsc::channel();
        let editing_store = store.clone();
        let edit = tokio::spawn(async move {
            editing_store
                .commit(true, move |state| {
                    entered.send(()).unwrap();
                    paused.recv().unwrap();
                    state.vault.snippets.push(Snippet {
                        id: Uuid::new_v4(),
                        label: "Newer edit".into(),
                        command: "echo newer".into(),
                    });
                    Ok(())
                })
                .await
                .unwrap()
        });
        ready.await.unwrap();
        let acknowledgement = checkpoint(&store, guard, identity, true);
        tokio::pin!(acknowledgement);
        assert!(futures_util::poll!(&mut acknowledgement).is_pending());
        resume.send(()).unwrap();
        let newer = edit.await.unwrap().vault.snapshot_id;
        acknowledgement.await.unwrap();
        let actual = store.snapshot();
        assert_eq!(actual.vault.snapshot_id, newer);
        assert_eq!(actual.vault.snippets[0].command, "echo newer");
        assert_eq!(
            actual.sync.as_ref().unwrap().base_snapshot_id,
            Some(submitted.vault.snapshot_id)
        );
        assert!(is_dirty(&actual));
        store.drain().await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_stale_download_cannot_erase_a_committed_edit() {
        let (_directory, store, guard) = device().await;
        let initial = store.snapshot().vault.clone();
        let mut downloaded = initial.clone();
        downloaded.snapshot_id = Uuid::new_v4();
        let identity = Identity {
            snapshot_id: downloaded.snapshot_id,
            content_sha256: downloaded.content_sha256().unwrap(),
            etag: format!("\"{}\"", "2".repeat(64)),
        };
        store
            .commit(true, |state| {
                state.vault.snippets.push(Snippet {
                    id: Uuid::new_v4(),
                    label: "Keep me".into(),
                    command: "echo local".into(),
                });
                Ok(())
            })
            .await
            .unwrap();
        let error = adopt(
            &store,
            guard,
            RemoteSnapshot {
                vault: downloaded,
                identity,
            },
            initial.snapshot_id,
        )
        .await
        .unwrap_err();
        assert!(error.is::<LocalChanged>());
        assert_eq!(store.snapshot().vault.snippets[0].command, "echo local");
        assert!(store.snapshot().sync.as_ref().unwrap().base_etag.is_none());
        store.drain().await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn equal_snapshot_ids_cannot_authenticate_different_content() {
        let (_directory, store, _guard) = device().await;
        let current = store.snapshot();
        let hash = current.vault.content_sha256().unwrap();
        let identity = Identity {
            snapshot_id: current.vault.snapshot_id,
            content_sha256: "0".repeat(64),
            etag: format!("\"{}\"", "3".repeat(64)),
        };
        assert!(validate_evidence(&current, &identity, Some(&hash)).is_err());
        store.drain().await.unwrap();
    }
}
