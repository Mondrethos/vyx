mod connection;
mod check;
#[cfg(test)]
mod check_tests;
use check::AuthCheck;
pub use check::AuthNotice;
pub use connection::{ConnectionTarget, PreparedConnection, ReconnectAuth};

use std::fmt;
use std::net::{IpAddr, Shutdown};
use std::pin::Pin;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;
use tokio::time::Instant;

use anyhow::{Context, Result, anyhow, ensure};
use bytes::Bytes;
use parking_lot::Mutex;
use russh::client::{self, AuthResult, KeyboardInteractiveAuthResponse};
use russh::keys::agent::{AgentIdentity, client::AgentClient};
use russh::keys::{HashAlg, PrivateKey, PrivateKeyWithHashAlg, PublicKey, PublicKeyOrCertificate};
use russh::{ChannelMsg, MethodKind, Sig};
use tokio::net::TcpStream;
use tokio::sync::{Notify, mpsc, oneshot, watch};
use uuid::Uuid;

use crate::terminal::TerminalState;
use crate::vault::{Auth, Credential, Host, HostAuth, KnownHost, Secret, Store, canonical_hostname};

const NETWORK_DEADLINE: Duration = Duration::from_secs(15);
const MAX_INPUT: usize = 64 * 1024;
const OUTPUT_CHUNK: usize = 64 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionPhase {
    Connecting,
    Authenticating,
    Connected,
    Closed {
        status: Option<u32>,
        signal: Option<String>,
    },
    Error(String),
}

impl SessionPhase {
    pub fn is_live(&self) -> bool {
        matches!(
            self,
            Self::Connecting | Self::Authenticating | Self::Connected
        )
    }

    pub fn label(&self) -> String {
        match self {
            Self::Connecting => "Connecting".to_owned(),
            Self::Authenticating => "Authenticating".to_owned(),
            Self::Connected => "Connected".to_owned(),
            Self::Closed {
                status: Some(status),
                signal: Some(signal),
            } => format!("Closed (exit {status}, signal {signal})"),
            Self::Closed {
                status: Some(status),
                signal: None,
            } => format!("Closed (exit {status})"),
            Self::Closed {
                status: None,
                signal: Some(signal),
            } => format!("Closed (signal {signal}, exit status unavailable)"),
            Self::Closed {
                status: None,
                signal: None,
            } => "Closed (exit status unavailable)".to_owned(),
            Self::Error(message) => format!("Error: {message}"),
        }
    }
}

impl fmt::Display for SessionPhase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.label())
    }
}

pub struct SessionView {
    pub terminal: TerminalState,
    pub phase: SessionPhase,
    pub output_ended: bool,
    pub auth_notice: Option<AuthNotice>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PromptField {
    pub label: String,
    pub secret: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PromptKind {
    Trust,
    Authentication,
}

pub struct PromptRequest {
    pub session_id: Uuid,
    pub title: String,
    pub description: String,
    pub fields: Vec<PromptField>,
    pub kind: PromptKind,
    pub response: oneshot::Sender<Option<Vec<Secret>>>,
    pub cancelled: watch::Receiver<bool>,
}

pub struct Session {
    pub id: Uuid,
    pub host_id: Option<Uuid>,
    pub destination: ConnectionTarget,
    pub label: String,
    pub view: Arc<Mutex<SessionView>>,
    input: mpsc::Sender<Bytes>,
    dimensions: watch::Sender<(u16, u16)>,
    cancel: watch::Sender<bool>,
    visible: Arc<AtomicBool>,
    dirty: Arc<Notify>,
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

struct Login {
    username: String,
    auth: LoginMode,
}

enum LoginMode {
    Standard(Auth),
    TailscaleNone,
}

impl Session {
    #[allow(clippy::too_many_arguments)]
    pub fn connect(
        prepared: PreparedConnection,
        store: Store,
        rows: u16,
        cols: u16,
        prompts: mpsc::Sender<PromptRequest>,
        dirty: Arc<Notify>,
    ) -> Result<Self> {
        let id = Uuid::new_v4();
        let rows = rows.max(1);
        let cols = cols.max(1);
        let view = Arc::new(Mutex::new(SessionView {
            terminal: TerminalState::new(rows, cols),
            phase: SessionPhase::Connecting,
            output_ended: false,
            auth_notice: None,
        }));
        let (input, input_rx) = mpsc::channel(1);
        let (dimensions, dimensions_rx) = watch::channel((rows, cols));
        let (cancel, cancel_rx) = watch::channel(false);
        let visible = Arc::new(AtomicBool::new(false));
        let host_id = prepared.host_id;
        let destination = prepared.target.clone();
        let label = destination.label.clone();

        let task_view = Arc::clone(&view);
        let task_visible = Arc::clone(&visible);
        let task_dirty = Arc::clone(&dirty);
        let task = tokio::spawn(async move {
            let end = run_transport(
                id,
                prepared,
                store,
                task_view.clone(),
                input_rx,
                dimensions_rx,
                cancel_rx,
                prompts,
                task_visible,
                Arc::clone(&task_dirty),
            )
            .await;
            match end {
                TransportEnd::Closed { status, signal } => {
                    set_phase(
                        &task_view,
                        &task_dirty,
                        SessionPhase::Closed { status, signal },
                    );
                }
                TransportEnd::Error(message) => {
                    set_phase(
                        &task_view,
                        &task_dirty,
                        SessionPhase::Error(check::sanitize_text(&message, 4096)),
                    );
                }
            }
        });

        Ok(Self {
            id,
            host_id,
            label,
            destination,
            view,
            input,
            dimensions,
            cancel,
            visible,
            dirty,
            task: Mutex::new(Some(task)),
        })
    }

    pub async fn send(&self, bytes: Vec<u8>) -> Result<()> {
        ensure!(bytes.len() <= MAX_INPUT, "terminal input exceeds 64 KiB");
        if bytes.is_empty() {
            return Ok(());
        }
        ensure!(self.is_live(), "SSH session is not live");
        self.input
            .send(bytes.into())
            .await
            .map_err(|_| anyhow!("SSH input transport is closed"))
    }

    pub(crate) fn try_input_slot(
        &self,
    ) -> std::result::Result<mpsc::Permit<'_, Bytes>, mpsc::error::TrySendError<()>> {
        self.input.try_reserve()
    }

    pub fn resize(&self, rows: u16, cols: u16) -> bool {
        let dimensions = (rows.max(1), cols.max(1));
        if *self.dimensions.borrow() == dimensions {
            return false;
        }
        self.view.lock().terminal.resize(dimensions.0, dimensions.1);
        self.dimensions.send_replace(dimensions);
        true
    }

    pub fn is_live(&self) -> bool {
        self.view.lock().phase.is_live()
    }

    pub fn set_visible(&self, visible: bool) {
        if !self.visible.swap(visible, Ordering::AcqRel) && visible {
            self.dirty.notify_one();
        }
    }

    pub fn cancel_unfinished_authentication(&self) {
        let mut view = self.view.lock();
        if matches!(view.phase, SessionPhase::Connecting | SessionPhase::Authenticating) {
            self.cancel.send_replace(true);
            view.auth_notice = None;
            self.dirty.notify_one();
        }
    }

    pub async fn close(&mut self) -> Result<()> {
        self.cancel.send_replace(true);
        let task = self.task.lock().take();
        if let Some(task) = task {
            task.await
                .context("SSH transport task stopped unexpectedly")?;
        }
        Ok(())
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.cancel.send_replace(true);
    }
}

#[derive(Clone)]
struct Repaint {
    visible: Arc<AtomicBool>,
    dirty: Arc<Notify>,
}

impl Repaint {
    fn output(&self) {
        if self.visible.load(Ordering::Acquire) {
            self.dirty.notify_one();
        }
    }

    fn status(&self) {
        self.dirty.notify_one();
    }
}

fn set_phase(view: &Arc<Mutex<SessionView>>, dirty: &Notify, phase: SessionPhase) {
    view.lock().phase = phase;
    dirty.notify_one();
}

#[derive(Debug)]
enum TransportEnd {
    Closed {
        status: Option<u32>,
        signal: Option<String>,
    },
    Error(String),
}

#[derive(Debug)]
enum OperationError {
    Cancelled,
    TimedOut,
    Failed(String),
}

impl OperationError {
    fn failed(message: impl Into<String>) -> Self {
        Self::Failed(message.into())
    }
}

#[derive(Clone)]
struct PromptPause(watch::Sender<bool>);

impl PromptPause {
    fn enter(&self) -> PromptPauseGuard {
        self.0.send_replace(true);
        PromptPauseGuard(self.0.clone())
    }
}

struct PromptPauseGuard(watch::Sender<bool>);

impl Drop for PromptPauseGuard {
    fn drop(&mut self) {
        self.0.send_replace(false);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NetworkStop {
    Cancelled,
    TimedOut,
}

struct NetworkBudget {
    remaining: Duration,
    pause: watch::Receiver<bool>,
    auth_deadline: Option<Instant>,
}

impl NetworkBudget {
    fn new(pause: watch::Receiver<bool>) -> Self {
        Self::with_limit(pause, NETWORK_DEADLINE)
    }

    fn with_limit(pause: watch::Receiver<bool>, limit: Duration) -> Self {
        Self {
            remaining: limit,
            pause,
            auth_deadline: None,
        }
    }

    async fn wait<F>(
        &mut self,
        mut future: Pin<&mut F>,
        cancel: &mut watch::Receiver<bool>,
    ) -> std::result::Result<F::Output, NetworkStop>
    where
        F: Future + ?Sized,
    {
        loop {
            if *cancel.borrow() {
                return Err(NetworkStop::Cancelled);
            }

            if self.auth_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                return Err(NetworkStop::TimedOut);
            }
            let deadline = self.auth_deadline;
            let absolute = async move {
                match deadline {
                    Some(deadline) => tokio::time::sleep_until(deadline).await,
                    None => std::future::pending().await,
                }
            };
            tokio::pin!(absolute);
            let paused = *self.pause.borrow_and_update();
            if paused {
                tokio::select! {
                    result = future.as_mut() => return Ok(result),
                    _ = wait_cancelled(cancel) => return Err(NetworkStop::Cancelled),
                    _ = &mut absolute => return Err(NetworkStop::TimedOut),
                    changed = self.pause.changed() => {
                        if changed.is_err() {
                            continue;
                        }
                    }
                }
                continue;
            }

            if self.remaining.is_zero() {
                return Err(NetworkStop::TimedOut);
            }
            let started = Instant::now();
            let sleep = tokio::time::sleep(self.remaining);
            tokio::pin!(sleep);
            tokio::select! {
                _ = &mut absolute => return Err(NetworkStop::TimedOut),
                result = future.as_mut() => {
                    self.remaining = self.remaining.saturating_sub(started.elapsed());
                    return Ok(result);
                }
                _ = wait_cancelled(cancel) => {
                    self.remaining = self.remaining.saturating_sub(started.elapsed());
                    return Err(NetworkStop::Cancelled);
                }
                changed = self.pause.changed() => {
                    self.remaining = self.remaining.saturating_sub(started.elapsed());
                    if changed.is_err() {
                        continue;
                    }
                }
                _ = &mut sleep => {
                    self.remaining = Duration::ZERO;
                    return Err(NetworkStop::TimedOut);
                }
            }
        }
    }
}

async fn wait_cancelled(cancel: &mut watch::Receiver<bool>) {
    loop {
        if *cancel.borrow() {
            return;
        }
        if cancel.changed().await.is_err() {
            return;
        }
    }
}

async fn network_call<F, T, E>(
    budget: &mut NetworkBudget,
    cancel: &mut watch::Receiver<bool>,
    future: F,
    failure: &'static str,
) -> std::result::Result<T, OperationError>
where
    F: Future<Output = std::result::Result<T, E>>,
{
    tokio::pin!(future);
    match budget.wait(future.as_mut(), cancel).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(_)) => Err(OperationError::failed(failure)),
        Err(NetworkStop::Cancelled) => Err(OperationError::Cancelled),
        Err(NetworkStop::TimedOut) => Err(OperationError::TimedOut),
    }
}

async fn cancelable_call<F, T, E>(
    cancel: &mut watch::Receiver<bool>,
    future: F,
    failure: &'static str,
) -> std::result::Result<T, OperationError>
where
    F: Future<Output = std::result::Result<T, E>>,
{
    tokio::pin!(future);
    tokio::select! {
        result = future.as_mut() => {
            result.map_err(|_| OperationError::failed(failure))
        }
        _ = wait_cancelled(cancel) => Err(OperationError::Cancelled),
    }
}

async fn network_wait<F, T>(
    budget: &mut NetworkBudget,
    cancel: &mut watch::Receiver<bool>,
    future: F,
) -> std::result::Result<T, OperationError>
where
    F: Future<Output = T>,
{
    tokio::pin!(future);
    match budget.wait(future.as_mut(), cancel).await {
        Ok(value) => Ok(value),
        Err(NetworkStop::Cancelled) => Err(OperationError::Cancelled),
        Err(NetworkStop::TimedOut) => Err(OperationError::TimedOut),
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_transport(
    session_id: Uuid,
    prepared: PreparedConnection,
    store: Store,
    view: Arc<Mutex<SessionView>>,
    input: mpsc::Receiver<Bytes>,
    dimensions: watch::Receiver<(u16, u16)>,
    mut cancel: watch::Receiver<bool>,
    prompts: mpsc::Sender<PromptRequest>,
    visible: Arc<AtomicBool>,
    dirty: Arc<Notify>,
) -> TransportEnd {
    let repaint = Repaint { visible, dirty };
    let (pause_tx, pause_rx) = watch::channel(false);
    let pause = PromptPause(pause_tx);
    let mut budget = NetworkBudget::new(pause_rx);

    let (stream, mut owner, tailscale_keys) = match connection::open(&prepared, &mut budget, &mut cancel).await {
        Ok(transport) => transport,
        Err(_) if *cancel.borrow() => return TransportEnd::Closed { status: None, signal: None },
        Err(error) => return TransportEnd::Error(sanitize_chrome(&format!("{error:#}"))),
    };
    let hostname = prepared.target.address;
    let port = prepared.target.port;
    let credential = prepared.login;

    let result = async {
        let handler_failure = Arc::new(Mutex::new(None));
        let check = AuthCheck::new(
            matches!(credential.auth, LoginMode::TailscaleNone),
            view.clone(), repaint.dirty.clone(), pause.clone(), cancel.clone(),
        );
        let handler = ClientHandler {
            session_id,
            hostname: hostname.clone(),
            port,
            store,
            prompts: prompts.clone(),
            cancel: cancel.clone(),
            pause: pause.clone(),
            failure: Arc::clone(&handler_failure),
            tailscale_keys,
            verified_tailscale_key: false,
            check: check.clone(),
        };
        let config = Arc::new(client::Config {
            window_size: 262_144,
            maximum_packet_size: 32_768,
            channel_buffer_size: 8,
            nodelay: false,
            ..Default::default()
        });

        let mut connecting = Box::pin(client::connect_stream(config, stream, handler));
        let connected = budget.wait(connecting.as_mut(), &mut cancel).await;
        let mut handle = match connected {
            Ok(Ok(handle)) => handle,
            Ok(Err(_)) => {
                let message = handler_failure
                    .lock()
                    .take()
                    .unwrap_or_else(|| "SSH handshake failed".to_owned());
                return TransportEnd::Error(message);
            }
            Err(stop) => {
                owner.shutdown().await;
                let _ = connecting.await;
                return match stop {
                    NetworkStop::Cancelled => TransportEnd::Closed {
                        status: None,
                        signal: None,
                    },
                    NetworkStop::TimedOut => {
                        TransportEnd::Error("SSH connection timed out".to_owned())
                    }
                };
            }
        };
        drop(connecting);

        set_phase(&view, &repaint.dirty, SessionPhase::Authenticating);
        let drive_end = setup_and_drive(
            session_id,
            &credential,
            &mut handle,
            &mut budget,
            &mut cancel,
            &prompts,
            &pause,
            &view,
            input,
            dimensions,
            &repaint,
            &check,
            &handler_failure,
        )
        .await;

        owner.shutdown().await;
        let _ = handle.await;

        match drive_end {
            DriveEnd::Closed { status, signal }
            | DriveEnd::Cancelled { status, signal }
            | DriveEnd::ReceiverEnded { status, signal }
                if status.is_some() || signal.is_some() =>
            {
                TransportEnd::Closed { status, signal }
            }
            DriveEnd::Closed { status, signal } | DriveEnd::Cancelled { status, signal } => {
                TransportEnd::Closed { status, signal }
            }
            DriveEnd::ReceiverEnded { .. } => {
                TransportEnd::Error("SSH transport ended unexpectedly".to_owned())
            }
            DriveEnd::Failed(message) => TransportEnd::Error(message),
        }
    }
    .await;
    owner.shutdown().await;
    result
}


struct ClientHandler {
    session_id: Uuid,
    hostname: String,
    port: u16,
    store: Store,
    prompts: mpsc::Sender<PromptRequest>,
    cancel: watch::Receiver<bool>,
    pause: PromptPause,
    failure: Arc<Mutex<Option<String>>>,
    tailscale_keys: Option<Vec<PublicKey>>,
    verified_tailscale_key: bool,
    check: AuthCheck,
}

impl ClientHandler {
    fn reject(&self, message: impl Into<String>) -> anyhow::Error {
        let message = sanitize_chrome(&message.into());
        *self.failure.lock() = Some(message.clone());
        anyhow!(message)
    }
}

impl client::Handler for ClientHandler {
    type Error = anyhow::Error;

    async fn auth_banner(
        &mut self,
        banner: &str,
        _session: &mut client::Session,
    ) -> std::result::Result<(), Self::Error> {
        if self.verified_tailscale_key {
            self.check.banner(banner).map_err(|error| self.reject(error))?;
        }
        Ok(())
    }

    async fn check_server_key(
        &mut self,
        server_key: &PublicKeyOrCertificate,
    ) -> std::result::Result<bool, Self::Error> {
        let incoming = match server_key {
            PublicKeyOrCertificate::PublicKey { key, .. } => key,
            PublicKeyOrCertificate::Certificate(_) => {
                return Err(self.reject("SSH host certificates are not supported"));
            }
        };
        if let Some(expected) = &self.tailscale_keys {
            if !expected.iter().any(|key| key.key_data() == incoming.key_data()) {
                return Err(self.reject("Tailscale-distributed SSH host key mismatch; no trust override is permitted"));
            }
            self.verified_tailscale_key = true;
            return Ok(true);
        }
        if self.check.is_keyless() {
            return Err(self.reject("Tailscale SSH requires distributed host keys; no trust override is permitted"));
        }
        let stored = self
            .store
            .snapshot()
            .vault
            .known_hosts
            .iter()
            .find(|entry| entry.hostname == self.hostname && entry.port == self.port)
            .map(|entry| entry.public_key_openssh.clone());

        match pin_decision(stored.as_deref(), incoming) {
            Ok(PinDecision::Trusted) => return Ok(true),
            Ok(PinDecision::Changed { old_fingerprint }) => {
                let message = format!(
                    "Server key changed for {}. Old fingerprint: {old_fingerprint}. New fingerprint: {}",
                    display_endpoint(&self.hostname, self.port),
                    fingerprint(incoming),
                );
                return Err(self.reject(message));
            }
            Ok(PinDecision::Unknown) => {}
            Err(_) => return Err(self.reject("Stored trusted host key is invalid")),
        }

        let description = format!(
            "{}\nAlgorithm: {}\nFingerprint: {}",
            display_endpoint(&self.hostname, self.port),
            incoming.algorithm().as_str(),
            fingerprint(incoming),
        );
        let answer = ask_prompt(
            self.session_id,
            "Unknown server key".to_owned(),
            description,
            Vec::new(),
            PromptKind::Trust,
            &self.prompts,
            &mut self.cancel,
            &self.pause,
        )
        .await;
        match answer {
            Ok(_) => {}
            Err(OperationError::Cancelled) => {
                return Err(self.reject("SSH connection was cancelled"));
            }
            Err(OperationError::Failed(message)) => return Err(self.reject(message)),
            Err(OperationError::TimedOut) => unreachable!("prompts do not have a deadline"),
        }

        let encoded = incoming
            .to_openssh()
            .map_err(|_| self.reject("Could not encode the server key"))?;
        let expected_key = incoming.clone();
        let hostname = self.hostname.clone();
        let port = self.port;
        if let Err(error) = self
            .store
            .commit(true, move |state| {
                match state
                    .vault
                    .known_hosts
                    .iter()
                    .find(|entry| entry.hostname == hostname && entry.port == port)
                {
                    Some(existing) => {
                        let pinned = PublicKey::from_openssh(&existing.public_key_openssh)
                            .context("stored trusted host key is invalid")?;
                        ensure!(
                            pinned.key_data() == expected_key.key_data(),
                            "trusted host key changed while awaiting approval"
                        );
                    }
                    None => state.vault.known_hosts.push(KnownHost {
                        hostname,
                        port,
                        public_key_openssh: encoded,
                    }),
                }
                Ok(())
            })
            .await
        {
            return Err(self.reject(format!(
                "Could not durably save the trusted host key: {}",
                sanitize_chrome(&error.to_string())
            )));
        }
        Ok(true)
    }
}

#[derive(Debug, PartialEq, Eq)]
enum PinDecision {
    Unknown,
    Trusted,
    Changed { old_fingerprint: String },
}

fn pin_decision(stored: Option<&str>, incoming: &PublicKey) -> Result<PinDecision> {
    let Some(stored) = stored else {
        return Ok(PinDecision::Unknown);
    };
    let pinned = PublicKey::from_openssh(stored).context("invalid stored public key")?;
    if pinned.key_data() == incoming.key_data() {
        Ok(PinDecision::Trusted)
    } else {
        Ok(PinDecision::Changed {
            old_fingerprint: fingerprint(&pinned),
        })
    }
}

fn fingerprint(key: &PublicKey) -> String {
    key.fingerprint(HashAlg::Sha256).to_string()
}

fn display_endpoint(hostname: &str, port: u16) -> String {
    if hostname
        .parse::<IpAddr>()
        .is_ok_and(|address| address.is_ipv6())
    {
        format!("[{hostname}]:{port}")
    } else {
        format!("{hostname}:{port}")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthDisposition {
    Complete,
    KeyboardInteractiveMfa,
    Rejected,
    UnsupportedContinuation,
}

fn auth_disposition(result: AuthResult) -> AuthDisposition {
    match result {
        AuthResult::Success => AuthDisposition::Complete,
        AuthResult::Failure {
            remaining_methods,
            partial_success: true,
        } if remaining_methods.contains(&MethodKind::KeyboardInteractive) => {
            AuthDisposition::KeyboardInteractiveMfa
        }
        AuthResult::Failure {
            partial_success: true,
            ..
        } => AuthDisposition::UnsupportedContinuation,
        AuthResult::Failure { .. } => AuthDisposition::Rejected,
    }
}

#[allow(clippy::too_many_arguments)]
async fn authenticate(
    session_id: Uuid,
    credential: &Login,
    handle: &mut client::Handle<ClientHandler>,
    budget: &mut NetworkBudget,
    cancel: &mut watch::Receiver<bool>,
    prompts: &mpsc::Sender<PromptRequest>,
    pause: &PromptPause,
) -> std::result::Result<(), OperationError> {
    match &credential.auth {
        LoginMode::Standard(Auth::Password { password }) => {
            let result = network_call(
                budget,
                cancel,
                handle.authenticate_password(
                    credential.username.clone(),
                    password.expose().to_owned(),
                ),
                "Password authentication failed",
            )
            .await?;
            finish_primary_auth(
                session_id,
                credential,
                handle,
                budget,
                cancel,
                prompts,
                pause,
                auth_disposition(result),
            )
            .await
        }
        LoginMode::Standard(Auth::PrivateKey { pem, passphrase }) => {
            let key = load_private_key(
                session_id,
                pem.clone(),
                passphrase.clone(),
                prompts,
                cancel,
                pause,
            )
            .await?;
            let hash = rsa_hash_for(handle, key.algorithm().is_rsa(), budget, cancel).await?;
            let result = network_call(
                budget,
                cancel,
                handle.authenticate_publickey(
                    credential.username.clone(),
                    PrivateKeyWithHashAlg::new(Arc::new(key), hash),
                ),
                "Private-key authentication failed",
            )
            .await?;
            finish_primary_auth(
                session_id,
                credential,
                handle,
                budget,
                cancel,
                prompts,
                pause,
                auth_disposition(result),
            )
            .await
        }
        LoginMode::Standard(Auth::Agent) => {
            authenticate_agent(
                session_id, credential, handle, budget, cancel, prompts, pause,
            )
            .await
        }
        LoginMode::Standard(Auth::KeyboardInteractive) => {
            keyboard_interactive(
                session_id, credential, handle, budget, cancel, prompts, pause,
            )
            .await
        }
        LoginMode::TailscaleNone => {
            let result = network_call(budget, cancel, handle.authenticate_none(credential.username.clone()), "Tailscale SSH authentication failed").await?;
            match result {
                AuthResult::Success => Ok(()),
                _ => Err(OperationError::failed("Tailscale SSH denied access; no credential fallback was attempted")),
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn finish_primary_auth(
    session_id: Uuid,
    credential: &Login,
    handle: &mut client::Handle<ClientHandler>,
    budget: &mut NetworkBudget,
    cancel: &mut watch::Receiver<bool>,
    prompts: &mpsc::Sender<PromptRequest>,
    pause: &PromptPause,
    disposition: AuthDisposition,
) -> std::result::Result<(), OperationError> {
    match disposition {
        AuthDisposition::Complete => Ok(()),
        AuthDisposition::KeyboardInteractiveMfa => {
            keyboard_interactive(
                session_id, credential, handle, budget, cancel, prompts, pause,
            )
            .await
        }
        AuthDisposition::Rejected => Err(OperationError::failed("SSH authentication was rejected")),
        AuthDisposition::UnsupportedContinuation => Err(OperationError::failed(
            "The server requires an unsupported additional authentication method",
        )),
    }
}

async fn load_private_key(
    session_id: Uuid,
    pem: Secret,
    saved_passphrase: Option<Secret>,
    prompts: &mpsc::Sender<PromptRequest>,
    cancel: &mut watch::Receiver<bool>,
    pause: &PromptPause,
) -> std::result::Result<PrivateKey, OperationError> {
    let first_pem = pem.clone();
    let first_passphrase = saved_passphrase.clone();
    let decoded = tokio::task::spawn_blocking(move || {
        russh::keys::decode_secret_key(
            first_pem.expose(),
            first_passphrase.as_ref().map(Secret::expose),
        )
    })
    .await
    .map_err(|_| OperationError::failed("Private-key decoding stopped unexpectedly"))?;

    match decoded {
        Ok(key) => Ok(key),
        Err(error)
            if saved_passphrase.is_none()
                && (matches!(&error, russh::keys::Error::KeyIsEncrypted)
                    || private_key_looks_encrypted(pem.expose())) =>
        {
            let answers = ask_prompt(
                session_id,
                "Private key passphrase".to_owned(),
                "Enter the passphrase for this connection. It will not be saved.".to_owned(),
                vec![PromptField {
                    label: "Passphrase".to_owned(),
                    secret: true,
                }],
                PromptKind::Authentication,
                prompts,
                cancel,
                pause,
            )
            .await?;
            let Some(passphrase) = answers.into_iter().next() else {
                return Err(OperationError::failed(
                    "Private-key passphrase was not provided",
                ));
            };
            let decoded = tokio::task::spawn_blocking(move || {
                russh::keys::decode_secret_key(pem.expose(), Some(passphrase.expose()))
            })
            .await
            .map_err(|_| OperationError::failed("Private-key decoding stopped unexpectedly"))?;
            decoded.map_err(|_| OperationError::failed("Private key or passphrase is invalid"))
        }
        Err(_) => Err(OperationError::failed(
            "Private key or passphrase is invalid",
        )),
    }
}

fn private_key_looks_encrypted(pem: &str) -> bool {
    pem.contains("-----BEGIN ENCRYPTED PRIVATE KEY-----")
        || pem.contains("Proc-Type: 4,ENCRYPTED")
        || pem.lines().any(|line| {
            line.strip_prefix("Encryption:")
                .is_some_and(|value| !value.trim().eq_ignore_ascii_case("none"))
        })
}

async fn rsa_hash_for(
    handle: &client::Handle<ClientHandler>,
    rsa: bool,
    budget: &mut NetworkBudget,
    cancel: &mut watch::Receiver<bool>,
) -> std::result::Result<Option<HashAlg>, OperationError> {
    if !rsa {
        return Ok(None);
    }
    let advertised = network_call(
        budget,
        cancel,
        handle.best_supported_rsa_hash(),
        "Could not negotiate RSA SHA-2 authentication",
    )
    .await?;
    match advertised {
        Some(Some(hash @ (HashAlg::Sha256 | HashAlg::Sha512))) => Ok(Some(hash)),
        None => Ok(Some(HashAlg::Sha512)),
        Some(None) => Err(OperationError::failed(
            "The SSH server does not offer RSA SHA-2 authentication",
        )),
        Some(Some(_)) => Err(OperationError::failed(
            "The SSH server offered an unsupported RSA signature hash",
        )),
    }
}

#[allow(clippy::too_many_arguments)]
async fn authenticate_agent(
    session_id: Uuid,
    credential: &Login,
    handle: &mut client::Handle<ClientHandler>,
    budget: &mut NetworkBudget,
    cancel: &mut watch::Receiver<bool>,
    prompts: &mpsc::Sender<PromptRequest>,
    pause: &PromptPause,
) -> std::result::Result<(), OperationError> {
    let mut agent = network_call(
        budget,
        cancel,
        AgentClient::connect_env(),
        "Could not connect to the local SSH agent",
    )
    .await?;
    let identities = network_call(
        budget,
        cancel,
        agent.request_identities(),
        "Could not read identities from the local SSH agent",
    )
    .await?;
    if identities.is_empty() {
        return Err(OperationError::failed(
            "The local SSH agent has no identities",
        ));
    }

    for identity in identities {
        let result = match identity {
            AgentIdentity::PublicKey { key, .. } => {
                let hash = rsa_hash_for(handle, key.algorithm().is_rsa(), budget, cancel).await?;
                network_call(
                    budget,
                    cancel,
                    handle.authenticate_publickey_with(
                        credential.username.clone(),
                        key,
                        hash,
                        &mut agent,
                    ),
                    "Local SSH-agent authentication failed",
                )
                .await?
            }
            AgentIdentity::Certificate { certificate, .. } => {
                let hash =
                    rsa_hash_for(handle, certificate.algorithm().is_rsa(), budget, cancel).await?;
                network_call(
                    budget,
                    cancel,
                    handle.authenticate_certificate_with(
                        credential.username.clone(),
                        certificate,
                        hash,
                        &mut agent,
                    ),
                    "Local SSH-agent authentication failed",
                )
                .await?
            }
        };
        match auth_disposition(result) {
            AuthDisposition::Complete => return Ok(()),
            AuthDisposition::KeyboardInteractiveMfa => {
                return keyboard_interactive(
                    session_id, credential, handle, budget, cancel, prompts, pause,
                )
                .await;
            }
            AuthDisposition::UnsupportedContinuation => {
                return Err(OperationError::failed(
                    "The server requires an unsupported additional authentication method",
                ));
            }
            AuthDisposition::Rejected => {}
        }
    }

    Err(OperationError::failed(
        "The SSH server rejected every local agent identity",
    ))
}

#[allow(clippy::too_many_arguments)]
async fn keyboard_interactive(
    session_id: Uuid,
    credential: &Login,
    handle: &mut client::Handle<ClientHandler>,
    budget: &mut NetworkBudget,
    cancel: &mut watch::Receiver<bool>,
    prompts: &mpsc::Sender<PromptRequest>,
    pause: &PromptPause,
) -> std::result::Result<(), OperationError> {
    let mut response = network_call(
        budget,
        cancel,
        handle.authenticate_keyboard_interactive_start(credential.username.clone(), None::<String>),
        "Keyboard-interactive authentication failed",
    )
    .await?;

    loop {
        match response {
            KeyboardInteractiveAuthResponse::Success => return Ok(()),
            KeyboardInteractiveAuthResponse::Failure { .. } => {
                return Err(OperationError::failed(
                    "Keyboard-interactive authentication was rejected",
                ));
            }
            KeyboardInteractiveAuthResponse::InfoRequest {
                name,
                instructions,
                prompts: server_prompts,
            } => {
                let fields = server_prompts
                    .iter()
                    .map(|prompt| PromptField {
                        label: sanitize_chrome(&prompt.prompt),
                        secret: !prompt.echo,
                    })
                    .collect::<Vec<_>>();
                let title = sanitize_chrome(&name);
                let answers = ask_prompt(
                    session_id,
                    if title.trim().is_empty() {
                        "Keyboard-interactive authentication".to_owned()
                    } else {
                        title
                    },
                    sanitize_chrome(&instructions),
                    fields,
                    PromptKind::Authentication,
                    prompts,
                    cancel,
                    pause,
                )
                .await?;
                ensure_prompt_count(server_prompts.len(), answers.len())?;
                let answers = answers
                    .into_iter()
                    .map(|answer| answer.expose().to_owned())
                    .collect();
                response = network_call(
                    budget,
                    cancel,
                    handle.authenticate_keyboard_interactive_respond(answers),
                    "Keyboard-interactive authentication failed",
                )
                .await?;
            }
        }
    }
}

fn ensure_prompt_count(expected: usize, actual: usize) -> std::result::Result<(), OperationError> {
    if expected == actual {
        Ok(())
    } else {
        Err(OperationError::failed(
            "Keyboard-interactive response count was invalid",
        ))
    }
}

async fn ask_prompt(
    session_id: Uuid,
    title: String,
    description: String,
    fields: Vec<PromptField>,
    kind: PromptKind,
    prompts: &mpsc::Sender<PromptRequest>,
    cancel: &mut watch::Receiver<bool>,
    pause: &PromptPause,
) -> std::result::Result<Vec<Secret>, OperationError> {
    let _paused = pause.enter();
    let (response, answer) = oneshot::channel();
    let request = PromptRequest {
        session_id,
        title: sanitize_chrome(&title),
        description: sanitize_chrome(&description),
        fields,
        kind,
        response,
        cancelled: cancel.clone(),
    };
    tokio::select! {
        sent = prompts.send(request) => {
            if sent.is_err() {
                return Err(OperationError::failed("Authentication prompt UI is unavailable"));
            }
        }
        _ = wait_cancelled(cancel) => return Err(OperationError::Cancelled),
    }
    tokio::select! {
        response = answer => match response {
            Ok(Some(answers)) => Ok(answers),
            Ok(None) => Err(OperationError::failed(match kind {
                PromptKind::Trust => "The server key was not trusted",
                PromptKind::Authentication => "SSH authentication was cancelled",
            })),
            Err(_) => Err(OperationError::failed("Authentication prompt was dismissed")),
        },
        _ = wait_cancelled(cancel) => Err(OperationError::Cancelled),
    }
}

#[derive(Debug)]
enum DriveEnd {
    Closed {
        status: Option<u32>,
        signal: Option<String>,
    },
    ReceiverEnded {
        status: Option<u32>,
        signal: Option<String>,
    },
    Cancelled {
        status: Option<u32>,
        signal: Option<String>,
    },
    Failed(String),
}

#[allow(clippy::too_many_arguments)]
async fn setup_and_drive(
    session_id: Uuid,
    credential: &Login,
    handle: &mut client::Handle<ClientHandler>,
    budget: &mut NetworkBudget,
    cancel: &mut watch::Receiver<bool>,
    prompts: &mpsc::Sender<PromptRequest>,
    pause: &PromptPause,
    view: &Arc<Mutex<SessionView>>,
    input: mpsc::Receiver<Bytes>,
    mut dimensions: watch::Receiver<(u16, u16)>,
    repaint: &Repaint,
    check: &AuthCheck,
    handler_failure: &Mutex<Option<String>>,
) -> DriveEnd {
    let authentication = check.authenticate(
        session_id, credential, handle, budget, cancel, prompts, pause, handler_failure,
    ).await;
    if let Err(error) = authentication {
        return drive_operation_error(error, "SSH authentication timed out");
    }

    let channel = match network_call(
        budget,
        cancel,
        handle.channel_open_session(),
        "Could not open an SSH session channel",
    )
    .await
    {
        Ok(channel) => channel,
        Err(error) => return drive_operation_error(error, "SSH channel setup timed out"),
    };
    let (mut reader, writer) = channel.split();
    let mut exit = ExitRecord::default();
    let requested_dimensions = *dimensions.borrow_and_update();
    if let Err(error) = network_call(
        budget,
        cancel,
        writer.request_pty(
            true,
            "xterm-256color",
            requested_dimensions.1.into(),
            requested_dimensions.0.into(),
            0,
            0,
            &[],
        ),
        "Could not request a remote terminal",
    )
    .await
    {
        return drive_operation_error(error, "SSH terminal request timed out");
    }
    if let Err(end) = wait_request_ack(
        "The SSH server rejected the terminal request",
        &mut reader,
        &writer,
        budget,
        cancel,
        view,
        repaint,
        &mut exit,
    )
    .await
    {
        return end;
    }

    if let Err(error) = network_call(
        budget,
        cancel,
        writer.request_shell(true),
        "Could not request the remote shell",
    )
    .await
    {
        return drive_operation_error(error, "SSH shell request timed out");
    }
    if let Err(end) = wait_request_ack(
        "The SSH server rejected the shell request",
        &mut reader,
        &writer,
        budget,
        cancel,
        view,
        repaint,
        &mut exit,
    )
    .await
    {
        return end;
    }

    let current_dimensions = *dimensions.borrow_and_update();
    if let Err(error) = network_call(
        budget,
        cancel,
        writer.window_change(
            current_dimensions.1.into(),
            current_dimensions.0.into(),
            0,
            0,
        ),
        "Could not size the remote terminal",
    )
    .await
    {
        return drive_operation_error(error, "SSH terminal resize timed out");
    }

    set_phase(view, &repaint.dirty, SessionPhase::Connected);
    drive_channel(
        reader,
        writer,
        input,
        &mut dimensions,
        cancel,
        view,
        repaint,
        exit,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn wait_request_ack(
    rejection: &'static str,
    reader: &mut russh::ChannelReadHalf,
    writer: &russh::ChannelWriteHalf<client::Msg>,
    budget: &mut NetworkBudget,
    cancel: &mut watch::Receiver<bool>,
    view: &Arc<Mutex<SessionView>>,
    repaint: &Repaint,
    exit: &mut ExitRecord,
) -> std::result::Result<(), DriveEnd> {
    loop {
        let event = match network_wait(budget, cancel, reader.wait()).await {
            Ok(Some(event)) => event,
            Ok(None) => {
                return Err(DriveEnd::ReceiverEnded {
                    status: exit.status,
                    signal: exit.signal.clone(),
                });
            }
            Err(error) => return Err(drive_operation_error(error, "SSH channel setup timed out")),
        };
        match event {
            ChannelMsg::Success => return Ok(()),
            ChannelMsg::Failure => return Err(DriveEnd::Failed(rejection.to_owned())),
            ChannelMsg::Data { data } | ChannelMsg::ExtendedData { data, .. } => {
                if let Err(error) =
                    process_setup_output(data.as_ref(), writer, budget, cancel, view, repaint).await
                {
                    return Err(drive_operation_error(error, "SSH channel setup timed out"));
                }
            }
            ChannelMsg::Eof => {
                exit.eof(view, repaint);
            }
            ChannelMsg::ExitStatus { exit_status } => exit.status = Some(exit_status),
            ChannelMsg::ExitSignal { signal_name, .. } => {
                exit.signal = Some(signal_name_text(signal_name));
            }
            ChannelMsg::Close => {
                return Err(DriveEnd::Closed {
                    status: exit.status,
                    signal: exit.signal.clone(),
                });
            }
            _ => {}
        }
    }
}

fn drive_operation_error(error: OperationError, timeout: &'static str) -> DriveEnd {
    match error {
        OperationError::Cancelled => DriveEnd::Cancelled {
            status: None,
            signal: None,
        },
        OperationError::TimedOut => DriveEnd::Failed(timeout.to_owned()),
        OperationError::Failed(message) => DriveEnd::Failed(message),
    }
}

#[derive(Default)]
struct ExitRecord {
    output_ended: bool,
    status: Option<u32>,
    signal: Option<String>,
}

impl ExitRecord {
    fn eof(&mut self, view: &Arc<Mutex<SessionView>>, repaint: &Repaint) {
        self.output_ended = true;
        view.lock().output_ended = true;
        repaint.status();
    }
}

async fn process_setup_output(
    bytes: &[u8],
    writer: &russh::ChannelWriteHalf<client::Msg>,
    budget: &mut NetworkBudget,
    cancel: &mut watch::Receiver<bool>,
    view: &Arc<Mutex<SessionView>>,
    repaint: &Repaint,
) -> std::result::Result<(), OperationError> {
    for chunk in bytes.chunks(OUTPUT_CHUNK) {
        let replies = view.lock().terminal.process(chunk);
        if replies.len() <= MAX_INPUT {
            network_call(
                budget,
                cancel,
                writer.data_bytes(replies),
                "Could not send a terminal reply",
            )
            .await?;
        } else {
            for reply in replies.chunks(MAX_INPUT) {
                network_call(
                    budget,
                    cancel,
                    writer.data_bytes(reply.to_vec()),
                    "Could not send a terminal reply",
                )
                .await?;
            }
        }
        tokio::task::yield_now().await;
    }
    repaint.output();
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn drive_channel(
    mut reader: russh::ChannelReadHalf,
    writer: russh::ChannelWriteHalf<client::Msg>,
    mut input: mpsc::Receiver<Bytes>,
    dimensions: &mut watch::Receiver<(u16, u16)>,
    cancel: &mut watch::Receiver<bool>,
    view: &Arc<Mutex<SessionView>>,
    repaint: &Repaint,
    mut exit: ExitRecord,
) -> DriveEnd {
    let mut input_open = true;
    loop {
        tokio::select! {
            _ = wait_cancelled(cancel) => {
                return DriveEnd::Cancelled {
                    status: exit.status,
                    signal: exit.signal,
                };
            }
            event = reader.wait() => {
                let Some(event) = event else {
                    return DriveEnd::ReceiverEnded {
                        status: exit.status,
                        signal: exit.signal,
                    };
                };
                match event {
                    ChannelMsg::Data { data } | ChannelMsg::ExtendedData { data, .. } => {
                        match process_live_output(
                            data.as_ref(),
                            &writer,
                            cancel,
                            view,
                            repaint,
                        )
                        .await
                        {
                            Ok(()) => {}
                            Err(OperationError::Cancelled) => {
                                return DriveEnd::Cancelled {
                                    status: exit.status,
                                    signal: exit.signal,
                                };
                            }
                            Err(_) => {
                                return DriveEnd::ReceiverEnded {
                                    status: exit.status,
                                    signal: exit.signal,
                                };
                            }
                        }
                    }
                    ChannelMsg::Eof => exit.eof(view, repaint),
                    ChannelMsg::ExitStatus { exit_status } => {
                        exit.status = Some(exit_status);
                        repaint.status();
                    }
                    ChannelMsg::ExitSignal { signal_name, .. } => {
                        exit.signal = Some(signal_name_text(signal_name));
                        repaint.status();
                    }
                    ChannelMsg::Close => {
                        return DriveEnd::Closed {
                            status: exit.status,
                            signal: exit.signal,
                        };
                    }
                    _ => {}
                }
            }
            bytes = input.recv(), if input_open => {
                match bytes {
                    Some(bytes) => {
                        // Wake the frontend to offer the next chunk without blocking its event loop.
                        repaint.dirty.notify_one();
                        match cancelable_call(
                            cancel,
                            writer.data_bytes(bytes),
                            "SSH input transport ended",
                        )
                        .await
                        {
                            Ok(()) => {}
                            Err(OperationError::Cancelled) => {
                                return DriveEnd::Cancelled {
                                    status: exit.status,
                                    signal: exit.signal,
                                };
                            }
                            Err(_) => {
                                return DriveEnd::ReceiverEnded {
                                    status: exit.status,
                                    signal: exit.signal,
                                };
                            }
                        }
                    }
                    None => input_open = false,
                }
            }
            changed = dimensions.changed() => {
                if changed.is_err() {
                    continue;
                }
                let (rows, cols) = *dimensions.borrow_and_update();
                match cancelable_call(
                    cancel,
                    writer.window_change(cols.into(), rows.into(), 0, 0),
                    "SSH resize transport ended",
                )
                .await
                {
                    Ok(()) => {}
                    Err(OperationError::Cancelled) => {
                        return DriveEnd::Cancelled {
                            status: exit.status,
                            signal: exit.signal,
                        };
                    }
                    Err(_) => {
                        return DriveEnd::ReceiverEnded {
                            status: exit.status,
                            signal: exit.signal,
                        };
                    }
                }
            }
        }
    }
}

async fn process_live_output(
    bytes: &[u8],
    writer: &russh::ChannelWriteHalf<client::Msg>,
    cancel: &mut watch::Receiver<bool>,
    view: &Arc<Mutex<SessionView>>,
    repaint: &Repaint,
) -> std::result::Result<(), OperationError> {
    for chunk in bytes.chunks(OUTPUT_CHUNK) {
        let replies = view.lock().terminal.process(chunk);
        if replies.len() <= MAX_INPUT {
            cancelable_call(
                cancel,
                writer.data_bytes(replies),
                "Terminal reply transport ended",
            )
            .await?;
        } else {
            for reply in replies.chunks(MAX_INPUT) {
                cancelable_call(
                    cancel,
                    writer.data_bytes(reply.to_vec()),
                    "Terminal reply transport ended",
                )
                .await?;
            }
        }
        tokio::task::yield_now().await;
    }
    repaint.output();
    Ok(())
}

fn signal_name_text(signal: Sig) -> String {
    match signal {
        Sig::ABRT => "ABRT".to_owned(),
        Sig::ALRM => "ALRM".to_owned(),
        Sig::FPE => "FPE".to_owned(),
        Sig::HUP => "HUP".to_owned(),
        Sig::ILL => "ILL".to_owned(),
        Sig::INT => "INT".to_owned(),
        Sig::KILL => "KILL".to_owned(),
        Sig::PIPE => "PIPE".to_owned(),
        Sig::QUIT => "QUIT".to_owned(),
        Sig::SEGV => "SEGV".to_owned(),
        Sig::TERM => "TERM".to_owned(),
        Sig::USR1 => "USR1".to_owned(),
        Sig::Custom(name) => sanitize_chrome(&name),
    }
}

fn sanitize_chrome(text: &str) -> String {
    const LIMIT: usize = 240;
    let mut sanitized = String::new();
    for character in text.chars().take(LIMIT) {
        if character == '\n' || character == '\t' || !character.is_control() {
            sanitized.push(character);
        }
    }
    sanitized
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    struct StalledClient;

    impl client::Handler for StalledClient {
        type Error = russh::Error;
    }

    fn public_key(algorithm: &str, base64: &str) -> PublicKey {
        PublicKey::from_openssh(&format!("{algorithm} {base64}")).unwrap()
    }

    #[test]
    fn complete_host_key_pin_rejects_any_different_key() {
        let first = public_key(
            "ssh-ed25519",
            "AAAAC3NzaC1lZDI1NTE5AAAAILagOJFgwaMNhBWQINinKOXmqS4Gh5NgxgriXwdOoINJ",
        );
        let second = public_key(
            "ecdsa-sha2-nistp256",
            "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMxBTpMIGvo7CnordO7wP0QQRqpBwUjOLl4eMhfucfE1sjTYyK5wmTl1UqoSDS1PtRVTBdl+0+9pquFb46U7fwg=",
        );
        let encoded = first.to_openssh().unwrap();

        assert_eq!(pin_decision(None, &first).unwrap(), PinDecision::Unknown);
        assert_eq!(
            pin_decision(Some(&encoded), &first).unwrap(),
            PinDecision::Trusted
        );
        assert!(matches!(
            pin_decision(Some(&encoded), &second).unwrap(),
            PinDecision::Changed { .. }
        ));
    }

    #[test]
    fn only_partial_keyboard_interactive_continues_authentication() {
        let keyboard = AuthResult::Failure {
            remaining_methods: (&[MethodKind::KeyboardInteractive][..]).into(),
            partial_success: true,
        };
        let password = AuthResult::Failure {
            remaining_methods: (&[MethodKind::Password][..]).into(),
            partial_success: true,
        };
        let not_partial = AuthResult::Failure {
            remaining_methods: (&[MethodKind::KeyboardInteractive][..]).into(),
            partial_success: false,
        };

        assert_eq!(
            auth_disposition(keyboard),
            AuthDisposition::KeyboardInteractiveMfa
        );
        assert_eq!(
            auth_disposition(password),
            AuthDisposition::UnsupportedContinuation
        );
        assert_eq!(auth_disposition(not_partial), AuthDisposition::Rejected);
    }

    #[test]
    fn eof_does_not_invent_or_discard_exit_status() {
        let view = Arc::new(Mutex::new(SessionView {
            terminal: TerminalState::new(24, 80),
            phase: SessionPhase::Connected,
            output_ended: false,
            auth_notice: None,
        }));
        let repaint = Repaint {
            visible: Arc::new(AtomicBool::new(false)),
            dirty: Arc::new(Notify::new()),
        };
        let mut exit = ExitRecord::default();
        exit.eof(&view, &repaint);
        assert!(exit.output_ended);
        assert_eq!(exit.status, None);
        exit.status = Some(7);
        assert_eq!(exit.status, Some(7));
    }

    #[tokio::test]
    async fn paused_prompt_time_is_not_charged_to_network_deadline() {
        let (pause_tx, pause_rx) = watch::channel(true);
        let (_cancel_tx, mut cancel_rx) = watch::channel(false);
        let mut budget = NetworkBudget::with_limit(pause_rx, Duration::from_millis(1));
        let operation = tokio::time::sleep(Duration::from_millis(10));
        tokio::pin!(operation);
        assert_eq!(
            budget.wait(operation.as_mut(), &mut cancel_rx).await,
            Ok(())
        );
        drop(pause_tx);
    }

    #[tokio::test]
    async fn shutdown_wakes_and_awaits_a_stalled_russh_handshake() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let fixture = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket.write_all(b"SSH-2.0-stalled\r\n").await.unwrap();
            tokio::time::sleep(Duration::from_secs(5)).await;
        });

        let stream = TcpStream::connect(address).await.unwrap();
        stream.set_nodelay(true).unwrap();
        let standard = stream.into_std().unwrap();
        let shutdown = standard.try_clone().unwrap();
        let stream = TcpStream::from_std(standard).unwrap();
        let connecting =
            client::connect_stream(Arc::new(client::Config::default()), stream, StalledClient);
        tokio::pin!(connecting);
        tokio::time::sleep(Duration::from_millis(20)).await;
        shutdown.shutdown(Shutdown::Both).unwrap();

        let completed = tokio::time::timeout(Duration::from_secs(1), connecting.as_mut())
            .await
            .expect("socket shutdown must wake the handshake");
        assert!(completed.is_err());
        fixture.abort();
        let _ = fixture.await;
    }

    #[test]
    fn remote_chrome_cannot_inject_terminal_controls() {
        assert_eq!(sanitize_chrome("bad\u{1b}[31m\0name"), "bad[31mname");
    }
}
