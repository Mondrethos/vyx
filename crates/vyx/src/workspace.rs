use std::{
    fs,
    io::{self, Write},
    os::{
        fd::AsRawFd,
        unix::{
            ffi::OsStrExt,
            fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt},
            process::CommandExt,
        },
    },
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail, ensure};
use crossterm::{
    event::{Event, EventStream},
    terminal,
};
use futures_util::StreamExt;
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{
        UnixListener, UnixStream,
        unix::{OwnedReadHalf, OwnedWriteHalf},
    },
    sync::{mpsc, watch},
    task::{JoinHandle, JoinSet},
    time::{Instant, sleep, timeout},
};

use crate::screen::TerminalGuard;

const PROTOCOL_MAGIC: &[u8; 4] = b"VYXW";
const PROTOCOL_VERSION: u16 = 3;
const HEADER_LEN: usize = 12;

const KIND_HELLO: u8 = 1;
const KIND_PROBE: u8 = 2;
const KIND_ATTACHED: u8 = 3;
const KIND_RUNNING: u8 = 4;
const KIND_REFUSED: u8 = 5;
const KIND_EVENT: u8 = 6;
const KIND_CLIENT_DETACH: u8 = 7;
const KIND_RENDER: u8 = 8;
const KIND_DETACHED: u8 = 9;
const KIND_FINISHED: u8 = 10;
const KIND_CONNECT: u8 = 11;
const KIND_CLIENT_SHUTDOWN: u8 = 12;

const MAX_DIMENSION: u16 = 4096;
const MAX_CELLS: u32 = 65_536;
const MAX_PASTE_BYTES: usize = 1024 * 1024;
// A control character can require six JSON bytes; reserve room for the event envelope.
const MAX_EVENT_PAYLOAD: usize = MAX_PASTE_BYTES * 6 + 1024;
const MAX_RENDER_PAYLOAD: usize = 8 * 1024 * 1024;
const MAX_CONTROL_PAYLOAD: usize = 4096;
const MAX_WIRE_PAYLOAD: usize = MAX_RENDER_PAYLOAD;
const EVENT_QUEUE_CAPACITY: usize = 4;
const OUTPUT_QUEUE_CAPACITY: usize = 4;
const CLIENT_FRAME_QUEUE_CAPACITY: usize = 4;
const MAX_SESSION_TASKS: usize = 8;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);
const FRAME_WRITE_TIMEOUT: Duration = Duration::from_millis(750);
const STARTUP_TIMEOUT: Duration = Duration::from_secs(5);
const ATTACH_ONLY_TIMEOUT: Duration = Duration::from_millis(600);
const WORKER_ORPHAN_TIMEOUT: Duration = Duration::from_secs(7);
const RETRY_INTERVAL: Duration = Duration::from_millis(40);
const FINISH_TIMEOUT: Duration = Duration::from_secs(2);
const REAP_TIMEOUT: Duration = Duration::from_secs(1);

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("vyx local workspaces currently support Linux and macOS");

#[derive(Debug)]
pub enum WorkspaceEvent {
    Attached(u16, u16),
    Detached,
    Input(Event),
    Connect(String),
}

pub struct DisplayWriter {
    shared: Arc<Shared>,
    attachment: Option<u64>,
    pending: Vec<u8>,
}

pub struct Workspace {
    shared: Arc<Shared>,
    events: mpsc::Receiver<InboundEvent>,
    lifecycle: watch::Receiver<Lifecycle>,
    shutdown: watch::Sender<bool>,
    listener_task: Option<JoinHandle<()>>,
    endpoint: PathBuf,
    socket_identity: SocketIdentity,
    finished: bool,
}

#[derive(Clone, Copy)]
struct SocketIdentity {
    device: u64,
    inode: u64,
}

struct Shared {
    state: Mutex<SharedState>,
    events: mpsc::Sender<InboundEvent>,
    lifecycle: watch::Sender<Lifecycle>,
    next_attachment: AtomicU64,
}

struct SharedState {
    current: Option<Attachment>,
    finishing: bool,
    ever_attached: bool,
    input_generation: u64,
}

struct Attachment {
    id: u64,
    announced: bool,
    output: mpsc::Sender<Outbound>,
    control: watch::Sender<SessionControl>,
}

struct InboundEvent {
    attachment: u64,
    input_generation: u64,
    event: WorkspaceEvent,
}

#[derive(Clone, Debug)]
struct Lifecycle {
    attachment: u64,
    state: LifecycleState,
}

#[derive(Clone, Debug)]
enum LifecycleState {
    Detached,
    Attached(u16, u16),
    Finished,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SessionControl {
    Running,
    Detach,
    Shutdown,
}

enum Outbound {
    Render(Vec<u8>),
    Finish(Option<String>),
}

struct Session {
    id: u64,
    stream: UnixStream,
    output: mpsc::Receiver<Outbound>,
    control: watch::Receiver<SessionControl>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReaderEnd {
    Detached,
    Shutdown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WriterEnd {
    Detached,
    Finished,
    Shutdown,
    Failed,
}

struct Frame {
    version: u16,
    kind: u8,
    payload: Vec<u8>,
}

enum HandshakeResult {
    Attached { stream: UnixStream, worker_pid: u32 },
    Running(u32),
}

enum ConnectFailure {
    Unavailable,
    Refused(String),
    Fatal(anyhow::Error),
}

enum FrontendExit {
    Detached,
    External,
    Finished(Option<String>),
    Failed(anyhow::Error),
}

impl Workspace {
    /// Binds this data directory's private local endpoint. The caller must already own the
    /// Directory lock, which is what makes reclaiming this endpoint safe.
    pub fn bind(data_dir: &Path) -> Result<Self> {
        let data_dir = canonical_existing_directory(data_dir)?;
        let endpoint = endpoint_for(&data_dir)?;
        reclaim_stale_endpoint(&endpoint)?;

        let listener = UnixListener::bind(&endpoint)
            .with_context(|| format!("bind local workspace endpoint {}", endpoint.display()))?;
        fs::set_permissions(&endpoint, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("secure local workspace endpoint {}", endpoint.display()))?;
        let metadata = secure_socket_metadata(&endpoint)?;
        let socket_identity = SocketIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        };

        let (event_sender, events) = mpsc::channel(EVENT_QUEUE_CAPACITY);
        let initial = Lifecycle {
            attachment: 0,
            state: LifecycleState::Detached,
        };
        let (lifecycle_sender, lifecycle) = watch::channel(initial);
        let shared = Arc::new(Shared {
            state: Mutex::new(SharedState {
                current: None,
                finishing: false,
                ever_attached: false,
                input_generation: 0,
            }),
            events: event_sender,
            lifecycle: lifecycle_sender,
            next_attachment: AtomicU64::new(1),
        });
        let (shutdown, shutdown_receiver) = watch::channel(false);
        let listener_shared = Arc::clone(&shared);
        let listener_task = tokio::spawn(async move {
            listener_loop(listener, listener_shared, shutdown_receiver).await;
        });

        Ok(Self {
            shared,
            events,
            lifecycle,
            shutdown,
            listener_task: Some(listener_task),
            endpoint,
            socket_identity,
            finished: false,
        })
    }

    pub fn writer(&self) -> DisplayWriter {
        DisplayWriter {
            shared: Arc::clone(&self.shared),
            attachment: None,
            pending: Vec::with_capacity(16 * 1024),
        }
    }

    pub async fn next_event(&mut self) -> Option<WorkspaceEvent> {
        loop {
            tokio::select! {
                biased;
                changed = self.lifecycle.changed() => {
                    if changed.is_err() {
                        return None;
                    }
                    let lifecycle = self.lifecycle.borrow_and_update().clone();
                    match lifecycle.state {
                        LifecycleState::Attached(columns, rows) => {
                            if self.shared.announce(lifecycle.attachment) {
                                return Some(WorkspaceEvent::Attached(columns, rows));
                            }
                        }
                        LifecycleState::Detached => return Some(WorkspaceEvent::Detached),
                        LifecycleState::Finished => return None,
                    }
                }
                incoming = self.events.recv() => {
                    let incoming = incoming?;
                    if self.shared.accepts(&incoming) {
                        return Some(incoming.event);
                    }
                }
            }
        }
    }

    pub(crate) fn fence_authentication_input(&mut self) {
        let mut state = self.shared.lock();
        state.input_generation = state.input_generation.wrapping_add(1);
    }

    pub fn is_attached(&self) -> bool {
        self.shared.is_attached()
    }

    /// Detaches synchronously from the worker's point of view. Socket notification and closure
    /// happen asynchronously, but is_attached() is false before this method returns.
    pub fn detach(&self) {
        self.shared.detach_current();
    }

    pub async fn finish(&mut self, error: Option<String>) -> Result<()> {
        if self.finished {
            return Ok(());
        }
        self.finished = true;

        let output = self.shared.begin_finish();
        if let Some((attachment, output)) = output {
            let message = Outbound::Finish(error.map(|value| safe_console_text(&value)));
            if timeout(FRAME_WRITE_TIMEOUT, output.send(message))
                .await
                .is_err()
            {
                self.shared.clear_if(attachment);
            } else {
                let mut lifecycle = self.shared.lifecycle.subscribe();
                let wait_for_session = async {
                    while self.shared.contains_attachment(attachment) {
                        if lifecycle.changed().await.is_err() {
                            break;
                        }
                    }
                };
                let _ = timeout(FINISH_TIMEOUT, wait_for_session).await;
            }
        }

        self.shared.mark_finished();
        self.shutdown.send_replace(true);

        let mut task_error = None;
        if let Some(mut task) = self.listener_task.take() {
            match timeout(FINISH_TIMEOUT, &mut task).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    task_error = Some(anyhow!(error).context("workspace listener failed"))
                }
                Err(_) => {
                    task.abort();
                    let _ = task.await;
                    task_error = Some(anyhow!("workspace listener did not stop promptly"));
                }
            }
        }

        let cleanup = remove_own_endpoint(&self.endpoint, self.socket_identity);
        if let Some(error) = task_error {
            cleanup?;
            return Err(error);
        }
        cleanup
    }
}

impl DisplayWriter {
    /// Publishes one complete Ratatui draw. CrosstermBackend flushes during cursor and clear
    /// operations, so std::io::Write::flush intentionally does not delimit transport frames.
    pub async fn publish(&mut self) {
        let Some(attachment) = self.attachment.take() else {
            self.pending.clear();
            return;
        };
        if self.pending.is_empty() {
            return;
        }
        let Some((current, output)) = self.shared.output_target() else {
            self.pending.clear();
            return;
        };
        if current != attachment {
            self.pending.clear();
            return;
        }

        // A burst of redraws must backpressure, not discard a delta. A closed output path means
        // the attached frontend is gone and must terminate this worker rather than detach it.
        let frame = std::mem::replace(&mut self.pending, Vec::with_capacity(16 * 1024));
        if output.send(Outbound::Render(frame)).await.is_err() {
            self.shared.shutdown_if(attachment);
        }
    }
}

impl Write for DisplayWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }

        let Some((attachment, _)) = self.shared.output_target() else {
            self.pending.clear();
            self.attachment = None;
            return Ok(bytes.len());
        };
        if self.attachment != Some(attachment) {
            self.pending.clear();
            self.attachment = Some(attachment);
        }

        let Some(new_length) = self.pending.len().checked_add(bytes.len()) else {
            self.pending.clear();
            self.attachment = None;
            self.shared.shutdown_if(attachment);
            return Ok(bytes.len());
        };
        if new_length > MAX_RENDER_PAYLOAD {
            self.pending.clear();
            self.attachment = None;
            self.shared.shutdown_if(attachment);
            return Ok(bytes.len());
        }
        self.pending.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, SharedState> {
        self.state.lock().unwrap_or_else(|error| error.into_inner())
    }

    fn attach(
        &self,
        columns: u16,
        rows: u16,
        output: mpsc::Sender<Outbound>,
        control: watch::Sender<SessionControl>,
    ) -> std::result::Result<u64, &'static str> {
        let mut state = self.lock();
        if state.finishing {
            return Err("The workspace is shutting down");
        }
        if state.current.is_some() {
            return Err("Another terminal is already attached to this workspace");
        }
        let id = self.next_attachment.fetch_add(1, Ordering::Relaxed);
        state.current = Some(Attachment {
            id,
            announced: false,
            output,
            control,
        });
        state.ever_attached = true;
        self.lifecycle.send_replace(Lifecycle {
            attachment: id,
            state: LifecycleState::Attached(columns, rows),
        });
        Ok(id)
    }
    fn announce(&self, attachment: u64) -> bool {
        let mut state = self.lock();
        if state.finishing {
            return false;
        }
        let Some(current) = state.current.as_mut() else {
            return false;
        };
        if current.id != attachment {
            return false;
        }
        current.announced = true;
        true
    }

    fn is_attached(&self) -> bool {
        let state = self.lock();
        !state.finishing
            && state
                .current
                .as_ref()
                .is_some_and(|current| current.announced)
    }

    fn accepts(&self, incoming: &InboundEvent) -> bool {
        let state = self.lock();
        !state.finishing
            && state.current.as_ref().is_some_and(|current| current.id == incoming.attachment)
            && (incoming.input_generation == state.input_generation
                || !matches!(&incoming.event,
                    WorkspaceEvent::Input(Event::Key(_) | Event::Paste(_) | Event::Mouse(_))))
    }

    fn contains_attachment(&self, attachment: u64) -> bool {
        self.lock()
            .current
            .as_ref()
            .is_some_and(|current| current.id == attachment)
    }

    fn output_target(&self) -> Option<(u64, mpsc::Sender<Outbound>)> {
        let state = self.lock();
        if state.finishing {
            return None;
        }
        state.current.as_ref().and_then(|current| {
            current
                .announced
                .then(|| (current.id, current.output.clone()))
        })
    }

    async fn submit_event(&self, attachment: u64, event: WorkspaceEvent) -> bool {
        let input_generation = {
            let state = self.lock();
            if state.finishing || !state.current.as_ref().is_some_and(|current| current.id == attachment) {
                return false;
            }
            state.input_generation
        };
        // Stamp before awaiting queue capacity: a sender blocked during authentication
        // belongs to the old input generation even if it is enqueued after the handoff.
        self.events
            .send(InboundEvent { attachment, input_generation, event })
            .await
            .is_ok()
    }

    fn detach_current(&self) {
        let attachment = self.lock().current.as_ref().map(|current| current.id);
        if let Some(attachment) = attachment {
            self.detach_if(attachment);
        }
    }

    fn detach_if(&self, attachment: u64) {
        let detached = {
            let mut state = self.lock();
            if !state.finishing
                && state
                    .current
                    .as_ref()
                    .is_some_and(|current| current.id == attachment)
            {
                state.current.take()
            } else {
                None
            }
        };
        if let Some(detached) = detached {
            self.lifecycle.send_replace(Lifecycle {
                attachment,
                state: LifecycleState::Detached,
            });
            detached.control.send_replace(SessionControl::Detach);
        }
    }

    fn shutdown_if(&self, attachment: u64) {
        let shutdown = {
            let mut state = self.lock();
            let current = state
                .current
                .as_ref()
                .is_some_and(|current| current.id == attachment);
            if current {
                state.finishing = true;
            }
            current
        };
        if shutdown {
            self.lifecycle.send_replace(Lifecycle {
                attachment,
                state: LifecycleState::Finished,
            });
        }
    }

    fn awaits_first_attachment(&self) -> bool {
        let state = self.lock();
        !state.ever_attached && state.current.is_none() && !state.finishing
    }

    fn shutdown_unattached(&self) -> bool {
        let shutdown = {
            let mut state = self.lock();
            if state.ever_attached || state.current.is_some() || state.finishing {
                false
            } else {
                state.finishing = true;
                true
            }
        };
        if shutdown {
            self.lifecycle.send_replace(Lifecycle {
                attachment: 0,
                state: LifecycleState::Finished,
            });
        }
        shutdown
    }

    fn clear_if(&self, attachment: u64) {
        let finished = {
            let mut state = self.lock();
            let current = state
                .current
                .as_ref()
                .is_some_and(|current| current.id == attachment);
            if current {
                state.current.take();
            }
            current && state.finishing
        };
        if finished {
            self.lifecycle.send_replace(Lifecycle {
                attachment,
                state: LifecycleState::Finished,
            });
        }
    }

    fn begin_finish(&self) -> Option<(u64, mpsc::Sender<Outbound>)> {
        let mut state = self.lock();
        state.finishing = true;
        state
            .current
            .as_ref()
            .map(|current| (current.id, current.output.clone()))
    }

    fn mark_finished(&self) {
        let current = {
            let mut state = self.lock();
            state.finishing = true;
            state.current.take()
        };
        if let Some(current) = current {
            current.control.send_replace(SessionControl::Shutdown);
        }
        self.lifecycle.send_replace(Lifecycle {
            attachment: 0,
            state: LifecycleState::Finished,
        });
    }

    fn listener_failed(&self) {
        self.mark_finished();
    }
}

async fn listener_loop(
    listener: UnixListener,
    shared: Arc<Shared>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut sessions = JoinSet::new();
    let orphan_timeout = sleep(WORKER_ORPHAN_TIMEOUT);
    tokio::pin!(orphan_timeout);
    loop {
        tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            _ = &mut orphan_timeout, if shared.awaits_first_attachment() => {
                if shared.shutdown_unattached() {
                    break;
                }
            }
            Some(_) = sessions.join_next(), if !sessions.is_empty() => {}
            accepted = listener.accept() => {
                let (stream, _) = match accepted {
                    Ok(value) => value,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(_) => {
                        shared.listener_failed();
                        break;
                    }
                };
                if sessions.len() >= MAX_SESSION_TASKS {
                    continue;
                }
                if let Some(session) = accept_client(stream, &shared).await {
                    let session_shared = Arc::clone(&shared);
                    let session_shutdown = shutdown.clone();
                    sessions.spawn(async move {
                        run_session(session, session_shared, session_shutdown).await;
                    });
                }
            }
        }
    }

    sessions.abort_all();
    while sessions.join_next().await.is_some() {}
}

async fn accept_client(mut stream: UnixStream, shared: &Arc<Shared>) -> Option<Session> {
    if verify_peer(&stream).is_err() {
        return None;
    }
    let frame = match timeout(HANDSHAKE_TIMEOUT, read_frame(&mut stream, 4)).await {
        Ok(Ok(Some(frame))) => frame,
        _ => return None,
    };
    if frame.version != PROTOCOL_VERSION {
        let _ = write_frame_timeout(
            &mut stream,
            KIND_REFUSED,
            b"Incompatible vyx local-workspace protocol",
        )
        .await;
        return None;
    }

    match frame.kind {
        KIND_PROBE if frame.payload.is_empty() => {
            let _ =
                write_frame_timeout(&mut stream, KIND_RUNNING, &std::process::id().to_be_bytes())
                    .await;
            None
        }
        KIND_HELLO => {
            let (columns, rows) = match decode_dimensions(&frame.payload) {
                Ok(value) => value,
                Err(_) => {
                    let _ = write_frame_timeout(
                        &mut stream,
                        KIND_REFUSED,
                        b"Invalid terminal dimensions",
                    )
                    .await;
                    return None;
                }
            };
            let (output_sender, output) = mpsc::channel(OUTPUT_QUEUE_CAPACITY);
            let (control_sender, control) = watch::channel(SessionControl::Running);
            let id = match shared.attach(columns, rows, output_sender, control_sender) {
                Ok(id) => id,
                Err(message) => {
                    let _ =
                        write_frame_timeout(&mut stream, KIND_REFUSED, message.as_bytes()).await;
                    return None;
                }
            };
            if write_frame_timeout(
                &mut stream,
                KIND_ATTACHED,
                &std::process::id().to_be_bytes(),
            )
            .await
            .is_err()
            {
                shared.shutdown_if(id);
                shared.clear_if(id);
                return None;
            }
            Some(Session {
                id,
                stream,
                output,
                control,
            })
        }
        _ => {
            let _ = write_frame_timeout(
                &mut stream,
                KIND_REFUSED,
                b"Invalid vyx local-workspace handshake",
            )
            .await;
            None
        }
    }
}

async fn run_session(session: Session, shared: Arc<Shared>, mut shutdown: watch::Receiver<bool>) {
    let Session {
        id,
        stream,
        output,
        control,
    } = session;
    let (reader, writer) = stream.into_split();
    let reader_shared = Arc::clone(&shared);
    let mut reader_task =
        tokio::spawn(async move { server_reader(reader, id, reader_shared).await });
    let mut writer_task =
        tokio::spawn(async move { server_writer(writer, output, control).await });

    enum FirstEnd {
        Reader(ReaderEnd),
        Writer(WriterEnd),
        Listener,
    }

    let first = tokio::select! {
        result = &mut reader_task => {
            FirstEnd::Reader(result.unwrap_or(ReaderEnd::Shutdown))
        }
        result = &mut writer_task => {
            FirstEnd::Writer(result.unwrap_or(WriterEnd::Failed))
        }
        changed = shutdown.changed() => {
            let _ = changed;
            FirstEnd::Listener
        }
    };
    let reader_done = matches!(&first, FirstEnd::Reader(_));
    let mut writer_done = matches!(&first, FirstEnd::Writer(_));

    match first {
        FirstEnd::Reader(ReaderEnd::Detached) => {
            shared.detach_if(id);
            if timeout(FINISH_TIMEOUT, &mut writer_task).await.is_ok() {
                writer_done = true;
            }
        }
        FirstEnd::Reader(ReaderEnd::Shutdown) => {
            shared.shutdown_if(id);
            tokio::select! {
                _ = &mut writer_task => writer_done = true,
                changed = shutdown.changed() => {
                    let _ = changed;
                }
            }
        }
        FirstEnd::Writer(WriterEnd::Detached) => shared.detach_if(id),
        FirstEnd::Writer(WriterEnd::Failed) => shared.shutdown_if(id),
        FirstEnd::Writer(WriterEnd::Finished | WriterEnd::Shutdown) | FirstEnd::Listener => {}
    }

    if !reader_done {
        reader_task.abort();
        let _ = reader_task.await;
    }
    if !writer_done {
        writer_task.abort();
        let _ = writer_task.await;
    }
    shared.clear_if(id);
}

async fn server_reader(
    mut reader: OwnedReadHalf,
    attachment: u64,
    shared: Arc<Shared>,
) -> ReaderEnd {
    loop {
        let frame = match read_frame(&mut reader, MAX_EVENT_PAYLOAD).await {
            Ok(Some(frame)) => frame,
            Ok(None) | Err(_) => return ReaderEnd::Shutdown,
        };
        if frame.version != PROTOCOL_VERSION {
            return ReaderEnd::Shutdown;
        }
        match frame.kind {
            KIND_EVENT => {
                let event: Event = match serde_json::from_slice(&frame.payload) {
                    Ok(event) => event,
                    Err(_) => return ReaderEnd::Shutdown,
                };
                if validate_event(&event).is_err()
                    || !shared
                        .submit_event(attachment, WorkspaceEvent::Input(event))
                        .await
                {
                    return ReaderEnd::Shutdown;
                }
            }
            KIND_CONNECT => {
                let server = match String::from_utf8(frame.payload) {
                    Ok(server) if !server.is_empty() => server,
                    _ => return ReaderEnd::Shutdown,
                };
                if !shared
                    .submit_event(attachment, WorkspaceEvent::Connect(server))
                    .await
                {
                    return ReaderEnd::Shutdown;
                }
            }
            KIND_CLIENT_DETACH if frame.payload.is_empty() => return ReaderEnd::Detached,
            KIND_CLIENT_SHUTDOWN if frame.payload.is_empty() => return ReaderEnd::Shutdown,
            _ => return ReaderEnd::Shutdown,
        }
    }
}

async fn server_writer(
    mut writer: OwnedWriteHalf,
    mut output: mpsc::Receiver<Outbound>,
    mut control: watch::Receiver<SessionControl>,
) -> WriterEnd {
    loop {
        tokio::select! {
            biased;
            changed = control.changed() => {
                if changed.is_err() {
                    return WriterEnd::Shutdown;
                }
                let command = *control.borrow_and_update();
                match command {
                    SessionControl::Running => {}
                    SessionControl::Detach => {
                        let _ = write_frame_timeout(&mut writer, KIND_DETACHED, &[]).await;
                        return WriterEnd::Detached;
                    }
                    SessionControl::Shutdown => return WriterEnd::Shutdown,
                }
            }
            message = output.recv() => {
                match message {
                    Some(Outbound::Render(bytes)) => {
                        if write_frame_timeout(&mut writer, KIND_RENDER, &bytes).await.is_err() {
                            return WriterEnd::Failed;
                        }
                    }
                    Some(Outbound::Finish(error)) => {
                        let payload = encode_finish(error.as_deref());
                        return if write_frame_timeout(&mut writer, KIND_FINISHED, &payload)
                            .await
                            .is_ok()
                        {
                            WriterEnd::Finished
                        } else {
                            WriterEnd::Failed
                        };
                    }
                    None => return WriterEnd::Shutdown,
                }
            }
        }
    }
}

pub async fn connect(
    data_dir: &Path,
    restore: Option<&Path>,
    attach_only: bool,
    server: Option<&str>,
) -> Result<()> {
    ensure!(
        !(restore.is_some() && attach_only),
        "Restore cannot be combined with attach-only mode"
    );
    if let Some(server) = server {
        ensure!(
            !server.is_empty() && server.len() <= MAX_EVENT_PAYLOAD,
            "Saved-server name must be nonempty and fit within the local-workspace message limit"
        );
        ensure!(restore.is_none(), "Restore cannot be combined with a saved-server name");
    }
    let data_dir = prepare_data_directory(data_dir)?;
    let endpoint = endpoint_for(&data_dir)?;
    let restore = restore.map(canonical_restore_file).transpose()?;

    if restore.is_some() {
        match fs::symlink_metadata(data_dir.join("state.vyx")) {
            Ok(_) => bail!("Restore refuses to overwrite an existing state.vyx"),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("inspect existing local vault"),
        }
        match probe_once(&endpoint).await {
            Ok(HandshakeResult::Running(_)) | Ok(HandshakeResult::Attached { .. }) => {
                bail!("Restore refuses to attach to a running workspace")
            }
            Err(ConnectFailure::Unavailable) => {}
            Err(ConnectFailure::Refused(message)) => bail!(message),
            Err(ConnectFailure::Fatal(error)) => return Err(error),
        }
    } else {
        match attach_once(&endpoint).await {
            Ok(HandshakeResult::Attached {
                stream,
                worker_pid: _,
            }) => {
                return run_frontend(stream, &data_dir, None, server).await;
            }
            Ok(HandshakeResult::Running(_)) => {
                bail!("Invalid response from the local vyx workspace")
            }
            Err(ConnectFailure::Refused(message)) => bail!(message),
            Err(ConnectFailure::Fatal(error)) => return Err(error),
            Err(ConnectFailure::Unavailable) => {}
        }
    }

    if attach_only {
        let deadline = Instant::now() + ATTACH_ONLY_TIMEOUT;
        loop {
            match attach_once(&endpoint).await {
                Ok(HandshakeResult::Attached {
                    stream,
                    worker_pid: _,
                }) => {
                    return run_frontend(stream, &data_dir, None, server).await;
                }
                Ok(HandshakeResult::Running(_)) => {
                    bail!("Invalid response from the local vyx workspace")
                }
                Err(ConnectFailure::Refused(message)) => bail!(message),
                Err(ConnectFailure::Fatal(error)) => return Err(error),
                Err(ConnectFailure::Unavailable) if Instant::now() < deadline => {
                    sleep(RETRY_INTERVAL).await;
                }
                Err(ConnectFailure::Unavailable) => {
                    bail!("No running vyx workspace was found for this data directory")
                }
            }
        }
    }

    let mut child = spawn_worker(&data_dir, restore.as_deref())?;
    let child_pid = child.id();
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    let (stream, owns_attached_worker) = loop {
        if restore.is_some() {
            match probe_once(&endpoint).await {
                Ok(HandshakeResult::Running(pid)) if pid == child_pid => {
                    match attach_once(&endpoint).await {
                        Ok(HandshakeResult::Attached {
                            mut stream,
                            worker_pid,
                        }) => {
                            if worker_pid == child_pid
                                && child
                                    .try_wait()
                                    .context("verify workspace worker ownership")?
                                    .is_none()
                            {
                                break (stream, true);
                            }
                            let _ =
                                write_frame_timeout(&mut stream, KIND_CLIENT_DETACH, &[]).await;
                            reap_competing_child(&mut child).await?;
                            bail!("Restore refuses to attach to a different running workspace");
                        }
                        Ok(HandshakeResult::Running(_)) => {
                            bail!("Invalid response from the local vyx workspace")
                        }
                        Err(ConnectFailure::Unavailable) => {}
                        Err(ConnectFailure::Refused(message)) => bail!(message),
                        Err(ConnectFailure::Fatal(error)) => return Err(error),
                    }
                }
                Ok(HandshakeResult::Running(_)) | Ok(HandshakeResult::Attached { .. }) => {
                    reap_competing_child(&mut child).await?;
                    bail!("Restore refuses to attach to a different running workspace")
                }
                Err(ConnectFailure::Unavailable) => {}
                Err(ConnectFailure::Refused(message)) => bail!(message),
                Err(ConnectFailure::Fatal(error)) => return Err(error),
            }
        } else {
            match attach_once(&endpoint).await {
                Ok(HandshakeResult::Attached {
                    mut stream,
                    worker_pid,
                }) => {
                    let owns_worker = worker_pid == child_pid
                        && child
                            .try_wait()
                            .context("verify workspace worker ownership")?
                            .is_none();
                    if owns_worker {
                        break (stream, true);
                    }
                    if let Err(error) = reap_competing_child(&mut child).await {
                        let _ =
                            write_frame_timeout(&mut stream, KIND_CLIENT_DETACH, &[]).await;
                        return Err(error);
                    }
                    break (stream, false);
                }
                Ok(HandshakeResult::Running(_)) => {
                    bail!("Invalid response from the local vyx workspace")
                }
                Err(ConnectFailure::Unavailable) => {}
                Err(ConnectFailure::Refused(message)) => bail!(message),
                Err(ConnectFailure::Fatal(error)) => return Err(error),
            }
        }

        if let Some(status) = child.try_wait().context("inspect workspace worker")? {
            if restore.is_some() {
                return Err(worker_exit_error(status));
            }
            break (await_racing_worker(&endpoint, status).await?, false);
        }

        if Instant::now() >= deadline {
            wait_child_exit(&mut child).await?;
            bail!("Timed out waiting for the local vyx workspace worker to start");
        }
        sleep(RETRY_INTERVAL).await;
    };

    run_frontend(
        stream,
        &data_dir,
        owns_attached_worker.then_some(&mut child),
        server,
    )
    .await
}

async fn await_racing_worker(endpoint: &Path, child_status: ExitStatus) -> Result<UnixStream> {
    let deadline = Instant::now() + ATTACH_ONLY_TIMEOUT;
    loop {
        match attach_once(endpoint).await {
            Ok(HandshakeResult::Attached { stream, .. }) => return Ok(stream),
            Ok(HandshakeResult::Running(_)) => {
                bail!("Invalid response from the local vyx workspace")
            }
            Err(ConnectFailure::Refused(message)) => bail!(message),
            Err(ConnectFailure::Fatal(error)) => return Err(error),
            Err(ConnectFailure::Unavailable) if Instant::now() < deadline => {
                sleep(RETRY_INTERVAL).await;
            }
            Err(ConnectFailure::Unavailable) => return Err(worker_exit_error(child_status)),
        }
    }
}

fn spawn_worker(data_dir: &Path, restore: Option<&Path>) -> Result<Child> {
    let executable = std::env::current_exe().context("locate the vyx executable")?;
    let current_directory = std::env::current_dir().context("read the current directory")?;
    let mut command = Command::new(executable);
    command
        .arg("--worker")
        .arg("--data-dir")
        .arg(data_dir)
        .current_dir(current_directory)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(file) = restore {
        command.arg("restore").arg("--file").arg(file);
    }
    // SAFETY: pre_exec only invokes the async-signal-safe setsid system call. The command does
    // not allocate, lock, or inspect Rust state in the child between fork and exec.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
    }
    command
        .spawn()
        .context("start the local vyx workspace worker")
}

async fn attach_once(endpoint: &Path) -> std::result::Result<HandshakeResult, ConnectFailure> {
    let (columns, rows) = terminal::size()
        .map_err(|error| ConnectFailure::Fatal(anyhow!(error).context("read terminal size")))?;
    if validate_dimensions(columns, rows).is_err() {
        return Err(ConnectFailure::Fatal(anyhow!(
            "Terminal dimensions are outside the supported range"
        )));
    }
    handshake_once(endpoint, KIND_HELLO, &encode_dimensions(columns, rows)).await
}

async fn probe_once(endpoint: &Path) -> std::result::Result<HandshakeResult, ConnectFailure> {
    handshake_once(endpoint, KIND_PROBE, &[]).await
}

async fn handshake_once(
    endpoint: &Path,
    kind: u8,
    payload: &[u8],
) -> std::result::Result<HandshakeResult, ConnectFailure> {
    match inspect_connect_endpoint(endpoint) {
        Ok(false) => return Err(ConnectFailure::Unavailable),
        Ok(true) => {}
        Err(error) => return Err(ConnectFailure::Fatal(error)),
    }
    let mut stream = match timeout(HANDSHAKE_TIMEOUT, UnixStream::connect(endpoint)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) if unavailable_error(&error) => return Err(ConnectFailure::Unavailable),
        Ok(Err(error)) => {
            return Err(ConnectFailure::Fatal(
                anyhow!(error).context("connect to the local vyx workspace"),
            ));
        }
        Err(_) => return Err(ConnectFailure::Unavailable),
    };
    verify_peer(&stream).map_err(ConnectFailure::Fatal)?;
    write_frame_timeout(&mut stream, kind, payload)
        .await
        .map_err(|_| ConnectFailure::Unavailable)?;
    let response = match timeout(
        HANDSHAKE_TIMEOUT,
        read_frame(&mut stream, MAX_CONTROL_PAYLOAD),
    )
    .await
    {
        Ok(Ok(Some(frame))) => frame,
        Ok(Ok(None)) | Err(_) => return Err(ConnectFailure::Unavailable),
        Ok(Err(error)) => {
            return Err(ConnectFailure::Fatal(
                error.context("read local workspace handshake"),
            ));
        }
    };
    if response.version != PROTOCOL_VERSION {
        return Err(ConnectFailure::Refused(
            "The running vyx workspace uses an incompatible protocol version. Quit it with the previous executable (Ctrl+B then q by default), then retry.".to_owned(),
        ));
    }
    match response.kind {
        KIND_ATTACHED if response.payload.len() == 4 => Ok(HandshakeResult::Attached {
            worker_pid: u32::from_be_bytes(response.payload.try_into().expect("checked length")),
            stream,
        }),
        KIND_RUNNING if response.payload.len() == 4 => Ok(HandshakeResult::Running(
            u32::from_be_bytes(response.payload.try_into().expect("checked length")),
        )),
        KIND_REFUSED => {
            let message = String::from_utf8(response.payload)
                .ok()
                .map(|message| safe_console_text(&message))
                .filter(|message| !message.is_empty())
                .unwrap_or_else(|| "The local vyx workspace refused this attachment".to_owned());
            Err(ConnectFailure::Refused(message))
        }
        _ => Err(ConnectFailure::Fatal(anyhow!(
            "Invalid response from the local vyx workspace"
        ))),
    }
}

async fn run_frontend(
    stream: UnixStream,
    data_dir: &Path,
    mut owned_child: Option<&mut Child>,
    server: Option<&str>,
) -> Result<()> {
    let setup = (|| -> Result<_> {
        let events = EventStream::new();
        let interrupt =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
        let terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        let hangup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
        let quit = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::quit())?;
        let guard = TerminalGuard::enter()?;
        // SIGWINCH is now subscribed; repair a resize that happened during the handshake.
        let dimensions = crossterm::terminal::size().context("read terminal dimensions")?;
        Ok((
            events, interrupt, terminate, hangup, quit, guard, dimensions,
        ))
    })();
    let (
        mut events,
        mut interrupt,
        mut terminate,
        mut hangup,
        mut quit,
        guard,
        (columns, rows),
    ) = match setup {
        Ok(setup) => setup,
        Err(error) => {
            drop(stream);
            if let Some(child) = owned_child.as_mut() {
                wait_child_exit(child).await?;
            }
            return Err(error);
        }
    };
    let (reader, mut writer) = stream.into_split();
    let setup_result: Result<()> = async {
        if let Some(server) = server {
            write_frame_timeout(&mut writer, KIND_CONNECT, server.as_bytes()).await?;
        }
        send_event(&mut writer, Event::Resize(columns, rows)).await
    }
    .await;
    if let Err(error) = setup_result {
        drop(reader);
        drop(writer);
        drop(events);
        drop(guard);
        if let Some(child) = owned_child.as_mut() {
            wait_child_exit(child).await?;
        }
        return Err(error);
    }

    // Start the framing reader only after every fallible frontend setup step. Any later
    // connection loss is a worker-shutdown request unless the user explicitly detached.
    let (frames_sender, mut frames) = mpsc::channel(CLIENT_FRAME_QUEUE_CAPACITY);
    let mut reader_task = tokio::spawn(frontend_reader(reader, frames_sender));

    let mut reader_done = false;
    let mut outcome = loop {
        tokio::select! {
            biased;
            frame = frames.recv() => {
                match frame {
                    Some(frame) => match handle_frontend_frame(frame) {
                        Ok(Some(outcome)) => break outcome,
                        Ok(None) => {}
                        Err(error) => break FrontendExit::Failed(error),
                    },
                    None => {
                        reader_done = true;
                        match (&mut reader_task).await {
                            Ok(Ok(())) => break FrontendExit::Failed(anyhow!("The workspace worker stopped unexpectedly")),
                            Ok(Err(error)) => break FrontendExit::Failed(error.context("read from the workspace worker")),
                            Err(error) => break FrontendExit::Failed(anyhow!(error).context("workspace reader failed")),
                        }
                    }
                }
            }
            result = &mut reader_task => {
                reader_done = true;
                match result {
                    Ok(Ok(())) => break FrontendExit::Failed(anyhow!("The workspace worker stopped unexpectedly")),
                    Ok(Err(error)) => break FrontendExit::Failed(error.context("read from the workspace worker")),
                    Err(error) => break FrontendExit::Failed(anyhow!(error).context("workspace reader failed")),
                }
            }
            event = events.next() => {
                match event {
                    Some(Ok(event)) => {
                        if let Err(error) = send_event(&mut writer, event).await {
                            break FrontendExit::Failed(error);
                        }
                    }
                    Some(Err(error)) => break FrontendExit::Failed(anyhow!(error).context("read terminal input")),
                    None => break FrontendExit::External,
                }
            }
            _ = interrupt.recv() => break FrontendExit::External,
            _ = terminate.recv() => break FrontendExit::External,
            _ = hangup.recv() => break FrontendExit::External,
            _ = quit.recv() => break FrontendExit::External,
        }
    };

    drop(events);
    drop(guard);
    if matches!(&outcome, FrontendExit::External) {
        outcome = match write_frame_timeout(&mut writer, KIND_CLIENT_SHUTDOWN, &[]).await {
            Ok(()) => {
                let (confirmed, finished_reader) =
                    await_shutdown_confirmation(&mut frames, &mut reader_task).await;
                reader_done |= finished_reader;
                confirmed
            }
            Err(error) => FrontendExit::Failed(
                error.context("request shutdown after terminal frontend exit"),
            ),
        };
    }

    if !reader_done {
        reader_task.abort();
        let _ = reader_task.await;
    }
    drop(writer);

    match (&outcome, owned_child.as_mut()) {
        (FrontendExit::Detached, _) => {}
        (_, Some(child)) => {
            wait_child_exit(child).await?;
        }
        (FrontendExit::Finished(_), None) => wait_workspace_release(data_dir).await?,
        (FrontendExit::External | FrontendExit::Failed(_), None) => {}
    }

    match outcome {
        FrontendExit::Detached => {
            eprintln!(
                "Detached. Reattach with `vyx --data-dir {} attach`.",
                safe_console_text(&data_dir.display().to_string())
            );
            Ok(())
        }
        FrontendExit::Finished(error) => match error {
            Some(error) => Err(anyhow!(error).context("Workspace worker stopped")),
            None => Ok(()),
        },
        FrontendExit::Failed(error) => Err(error),
        FrontendExit::External => Err(anyhow!("Workspace shutdown was not confirmed")),
    }
}

async fn await_shutdown_confirmation(
    frames: &mut mpsc::Receiver<Frame>,
    reader_task: &mut JoinHandle<Result<()>>,
) -> (FrontendExit, bool) {
    loop {
        let Some(frame) = frames.recv().await else {
            let outcome = match (&mut *reader_task).await {
                Ok(Ok(())) => {
                    FrontendExit::Failed(anyhow!("The workspace worker stopped unexpectedly"))
                }
                Ok(Err(error)) => {
                    FrontendExit::Failed(error.context("read from the workspace worker"))
                }
                Err(error) => {
                    FrontendExit::Failed(anyhow!(error).context("workspace reader failed"))
                }
            };
            return (outcome, true);
        };
        if frame.version != PROTOCOL_VERSION {
            return (
                FrontendExit::Failed(anyhow!(
                    "Workspace protocol version changed during attachment"
                )),
                false,
            );
        }
        match frame.kind {
            KIND_RENDER if frame.payload.len() <= MAX_RENDER_PAYLOAD => {}
            KIND_DETACHED if frame.payload.is_empty() => {
                return (FrontendExit::Detached, false);
            }
            KIND_FINISHED => {
                let outcome = match decode_finish(&frame.payload) {
                    Ok(error) => FrontendExit::Finished(error),
                    Err(error) => FrontendExit::Failed(error),
                };
                return (outcome, false);
            }
            _ => {
                return (
                    FrontendExit::Failed(anyhow!("Unexpected frame from the workspace worker")),
                    false,
                );
            }
        }
    }
}

async fn frontend_reader(mut reader: OwnedReadHalf, frames: mpsc::Sender<Frame>) -> Result<()> {
    loop {
        let Some(frame) = read_frame(&mut reader, MAX_WIRE_PAYLOAD).await? else {
            return Ok(());
        };
        if frames.send(frame).await.is_err() {
            return Ok(());
        }
    }
}

fn handle_frontend_frame(frame: Frame) -> Result<Option<FrontendExit>> {
    ensure!(
        frame.version == PROTOCOL_VERSION,
        "Workspace protocol version changed during attachment"
    );
    match frame.kind {
        KIND_RENDER => {
            ensure!(
                frame.payload.len() <= MAX_RENDER_PAYLOAD,
                "Workspace render frame is too large"
            );
            let mut stdout = io::stdout().lock();
            stdout
                .write_all(&frame.payload)
                .context("write workspace display")?;
            stdout.flush().context("flush workspace display")?;
            Ok(None)
        }
        KIND_DETACHED => {
            ensure!(frame.payload.is_empty(), "Invalid detach frame");
            Ok(Some(FrontendExit::Detached))
        }
        KIND_FINISHED => Ok(Some(FrontendExit::Finished(decode_finish(&frame.payload)?))),
        _ => bail!("Unexpected frame from the workspace worker"),
    }
}

async fn send_event(writer: &mut OwnedWriteHalf, event: Event) -> Result<()> {
    validate_event(&event)?;
    let payload = serde_json::to_vec(&event).context("encode terminal input")?;
    ensure!(
        payload.len() <= MAX_EVENT_PAYLOAD,
        "Terminal input event is too large"
    );
    write_frame_timeout(writer, KIND_EVENT, &payload)
        .await
        .context("send terminal input to the workspace worker")
}

fn validate_event(event: &Event) -> Result<()> {
    match event {
        Event::Resize(columns, rows) => validate_dimensions(*columns, *rows),
        Event::Paste(text) => {
            ensure!(text.len() <= MAX_PASTE_BYTES, "Pasted input exceeds 1 MiB");
            Ok(())
        }
        _ => Ok(()),
    }
}

fn encode_dimensions(columns: u16, rows: u16) -> [u8; 4] {
    let columns = columns.to_be_bytes();
    let rows = rows.to_be_bytes();
    [columns[0], columns[1], rows[0], rows[1]]
}

fn decode_dimensions(payload: &[u8]) -> Result<(u16, u16)> {
    ensure!(payload.len() == 4, "Invalid terminal dimensions");
    let columns = u16::from_be_bytes([payload[0], payload[1]]);
    let rows = u16::from_be_bytes([payload[2], payload[3]]);
    validate_dimensions(columns, rows)?;
    Ok((columns, rows))
}

fn validate_dimensions(columns: u16, rows: u16) -> Result<()> {
    ensure!(
        columns > 0 && rows > 0,
        "Terminal dimensions must be positive"
    );
    ensure!(
        columns <= MAX_DIMENSION && rows <= MAX_DIMENSION,
        "Terminal dimensions are too large"
    );
    ensure!(
        u32::from(columns) * u32::from(rows) <= MAX_CELLS,
        "Terminal surface is too large"
    );
    Ok(())
}

fn encode_finish(error: Option<&str>) -> Vec<u8> {
    match error {
        None => vec![0],
        Some(error) => {
            let error = safe_console_text(error);
            let bytes = error.as_bytes();
            let length = bytes.len().min(MAX_CONTROL_PAYLOAD - 1);
            let mut payload = Vec::with_capacity(length + 1);
            payload.push(1);
            payload.extend_from_slice(&bytes[..length]);
            payload
        }
    }
}

fn decode_finish(payload: &[u8]) -> Result<Option<String>> {
    let Some((&tag, message)) = payload.split_first() else {
        bail!("Invalid worker-finished frame");
    };
    match tag {
        0 if message.is_empty() => Ok(None),
        1 => {
            let message =
                std::str::from_utf8(message).context("Worker error is not valid UTF-8")?;
            Ok(Some(safe_console_text(message)))
        }
        _ => bail!("Invalid worker-finished frame"),
    }
}

fn safe_console_text(value: &str) -> String {
    let mut output = String::with_capacity(value.len().min(MAX_CONTROL_PAYLOAD));
    for character in value.chars() {
        if output.len() >= MAX_CONTROL_PAYLOAD - 4 {
            break;
        }
        match character {
            '\n' | '\r' | '\t' => output.push(' '),
            _ if character.is_control() => {}
            _ => output.push(character),
        }
    }
    output
}

async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R, maximum: usize) -> Result<Option<Frame>> {
    let mut header = [0_u8; HEADER_LEN];
    let mut read = 0;
    while read < header.len() {
        let count = reader
            .read(&mut header[read..])
            .await
            .context("read local workspace frame header")?;
        if count == 0 {
            if read == 0 {
                return Ok(None);
            }
            bail!("Local workspace connection ended in a frame header");
        }
        read += count;
    }
    ensure!(
        &header[..4] == PROTOCOL_MAGIC,
        "Invalid local workspace frame magic"
    );
    ensure!(header[7] == 0, "Invalid local workspace frame flags");
    let version = u16::from_be_bytes([header[4], header[5]]);
    let kind = header[6];
    let length = u32::from_be_bytes(header[8..12].try_into().expect("fixed header")) as usize;
    ensure!(
        length <= maximum,
        "Local workspace frame exceeds its size limit"
    );
    let mut payload = vec![0; length];
    if let Err(error) = reader.read_exact(&mut payload).await {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            bail!("Local workspace connection ended in a frame payload");
        }
        return Err(error).context("read local workspace frame payload");
    }
    Ok(Some(Frame {
        version,
        kind,
        payload,
    }))
}

async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    kind: u8,
    payload: &[u8],
) -> Result<()> {
    ensure!(
        payload.len() <= MAX_WIRE_PAYLOAD,
        "Local workspace frame exceeds its size limit"
    );
    let length = u32::try_from(payload.len()).context("local workspace frame length")?;
    let mut header = [0_u8; HEADER_LEN];
    header[..4].copy_from_slice(PROTOCOL_MAGIC);
    header[4..6].copy_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    header[6] = kind;
    header[8..12].copy_from_slice(&length.to_be_bytes());
    writer
        .write_all(&header)
        .await
        .context("write local workspace frame header")?;
    writer
        .write_all(payload)
        .await
        .context("write local workspace frame payload")?;
    writer
        .flush()
        .await
        .context("flush local workspace frame")?;
    Ok(())
}

async fn write_frame_timeout<W: AsyncWrite + Unpin>(
    writer: &mut W,
    kind: u8,
    payload: &[u8],
) -> Result<()> {
    timeout(FRAME_WRITE_TIMEOUT, write_frame(writer, kind, payload))
        .await
        .context("local workspace write timed out")?
}

fn prepare_data_directory(path: &Path) -> Result<PathBuf> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true).mode(0o700);
    builder
        .create(path)
        .with_context(|| format!("create data directory {}", path.display()))?;
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect data directory {}", path.display()))?;
    ensure!(
        metadata.file_type().is_dir(),
        "Data directory path is not a directory"
    );
    ensure!(
        metadata.uid() == effective_uid(),
        "Data directory is not owned by the current user"
    );
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("secure data directory {}", path.display()))?;
    canonical_existing_directory(path)
}

fn canonical_existing_directory(path: &Path) -> Result<PathBuf> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect data directory {}", path.display()))?;
    ensure!(
        metadata.file_type().is_dir(),
        "Data directory path is not a directory"
    );
    ensure!(
        metadata.uid() == effective_uid(),
        "Data directory is not owned by the current user"
    );
    fs::canonicalize(path)
        .with_context(|| format!("canonicalize data directory {}", path.display()))
}

fn canonical_restore_file(path: &Path) -> Result<PathBuf> {
    let path = fs::canonicalize(path)
        .with_context(|| format!("canonicalize restore file {}", path.display()))?;
    let metadata = fs::symlink_metadata(&path)
        .with_context(|| format!("inspect restore file {}", path.display()))?;
    ensure!(
        metadata.file_type().is_file(),
        "Restore path is not a regular file"
    );
    Ok(path)
}

fn endpoint_for(canonical_data_dir: &Path) -> Result<PathBuf> {
    let runtime = private_runtime_directory()?;
    let bytes = canonical_data_dir.as_os_str().as_bytes();
    let digest = Sha256::digest(bytes);
    let mut name = String::with_capacity(64 + 5);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut name, "{byte:02x}").expect("write to String");
    }
    name.push_str(".sock");
    Ok(runtime.join(name))
}

fn private_runtime_directory() -> Result<PathBuf> {
    let uid = effective_uid();
    let path = PathBuf::from(format!("/tmp/vyx-{uid}"));
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    match builder.create(&path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error).context("create private vyx runtime directory"),
    }
    let metadata = fs::symlink_metadata(&path).context("inspect private vyx runtime directory")?;
    ensure!(
        metadata.file_type().is_dir(),
        "Private vyx runtime path is not a directory"
    );
    ensure!(
        metadata.uid() == uid,
        "Private vyx runtime directory has the wrong owner"
    );
    if metadata.mode() & 0o777 != 0o700 {
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .context("secure private vyx runtime directory")?;
    }
    let checked = fs::symlink_metadata(&path).context("reinspect private vyx runtime directory")?;
    ensure!(
        checked.file_type().is_dir(),
        "Private vyx runtime path changed type"
    );
    ensure!(
        checked.uid() == uid,
        "Private vyx runtime directory changed owner"
    );
    ensure!(
        checked.mode() & 0o777 == 0o700,
        "Private vyx runtime directory is not private"
    );
    Ok(path)
}

fn reclaim_stale_endpoint(endpoint: &Path) -> Result<()> {
    match fs::symlink_metadata(endpoint) {
        Ok(metadata) => {
            ensure!(
                metadata.file_type().is_socket(),
                "Workspace endpoint path is not a socket"
            );
            ensure!(
                metadata.uid() == effective_uid(),
                "Workspace endpoint has the wrong owner"
            );
            fs::remove_file(endpoint)
                .with_context(|| format!("remove stale workspace endpoint {}", endpoint.display()))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("inspect stale workspace endpoint"),
    }
}

fn inspect_connect_endpoint(endpoint: &Path) -> Result<bool> {
    match fs::symlink_metadata(endpoint) {
        Ok(_) => {
            secure_socket_metadata(endpoint)?;
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).context("inspect local workspace endpoint"),
    }
}

fn secure_socket_metadata(endpoint: &Path) -> Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(endpoint)
        .with_context(|| format!("inspect local workspace endpoint {}", endpoint.display()))?;
    ensure!(
        metadata.file_type().is_socket(),
        "Local workspace endpoint is not a socket"
    );
    ensure!(
        metadata.uid() == effective_uid(),
        "Local workspace endpoint has the wrong owner"
    );
    ensure!(
        metadata.mode() & 0o777 == 0o600,
        "Local workspace endpoint permissions are not private"
    );
    Ok(metadata)
}

fn remove_own_endpoint(endpoint: &Path, identity: SocketIdentity) -> Result<()> {
    match fs::symlink_metadata(endpoint) {
        Ok(metadata)
            if metadata.file_type().is_socket()
                && metadata.uid() == effective_uid()
                && metadata.dev() == identity.device
                && metadata.ino() == identity.inode =>
        {
            fs::remove_file(endpoint)
                .with_context(|| format!("remove local workspace endpoint {}", endpoint.display()))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("inspect local workspace endpoint during shutdown"),
    }
}

fn verify_peer(stream: &UnixStream) -> Result<()> {
    let peer = peer_uid(stream)?;
    ensure!(
        peer == effective_uid(),
        "Local workspace peer has a different effective user ID"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn peer_uid(stream: &UnixStream) -> Result<libc::uid_t> {
    let mut credentials = std::mem::MaybeUninit::<libc::ucred>::uninit();
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: credentials points to writable storage of the exact length supplied to getsockopt;
    // stream owns a valid Unix-domain socket descriptor for the duration of the call.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            credentials.as_mut_ptr().cast(),
            &mut length,
        )
    };
    if result == -1 {
        return Err(io::Error::last_os_error()).context("verify local workspace peer credentials");
    }
    ensure!(
        length as usize >= std::mem::size_of::<libc::ucred>(),
        "Incomplete peer credentials"
    );
    // SAFETY: successful getsockopt initialized the complete ucred structure, checked above.
    Ok(unsafe { credentials.assume_init() }.uid)
}

#[cfg(target_os = "macos")]
fn peer_uid(stream: &UnixStream) -> Result<libc::uid_t> {
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    // SAFETY: uid and gid are valid writable pointers, and stream owns a valid Unix-domain socket
    // descriptor for the duration of getpeereid.
    let result = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
    if result == -1 {
        return Err(io::Error::last_os_error()).context("verify local workspace peer credentials");
    }
    Ok(uid)
}

fn effective_uid() -> libc::uid_t {
    // SAFETY: geteuid takes no arguments and has no preconditions.
    unsafe { libc::geteuid() }
}

fn unavailable_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::NotFound
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::UnexpectedEof
    )
}

fn worker_exit_error(status: ExitStatus) -> anyhow::Error {
    anyhow!("The local vyx workspace worker exited before attachment ({status})")
}

async fn wait_child_exit(child: &mut Child) -> Result<ExitStatus> {
    loop {
        if let Some(status) = child.try_wait().context("inspect workspace worker")? {
            return Ok(status);
        }
        sleep(Duration::from_millis(20)).await;
    }
}

async fn reap_competing_child(child: &mut Child) -> Result<()> {
    timeout(REAP_TIMEOUT, wait_child_exit(child))
        .await
        .context("Competing workspace worker did not exit promptly")??;
    Ok(())
}
/// An attached frontend may not own the worker as a child. The worker retains this directory lock
/// for its entire main task, so lock acquisition confirms shutdown without signaling an unowned PID.

async fn wait_workspace_release(data_dir: &Path) -> Result<()> {
    let lock_path = data_dir.join(".lock");
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&lock_path)
        .with_context(|| format!("open workspace lock {}", lock_path.display()))?;
    let display = data_dir.display().to_string();
    tokio::task::spawn_blocking(move || {
        lock.lock()
            .with_context(|| format!("wait for workspace exit {display}"))
    })
    .await
    .context("Workspace exit waiter stopped")??;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::Directory;
    use tokio::io::{AsyncWriteExt, duplex};

    #[tokio::test]
    async fn framing_accepts_fragmentation_and_rejects_partial_eof() {
        let (mut writer, mut reader) = duplex(128);
        let payload = b"fragmented";
        let mut bytes = Vec::new();
        bytes.extend_from_slice(PROTOCOL_MAGIC);
        bytes.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
        bytes.push(KIND_RENDER);
        bytes.push(0);
        bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        bytes.extend_from_slice(payload);
        let sender = tokio::spawn(async move {
            for byte in bytes {
                writer.write_all(&[byte]).await.unwrap();
            }
        });
        let frame = read_frame(&mut reader, 32).await.unwrap().unwrap();
        assert_eq!(frame.kind, KIND_RENDER);
        assert_eq!(frame.payload, payload);
        sender.await.unwrap();

        let (mut writer, mut reader) = duplex(32);
        writer.write_all(&PROTOCOL_MAGIC[..2]).await.unwrap();
        drop(writer);
        assert!(read_frame(&mut reader, 32).await.is_err());

        let (mut writer, mut reader) = duplex(32);
        let mut header = [0_u8; HEADER_LEN];
        header[..4].copy_from_slice(PROTOCOL_MAGIC);
        header[4..6].copy_from_slice(&PROTOCOL_VERSION.to_be_bytes());
        header[6] = KIND_RENDER;
        header[8..12].copy_from_slice(&5_u32.to_be_bytes());
        writer.write_all(&header).await.unwrap();
        writer.write_all(b"ab").await.unwrap();
        drop(writer);
        assert!(read_frame(&mut reader, 32).await.is_err());
    }

    #[tokio::test]
    async fn framing_rejects_oversize_before_payload_allocation() {
        let (mut writer, mut reader) = duplex(32);
        let mut header = [0_u8; HEADER_LEN];
        header[..4].copy_from_slice(PROTOCOL_MAGIC);
        header[4..6].copy_from_slice(&PROTOCOL_VERSION.to_be_bytes());
        header[6] = KIND_EVENT;
        header[8..12].copy_from_slice(&1024_u32.to_be_bytes());
        writer.write_all(&header).await.unwrap();
        assert!(read_frame(&mut reader, 16).await.is_err());
    }

    #[tokio::test]
    async fn unexpected_client_eof_finishes_worker_and_fences_reattachment() {
        let temporary = tempfile::tempdir().unwrap();
        let directory = Directory::open(temporary.path().join("vault")).unwrap();
        let mut workspace = Workspace::bind(directory.path()).unwrap();
        let endpoint = endpoint_for(&fs::canonicalize(directory.path()).unwrap()).unwrap();
        let client = raw_attach(&endpoint).await.unwrap();
        assert!(matches!(
            workspace.next_event().await,
            Some(WorkspaceEvent::Attached(80, 24))
        ));

        drop(client);
        assert!(
            timeout(Duration::from_secs(3), workspace.next_event())
                .await
                .unwrap()
                .is_none()
        );
        assert!(!workspace.is_attached());

        let mut retry = UnixStream::connect(&endpoint).await.unwrap();
        verify_peer(&retry).unwrap();
        write_frame(&mut retry, KIND_HELLO, &encode_dimensions(80, 24))
            .await
            .unwrap();
        let refusal = read_frame(&mut retry, MAX_CONTROL_PAYLOAD)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(refusal.kind, KIND_REFUSED);

        workspace.finish(None).await.unwrap();
        assert!(!endpoint.exists());
    }

    #[tokio::test]
    async fn frontend_shutdown_is_confirmed_before_transport_closes() {
        let temporary = tempfile::tempdir().unwrap();
        let directory = Directory::open(temporary.path().join("vault")).unwrap();
        let mut workspace = Workspace::bind(directory.path()).unwrap();
        let endpoint = endpoint_for(&fs::canonicalize(directory.path()).unwrap()).unwrap();
        let mut client = raw_attach(&endpoint).await.unwrap();
        assert!(matches!(
            workspace.next_event().await,
            Some(WorkspaceEvent::Attached(80, 24))
        ));

        write_frame(&mut client, KIND_CLIENT_SHUTDOWN, &[])
            .await
            .unwrap();
        assert!(
            timeout(Duration::from_secs(3), workspace.next_event())
                .await
                .unwrap()
                .is_none()
        );
        workspace.finish(None).await.unwrap();

        let finished = read_frame(&mut client, MAX_CONTROL_PAYLOAD)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(finished.kind, KIND_FINISHED);
        assert_eq!(decode_finish(&finished.payload).unwrap(), None);
        assert!(
            timeout(
                Duration::from_secs(3),
                read_frame(&mut client, MAX_CONTROL_PAYLOAD)
            )
            .await
            .unwrap()
            .unwrap()
            .is_none()
        );
        assert!(!endpoint.exists());
    }

    #[tokio::test]
    async fn explicit_workspace_detach_allows_reattachment_and_fences_old_input() {
        let temporary = tempfile::tempdir().unwrap();
        let directory = Directory::open(temporary.path().join("vault")).unwrap();
        let mut workspace = Workspace::bind(directory.path()).unwrap();
        let endpoint = endpoint_for(&fs::canonicalize(directory.path()).unwrap()).unwrap();

        let mut first = raw_attach(&endpoint).await.unwrap();
        assert!(matches!(
            workspace.next_event().await,
            Some(WorkspaceEvent::Attached(80, 24))
        ));
        let mut display = workspace.writer();
        display.write_all(b"old generation").unwrap();

        let mut second = UnixStream::connect(&endpoint).await.unwrap();
        verify_peer(&second).unwrap();
        write_frame(&mut second, KIND_HELLO, &encode_dimensions(80, 24))
            .await
            .unwrap();
        let refusal = read_frame(&mut second, MAX_CONTROL_PAYLOAD)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(refusal.kind, KIND_REFUSED);
        // An abandoned client's queued connection must not run after reattachment.
        let old_attachment = workspace.shared.lock().current.as_ref().unwrap().id;
        assert!(workspace.shared.submit_event(
            old_attachment,
            WorkspaceEvent::Connect("discarded destination".to_owned()),
        ).await);

        let stale = Event::Resize(90, 30);
        let stale_payload = serde_json::to_vec(&stale).unwrap();
        write_frame(&mut first, KIND_EVENT, &stale_payload)
            .await
            .unwrap();
        workspace.detach();
        assert!(!workspace.is_attached());
        assert!(matches!(
            workspace.next_event().await,
            Some(WorkspaceEvent::Detached)
        ));
        let detached = read_frame(&mut first, MAX_CONTROL_PAYLOAD)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(detached.kind, KIND_DETACHED);
        assert!(detached.payload.is_empty());

        let mut replacement = None;
        for _ in 0..20 {
            match raw_attach(&endpoint).await {
                Ok(stream) => {
                    replacement = Some(stream);
                    break;
                }
                Err(_) => sleep(Duration::from_millis(10)).await,
            }
        }
        let mut replacement = replacement.expect("replacement attachment");
        assert!(matches!(
            workspace.next_event().await,
            Some(WorkspaceEvent::Attached(80, 24))
        ));
        display.write_all(b"fresh generation").unwrap();
        display.publish().await;
        let render = read_frame(&mut replacement, MAX_RENDER_PAYLOAD)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(render.kind, KIND_RENDER);
        assert_eq!(render.payload, b"fresh generation");
        let fresh = Event::Resize(100, 40);
        write_frame(
            &mut replacement,
            KIND_EVENT,
            &serde_json::to_vec(&fresh).unwrap(),
        )
        .await
        .unwrap();
        assert!(matches!(
            workspace.next_event().await,
            Some(WorkspaceEvent::Input(Event::Resize(100, 40)))
        ));

        workspace.finish(None).await.unwrap();
        let finished = read_frame(&mut replacement, MAX_CONTROL_PAYLOAD)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(finished.kind, KIND_FINISHED);
        assert_eq!(decode_finish(&finished.payload).unwrap(), None);
        assert!(!endpoint.exists());
    }

    #[tokio::test]
    async fn input_bursts_do_not_disconnect_or_drop_keys() {
        let temporary = tempfile::tempdir().unwrap();
        let directory = Directory::open(temporary.path().join("vault")).unwrap();
        let mut workspace = Workspace::bind(directory.path()).unwrap();
        let endpoint = endpoint_for(&fs::canonicalize(directory.path()).unwrap()).unwrap();
        let mut stream = raw_attach(&endpoint).await.unwrap();
        assert!(matches!(
            workspace.next_event().await,
            Some(WorkspaceEvent::Attached(..))
        ));
        for index in 0..64u8 {
            let key = crossterm::event::KeyEvent::new(
                crossterm::event::KeyCode::Char(char::from(b'A' + index % 26)),
                crossterm::event::KeyModifiers::NONE,
            );
            write_frame(
                &mut stream,
                KIND_EVENT,
                &serde_json::to_vec(&Event::Key(key)).unwrap(),
            )
            .await
            .unwrap();
        }
        tokio::task::yield_now().await;
        for index in 0..64u8 {
            let event = timeout(Duration::from_secs(3), workspace.next_event())
                .await
                .unwrap();
            assert!(matches!(event, Some(WorkspaceEvent::Input(Event::Key(key)))
                if key.code == crossterm::event::KeyCode::Char(char::from(b'A' + index % 26))));
        }
        assert!(workspace.is_attached());
        workspace.finish(None).await.unwrap();
    }

    #[tokio::test]
    async fn authentication_completion_fences_locked_burst_and_preserves_control_events() {
        use crate::{
            screen::{Screen, ScreenEvent},
            settings::Motion,
            shortcuts::Bindings,
            theme::default_theme,
            ui::lock::{UnlockOptions, UnlockRequest, unlock},
            vault::Secret,
        };
        use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

        let temporary = tempfile::tempdir().unwrap();
        let directory = Directory::open(temporary.path().join("vault")).unwrap();
        let store = directory.create(Secret::new("authentication boundary passphrase")).await.unwrap();
        let workspace = Workspace::bind(directory.path()).unwrap();
        let shared = Arc::clone(&workspace.shared);
        let endpoint = endpoint_for(&fs::canonicalize(directory.path()).unwrap()).unwrap();
        let _client = raw_attach(&endpoint).await.unwrap();
        let mut screen = Screen::open(workspace).unwrap();
        assert!(matches!(screen.next_event().await.unwrap(),
            Some(ScreenEvent::Input(Event::Resize(80, 24)))));
        let attachment = shared.lock().current.as_ref().unwrap().id;
        for event in [
            Event::Paste("authentication boundary passphrase".into()),
            Event::Key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)),
        ] {
            assert!(shared.submit_event(attachment, WorkspaceEvent::Input(event)).await);
        }
        let bindings = Bindings::default();
        let outcome = unlock(
            &mut screen, &bindings, &default_theme().palette,
            UnlockOptions {
                title: "Vault locked", description: "Retained SSH session",
                live_sessions: 1, confirm_quit: true, allow_recovery: true, motion: Motion::Off,
            },
            |request| async {
                let UnlockRequest::Passphrase(passphrase) = request else { panic!("password method"); };
                store.verify_passphrase(passphrase).await?;
                // These arrive in the same poll that completes verification. They must
                // never become input to the retained, terminal-focused workspace.
                for event in [
                    Event::Key(KeyEvent::new(KeyCode::Char('s'), KeyModifiers::NONE)),
                    Event::Paste("locked-secret-burst".into()),
                    Event::Resize(100, 32),
                ] {
                    assert!(shared.submit_event(attachment, WorkspaceEvent::Input(event)).await);
                }
                assert!(shared.submit_event(attachment, WorkspaceEvent::Connect("retained destination".into())).await);
                Ok(())
            },
        ).await.unwrap().unwrap();
        assert!(!outcome.recovered);
        assert!(matches!(screen.next_event().await.unwrap(),
            Some(ScreenEvent::Input(Event::Resize(100, 32)))));
        assert!(matches!(screen.next_event().await.unwrap(), Some(ScreenEvent::ConnectRequested)));
        assert_eq!(screen.take_connect_request().as_deref(), Some("retained destination"));
        assert!(shared.submit_event(attachment, WorkspaceEvent::Input(Event::Paste("unlocked command".into()))).await);
        assert!(matches!(screen.next_event().await.unwrap(),
            Some(ScreenEvent::Input(Event::Paste(text))) if text == "unlocked command"));
        shared.detach_current();
        assert!(matches!(screen.next_event().await.unwrap(),
            Some(ScreenEvent::Input(Event::FocusLost))));
        screen.finish(None).await.unwrap();
        store.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn authentication_fence_covers_blocked_senders_without_losing_lifecycle() {
        use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
        use std::task::Poll;

        let temporary = tempfile::tempdir().unwrap();
        let directory = Directory::open(temporary.path().join("vault")).unwrap();
        let mut workspace = Workspace::bind(directory.path()).unwrap();
        let endpoint = endpoint_for(&fs::canonicalize(directory.path()).unwrap()).unwrap();
        let _client = raw_attach(&endpoint).await.unwrap();
        assert!(matches!(workspace.next_event().await, Some(WorkspaceEvent::Attached(..))));
        let shared = Arc::clone(&workspace.shared);
        let attachment = shared.lock().current.as_ref().unwrap().id;
        let burst = [
            Event::Key(KeyEvent::new(KeyCode::Char('s'), KeyModifiers::NONE)),
            Event::Paste("queued locked secret".into()),
            Event::Mouse(MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Left),
                column: 40, row: 4, modifiers: KeyModifiers::NONE,
            }),
        ];
        for index in 0..EVENT_QUEUE_CAPACITY - 1 {
            assert!(shared.submit_event(attachment, WorkspaceEvent::Input(burst[index % burst.len()].clone())).await);
        }
        assert!(shared.submit_event(attachment, WorkspaceEvent::Input(Event::FocusLost)).await);
        let blocked = shared.submit_event(attachment, WorkspaceEvent::Input(Event::Paste("blocked locked secret".into())));
        tokio::pin!(blocked);
        assert!(matches!(futures_util::poll!(&mut blocked), Poll::Pending));
        workspace.fence_authentication_input();
        let (sent, event) = tokio::join!(&mut blocked, workspace.next_event());
        assert!(sent);
        assert!(matches!(event, Some(WorkspaceEvent::Input(Event::FocusLost))));
        assert!(shared.submit_event(attachment, WorkspaceEvent::Input(Event::Paste("fresh command".into()))).await);
        assert!(matches!(workspace.next_event().await,
            Some(WorkspaceEvent::Input(Event::Paste(text))) if text == "fresh command"));

        shared.detach_current();
        workspace.fence_authentication_input();
        assert!(matches!(workspace.next_event().await, Some(WorkspaceEvent::Detached)));
        shared.mark_finished();
        workspace.fence_authentication_input();
        assert!(workspace.next_event().await.is_none());
        workspace.finish(None).await.unwrap();
    }

    #[tokio::test]
    async fn redraw_bursts_preserve_every_frame() {
        let temporary = tempfile::tempdir().unwrap();
        let directory = Directory::open(temporary.path().join("vault")).unwrap();
        let mut workspace = Workspace::bind(directory.path()).unwrap();
        let endpoint = endpoint_for(&fs::canonicalize(directory.path()).unwrap()).unwrap();
        let mut stream = raw_attach(&endpoint).await.unwrap();
        assert!(matches!(
            workspace.next_event().await,
            Some(WorkspaceEvent::Attached(..))
        ));
        let mut display = workspace.writer();
        let producer = tokio::spawn(async move {
            for index in 0..64u8 {
                display.write_all(&[index]).unwrap();
                display.publish().await;
            }
        });
        for index in 0..64u8 {
            let frame = timeout(
                Duration::from_secs(3),
                read_frame(&mut stream, MAX_RENDER_PAYLOAD),
            )
            .await
            .unwrap()
            .unwrap()
            .unwrap();
            assert_eq!(frame.kind, KIND_RENDER);
            assert_eq!(frame.payload, [index]);
        }
        producer.await.unwrap();
        assert!(workspace.is_attached());
        workspace.finish(None).await.unwrap();
    }

    #[test]
    fn terminal_dimensions_bound_total_grid_allocation() {
        assert_eq!(
            decode_dimensions(&encode_dimensions(256, 256)).unwrap(),
            (256, 256)
        );
        assert!(decode_dimensions(&encode_dimensions(4096, 4096)).is_err());
        assert!(validate_event(&Event::Resize(256, 257)).is_err());
        assert!(decode_dimensions(&encode_dimensions(0, 24)).is_err());
    }

    #[tokio::test]
    async fn large_escaped_paste_reaches_the_workspace_intact() {
        let temporary = tempfile::tempdir().unwrap();
        let directory = Directory::open(temporary.path().join("vault")).unwrap();
        let mut workspace = Workspace::bind(directory.path()).unwrap();
        let endpoint = endpoint_for(&fs::canonicalize(directory.path()).unwrap()).unwrap();
        let client = raw_attach(&endpoint).await.unwrap();
        assert!(matches!(
            workspace.next_event().await,
            Some(WorkspaceEvent::Attached(..))
        ));
        let (_reader, mut writer) = client.into_split();
        let sending = tokio::spawn(async move {
            send_event(&mut writer, Event::Paste("\u{1}".repeat(MAX_PASTE_BYTES)))
                .await
                .unwrap();
            writer
        });
        match workspace.next_event().await {
            Some(WorkspaceEvent::Input(Event::Paste(text))) => {
                assert_eq!(text.len(), MAX_PASTE_BYTES);
                assert!(text.bytes().all(|byte| byte == 1));
            }
            event => panic!("Expected a complete paste, received {event:?}"),
        }
        let _writer = sending.await.unwrap();
        workspace.finish(None).await.unwrap();
    }

    async fn raw_attach(endpoint: &Path) -> Result<UnixStream> {
        let mut stream = UnixStream::connect(endpoint).await?;
        verify_peer(&stream)?;
        write_frame(&mut stream, KIND_HELLO, &encode_dimensions(80, 24)).await?;
        let response = read_frame(&mut stream, MAX_CONTROL_PAYLOAD)
            .await?
            .context("missing handshake response")?;
        ensure!(response.kind == KIND_ATTACHED, "attachment refused");
        Ok(stream)
    }
}
