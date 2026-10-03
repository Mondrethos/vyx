//! Parent-only extension process supervision and authority; no guest engine.
//!
//! The native watchdog owns and reaps the child independently of the async UI and
//! broker. Wasm memory limits are not a process RSS limit: compilation can still
//! exhaust host memory. No compiled artifacts are deserialized or cached.
use std::{
    collections::VecDeque,
    future::Future,
    fs::OpenOptions,
    io::{self, Read, Write},
    os::unix::{fs::{MetadataExt, OpenOptionsExt}, process::CommandExt},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{Arc, mpsc},
    time::{Duration, Instant},
};

use anyhow::{Context as _, Result, anyhow, bail, ensure};
use parking_lot::{Condvar, Mutex};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::{Notify, oneshot};

use super::contract::{read_frame, write_frame, write_frame_bounded};
use super::contract::{Bootstrap, Method, ProtocolError, WorkerMessage};

pub(super) const MAX_WASM_BYTES: usize = 8 * 1024 * 1024;
const MAX_STATE_BYTES: usize = 64 * 1024;
pub(super) const MAX_DIAGNOSTICS: usize = 64 * 1024;
pub(super) const MAX_CALLS: u64 = 32;
const COMPILE_TIMEOUT: Duration = Duration::from_secs(20);
const EVENT_TIMEOUT: Duration = Duration::from_secs(10);

/// Host-approved immutable cache entry, never an extension-selected executable.
#[derive(Clone, Debug)]
pub struct WorkerExecutable {
    pub path: PathBuf,
    pub sha256: [u8; 32],
}

impl WorkerExecutable {
    fn verify(&self) -> Result<()> {
        ensure!(self.path.is_absolute(), "extension runtime path must be absolute");
        // NONBLOCK prevents a substituted FIFO/device from stalling before the
        // descriptor-based regular-file check. Never follow a final symlink.
        let mut file = OpenOptions::new().read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(&self.path).context("opening optional extension runtime")?;
        let metadata = file.metadata()?;
        ensure!(metadata.is_file() && metadata.uid() == unsafe { libc::geteuid() },
            "extension runtime must be a regular file owned by the current user");
        ensure!(metadata.mode() & 0o6022 == 0 && metadata.mode() & 0o100 != 0,
            "extension runtime must be owner-executable, without set-ID or group/other write permissions");
        const MAX_EXECUTABLE_BYTES: u64 = 128 * 1024 * 1024;
        ensure!((1..=MAX_EXECUTABLE_BYTES).contains(&metadata.len()), "invalid extension runtime size");
        let mut hash = Sha256::new();
        let mut buffer = [0; 64 * 1024];
        let mut total = 0u64;
        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 { break; }
            total += count as u64;
            ensure!(total <= MAX_EXECUTABLE_BYTES, "extension runtime exceeds 128 MiB");
            hash.update(&buffer[..count]);
        }
        ensure!(total == metadata.len(), "extension runtime changed during verification");
        ensure!(<[u8; 32]>::from(hash.finalize()) == self.sha256,
            "extension runtime integrity check failed; download it again from Settings / Extensions");
        Ok(())
    }
}


/// Provenance comes from this host-created value, never from guest JSON.
#[derive(Clone, Debug)]
pub struct BrokerRequest {
    pub generation: u64,
    pub event_id: u64,
    pub id: u64,
    pub method: Method,
}



pub(super) fn bounded_state(state: &Value) -> Result<()> {
    ensure!(serde_json::to_vec(state)?.len() <= MAX_STATE_BYTES, "state exceeds 64 KiB");
    Ok(())
}


pub(super) fn sanitize(text: &str) -> String {
    text.chars().map(|c| {
        if (c.is_control() && c != '\n' && c != '\t') || matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}') { '\u{fffd}' } else { c }
    }).collect()
}


struct WatchState { deadline: Option<Instant>, reason: Option<String>, reaped: bool }
struct Watch {
    state: Mutex<WatchState>,
    changed: Condvar,
    notify: Notify,
}

/// Cloneable revocation handle. Cancellation never waits for guest/broker I/O.
#[derive(Clone)]
pub struct WorkerCancellation(Arc<Watch>);
impl WorkerCancellation {
    pub fn cancel(&self) { self.stop("CANCELLED: extension generation revoked".into()); }
    fn stop(&self, reason: String) {
        let mut state = self.0.state.lock();
        if state.reason.is_none() { state.reason = Some(reason); }
        self.0.changed.notify_all();
        self.0.notify.notify_waiters();
    }
    fn deadline(&self, duration: Option<Duration>) -> Result<()> {
        let mut state = self.0.state.lock();
        if state.deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            state.reason.get_or_insert_with(|| "LIMIT_EXCEEDED: extension deadline exceeded".into());
            self.0.changed.notify_all();
            self.0.notify.notify_waiters();
        }
        if let Some(reason) = &state.reason { bail!("{reason}"); }
        state.deadline = duration.map(|duration| Instant::now() + duration);
        self.0.changed.notify_all();
        Ok(())
    }
    async fn stopped(&self) -> String {
        loop {
            let notified = self.0.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if let Some(reason) = &self.0.state.lock().reason { return reason.clone(); }
            notified.await;
        }
    }
    pub async fn wait_reaped(&self) {
        loop {
            let notified = self.0.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.0.state.lock().reaped { return; }
            notified.await;
        }
    }
}

struct ReapChild(Child);
impl Drop for ReapChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn watchdog(mut owner: ReapChild, watch: WorkerCancellation) {
    let child = &mut owner.0;
    let mut state = watch.0.state.lock();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                state.reason.get_or_insert_with(|| format!("RUNTIME_FAILED: worker exited ({status})"));
                break;
            }
            Err(error) => { state.reason.get_or_insert_with(|| format!("RUNTIME_FAILED: worker wait failed: {error}")); break; }
            Ok(None) => {}
        }
        let now = Instant::now();
        if state.deadline.is_some_and(|deadline| now >= deadline) {
            state.reason.get_or_insert_with(|| "LIMIT_EXCEEDED: extension deadline exceeded".into());
        }
        if state.reason.is_some() {
            let _ = child.kill();
            // Only this thread waits or kills, so no PID-reuse race exists.
            let _ = child.wait();
            break;
        }
        let wait = state.deadline.map_or(Duration::from_millis(100), |deadline| deadline.saturating_duration_since(now).min(Duration::from_millis(100)));
        watch.0.changed.wait_for(&mut state, wait);
    }
    // Also reap after an unusual try_wait error; never leave a running child.
    let _ = child.kill();
    let _ = child.wait();
    state.reaped = true;
    watch.0.changed.notify_all();
    watch.0.notify.notify_waiters();
}

struct EventCommand {
    id: u64,
    event: Value,
    state: Value,
    calls: tokio::sync::mpsc::Sender<PendingCall>,
    reply: oneshot::Sender<Result<Value>>,
}
struct PendingCall {
    request: BrokerRequest,
    reply: mpsc::SyncSender<std::result::Result<Value, ProtocolError>>,
}

/// One open surface, one in-flight event. Dropping this value revokes it.
pub struct Worker {
    commands: mpsc::SyncSender<EventCommand>,
    cancellation: WorkerCancellation,
    diagnostics: Arc<Mutex<VecDeque<u8>>>,
    generation: u64,
    next_event: u64,
}

impl Worker {
    pub async fn spawn(executable: WorkerExecutable, wasm: Vec<u8>, generation: u64) -> Result<Self> {
        ensure!(!wasm.is_empty() && wasm.len() <= MAX_WASM_BYTES, "invalid Wasm size");
        let executable = tokio::task::spawn_blocking(move || {
            executable.verify()?;
            Ok::<_, anyhow::Error>(executable)
        }).await.context("checking extension runtime")??;
        let mut command = Command::new(&executable.path);
        command.env_clear().current_dir("/")
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
        // Compute the descriptor bound before fork; pre_exec uses only
        // async-signal-safe syscalls and cannot allocate or acquire locks.
        let mut nofile = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut nofile) } != 0 { return Err(io::Error::last_os_error().into()); }
        let descriptor_limit = nofile.rlim_max.min(i32::MAX as _) as i32;
        unsafe {
            command.pre_exec(move || {
                let zero = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
                if libc::setrlimit(libc::RLIMIT_CORE, &zero) != 0 { return Err(io::Error::last_os_error()); }
                #[cfg(target_os = "linux")]
                if libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 4u32) == 0 { return Ok(()); }
                for fd in 3..descriptor_limit {
                    if libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) < 0 && io::Error::last_os_error().raw_os_error() != Some(libc::EBADF) {
                        return Err(io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
        let mut child = command.spawn().context("starting extension worker")?;
        let mut stdin = child.stdin.take().unwrap();
        let mut stdout = child.stdout.take().unwrap();
        let mut stderr = child.stderr.take().unwrap();
        let cancellation = WorkerCancellation(Arc::new(Watch {
            state: Mutex::new(WatchState { deadline: Some(Instant::now() + COMPILE_TIMEOUT), reason: None, reaped: false }),
            changed: Condvar::new(), notify: Notify::new(),
        }));
        let watch = cancellation.clone();
        // If thread creation fails, dropping the closure still kills/reaps.
        let child = ReapChild(child);
        std::thread::Builder::new().name("extension-watchdog".into())
            .spawn(move || watchdog(child, watch))?;
        let diagnostics = Arc::new(Mutex::new(VecDeque::with_capacity(MAX_DIAGNOSTICS)));
        let ring = diagnostics.clone();
        std::thread::Builder::new().name("extension-diagnostics".into()).spawn(move || {
            let mut buffer = [0; 4096];
            while let Ok(count) = stderr.read(&mut buffer) {
                if count == 0 { break; }
                let clean = sanitize(&String::from_utf8_lossy(&buffer[..count]));
                let mut ring = ring.lock();
                for byte in clean.bytes() {
                    if ring.len() == MAX_DIAGNOSTICS { ring.pop_front(); }
                    ring.push_back(byte);
                }
            }
        }).inspect_err(|_| cancellation.cancel())?;
        let (commands, receiver) = mpsc::sync_channel(16);
        let (ready_tx, ready_rx) = oneshot::channel();
        let worker = Self { commands, cancellation: cancellation.clone(), diagnostics, generation, next_event: 1 };
        std::thread::Builder::new().name("extension-protocol".into()).spawn(move || {
            let startup = (|| -> Result<()> {
                write_frame_bounded(&mut stdin, &Bootstrap { protocol_version: 2, runtime_version: env!("CARGO_PKG_VERSION").into() }, 64 * 1024)?;
                stdin.write_all(&(wasm.len() as u32).to_le_bytes())?;
                stdin.write_all(&wasm)?;
                stdin.flush()?;
                match read_frame::<_, WorkerMessage>(&mut stdout)? {
                    WorkerMessage::Ready => {}
                    WorkerMessage::Failure { error, .. } => bail!("worker startup failed: {}", sanitize(&error.message)),
                    _ => bail!("worker sent an event message before readiness"),
                }
                cancellation.deadline(None)?;
                Ok(())
            })();
            drop(wasm);
            if let Err(error) = startup {
                cancellation.stop(format!("RUNTIME_FAILED: {error:#}"));
                let _ = ready_tx.send(Err(error));
                return;
            }
            if ready_tx.send(Ok(())).is_err() { cancellation.cancel(); return; }
            let mut last_request = 0;
            loop {
                if cancellation.0.state.lock().reason.is_some() { break; }
                let event = match receiver.recv_timeout(Duration::from_millis(100)) {
                    Ok(event) => event,
                    Err(mpsc::RecvTimeoutError::Timeout) => continue,
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                };
                let result = parent_event(&mut stdin, &mut stdout, &event, generation, &mut last_request, &cancellation);
                let failed = result.is_err();
                if let Err(error) = &result { cancellation.stop(format!("RUNTIME_FAILED: {error:#}")); }
                let _ = event.reply.send(result);
                if failed { break; }
            }
            cancellation.cancel();
        })?;
        let ready = tokio::select! {
            ready = ready_rx => ready.context("worker startup channel closed")?,
            reason = worker.cancellation.stopped() => Err(anyhow!(reason)),
        };
        if let Err(error) = ready {
            worker.cancellation.cancel();
            worker.cancellation.wait_reaped().await;
            return Err(error);
        }
        Ok(worker)
    }

    pub fn generation(&self) -> u64 { self.generation }
    pub fn cancellation(&self) -> WorkerCancellation { self.cancellation.clone() }
    pub fn diagnostics(&self) -> String {
        let ring = self.diagnostics.lock();
        let bytes: Vec<u8> = ring.iter().copied().collect();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    /// Host must authorize every callback and validate the resulting view and
    /// proposal against the current host-owned grant/view generation.
    pub async fn event<F, Fut>(&mut self, event: Value, state: Value, mut broker: F) -> Result<Value>
    where F: FnMut(BrokerRequest) -> Fut,
          Fut: Future<Output = std::result::Result<Value, ProtocolError>>,
    {
        bounded_state(&state)?;
        let id = self.next_event;
        ensure!(id <= ((1u64 << 53) - 1) / MAX_CALLS, "event ID exceeds SDK exact integer range");
        self.next_event = id.checked_add(1).ok_or_else(|| anyhow!("event ID exhausted"))?;
        let (calls, mut incoming) = tokio::sync::mpsc::channel(1);
        let (reply, mut response) = oneshot::channel();
        // A cancelled/dropped event future must not leave its worker running or
        // allow a delayed callback to authorize another event.
        let mut guard = EventGuard(Some(self.cancellation.clone()));
        self.commands.try_send(EventCommand { id, event, state, calls, reply }).map_err(|_| anyhow!("worker unavailable or event queue full"))?;
        let result = loop {
            tokio::select! {
                result = &mut response => break result.context("worker event channel closed")?,
                reason = self.cancellation.stopped() => break Err(anyhow!(reason)),
                Some(call) = incoming.recv() => {
                    let result = tokio::select! {
                        result = broker(call.request) => result,
                        reason = self.cancellation.stopped() => break Err(anyhow!(reason)),
                    };
                    if call.reply.send(result).is_err() { break Err(anyhow!("broker request cancelled")); }
                }
            }
        };
        if result.is_err() {
            self.cancellation.cancel();
            self.cancellation.wait_reaped().await;
        }
        guard.0 = None;
        result
    }

    pub async fn shutdown(self) {
        self.cancellation.cancel();
        self.cancellation.wait_reaped().await;
    }
}
impl Drop for Worker { fn drop(&mut self) { self.cancellation.cancel(); } }
struct EventGuard(Option<WorkerCancellation>);
impl Drop for EventGuard {
    fn drop(&mut self) { if let Some(cancellation) = &self.0 { cancellation.cancel(); } }
}

fn parent_event(stdin: &mut impl Write, stdout: &mut impl Read, event: &EventCommand, generation: u64, last_request: &mut u64, cancellation: &WorkerCancellation) -> Result<Value> {
    cancellation.deadline(Some(EVENT_TIMEOUT))?;
    let deadline = Instant::now() + EVENT_TIMEOUT;
    write_frame(stdin, &json!({"kind":"event", "id":event.id, "event":event.event, "state":event.state}))?;
    let mut calls = 0;
    loop {
        match read_frame::<_, WorkerMessage>(stdout)? {
            WorkerMessage::Ready => bail!("unexpected worker readiness during an event"),
            WorkerMessage::Failure { error, .. } => bail!("worker failure: {}", sanitize(&error.message)),
            WorkerMessage::Request { event_id, id, method } => {
                ensure!(event_id == event.id && id > *last_request, "invalid worker request");
                ensure!(calls < MAX_CALLS, "broker call limit exceeded");
                calls += 1;
                *last_request = id;
                let (reply, response) = mpsc::sync_channel(1);
                event.calls.blocking_send(PendingCall { request: BrokerRequest { generation, event_id, id, method }, reply }).map_err(|_| anyhow!("broker cancelled"))?;
                let response = loop {
                    if let Some(reason) = &cancellation.0.state.lock().reason { bail!("{reason}"); }
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    ensure!(!remaining.is_zero(), "broker deadline exceeded");
                    match response.recv_timeout(remaining.min(Duration::from_millis(100))) {
                        Ok(response) => break response,
                        Err(mpsc::RecvTimeoutError::Timeout) => continue,
                        Err(mpsc::RecvTimeoutError::Disconnected) => bail!("broker cancelled"),
                    }
                };
                let frame = match response {
                    Ok(value) => json!({"kind":"response", "eventId":event_id, "id":id, "value":value}),
                    Err(error) => json!({"kind":"response", "eventId":event_id, "id":id, "error":error}),
                };
                write_frame(stdin, &frame)?;
            }
            WorkerMessage::Result { event_id, mut result } => {
                ensure!(event_id == event.id, "mismatched worker result");
                result.validate_and_sanitize()?;
                cancellation.deadline(None)?;
                return Ok(serde_json::to_value(result)?);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_verification_rejects_tampering_and_unsafe_cache_files() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("worker");
        let contents = b"immutable runtime";
        std::fs::write(&path, contents).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let executable = WorkerExecutable { path: path.clone(), sha256: Sha256::digest(contents).into() };
        executable.verify().unwrap();

        std::fs::write(&path, b"modified runtime").unwrap();
        assert!(executable.verify().is_err());
        std::fs::write(&path, contents).unwrap();
        for mode in [0o600, 0o720, 0o702, 0o4700] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            assert!(executable.verify().is_err());
        }
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let link = directory.path().join("link");
        symlink(&path, &link).unwrap();
        assert!(WorkerExecutable { path: link, ..executable.clone() }.verify().is_err());
        assert!(WorkerExecutable { path: directory.path().to_owned(), ..executable.clone() }.verify().is_err());
        assert!(WorkerExecutable { path: PathBuf::from("worker"), ..executable.clone() }.verify().is_err());

        let file = OpenOptions::new().write(true).open(&path).unwrap();
        file.set_len(128 * 1024 * 1024 + 1).unwrap();
        assert!(executable.verify().is_err());
        file.set_len(0).unwrap();
        assert!(executable.verify().is_err());
    }


    #[test]
    fn diagnostics_remove_terminal_and_bidi_controls() {
        assert_eq!(sanitize("hello\u{1b}]52;secret\u{7}\u{202e}\n"), "hello\u{fffd}]52;secret\u{fffd}\u{fffd}\n");
    }

    #[test]
    fn watchdog_kills_and_reaps_blocked_input_without_async_executor() {
        for cancel in [false, true] {
            // POSIX sh is available on supported Linux/macOS targets. Keeping
            // stdin open makes read block without a timer or an EOF exit race.
            let child = Command::new("sh").args(["-c", "read -r line"])
                .stdin(Stdio::piped()).spawn().unwrap();
            let pid = child.id();
            let watch = WorkerCancellation(Arc::new(Watch {
                state: Mutex::new(WatchState {
                    deadline: (!cancel).then(|| Instant::now() + Duration::from_millis(20)),
                    reason: None,
                    reaped: false,
                }),
                changed: Condvar::new(), notify: Notify::new(),
            }));
            let owner = watch.clone();
            let thread = std::thread::spawn(move || watchdog(ReapChild(child), owner));
            if cancel { watch.cancel(); }
            let mut state = watch.0.state.lock();
            let deadline = Instant::now() + Duration::from_secs(5);
            while !state.reaped {
                let remaining = deadline.saturating_duration_since(Instant::now());
                assert!(!remaining.is_zero(), "watchdog failed to reap blocked child");
                watch.0.changed.wait_for(&mut state, remaining);
            }
            let expected = if cancel { "CANCELLED" } else { "LIMIT_EXCEEDED" };
            assert!(state.reason.as_ref().unwrap().starts_with(expected));
            drop(state);
            thread.join().unwrap();
            assert_eq!(unsafe { libc::waitpid(pid as i32, std::ptr::null_mut(), libc::WNOHANG) }, -1);
            assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::ECHILD));
        }
    }
}
