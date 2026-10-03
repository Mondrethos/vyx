//! Exercise the shipped worker entry point without a vault, author tools, or tailnet.
#![cfg(feature = "extension-worker")]
use std::{process::Stdio, time::Duration};

use serde_json::{Value, json};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::{Child, ChildStdin, ChildStdout, Command},
    task::JoinHandle,
    time::timeout,
};

const DEADLINE: Duration = Duration::from_secs(30);

struct WorkerProcess {
    child: Child,
    input: ChildStdin,
    output: ChildStdout,
    diagnostics: JoinHandle<Vec<u8>>,
    _directory: tempfile::TempDir,
}

impl WorkerProcess {
    fn spawn() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_vyx-extension-worker"))
            .env_clear()
            // Deliberately present in the native worker, but never in WASI.
            .env("VYX_TEST_SECRET", "must-not-reach-guest")
            .env("HOME", directory.path())
            .current_dir(directory.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let input = child.stdin.take().unwrap();
        let output = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();
        let diagnostics = tokio::spawn(async move {
            let mut bytes = Vec::new();
            // A regression must not make the test itself accumulate unlimited logs.
            stderr.take(128 * 1024 + 1).read_to_end(&mut bytes).await.unwrap();
            bytes
        });
        Self { child, input, output, diagnostics, _directory: directory }
    }

    async fn send(&mut self, value: Value) {
        let bytes = serde_json::to_vec(&value).unwrap();
        timeout(DEADLINE, async {
            self.input.write_u32_le(bytes.len() as u32).await.unwrap();
            self.input.write_all(&bytes).await.unwrap();
            self.input.flush().await.unwrap();
        }).await.expect("worker input deadline");
    }

    async fn receive(&mut self) -> Value {
        timeout(DEADLINE, async {
            let size = self.output.read_u32_le().await.unwrap() as usize;
            assert!((1..=1024 * 1024).contains(&size));
            let mut bytes = vec![0; size];
            self.output.read_exact(&mut bytes).await.unwrap();
            serde_json::from_slice(&bytes).unwrap()
        }).await.expect("worker response deadline")
    }

    async fn bootstrap(&mut self, source: &str) -> Value {
        let wasm = wat::parse_str(source).unwrap();
        self.send(json!({"protocolVersion":2, "runtimeVersion":env!("CARGO_PKG_VERSION")})).await;
        timeout(DEADLINE, async {
            self.input.write_u32_le(wasm.len() as u32).await.unwrap();
            self.input.write_all(&wasm).await.unwrap();
            self.input.flush().await.unwrap();
        }).await.expect("bootstrap deadline");
        self.receive().await
    }

    async fn event(&mut self, id: u64, state: Value) {
        self.send(json!({"kind":"event", "id":id, "event":{"kind":"open", "commandId":"probe", "reason":"launch"}, "state":state})).await;
    }

    async fn failed_exit(mut self) -> Vec<u8> {
        let status = timeout(DEADLINE, self.child.wait()).await.expect("failed worker exit deadline").unwrap();
        assert!(!status.success());
        let mut trailing = Vec::new();
        timeout(DEADLINE, self.output.take(1024 * 1024 + 1).read_to_end(&mut trailing)).await.unwrap().unwrap();
        assert!(trailing.is_empty(), "failed worker published additional output");
        timeout(DEADLINE, self.diagnostics).await.unwrap().unwrap()
    }

    async fn cancel(mut self) -> Vec<u8> {
        let pid = self.child.id().unwrap();
        timeout(DEADLINE, self.child.kill()).await.expect("worker kill deadline").unwrap();
        let status = timeout(DEADLINE, self.child.wait()).await.expect("worker reap deadline").unwrap();
        assert!(!status.success());
        #[cfg(unix)]
        {
            // kill() must reap, not merely signal the child or leave a zombie.
            assert_eq!(unsafe { libc::waitpid(pid as i32, std::ptr::null_mut(), libc::WNOHANG) }, -1);
            assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::ECHILD));
        }
        timeout(DEADLINE, self.diagnostics).await.unwrap().unwrap()
    }
}

fn data(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("\\{byte:02x}")).collect()
}

fn frame(value: Value) -> Vec<u8> {
    let bytes = serde_json::to_vec(&value).unwrap();
    let mut frame = (bytes.len() as u32).to_le_bytes().to_vec();
    frame.extend(bytes);
    frame
}

fn result(id: u64, title: &str) -> Value {
    json!({"kind":"result", "eventId":id, "result":{"view":{"kind":"detail", "title":title, "fields":[], "actions":[]}}})
}

// Shared WAT only supplies real WASI byte I/O. Assertions/traps live in the guest,
// so success proves a probe ran rather than merely accepting a valid module.
fn guest(imports: &str, declarations: &str, body: &str) -> String {
    let response = frame(result(1, "Boundary held"));
    format!(r#"(module
        (import "wasi_snapshot_preview1" "fd_read" (func $read (param i32 i32 i32 i32) (result i32)))
        (import "wasi_snapshot_preview1" "fd_write" (func $write (param i32 i32 i32 i32) (result i32)))
        {imports}
        (memory (export "memory") 2)
        (data (i32.const 1024) "{}")
        {declarations}
        (func $assert (param $ok i32) (if (i32.eqz (local.get $ok)) (then unreachable)))
        (func $consume
            (i32.store (i32.const 0) (i32.const 64))
            (i32.store (i32.const 4) (i32.const 4))
            (call $assert (i32.eqz (call $read (i32.const 0) (i32.const 0) (i32.const 1) (i32.const 8))))
            (call $assert (i32.eq (i32.load (i32.const 8)) (i32.const 4)))
            (i32.store (i32.const 0) (i32.const 4096))
            (i32.store (i32.const 4) (i32.load (i32.const 64)))
            (call $assert (i32.eqz (call $read (i32.const 0) (i32.const 0) (i32.const 1) (i32.const 8))))
            (call $assert (i32.eq (i32.load (i32.const 8)) (i32.load (i32.const 64)))))
        (func $emit (param $fd i32) (param $ptr i32) (param $len i32)
            (i32.store (i32.const 0) (local.get $ptr))
            (i32.store (i32.const 4) (local.get $len))
            (call $assert (i32.eqz (call $write (local.get $fd) (i32.const 0) (i32.const 1) (i32.const 8)))))
        (func $finish (call $emit (i32.const 1) (i32.const 1024) (i32.const {})))
        (func (export "_start") {body}))"#, data(&response), response.len())
}

#[tokio::test]
async fn mismatched_runtime_bootstrap_fails_before_reading_wasm() {
    for bootstrap in [
        json!({"protocolVersion":1, "runtimeVersion":env!("CARGO_PKG_VERSION")}),
        json!({"protocolVersion":2, "runtimeVersion":"0.0.0-incompatible"}),
        json!({"protocolVersion":2}),
    ] {
        let mut worker = WorkerProcess::spawn();
        worker.send(bootstrap).await;
        // No Wasm length/payload is sent: rejection must precede either read.
        let response = worker.receive().await;
        assert_eq!(response["kind"], "failure");
        assert_eq!(response["error"]["code"], "RUNTIME_FAILED");
        worker.failed_exit().await;
    }
}


#[tokio::test]
async fn wasi_has_no_environment_arguments_preopens_or_socket_authority() {
    let source = guest(
        r#"(import "wasi_snapshot_preview1" "environ_sizes_get" (func $env (param i32 i32) (result i32)))
        (import "wasi_snapshot_preview1" "args_sizes_get" (func $args (param i32 i32) (result i32)))
        (import "wasi_snapshot_preview1" "fd_prestat_get" (func $prestat (param i32 i32) (result i32)))
        (import "wasi_snapshot_preview1" "sock_accept" (func $accept (param i32 i32 i32) (result i32)))
        (import "wasi_snapshot_preview1" "path_open" (func $open (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))"#,
        r#"(data (i32.const 512) "/etc/passwd")"#,
        r#"(local $fd i32)
        (call $consume)
        (call $assert (i32.eqz (call $env (i32.const 32) (i32.const 36))))
        (call $assert (i32.eqz (i32.or (i32.load (i32.const 32)) (i32.load (i32.const 36)))))
        (call $assert (i32.eqz (call $args (i32.const 32) (i32.const 36))))
        (call $assert (i32.eqz (i32.or (i32.load (i32.const 32)) (i32.load (i32.const 36)))))
        (local.set $fd (i32.const 3))
        (loop $fds
            (call $assert (i32.ne (call $prestat (local.get $fd) (i32.const 32)) (i32.const 0)))
            (local.set $fd (i32.add (local.get $fd) (i32.const 1)))
            (br_if $fds (i32.lt_u (local.get $fd) (i32.const 32))))
        (call $assert (i32.ne (call $open (i32.const 3) (i32.const 0) (i32.const 512) (i32.const 11) (i32.const 0) (i64.const 2) (i64.const 0) (i32.const 0) (i32.const 32)) (i32.const 0)))
        (call $assert (i32.ne (call $accept (i32.const 0) (i32.const 0) (i32.const 32)) (i32.const 0)))
        (call $finish)"#,
    );
    let mut worker = WorkerProcess::spawn();
    assert_eq!(worker.bootstrap(&source).await, json!({"kind":"ready"}));
    worker.event(1, json!({})).await;
    assert_eq!(worker.receive().await, result(1, "Boundary held"));
    worker.cancel().await;
}

#[tokio::test]
async fn privileged_and_unknown_wasi_imports_are_rejected_before_ready() {
    for (module, name) in [
        ("env", "exec"),
        ("wasi_snapshot_preview1", "sock_open"),
        ("wasi_snapshot_preview1", "unknown\u{1b}]52;injected\u{7}\u{202e}"),
    ] {
        let mut worker = WorkerProcess::spawn();
        let name = data(name.as_bytes());
        let response = worker.bootstrap(&format!(r#"(module (import "{module}" "{name}" (func)))"#)).await;
        assert_eq!(response["kind"], "failure");
        assert_eq!(response["error"]["code"], "RUNTIME_FAILED");
        let diagnostic = String::from_utf8(worker.failed_exit().await).unwrap();
        assert!(!diagnostic.contains(['\u{1b}', '\u{7}', '\u{202e}']));
    }
}

#[tokio::test]
async fn each_event_has_fresh_globals_and_memory_but_receives_explicit_state() {
    let second = frame(result(2, "Second explicit state"));
    let source = guest("", &format!(r#"
        (global $counter (mut i32) (i32.const 0))
        (data (i32.const 600) "\07")
        (data (i32.const 2048) "{}")"#, data(&second)), &format!(r#"
        (local $ptr i32) (local $token i32)
        (call $consume)
        (call $assert (i32.eqz (global.get $counter)))
        (call $assert (i32.eq (i32.load8_u (i32.const 600)) (i32.const 7)))
        (global.set $counter (i32.const 99))
        (i32.store8 (i32.const 600) (i32.const 99))
        (local.set $ptr (i32.const 4096))
        (loop $scan
            (if (i32.or (i32.eq (i32.load8_u (local.get $ptr)) (i32.const 65)) (i32.eq (i32.load8_u (local.get $ptr)) (i32.const 66)))
                (then (local.set $token (i32.load8_u (local.get $ptr)))))
            (local.set $ptr (i32.add (local.get $ptr) (i32.const 1)))
            (br_if $scan (i32.lt_u (local.get $ptr) (i32.add (i32.const 4096) (i32.load (i32.const 64))))))
        (call $assert (i32.ne (local.get $token) (i32.const 0)))
        (if (i32.eq (local.get $token) (i32.const 65))
            (then (call $finish))
            (else (call $emit (i32.const 1) (i32.const 2048) (i32.const {}))))"#, second.len()));
    let mut worker = WorkerProcess::spawn();
    assert_eq!(worker.bootstrap(&source).await, json!({"kind":"ready"}));
    worker.event(1, json!({"token":"A"})).await;
    assert_eq!(worker.receive().await, result(1, "Boundary held"));
    worker.event(2, json!({"token":"B"})).await;
    assert_eq!(worker.receive().await, result(2, "Second explicit state"));
    worker.cancel().await;
}

#[tokio::test]
async fn tentative_final_result_is_discarded_when_start_traps() {
    let mut worker = WorkerProcess::spawn();
    let source = guest("", "", "(call $consume) (call $finish) unreachable");
    assert_eq!(worker.bootstrap(&source).await, json!({"kind":"ready"}));
    worker.event(1, json!({})).await;
    let response = worker.receive().await;
    assert_eq!(response["kind"], "failure");
    assert_eq!(response["eventId"], 1);
    assert!(response.get("result").is_none());
    worker.failed_exit().await;
}

#[tokio::test]
async fn growth_beyond_memory_and_table_limits_traps_in_the_worker() {
    for (declarations, operation) in [
        ("", "(drop (memory.grow (i32.const 2047)))"),
        ("(table 1 funcref)", "(drop (table.grow (ref.null func) (i32.const 65536)))"),
    ] {
        let mut worker = WorkerProcess::spawn();
        let source = guest("", declarations, &format!("(call $consume) {operation} (call $finish)"));
        assert_eq!(worker.bootstrap(&source).await, json!({"kind":"ready"}));
        worker.event(1, json!({})).await;
        let response = worker.receive().await;
        assert_eq!(response["kind"], "failure");
        assert_eq!(response["eventId"], 1);
        worker.failed_exit().await;
    }
}

#[tokio::test]
async fn guest_stderr_is_bounded_and_terminal_controls_never_escape() {
    let log = "\u{1b}]52;payload\u{7}\u{202e}\n".repeat(5000);
    let source = guest("", &format!(r#"(data (i32.const 8192) "{}")"#, data(log.as_bytes())), &format!(
        "(call $consume) (call $emit (i32.const 2) (i32.const 8192) (i32.const {})) (call $finish)", log.len()));
    let mut worker = WorkerProcess::spawn();
    assert_eq!(worker.bootstrap(&source).await, json!({"kind":"ready"}));
    worker.event(1, json!({})).await;
    assert_eq!(worker.receive().await, result(1, "Boundary held"));
    let bytes = worker.cancel().await;
    assert!(bytes.len() <= 64 * 1024);
    let text = std::str::from_utf8(&bytes).unwrap();
    assert!(text.starts_with("\u{fffd}]52;payload\u{fffd}\u{fffd}\n"));
    assert!(!text.contains(['\u{1b}', '\u{7}', '\u{202e}']));
}

#[tokio::test]
async fn blocked_parent_and_broker_reads_can_be_killed_and_reaped() {
    let mut worker = WorkerProcess::spawn();
    assert_eq!(worker.bootstrap(&guest("", "", "(call $consume) (call $finish)")).await, json!({"kind":"ready"}));
    // Startup has completed; a partial event blocks the parent's pipe read.
    timeout(DEADLINE, worker.input.write_all(&[20, 0, 0, 0, b'{'])).await.unwrap().unwrap();
    worker.cancel().await;

    let request = frame(json!({"kind":"request", "eventId":1, "id":1, "method":"hosts.list"}));
    let source = guest("", &format!(r#"(data (i32.const 2048) "{}")"#, data(&request)), &format!(
        "(call $consume) (call $emit (i32.const 1) (i32.const 2048) (i32.const {})) (call $finish)", request.len()));
    let mut worker = WorkerProcess::spawn();
    assert_eq!(worker.bootstrap(&source).await, json!({"kind":"ready"}));
    worker.event(1, json!({})).await;
    assert_eq!(worker.receive().await, json!({"kind":"request", "eventId":1, "id":1, "method":"hosts.list"}));
    // No broker response: the child is synchronously blocked inside WASI fd_write.
    worker.cancel().await;
}
