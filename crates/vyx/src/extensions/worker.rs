//! Optional sandbox executable implementation; never initialized by the core CLI.
//! Wasm memory limits do not bound compiler/process RSS. No native artifacts or cache.
use std::{
    io::{self, Cursor, Read, Write},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use anyhow::{Result, anyhow, bail, ensure};
use bytes::Bytes;
use parking_lot::Mutex;
use serde::Serialize;
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use wasmtime::{Config, Engine, Linker, Module, Store, StoreLimits, StoreLimitsBuilder};
use wasmtime_wasi::{WasiCtxBuilder, cli::{IsTerminal, StdinStream, StdoutStream}, p1::WasiP1Ctx};
use wasmtime_wasi::p2::{InputStream, Pollable, StreamError, StreamResult};

use super::contract::{Bootstrap, GuestMessage, MAX_FRAME_BYTES, ParentMessage, parse_json, read_frame, read_frame_bounded, write_frame};
use super::runtime::{MAX_CALLS, MAX_DIAGNOSTICS, MAX_WASM_BYTES, bounded_state, sanitize};

fn framed(value: &impl Serialize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    write_frame(&mut bytes, value)?;
    Ok(bytes)
}

struct GuestIo {
    input: Cursor<Vec<u8>>,
    output: Vec<u8>,
    frame_len: Option<usize>,
    event_id: u64,
    last_request: u64,
    calls: u64,
    result: Option<Value>,
    failure: Option<String>,
}

impl GuestIo {
    fn new(event_id: u64, event: &impl Serialize, state: &Value, last_request: u64) -> Result<Self> {
        Ok(Self {
            input: Cursor::new(framed(&json!({"kind":"event", "id":event_id, "event":event, "state":state}))?),
            output: Vec::new(), frame_len: None, event_id, last_request,
            calls: 0, result: None, failure: None,
        })
    }

    fn message(&mut self, bytes: &[u8]) -> Result<()> {
        ensure!(self.result.is_none(), "guest wrote after its final result");
        match parse_json::<GuestMessage>(bytes)? {
            GuestMessage::Request { event_id, id, method } => {
                ensure!(event_id == self.event_id && id > self.last_request, "invalid guest request identity");
                ensure!(self.calls < MAX_CALLS, "broker call limit exceeded");
                ensure!(self.input.position() as usize == self.input.get_ref().len(), "guest has unread input");
                self.last_request = id;
                self.calls += 1;
                write_frame(&mut io::stdout().lock(), &json!({"kind":"request", "eventId":event_id, "id":id, "method":method}))?;
                // Guest never reads this pipe directly. Only this exact response
                // to the one outstanding request can enter its bounded stdin.
                let response: ParentMessage = read_frame(&mut io::stdin().lock())?;
                response.validate()?;
                match &response {
                    ParentMessage::Response { event_id: response_event, id: response_id, .. } => {
                        ensure!(*response_event == event_id && *response_id == id, "mismatched broker response");
                    }
                    _ => bail!("expected broker response"),
                }
                self.input = Cursor::new(framed(&response)?);
            }
            GuestMessage::Result { event_id, mut result } => {
                ensure!(event_id == self.event_id, "mismatched final event ID");
                ensure!(self.input.position() as usize == self.input.get_ref().len(), "guest has unread input");
                result.validate_and_sanitize()?;
                self.result = Some(serde_json::to_value(result)?);
            }
        }
        Ok(())
    }

    fn write(&mut self, mut bytes: &[u8]) -> Result<()> {
        ensure!(self.failure.is_none(), "guest protocol already failed");
        while !bytes.is_empty() {
            ensure!(self.result.is_none(), "guest wrote after its final result");
            let target = self.frame_len.map_or(4, |length| length + 4);
            let take = (target - self.output.len()).min(bytes.len());
            self.output.extend_from_slice(&bytes[..take]);
            bytes = &bytes[take..];
            if self.frame_len.is_none() && self.output.len() == 4 {
                let length = u32::from_le_bytes(self.output[..4].try_into().unwrap()) as usize;
                ensure!(length > 0 && length <= MAX_FRAME_BYTES, "invalid guest frame length");
                self.frame_len = Some(length);
            }
            if self.frame_len.is_some_and(|length| self.output.len() == length + 4) {
                let frame = std::mem::take(&mut self.output);
                self.frame_len = None;
                self.message(&frame[4..])?;
            }
        }
        Ok(())
    }
}

#[derive(Clone)]
struct GuestInput(Arc<Mutex<GuestIo>>);
#[derive(Clone)]
struct GuestOutput(Arc<Mutex<GuestIo>>);

impl IsTerminal for GuestInput { fn is_terminal(&self) -> bool { false } }
impl IsTerminal for GuestOutput { fn is_terminal(&self) -> bool { false } }
impl StdinStream for GuestInput {
    fn async_stream(&self) -> Box<dyn AsyncRead + Send + Sync> { Box::new(self.clone()) }
    fn p2_stream(&self) -> Box<dyn InputStream> { Box::new(self.clone()) }
}
impl StdoutStream for GuestOutput {
    fn async_stream(&self) -> Box<dyn AsyncWrite + Send + Sync> { Box::new(self.clone()) }
}
impl AsyncRead for GuestInput {
    fn poll_read(self: Pin<&mut Self>, _: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let mut state = self.0.lock();
        if state.failure.is_some() { return Poll::Ready(Err(io::Error::other("guest protocol failed"))); }
        let position = state.input.position() as usize;
        let available = &state.input.get_ref()[position..];
        if available.is_empty() && buf.remaining() != 0 {
            state.failure = Some("guest read without an outstanding response".into());
            return Poll::Ready(Err(io::Error::other("no guest input available")));
        }
        let take = available.len().min(buf.remaining());
        buf.put_slice(&available[..take]);
        state.input.set_position((position + take) as u64);
        Poll::Ready(Ok(()))
    }
}
// Avoid AsyncReadStream's eager background prefetch: reading a response before
// the guest has issued its request would violate this synchronous RPC protocol.
#[wasmtime_wasi::async_trait]
impl Pollable for GuestInput {
    async fn ready(&mut self) {}
}
#[wasmtime_wasi::async_trait]
impl InputStream for GuestInput {
    fn read(&mut self, size: usize) -> StreamResult<Bytes> {
        let mut state = self.0.lock();
        if state.failure.is_some() { return Err(StreamError::trap("guest protocol failed")); }
        let position = state.input.position() as usize;
        let available = &state.input.get_ref()[position..];
        if available.is_empty() && size != 0 {
            state.failure = Some("guest read without an outstanding response".into());
            return Err(StreamError::trap("no guest input available"));
        }
        let take = available.len().min(size);
        let bytes = Bytes::copy_from_slice(&available[..take]);
        state.input.set_position((position + take) as u64);
        Ok(bytes)
    }
}
impl AsyncWrite for GuestOutput {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let mut state = self.0.lock();
        match state.write(buf) {
            Ok(()) => Poll::Ready(Ok(buf.len())),
            Err(error) => {
                state.failure = Some(format!("{error:#}"));
                Poll::Ready(Err(io::Error::other(error.to_string())))
            }
        }
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> { Poll::Ready(Ok(())) }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> { Poll::Ready(Ok(())) }
}
#[derive(Clone)]
struct GuestDiagnostics(Arc<Mutex<usize>>);
impl IsTerminal for GuestDiagnostics { fn is_terminal(&self) -> bool { false } }
impl StdoutStream for GuestDiagnostics {
    fn async_stream(&self) -> Box<dyn AsyncWrite + Send + Sync> { Box::new(self.clone()) }
}
impl AsyncWrite for GuestDiagnostics {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let mut written = self.0.lock();
        let remaining = MAX_DIAGNOSTICS - *written;
        let take = remaining.min(buf.len());
        let clean = sanitize(&String::from_utf8_lossy(&buf[..take]));
        let mut end = clean.len().min(remaining);
        while !clean.is_char_boundary(end) { end -= 1; }
        if let Err(error) = io::stderr().lock().write_all(&clean.as_bytes()[..end]) { return Poll::Ready(Err(error)); }
        *written += end;
        Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> { Poll::Ready(Ok(())) }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> { Poll::Ready(Ok(())) }
}

struct GuestStore { wasi: WasiP1Ctx, limits: StoreLimits }

fn engine() -> Result<Engine> {
    let mut config = Config::new();
    config.consume_fuel(true).max_wasm_stack(1024 * 1024)
        .wasm_memory64(false).wasm_multi_memory(false)
        .wasm_component_model(false).wasm_gc(false).wasm_stack_switching(false);
    // The `threads` feature is absent entirely. No native artifact loader or
    // cache is enabled. Only core Module::new on approved raw bytes is used.
    Ok(Engine::new(&config)?)
}

fn run_guest(engine: &Engine, module: &Module, linker: &Linker<GuestStore>, id: u64, event: &impl Serialize, state: &Value, last_request: &mut u64) -> Result<Value> {
    bounded_state(state)?;
    let channel = Arc::new(Mutex::new(GuestIo::new(id, event, state, *last_request)?));
    let wasi = WasiCtxBuilder::new()
        .stdin(GuestInput(channel.clone())).stdout(GuestOutput(channel.clone()))
        .stderr(GuestDiagnostics(Arc::new(Mutex::new(0))))
        .allow_tcp(false).allow_udp(false).allow_ip_name_lookup(false).build_p1();
    let limits = StoreLimitsBuilder::new().memory_size(128 * 1024 * 1024)
        .memories(1).instances(1).tables(4).table_elements(65_536)
        .trap_on_grow_failure(true).build();
    let mut store = Store::new(engine, GuestStore { wasi, limits });
    store.limiter(|data| &mut data.limits);
    store.set_fuel(100_000_000)?;
    let instance = linker.instantiate(&mut store, module)?;
    let start = instance.get_typed_func::<(), ()>(&mut store, "_start")?;
    let execution = start.call(&mut store, ());
    // Drop stream adapters before inspecting final protocol state. The sync
    // WASIp1 adapter completes every write before returning the host call.
    drop(store);
    let mut channel = channel.lock();
    if let Some(error) = channel.failure.take() { bail!("guest protocol: {error}"); }
    if let Err(error) = execution {
        if !error.downcast_ref::<wasmtime_wasi::I32Exit>().is_some_and(|exit| exit.0 == 0) {
            return Err(anyhow::Error::from(error).context("guest execution failed"));
        }
    }
    ensure!(channel.output.is_empty(), "guest left a truncated output frame");
    *last_request = channel.last_request;
    channel.result.take().ok_or_else(|| anyhow!("guest returned without a final result"))
}

/// Dedicated executable entry point, independent of app, vault and data directory.
/// Failure frames, not raw stderr, are the worker's machine-readable errors.
pub fn worker_main() -> Result<()> {
    let mut event_id = None;
    let result = worker_loop(&mut event_id);
    if let Err(error) = &result {
        let message = sanitize(&format!("{error:#}"));
        let mut end = message.len().min(8192);
        while !message.is_char_boundary(end) { end -= 1; }
        let mut failure = json!({"kind":"failure", "error":{"code":"RUNTIME_FAILED", "message":&message[..end]}});
        if let Some(id) = event_id { failure["eventId"] = json!(id); }
        let _ = write_frame(&mut io::stdout().lock(), &failure);
        // main's Result termination also prints this error to stderr. Never
        // return the original chain: import names and other Wasm metadata are
        // guest-controlled, including terminal controls and unbounded text.
        return Err(anyhow!("{}", &message[..end]));
    }
    result
}

fn worker_loop(event_id: &mut Option<u64>) -> Result<()> {
    let bootstrap: Bootstrap = read_frame_bounded(&mut io::stdin().lock(), 64 * 1024)?;
    ensure!(bootstrap.protocol_version == 2, "unsupported extension protocol version");
    ensure!(bootstrap.runtime_version == env!("CARGO_PKG_VERSION"), "extension runtime version mismatch");
    let mut length = [0; 4];
    io::stdin().lock().read_exact(&mut length)?;
    let length = u32::from_le_bytes(length) as usize;
    ensure!(length > 0 && length <= MAX_WASM_BYTES, "invalid bootstrap Wasm size");
    let mut wasm = vec![0; length];
    io::stdin().lock().read_exact(&mut wasm)?;
    let engine = engine()?;
    let module = Module::new(&engine, &wasm)?;
    drop(wasm);
    let mut linker = Linker::<GuestStore>::new(&engine);
    wasmtime_wasi::p1::add_to_linker_sync(&mut linker, |data| &mut data.wasi)?;
    for import in module.imports() {
        ensure!(import.module() == "wasi_snapshot_preview1" && matches!(import.ty(), wasmtime::ExternType::Func(_)), "unsupported extension import");
    }
    // Check every import before reporting readiness, without instantiating or
    // running a guest start section until an event deadline is active.
    linker.instantiate_pre(&module)?;
    write_frame(&mut io::stdout().lock(), &json!({"kind":"ready"}))?;
    let mut last_event = 0;
    let mut last_request = 0;
    loop {
        let message: ParentMessage = read_frame(&mut io::stdin().lock())?;
        let ParentMessage::Event { id, event, state } = message else { bail!("expected event, not response/bootstrap"); };
        ensure!(id > last_event && id <= ((1u64 << 53) - 1) / MAX_CALLS, "invalid event ID");
        *event_id = Some(id);
        last_event = id;
        let result = run_guest(&engine, &module, &linker, id, &event, &state, &mut last_request)?;
        write_frame(&mut io::stdout().lock(), &json!({"kind":"result", "eventId":id, "result":result}))?;
        *event_id = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn infinite_guest_exhausts_production_fuel_budget() {
        // Core module exporting _start: (loop (br 0)). No author toolchain.
        let wasm = [
            0, 97, 115, 109, 1, 0, 0, 0,
            1, 4, 1, 96, 0, 0,
            3, 2, 1, 0,
            7, 10, 1, 6, 95, 115, 116, 97, 114, 116, 0, 0,
            10, 9, 1, 7, 0, 3, 64, 12, 0, 11, 11,
        ];
        let engine = engine().unwrap();
        let module = Module::new(&engine, wasm).unwrap();
        let linker = Linker::new(&engine);
        let error = run_guest(&engine, &module, &linker, 1, &json!({}), &json!({}), &mut 0).unwrap_err();
        assert_eq!(error.downcast_ref::<wasmtime::Trap>(), Some(&wasmtime::Trap::OutOfFuel));
    }

    #[test]
    fn unsupported_memory_features_are_rejected() {
        let engine = engine().unwrap();
        let mut wasm = vec![0, 97, 115, 109, 1, 0, 0, 0];
        // Two 32-bit unshared memories.
        wasm.extend_from_slice(&[5, 5, 2, 0, 0, 0, 0]);
        assert!(Module::new(&engine, &wasm).is_err());
        wasm.truncate(8);
        // One memory64.
        wasm.extend_from_slice(&[5, 3, 1, 4, 0]);
        assert!(Module::new(&engine, &wasm).is_err());
        wasm.truncate(8);
        // One shared memory, with a maximum.
        wasm.extend_from_slice(&[5, 4, 1, 3, 0, 1]);
        assert!(Module::new(&engine, &wasm).is_err());
    }

    #[test]
    fn oversized_guest_frame_fails_before_payload_allocation() {
        let mut io = GuestIo::new(1, &json!({}), &json!({}), 0).unwrap();
        assert!(io.write(&((MAX_FRAME_BYTES + 1) as u32).to_le_bytes()).is_err());
        assert_eq!(io.output.len(), 4);
    }

    #[test]
    fn result_then_output_is_a_protocol_failure() {
        let mut io = GuestIo::new(1, &json!({}), &json!({}), 0).unwrap();
        io.input.set_position(io.input.get_ref().len() as u64);
        let result = framed(&json!({"kind":"result", "eventId":1, "result":{"view":{"kind":"detail","title":"Result","fields":[]}}})).unwrap();
        for byte in &result { io.write(&[*byte]).unwrap(); }
        assert!(io.write(&[0]).is_err());
    }

    #[test]
    fn guest_cannot_retarget_or_skip_unread_response() {
        let mut io = GuestIo::new(4, &json!({}), &json!({}), 7).unwrap();
        for request in [
            json!({"kind":"request", "eventId":3, "id":8, "method":"hosts.list"}),
            json!({"kind":"request", "eventId":4, "id":7, "method":"hosts.list"}),
            json!({"kind":"request", "eventId":4, "id":8, "method":"process.exec"}),
            json!({"kind":"request", "eventId":4, "id":8, "method":"hosts.list"}),
        ] { assert!(io.message(&serde_json::to_vec(&request).unwrap()).is_err()); }
    }
}
