//! Parent-only lifetime and authorization owner. No vault or terminal handles cross this boundary.
use std::{collections::{BTreeMap, VecDeque}, path::{Path, PathBuf}, time::{Duration, Instant}};
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use tokio::sync::{mpsc, oneshot};
use super::{contract::{Binding, Event, ExtensionResult, Method, OpenReason, Permissions, ProtocolError, Provenance, View}, registry::{Registry, Snapshot}, runtime::{BrokerRequest, Worker, WorkerCancellation, WorkerExecutable}};

pub enum ManagerEvent {
    Started { binding: Binding, cancellation: WorkerCancellation },
    Request { binding: Binding, request: BrokerRequest, reply: oneshot::Sender<Result<Value, ProtocolError>> },
    Finished { binding: Binding, event: Event, provenance: Provenance, event_id: u64, result: Result<ExtensionResult>, diagnostics: String },
    Development { binding: Binding, snapshot: Result<Snapshot> },
}
struct Active {
    binding: Binding,
    command: String,
    task: tokio::task::JoinHandle<()>,
    cancellation: Option<WorkerCancellation>,
    sender: mpsc::Sender<(Event, Provenance)>,
    view: Option<View>,
    busy: bool,
    failed: bool,
}
impl Drop for Active {
    fn drop(&mut self) {
        if let Some(cancellation) = &self.cancellation { cancellation.cancel(); }
        self.task.abort();
    }
}

pub struct Development {
    pub path: PathBuf,
    pub digest: String,
    pub trusted_permissions: Option<Vec<super::contract::Permission>>,
    pub replacement: Option<Snapshot>,
    pub candidate: Option<(String, Instant)>,
}
pub struct Manager {
    pub registry: Registry,
    pub(crate) runtime: Option<WorkerExecutable>,
    active: Option<Active>,
    generation: u64,
    sender: mpsc::Sender<ManagerEvent>,
    pub events: mpsc::Receiver<ManagerEvent>,
    pub diagnostics: BTreeMap<String, String>,
    pub development: BTreeMap<String, Development>,
    pending: VecDeque<(Event, Provenance)>,
    scanning: bool,
    pub next_scan: tokio::time::Instant,
}
impl Manager {
    pub fn open(path: &Path) -> Result<Self> {
        let (sender, events) = mpsc::channel(16);
        let mut manager = Self { registry: Registry::open(path)?, runtime: None, active: None, generation: 0, sender, events, diagnostics: BTreeMap::new(), development: BTreeMap::new(), pending: VecDeque::new(), scanning: false, next_scan: tokio::time::Instant::now() + Duration::from_millis(500) };
        manager.attach_remembered();
        Ok(manager)
    }
    /// Reattach reviewed development sources whose bytes still have the installed
    /// digest. This only reads: missing, changed or invalid sources stay unattached
    /// (review needed), and enablement and grants never change.
    pub fn attach_remembered(&mut self) {
        if self.registry.is_blocked() { return; }
        for entry in self.registry.entries() {
            let Some(path) = &entry.development_path else { continue; };
            if entry.source.is_some() || self.development.contains_key(&entry.id) { continue; }
            if super::registry::read_development(path).is_ok_and(|snapshot| snapshot.digest == entry.digest) {
                self.development.insert(entry.id.clone(), Development { path: path.clone(), digest: entry.digest.clone(), trusted_permissions: None, replacement: None, candidate: None });
            }
        }
    }
    pub fn close(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        self.active = None;
        self.pending.clear();
    }
    pub fn binding(&self) -> Option<&Binding> { self.active.as_ref().map(|active| &active.binding) }
    pub fn command(&self) -> Option<&str> { self.active.as_ref().map(|active| active.command.as_str()) }
    pub fn invalidate(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        if let Some(active) = &mut self.active {
            active.failed = true;
            if let Some(cancellation) = &active.cancellation { cancellation.cancel(); }
            active.task.abort();
        }
        self.pending.clear();
    }
    pub fn watching(&self) -> bool {
        !self.scanning && self.active.as_ref().is_some_and(|active| !active.failed && self.development.contains_key(&active.binding.extension_id))
    }
    pub fn scan(&mut self) {
        self.next_scan = tokio::time::Instant::now() + Duration::from_millis(500);
        if !self.watching() { return; }
        let binding = self.active.as_ref().unwrap().binding.clone();
        let path = self.development[&binding.extension_id].path.clone();
        self.scanning = true;
        let output = self.sender.clone();
        tokio::spawn(async move {
            let snapshot = tokio::task::spawn_blocking(move || super::registry::read_development(&path)).await
                .map_err(anyhow::Error::from).and_then(|result| result);
            let _ = output.send(ManagerEvent::Development { binding, snapshot }).await;
        });
    }
    /// Require two identical snapshots separated by the debounce interval.
    pub fn development_snapshot(&mut self, binding: &Binding, snapshot: Result<Snapshot>) -> Result<bool> {
        self.scanning = false;
        if !self.current(binding) { return Ok(false); }
        let snapshot = snapshot?;
        let development = self.development.get_mut(&binding.extension_id).context("Development path removed")?;
        if snapshot.digest == development.digest { development.candidate = None; return Ok(false); }
        if !development.candidate.as_ref().is_some_and(|(digest, since)| digest == &snapshot.digest && since.elapsed() >= Duration::from_millis(400)) {
            development.candidate = Some((snapshot.digest.clone(), Instant::now()));
            return Ok(false);
        }
        development.replacement = Some(snapshot);
        self.invalidate();
        Ok(true)
    }
    pub fn current(&self, binding: &Binding) -> bool {
        !self.registry.is_blocked() && self.active.as_ref().is_some_and(|active| !active.failed && &active.binding == binding) && self.registry.entries().iter().any(|entry| entry.id == binding.extension_id && entry.digest == binding.digest && entry.enabled)
    }
    pub fn permissions(&self, binding: &Binding) -> Result<Permissions> {
        ensure!(self.current(binding), "STALE_TARGET: extension generation is no longer active");
        let entry = self.registry.entries().iter().find(|entry| entry.id == binding.extension_id).context("Extension no longer installed")?;
        Ok(Permissions::new(entry.manifest.permissions.iter().copied(), entry.approved_permissions.iter().copied()))
    }
    pub fn authorize(&self, binding: &Binding, method: Method) -> Result<(), ProtocolError> {
        self.permissions(binding).map_err(|_| ProtocolError { code: super::contract::ErrorCode::Cancelled, message: "Extension generation revoked".into() })?.authorize_method(method)
    }
    pub fn launch(&mut self, id: &str, command: &str, reason: OpenReason) -> Result<()> {
        ensure!(!self.registry.is_blocked(), "Extension registry needs a durable retry before activation");
        let entry = self.registry.entries().iter().find(|entry| entry.id == id && entry.enabled).context("Extension is not enabled")?;
        ensure!(entry.manifest.declares_command(command), "Undeclared extension command");
        let executable = self.runtime.clone().context("Extension runtime is not installed. Download the optional runtime from Settings / Extensions, then reopen the extension.")?;
        let snapshot = self.registry.load(&entry.digest)?;
        let parsed = super::package::Package::parse(&snapshot.bytes)?;
        let wasm = parsed.wasm.to_vec();
        self.close();
        let binding = Binding { extension_id: id.into(), digest: snapshot.digest, grant_generation: self.generation, view_generation: self.generation };
        let (sender, mut events) = mpsc::channel::<(Event, Provenance)>(16);
        let output = self.sender.clone();
        let owner = binding.clone();
        let initial = Event::Open { command_id: command.into(), reason };
        let provenance = if reason == OpenReason::Launch { Provenance::CommandLaunch } else { Provenance::AutomaticReload };
        sender.try_send((initial, provenance))?;
        let task = tokio::spawn(async move {
            let mut worker = match Worker::spawn(executable, wasm, owner.view_generation).await {
                Ok(worker) => worker,
                Err(error) => {
                    let _ = output.send(ManagerEvent::Finished { binding: owner, event: Event::Open { command_id: String::new(), reason }, provenance, event_id: 0, result: Err(error), diagnostics: String::new() }).await;
                    return;
                }
            };
            if output.send(ManagerEvent::Started { binding: owner.clone(), cancellation: worker.cancellation() }).await.is_err() { worker.shutdown().await; return; }
            let mut state = serde_json::json!({});
            let mut event_id = 0;
            while let Some((event, provenance)) = events.recv().await {
                event_id += 1;
                let wire = match serde_json::to_value(&event) { Ok(wire) => wire, Err(_) => break };
                let result = worker.event(wire, state.clone(), |request| {
                    let output = output.clone();
                    let binding = owner.clone();
                    async move {
                        let (reply, response) = oneshot::channel();
                        let cancelled = || ProtocolError { code: super::contract::ErrorCode::Cancelled, message: "Extension surface closed".into() };
                        output.send(ManagerEvent::Request { binding, request, reply }).await.map_err(|_| cancelled())?;
                        response.await.map_err(|_| cancelled())?
                    }
                }).await.and_then(|value| {
                    let mut result: ExtensionResult = serde_json::from_value(value)?;
                    result.validate_and_sanitize()?;
                    if let Some(next) = &result.state { state = next.clone(); }
                    Ok(result)
                });
                let failed = result.is_err();
                let diagnostics = worker.diagnostics();
                if output.send(ManagerEvent::Finished { binding: owner.clone(), event, provenance, event_id, result, diagnostics }).await.is_err() || failed { break; }
            }
            worker.shutdown().await;
        });
        self.active = Some(Active { binding, command: command.into(), task, cancellation: None, sender, view: None, busy: true, failed: false });
        Ok(())
    }
    pub fn reload(&mut self) -> Result<()> {
        let active = self.active.as_ref().context("Open an extension before reloading")?;
        let id = active.binding.extension_id.clone();
        let command = active.command.clone();
        self.launch(&id, &command, OpenReason::Reload)
    }
    pub fn dispatch(&mut self, event: Event) -> Result<()> {
        let active = self.active.as_ref().context("No open extension")?;
        ensure!(!active.failed, "Extension failed; explicitly Reload before another action");
        let entry = self.registry.entries().iter().find(|entry| entry.id == active.binding.extension_id).context("Extension removed")?;
        event.validate(&entry.manifest, active.view.as_ref())?;
        let provenance = match event { Event::Action { .. } => Provenance::Action, Event::Submit { .. } => Provenance::Submission, Event::Open { .. } => anyhow::bail!("Open events require a command launch or reload") };
        if active.busy {
            // Refresh coalesces only itself. Other user events never accumulate unbounded work.
            let refresh = matches!(&event, Event::Action { action_id, item_id: None } if action_id == "refresh");
            if refresh && self.pending.iter().any(|(queued, _)| matches!(queued, Event::Action { action_id, item_id: None } if action_id == "refresh")) { return Ok(()); }
            ensure!(self.pending.len() < 16, "LIMIT_EXCEEDED: extension event queue is full");
            self.pending.push_back((event, provenance));
        } else {
            active.sender.try_send((event, provenance))?;
            self.active.as_mut().unwrap().busy = true;
        }
        Ok(())
    }
    pub fn started(&mut self, binding: &Binding, cancellation: WorkerCancellation) {
        if self.current(binding) { self.active.as_mut().unwrap().cancellation = Some(cancellation); }
        else { cancellation.cancel(); }
    }
    pub fn finish(&mut self, binding: &Binding, result: &Result<ExtensionResult>, diagnostics: String) -> Result<()> {
        ensure!(self.current(binding), "Stale extension result discarded");
        self.diagnostics.insert(binding.extension_id.clone(), diagnostics);
        let active = self.active.as_mut().unwrap();
        active.busy = false;
        match result {
            Ok(result) => active.view = Some(result.view.clone()),
            Err(_) => { active.failed = true; active.view = None; self.pending.clear(); }
        }
        // A newly rendered view can change action meanings. Queued clicks against
        // its predecessor are discarded; only a redundant Refresh survives.
        let refresh = self.pending.drain(..).find(|(event, _)| matches!(event, Event::Action { action_id, item_id: None } if action_id == "refresh"));
        if result.as_ref().is_ok_and(|result| result.proposal.is_none()) {
            if let Some((event, _)) = refresh { self.dispatch(event)?; }
        }
        Ok(())
    }
}
