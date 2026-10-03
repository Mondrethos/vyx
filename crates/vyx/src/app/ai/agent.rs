//! Bounded AI runs. A deliberate request may start one run. Each completed eligible reply's
//! validated action batch executes one action at a time through native authority, approval,
//! and session-lifecycle checks. Nothing here schedules inference, retries, or keeps working
//! in the background.
use super::*;
use crate::{
    ai::actions::{self, ControlContext, HostTarget, Key, Outcome, Request, SessionTarget, Tracked},
    settings::TerminalLayout,
    ui::actions::EditorTarget,
    vault::{Host, HostAuth, HostTransport, Secret},
};

const TICK: Duration = Duration::from_millis(250);
/// Output must stay unchanged this long before a result is captured.
const QUIET: Duration = Duration::from_millis(1500);
const MIN_OUTPUT_WAIT: Duration = Duration::from_secs(1);
const RUN_OUTPUT_LIMIT: Duration = Duration::from_secs(60);
const INPUT_OUTPUT_LIMIT: Duration = Duration::from_secs(10);
const CONNECTION_LIMIT: Duration = Duration::from_secs(120);
const RESULT_LINES: usize = 120;
const SAVED_HOST_LIMIT: usize = 50;
const ASSIST_REASON: &str = "Assist asks before every change";
const STOP_NOTE: &str = "Vyx sent no interrupt and cannot undo terminal input that was already submitted.";
const PTY_WARNING: &str = "PTY input is not isolated: it goes to whatever runs in the terminal, which may be a foreground program rather than a shell prompt.";

/// A session as resolved from the request snapshot; actions never retarget by label or focus.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Target {
    id: Uuid,
    label: String,
    address: String,
    port: u16,
}

impl Target {
    fn describe(&self) -> String {
        format!(
            "{} ({}:{})",
            contract::sanitize_display(&self.label),
            contract::sanitize_display(&self.address),
            self.port
        )
    }
}

/// Authority and inventory captured when a run's request was sent. That reply's actions
/// resolve only against this snapshot.
pub(super) struct Control {
    run: u64,
    level: PermissionLevel,
    capabilities: BTreeSet<Capability>,
    remaining: u16,
    sessions: Vec<SessionTarget>,
    hosts: Vec<HostTarget>,
    omitted_hosts: usize,
    vault_snapshot: Uuid,
}

impl Control {
    pub(super) fn context(&self) -> ControlContext<'_> {
        ControlContext {
            level: self.level,
            capabilities: &self.capabilities,
            remaining_steps: self.remaining,
            sessions: &self.sessions,
            hosts: &self.hosts,
            omitted_hosts: self.omitted_hosts,
        }
    }
}

enum Step {
    Read { session: Target, lines: usize },
    Run { session: Target, command: String },
    Type { session: Target, text: String },
    Keys { session: Target, keys: Vec<Key> },
    Open { host: Uuid, label: String, vault_snapshot: Uuid },
    Close { session: Target },
    Focus { session: Target },
    Rename { session: Target, title: String },
    Layout { layout: TerminalLayout },
    Draft { label: String, hostname: String, port: u16, username: Option<String> },
}

impl Step {
    fn capability(&self) -> Capability {
        match self {
            Self::Read { .. } => Capability::ReadOutput,
            Self::Run { .. } | Self::Type { .. } | Self::Keys { .. } => Capability::RunCommands,
            Self::Open { .. } | Self::Close { .. } => Capability::Sessions,
            Self::Focus { .. } | Self::Rename { .. } | Self::Layout { .. } => Capability::TabsLayout,
            Self::Draft { .. } => Capability::ServerDrafts,
        }
    }

    fn session(&self) -> Option<&Target> {
        match self {
            Self::Read { session, .. }
            | Self::Run { session, .. }
            | Self::Type { session, .. }
            | Self::Keys { session, .. }
            | Self::Close { session }
            | Self::Focus { session }
            | Self::Rename { session, .. } => Some(session),
            Self::Open { .. } | Self::Layout { .. } | Self::Draft { .. } => None,
        }
    }

    /// Terminal input requires a connected session; other session actions may address an
    /// existing ended tab.
    fn needs_connected(&self) -> bool {
        matches!(self, Self::Run { .. } | Self::Type { .. } | Self::Keys { .. })
    }

    fn target(&self) -> String {
        match self {
            Self::Open { label, .. } => format!("saved server \"{}\"", contract::sanitize_display(label)),
            Self::Layout { .. } => "terminal layout".into(),
            Self::Draft { label, .. } => format!("new saved server \"{}\"", contract::sanitize_display(label)),
            _ => self.session().map(Target::describe).unwrap_or_default(),
        }
    }
}

struct Queued {
    summary: String,
    step: Step,
    /// A tab title implied by the reply's title line; reported in status, never followed up.
    implicit: bool,
}

enum Wait {
    /// Ready for the next queued action.
    Idle,
    /// The run's provider request is streaming.
    Reply,
    Review(Uuid),
    Output { session: Uuid, started: Instant, changed: Instant, bytes: u64, limit: Duration },
    Connection { session: Uuid, started: Instant },
    Draft { host: Uuid, label: String, saved: bool },
}

pub(super) struct Run {
    pub(super) generation: u64,
    pub(super) conversation: Uuid,
    package: Package,
    pub(super) profile: Uuid,
    routing: RoutingIdentity,
    steps: u16,
    limit: u16,
    queue: VecDeque<Queued>,
    /// The exact validated action awaiting native approval.
    pending: Option<Queued>,
    /// The target session's tracked input when that approval was requested.
    reviewed_input: Option<Tracked>,
    /// The action whose wait is in progress.
    current: Option<Outcome>,
    outcomes: Vec<Outcome>,
    wait: Wait,
    ticker: Option<tokio::task::JoinHandle<()>>,
    session_handles: HashMap<Uuid, String>,
    host_handles: HashMap<Uuid, String>,
    next_session: u32,
    next_host: u32,
}

impl Drop for Run {
    fn drop(&mut self) {
        if let Some(ticker) = self.ticker.take() {
            ticker.abort();
        }
    }
}

impl Run {
    pub(super) fn status(&self) -> AgentStatus {
        match self.wait {
            Wait::Review(_) | Wait::Draft { .. } => AgentStatus::Approval,
            Wait::Output { .. } => AgentStatus::Output,
            Wait::Connection { .. } => AgentStatus::Connection,
            Wait::Idle | Wait::Reply => AgentStatus::Working { step: self.steps.min(self.limit), limit: self.limit },
        }
    }

    pub(super) fn awaiting_reply(&self) -> bool {
        matches!(self.wait, Wait::Reply)
    }

    /// Handles are assigned once per run and never reused for another target.
    fn session_handle(&mut self, id: Uuid) -> String {
        if let Some(handle) = self.session_handles.get(&id) {
            return handle.clone();
        }
        self.next_session += 1;
        let handle = format!("s{}", self.next_session);
        self.session_handles.insert(id, handle.clone());
        handle
    }

    fn host_handle(&mut self, id: Uuid) -> String {
        if let Some(handle) = self.host_handles.get(&id) {
            return handle.clone();
        }
        self.next_host += 1;
        let handle = format!("h{}", self.next_host);
        self.host_handles.insert(id, handle.clone());
        handle
    }

    fn timed(&self) -> bool {
        matches!(self.wait, Wait::Output { .. } | Wait::Connection { .. } | Wait::Draft { .. })
    }
}

fn outcome(action: String, target: String, approval: &'static str, status: String) -> Outcome {
    Outcome { action, target, approval, status, output: None, captured_at: None }
}

impl App {
    /// A deliberate request starts a run when the chat's effective level allows actions.
    pub(super) fn begin_ai_run(&mut self, conversation: Uuid, package: &Package, profile: &Profile) -> Result<()> {
        self.ai.agent = None;
        let config = &self.ai.data.config;
        if config.effective_permission(self.ai.conversation(conversation)?.permission) == PermissionLevel::ChatOnly {
            return Ok(());
        }
        let routing = RoutingIdentity::from_profile(profile)?;
        let limit = config.agent_steps;
        let generation = self.ai.next_generation();
        self.ai.agent = Some(Run {
            generation,
            conversation,
            package: package.clone(),
            profile: profile.id,
            routing,
            steps: 0,
            limit,
            queue: VecDeque::new(),
            pending: None,
            reviewed_input: None,
            current: None,
            outcomes: Vec::new(),
            wait: Wait::Reply,
            ticker: None,
            session_handles: HashMap::new(),
            host_handles: HashMap::new(),
            next_session: 0,
            next_host: 0,
        });
        Ok(())
    }

    /// The authority snapshot for the next request of `conversation`'s run, if it has one.
    pub(super) fn ai_control(&mut self, conversation: Uuid) -> Option<Control> {
        let config = &self.ai.data.config;
        let entry = self.ai.data.conversations.iter().find(|entry| entry.id == conversation)?;
        let level = config.effective_permission(entry.permission);
        if level == PermissionLevel::ChatOnly {
            return None;
        }
        let run = self.ai.agent.as_mut().filter(|run| run.conversation == conversation)?;
        let mut sessions = Vec::with_capacity(entry.sessions.len());
        for id in &entry.sessions {
            let Some(session) = self.sessions.iter().find(|session| session.id == *id) else {
                continue;
            };
            let phase = session.view.lock().phase.label();
            sessions.push(SessionTarget {
                handle: run.session_handle(*id),
                id: *id,
                label: session.label.clone(),
                address: session.destination.address.clone(),
                port: session.destination.port,
                phase,
            });
        }
        let mut hosts = Vec::new();
        let mut omitted_hosts = 0;
        if config.grants(level, Capability::Sessions) {
            let mut saved: Vec<&Host> = self.state.vault.hosts.iter().collect();
            saved.sort_by(|left, right| left.label.cmp(&right.label).then(left.id.cmp(&right.id)));
            omitted_hosts = saved.len().saturating_sub(SAVED_HOST_LIMIT);
            for host in saved.into_iter().take(SAVED_HOST_LIMIT) {
                hosts.push(HostTarget {
                    handle: run.host_handle(host.id),
                    id: host.id,
                    label: host.label.clone(),
                    address: host.hostname.clone(),
                    port: host.port,
                });
            }
        }
        Some(Control {
            run: run.generation,
            level,
            capabilities: config.capabilities.clone(),
            remaining: run.limit.saturating_sub(run.steps),
            sessions,
            hosts,
            omitted_hosts,
            vault_snapshot: self.state.vault.snapshot_id,
        })
    }

    /// Validates a completed reply's action blocks against its request snapshot and queues
    /// them. Ineligible replies run nothing; their title can only become a suggestion.
    pub(super) fn queue_ai_actions(
        &mut self,
        conversation: Uuid,
        parsed: Result<Vec<Request>>,
        control: Option<Control>,
        title: Option<&str>,
    ) {
        let control = control.filter(|control| {
            self.ai.agent.as_ref().is_some_and(|run| {
                run.generation == control.run && run.conversation == conversation && run.awaiting_reply()
            })
        });
        let Some(control) = control else {
            let proposed = parsed.as_ref().map_or(true, |requests| !requests.is_empty());
            if proposed {
                self.append_ai_results(conversation, &[outcome(
                    "Action blocks in the reply".into(),
                    "none".into(),
                    "not run",
                    "Not performed: this reply was not eligible to run actions (Chat only, background, or stopped). Nothing was sent to any session.".into(),
                )]);
            }
            if let Some(title) = title {
                self.ai_title_suggestion(conversation, title);
            }
            return;
        };
        let requests = match parsed {
            Ok(requests) => requests,
            Err(error) => {
                if let Some(title) = title {
                    self.ai_title_suggestion(conversation, title);
                }
                self.reject_ai_batch(conversation, format!("Batch rejected before anything ran: {}", error_text(&error)));
                return;
            }
        };
        let mut queue = VecDeque::with_capacity(requests.len() + 1);
        for request in &requests {
            match self.resolve_ai_request(&control, request) {
                Ok(step) => queue.push_back(Queued { summary: request.summary(), step, implicit: false }),
                Err(error) => {
                    if let Some(title) = title {
                        self.ai_title_suggestion(conversation, title);
                    }
                    self.reject_ai_batch(conversation, format!("Batch rejected before anything ran: {}", error_text(&error)));
                    return;
                }
            }
        }
        if let Some(title) = title {
            match self.implicit_rename(&control, conversation, title, &queue) {
                Some(step) if queue.len() < actions::MAX_ACTIONS => {
                    let summary = format!("rename tab to \"{}\"", contract::sanitize_display(title));
                    queue.push_back(Queued { summary, step, implicit: true });
                }
                Some(_) | None => self.ai_title_suggestion(conversation, title),
            }
        }
        let Some(run) = self.ai.agent.as_mut() else {
            return;
        };
        if queue.is_empty() {
            // A reply without actions ends the run.
            self.ai.agent = None;
            return;
        }
        run.queue = queue;
        run.wait = Wait::Idle;
    }

    /// Host-dependent preflight: every target and capability must resolve against the request
    /// snapshot before anything in the batch runs.
    fn resolve_ai_request(&self, control: &Control, request: &Request) -> Result<Step> {
        let capability = request.capability();
        ensure!(
            control.level > PermissionLevel::ChatOnly && control.capabilities.contains(&capability),
            "{} is not allowed in this chat",
            capability.label()
        );
        let session = |handle: &str| -> Result<Target> {
            let target = control
                .sessions
                .iter()
                .find(|session| session.handle == handle)
                .with_context(|| format!("unknown or out-of-scope session {}", contract::sanitize_display(handle)))?;
            Ok(Target {
                id: target.id,
                label: target.label.clone(),
                address: target.address.clone(),
                port: target.port,
            })
        };
        Ok(match request {
            Request::Read { session: handle, lines } => Step::Read { session: session(handle)?, lines: usize::from(*lines) },
            Request::Run { session: handle, command } => Step::Run { session: session(handle)?, command: command.clone() },
            Request::Type { session: handle, text } => Step::Type { session: session(handle)?, text: text.clone() },
            Request::Keys { session: handle, keys } => Step::Keys { session: session(handle)?, keys: keys.clone() },
            Request::Close { session: handle } => Step::Close { session: session(handle)? },
            Request::Focus { session: handle } => Step::Focus { session: session(handle)? },
            Request::Rename { session: handle, title } => Step::Rename { session: session(handle)?, title: title.clone() },
            Request::Layout { layout } => Step::Layout { layout: *layout },
            Request::Open { host } => {
                ensure!(
                    self.state.vault.snapshot_id == control.vault_snapshot,
                    "saved servers changed after this request; ask again"
                );
                let id = match control.hosts.iter().find(|target| target.handle == *host) {
                    Some(target) => target.id,
                    None => saved_host_id(&self.state.vault, host)?,
                };
                let label = self
                    .state
                    .vault
                    .hosts
                    .iter()
                    .find(|saved| saved.id == id)
                    .map(|saved| saved.label.clone())
                    .context("that saved server no longer exists")?;
                Step::Open { host: id, label, vault_snapshot: control.vault_snapshot }
            }
            Request::DraftServer { label, hostname, port, username } => Step::Draft {
                label: label.clone(),
                hostname: hostname.clone(),
                port: *port,
                username: username.clone(),
            },
        })
    }

    /// The tab rename an eligible reply's title line implies, when AutoTitle, TabsLayout, and
    /// naming pins allow it and it would change the tab.
    fn implicit_rename(&self, control: &Control, conversation: Uuid, title: &str, queue: &VecDeque<Queued>) -> Option<Step> {
        if !self.ai.data.config.allows(Feature::AutoTitle) || !control.capabilities.contains(&Capability::TabsLayout) {
            return None;
        }
        let entry = self.ai.conversation(conversation).ok()?;
        if entry.naming_paused {
            return None;
        }
        let target = control.sessions.first()?;
        let explicit = queue
            .iter()
            .any(|queued| matches!(&queued.step, Step::Rename { session, .. } if session.id == target.id));
        let pinned = self
            .ai
            .names
            .get(&target.id)
            .is_some_and(|name| matches!(name.naming, Naming::Manual | Naming::Paused));
        if explicit || pinned {
            return None;
        }
        let session = self.sessions.iter().find(|session| session.id == target.id)?;
        let server = self
            .ai
            .names
            .get(&target.id)
            .map_or(session.destination.label.as_str(), |name| name.original.as_str());
        let composed = ai::compose_tab_title(Some(server), title, self.ai.data.config.title_prefix)?;
        (composed != session.label).then(|| Step::Rename {
            session: Target {
                id: target.id,
                label: target.label.clone(),
                address: target.address.clone(),
                port: target.port,
            },
            title: title.to_owned(),
        })
    }

    /// A rejected batch records why and ends the run; nothing runs and nothing follows up.
    fn reject_ai_batch(&mut self, conversation: Uuid, reason: String) {
        self.ai.agent = None;
        self.append_ai_results(conversation, &[outcome("Action batch".into(), "none".into(), "not run", reason.clone())]);
        self.ai.panel.set_error(reason);
    }

    /// Ends the active run: its stream, queued actions, ticker, review, and unsaved draft
    /// editor. Completed and partial results are kept where history allows.
    pub(super) fn stop_ai_agent(&mut self, reason: &str) {
        let Some(mut run) = self.ai.agent.take() else {
            return;
        };
        if run.awaiting_reply() {
            self.stop_ai_stream(STOPPED);
        }
        if let Wait::Review(id) = run.wait
            && self.ai.review.as_ref().is_some_and(|review| review.id == id)
        {
            self.ai.review = None;
            if matches!(&self.dialog, Some(Dialog::ExtensionReview(review)) if review.id == id) {
                self.dialog = None;
            }
            if matches!(&self.quit_dialog, Some(Dialog::ExtensionReview(review)) if review.id == id) {
                self.quit_dialog = None;
            }
        }
        if let Wait::Draft { host, saved: false, .. } = run.wait
            && matches!(&self.dialog, Some(Dialog::Editor(editor)) if matches!(editor.target, EditorTarget::Host { id, .. } if id == host))
        {
            self.dialog = None;
        }
        self.restore_focused_mode();
        let discarded = run.queue.len() + usize::from(run.pending.is_some());
        if let Some(mut current) = run.current.take() {
            current.status = format!("Interrupted while waiting: {reason}");
            run.outcomes.push(current);
        }
        if !run.outcomes.is_empty() || discarded > 0 {
            run.outcomes.push(outcome(
                "Run stopped".into(),
                "none".into(),
                "not run",
                format!("{reason} {discarded} queued action(s) were discarded. {STOP_NOTE}"),
            ));
            let outcomes = std::mem::take(&mut run.outcomes);
            self.append_ai_results(run.conversation, &outcomes);
        }
        self.ai.panel.set_status(format!("{reason} {STOP_NOTE}"));
        self.mark_dirty();
    }

    /// Stores results as one redacted action message when the conversation has room.
    fn append_ai_results(&mut self, conversation: Uuid, outcomes: &[Outcome]) -> bool {
        let text = actions::format_results(outcomes, self.ai.data.config.context_chars);
        let Ok(entry) = self.ai.conversation_mut(conversation) else {
            return false;
        };
        if entry.messages.len() >= ai::MAX_MESSAGES || entry.push(Message::new(Role::Action, text)).is_err() {
            return false;
        }
        entry.updated_at = ai::now();
        self.ai.touched(conversation);
        self.mark_dirty();
        true
    }

    /// Ticks only while a run waits on time, a terminal, a connection, or a draft editor.
    fn update_agent_ticker(&mut self) {
        let sender = self.ai.sender.clone();
        let Some(run) = self.ai.agent.as_mut() else {
            return;
        };
        if !run.timed() {
            if let Some(ticker) = run.ticker.take() {
                ticker.abort();
            }
            return;
        }
        if run.ticker.is_some() {
            return;
        }
        let generation = run.generation;
        run.ticker = Some(tokio::spawn(async move {
            loop {
                tokio::time::sleep(TICK).await;
                if sender.send(Event { generation, kind: EventKind::AgentTick }).await.is_err() {
                    return;
                }
            }
        }));
    }

    /// Rechecks everything an effect relies on, immediately before it happens.
    fn agent_authority(&self, step: &Step) -> Result<PermissionLevel> {
        let run = self.ai.agent.as_ref().context("the run ended")?;
        ensure!(self.attached, "the workspace is detached or locked");
        let package = self.ai_ready(Some(Feature::Chat))?;
        ensure!(package == run.package, "the Vyx AI package changed");
        let profile = self.ai.profile(run.profile)?;
        ensure!(RoutingIdentity::from_profile(profile)? == run.routing, "the provider routing changed");
        let entry = self.ai.conversation(run.conversation)?;
        let config = &self.ai.data.config;
        let level = config.effective_permission(entry.permission);
        ensure!(config.grants(level, step.capability()), "{} is not allowed now", step.capability().label());
        if let Some(target) = step.session() {
            ensure!(entry.sessions.contains(&target.id), "the session left this chat's scope");
            let session = self
                .sessions
                .iter()
                .find(|session| session.id == target.id)
                .context("the session closed")?;
            ensure!(
                session.destination.address == target.address && session.destination.port == target.port,
                "the session's destination changed"
            );
            ensure!(!step.needs_connected() || session_connected(session), "the session is not connected");
        }
        if let Step::Open { vault_snapshot, .. } = step {
            ensure!(self.state.vault.snapshot_id == *vault_snapshot, "saved servers changed after this request");
        }
        Ok(level)
    }

    /// Whether the run must wait before its next action: an unrelated modal, menu, pending
    /// native prompt, or detached workspace pauses it until closed.
    fn agent_paused(&self) -> bool {
        self.dialog.is_some()
            || self.menu.is_some()
            || self.quit_confirming
            || !self.prompt_queue.is_empty()
            || !self.attached
    }

    /// Resumes a run paused by an unrelated modal once it closed; cheap when idle.
    pub(in crate::app) async fn resume_ai_agent(&mut self) {
        if self.ai.agent.as_ref().is_some_and(|run| matches!(run.wait, Wait::Idle)) && !self.agent_paused() {
            self.advance_ai_agent().await;
        }
    }

    /// Drives the run: settles a finished wait, then executes queued actions one at a time
    /// until one needs approval, terminal output, a connection, the user, or the provider.
    pub(super) async fn advance_ai_agent(&mut self) {
        loop {
            match self.settle_agent_wait() {
                Settled::Waiting => {
                    self.update_agent_ticker();
                    return;
                }
                Settled::Failed => {
                    self.finish_ai_batch(false);
                    return;
                }
                Settled::Ready => {}
            }
            self.update_agent_ticker();
            if self.agent_paused() {
                return;
            }
            let Some(run) = self.ai.agent.as_mut() else {
                return;
            };
            let Some(queued) = run.queue.pop_front() else {
                self.finish_ai_batch(true);
                return;
            };
            if run.steps >= run.limit {
                run.outcomes.push(outcome(
                    queued.summary,
                    queued.step.target(),
                    "not run",
                    "Step limit reached—send a message to continue".into(),
                ));
                run.queue.clear();
                self.finish_ai_batch(false);
                self.ai.panel.set_status("Step limit reached—send a message to continue".into());
                return;
            }
            run.steps += 1;
            if queued.implicit && !self.ai.data.config.allows(Feature::AutoTitle) {
                continue;
            }
            let level = match self.agent_authority(&queued.step) {
                Ok(level) => level,
                Err(error) => {
                    self.record_agent_failure(&queued, "not run", &error);
                    self.finish_ai_batch(false);
                    return;
                }
            };
            if let Some(reason) = self.agent_review_reason(level, &queued.step) {
                if let Err(error) = self.open_agent_review(queued, &reason) {
                    let queued = self.ai.agent.as_mut().and_then(|run| run.pending.take());
                    if let Some(queued) = queued {
                        self.record_agent_failure(&queued, "not run", &error);
                    }
                    self.finish_ai_batch(false);
                }
                return;
            }
            if !self.perform_agent_step(queued, "automatic").await {
                return;
            }
        }
    }

    /// `Some(reason)` when this action needs native approval at `level`. Full asks only for
    /// high-risk or unclassifiable input and for closing a session this chat did not open.
    fn agent_review_reason(&self, level: PermissionLevel, step: &Step) -> Option<String> {
        let assist = level < PermissionLevel::Full;
        let tracked = |target: &Target| self.ai.inputs.get(&target.id).cloned().unwrap_or_default();
        let risk = match step {
            Step::Read { .. } | Step::Draft { .. } => return None,
            Step::Run { session, command } => tracked(session).run(command),
            Step::Keys { session, keys } => tracked(session).keys(keys).0,
            Step::Close { session } => {
                let owned = self
                    .ai
                    .agent
                    .as_ref()
                    .is_some_and(|run| self.ai.owned.get(&session.id) == Some(&run.conversation));
                (!owned).then_some("Closing a session this chat did not open")
            }
            Step::Type { .. } | Step::Open { .. } | Step::Focus { .. } | Step::Rename { .. } | Step::Layout { .. } => None,
        };
        match risk {
            Some(reason) => Some(reason.to_owned()),
            None if assist => Some(ASSIST_REASON.to_owned()),
            None => None,
        }
    }

    fn open_agent_review(&mut self, queued: Queued, reason: &str) -> Result<()> {
        let run = self.ai.agent.as_ref().context("The run ended")?;
        let (generation, package, index) = (run.generation, run.package.clone(), usize::from(run.steps));
        let target = queued.step.target();
        let (title, payload, effect, kind) = match &queued.step {
            Step::Run { command, .. } => (
                "Run command",
                Some(command.clone()),
                format!("Types this exact text and presses Enter in {target}. {PTY_WARNING}"),
                ButtonKind::Danger,
            ),
            Step::Type { text, .. } => (
                "Type text",
                Some(text.clone()),
                format!("Types this exact text without Enter in {target}. {PTY_WARNING}"),
                ButtonKind::Danger,
            ),
            Step::Keys { keys, .. } => (
                "Send keys",
                Some(keys.iter().map(|key| key.name()).collect::<Vec<_>>().join(" ")),
                format!("Sends these keys in order to {target}. {PTY_WARNING}"),
                ButtonKind::Danger,
            ),
            Step::Close { .. } => (
                "Close session",
                None,
                format!("Disconnects {target}. Remote programs may stop unless they run in a multiplexer."),
                ButtonKind::Danger,
            ),
            Step::Open { .. } => (
                "Open saved server",
                None,
                format!("Connects to {target} in a new tab. Normal host-key and credential prompts still apply."),
                ButtonKind::Primary,
            ),
            Step::Focus { .. } => ("Focus session", None, format!("Shows {target}; your keyboard stays in Vyx AI."), ButtonKind::Primary),
            Step::Rename { title, .. } => (
                "Rename tab",
                Some(title.clone()),
                format!("Renames the tab of {target} for this session only. Saved servers are not renamed."),
                ButtonKind::Primary,
            ),
            Step::Layout { layout } => (
                "Change layout",
                Some(layout.label().to_owned()),
                "Changes the terminal layout and saves it as your preference.".into(),
                ButtonKind::Primary,
            ),
            Step::Read { .. } | Step::Draft { .. } => anyhow::bail!("this action never needs a separate approval"),
        };
        let session = queued
            .step
            .session()
            .map_or_else(String::new, |target| format!("Session UUID: {}\n", target.id));
        let content = format!(
            "Requested by the AI in this chat. Model text is not a security boundary.\nWhy approval is needed: {reason}\n{session}Target: {target}\n\n{effect}\n\nApprove performs only this action; it grants nothing to later actions. Cancel sends nothing and ends the run."
        );
        let mut review = ExtensionReview::new(
            title,
            content,
            if kind == ButtonKind::Danger { "Approve" } else { "Allow" },
        );
        review.form.submit_kind = kind;
        if let Some(payload) = payload {
            review = review.with_payload(payload);
        }
        let reviewed_input = queued
            .step
            .session()
            .map(|target| self.ai.inputs.get(&target.id).cloned().unwrap_or_default());
        if let Some(run) = self.ai.agent.as_mut() {
            run.pending = Some(queued);
            run.reviewed_input = reviewed_input;
        }
        let id = self.review_ai_with(
            review,
            Some(package),
            ReviewKind::Agent { generation, action_index: index },
        )?;
        if let Some(run) = self.ai.agent.as_mut() {
            run.wait = Wait::Review(id);
        }
        Ok(())
    }

    /// The user approved pending action `index` of run `generation`; it is consumed once.
    pub(super) async fn accept_agent_review(&mut self, generation: u64, index: usize) -> Result<String> {
        let run = self
            .ai
            .agent
            .as_mut()
            .filter(|run| run.generation == generation && usize::from(run.steps) == index)
            .context("The run this approval belonged to ended. Nothing was sent.")?;
        let queued = run.pending.take().context("This approval was already used. Nothing was sent.")?;
        let reviewed_input = run.reviewed_input.take();
        run.wait = Wait::Idle;
        let current_input = queued
            .step
            .session()
            .map(|target| self.ai.inputs.get(&target.id).cloned().unwrap_or_default());
        let checked = self.agent_authority(&queued.step).and_then(|_| {
            ensure!(current_input == reviewed_input, "the session's pending input changed after review");
            Ok(())
        });
        if let Err(error) = checked {
            let message = format!("Not performed: {}. Nothing was sent.", error_text(&error));
            self.record_agent_failure(&queued, "approved", &error);
            self.finish_ai_batch(false);
            return Ok(message);
        }
        let summary = queued.summary.clone();
        if self.perform_agent_step(queued, "approved").await {
            self.advance_ai_agent().await;
        }
        Ok(format!("Approved: {summary}"))
    }

    /// The user cancelled the pending action: nothing more runs and nothing follows up.
    pub(super) fn reject_agent_review(&mut self) {
        let Some(run) = self.ai.agent.as_mut() else {
            return;
        };
        if let Some(queued) = run.pending.take() {
            run.outcomes.push(outcome(queued.summary, queued.step.target(), "rejected", "Cancelled by you; nothing was sent".into()));
        }
        run.queue.clear();
        run.wait = Wait::Idle;
        self.finish_ai_batch(false);
    }

    /// The pending approval became invalid (authority, target, or workspace changed).
    pub(super) fn invalidate_agent_review(&mut self, reason: &str) {
        let Some(run) = self.ai.agent.as_mut() else {
            return;
        };
        if let Some(queued) = run.pending.take() {
            run.outcomes.push(outcome(queued.summary, queued.step.target(), "not run", format!("Not performed: {reason}")));
        }
        run.queue.clear();
        run.wait = Wait::Idle;
        self.finish_ai_batch(false);
    }

    /// Whether the pending action's authority still holds, for the review watchdog.
    pub(super) fn agent_review_valid(&self, generation: u64) -> Result<()> {
        let run = self
            .ai
            .agent
            .as_ref()
            .filter(|run| run.generation == generation)
            .context("its run ended")?;
        let queued = run.pending.as_ref().context("it was already used")?;
        self.agent_authority(&queued.step).map(|_| ())
    }

    fn record_agent_failure(&mut self, queued: &Queued, approval: &'static str, error: &anyhow::Error) {
        if let Some(run) = self.ai.agent.as_mut() {
            run.outcomes.push(outcome(
                queued.summary.clone(),
                queued.step.target(),
                approval,
                format!("Not performed: {}", error_text(error)),
            ));
            run.queue.clear();
        }
    }

    /// Performs one authorized action. Returns false when the run must stop advancing now:
    /// it is waiting, or the batch ended.
    async fn perform_agent_step(&mut self, queued: Queued, approval: &'static str) -> bool {
        let Queued { summary, step, implicit } = queued;
        let target = step.target();
        match self.agent_effect(step).await {
            Ok(Effect::Done(status, output)) => {
                if implicit {
                    self.ai.panel.set_status(status);
                } else if let Some(run) = self.ai.agent.as_mut() {
                    let captured_at = output.as_ref().map(|_| ai::now());
                    run.outcomes.push(Outcome { action: summary, target, approval, status, output, captured_at });
                }
                true
            }
            Ok(Effect::Wait(wait)) => {
                if let Some(run) = self.ai.agent.as_mut() {
                    run.current = Some(outcome(summary, target, approval, "in progress".into()));
                    run.wait = wait;
                }
                self.update_agent_ticker();
                false
            }
            Err(error) => {
                if let Some(run) = self.ai.agent.as_mut() {
                    run.outcomes.push(outcome(summary, target, approval, format!("Not performed: {}", error_text(&error))));
                    run.queue.clear();
                }
                self.finish_ai_batch(false);
                false
            }
        }
    }

    fn read_permitted(&self) -> bool {
        let config = &self.ai.data.config;
        self.ai
            .agent
            .as_ref()
            .and_then(|run| self.ai.conversation(run.conversation).ok())
            .is_some_and(|entry| config.grants(config.effective_permission(entry.permission), Capability::ReadOutput))
    }

    async fn agent_effect(&mut self, step: Step) -> Result<Effect> {
        let conversation = self.ai.agent.as_ref().context("the run ended")?.conversation;
        match step {
            Step::Read { session, lines } => {
                let live = self
                    .sessions
                    .iter()
                    .find(|entry| entry.id == session.id)
                    .context("the session closed")?;
                let text = ai::redact(&recent_output(live, lines));
                let shown = text.lines().count();
                Ok(Effect::Done(format!("Read the most recent {shown} line(s) of terminal output"), Some(text)))
            }
            Step::Run { session, command } => {
                contract::validate_terminal_command(&command)?;
                let enter = [KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)];
                self.submit_ai_input(session.id, &session.address, session.port, Some(&command), &enter)?;
                self.ai.inputs.insert(session.id, Tracked::Known(String::new()));
                Ok(Effect::Wait(self.output_wait(session.id, RUN_OUTPUT_LIMIT)))
            }
            Step::Type { session, text } => {
                contract::validate_terminal_command(&text)?;
                let next = self.ai.inputs.get(&session.id).cloned().unwrap_or_default().typed(&text);
                self.submit_ai_input(session.id, &session.address, session.port, Some(&text), &[])?;
                self.ai.inputs.insert(session.id, next);
                Ok(Effect::Wait(self.output_wait(session.id, INPUT_OUTPUT_LIMIT)))
            }
            Step::Keys { session, keys } => {
                let events: Vec<KeyEvent> = keys.iter().map(|key| key.event()).collect();
                let (_, next) = self.ai.inputs.get(&session.id).cloned().unwrap_or_default().keys(&keys);
                self.submit_ai_input(session.id, &session.address, session.port, None, &events)?;
                self.ai.inputs.insert(session.id, next);
                Ok(Effect::Wait(self.output_wait(session.id, INPUT_OUTPUT_LIMIT)))
            }
            Step::Open { host, label, .. } => {
                let scope = self.ai.conversation(conversation)?.sessions.len();
                ensure!(
                    scope < ai::MAX_SCOPE_SESSIONS,
                    "this chat already addresses {} sessions; remove one from its scope first",
                    ai::MAX_SCOPE_SESSIONS
                );
                ensure!(!self.store.is_uncertain(), "vault durability is uncertain; retry the save first");
                ensure!(
                    self.state.vault.hosts.iter().any(|saved| saved.id == host),
                    "saved server \"{}\" no longer exists",
                    contract::sanitize_display(&label)
                );
                let (focus, mode) = (self.focus, self.mode);
                self.connect_host(host, None)?;
                // `connect_prepared` appends the new session synchronously; capture it now.
                let session = self.sessions.last().map(|session| session.id).context("no session was created")?;
                self.focus = focus;
                self.mode = mode;
                self.restore_focused_mode();
                let entry = self.ai.conversation_mut(conversation)?;
                let mut scope = entry.sessions.clone();
                scope.push(session);
                entry.set_scope(scope);
                self.ai.touched(conversation);
                self.ai.owned.insert(session, conversation);
                Ok(Effect::Wait(Wait::Connection { session, started: Instant::now() }))
            }
            Step::Close { session } => {
                self.ai.agent_closing = Some(session.id);
                let result = self.close_session(session.id).await;
                self.ai.agent_closing = None;
                result?;
                Ok(Effect::Done("Closed the session; it left this chat's scope".into(), None))
            }
            Step::Focus { session } => {
                let index = self
                    .sessions
                    .iter()
                    .position(|entry| entry.id == session.id)
                    .context("the session closed")?;
                let (focus, mode) = (self.focus, self.mode);
                self.activate_session(index);
                self.focus = focus;
                self.mode = mode;
                self.restore_focused_mode();
                Ok(Effect::Done("Showed the session tab".into(), None))
            }
            Step::Rename { session, title } => {
                ensure!(
                    !self
                        .ai
                        .names
                        .get(&session.id)
                        .is_some_and(|name| matches!(name.naming, Naming::Manual | Naming::Paused)),
                    "the tab name is pinned; resume AI naming for it first"
                );
                self.apply_session_title(session.id, &title, Naming::Ai)?;
                let label = self
                    .sessions
                    .iter()
                    .find(|entry| entry.id == session.id)
                    .map(|entry| contract::sanitize_display(&entry.label))
                    .unwrap_or_default();
                Ok(Effect::Done(format!("Renamed the tab to \"{label}\" (local only)"), None))
            }
            Step::Layout { layout } => {
                if let Some(warning) = self.set_terminal_layout(layout)? {
                    self.notify_warning(warning);
                }
                Ok(Effect::Done(format!("Terminal layout is now {}", layout.label()), None))
            }
            Step::Draft { label, hostname, port, username } => {
                ensure!(self.dialog.is_none(), "another dialog is open");
                let host = Host {
                    id: Uuid::new_v4(),
                    label: label.clone(),
                    hostname,
                    port,
                    category_id: None,
                    transport: HostTransport::Direct,
                    auth: HostAuth::Password {
                        username: username.unwrap_or_default(),
                        password: Secret::new(""),
                    },
                };
                let id = host.id;
                let mut editor = Editor::host_draft(&self.state.vault, &host)?;
                editor.form.title = "Saved server draft from Vyx AI".into();
                editor.form.description = "Review every field and choose authentication yourself. Nothing is saved until you press Save, and saving never connects.".into();
                self.set_dialog(Dialog::Editor(editor));
                Ok(Effect::Wait(Wait::Draft { host: id, label, saved: false }))
            }
        }
    }

    fn output_wait(&self, session: Uuid, limit: Duration) -> Wait {
        let bytes = self
            .sessions
            .iter()
            .find(|entry| entry.id == session)
            .map_or(0, |entry| entry.view.lock().terminal.output_bytes());
        let now = Instant::now();
        Wait::Output { session, started: now, changed: now, bytes, limit }
    }

    /// Settles the run's timed wait, recording the in-progress action's result once done.
    fn settle_agent_wait(&mut self) -> Settled {
        let read = self.read_permitted();
        let Some(run) = self.ai.agent.as_mut() else {
            return Settled::Waiting;
        };
        let (status, output, failed) = match &mut run.wait {
            Wait::Idle => return Settled::Ready,
            Wait::Reply | Wait::Review(_) => return Settled::Waiting,
            Wait::Output { session, started, changed, bytes, limit } => {
                let now = Instant::now();
                let Some(live) = self.sessions.iter().find(|entry| entry.id == *session) else {
                    return finish_wait(run, "The session closed while waiting for output".into(), None, true);
                };
                let current = live.view.lock().terminal.output_bytes();
                if current != *bytes {
                    *bytes = current;
                    *changed = now;
                }
                let elapsed = now.duration_since(*started);
                let quiet = now.duration_since(*changed) >= QUIET && elapsed >= MIN_OUTPUT_WAIT;
                let timed_out = elapsed >= *limit;
                if !quiet && !timed_out {
                    return Settled::Waiting;
                }
                let mut status = if timed_out {
                    format!(
                        "Submitted; output was still changing after {} s, so the command may still be running. Recent terminal output; command completion and exit status are unknown.",
                        limit.as_secs()
                    )
                } else {
                    "Submitted; output was quiet for 1.5 s. Recent terminal output; command completion and exit status are unknown.".to_owned()
                };
                let output = if read {
                    Some(ai::redact(&recent_output(live, RESULT_LINES)))
                } else {
                    status.push_str(" Output is not shared because Share terminal output automatically is off.");
                    None
                };
                // Hitting the maximum ends the run instead of chaining another command.
                (status, output, timed_out)
            }
            Wait::Connection { session, started } => {
                let Some(live) = self.sessions.iter().find(|entry| entry.id == *session) else {
                    return finish_wait(run, "The new session was closed before it connected".into(), None, true);
                };
                let phase = live.view.lock().phase.clone();
                match phase {
                    SessionPhase::Connected => (
                        "Connected. The session joined this chat's scope and is addressable on the next turn.".into(),
                        None,
                        false,
                    ),
                    SessionPhase::Error(message) => (
                        format!("Connection failed: {}", contract::sanitize_display(&message)),
                        None,
                        true,
                    ),
                    SessionPhase::Closed { .. } => ("The connection closed before it was ready".into(), None, true),
                    SessionPhase::Connecting | SessionPhase::Authenticating if started.elapsed() < CONNECTION_LIMIT => {
                        return Settled::Waiting;
                    }
                    SessionPhase::Connecting | SessionPhase::Authenticating => (
                        "Still connecting after 120 s. Automation ended; the session stays open for you.".into(),
                        None,
                        true,
                    ),
                }
            }
            Wait::Draft { host, label, saved } => {
                let open = matches!(&self.dialog, Some(Dialog::Editor(editor)) if matches!(editor.target, EditorTarget::Host { id, .. } if id == *host));
                if open && !*saved {
                    return Settled::Waiting;
                }
                let label = contract::sanitize_display(label);
                if *saved {
                    (format!("You reviewed and saved \"{label}\"; nothing was connected"), None, false)
                } else {
                    if let Some(current) = run.current.as_mut() {
                        current.approval = "rejected";
                    }
                    (format!("You cancelled the draft \"{label}\"; nothing was saved"), None, true)
                }
            }
        };
        finish_wait(run, status, output, failed)
    }

    /// Records a successful saved-server mutation; the draft wait matches it by UUID.
    pub(in crate::app) fn ai_host_saved(&mut self, id: Uuid) {
        if let Some(Run { wait: Wait::Draft { host, saved, .. }, .. }) = self.ai.agent.as_mut()
            && *host == id
        {
            *saved = true;
        }
    }

    /// A batch finished or failed: records its results and, only after a fully successful
    /// batch, asks for the next reply while the chat stays open, authorized, and has room.
    fn finish_ai_batch(&mut self, follow: bool) {
        let Some(mut run) = self.ai.agent.take() else {
            return;
        };
        if let Some(ticker) = run.ticker.take() {
            ticker.abort();
        }
        let conversation = run.conversation;
        let outcomes = std::mem::take(&mut run.outcomes);
        if outcomes.is_empty() {
            // Only an implicit tab rename ran: it never asks for another reply.
            return;
        }
        let stored = self.append_ai_results(conversation, &outcomes);
        let exhausted = run.steps >= run.limit;
        let room = self
            .ai
            .conversation(conversation)
            .is_ok_and(|entry| entry.messages.len() + 2 <= ai::MAX_MESSAGES);
        if !follow {
            self.ai.panel.set_error("Actions stopped; the results are in the conversation. Send a message to continue.".into());
            return;
        }
        if !stored || !room {
            self.ai.panel.set_error("Results could not be added to this conversation; start another conversation to continue.".into());
            return;
        }
        if exhausted {
            self.ai.panel.set_status("Step limit reached—send a message to continue".into());
            return;
        }
        if !self.ai.panel.is_open() || self.ai.panel.selected() != Some(conversation) {
            return;
        }
        let package = run.package.clone();
        run.queue.clear();
        run.wait = Wait::Reply;
        self.ai.agent = Some(run);
        if let Err(error) = self.start_ai_reply(conversation, package, false) {
            self.ai.agent = None;
            self.ai.panel.set_error(format!("Follow-up not requested: {}", error_text(&error)));
        }
    }

    /// Manual typing, paste, mouse input, or other non-AI input into a session makes its
    /// pending input unknown and, when the run addresses that session, stops it first.
    pub(in crate::app) fn ai_user_input(&mut self, session: Uuid) {
        self.ai.inputs.remove(&session);
        let in_scope = self
            .ai
            .agent
            .as_ref()
            .and_then(|run| self.ai.conversation(run.conversation).ok())
            .is_some_and(|entry| entry.sessions.contains(&session));
        if in_scope {
            self.stop_ai_agent("Stopped because you used a session this chat was working in.");
        }
    }

    /// Ends automation without stopping an already-requested reply: switching chats or
    /// closing the panel may let that text finish, but it can no longer run anything.
    pub(super) fn end_ai_automation(&mut self, reason: &str) {
        if let Some(stream) = self.ai.stream.as_mut() {
            stream.control = None;
        }
        if let Some(run) = self.ai.agent.as_mut()
            && run.awaiting_reply()
        {
            run.wait = Wait::Idle;
        }
        self.stop_ai_agent(reason);
    }

    /// Revoking automatic output sharing withholds results not yet stored; text already
    /// sent stays in history.
    pub(super) fn withhold_agent_output(&mut self) {
        let Some(run) = self.ai.agent.as_mut() else {
            return;
        };
        for outcome in run.outcomes.iter_mut().chain(run.current.as_mut()) {
            if outcome.output.take().is_some() {
                outcome.captured_at = None;
                outcome
                    .status
                    .push_str(" Output withheld because automatic output sharing was turned off.");
            }
        }
    }
}

enum Effect {
    Done(String, Option<String>),
    Wait(Wait),
}

enum Settled {
    Ready,
    Waiting,
    Failed,
}

fn finish_wait(run: &mut Run, status: String, output: Option<String>, failed: bool) -> Settled {
    let mut finished = run.current.take().unwrap_or_else(|| outcome("Action".into(), String::new(), "automatic", String::new()));
    finished.status = status;
    finished.captured_at = output.as_ref().map(|_| ai::now());
    finished.output = output;
    run.outcomes.push(finished);
    run.wait = Wait::Idle;
    if failed {
        run.queue.clear();
        Settled::Failed
    } else {
        Settled::Ready
    }
}
