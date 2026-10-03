//! Native Vyx AI controller. The optional official `com.vyx.ai` package, or the unverified
//! `dev.vyx.ai` package explicitly loaded from a development path in this session, only
//! gates these host-owned capabilities. Guest code never receives credentials, history,
//! terminal context, or actions, and no extension runtime is needed for native AI.
use super::*;
use crate::{
    ai::{
        self, AiData, Attachment, Capability, Config, Conversation, Directive, Feature, Message,
        PermissionLevel, Profile, ProviderKind, Role, codex,
        actions::Tracked,
        providers::{self, ProviderEvent},
    },
    extensions::{contract, distribution::ReleaseSource, manager::Manager, registry::Entry},
    shortcuts::Bindings,
    ui::{
        actions::ExtensionReview,
        ai::{
            Action, AgentStatus, Addon, AiRender, CaptureKind, Check, Checks, Draft, HostInfo,
            Naming, Panel, SessionInfo, Tab, View,
        },
        widgets::ButtonKind,
    },
};
use crossterm::event::{KeyCode, KeyModifiers};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    future::Future,
    path::{Path, PathBuf},
};

mod agent;

pub(super) const OFFICIAL_ID: &str = "com.vyx.ai";
pub(super) const DEVELOPMENT_ID: &str = "dev.vyx.ai";
const CHAT_COMMAND: &str = "chat";
const SETTINGS_COMMAND: &str = "settings";
const EVENT_CAPACITY: usize = 64;
const PROVIDER_EVENTS: usize = 32;
const MAX_TITLE_REPLY_BYTES: usize = 4096;
const SCROLLBACK_LINES: usize = 400;
const MAX_STATUS_CHARS: usize = 4096;
const FULL_CONTROL: &str = "AI may read shared terminal output, run commands, send keys, and manage sessions without asking each time. Terminal text can mislead the AI. High-risk detection is best effort, not a sandbox. Use Full control only on servers you intend to administer.";
const STOPPED: &str = "[Reply stopped before completion]";
const FAILED: &str = "[Reply incomplete: the provider reported an error]";
const TOO_LONG: &str = "[Reply stopped: size limit reached]";
// Leave room for an incomplete-reply marker inside the stored message limit.
const MAX_REPLY_BYTES: usize = ai::MAX_MESSAGE_BYTES - 128;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Package {
    id: String,
    digest: String,
}

/// Recognize installed native settings separately from reviewed request authority.
/// A local development package remains configurable after its workspace activation ends.
pub(super) fn native_entry(manager: &Manager, entry: &Entry) -> Option<Addon> {
    if !(entry.manifest.declares_command(CHAT_COMMAND)
        && entry.manifest.declares_command(SETTINGS_COMMAND))
    {
        return None;
    }
    if entry.id == OFFICIAL_ID
        && entry
            .source
            .as_ref()
            .is_some_and(ReleaseSource::is_official)
    {
        return Some(Addon::Official);
    }
    if entry.id == DEVELOPMENT_ID && entry.source.is_none() {
        return Some(if manager
            .development
            .get(&entry.id)
            .is_some_and(|development| development.digest == entry.digest)
        {
            Addon::Development
        } else {
            Addon::DevelopmentInactive
        });
    }
    None
}

/// Reserved native identities must never fall back to downloading or running a guest.
pub(super) fn check_native_entry(manager: &Manager, entry: &Entry) -> Result<bool> {
    if matches!(native_entry(manager, entry), Some(Addon::Official | Addon::Development)) {
        return Ok(true);
    }
    match entry.id.as_str() {
        DEVELOPMENT_ID if entry.development_path.is_some() => anyhow::bail!(
            "The remembered dev.vyx.ai package changed or is unavailable. Review it again with Load development package in Settings / Extensions. Matching reviewed bytes are remembered across restarts; trusted rebuilds last only for this session. Vyx AI does not need the sandbox worker."
        ),
        DEVELOPMENT_ID => anyhow::bail!(
            "Vyx AI needs a reviewed development package. Use Settings / Extensions / Load development package, select dev.vyx.ai.vyxext, approve it, then Review and enable. The reviewed path and digest are remembered across restarts; trusted rebuilds last only for this session, and a changed or missing file needs review again. Vyx AI does not need the sandbox worker."
        ),
        OFFICIAL_ID => anyhow::bail!(
            "Vyx AI requires a reviewed official-release package with native chat and settings commands. For a local build, use Load development package with dev.vyx.ai.vyxext instead. Vyx AI does not need the sandbox worker."
        ),
        _ => Ok(false),
    }
}

/// Enabled, reviewed packages win over configuration-only entries; official wins ties.
/// Inactive development packages and a registry awaiting Retry grant no request authority.
fn native_package(manager: &Manager) -> (Addon, Option<Package>) {
    let blocked = manager.registry.is_blocked();
    let best = manager
        .registry
        .entries()
        .iter()
        .filter_map(|entry| native_entry(manager, entry).map(|addon| (entry, addon)))
        .max_by_key(|(entry, addon)| (entry.enabled && !blocked && *addon != Addon::DevelopmentInactive, *addon == Addon::Official));
    match best {
        None => (Addon::Missing, None),
        Some((entry, _)) if !entry.enabled || blocked => (Addon::Disabled, None),
        Some((_, Addon::DevelopmentInactive)) => (Addon::DevelopmentInactive, None),
        Some((entry, addon)) => (
            addon,
            Some(Package {
                id: entry.id.clone(),
                digest: entry.digest.clone(),
            }),
        ),
    }
}

pub(super) struct State {
    panel: Panel,
    data: AiData,
    data_dir: PathBuf,
    sender: mpsc::Sender<Event>,
    pub(super) receiver: mpsc::Receiver<Event>,
    generation: u64,
    stream: Option<Stream>,
    task: Option<Task>,
    captures: HashMap<u64, Capture>,
    next_token: u64,
    review: Option<Review>,
    names: HashMap<Uuid, Name>,
    suggestions: BTreeMap<Uuid, String>,
    models: BTreeMap<Uuid, Vec<String>>,
    checks: Checks,
    /// Installed-helper metadata by Codex profile, refreshed outside drawing.
    helpers: BTreeMap<Uuid, bool>,
    agent: Option<agent::Run>,
    /// Runtime only: sessions an AI run opened, with the chat that opened each.
    owned: HashMap<Uuid, Uuid>,
    /// Runtime only: tracked pending input per session; absent means unknown.
    inputs: HashMap<Uuid, Tracked>,
    /// The session a run is closing itself, whose removal is expected.
    agent_closing: Option<Uuid>,
    /// Level and scope of the chat shown before its first message.
    unsent: Option<Unsent>,
    clipboard: Option<String>,
    save: bool,
    save_failed: bool,
    package: Option<Package>,
}

struct Unsent {
    permission: PermissionLevel,
    sessions: Vec<Uuid>,
}

pub(super) struct Event {
    generation: u64,
    kind: EventKind,
}

enum EventKind {
    Provider(ProviderEvent),
    Finished(Result<(), String>),
    Task(Result<Output, String>),
    /// Generation-tagged progress check while a run waits.
    AgentTick,
}

enum Output {
    Text(String),
    Models(Vec<String>),
}

struct Stream {
    generation: u64,
    conversation: Uuid,
    message: Uuid,
    package: Package,
    profile: String,
    profile_id: Uuid,
    handle: tokio::task::JoinHandle<()>,
    /// A run's authority snapshot for this request; `None` means the reply may run nothing.
    control: Option<agent::Control>,
}

impl Drop for Stream {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

#[derive(Clone, Copy)]
enum TaskKind {
    Test(Uuid),
    Models(Uuid),
    CodexInstall(Uuid),
    CodexLogin(Uuid),
    CodexStatus(Uuid),
    Title {
        conversation: Uuid,
        session: Uuid,
        profile: Uuid,
    },
}

impl TaskKind {
    /// The profile check this task performs; title requests are not checks.
    fn check(self) -> Option<(Uuid, Check)> {
        match self {
            Self::Test(id) => Some((id, Check::Test)),
            Self::Models(id) => Some((id, Check::Models)),
            Self::CodexInstall(id) => Some((id, Check::Install)),
            Self::CodexLogin(id) => Some((id, Check::SignIn)),
            Self::CodexStatus(id) => Some((id, Check::Account)),
            Self::Title { .. } => None,
        }
    }
}

struct Task {
    generation: u64,
    label: String,
    kind: TaskKind,
    package: Package,
    handle: tokio::task::JoinHandle<()>,
}

impl Drop for Task {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

/// App-issued attachment token. Drafts are valid only while their capture remains here.
struct Capture {
    session_id: Uuid,
    address: String,
    port: u16,
    source: String,
    captured_at: u64,
}

struct Name {
    original: String,
    naming: Naming,
}

struct Review {
    /// The dialog's identity; continuations match it, never its title or text.
    id: Uuid,
    package: Option<Package>,
    kind: ReviewKind,
}

/// Consent is bound to validated routing, never to a shortened UI label.
#[derive(Clone, PartialEq, Eq)]
struct RoutingIdentity {
    kind: ProviderKind,
    api_style: ai::ApiStyle,
    endpoint: Option<String>,
}

impl RoutingIdentity {
    fn from_profile(profile: &Profile) -> Result<Self> {
        profile.validate()?;
        Ok(Self {
            kind: profile.kind,
            api_style: profile.api_style,
            endpoint: if profile.base_url.is_empty() {
                None
            } else {
                Some(profile.endpoint("")?.to_string())
            },
        })
    }

    fn description(&self) -> String {
        format!(
            "{} · {} · {}",
            self.kind.label(),
            self.api_style.label(),
            self.endpoint
                .as_deref()
                .unwrap_or("No HTTP endpoint configured")
        )
    }
}

enum ReviewKind {
    Command {
        execute: bool,
        session_id: Uuid,
        address: String,
        port: u16,
        command: String,
    },
    Connect {
        host_id: Uuid,
        vault_snapshot: Uuid,
    },
    Switch {
        conversation: Uuid,
        profile: Uuid,
        recipient: RoutingIdentity,
        model: String,
    },
    Profile {
        profile: Box<Profile>,
        previous: RoutingIdentity,
        discover: bool,
    },
    Export {
        conversation: Uuid,
        path: PathBuf,
        updated_at: u64,
    },
    Delete(Uuid),
    DeleteAll,
    DeleteProfile(Uuid),
    CodexLogin {
        generation: u64,
        url: crate::vault::Secret,
    },
    InstallCodex(Uuid),
    /// The complete validated configuration a Full-control consent would apply.
    AllowFull(Box<Config>),
    /// The pending action of run `generation`, kept exactly in the run.
    Agent {
        generation: u64,
        action_index: usize,
    },
}

impl ReviewKind {
    fn conversation(&self) -> Option<Uuid> {
        match self {
            Self::Switch { conversation, .. }
            | Self::Export { conversation, .. }
            | Self::Delete(conversation) => Some(*conversation),
            _ => None,
        }
    }
}

impl State {
    pub(super) fn new(data: &AiData, data_dir: &Path) -> Self {
        let (sender, receiver) = mpsc::channel(EVENT_CAPACITY);
        let mut data = data.clone();
        data.normalize();
        let save = !data.prune_history(ai::now()).is_empty();
        // Session UUIDs never survive a restart: stored scope is stale and grants nothing.
        for conversation in &mut data.conversations {
            conversation.sessions.clear();
        }
        Self {
            panel: Panel::new(),
            data,
            data_dir: data_dir.to_owned(),
            sender,
            receiver,
            generation: 0,
            stream: None,
            task: None,
            captures: HashMap::new(),
            next_token: 1,
            review: None,
            names: HashMap::new(),
            suggestions: BTreeMap::new(),
            models: BTreeMap::new(),
            checks: BTreeMap::new(),
            helpers: BTreeMap::new(),
            agent: None,
            owned: HashMap::new(),
            inputs: HashMap::new(),
            agent_closing: None,
            unsent: None,
            clipboard: None,
            save,
            save_failed: false,
            package: None,
        }
    }

    pub(super) fn render<'a>(
        &'a mut self,
        addon: Addon,
        focused: bool,
        sessions: &'a [SessionInfo],
        hosts: &'a [HostInfo],
    ) -> AiRender<'a> {
        let agent = self.agent.as_ref().map(agent::Run::status);
        let Self {
            panel,
            data,
            stream,
            task,
            models,
            checks,
            suggestions,
            helpers,
            unsent,
            ..
        } = self;
        let (unsent_permission, unsent_sessions) = unsent
            .as_ref()
            .map_or((PermissionLevel::ChatOnly, &[][..]), |unsent| {
                (unsent.permission, unsent.sessions.as_slice())
            });
        AiRender {
            panel,
            view: View {
                data,
                addon,
                focused,
                streaming: stream.as_ref().map(|stream| stream.conversation),
                task: task.as_ref().map(|task| task.label.as_str()),
                sessions,
                hosts,
                models,
                checks,
                suggestions,
                helpers,
                agent,
                unsent_permission,
                unsent_sessions,
            },
        }
    }

    pub(super) fn is_open(&self) -> bool {
        self.panel.is_open()
    }
    pub(super) fn needs_save_retry(&self) -> bool {
        self.save_failed
    }

    fn next_generation(&mut self) -> u64 {
        self.generation = self.generation.wrapping_add(1);
        self.generation
    }

    fn conversation(&self, id: Uuid) -> Result<&Conversation> {
        self.data
            .conversations
            .iter()
            .find(|conversation| conversation.id == id)
            .context("The conversation no longer exists")
    }

    fn conversation_mut(&mut self, id: Uuid) -> Result<&mut Conversation> {
        self.data
            .conversations
            .iter_mut()
            .find(|conversation| conversation.id == id)
            .context("The conversation no longer exists")
    }

    fn profile(&self, id: Uuid) -> Result<&Profile> {
        self.data
            .profiles
            .iter()
            .find(|profile| profile.id == id)
            .context("The provider profile no longer exists")
    }

    /// Records a retained-history change; temporary conversations never schedule a save.
    fn touched(&mut self, conversation: Uuid) {
        if self
            .conversation(conversation)
            .is_ok_and(|conversation| !conversation.temporary)
        {
            self.save = true;
        }
    }

    fn clear_drafts(&mut self, mut keep: impl FnMut(&Capture) -> bool) {
        self.captures.retain(|_, capture| keep(capture));
        let captures = &self.captures;
        self.panel
            .retain_attachments(|draft| captures.contains_key(&draft.token));
    }

    /// Only the explicitly chosen default; there is deliberately no fallback provider.
    fn default_profile(&self) -> Option<&Profile> {
        self.data.default_profile()
    }

    fn budget_notice(&self, conversation: Uuid) -> Option<String> {
        let used = self.conversation(conversation).ok()?.usage().total_tokens();
        self.data.config.budget_warning(used).map(|warning| format!("{warning}, counting only usage the provider reported. Subscription quotas are separate from API costs, and stopping a reply does not reverse charges already incurred."))
    }
}

/// Retained history only: temporary chats and the in-flight partial reply never persist.
fn persisted(data: &AiData, in_flight: Option<(Uuid, Uuid)>) -> AiData {
    let mut data = data.clone();
    data.conversations
        .retain(|conversation| !conversation.temporary);
    if let Some((conversation, message)) = in_flight
        && let Some(conversation) = data
            .conversations
            .iter_mut()
            .find(|entry| entry.id == conversation)
    {
        conversation.messages.retain(|entry| entry.id != message);
    }
    data
}

fn bidi_control(c: char) -> bool {
    matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

/// Multi-line display text without terminal controls, bounded in characters.
fn display(text: &str, max_chars: usize) -> String {
    text.chars()
        .filter(|c| matches!(c, '\n' | '\t') || !(c.is_control() || bidi_control(*c)))
        .take(max_chars)
        .collect()
}

fn error_text(error: &anyhow::Error) -> String {
    display(&format!("{error:#}"), MAX_STATUS_CHARS)
}

fn trim_lines(text: &str) -> String {
    let lines: Vec<&str> = text.lines().map(str::trim_end).collect();
    let end = lines
        .iter()
        .rposition(|line| !line.is_empty())
        .map_or(0, |index| index + 1);
    lines[..end].join("\n")
}

/// Most recent `max_lines` rows, oldest first: scrollback followed by the live screen.
fn screen_lines(mut screen: vt100::Screen, max_lines: usize) -> String {
    let (rows, columns) = screen.size();
    let visible = usize::from(rows).max(1);
    screen.set_scrollback(usize::MAX);
    let history = screen.scrollback().min(max_lines.saturating_sub(visible));
    let mut lines = Vec::with_capacity(history + visible);
    let mut offset = history;
    while offset > 0 {
        screen.set_scrollback(offset);
        let take = offset.min(visible);
        lines.extend(screen.rows(0, columns).take(take));
        offset -= take;
    }
    screen.set_scrollback(0);
    lines.extend(screen.rows(0, columns));
    let skip = lines.len().saturating_sub(max_lines.max(visible));
    trim_lines(&lines[skip..].join("\n"))
}

fn visible_screen(session: &Session) -> String {
    let contents = session.view.lock().terminal.screen().contents();
    trim_lines(&contents)
}

fn recent_output(session: &Session, max_lines: usize) -> String {
    let screen = session.view.lock().terminal.screen().clone();
    screen_lines(screen, max_lines)
}

/// Only the catalog-approved metadata: never usernames, credentials, keys, or agent handles.
fn metadata_text(session: &Session) -> String {
    let phase = session.view.lock().phase.label();
    let routing = match session.destination.transport {
        crate::vault::HostTransport::Direct => "Direct SSH",
        crate::vault::HostTransport::Tailscale => "Tailscale",
    };
    let authentication = match &session.destination.auth {
        crate::ssh::ReconnectAuth::Credential(_) => "Saved credential",
        crate::ssh::ReconnectAuth::Password { .. } => "Server password",
        crate::ssh::ReconnectAuth::Tailscale { .. } => "Tailscale SSH",
    };
    format!(
        "Session label: {}\nServer address: {}\nPort: {}\nRouting: {routing}\nConnection phase: {phase}\nAuthentication mode: {authentication}",
        contract::sanitize_display(&session.label),
        contract::sanitize_display(&session.destination.address),
        session.destination.port
    )
}

async fn run_stream(generation: u64, request: providers::Request, output: mpsc::Sender<Event>) {
    let (sender, mut receiver) = mpsc::channel(PROVIDER_EVENTS);
    let request = providers::stream(request, sender);
    tokio::pin!(request);
    let mut finished = None;
    loop {
        tokio::select! {
            event = receiver.recv() => match event {
                Some(event) => if output.send(Event { generation, kind: EventKind::Provider(event) }).await.is_err() { return; },
                None => break,
            },
            result = &mut request, if finished.is_none() => finished = Some(result),
        }
    }
    let result = match finished {
        Some(result) => result,
        None => request.await,
    };
    let _ = output
        .send(Event {
            generation,
            kind: EventKind::Finished(result.map_err(|error| error_text(&error))),
        })
        .await;
}

/// Collects title text locally while forwarding native credential updates.
async fn collect_title(
    request: providers::Request,
    output: mpsc::Sender<ProviderEvent>,
) -> Result<Output> {
    let (sender, mut receiver) = mpsc::channel(PROVIDER_EVENTS);
    let collect = async move {
        let mut text = String::new();
        while let Some(event) = receiver.recv().await {
            if let ProviderEvent::Delta(delta) = event {
                let mut end = delta
                    .len()
                    .min(MAX_TITLE_REPLY_BYTES.saturating_sub(text.len()));
                while !delta.is_char_boundary(end) {
                    end -= 1;
                }
                text.push_str(&delta[..end]);
            } else if let ProviderEvent::CodexAuth(credentials) = event {
                let _ = output.send(ProviderEvent::CodexAuth(credentials)).await;
            }
        }
        text
    };
    let (result, text) = tokio::join!(providers::stream(request, sender), collect);
    result?;
    Ok(Output::Text(text))
}
fn history_preview(conversation: &Conversation, limit: usize) -> String {
    let start = ai::context_start(&conversation.messages, limit);
    let mut preview = String::new();
    if start > 0 {
        preview.push_str(&format!("[{start} older message(s) exceed the {limit}-character context limit and are not sent]\n\n"));
    }
    for message in &conversation.messages[start..] {
        preview.push_str(&format!(
            "{} · {}\n{}\n\n",
            message.role.label(),
            ai::format_timestamp(message.created_at),
            message.text
        ));
    }
    preview
}

impl App {
    pub(super) fn ai_addon(&self) -> (Addon, Option<Package>) {
        // Registry identity and digest, not a manifest-supplied display name, grant access.
        self.extensions
            .as_ref()
            .map_or((Addon::Missing, None), native_package)
    }

    /// Configuration and local history need an installed package (enabled or not).
    fn ai_installed(&self) -> Result<()> {
        ensure!(
            self.ai_addon().0 != Addon::Missing,
            "Vyx AI is not installed. Install the official Vyx AI extension from Settings / Extensions."
        );
        Ok(())
    }

    fn ai_local(&self, feature: Feature) -> Result<()> {
        self.ai_ready(Some(feature)).map(|_| ())
    }

    /// Provider requests, terminal reads and actions need the enabled package, the master
    /// switch and (optionally) one feature. Every call rechecks the registry binding.
    fn ai_ready(&self, feature: Option<Feature>) -> Result<Package> {
        let (addon, package) = self.ai_addon();
        let package = package.with_context(|| match addon {
            Addon::Missing => "Vyx AI is not installed. Install the official Vyx AI extension from Settings / Extensions.",
            Addon::DevelopmentInactive => "Load the development package once to activate Vyx AI: Settings / Extensions / Vyx AI / Load development package. Vyx remembers that review across restarts and asks again only if the file changes or moves. Local settings remain available; no AI request was sent.",
            _ => "The Vyx AI extension is disabled. Enable it in Settings / Extensions; nothing is sent while it is disabled.",
        })?;
        ensure!(self.attached, "The workspace is detached");
        ensure!(
            self.ai.data.config.enabled,
            "Vyx AI is turned off. Turn it on in Vyx AI settings."
        );
        if let Some(feature) = feature {
            ensure!(
                self.ai.data.config.allows(feature),
                "{} is turned off in Vyx AI settings",
                feature.label()
            );
        }
        Ok(package)
    }

    fn ai_profile_for(&self, conversation: &Conversation) -> Result<Profile> {
        let id = conversation
            .profile_id
            .context("Choose a provider for this conversation first")?;
        let mut profile = self.ai.profile(id)
            .context("This conversation's provider profile was deleted. Switch provider (reviewed) before sending.")?
            .clone();
        if !conversation.model.trim().is_empty() {
            profile.model = conversation.model.clone();
        }
        profile.ready()?;
        Ok(profile)
    }

    pub(super) fn ai_sessions(&self) -> Vec<SessionInfo> {
        self.sessions
            .iter()
            .map(|session| {
                let phase = session.view.lock().phase.clone();
                SessionInfo {
                    id: session.id,
                    label: session.label.clone(),
                    server: format!(
                        "{}:{}",
                        session.destination.address, session.destination.port
                    ),
                    connected: phase == SessionPhase::Connected,
                    phase: phase.label(),
                    naming: self
                        .ai
                        .names
                        .get(&session.id)
                        .map_or(Naming::Original, |name| name.naming),
                }
            })
            .collect()
    }

    pub(super) fn ai_hosts(&self) -> Vec<HostInfo> {
        self.state
            .vault
            .hosts
            .iter()
            .map(|host| HostInfo {
                id: host.id,
                label: host.label.clone(),
                address: host.hostname.clone(),
                port: host.port,
            })
            .collect()
    }

    fn ai_input(&mut self, input: impl FnOnce(&mut Panel, &View, &Bindings) -> Action) -> Action {
        self.prepare_ai_unsent();
        let (addon, _) = self.ai_addon();
        let sessions = self.ai_sessions();
        let hosts = self.ai_hosts();
        let focused = self.focus == Focus::Ai;
        let bindings = &self.settings.bindings;
        let AiRender { panel, view } = self.ai.render(addon, focused, &sessions, &hosts);
        input(panel, &view, bindings)
    }

    pub(super) async fn handle_ai_key(&mut self, key: KeyEvent) -> Result<()> {
        if !self.ai.panel.is_open() {
            self.leave_ai_focus();
            return Ok(());
        }
        let action = self.ai_input(|panel, view, bindings| panel.key(key, bindings, view));
        self.handle_ai_action(action).await;
        Ok(())
    }

    pub(super) async fn handle_ai_paste(&mut self, text: &str) {
        if !self.ai.panel.is_open() {
            return;
        }
        let action = self.ai_input(|panel, view, _| panel.paste(text, view));
        self.handle_ai_action(action).await;
    }

    /// Routes a pointer event to the chat panel. Presses inside the panel focus it;
    /// wheel events never move focus.
    pub(super) async fn handle_ai_mouse(&mut self, mouse: MouseEvent) {
        if !self.ai.panel.is_open() {
            return;
        }
        if matches!(mouse.kind, MouseEventKind::Down(_)) && self.focus != Focus::Ai {
            self.focus = Focus::Ai;
            self.restore_focused_mode();
        }
        let action = self.ai_input(|panel, view, _| panel.mouse(mouse, view));
        self.handle_ai_action(action).await;
    }

    pub(super) fn ai_mouse_inside(&self, mouse: &MouseEvent) -> bool {
        self.ai.panel.is_open()
            && self
                .render
                .ai
                .is_some_and(|area| contains(area, mouse.column, mouse.row))
    }
    pub(super) fn launch_ai(&mut self, id: &str, digest: &str, command: &str) -> Result<()> {
        let manager = self.extensions.as_ref().context("Extensions unavailable")?;
        let entry = manager
            .registry
            .entries()
            .iter()
            .find(|entry| entry.id == id && entry.digest == digest)
            .context("The Vyx AI package changed; reopen the extension picker")?;
        if command == SETTINGS_COMMAND && native_entry(manager, entry).is_some() {
            self.open_ai(Tab::Settings);
            return Ok(());
        }
        ensure!(
            !manager.registry.is_blocked(),
            "The extension registry needs Retry before activation"
        );
        let native = check_native_entry(manager, entry)?;
        ensure!(
            entry.enabled && native,
            "The native Vyx AI package is not enabled"
        );
        let tab = match command {
            CHAT_COMMAND => Tab::Chat,
            SETTINGS_COMMAND => Tab::Settings,
            _ => anyhow::bail!("This package command has no native Vyx AI implementation"),
        };
        self.open_ai(tab);
        Ok(())
    }

    pub(super) fn open_ai(&mut self, tab: Tab) {
        if self.ai_addon().0 == Addon::Missing {
            self.set_dialog(message("Vyx AI is not installed", "Install the official Vyx AI extension from Settings / Extensions to use native AI chat. Core Vyx works without it."));
            return;
        }
        self.close_prefix();
        self.close_extensions();
        self.menu = None;
        if self.search.is_some() {
            self.finish_search(false);
        }
        self.mouse_capture = None;
        self.last_click = None;
        self.ai.panel.open(tab);
        self.refresh_ai_helpers();
        self.focus = Focus::Ai;
        self.restore_focused_mode();
        self.mark_dirty();
    }

    /// Closing never touches SSH sessions. It stops the active reply unless background
    /// replies are allowed, and always discards temporary conversations.
    pub(super) fn close_ai(&mut self) {
        if self.ai.stream.is_some() && !self.ai.data.config.allows(Feature::BackgroundReply) {
            self.stop_ai_stream(STOPPED);
            self.ai
                .panel
                .set_status("Reply stopped because the chat panel closed.".into());
        }
        // Closing always ends automation; a background reply may only finish its text.
        self.end_ai_automation("Stopped because the chat panel closed.");
        self.ai.task = None;
        self.ai.clear_drafts(|_| false);
        self.cancel_ai_review(None);
        self.discard_temporary_ai(None);
        self.ai.unsent = None;
        self.ai.panel.close();
        self.leave_ai_focus();
    }

    fn leave_ai_focus(&mut self) {
        if self.focus == Focus::Ai {
            self.focus = if self
                .active_session
                .is_some_and(|index| index < self.sessions.len())
            {
                Focus::Terminal
            } else {
                Focus::Sidebar
            };
            self.restore_focused_mode();
        }
        self.mark_dirty();
    }

    pub(super) fn toggle_ai(&mut self) {
        if self.ai.panel.is_open() && self.focus == Focus::Ai {
            self.close_ai();
        } else {
            self.open_ai(Tab::Chat);
        }
    }

    pub(super) fn focus_ai(&mut self) {
        if !self.ai.panel.is_open() {
            self.open_ai(Tab::Chat);
        } else if self.focus == Focus::Ai {
            self.leave_ai_focus();
        } else {
            self.focus = Focus::Ai;
            self.restore_focused_mode();
            self.mark_dirty();
        }
    }

    /// Recomputes the registry binding. Any change of package, digest, enablement, master
    /// switch or attachment stops in-flight work and invalidates reviews and drafts.
    pub(super) fn revalidate_ai(&mut self) {
        let (addon, package) = self.ai_addon();
        let usable = package.is_some() && self.ai.data.config.enabled && self.attached;
        let changed = package != self.ai.package;
        let active = self.ai.stream.is_some()
            || self.ai.task.is_some()
            || self.ai.agent.is_some()
            || self
                .ai
                .review
                .as_ref()
                .is_some_and(|review| review.package.is_some())
            || !self.ai.captures.is_empty();
        if changed || (!usable && active) {
            self.halt_ai((changed && self.ai.package.is_some())
                .then_some("Vyx AI stopped because its extension package was disabled, removed, or changed. Nothing further was sent."));
            if changed && self.ai.package.is_some() {
                self.discard_temporary_ai(None);
                self.ai.panel.reset();
                self.leave_ai_focus();
            }
        }
        self.ai.package = package;
        if addon == Addon::Missing && self.ai.panel.is_open() {
            self.discard_temporary_ai(None);
            self.ai.panel.reset();
            self.ai.panel.close();
            self.leave_ai_focus();
        }
    }

    fn halt_ai(&mut self, reason: Option<&str>) {
        let busy = self.ai.stream.is_some()
            || self.ai.task.is_some()
            || self.ai.agent.is_some()
            || self.ai.review.is_some()
            || !self.ai.captures.is_empty();
        self.stop_ai_agent(reason.unwrap_or(
            "Stopped because Vyx AI became unavailable (turned off, locked, or detached).",
        ));
        self.stop_ai_stream(STOPPED);
        self.ai.task = None;
        self.cancel_ai_review(None);
        self.ai.clear_drafts(|_| false);
        self.ai.suggestions.clear();
        self.ai.clipboard = None;
        if busy && let Some(reason) = reason {
            self.ai.panel.set_error(reason.into());
        }
        self.mark_dirty();
    }

    /// Lock and detach cancel everything, including permitted background replies.
    pub(super) fn suspend_ai(&mut self) {
        self.halt_ai(None);
        self.discard_temporary_ai(None);
        self.ai.unsent = None;
        self.ai.panel.reset();
        self.ai.panel.close();
        if self.focus == Focus::Ai {
            self.focus = if self
                .active_session
                .is_some_and(|index| index < self.sessions.len())
            {
                Focus::Terminal
            } else {
                Focus::Sidebar
            };
            if !matches!(self.mode, InputMode::Prefix { .. }) {
                self.restore_focused_mode();
            }
        }
    }

    pub(super) async fn shutdown_ai(&mut self) -> Result<()> {
        self.stop_ai_agent("Stopped because Vyx is shutting down.");
        self.stop_ai_stream(STOPPED);
        self.ai.task = None;
        self.ai.review = None;
        self.ai.captures.clear();
        self.discard_temporary_ai(None);
        if self.ai.save || self.ai.save_failed {
            self.save_ai().await;
        }
        ensure!(
            !self.ai.save_failed,
            "Vyx AI changes could not be saved before shutdown"
        );
        Ok(())
    }

    /// Stops the reply task and marks retained partial text as incomplete.
    fn stop_ai_stream(&mut self, marker: &str) {
        let Some(stream) = self.ai.stream.take() else {
            return;
        };
        if self.ai.agent.as_ref().is_some_and(agent::Run::awaiting_reply) {
            // A run cannot continue without its reply; its earlier results are already stored.
            self.ai.agent = None;
        }
        let (conversation, message) = (stream.conversation, stream.message);
        drop(stream);
        if let Ok(entry) = self.ai.conversation_mut(conversation) {
            if let Some(index) = entry.messages.iter().position(|entry| entry.id == message) {
                if entry.messages[index].text.trim().is_empty() {
                    entry.messages.remove(index);
                } else {
                    entry.messages[index].text.push_str("\n\n");
                    entry.messages[index].text.push_str(marker);
                }
            }
            entry.updated_at = ai::now();
        }
        self.ai.touched(conversation);
        self.mark_dirty();
    }

    /// Temporary conversations live only while selected in an open panel.
    fn discard_temporary_ai(&mut self, keep: Option<Uuid>) -> usize {
        let discarded: Vec<Uuid> = self
            .ai
            .data
            .conversations
            .iter()
            .filter(|conversation| conversation.temporary && Some(conversation.id) != keep)
            .map(|conversation| conversation.id)
            .collect();
        if discarded.is_empty() {
            return 0;
        }
        if self
            .ai
            .agent
            .as_ref()
            .is_some_and(|run| discarded.contains(&run.conversation))
        {
            self.stop_ai_agent("Stopped because the temporary chat was discarded.");
        }
        if self
            .ai
            .stream
            .as_ref()
            .is_some_and(|stream| discarded.contains(&stream.conversation))
        {
            self.ai.stream = None;
        }
        if matches!(self.ai.task.as_ref().map(|task| task.kind), Some(TaskKind::Title { conversation, .. }) if discarded.contains(&conversation))
        {
            self.ai.task = None;
        }
        if self
            .ai
            .review
            .as_ref()
            .and_then(|review| review.kind.conversation())
            .is_some_and(|id| discarded.contains(&id))
        {
            self.cancel_ai_review(None);
        }
        self.ai
            .data
            .conversations
            .retain(|conversation| !discarded.contains(&conversation.id));
        if self
            .ai
            .panel
            .selected()
            .is_some_and(|id| discarded.contains(&id))
        {
            self.ai.panel.select(None);
        }
        discarded.len()
    }

    /// Reviews match by identity, never by their (re-renderable) title or text.
    pub(super) fn ai_review_matches(&self, review: &ExtensionReview) -> bool {
        self.ai
            .review
            .as_ref()
            .is_some_and(|pending| pending.id == review.id)
    }

    fn ai_dialog_is_review(&self, dialog: &Option<Dialog>) -> bool {
        matches!(dialog, Some(Dialog::ExtensionReview(review)) if self.ai_review_matches(review))
    }

    fn stop_reviewed_codex_login(&mut self) -> bool {
        let Some(ReviewKind::CodexLogin { generation, .. }) =
            self.ai.review.as_ref().map(|review| &review.kind)
        else {
            return false;
        };
        if self
            .ai
            .task
            .as_ref()
            .is_some_and(|task| task.generation == *generation)
        {
            self.ai.task = None;
        }
        true
    }

    /// Drops the native review/dialog and stops any sign-in operation bound to it. A run's
    /// approval that can no longer be granted ends that run; a profile or permissions save
    /// keeps its draft with the reason.
    pub(super) fn cancel_ai_review(&mut self, reason: Option<&str>) {
        if self.ai.review.is_none() {
            return;
        }
        self.stop_reviewed_codex_login();
        if self.ai_dialog_is_review(&self.dialog) {
            self.dialog = None;
            self.restore_focused_mode();
        }
        if self.ai_dialog_is_review(&self.quit_dialog) {
            self.quit_dialog = None;
        }
        let closed = reason.unwrap_or("its review closed");
        match self.ai.review.take().map(|review| review.kind) {
            Some(ReviewKind::Agent { generation, .. })
                if self.ai.agent.as_ref().is_some_and(|run| run.generation == generation) =>
            {
                self.invalidate_agent_review(closed);
            }
            Some(ReviewKind::Profile { .. }) => self.ai.panel.profile_save_failed(closed.into()),
            Some(ReviewKind::AllowFull(_)) => self.ai.panel.permissions_failed(closed.into()),
            _ => {}
        }
        if let Some(reason) = reason {
            self.ai.panel.set_error(reason.into());
        }
        self.mark_dirty();
    }

    /// Called when the user dismisses the review dialog.
    pub(super) fn dismiss_ai_review(&mut self) {
        let login = self.stop_reviewed_codex_login();
        match self.ai.review.take().map(|review| review.kind) {
            Some(ReviewKind::Agent { generation, .. })
                if self.ai.agent.as_ref().is_some_and(|run| run.generation == generation) =>
            {
                self.reject_agent_review();
                self.ai.panel.set_status(
                    "Cancelled. Nothing was sent, and the rest of the batch was discarded.".into(),
                );
            }
            Some(ReviewKind::Profile { .. }) => self.ai.panel.profile_save_failed(
                "Not saved: the endpoint change was cancelled. The saved profile is unchanged."
                    .into(),
            ),
            Some(ReviewKind::AllowFull(_)) => self.ai.panel.permissions_failed(
                "Full control was not allowed. Settings are unchanged.".into(),
            ),
            _ => self.ai.panel.set_status(if login {
                "Sign-in cancelled. Existing account credentials were not changed.".into()
            } else {
                "Review cancelled. Nothing was sent or changed.".into()
            }),
        }
    }

    /// Closes reviews whose target session disappeared, reconnected, changed destination,
    /// or whose feature/package authority no longer holds.
    pub(super) fn check_ai_review(&mut self) {
        let Some(review) = &self.ai.review else {
            return;
        };
        if !self.ai_dialog_is_review(&self.dialog) && !self.ai_dialog_is_review(&self.quit_dialog) {
            self.cancel_ai_review(None);
            return;
        }
        let authority = |feature: Option<Feature>| self.ai_ready(feature).ok() == review.package;
        let reason = match &review.kind {
            ReviewKind::Command {
                session_id,
                address,
                port,
                ..
            } => {
                let target = self
                    .sessions
                    .iter()
                    .find(|session| session.id == *session_id)
                    .is_some_and(|session| {
                        session_connected(session)
                            && session.destination.address == *address
                            && session.destination.port == *port
                    });
                if !target {
                    Some("its target session closed, reconnected, or changed".to_owned())
                } else if !authority(Some(Feature::Chat)) {
                    Some("Vyx AI permission or package changed".to_owned())
                } else {
                    None
                }
            }
            ReviewKind::Connect { .. } => (!authority(Some(Feature::Chat)))
                .then(|| "Vyx AI permission or package changed".to_owned()),
            ReviewKind::InstallCodex(_) => {
                (!authority(None)).then(|| "Vyx AI permission or package changed".to_owned())
            }
            ReviewKind::CodexLogin { generation, .. } => (!authority(None)
                || !self
                    .ai
                    .task
                    .as_ref()
                    .is_some_and(|task| task.generation == *generation))
            .then(|| "the sign-in operation ended or its authority changed".to_owned()),
            ReviewKind::Export { .. } => (!self.ai.data.config.allows(Feature::Export))
                .then(|| "transcript export was turned off".to_owned()),
            ReviewKind::Agent { generation, .. } => self
                .agent_review_valid(*generation)
                .err()
                .map(|error| error_text(&error)),
            _ => None,
        };
        if let Some(reason) = reason {
            let text = if matches!(review.kind, ReviewKind::CodexLogin { .. }) {
                format!("Sign-in review closed because {reason}.")
            } else {
                format!("Review cancelled because {reason}. Nothing was sent.")
            };
            self.cancel_ai_review(Some(&text));
        }
    }

    fn review_ai(
        &mut self,
        title: &str,
        content: String,
        submit: &str,
        package: Option<Package>,
        kind: ReviewKind,
    ) -> Result<()> {
        self.review_ai_with(ExtensionReview::new(title, content, submit), package, kind)
            .map(|_| ())
    }

    /// Opens a native review and returns its identity. It never replaces another dialog,
    /// menu, or prompt.
    fn review_ai_with(
        &mut self,
        mut dialog: ExtensionReview,
        package: Option<Package>,
        kind: ReviewKind,
    ) -> Result<Uuid> {
        ensure!(self.attached, "The workspace is detached");
        ensure!(
            self.dialog.is_none()
                && self.menu.is_none()
                && self.extension_review.is_none()
                && !self.quit_confirming,
            "Another dialog is open; finish it before reviewing this action"
        );
        dialog.form.title = format!("Vyx AI · {}", dialog.form.title);
        let id = dialog.id;
        self.ai.review = Some(Review {
            id,
            package,
            kind,
        });
        self.set_dialog(Dialog::ExtensionReview(dialog));
        Ok(id)
    }

    pub(super) async fn accept_ai_review(&mut self) {
        let Some(review) = self.ai.review.take() else {
            return;
        };
        let origin = match review.kind {
            ReviewKind::Profile { .. } => Some(true),
            ReviewKind::AllowFull(_) => Some(false),
            _ => None,
        };
        match self.apply_ai_review(review).await {
            Ok(notice) => {
                self.ai.panel.set_status(notice);
                self.restore_focused_mode();
            }
            Err(error) => match origin {
                Some(true) => self.ai.panel.profile_save_failed(error_text(&error)),
                Some(false) => self.ai.panel.permissions_failed(error_text(&error)),
                None => self.set_dialog(message("Vyx AI action not performed", error)),
            },
        }
        self.mark_dirty();
    }

    async fn apply_ai_review(&mut self, review: Review) -> Result<String> {
        ensure!(self.attached, "The workspace is detached; nothing was sent");
        let same_package = |current: &Package| review.package.as_ref() == Some(current);
        match review.kind {
            ReviewKind::CodexLogin { generation, url } => {
                let package = self.ai_ready(None)?;
                ensure!(
                    same_package(&package)
                        && self
                            .ai
                            .task
                            .as_ref()
                            .is_some_and(|task| task.generation == generation),
                    "This sign-in request is no longer active"
                );
                self.ai.clipboard = Some(url.expose().to_owned());
                Ok("Finish sign-in in your browser. Stop cancels the pending sign-in.".into())
            }
            ReviewKind::Command {
                execute,
                session_id,
                address,
                port,
                command,
            } => {
                let package = self.ai_ready(Some(Feature::Chat))?;
                ensure!(
                    same_package(&package),
                    "STALE_TARGET: the Vyx AI package changed; review again. Nothing was sent."
                );
                contract::validate_terminal_command(&command)?;
                // Reviewed manual input is the user's own: a run working in this session
                // stops before anything is forwarded.
                self.ai_user_input(session_id);
                let enter = [KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)];
                let keys: &[KeyEvent] = if execute { &enter } else { &[] };
                self.submit_ai_input(session_id, &address, port, Some(&command), keys)?;
                if let Some(index) = self.sessions.iter().position(|session| session.id == session_id) {
                    self.activate_session(index);
                }
                Ok(if execute {
                    "Reviewed text and Enter sent to the existing terminal; execution is not isolated. Every further submission needs its own approval.".into()
                } else {
                    "Inserted without Enter into the reviewed session.".into()
                })
            }
            ReviewKind::Connect {
                host_id,
                vault_snapshot,
            } => {
                let package = self.ai_ready(Some(Feature::Chat))?;
                ensure!(
                    same_package(&package),
                    "STALE_TARGET: the Vyx AI package changed; review again"
                );
                ensure!(
                    !self.store.is_uncertain(),
                    "Vault durability is uncertain; retry the save before connecting"
                );
                ensure!(
                    self.state.vault.snapshot_id == vault_snapshot,
                    "STALE_TARGET: saved servers changed; review again"
                );
                self.connect_host(host_id, None)?;
                Ok("Connecting to the reviewed saved server. Normal host-key and credential checks apply.".into())
            }
            ReviewKind::AllowFull(config) => {
                self.apply_ai_permissions(*config)?;
                self.ai.panel.permissions_applied();
                Ok("Full control is now the maximum. Each chat still chooses its own level, and high-risk input still needs approval.".into())
            }
            ReviewKind::Agent {
                generation,
                action_index,
            } => self.accept_agent_review(generation, action_index).await,
            ReviewKind::Switch {
                conversation,
                profile,
                recipient,
                model,
            } => {
                let package = self.ai_ready(Some(Feature::Chat))?;
                ensure!(
                    same_package(&package),
                    "The Vyx AI package changed; review the switch again"
                );
                ensure!(
                    RoutingIdentity::from_profile(self.ai.profile(profile)?)? == recipient,
                    "The provider profile changed after review; review the switch again"
                );
                ensure!(
                    self.ai.agent.is_none()
                        && self
                            .ai
                            .stream
                            .as_ref()
                            .is_none_or(|stream| stream.conversation != conversation),
                    "Stop the active reply or actions before switching provider"
                );
                let name = self.ai.profile(profile)?.name.clone();
                let entry = self.ai.conversation_mut(conversation)?;
                entry.profile_id = Some(profile);
                entry.model = model.clone();
                entry.updated_at = ai::now();
                if matches!(self.ai.task.as_ref().map(|task| task.kind), Some(TaskKind::Title { conversation: id, .. }) if id == conversation)
                {
                    self.ai.task = None;
                }
                self.ai.clear_drafts(|_| false);
                self.ai.touched(conversation);
                Ok(format!(
                    "This conversation now uses {name} · {model}. Nothing was sent."
                ))
            }
            ReviewKind::Profile {
                profile,
                previous,
                discover,
            } => {
                self.ai_installed()?;
                let id = profile.id;
                ensure!(
                    RoutingIdentity::from_profile(self.ai.profile(id)?)? == previous,
                    "The provider profile changed after review; save it again"
                );
                self.store_ai_profile(*profile)?;
                self.ai_profile_stored(id, discover);
                Ok(
                    "Provider profile saved. Its conversations now send to the reviewed endpoint."
                        .into(),
                )
            }
            ReviewKind::Export {
                conversation,
                path,
                updated_at,
            } => {
                self.ai_local(Feature::Export)?;
                ensure!(
                    self.ai.conversation(conversation)?.updated_at == updated_at,
                    "The conversation changed after review; export again"
                );
                self.ai.data.export_transcript(conversation, &path)?;
                Ok(format!(
                    "Plaintext transcript written to {}. Vyx does not track or delete exported copies.",
                    path.display()
                ))
            }
            ReviewKind::Delete(conversation) => {
                self.ai_installed()?;
                if self.ai.agent.as_ref().is_some_and(|run| run.conversation == conversation) {
                    self.stop_ai_agent("Stopped because its conversation was deleted.");
                }
                if self
                    .ai
                    .stream
                    .as_ref()
                    .is_some_and(|stream| stream.conversation == conversation)
                {
                    self.ai.stream = None;
                }
                if matches!(self.ai.task.as_ref().map(|task| task.kind), Some(TaskKind::Title { conversation: id, .. }) if id == conversation)
                {
                    self.ai.task = None;
                }
                let temporary = self.ai.conversation(conversation)?.temporary;
                self.ai.data.remove_conversation(conversation);
                self.ai.owned.retain(|_, owner| *owner != conversation);
                self.ai.clear_drafts(|_| false);
                if self.ai.panel.selected() == Some(conversation) {
                    self.ai.panel.select(None);
                }
                if !temporary {
                    self.ai.save = true;
                }
                Ok("Conversation deleted from local history.".into())
            }
            ReviewKind::DeleteAll => {
                self.ai_installed()?;
                self.stop_ai_agent("Stopped because all conversations were deleted.");
                self.ai.stream = None;
                if matches!(
                    self.ai.task.as_ref().map(|task| task.kind),
                    Some(TaskKind::Title { .. })
                ) {
                    self.ai.task = None;
                }
                self.ai.data.clear_history();
                self.ai.owned.clear();
                self.ai.clear_drafts(|_| false);
                self.ai.panel.select(None);
                self.ai.panel.set_search(None);
                self.ai.save = true;
                Ok("All Vyx AI conversations were deleted from this device.".into())
            }
            ReviewKind::DeleteProfile(id) => {
                self.ai_installed()?;
                self.stop_ai_profile_work(id, true);
                self.ai.data.remove_profile(id);
                self.refresh_ai_helpers();
                self.ai.panel.open(Tab::Settings);
                self.ai.save = true;
                Ok(
                    "Provider profile and its saved credential were removed from this device."
                        .into(),
                )
            }
            ReviewKind::InstallCodex(id) => {
                let (package, _, data_dir) = self.codex_profile(id)?;
                ensure!(
                    same_package(&package),
                    "The Vyx AI package changed; review installation again"
                );
                self.spawn_ai_task(
                    "Installing optional Codex helper…".into(),
                    TaskKind::CodexInstall(id),
                    package,
                    move |_| async move { codex::install(&data_dir).await.map(Output::Text) },
                )?;
                Ok(
                    "Installing the reviewed optional helper. No sign-in or inference was started."
                        .into(),
                )
            }
        }
    }

    /// The one synchronous AI input boundary, shared by manual reviews and runs. It targets
    /// an immutable session ID and destination, needs a connected session with no application
    /// backlog and an immediately free input slot, and submits once; busy input is a visible
    /// failure, never a delayed send. Local scrollback returns to the live screen first.
    fn submit_ai_input(
        &mut self,
        session: Uuid,
        address: &str,
        port: u16,
        text: Option<&str>,
        keys: &[KeyEvent],
    ) -> Result<()> {
        let target = self
            .sessions
            .iter()
            .find(|entry| entry.id == session)
            .context("STALE_TARGET: the session closed. Nothing was sent.")?;
        ensure!(
            target.destination.address == address && target.destination.port == port,
            "STALE_TARGET: the session's destination changed. Nothing was sent."
        );
        ensure!(
            session_connected(target),
            "The session is not connected. Nothing was sent."
        );
        ensure!(
            self.input_queues
                .get(&session)
                .is_none_or(InputQueue::is_empty),
            "Session input is backed up; nothing was sent. Try again once it drains."
        );
        let slot = target
            .try_input_slot()
            .map_err(|_| anyhow!("Session input is busy or closed; nothing was sent."))?;
        let bytes = {
            let mut view = target.view.lock();
            let mut bytes = text.map_or_else(Vec::new, |text| view.terminal.paste(text));
            for key in keys {
                bytes.extend(
                    view.terminal
                        .key(*key)
                        .context("A key cannot be encoded for this terminal; nothing was sent")?,
                );
            }
            if view.terminal.screen().scrollback() > 0 {
                view.terminal.reset_scrollback();
            }
            bytes
        };
        slot.send(bytes.into());
        self.mark_dirty();
        Ok(())
    }

    /// Applies the Permissions form after validation. Raising the maximum to Full needs its
    /// own native review, including when an unconfirmed saved configuration already names Full.
    fn set_ai_permissions(
        &mut self,
        default_permission: PermissionLevel,
        max_permission: PermissionLevel,
        capabilities: BTreeSet<Capability>,
        agent_steps: u16,
    ) -> Result<()> {
        self.ai_installed()?;
        let current = &self.ai.data.config;
        let mut candidate = current.clone();
        candidate.default_permission = default_permission;
        candidate.max_permission = max_permission;
        candidate.capabilities = capabilities;
        candidate.agent_steps = agent_steps;
        candidate.permissions_confirmed = true;
        if let Err(error) = candidate.validate() {
            self.ai.panel.permissions_failed(error_text(&error));
            return Ok(());
        }
        if candidate.max_permission == PermissionLevel::Full
            && (current.max_permission != PermissionLevel::Full || !current.permissions_confirmed)
        {
            let mut review = ExtensionReview::new("Allow Full control", FULL_CONTROL.into(), "Allow Full control");
            review.form.submit_kind = ButtonKind::Danger;
            if let Err(error) = self.review_ai_with(review, None, ReviewKind::AllowFull(Box::new(candidate))) {
                self.ai.panel.permissions_failed(error_text(&error));
            }
            return Ok(());
        }
        match self.apply_ai_permissions(candidate) {
            Ok(()) => {
                self.ai.panel.permissions_applied();
                self.ai.panel.set_status("Permissions applied.".into());
            }
            Err(error) => self.ai.panel.permissions_failed(error_text(&error)),
        }
        Ok(())
    }

    /// The selected (or unsent) chat's level. It cannot exceed the Settings maximum, and before
    /// permissions are confirmed it opens Permissions instead of pretending to grant authority.
    fn set_ai_chat_permission(&mut self, level: PermissionLevel) -> Result<()> {
        self.ai_installed()?;
        let config = &self.ai.data.config;
        if !config.permissions_confirmed {
            self.ai_input(|panel, view, _| {
                panel.open_permissions(view);
                Action::None
            });
            return Ok(());
        }
        ensure!(
            level <= config.max_permission,
            "{} is above the maximum allowed in Settings ({}). Only Settings / Permissions can raise it.",
            level.label(),
            config.max_permission.label()
        );
        match self.ai.panel.selected() {
            Some(id) => {
                if self.ai.conversation(id)?.permission != level {
                    if self.ai.agent.as_ref().is_some_and(|run| run.conversation == id) {
                        self.stop_ai_agent("Stopped because this chat's permission changed.");
                    }
                    self.ai.conversation_mut(id)?.permission = level;
                    self.ai.touched(id);
                }
            }
            None => {
                self.prepare_ai_unsent();
                if let Some(unsent) = self.ai.unsent.as_mut() {
                    unsent.permission = level;
                }
            }
        }
        let effective = self.ai.data.config.effective_permission(level);
        self.ai.panel.set_status(if effective == level {
            format!("This chat is now {}.", level.label())
        } else {
            format!("This chat is set to {}, but acts as {} until Vyx AI and Chat are on.", level.label(), effective.label())
        });
        Ok(())
    }

    /// Adds or removes a live session from the selected (or unsent) chat's scope. Switching
    /// terminal focus never changes scope; only this explicit choice does.
    fn toggle_ai_scope(&mut self, session: Uuid) -> Result<()> {
        self.ai_installed()?;
        let selected = self.ai.panel.selected();
        if selected.is_none() {
            self.prepare_ai_unsent();
        }
        let mut scope = match selected {
            Some(id) => self.ai.conversation(id)?.sessions.clone(),
            None => self.ai.unsent.as_ref().map(|unsent| unsent.sessions.clone()).unwrap_or_default(),
        };
        let added = match scope.iter().position(|id| *id == session) {
            Some(index) => {
                scope.remove(index);
                false
            }
            None => {
                ensure!(
                    self.sessions.iter().any(|entry| entry.id == session),
                    "That session is closed"
                );
                ensure!(
                    scope.len() < ai::MAX_SCOPE_SESSIONS,
                    "A chat can address at most {} sessions; remove one first",
                    ai::MAX_SCOPE_SESSIONS
                );
                scope.push(session);
                true
            }
        };
        match selected {
            Some(id) => {
                if self.ai.agent.as_ref().is_some_and(|run| run.conversation == id) {
                    self.stop_ai_agent("Stopped because this chat's sessions changed.");
                }
                self.ai.conversation_mut(id)?.set_scope(scope);
                self.ai.touched(id);
            }
            None => {
                if let Some(unsent) = self.ai.unsent.as_mut() {
                    unsent.sessions = scope;
                }
            }
        }
        self.ai.panel.set_status(if added {
            "Session added to this chat. Its permission decides what Vyx AI may do there.".into()
        } else {
            "Session removed from this chat.".into()
        });
        Ok(())
    }

    /// A new chat's level is the Settings default (Chat only until permissions are
    /// confirmed); at Assist or Full it starts with the current connected session in scope.
    fn ai_new_chat_scope(&self) -> (PermissionLevel, Vec<Uuid>) {
        let config = &self.ai.data.config;
        let level = if config.permissions_confirmed {
            config.default_permission.min(config.max_permission)
        } else {
            PermissionLevel::ChatOnly
        };
        let session = self
            .active_session
            .and_then(|index| self.sessions.get(index))
            .filter(|session| level > PermissionLevel::ChatOnly && session_connected(session))
            .map(|session| session.id);
        (level, session.into_iter().collect())
    }

    /// The unsent chat snapshots its level and scope once, when the panel first shows it.
    pub(super) fn prepare_ai_unsent(&mut self) {
        if self.ai.unsent.is_none() && self.ai.panel.is_open() && self.ai.panel.selected().is_none() {
            let (permission, sessions) = self.ai_new_chat_scope();
            self.ai.unsent = Some(Unsent { permission, sessions });
        }
    }

    /// Registry ID of the installed native AI package, preferring the official one.
    fn ai_extension_id(&self) -> Option<String> {
        let manager = self.extensions.as_ref()?;
        manager
            .registry
            .entries()
            .iter()
            .filter(|entry| native_entry(manager, entry).is_some())
            .max_by_key(|entry| entry.id == OFFICIAL_ID)
            .map(|entry| entry.id.clone())
    }

    pub(super) async fn handle_ai_action(&mut self, action: Action) {
        if let Err(error) = self.ai_action(action).await {
            self.ai.panel.set_error(error_text(&error));
        }
        self.mark_dirty();
    }

    async fn ai_action(&mut self, action: Action) -> Result<()> {
        match action {
            Action::None => {}
            Action::Close => self.close_ai(),
            Action::Unfocus => self.leave_ai_focus(),
            Action::Resize(width) => {
                if width != self.ai.data.config.panel_width {
                    let config = Config {
                        panel_width: width,
                        ..self.ai.data.config.clone()
                    };
                    self.set_ai_config(config)?;
                }
            }
            Action::Copy(text) => {
                self.ai_installed()?;
                ensure!(!text.is_empty(), "Nothing to copy");
                self.ai.clipboard = Some(text);
            }
            Action::New { temporary } => {
                self.ai_ready(Some(Feature::Chat))?;
                ensure!(
                    self.ai.data.conversations.len() < ai::MAX_CONVERSATIONS,
                    "Conversation limit reached; delete old conversations first"
                );
                self.end_ai_automation("Stopped because you started another chat.");
                let mut conversation = Conversation::new(self.ai.default_profile(), temporary);
                let (permission, sessions) = self.ai_new_chat_scope();
                conversation.permission = permission;
                conversation.set_scope(sessions);
                let id = conversation.id;
                self.discard_temporary_ai(None);
                self.ai.data.conversations.push(conversation);
                self.ai.touched(id);
                self.ai.panel.select(Some(id));
                self.ai.panel.set_status(if temporary {
                    "Temporary chat: messages are never saved and are discarded when you leave this chat or close the panel.".into()
                } else {
                    "New chat. Only what you type, explicitly attach, or this chat's permission allows is sent.".into()
                });
            }
            Action::Select(id) => {
                self.ai_ready(Some(Feature::Chat))?;
                self.ai.conversation(id)?;
                if self.ai.agent.as_ref().is_some_and(|run| run.conversation != id) {
                    self.end_ai_automation("Stopped because you switched conversations.");
                }
                let discarded = self.discard_temporary_ai(Some(id));
                self.ai.panel.select(Some(id));
                if discarded > 0 {
                    self.ai.panel.set_status("Temporary chat discarded.".into());
                }
            }
            Action::Rename {
                conversation,
                title,
            } => {
                self.ai_ready(Some(Feature::Chat))?;
                let title: String = safe_text(title.trim())
                    .chars()
                    .take(ai::MAX_TITLE_CHARS)
                    .collect();
                ensure!(
                    !title.trim().is_empty(),
                    "Conversation title cannot be blank"
                );
                self.ai.conversation_mut(conversation)?.title = title.trim().to_owned();
                self.ai.conversation_mut(conversation)?.updated_at = ai::now();
                self.ai.touched(conversation);
            }
            Action::Delete(id) => self.review_ai_delete(id)?,
            Action::DeleteAll => {
                self.ai_installed()?;
                let count = self.ai.data.conversations.len();
                ensure!(count > 0, "There is no conversation history to delete");
                self.review_ai("Delete all history", format!("Delete all {count} Vyx AI conversations from this device, including temporary chats?\n\nEncrypted local history is removed and cannot be restored. Previously exported plaintext files are not affected."), "Delete all", None, ReviewKind::DeleteAll)?;
            }
            Action::Search(query) => {
                if query.trim().is_empty() {
                    self.ai.panel.set_search(None);
                } else {
                    self.ai_local(Feature::HistorySearch)?;
                    let results = self.ai.data.search(query.trim());
                    self.ai.panel.set_search(Some(results));
                }
            }
            Action::Export { conversation, path } => self.review_ai_export(conversation, path)?,
            Action::Send {
                conversation,
                text,
                attachments,
            } => self.send_ai(conversation, text, attachments)?,
            Action::Stop => {
                let actions = self.ai.agent.is_some();
                ensure!(
                    actions || self.ai.stream.is_some(),
                    "No reply or action is in progress"
                );
                if actions {
                    self.stop_ai_agent("Stopped.");
                }
                if self.ai.stream.is_some() {
                    self.stop_ai_stream(STOPPED);
                    if !actions {
                        self.ai.panel.set_status(
                            "Reply stopped. Charges already incurred by the provider are not reversed."
                                .into(),
                        );
                    }
                }
            }
            Action::Retry(conversation) => {
                let pending = self
                    .ai
                    .conversation(conversation)?
                    .messages
                    .last()
                    .is_some_and(|message| message.role.is_user_turn());
                if pending {
                    let package = self.ai_ready(Some(Feature::Chat))?;
                    ensure!(
                        self.ai.stream.is_none() && self.ai.agent.is_none(),
                        "A reply or actions are already in progress; stop them first"
                    );
                    self.start_ai_reply(conversation, package, true)?;
                } else {
                    self.regenerate_ai(conversation)?;
                }
            }
            Action::Regenerate(conversation) => self.regenerate_ai(conversation)?,
            Action::Edit {
                conversation,
                index,
                text,
            } => self.edit_ai(conversation, index, text)?,
            Action::SwitchModel {
                conversation,
                profile,
                model,
            } => self.review_ai_switch(conversation, profile, model)?,
            Action::Capture { session, kind } => {
                let draft = self.capture_ai(session, kind)?;
                self.ai.panel.add_attachment(draft);
                self.ai.panel.set_status(format!(
                    "Review the attachment before sending. {}",
                    ai::REDACTION_DISCLAIMER
                ));
            }
            Action::Insert { session, command } => {
                self.review_ai_command(session, command, false)?
            }
            Action::Execute { session, command } => {
                self.review_ai_command(session, command, true)?
            }
            Action::Connect { host } => self.review_ai_connect(host)?,
            Action::Template(index) => {
                self.ai_ready(Some(Feature::Templates))?;
                let template = ai::TEMPLATES
                    .get(index)
                    .context("Unknown prompt template")?;
                ensure!(
                    template.allowed(&self.ai.data.config),
                    "Prompt templates or the {} assistance switch are turned off",
                    template.feature.label()
                );
                self.ai.panel.insert(template.prompt);
            }
            Action::SuggestTitle { conversation } => self.suggest_ai_title(conversation)?,
            Action::AcceptTitle { session } => {
                self.ai_ready(Some(Feature::TitleSuggestions))?;
                let title = self
                    .ai
                    .suggestions
                    .get(&session)
                    .cloned()
                    .context("That title suggestion expired")?;
                ensure!(
                    !self
                        .ai
                        .names
                        .get(&session)
                        .is_some_and(|name| name.naming == Naming::Manual),
                    "This session name is manually pinned. Resume AI naming before accepting an AI title."
                );
                let naming = match self.ai.names.get(&session).map(|name| name.naming) {
                    Some(naming @ (Naming::Manual | Naming::Paused)) => naming,
                    _ => Naming::Ai,
                };
                self.apply_session_title(session, &title, naming)?;
                self.ai.suggestions.remove(&session);
            }
            Action::RejectTitle { session } => {
                self.ai.suggestions.remove(&session);
            }
            Action::PauseNaming(session) => {
                self.ai_installed()?;
                let name = self.ai_name(session)?;
                if name.naming != Naming::Manual {
                    name.naming = Naming::Paused;
                }
                self.ai.suggestions.remove(&session);
                if matches!(self.ai.task.as_ref().map(|task| task.kind), Some(TaskKind::Title { session: id, .. }) if id == session)
                {
                    self.ai.task = None;
                }
            }
            Action::ResumeNaming(session) => {
                self.ai_installed()?;
                let label = self
                    .sessions
                    .iter()
                    .find(|entry| entry.id == session)
                    .map(|entry| entry.label.clone())
                    .context("That session is closed")?;
                let name = self.ai_name(session)?;
                name.naming = if label == name.original {
                    Naming::Original
                } else {
                    Naming::Ai
                };
                self.ai.panel.set_status(
                    "AI naming resumed for this session; manual renaming pins it again.".into(),
                );
            }
            Action::RestoreTitle(session) => {
                self.ai_installed()?;
                let original = self.ai_name(session)?.original.clone();
                let entry = self
                    .sessions
                    .iter_mut()
                    .find(|entry| entry.id == session)
                    .context("That session is closed")?;
                entry.label = original;
                self.ai_name(session)?.naming = Naming::Paused;
                self.ai.suggestions.remove(&session);
                if matches!(self.ai.task.as_ref().map(|task| task.kind), Some(TaskKind::Title { session: id, .. }) if id == session)
                {
                    self.ai.task = None;
                }
                self.catalog.invalidate();
                self.ai.panel.set_status(
                    "Original session name restored; AI naming is paused for this session.".into(),
                );
            }
            Action::SetConfig(config) => self.set_ai_config(config)?,
            Action::SetPermissions {
                default_permission,
                max_permission,
                capabilities,
                agent_steps,
            } => self.set_ai_permissions(default_permission, max_permission, capabilities, agent_steps)?,
            Action::SetPermission(level) => self.set_ai_chat_permission(level)?,
            Action::ToggleScope(session) => self.toggle_ai_scope(session)?,
            Action::SaveProfile(profile) => {
                if let Err(error) = self.save_ai_profile(profile, false) {
                    self.ai.panel.profile_save_failed(error_text(&error));
                }
            }
            Action::SaveSetupProfile { profile, discover } => {
                if let Err(error) = self.save_ai_profile(profile, discover) {
                    self.ai.panel.profile_save_failed(error_text(&error));
                }
            }
            Action::DeleteProfile(id) => {
                self.ai_installed()?;
                let profile = self.ai.profile(id)?;
                let users = self
                    .ai
                    .data
                    .conversations
                    .iter()
                    .filter(|conversation| conversation.profile_id == Some(id))
                    .count();
                let content = format!(
                    "Delete provider profile '{}' ({})?\n\nIts saved credential is removed from this device. {users} conversation(s) use it; they keep their history but need a reviewed provider switch before sending again.",
                    safe_text(&profile.name),
                    profile.billing_label()
                );
                self.review_ai(
                    "Delete provider profile",
                    content,
                    "Delete profile",
                    None,
                    ReviewKind::DeleteProfile(id),
                )?;
            }
            Action::TestProfile(id) => {
                let package = self.ai_ready(None)?;
                let profile = self.ai.profile(id)?.clone();
                if profile.kind == ProviderKind::Codex {
                    self.codex_profile(id)?;
                }
                let data_dir = self.ai.data_dir.clone();
                let label = format!("Testing {}…", safe_text(&profile.name));
                self.spawn_ai_task(
                    label,
                    TaskKind::Test(id),
                    package,
                    move |sender| async move {
                        providers::test(&profile, &data_dir, sender)
                            .await
                            .map(Output::Text)
                    },
                )?;
            }
            Action::DiscoverModels(id) => self.discover_ai_models(id)?,
            Action::InstallCodex(id) => {
                let (package, _, _) = self.codex_profile(id)?;
                self.review_ai("Install optional Codex helper",
                    format!("Download and install Vyx's isolated Codex helper from the official Mondrethos/vyx release matching Vyx {}?\n\nThis is a separate optional native component, built from pinned Codex core with all model tools disabled. Requires Linux, bubblewrap and user namespaces. It runs with isolated local files. Your standalone Codex installation and account are not used. Installation verifies the release checksum and does not sign in or send conversations. Cancel downloads nothing.", env!("CARGO_PKG_VERSION")),
                    "Install helper", Some(package), ReviewKind::InstallCodex(id))?;
            }
            Action::CodexLogin {
                profile: id,
                method,
            } => {
                let (package, profile, data_dir) = self.codex_profile(id)?;
                let label = format!("Signing in to Codex for {}…", safe_text(&profile.name));
                self.spawn_ai_task(
                    label,
                    TaskKind::CodexLogin(id),
                    package,
                    move |sender| async move {
                        codex::login(&profile, &data_dir, method, sender)
                            .await
                            .map(Output::Text)
                    },
                )?;
            }
            Action::CodexStatus(id) => {
                let (package, profile, data_dir) = self.codex_profile(id)?;
                let label = format!("Checking Codex account for {}…", safe_text(&profile.name));
                self.spawn_ai_task(
                    label,
                    TaskKind::CodexStatus(id),
                    package,
                    move |sender| async move {
                        codex::status(&profile, &data_dir, sender)
                            .await
                            .map(Output::Text)
                    },
                )?;
            }
            Action::CodexLogout(id) => {
                self.ai_installed()?;
                ensure!(
                    self.ai.profile(id)?.kind == ProviderKind::Codex,
                    "This is not a ChatGPT/Codex subscription profile"
                );
                self.stop_ai_profile_work(id, true);
                self.update_codex_auth(id, None);
                self.ai.panel.set_status(
                    "Disconnected this Vyx profile's ChatGPT account. Other Codex installations were not changed.".into(),
                );
            }
            Action::CancelTask => {
                let task = self.ai.task.take().context("Nothing is in progress")?;
                let install = matches!(task.kind, TaskKind::CodexInstall(_));
                drop(task);
                if install {
                    self.refresh_ai_helpers();
                }
                self.ai.panel.set_status("Cancelled.".into());
            }
            Action::OpenExtensionSettings => {
                self.ai_installed()?;
                let id = self.ai_extension_id();
                self.open_extension_settings(id.as_deref());
            }
        }
        Ok(())
    }

    fn codex_profile(&self, id: Uuid) -> Result<(Package, Profile, PathBuf)> {
        ensure!(
            self.ai.stream.is_none() && self.ai.task.is_none(),
            "Stop the active reply or account task before a Codex account operation"
        );
        let package = self.ai_ready(None)?;
        let profile = self.ai.profile(id)?.clone();
        ensure!(
            profile.kind == ProviderKind::Codex,
            "This is not a ChatGPT/Codex subscription profile"
        );
        Ok((package, profile, self.ai.data_dir.clone()))
    }

    /// One task slot: a running task is never silently aborted to start another.
    fn spawn_ai_task<F, Fut>(&mut self, label: String, kind: TaskKind, package: Package, work: F) -> Result<()>
    where
        F: FnOnce(mpsc::Sender<ProviderEvent>) -> Fut + Send + 'static,
        Fut: Future<Output = Result<Output>> + Send + 'static,
    {
        ensure!(
            self.ai.task.is_none(),
            "Another Vyx AI operation is in progress; cancel it first"
        );
        let generation = self.ai.next_generation();
        let output = self.ai.sender.clone();
        let handle = tokio::spawn(async move {
            let (sender, mut receiver) = mpsc::channel(8);
            let work = work(sender);
            tokio::pin!(work);
            let result = loop {
                tokio::select! {
                    Some(event) = receiver.recv() => {
                        if output.send(Event { generation, kind: EventKind::Provider(event) }).await.is_err() { return; }
                    }
                    result = &mut work => break result,
                }
            };
            while let Ok(event) = receiver.try_recv() {
                if output
                    .send(Event {
                        generation,
                        kind: EventKind::Provider(event),
                    })
                    .await
                    .is_err()
                {
                    return;
                }
            }
            let _ = output
                .send(Event {
                    generation,
                    kind: EventKind::Task(result.map_err(|error| error_text(&error))),
                })
                .await;
        });
        self.ai.panel.set_status(label.clone());
        self.ai.task = Some(Task {
            generation,
            label,
            kind,
            package,
            handle,
        });
        Ok(())
    }

    /// General settings never change permissions: those apply only through the Permissions
    /// form and its Full-control review, so the current permission fields are kept.
    fn set_ai_config(&mut self, mut config: Config) -> Result<()> {
        self.ai_installed()?;
        let current = &self.ai.data.config;
        config.default_permission = current.default_permission;
        config.max_permission = current.max_permission;
        config.capabilities = current.capabilities.clone();
        config.agent_steps = current.agent_steps;
        config.permissions_confirmed = current.permissions_confirmed;
        self.replace_ai_config(config)
    }

    /// Validates and applies a complete configuration. A pending Full-control review is
    /// dismissed first, so stale consent can never overwrite a newer configuration.
    fn replace_ai_config(&mut self, config: Config) -> Result<()> {
        let previous = std::mem::replace(&mut self.ai.data.config, config);
        if let Err(error) = self.ai.data.validate() {
            self.ai.data.config = previous;
            return Err(error);
        }
        if matches!(self.ai.review.as_ref().map(|review| &review.kind), Some(ReviewKind::AllowFull(_))) {
            self.cancel_ai_review(Some(
                "The Full control review closed because settings changed. Nothing was applied.",
            ));
        }
        self.ai_config_changed(&previous);
        self.ai.panel.invalidate();
        self.ai.save = true;
        Ok(())
    }

    /// Applies a validated Permissions draft. Any authority change stops the active run
    /// first; a lower ceiling clamps every chat and the unsent chat, so a later increase
    /// restores nothing. The first confirmation re-creates the unsent chat from the chosen
    /// default, since before it every new chat was forced to Chat only rather than chosen.
    fn apply_ai_permissions(&mut self, permissions: Config) -> Result<()> {
        self.ai_installed()?;
        let current = &self.ai.data.config;
        let first = !current.permissions_confirmed;
        let mut next = current.clone();
        next.default_permission = permissions.default_permission;
        next.max_permission = permissions.max_permission;
        next.capabilities = permissions.capabilities;
        next.agent_steps = permissions.agent_steps;
        next.permissions_confirmed = true;
        next.validate()?;
        let changed = next != *current;
        let read_revoked = current.capabilities.contains(&Capability::ReadOutput)
            && !next.capabilities.contains(&Capability::ReadOutput);
        if read_revoked {
            self.withhold_agent_output();
        }
        if changed {
            self.stop_ai_agent("Stopped because permissions changed.");
        }
        let ceiling = next.max_permission;
        self.replace_ai_config(next)?;
        let mut clamped = Vec::new();
        for conversation in &mut self.ai.data.conversations {
            if conversation.permission > ceiling {
                conversation.permission = ceiling;
                clamped.push(conversation.id);
            }
        }
        for conversation in clamped {
            self.ai.touched(conversation);
        }
        if first {
            self.ai.unsent = None;
            self.prepare_ai_unsent();
        } else if let Some(unsent) = self.ai.unsent.as_mut() {
            unsent.permission = unsent.permission.min(ceiling);
        }
        Ok(())
    }

    /// Turning a feature off stops its native work, not just its controls.
    fn ai_config_changed(&mut self, old: &Config) {
        let new = self.ai.data.config.clone();
        let off = |feature: Feature| old.allows(feature) && !new.allows(feature);
        if old.enabled && !new.enabled {
            self.halt_ai(Some(
                "Vyx AI turned off. Active work stopped and nothing further was sent.",
            ));
            self.discard_temporary_ai(None);
            let open = self.ai.panel.is_open();
            self.ai.panel.reset();
            if open {
                self.ai.panel.open(Tab::Settings);
            }
            return;
        }
        if off(Feature::Chat) {
            self.stop_ai_agent("Stopped because Chat was turned off.");
            self.ai.clear_drafts(|_| false);
            if matches!(
                self.ai.review.as_ref().map(|review| &review.kind),
                Some(ReviewKind::Command { .. } | ReviewKind::Connect { .. } | ReviewKind::Switch { .. })
            ) {
                self.cancel_ai_review(Some(
                    "Review cancelled because Chat was turned off. Nothing was sent.",
                ));
            }
        }
        let reply_features = [
            Feature::Chat,
            Feature::Streaming,
            Feature::Explanations,
            Feature::Troubleshooting,
            Feature::Runbooks,
            Feature::Review,
        ];
        if self.ai.stream.is_some()
            && (reply_features.into_iter().any(off)
                || (off(Feature::BackgroundReply) && !self.ai.panel.is_open()))
        {
            self.stop_ai_stream(STOPPED);
            self.ai.panel.set_status(
                "Reply stopped because a setting it depended on was turned off.".into(),
            );
        }
        if off(Feature::TitleSuggestions) {
            if matches!(
                self.ai.task.as_ref().map(|task| task.kind),
                Some(TaskKind::Title { .. })
            ) {
                self.ai.task = None;
            }
            self.ai.suggestions.clear();
        }
        if off(Feature::Export)
            && matches!(self.ai.review.as_ref().map(|review| &review.kind), Some(ReviewKind::Export { .. }))
        {
            self.cancel_ai_review(Some(
                "Review cancelled because its feature was turned off. Nothing was sent.",
            ));
        }
        if off(Feature::HistorySearch) {
            self.ai.panel.set_search(None);
        }
    }

    fn save_ai_profile(&mut self, profile: Profile, discover: bool) -> Result<()> {
        self.ai_installed()?;
        profile.validate()?;
        if let Ok(existing) = self.ai.profile(profile.id) {
            let previous = RoutingIdentity::from_profile(existing)?;
            let recipient = RoutingIdentity::from_profile(&profile)?;
            let users: Vec<&Conversation> = self
                .ai
                .data
                .conversations
                .iter()
                .filter(|conversation| conversation.profile_id == Some(profile.id))
                .collect();
            if previous != recipient && !users.is_empty() {
                ensure!(
                    self.ai.stream.as_ref().is_none_or(|stream| !users
                        .iter()
                        .any(|conversation| conversation.id == stream.conversation)),
                    "Stop the active reply before changing its provider endpoint so the history preview remains exact"
                );
                let mut preview = String::new();
                for conversation in &users {
                    preview.push_str(&format!(
                        "Conversation: {}\n{}\n",
                        conversation.display_title(),
                        history_preview(conversation, self.ai.data.config.context_chars)
                    ));
                }
                let content = format!(
                    "Profile '{}' changes recipient:\nFrom: {}\nTo: {}\nBilling: {}\n\n{} conversation(s) use this profile. On each conversation's next message, history within its context limit will go to the new recipient. Pending attachments are discarded; capture and review them again.\n\nCancel keeps the saved profile unchanged. Vyx never falls back to another provider or billing mode.\n\nHistory currently eligible for sharing:\n\n{preview}",
                    safe_text(&profile.name),
                    previous.description(),
                    recipient.description(),
                    profile.billing_label(),
                    users.len()
                );
                return self.review_ai(
                    "Change provider endpoint",
                    content,
                    "Save and change recipient",
                    None,
                    ReviewKind::Profile {
                        profile: Box::new(profile),
                        previous,
                        discover,
                    },
                );
            }
        }
        let id = profile.id;
        self.store_ai_profile(profile)?;
        self.ai_profile_stored(id, discover);
        Ok(())
    }

    /// The save is acknowledged only after it, and any routing review, completed.
    fn ai_profile_stored(&mut self, id: Uuid, discover: bool) {
        self.ai.panel.profile_saved(id);
        self.refresh_ai_helpers();
        if !discover {
            self.ai
                .panel
                .set_status("Provider profile saved locally.".into());
        } else if let Err(error) = self.discover_ai_models(id) {
            self.ai.panel.set_error(format!(
                "Profile saved. Models were not requested: {}",
                error_text(&error)
            ));
        }
    }

    /// One explicit model-list request for a saved profile.
    fn discover_ai_models(&mut self, id: Uuid) -> Result<()> {
        let package = self.ai_ready(None)?;
        let profile = self.ai.profile(id)?.clone();
        if profile.kind == ProviderKind::Codex {
            self.codex_profile(id)?;
        }
        let data_dir = self.ai.data_dir.clone();
        let label = format!("Discovering models for {}…", safe_text(&profile.name));
        self.spawn_ai_task(
            label,
            TaskKind::Models(id),
            package,
            move |sender| async move {
                providers::models(&profile, &data_dir, sender)
                    .await
                    .map(Output::Models)
            },
        )
    }

    fn store_ai_profile(&mut self, profile: Profile) -> Result<()> {
        let id = profile.id;
        let previous = self.ai.profile(id).ok().cloned();
        self.ai.data.put_profile(profile)?;
        if self.ai.data.config.default_profile.is_none() {
            self.ai.data.config.default_profile = Some(id);
        }
        if let Some(previous) = previous {
            let current = self.ai.profile(id)?;
            if previous != *current {
                // A model-only change stops affected requests but keeps discovery results.
                let readiness = previous.kind != current.kind
                    || previous.base_url != current.base_url
                    || previous.api_style != current.api_style
                    || previous.credential != current.credential
                    || previous.codex_path != current.codex_path
                    || previous.codex_auth != current.codex_auth;
                self.stop_ai_profile_work(id, readiness);
            }
        }
        self.ai.save = true;
        Ok(())
    }

    /// Stops requests that use profile `id`; `readiness` also forgets its model list and
    /// check results.
    fn stop_ai_profile_work(&mut self, id: Uuid, readiness: bool) {
        if readiness {
            self.ai.models.remove(&id);
            self.ai.checks.retain(|(profile, _), _| *profile != id);
            self.ai.panel.invalidate();
        }
        if self.ai.agent.as_ref().is_some_and(|run| run.profile == id) {
            self.stop_ai_agent("Stopped because its provider profile changed.");
        }
        if self
            .ai
            .stream
            .as_ref()
            .and_then(|stream| self.ai.conversation(stream.conversation).ok())
            .is_some_and(|conversation| conversation.profile_id == Some(id))
        {
            self.stop_ai_stream(STOPPED);
        }
        let affected_task = self.ai.task.as_ref().is_some_and(|task| match task.kind {
            TaskKind::Test(profile)
            | TaskKind::Models(profile)
            | TaskKind::CodexInstall(profile)
            | TaskKind::CodexLogin(profile)
            | TaskKind::CodexStatus(profile) => profile == id,
            TaskKind::Title { conversation, .. } => self
                .ai
                .conversation(conversation)
                .is_ok_and(|conversation| conversation.profile_id == Some(id)),
        });
        if affected_task {
            self.ai.task = None;
        }
        self.ai.clear_drafts(|_| false);
    }

    /// Installed-helper metadata for Codex profiles. Checked on demand, never per frame;
    /// actual launches still verify everything.
    fn refresh_ai_helpers(&mut self) {
        let data_dir = &self.ai.data_dir;
        let helpers = self
            .ai
            .data
            .profiles
            .iter()
            .filter(|profile| profile.kind == ProviderKind::Codex)
            .map(|profile| (profile.id, codex::helper_installed(profile, data_dir)))
            .collect();
        self.ai.helpers = helpers;
        self.ai.panel.invalidate();
    }

    fn ai_name(&mut self, session: Uuid) -> Result<&mut Name> {
        match self.ai.names.entry(session) {
            std::collections::hash_map::Entry::Occupied(entry) => Ok(entry.into_mut()),
            std::collections::hash_map::Entry::Vacant(entry) => {
                let label = self
                    .sessions
                    .iter()
                    .find(|entry| entry.id == session)
                    .map(|entry| entry.label.clone())
                    .context("That session is closed")?;
                Ok(entry.insert(Name {
                    original: label,
                    naming: Naming::Original,
                }))
            }
        }
    }

    /// Live session labels only: the saved server and remote hostname never change.
    fn apply_session_title(&mut self, session: Uuid, title: &str, naming: Naming) -> Result<()> {
        let index = self
            .sessions
            .iter()
            .position(|entry| entry.id == session)
            .context("That session is closed")?;
        let server = self
            .ai
            .names
            .get(&session)
            .map_or(self.sessions[index].destination.label.as_str(), |name| {
                name.original.as_str()
            });
        let label = ai::compose_tab_title(Some(server), title, self.ai.data.config.title_prefix)
            .context("The suggested title is empty")?;
        self.ai_name(session)?.naming = naming;
        self.sessions[index].label = label;
        self.catalog.invalidate();
        self.mark_dirty();
        Ok(())
    }

    pub(super) fn ai_session_opened(&mut self, session: Uuid, label: &str) {
        self.ai.names.insert(
            session,
            Name {
                original: label.to_owned(),
                naming: Naming::Original,
            },
        );
        // Login and foreground state cannot establish an empty shell line.
        self.ai.inputs.remove(&session);
    }

    /// Manual renaming pins the title until the user explicitly resumes AI naming.
    pub(super) fn ai_session_renamed(&mut self, session: Uuid) {
        if let Ok(name) = self.ai_name(session) {
            name.naming = Naming::Manual;
        }
        self.ai.suggestions.remove(&session);
        if matches!(self.ai.task.as_ref().map(|task| task.kind), Some(TaskKind::Title { session: id, .. }) if id == session)
        {
            self.ai.task = None;
        }
    }

    /// The session was removed or replaced: its naming, scope membership, AI ownership, and
    /// input tracking end with it.
    pub(super) fn ai_session_closed(&mut self, session: Uuid) {
        self.ai_session_invalidated(session);
        self.ai.names.remove(&session);
        self.ai.inputs.remove(&session);
        self.ai.owned.remove(&session);
        let mut changed = Vec::new();
        for conversation in &mut self.ai.data.conversations {
            if conversation.sessions.contains(&session) {
                conversation.sessions.retain(|id| *id != session);
                changed.push(conversation.id);
            }
        }
        for conversation in changed {
            self.ai.touched(conversation);
        }
        if let Some(unsent) = self.ai.unsent.as_mut() {
            unsent.sessions.retain(|id| *id != session);
        }
    }

    pub(super) fn ai_session_invalidated(&mut self, session: Uuid) {
        self.ai.suggestions.remove(&session);
        let in_scope = self
            .ai
            .agent
            .as_ref()
            .and_then(|run| self.ai.conversation(run.conversation).ok())
            .is_some_and(|entry| entry.sessions.contains(&session));
        if in_scope && self.ai.agent_closing != Some(session) {
            self.stop_ai_agent("Stopped because a session this chat was using closed or changed.");
        }
        self.ai
            .clear_drafts(|capture| capture.session_id != session);
        if matches!(self.ai.task.as_ref().map(|task| task.kind), Some(TaskKind::Title { session: id, .. }) if id == session)
        {
            self.ai.task = None;
        }
        if matches!(self.ai.review.as_ref().map(|review| &review.kind), Some(ReviewKind::Command { session_id, .. }) if *session_id == session)
        {
            self.cancel_ai_review(Some(
                "Review cancelled because its session closed. Nothing was sent.",
            ));
        }
    }

    /// A deliberate manual capture; the token binds session, destination, source, and time.
    fn capture_ai(&mut self, session_id: Uuid, kind: CaptureKind) -> Result<Draft> {
        self.ai_ready(Some(Feature::Chat))?;
        let session = self
            .sessions
            .iter()
            .find(|session| session.id == session_id)
            .context("That session is closed")?;
        let label = contract::sanitize_display(&session.label);
        let address = session.destination.address.clone();
        let port = session.destination.port;
        let endpoint = format!("{}:{port}", contract::sanitize_display(&address));
        let (source, raw) = match kind {
            CaptureKind::Snapshot => (
                format!("Visible screen · {label} ({endpoint})"),
                visible_screen(session),
            ),
            CaptureKind::Scrollback => (
                format!("Recent output, up to {SCROLLBACK_LINES} lines · {label} ({endpoint})"),
                recent_output(session, SCROLLBACK_LINES),
            ),
            CaptureKind::Metadata => (format!("Server metadata · {label}"), metadata_text(session)),
        };
        Ok(self.issue_ai_draft(session_id, address, port, source, &raw))
    }

    fn issue_ai_draft(
        &mut self,
        session_id: Uuid,
        address: String,
        port: u16,
        source: String,
        raw: &str,
    ) -> Draft {
        let attachment =
            Attachment::new(session_id, source, raw, self.ai.data.config.context_chars);
        let token = self.ai.next_token;
        self.ai.next_token = self.ai.next_token.wrapping_add(1).max(1);
        self.ai.captures.insert(
            token,
            Capture {
                session_id,
                address,
                port,
                source: attachment.source.clone(),
                captured_at: attachment.captured_at,
            },
        );
        Draft { token, attachment }
    }

    /// Validates app-issued drafts against the current workspace and settings.
    fn accept_ai_drafts(&self, drafts: &[Draft]) -> Result<Vec<Attachment>> {
        let config = &self.ai.data.config;
        let mut attachments = Vec::with_capacity(drafts.len());
        for draft in drafts {
            let capture = self.ai.captures.get(&draft.token)
                .context("An attachment expired because the workspace, a setting, or its session changed. Capture it again.")?;
            ensure!(
                draft.attachment.session_id == capture.session_id
                    && draft.attachment.source == capture.source
                    && draft.attachment.captured_at == capture.captured_at,
                "Attachment details changed; capture it again"
            );
            let session = self
                .sessions
                .iter()
                .find(|session| session.id == capture.session_id)
                .context("An attached session was closed; remove its attachment")?;
            ensure!(
                session.destination.address == capture.address
                    && session.destination.port == capture.port,
                "An attached session's destination changed"
            );
            let mut attachment = draft.attachment.clone();
            ensure!(
                attachment.text.chars().count() <= config.context_chars,
                "An edited attachment exceeds the context limit; shorten it and review it again."
            );
            attachment.text = display(&attachment.text, usize::MAX);
            attachments.push(attachment);
        }
        Ok(attachments)
    }

    /// Validates everything before touching history, so a rejected send leaves no trace.
    fn send_ai(
        &mut self,
        conversation: Option<Uuid>,
        text: String,
        drafts: Vec<Draft>,
    ) -> Result<()> {
        let package = self.ai_ready(Some(Feature::Chat))?;
        if conversation.is_none() {
            ensure!(
                self.ai.data.conversations.len() < ai::MAX_CONVERSATIONS,
                "Conversation limit reached; delete old conversations first"
            );
        }
        ensure!(
            self.ai.stream.is_none() && self.ai.agent.is_none(),
            "A reply or actions are already in progress; stop them first"
        );
        let text = display(text.trim_end(), usize::MAX);
        ensure!(
            !text.trim().is_empty() || !drafts.is_empty(),
            "Type a message first"
        );
        let default = self.ai.default_profile().map(|profile| profile.id);
        let created = match conversation {
            Some(_) => None,
            None => {
                let mut created = Conversation::new(self.ai.default_profile(), false);
                let (permission, sessions) = match &self.ai.unsent {
                    Some(unsent) => (unsent.permission, unsent.sessions.clone()),
                    None => self.ai_new_chat_scope(),
                };
                created.permission = permission.min(self.ai.data.config.max_permission);
                created.set_scope(sessions);
                Some(created)
            }
        };
        let entry = match (&created, conversation) {
            (Some(entry), _) => entry,
            (None, Some(id)) => self.ai.conversation(id)?,
            (None, None) => unreachable!("a missing conversation is created above"),
        };
        let id = entry.id;
        ensure!(
            entry.messages.len() + 2 <= ai::MAX_MESSAGES,
            "This conversation reached its message limit; start another conversation"
        );
        // A conversation that never sent anything adopts the chosen default; otherwise changing
        // recipient always requires the reviewed provider switch.
        let profile_id = match entry.profile_id {
            Some(profile) => profile,
            None if entry.messages.is_empty() => {
                default.context("Add a provider profile and choose a default in Vyx AI settings")?
            }
            None => anyhow::bail!(
                "Choose a provider for this conversation with a reviewed provider switch before sending"
            ),
        };
        let mut profile = self.ai.profile(profile_id)
            .context("This conversation's provider profile was deleted. Switch provider (reviewed) before sending.")?
            .clone();
        if entry.profile_id.is_some() && !entry.model.is_empty() {
            profile.model = entry.model.clone();
        }
        profile.ready()?;
        let attachments = self.accept_ai_drafts(&drafts)?;
        let mut body = text;
        for attachment in &attachments {
            if !body.is_empty() {
                body.push_str("\n\n");
            }
            body.push_str(&attachment.to_prompt());
        }
        let limit = self.ai.data.config.context_chars;
        let length = body.chars().count();
        ensure!(
            length <= limit,
            "This message is {length} characters including attachments, above the {limit}-character context limit. Shorten it or raise the limit."
        );
        if let Some(created) = created {
            self.discard_temporary_ai(None);
            self.ai.data.conversations.push(created);
            self.ai.unsent = None;
            self.ai.panel.select(Some(id));
        }
        let entry = self.ai.conversation_mut(id)?;
        if entry.profile_id.is_none() {
            entry.profile_id = Some(profile_id);
            entry.model = profile.model;
        }
        entry.push(Message::new(Role::User, body))?;
        for draft in &drafts {
            self.ai.captures.remove(&draft.token);
        }
        self.ai.touched(id);
        self.ai.panel.sent();
        self.start_ai_reply(id, package, true)
    }

    /// Requests a reply. A deliberate request (Send, Retry, Edit, Regenerate) may start one
    /// run; a follow-up continues the active one. Either snapshots the run's authority and
    /// inventory into the stream.
    fn start_ai_reply(&mut self, conversation: Uuid, package: Package, deliberate: bool) -> Result<()> {
        let entry = self.ai.conversation(conversation)?;
        ensure!(
            self.ai_ready(Some(Feature::Chat))? == package,
            "The Vyx AI package changed before sending; retry explicitly"
        );
        ensure!(
            entry
                .messages
                .last()
                .is_some_and(|message| message.role.is_user_turn()),
            "There is no prompt to answer"
        );
        let profile = self.ai_profile_for(entry)?;
        if profile.kind == ProviderKind::Codex {
            self.codex_profile(profile.id)?;
        }
        if deliberate {
            self.begin_ai_run(conversation, &package, &profile)?;
        }
        let control = self.ai_control(conversation);
        let profile_id = profile.id;
        let name = safe_text(&profile.name);
        let config = &self.ai.data.config;
        let entry = self.ai.conversation(conversation)?;
        let context = control.as_ref().map(agent::Control::context);
        let mut messages = Vec::with_capacity(entry.messages.len() + 1);
        messages.push(Message::new(Role::System, ai::system_prompt(config, context.as_ref())));
        messages.extend(
            entry
                .messages
                .iter()
                .filter(|message| message.role != Role::System)
                .cloned(),
        );
        let streaming = profile.streaming && config.allows(Feature::Streaming);
        let request = providers::Request {
            profile,
            messages,
            context_chars: config.context_chars,
            streaming,
            data_dir: self.ai.data_dir.clone(),
        };
        let reply = Message::new(Role::Assistant, String::new());
        let message = reply.id;
        if let Err(error) = self.ai.conversation_mut(conversation).and_then(|entry| entry.push(reply)) {
            self.ai.agent = None;
            return Err(error);
        }
        let generation = self.ai.next_generation();
        let handle = tokio::spawn(run_stream(generation, request, self.ai.sender.clone()));
        self.ai.stream = Some(Stream {
            generation,
            conversation,
            message,
            package,
            profile: name.clone(),
            profile_id,
            handle,
            control,
        });
        self.ai.panel.set_status(
            self.ai
                .budget_notice(conversation)
                .unwrap_or_else(|| format!("Waiting for {name}…")),
        );
        Ok(())
    }

    fn regenerate_ai(&mut self, conversation: Uuid) -> Result<()> {
        let package = self.ai_ready(Some(Feature::Chat))?;
        ensure!(
            self.ai.stream.is_none() && self.ai.agent.is_none(),
            "A reply or actions are already in progress; stop them first"
        );
        let entry = self.ai.conversation(conversation)?;
        let last_user = entry
            .messages
            .iter()
            .rposition(|message| message.role == Role::User)
            .context("There is no prompt to regenerate")?;
        let branch = entry.branch(last_user + 1)?;
        self.start_ai_branch(conversation, branch, package)
    }

    fn edit_ai(&mut self, conversation: Uuid, index: usize, text: String) -> Result<()> {
        let package = self.ai_ready(Some(Feature::Chat))?;
        ensure!(
            self.ai.stream.is_none() && self.ai.agent.is_none(),
            "A reply or actions are already in progress; stop them first"
        );
        let text = display(text.trim_end(), usize::MAX);
        ensure!(!text.trim().is_empty(), "The edited prompt is empty");
        let limit = self.ai.data.config.context_chars;
        ensure!(
            text.chars().count() <= limit,
            "The edited prompt exceeds the {limit}-character context limit"
        );
        let entry = self.ai.conversation(conversation)?;
        ensure!(
            entry
                .messages
                .get(index)
                .is_some_and(|message| message.role == Role::User),
            "Only your own prompts can be edited"
        );
        let mut branch = entry.branch(index)?;
        branch.messages.push(Message::new(Role::User, text));
        self.start_ai_branch(conversation, branch, package)
    }

    /// History is never rewritten: edits and regenerations continue in a visible branch.
    fn start_ai_branch(
        &mut self,
        parent: Uuid,
        mut branch: Conversation,
        package: Package,
    ) -> Result<()> {
        ensure!(
            self.ai.data.conversations.len() < ai::MAX_CONVERSATIONS,
            "Conversation limit reached; delete old conversations first"
        );
        ensure!(
            branch.messages.len() < ai::MAX_MESSAGES,
            "This branch has no room for another reply; edit an earlier prompt or start a new conversation"
        );
        self.ai_profile_for(&branch)?;
        branch.updated_at = ai::now();
        branch.permission = branch.permission.min(self.ai.data.config.max_permission);
        let id = branch.id;
        let temporary = branch.temporary;
        self.ai.data.conversations.push(branch);
        let discarded = self.discard_temporary_ai(Some(id));
        self.ai.panel.select(Some(id));
        self.ai.touched(id);
        self.start_ai_reply(id, package, true)?;
        if temporary && discarded > 0 {
            self.ai.panel.set_status(
                "Temporary chat branched; the previous temporary version was discarded.".into(),
            );
        } else if !temporary {
            let parent = self
                .ai
                .conversation(parent)
                .map(|entry| safe_text(&entry.title))
                .unwrap_or_default();
            self.ai.panel.set_status(format!(
                "Continuing in a new branch of '{parent}'; the original conversation is unchanged."
            ));
        }
        Ok(())
    }

    pub(super) async fn handle_ai_event(&mut self, event: Event) {
        if matches!(event.kind, EventKind::AgentTick) {
            if self
                .ai
                .agent
                .as_ref()
                .is_some_and(|run| run.generation == event.generation)
            {
                self.advance_ai_agent().await;
            }
        } else if self
            .ai
            .stream
            .as_ref()
            .is_some_and(|stream| stream.generation == event.generation)
        {
            let finished = matches!(event.kind, EventKind::Finished(_));
            self.handle_ai_stream(event.kind);
            if finished {
                self.advance_ai_agent().await;
            }
        } else if self
            .ai
            .task
            .as_ref()
            .is_some_and(|task| task.generation == event.generation)
        {
            self.handle_ai_task(event.kind);
        }
        self.mark_dirty();
    }

    fn handle_ai_stream(&mut self, kind: EventKind) {
        let Some(stream) = &self.ai.stream else {
            return;
        };
        if self.ai_ready(Some(Feature::Chat)).ok().as_ref() != Some(&stream.package) {
            self.stop_ai_stream(STOPPED);
            self.ai.panel.set_error("Reply stopped because Vyx AI was disabled, changed, or the workspace detached. Nothing further was sent.".into());
            return;
        }
        let (conversation, message, profile_id) =
            (stream.conversation, stream.message, stream.profile_id);
        match kind {
            EventKind::Provider(ProviderEvent::Delta(delta)) => {
                let delta = display(&delta, usize::MAX);
                let Some(target) = self
                    .ai
                    .data
                    .conversations
                    .iter_mut()
                    .find(|entry| entry.id == conversation)
                    .and_then(|entry| entry.messages.iter_mut().find(|entry| entry.id == message))
                else {
                    self.ai.stream = None;
                    return;
                };
                let room = MAX_REPLY_BYTES.saturating_sub(target.text.len());
                if delta.len() <= room {
                    target.text.push_str(&delta);
                } else {
                    let mut end = room;
                    while !delta.is_char_boundary(end) {
                        end -= 1;
                    }
                    target.text.push_str(&delta[..end]);
                    self.stop_ai_stream(TOO_LONG);
                }
            }
            EventKind::Provider(ProviderEvent::Usage(usage)) => {
                if let Some(target) = self
                    .ai
                    .data
                    .conversations
                    .iter_mut()
                    .find(|entry| entry.id == conversation)
                    .and_then(|entry| entry.messages.iter_mut().find(|entry| entry.id == message))
                {
                    target.usage = Some(usage);
                }
            }
            EventKind::Provider(ProviderEvent::Status(status)) => {
                self.ai.panel.set_status(display(&status, MAX_STATUS_CHARS))
            }
            EventKind::Provider(ProviderEvent::CodexAuth(credentials)) => {
                self.update_codex_auth(profile_id, credentials);
            }
            EventKind::Provider(ProviderEvent::CodexLogin { .. }) => {
                self.stop_ai_stream(FAILED);
                self.ai.panel.set_error(
                    "Unexpected sign-in request during inference; reply stopped.".into(),
                );
            }
            EventKind::Finished(Ok(())) => self.finish_ai_reply(),
            EventKind::Finished(Err(error)) => {
                let profile = self
                    .ai
                    .stream
                    .as_ref()
                    .map(|stream| stream.profile.clone())
                    .unwrap_or_default();
                self.stop_ai_stream(FAILED);
                self.ai.panel.set_error(format!("{profile}: {error}"));
            }
            EventKind::Task(_) | EventKind::AgentTick => {}
        }
    }

    /// A completed reply: only now are its title line and, for an eligible run reply, its
    /// action blocks considered. Failed, stopped, oversized, or partial replies never get here.
    fn finish_ai_reply(&mut self) {
        let Some(mut stream) = self.ai.stream.take() else {
            return;
        };
        let (conversation, message) = (stream.conversation, stream.message);
        let control = stream.control.take();
        drop(stream);
        let mut title = None;
        let mut parsed = Ok(Vec::new());
        if let Ok(entry) = self.ai.conversation_mut(conversation) {
            if let Some(reply) = entry.messages.iter_mut().find(|entry| entry.id == message) {
                let (text, directives) = ai::take_directives(&reply.text);
                let text = text.trim().to_owned();
                title = directives
                    .into_iter()
                    .map(|Directive::Title(title)| title)
                    .next_back();
                reply.text = if text.is_empty() {
                    "[The provider returned an empty reply]".into()
                } else {
                    text
                };
                parsed = ai::actions::parse_reply(&reply.text);
            }
            entry.updated_at = ai::now();
        }
        self.ai.touched(conversation);
        if let Some(title) = &title {
            self.ai_conversation_title(conversation, title);
        }
        self.queue_ai_actions(conversation, parsed, control, title.as_deref());
        let usage = self
            .ai
            .conversation(conversation)
            .ok()
            .and_then(|entry| entry.messages.iter().find(|entry| entry.id == message))
            .and_then(|message| message.usage.clone());
        let status = match (self.ai.budget_notice(conversation), usage) {
            (Some(notice), _) => notice,
            (None, Some(usage)) if self.ai.data.config.allows(Feature::Usage) => format!(
                "Reply complete · {} input / {} output tokens{}",
                usage.input_tokens,
                usage.output_tokens,
                usage.cost_usd.map_or_else(String::new, |cost| format!(
                    " · provider-reported ${cost:.4} (not an invoice)"
                ))
            ),
            _ => "Reply complete.".into(),
        };
        if !self.ai.panel.has_error() {
            self.ai.panel.set_status(status);
        }
    }

    /// Conversation names are local metadata from an already-requested reply.
    fn ai_conversation_title(&mut self, conversation: Uuid, title: &str) {
        if !self.ai.data.config.allows(Feature::AutoConversationTitle) {
            return;
        }
        let Some(title) = ai::sanitize_title(title, ai::MAX_TITLE_CHARS) else {
            return;
        };
        if let Ok(entry) = self.ai.conversation_mut(conversation)
            && entry.title.is_empty()
        {
            entry.title = title;
            self.ai.touched(conversation);
        }
    }

    /// A reply title that may not rename a tab becomes a suggestion for the chat's first live
    /// in-scope session; it never captures terminal text or renames silently.
    fn ai_title_suggestion(&mut self, conversation: Uuid, title: &str) {
        if !self.ai.data.config.allows(Feature::TitleSuggestions) {
            return;
        }
        let Some(title) = ai::sanitize_title(title, ai::MAX_TAB_TITLE_CHARS) else {
            return;
        };
        let Ok(entry) = self.ai.conversation(conversation) else {
            return;
        };
        if entry.naming_paused {
            return;
        }
        let Some(session) = entry
            .sessions
            .iter()
            .copied()
            .find(|id| self.sessions.iter().any(|session| session.id == *id))
        else {
            return;
        };
        if self
            .ai
            .names
            .get(&session)
            .is_some_and(|name| matches!(name.naming, Naming::Manual | Naming::Paused))
        {
            return;
        }
        self.ai.suggestions.insert(session, title);
    }

    fn update_codex_auth(&mut self, id: Uuid, credentials: Option<crate::vault::Secret>) {
        if let Some(profile) = self
            .ai
            .data
            .profiles
            .iter_mut()
            .find(|profile| profile.id == id && profile.kind == ProviderKind::Codex)
        {
            profile.codex_auth = credentials;
            self.ai.save = true;
        }
    }

    fn handle_ai_task(&mut self, kind: EventKind) {
        let Some(task) = &self.ai.task else {
            return;
        };
        if self.ai_ready(None).ok().as_ref() != Some(&task.package) {
            self.ai.task = None;
            self.ai.panel.set_error(
                "Cancelled because Vyx AI was disabled, changed, or the workspace detached.".into(),
            );
            return;
        }
        let task_kind = task.kind;
        let generation = task.generation;
        match kind {
            EventKind::Provider(ProviderEvent::Status(status)) => {
                self.ai.panel.set_status(display(&status, MAX_STATUS_CHARS))
            }
            EventKind::Provider(ProviderEvent::CodexAuth(credentials)) => {
                let profile = match task_kind {
                    TaskKind::CodexInstall(id)
                    | TaskKind::CodexLogin(id)
                    | TaskKind::CodexStatus(id)
                    | TaskKind::Test(id)
                    | TaskKind::Models(id) => id,
                    TaskKind::Title { profile, .. } => profile,
                };
                self.update_codex_auth(profile, credentials);
            }
            EventKind::Provider(ProviderEvent::CodexLogin { url, code }) => {
                if !matches!(task_kind, TaskKind::CodexLogin(_)) {
                    self.ai.task = None;
                    self.ai
                        .panel
                        .set_error("Unexpected sign-in request; operation stopped.".into());
                    return;
                }
                let package = task.package.clone();
                let mut instructions = format!(
                    "Open this official OpenAI sign-in link in your browser:\n\n{}\n",
                    url.expose()
                );
                if let Some(code) = code {
                    instructions.push_str(&format!(
                        "\nEnter this code: {}\nKeep the code private.\n",
                        code.expose()
                    ));
                } else {
                    instructions.push_str("\nThe browser callback must reach Vyx on this computer. Use device-code sign-in for a remote workspace.\n");
                }
                instructions.push_str("\nCopy sign-in link requests your terminal clipboard. Finish in your browser; Vyx waits for completion. Cancel stops sign-in without replacing saved credentials. After copying, Stop also cancels.");
                if let Err(error) = self.review_ai(
                    "ChatGPT sign-in",
                    instructions,
                    "Copy sign-in link",
                    Some(package),
                    ReviewKind::CodexLogin { generation, url },
                ) {
                    self.ai.task = None;
                    self.ai
                        .panel
                        .set_error(format!("Sign-in stopped: {}", error_text(&error)));
                }
            }
            EventKind::Provider(_) => {}
            EventKind::Task(result) => {
                self.ai.task = None;
                if matches!(task_kind, TaskKind::CodexInstall(_)) {
                    self.refresh_ai_helpers();
                }
                if matches!(self.ai.review.as_ref().map(|review| &review.kind),
                    Some(ReviewKind::CodexLogin { generation: pending, .. }) if *pending == generation)
                {
                    self.cancel_ai_review(None);
                }
                let check = task_kind.check();
                match (task_kind, result) {
                    (TaskKind::Test(profile), Ok(Output::Text(text))) => {
                        let text = display(&text, MAX_STATUS_CHARS);
                        self.ai.checks.insert((profile, Check::Test), Ok(text.clone()));
                        self.ai
                            .panel
                            .set_status(format!("Connection test passed: {text}"));
                    }
                    (
                        TaskKind::CodexInstall(_)
                        | TaskKind::CodexLogin(_)
                        | TaskKind::CodexStatus(_),
                        Ok(Output::Text(text)),
                    ) => {
                        let text = display(&text, MAX_STATUS_CHARS);
                        if let Some(check) = check {
                            self.ai.checks.insert(check, Ok(text.clone()));
                        }
                        self.ai.panel.set_status(text);
                    }
                    (TaskKind::Models(profile), Ok(Output::Models(models))) => {
                        let mut models: Vec<String> = models
                            .into_iter()
                            .map(|model| {
                                contract::sanitize_display(&model)
                                    .chars()
                                    .take(ai::MAX_MODEL_CHARS)
                                    .collect::<String>()
                            })
                            .filter(|model| !model.trim().is_empty())
                            .collect();
                        models.sort();
                        models.dedup();
                        let text = format!("{} model(s) available. Choose one and save the profile, or type a model ID manually.", models.len());
                        self.ai.checks.insert((profile, Check::Models), Ok(text.clone()));
                        self.ai.panel.set_status(text);
                        self.ai.models.insert(profile, models);
                    }
                    (TaskKind::Title { session, .. }, Ok(Output::Text(text))) => {
                        match ai::sanitize_title(&text, ai::MAX_TAB_TITLE_CHARS) {
                            Some(title)
                                if self.sessions.iter().any(|entry| entry.id == session)
                                    && !self.ai.names.get(&session).is_some_and(|name| {
                                        matches!(name.naming, Naming::Manual | Naming::Paused)
                                    })
                                    && self.ai.data.config.allows(Feature::TitleSuggestions) =>
                            {
                                self.ai.panel.set_status(format!(
                                    "Suggested tab title: '{title}'. Accept or reject it."
                                ));
                                self.ai.suggestions.insert(session, title);
                            }
                            Some(_) => {}
                            None => self
                                .ai
                                .panel
                                .set_error("The provider did not return a usable title.".into()),
                        }
                    }
                    (_, Err(error)) => {
                        if let Some(check) = check {
                            self.ai.checks.insert(check, Err(error.clone()));
                        }
                        self.ai.panel.set_error(error);
                    }
                    (_, Ok(_)) => {}
                }
            }
            EventKind::Finished(_) | EventKind::AgentTick => {}
        }
    }

    fn suggest_ai_title(&mut self, conversation: Uuid) -> Result<()> {
        let package = self.ai_ready(Some(Feature::TitleSuggestions))?;
        ensure!(
            self.ai.stream.is_none(),
            "Wait for the reply to finish or stop it before requesting a title"
        );
        let entry = self.ai.conversation(conversation)?;
        let session = entry
            .sessions
            .iter()
            .copied()
            .find(|id| self.sessions.iter().any(|session| session.id == *id))
            .context("Add a live session to this chat's Sessions before requesting a tab title")?;
        ensure!(
            !self
                .ai
                .names
                .get(&session)
                .is_some_and(|name| matches!(name.naming, Naming::Manual | Naming::Paused)),
            "AI naming is paused or manually pinned for this session. Resume AI naming before requesting a title."
        );
        ensure!(
            entry
                .messages
                .iter()
                .any(|message| message.role == Role::User),
            "Send a message first"
        );
        let profile = self.ai_profile_for(entry)?;
        if profile.kind == ProviderKind::Codex {
            self.codex_profile(profile.id)?;
        }
        let profile_id = profile.id;
        let mut messages = vec![Message::new(Role::System, ai::TITLE_REQUEST)];
        messages.extend(
            entry
                .messages
                .iter()
                .filter(|message| message.role != Role::System && !message.text.trim().is_empty())
                .cloned(),
        );
        match messages.last_mut() {
            Some(last) if last.role == Role::User => last
                .text
                .push_str("\n\n(Vyx: reply only with the requested tab title.)"),
            _ => messages.push(Message::new(
                Role::User,
                "Reply only with the requested tab title.",
            )),
        }
        let request = providers::Request {
            profile,
            messages,
            context_chars: self.ai.data.config.context_chars,
            streaming: false,
            data_dir: self.ai.data_dir.clone(),
        };
        let label = "Requesting a tab title suggestion…".to_owned();
        self.spawn_ai_task(
            label,
            TaskKind::Title {
                conversation,
                session,
                profile: profile_id,
            },
            package,
            move |sender| collect_title(request, sender),
        )
    }

    fn review_ai_command(
        &mut self,
        session_id: Uuid,
        command: String,
        execute: bool,
    ) -> Result<()> {
        let package = self.ai_ready(Some(Feature::Chat))?;
        let command = command.trim().to_owned();
        contract::validate_terminal_command(&command).context(
            "Only one exact single-line command without terminal controls can be reviewed",
        )?;
        let session = self
            .sessions
            .iter()
            .find(|session| session.id == session_id && session_connected(session))
            .context("The target session is not connected")?;
        let (address, port) = (
            session.destination.address.clone(),
            session.destination.port,
        );
        let provider = self
            .ai
            .panel
            .selected()
            .and_then(|id| self.ai.conversation(id).ok())
            .and_then(|entry| {
                entry
                    .profile_id
                    .and_then(|id| self.ai.profile(id).ok())
                    .map(|profile| {
                        format!("{} · {}", safe_text(&profile.name), safe_text(&entry.model))
                    })
            })
            .unwrap_or_else(|| "AI proposal".into());
        let header = format!(
            "Source: {provider} (model-generated; warnings from the model are not a security boundary)\nSession: {}\nSession UUID: {}\nDestination: {}:{port}\n\n",
            contract::sanitize_display(&session.label),
            session.id,
            contract::sanitize_display(&address)
        );
        let (title, body, submit, kind) = if execute {
            (
                "Run command",
                "WARNING: This submits the text above followed by Enter to the existing interactive terminal, NOT an isolated SSH exec channel. Existing input is NOT cleared: pending shell text can combine with this text and execute a different command. A foreground program may interpret it as input instead. Vyx cannot verify that the terminal is at an empty shell prompt. Cancel and inspect/clear the target prompt yourself if unsure; do not Run after Insert without removing the inserted text first. Approval authorizes this terminal submission, not a guarantee of what executes. Every later submission needs its own approval. Cancel sends nothing.",
                "Send text + Enter",
                ButtonKind::Danger,
            )
        } else {
            (
                "Insert without Enter",
                "Verify the shell/prompt. Vyx sends the text above with no Enter, but a remote application can interpret ordinary text immediately. Cancel sends nothing.",
                "Insert without Enter",
                ButtonKind::Primary,
            )
        };
        let mut review = ExtensionReview::new(title, format!("{header}{body}"), submit)
            .with_payload(command.clone());
        review.form.submit_kind = kind;
        self.review_ai_with(
            review,
            Some(package),
            ReviewKind::Command {
                execute,
                session_id,
                address,
                port,
                command,
            },
        )
        .map(|_| ())
    }

    fn review_ai_connect(&mut self, host_id: Uuid) -> Result<()> {
        let package = self.ai_ready(Some(Feature::Chat))?;
        ensure!(
            !self.store.is_uncertain(),
            "Vault durability is uncertain; retry the save before connecting"
        );
        let host = self
            .state
            .vault
            .hosts
            .iter()
            .find(|host| host.id == host_id)
            .context("That saved server no longer exists")?;
        let (username, authentication) = match &host.auth {
            crate::vault::HostAuth::Credential { credential_id } => {
                let credential = self
                    .state
                    .vault
                    .credentials
                    .iter()
                    .find(|credential| credential.id == *credential_id)
                    .context("Saved credential removed")?;
                (credential.username.as_str(), credential.label.as_str())
            }
            crate::vault::HostAuth::Password { username, .. } => {
                (username.as_str(), "Server password")
            }
            crate::vault::HostAuth::Tailscale { username, .. } => (
                username.as_str(),
                "Keyless Tailscale SSH; distributed host keys",
            ),
        };
        let content = format!(
            "Saved server: {}\nDestination: {}:{}\nUsername: {}\nAuthentication: {}\n\nConnect only after reviewing this destination. Normal credential and host-key checks still apply. Cancellation does not connect or switch sessions.",
            contract::sanitize_display(&host.label),
            contract::sanitize_display(&host.hostname),
            host.port,
            contract::sanitize_display(username),
            contract::sanitize_display(authentication)
        );
        let vault_snapshot = self.state.vault.snapshot_id;
        self.review_ai(
            "Connect to saved server",
            content,
            "Connect",
            Some(package),
            ReviewKind::Connect {
                host_id,
                vault_snapshot,
            },
        )
    }

    fn review_ai_switch(
        &mut self,
        conversation: Uuid,
        profile_id: Uuid,
        model: String,
    ) -> Result<()> {
        let package = self.ai_ready(Some(Feature::Chat))?;
        let model = model.trim().to_owned();
        ensure!(
            model.chars().count() <= ai::MAX_MODEL_CHARS,
            "Model ID is too long"
        );
        ensure!(!model.is_empty(), "Choose or type a model ID");
        ensure!(
            self.ai.agent.is_none()
                && self
                    .ai
                    .stream
                    .as_ref()
                    .is_none_or(|stream| stream.conversation != conversation),
            "Stop the active reply or actions before switching provider"
        );
        let entry = self.ai.conversation(conversation)?;
        let target = self.ai.profile(profile_id)?;
        let mut selected = target.clone();
        selected.model = model.clone();
        selected.validate()?;
        if entry.profile_id == Some(profile_id) && entry.model == model {
            self.ai
                .panel
                .set_status("That provider and model are already selected.".into());
            return Ok(());
        }
        let current = entry
            .profile_id
            .and_then(|id| self.ai.profile(id).ok())
            .map_or_else(
                || "No provider".into(),
                |profile| {
                    format!(
                        "{} · {} · {} · model {}",
                        safe_text(&profile.name),
                        profile.billing_label(),
                        RoutingIdentity::from_profile(profile)
                            .map(|route| route.description())
                            .unwrap_or_else(|_| "Invalid endpoint".into()),
                        safe_text(&entry.model)
                    )
                },
            );
        let preview = history_preview(entry, self.ai.data.config.context_chars);
        let recipient = RoutingIdentity::from_profile(target)?;
        let content = format!(
            "Conversation: {}\nFrom: {current}\nTo: {} · {} · {} · model {model}\n\nNothing is sent now. On your next message, this history and any attachments in it go to the new recipient under its billing. Pending attachments are discarded; capture and review them again. Vyx never switches provider or billing mode automatically.\n\nHistory the next request would include:\n\n{preview}",
            safe_text(&entry.title),
            safe_text(&target.name),
            target.billing_label(),
            recipient.description()
        );
        self.review_ai(
            "Switch provider",
            content,
            "Switch provider",
            Some(package),
            ReviewKind::Switch {
                conversation,
                profile: profile_id,
                recipient,
                model,
            },
        )
    }

    fn review_ai_export(&mut self, conversation: Uuid, path: String) -> Result<()> {
        self.ai_local(Feature::Export)?;
        let path = PathBuf::from(path.trim());
        ensure!(
            path.is_absolute(),
            "Choose an absolute export path; ~ is not expanded."
        );
        ensure!(
            path.file_name().is_some(),
            "Choose a file name for the export"
        );
        ensure!(
            std::fs::symlink_metadata(&path).is_err(),
            "That file already exists. Vyx never overwrites files; choose a new path."
        );
        ensure!(
            self.ai
                .stream
                .as_ref()
                .is_none_or(|stream| stream.conversation != conversation),
            "Wait for the reply to finish or stop it before exporting"
        );
        let entry = self.ai.conversation(conversation)?;
        let content = format!(
            "Conversation: {}\nMessages: {}\nDestination: {}\n\nWARNING: The export is an unencrypted plaintext file. It may contain server output, commands, hostnames, and anything else in this conversation. Vyx does not track, protect, or delete exported copies. The file is created new with owner-only permissions; existing files are never replaced.",
            safe_text(&entry.title),
            entry.messages.len(),
            path.display()
        );
        let updated_at = entry.updated_at;
        self.review_ai(
            "Export plaintext transcript",
            content,
            "Export plaintext",
            None,
            ReviewKind::Export {
                conversation,
                path,
                updated_at,
            },
        )
    }

    fn review_ai_delete(&mut self, conversation: Uuid) -> Result<()> {
        self.ai_installed()?;
        let entry = self.ai.conversation(conversation)?;
        let content = format!(
            "Delete '{}' ({} messages){}?\n\n{}",
            safe_text(&entry.title),
            entry.messages.len(),
            if entry.temporary {
                ", a temporary chat"
            } else {
                ""
            },
            if entry.temporary {
                "Temporary chats are never saved; this discards it now."
            } else {
                "It is removed from encrypted local history and cannot be restored. Previously exported plaintext files are not affected."
            }
        );
        self.review_ai(
            "Delete conversation",
            content,
            "Delete",
            None,
            ReviewKind::Delete(conversation),
        )
    }

    /// Explicit user copy and retained-history persistence happen at loop boundaries.
    pub(super) async fn flush_ai(&mut self, screen: &mut Screen) {
        if let Some(text) = self.ai.clipboard.take() {
            let result = if self.attached {
                screen.copy_to_clipboard(&text).await
            } else {
                Err(anyhow!("The workspace is detached"))
            };
            match result {
                Ok(()) => self.ai.panel.set_status("Copy requested from your terminal (OSC 52). Some terminals ignore or block clipboard requests.".into()),
                Err(error) => self.ai.panel.set_error(format!("Copy failed: {}", error_text(&error))),
            }
            self.mark_dirty();
        }
        if self.ai.save {
            self.save_ai().await;
        }
    }
    pub(super) async fn retry_ai_save(&mut self) {
        if self.ai.save_failed {
            self.save_ai().await;
        }
    }

    async fn save_ai(&mut self) {
        self.ai.save = false;
        self.ai.data.prune_history(ai::now());
        let in_flight = self
            .ai
            .stream
            .as_ref()
            .map(|stream| (stream.conversation, stream.message));
        let data = persisted(&self.ai.data, in_flight);
        match self
            .store
            .commit(false, move |state| {
                state.ai = data;
                Ok(())
            })
            .await
        {
            Ok(state) => {
                self.ai.save_failed = false;
                self.adopt_state(state);
            }
            Err(error) => {
                self.ai.save_failed = true;
                self.ai.panel.set_error(format!(
                    "Vyx AI changes are not saved; use Retry save: {}",
                    error_text(&error)
                ));
                self.mark_dirty();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Current-thread construction lets us cancel the unrelated release monitor before
    // it is ever polled. These tests use encrypted temporary storage, no provider or SSH.
    async fn fixture() -> (tempfile::TempDir, App) {
        let temporary = tempfile::tempdir().unwrap();
        let directory = Directory::open(temporary.path().join("state")).unwrap();
        let store = directory
            .create(crate::vault::Secret::new(
                "isolated AI regression passphrase",
            ))
            .await
            .unwrap();
        let settings = Settings::load(directory.path()).unwrap();
        let mut app = App::new(store, settings, directory.path()).await;
        app.updates.shutdown().await;
        let path = temporary.path().join("ai.vyxext");
        let manifest = serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 1, "apiVersion": 1, "id": DEVELOPMENT_ID, "name": "AI regression",
            "description": "Native regression fixture", "version": "1.0.0", "permissions": [],
            "commands": [{"id":"chat","title":"Chat","description":"Chat"}, {"id":"settings","title":"Settings","description":"Settings"}]
        })).unwrap();
        let mut bytes = crate::extensions::package::MAGIC.to_vec();
        bytes.extend((manifest.len() as u32).to_le_bytes());
        bytes.extend(8u32.to_le_bytes());
        bytes.extend(manifest);
        bytes.extend(b"\0asm\x01\0\0\0");
        std::fs::write(&path, bytes).unwrap();
        let manager = app.extensions.as_mut().unwrap();
        super::super::extensions::persisted(manager.registry.install(&path).unwrap()).unwrap();
        let digest = manager.registry.entries()[0].digest.clone();
        manager.development.insert(
            DEVELOPMENT_ID.into(),
            crate::extensions::manager::Development {
                path,
                digest: digest.clone(),
                trusted_permissions: None,
                replacement: None,
                candidate: None,
            },
        );
        app.attached = true;
        app.ai.data.config.enabled = true;
        app.handle_extension_management(crate::ui::extensions::ManagementAction::Enable {
            extension_id: DEVELOPMENT_ID.into(),
            digest,
            grants: Vec::new(),
        })
        .await;
        assert!(matches!(app.ai_addon().0, Addon::Development));
        (temporary, app)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn subscription_login_review_preserves_full_link_and_controls_cancellation() {
        let (_temporary, mut app) = fixture().await;
        let profile = Profile::new(ProviderKind::Codex);
        let id = profile.id;
        app.ai.data.profiles.push(profile);
        let url = format!(
            "https://auth.openai.com/authorize?state={}&code_challenge=fixture-end",
            "x".repeat(MAX_STATUS_CHARS + 100)
        );
        for cancel in [true, false] {
            let generation = app.ai.next_generation();
            app.ai.task = Some(Task {
                generation,
                label: "Subscription sign-in".into(),
                kind: TaskKind::CodexLogin(id),
                package: app.ai_addon().1.unwrap(),
                handle: tokio::spawn(std::future::pending()),
            });
            app.handle_ai_event(Event {
                generation,
                kind: EventKind::Provider(ProviderEvent::CodexLogin {
                    url: crate::vault::Secret::new(&url),
                    code: Some(crate::vault::Secret::new("FIXTURE-CODE")),
                }),
            })
            .await;
            assert!(
                app.ai.review.is_some(),
                "sign-in needs a scrollable native review, not clipped status text"
            );
            let Some(Dialog::ExtensionReview(dialog)) = &app.dialog else {
                panic!("sign-in review dialog");
            };
            assert!(dialog.content.contains(&url));
            assert!(dialog.content.contains("FIXTURE-CODE"));
            assert!(app.ai.data.conversations.is_empty());
            if cancel {
                app.cancel_ai_review(None);
                assert!(app.ai.task.is_none());
                assert!(app.ai.clipboard.is_none());
                assert!(app.ai.profile(id).unwrap().codex_auth.is_none());
            } else {
                let review = app.ai.review.take().unwrap();
                app.dialog = None;
                app.apply_ai_review(review).await.unwrap();
                assert_eq!(app.ai.clipboard.take().as_deref(), Some(url.as_str()));
                assert!(
                    app.ai.task.is_some(),
                    "copying the URL must keep sign-in alive"
                );
                app.ai_action(Action::CancelTask).await.unwrap();
            }
        }
        app.shutdown().await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn codex_credentials_follow_profile_and_generation_without_entering_chat() {
        let (_temporary, mut app) = fixture().await;
        let account = Profile::new(ProviderKind::Codex);
        let account_id = account.id;
        let other = Profile::new(ProviderKind::Codex);
        let other_id = other.id;
        app.ai.data.profiles.extend([account, other]);
        let generation = app.ai.next_generation();
        app.ai.task = Some(Task {
            generation,
            label: "Subscription sign-in".into(),
            kind: TaskKind::CodexLogin(account_id),
            package: app.ai_addon().1.unwrap(),
            handle: tokio::spawn(std::future::pending()),
        });
        let credentials = r#"{"auth_mode":"chatgpt","tokens":{"access_token":"fixture-access","refresh_token":"fixture-refresh","id_token":"fixture-id","account_id":"fixture-account"},"last_refresh":"2026-09-28T00:00:00Z"}"#;
        app.handle_ai_event(Event {
            generation,
            kind: EventKind::Provider(ProviderEvent::CodexAuth(Some(crate::vault::Secret::new(
                credentials,
            )))),
        })
        .await;
        assert_eq!(
            app.ai
                .profile(account_id)
                .unwrap()
                .codex_auth
                .as_ref()
                .unwrap()
                .expose(),
            credentials
        );
        assert!(app.ai.profile(other_id).unwrap().codex_auth.is_none());
        assert!(app.ai.data.conversations.is_empty());
        assert!(app.ai.save);
        app.ai_action(Action::CancelTask).await.unwrap();
        app.handle_ai_event(Event {
            generation,
            kind: EventKind::Provider(ProviderEvent::CodexAuth(None)),
        })
        .await;
        assert!(
            app.ai.profile(account_id).unwrap().codex_auth.is_some(),
            "cancelled task must not clear a saved account"
        );
        app.ai.data.config.enabled = false;
        app.ai_action(Action::CodexLogout(account_id))
            .await
            .unwrap();
        assert!(app.ai.profile(account_id).unwrap().codex_auth.is_none());
        app.handle_ai_event(Event {
            generation,
            kind: EventKind::Provider(ProviderEvent::CodexAuth(Some(crate::vault::Secret::new(
                credentials,
            )))),
        })
        .await;
        assert!(
            app.ai.profile(account_id).unwrap().codex_auth.is_none(),
            "late refresh must not restore a signed-out account"
        );
        app.shutdown().await.unwrap();
    }

    fn profile(name: &str) -> Profile {
        let mut profile = Profile::new(ProviderKind::Compatible);
        profile.name = name.into();
        profile.base_url = "http://127.0.0.1:1/v1".into();
        profile.model = "test-model".into();
        profile
    }

    fn pending_reply(app: &mut App, temporary: bool) -> (Uuid, u64) {
        let mut conversation = Conversation::new(None, temporary);
        conversation
            .push(Message::new(Role::User, "Explain this command"))
            .unwrap();
        let reply = Message::new(Role::Assistant, "The command lists files.");
        let message = reply.id;
        conversation.push(reply).unwrap();
        let id = conversation.id;
        app.ai.data.conversations.push(conversation);
        let generation = app.ai.next_generation();
        app.ai.stream = Some(Stream {
            generation,
            conversation: id,
            message,
            package: app.ai_addon().1.unwrap(),
            profile: "Pending test request".into(),
            profile_id: Uuid::nil(),
            handle: tokio::spawn(std::future::pending()),
            control: None,
        });
        app.ai.panel.open(Tab::Chat);
        app.ai.panel.select(Some(id));
        app.focus = Focus::Ai;
        (id, generation)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn inactive_development_settings_remain_accessible_without_request_authority() {
        use crate::ui::extensions::{ManagementAction, SurfaceAction};

        let (_temporary, mut app) = fixture().await;
        let manager = app.extensions.as_mut().unwrap();
        let development = manager.development.remove(DEVELOPMENT_ID).unwrap();
        let digest = manager.registry.entries()[0].digest.clone();
        assert!(manager.runtime.is_none());

        // A previously enabled package loses native activation on workspace restart.
        app.handle_extension_surface(SurfaceAction::Launch {
            extension_id: DEVELOPMENT_ID.into(),
            command_id: SETTINGS_COMMAND.into(),
        })
        .await;
        assert!(app.ai.panel.is_open());
        assert!(app.dialog.is_none());
        assert!(app.extension_entries()[0].native);
        let profile = Profile::new(ProviderKind::Codex);
        let profile_id = profile.id;
        app.handle_ai_action(Action::SaveProfile(profile)).await;
        assert_eq!(app.ai.profile(profile_id).unwrap().kind, ProviderKind::Codex);
        assert!(app.ai_ready(None).is_err());
        app.handle_ai_action(Action::CodexLogin {
            profile: profile_id,
            method: codex::LoginMethod::DeviceCode,
        }).await;
        assert!(app.ai.task.is_none());
        assert!(app.extensions.as_ref().unwrap().binding().is_none());
        app.close_ai();
        app.handle_extension_surface(SurfaceAction::Launch {
            extension_id: DEVELOPMENT_ID.into(),
            command_id: CHAT_COMMAND.into(),
        }).await;
        assert!(matches!(app.dialog, Some(Dialog::Message { .. })));
        assert!(!app.ai.panel.is_open());
        app.dialog = None;

        super::super::extensions::persisted(
            app.extensions
                .as_mut()
                .unwrap()
                .registry
                .disable(DEVELOPMENT_ID)
                .unwrap(),
        )
        .unwrap();
        app.handle_extension_management(ManagementAction::Enable {
            extension_id: DEVELOPMENT_ID.into(),
            digest: digest.clone(),
            grants: Vec::new(),
        })
        .await;
        // An activation error, not a runtime lookup/download; consent is unchanged.
        assert!(matches!(app.dialog, Some(Dialog::Message { .. })));
        assert!(!app.extensions.as_ref().unwrap().registry.entries()[0].enabled);
        app.dialog = None;

        app.handle_extension_management(ManagementAction::LoadDevelopment {
            path: development.path,
        })
        .await;
        let Some(Dialog::ExtensionReview(review)) = app.dialog.take() else {
            panic!("explicit development review");
        };
        app.accept_extension_review(review).await;
        app.handle_extension_management(ManagementAction::Enable {
            extension_id: DEVELOPMENT_ID.into(),
            digest,
            grants: Vec::new(),
        })
        .await;
        assert!(app.extensions.as_ref().unwrap().registry.entries()[0].enabled);
        assert!(app.dialog.is_none());
        app.handle_extension_surface(SurfaceAction::Launch {
            extension_id: DEVELOPMENT_ID.into(),
            command_id: SETTINGS_COMMAND.into(),
        })
        .await;
        assert!(app.ai.panel.is_open());
        assert!(app.extensions.as_ref().unwrap().runtime.is_none());
        assert!(app.dialog.is_none());
        app.shutdown().await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn identical_local_update_preserves_grants_without_native_activation() {
        use crate::ui::extensions::ManagementAction;

        let (_temporary, mut app) = fixture().await;
        let manager = app.extensions.as_mut().unwrap();
        let development = manager.development.remove(DEVELOPMENT_ID).unwrap();
        super::super::extensions::persisted(manager.registry.disable(DEVELOPMENT_ID).unwrap())
            .unwrap();
        let digest = manager.registry.entries()[0].digest.clone();
        let before = std::fs::read(app.ai.data_dir.join("extensions/registry.json")).unwrap();
        app.handle_extension_management(ManagementAction::Update {
            extension_id: DEVELOPMENT_ID.into(),
            digest,
            path: development.path,
        })
        .await;
        let Some(Dialog::ExtensionReview(review)) = app.dialog.take() else {
            panic!("local package review");
        };
        app.accept_extension_review(review).await;
        assert!(
            app.dialog.is_none(),
            "an identical package is not a failed update"
        );
        let manager = app.extensions.as_ref().unwrap();
        assert!(!manager.development.contains_key(DEVELOPMENT_ID));
        assert!(!manager.registry.entries()[0].enabled);
        assert!(
            manager.registry.entries()[0]
                .approved_permissions
                .is_empty()
        );
        assert_eq!(
            std::fs::read(app.ai.data_dir.join("extensions/registry.json")).unwrap(),
            before
        );
        app.shutdown().await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn reattaching_identical_development_package_preserves_disabled_grants() {
        let (_temporary, mut app) = fixture().await;
        let manager = app.extensions.as_mut().unwrap();
        let development = manager.development.remove(DEVELOPMENT_ID).unwrap();
        super::super::extensions::persisted(manager.registry.disable(DEVELOPMENT_ID).unwrap())
            .unwrap();
        app.handle_extension_management(crate::ui::extensions::ManagementAction::LoadDevelopment {
            path: development.path.clone(),
        })
        .await;
        let Some(Dialog::ExtensionReview(review)) = app.dialog.take() else {
            panic!("explicit development review");
        };
        app.accept_extension_review(review).await;
        let manager = app.extensions.as_ref().unwrap();
        assert!(manager.development.contains_key(DEVELOPMENT_ID));
        assert!(!manager.registry.entries()[0].enabled);
        assert!(
            manager.registry.entries()[0]
                .approved_permissions
                .is_empty()
        );
        // The reviewed source is remembered; remembering never enables or grants.
        assert_eq!(
            manager.registry.entries()[0].development_path.as_deref(),
            Some(development.path.as_path())
        );
        assert!(matches!(app.ai_addon().0, Addon::Disabled));
        app.shutdown().await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn same_host_endpoint_path_changes_require_review_and_revalidation() {
        let (_temporary, mut app) = fixture().await;
        let mut original = profile("Tenant profile");
        original.base_url = "http://127.0.0.1:1/tenant-a/v1".into();
        app.ai.data.put_profile(original.clone()).unwrap();
        let mut conversation = Conversation::new(Some(&original), false);
        conversation
            .push(Message::new(Role::User, "Retained tenant-a history"))
            .unwrap();
        app.ai.data.conversations.push(conversation);
        let mut replacement = original.clone();
        replacement.base_url = "http://127.0.0.1:1/tenant-b/v1".into();

        app.save_ai_profile(replacement.clone(), false).unwrap();
        assert!(
            app.ai.review.is_some(),
            "a same-host path change must require review"
        );
        assert_eq!(
            app.ai.profile(original.id).unwrap().base_url,
            original.base_url
        );
        let dialog = app.dialog.take().unwrap();
        app.handle_dialog_input(dialog, DialogInput::Cancel)
            .await
            .unwrap();
        assert_eq!(
            app.ai.profile(original.id).unwrap().base_url,
            original.base_url
        );

        app.save_ai_profile(replacement.clone(), false).unwrap();
        let review = app.ai.review.take().unwrap();
        app.dialog = None;
        app.apply_ai_review(review).await.unwrap();
        assert_eq!(
            app.ai.profile(original.id).unwrap().base_url,
            replacement.base_url
        );

        app.save_ai_profile(original.clone(), false).unwrap();
        let stale = app.ai.review.take().unwrap();
        app.dialog = None;
        app.ai
            .data
            .profiles
            .iter_mut()
            .find(|profile| profile.id == original.id)
            .unwrap()
            .base_url = "http://127.0.0.1:1/tenant-c/v1".into();
        assert!(app.apply_ai_review(stale).await.is_err());
        assert_eq!(
            app.ai.profile(original.id).unwrap().base_url,
            "http://127.0.0.1:1/tenant-c/v1"
        );
        assert!(
            app.ai.stream.is_none(),
            "profile review must never send history"
        );
        app.shutdown().await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancelled_or_revoked_review_never_changes_the_recipient() {
        let (_temporary, mut app) = fixture().await;
        let original = profile("Original recipient");
        let replacement = profile("New recipient");
        app.ai.data.put_profile(original.clone()).unwrap();
        app.ai.data.put_profile(replacement.clone()).unwrap();
        let mut conversation = Conversation::new(Some(&original), false);
        conversation
            .push(Message::new(Role::User, "Deliberately shared history"))
            .unwrap();
        let id = conversation.id;
        app.ai.data.conversations.push(conversation);
        app.review_ai_switch(id, replacement.id, replacement.model.clone())
            .unwrap();
        let dialog = app.dialog.take().unwrap();
        app.handle_dialog_input(dialog, DialogInput::Cancel)
            .await
            .unwrap();
        assert_eq!(
            app.ai.conversation(id).unwrap().profile_id,
            Some(original.id)
        );
        assert!(app.ai.review.is_none());
        app.review_ai_switch(id, replacement.id, replacement.model)
            .unwrap();
        let stale = app.ai.review.take().unwrap();
        app.dialog = None;
        let manager = app.extensions.as_mut().unwrap();
        super::super::extensions::persisted(manager.registry.revoke(DEVELOPMENT_ID).unwrap())
            .unwrap();
        app.revalidate_ai();
        assert!(app.apply_ai_review(stale).await.is_err());
        assert_eq!(
            app.ai.conversation(id).unwrap().profile_id,
            Some(original.id)
        );
        assert!(app.input_queues.is_empty());
        app.shutdown().await.unwrap();
        app.store.shutdown().await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn stopped_and_detached_replies_ignore_late_events_and_discard_temporary_history() {
        let (_temporary, mut app) = fixture().await;
        let (retained, generation) = pending_reply(&mut app, false);
        app.ai_action(Action::Stop).await.unwrap();
        app.handle_ai_event(Event {
            generation,
            kind: EventKind::Provider(ProviderEvent::Delta(" stale text".into())),
        })
        .await;
        assert_eq!(
            app.ai
                .conversation(retained)
                .unwrap()
                .messages
                .last()
                .unwrap()
                .text,
            format!("The command lists files.\n\n{STOPPED}")
        );
        let (temporary, generation) = pending_reply(&mut app, true);
        app.set_attached(false);
        app.handle_ai_event(Event {
            generation,
            kind: EventKind::Finished(Ok(())),
        })
        .await;
        assert!(app.ai.conversation(temporary).is_err());
        assert!(app.ai.stream.is_none());
        assert!(!app.ai.is_open());
        assert_ne!(app.focus, Focus::Ai);
        assert_eq!(
            persisted(&app.ai.data, None)
                .conversations
                .iter()
                .map(|conversation| conversation.id)
                .collect::<Vec<_>>(),
            vec![retained]
        );
        app.shutdown().await.unwrap();
        app.store.shutdown().await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn manual_names_pin_against_pending_and_automatic_suggestions() {
        let (_temporary, mut app) = fixture().await;
        app.ai.data.config.features.extend([
            Feature::TitleSuggestions,
            Feature::AutoTitle,
            Feature::AutoConversationTitle,
        ]);
        let session = Uuid::new_v4();
        app.ai_session_opened(session, "original");
        app.ai.suggestions.insert(session, "old suggestion".into());
        let mut conversation = Conversation::new(None, false);
        conversation.title = "My chosen conversation name".into();
        conversation.sessions = vec![session];
        let id = conversation.id;
        app.ai.data.conversations.push(conversation);
        let generation = app.ai.next_generation();
        app.ai.task = Some(Task {
            generation,
            label: "Pending title".into(),
            kind: TaskKind::Title {
                conversation: id,
                session,
                profile: Uuid::nil(),
            },
            package: app.ai_addon().1.unwrap(),
            handle: tokio::spawn(std::future::pending()),
        });
        app.ai_session_renamed(session);
        app.handle_ai_event(Event {
            generation,
            kind: EventKind::Task(Ok(Output::Text("Late title".into()))),
        })
        .await;
        app.ai_conversation_title(id, "Automatic title");
        app.ai_title_suggestion(id, "Automatic title");
        assert!(matches!(
            app.ai.names.get(&session).unwrap().naming,
            Naming::Manual
        ));
        assert!(!app.ai.suggestions.contains_key(&session));
        assert!(app.ai.task.is_none());
        assert_eq!(
            app.ai.conversation(id).unwrap().title,
            "My chosen conversation name"
        );
        app.ai_session_invalidated(session);
        assert!(matches!(
            app.ai.names.get(&session).unwrap().naming,
            Naming::Manual
        ));
        app.shutdown().await.unwrap();
        app.store.shutdown().await.unwrap();
    }

    #[test]
    fn recent_output_is_contiguous_across_scrollback_pages() {
        let mut terminal = crate::terminal::TerminalState::new(10, 20);
        for line in 1..=50 {
            terminal.process(format!("line {line}\r\n").as_bytes());
        }
        let captured = screen_lines(terminal.screen().clone(), 30);
        let lines: Vec<&str> = captured.lines().collect();
        let expected: Vec<String> = (22..=50).map(|line| format!("line {line}")).collect();
        assert_eq!(lines, expected);
        assert_eq!(
            terminal.screen().scrollback(),
            0,
            "capturing must not scroll the user's view"
        );
    }

    fn permissions(default_permission: PermissionLevel, max_permission: PermissionLevel) -> Action {
        Action::SetPermissions {
            default_permission,
            max_permission,
            capabilities: Capability::ALL.into_iter().collect(),
            agent_steps: ai::DEFAULT_AGENT_STEPS,
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn permissions_apply_after_validation_and_full_control_needs_its_own_review() {
        let (_temporary, mut app) = fixture().await;
        let mut chat = Conversation::new(None, false);
        chat.permission = PermissionLevel::Full;
        let chat_id = chat.id;
        app.ai.data.conversations.push(chat);
        assert_eq!(
            app.ai.data.config.effective_permission(PermissionLevel::Full),
            PermissionLevel::ChatOnly,
            "unconfirmed permissions grant nothing"
        );

        app.handle_ai_action(permissions(PermissionLevel::Full, PermissionLevel::Assist)).await;
        assert!(!app.ai.data.config.permissions_confirmed, "an invalid draft changes nothing");

        app.handle_ai_action(permissions(PermissionLevel::Assist, PermissionLevel::Full)).await;
        assert!(matches!(app.ai.review.as_ref().map(|review| &review.kind), Some(ReviewKind::AllowFull(_))));
        let dialog = app.dialog.take().unwrap();
        app.handle_dialog_input(dialog, DialogInput::Cancel).await.unwrap();
        assert_eq!(app.ai.data.config.max_permission, PermissionLevel::Assist);
        assert!(!app.ai.data.config.permissions_confirmed);

        app.handle_ai_action(permissions(PermissionLevel::Assist, PermissionLevel::Full)).await;
        let dialog = app.dialog.take().unwrap();
        app.handle_dialog_input(dialog, DialogInput::Submit).await.unwrap();
        assert_eq!(app.ai.data.config.max_permission, PermissionLevel::Full);
        assert!(app.ai.data.config.permissions_confirmed);
        assert_eq!(app.ai.data.config.effective_permission(PermissionLevel::Full), PermissionLevel::Full);

        // Lowering the ceiling needs no review and clamps existing chats, so a later
        // increase cannot silently restore their previous level.
        app.handle_ai_action(permissions(PermissionLevel::ChatOnly, PermissionLevel::Assist)).await;
        assert!(app.ai.review.is_none());
        assert_eq!(app.ai.conversation(chat_id).unwrap().permission, PermissionLevel::Assist);
        app.ai.panel.select(Some(chat_id));
        app.handle_ai_action(Action::SetPermission(PermissionLevel::Full)).await;
        assert_eq!(
            app.ai.conversation(chat_id).unwrap().permission,
            PermissionLevel::Assist,
            "the chat control cannot exceed the Settings maximum"
        );
        app.shutdown().await.unwrap();
        app.store.shutdown().await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn ineligible_replies_never_run_their_action_blocks() {
        let (_temporary, mut app) = fixture().await;
        let layout = app.settings.workspace.terminal_layout;
        let (conversation, _) = pending_reply(&mut app, false);
        app.ai.conversation_mut(conversation).unwrap().messages.last_mut().unwrap().text =
            "Switching layout.\n\n```vyx-action\n{\"action\":\"layout\",\"layout\":\"grid\"}\n```".into();
        app.finish_ai_reply();
        assert!(app.ai.agent.is_none());
        assert_eq!(app.settings.workspace.terminal_layout, layout);
        assert_eq!(
            app.ai.conversation(conversation).unwrap().messages.last().unwrap().role,
            Role::Action,
            "a Chat only reply records that its actions were not performed"
        );
        app.shutdown().await.unwrap();
        app.store.shutdown().await.unwrap();
    }

    const GRID: &str = "```vyx-action\n{\"action\":\"layout\",\"layout\":\"grid\"}\n```";

    /// A completed provider reply in a chat at `level`, requested the way a deliberate Send
    /// requests one: confirmed permissions, a started run, and its authority snapshot.
    fn run_reply(app: &mut App, level: PermissionLevel, reply: &str) -> Uuid {
        app.ai.data.config.permissions_confirmed = true;
        app.ai.data.config.max_permission = PermissionLevel::Full;
        let profile = profile("agent");
        app.ai.data.put_profile(profile.clone()).unwrap();
        let mut chat = Conversation::new(Some(&profile), false);
        chat.permission = level;
        chat.push(Message::new(Role::User, "Please do it")).unwrap();
        let answer = Message::new(Role::Assistant, reply);
        let message = answer.id;
        chat.push(answer).unwrap();
        let id = chat.id;
        app.ai.data.conversations.push(chat);
        let package = app.ai_addon().1.unwrap();
        app.begin_ai_run(id, &package, &profile).unwrap();
        let control = app.ai_control(id);
        assert!(control.is_some(), "confirmed Assist or Full starts a run");
        let generation = app.ai.next_generation();
        app.ai.stream = Some(Stream {
            generation,
            conversation: id,
            message,
            package,
            profile: "agent".into(),
            profile_id: profile.id,
            handle: tokio::spawn(std::future::pending()),
            control,
        });
        app.ai.panel.open(Tab::Chat);
        app.ai.panel.select(Some(id));
        id
    }

    #[tokio::test(flavor = "current_thread")]
    async fn unresolved_targets_reject_the_whole_batch_before_anything_runs() {
        let (_temporary, mut app) = fixture().await;
        let layout = app.settings.workspace.terminal_layout;
        let id = run_reply(
            &mut app,
            PermissionLevel::Full,
            &format!("{GRID}\n```vyx-action\n{{\"action\":\"read\",\"session\":\"s1\"}}\n```"),
        );
        app.finish_ai_reply();
        app.advance_ai_agent().await;
        assert!(app.ai.agent.is_none());
        assert_eq!(app.settings.workspace.terminal_layout, layout, "no earlier action in the batch ran");
        assert_eq!(app.ai.conversation(id).unwrap().messages.last().unwrap().role, Role::Action);
        assert!(app.ai.stream.is_none(), "a rejected batch requests no follow-up");
        app.shutdown().await.unwrap();
        app.store.shutdown().await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn assist_asks_before_each_change_and_cancel_ends_the_run() {
        let (_temporary, mut app) = fixture().await;
        let layout = app.settings.workspace.terminal_layout;
        assert_ne!(layout, crate::settings::TerminalLayout::Grid);
        let rejected = run_reply(&mut app, PermissionLevel::Assist, GRID);
        app.finish_ai_reply();
        app.advance_ai_agent().await;
        assert!(matches!(app.ai.review.as_ref().map(|review| &review.kind), Some(ReviewKind::Agent { .. })));
        assert_eq!(app.settings.workspace.terminal_layout, layout, "nothing changes before approval");
        let dialog = app.dialog.take().unwrap();
        app.handle_dialog_input(dialog, DialogInput::Cancel).await.unwrap();
        assert!(app.ai.agent.is_none() && app.ai.stream.is_none(), "cancel ends the run without a follow-up");
        assert_eq!(app.settings.workspace.terminal_layout, layout);
        assert_eq!(app.ai.conversation(rejected).unwrap().messages.last().unwrap().role, Role::Action);

        let approved = run_reply(&mut app, PermissionLevel::Assist, GRID);
        app.finish_ai_reply();
        app.advance_ai_agent().await;
        let dialog = app.dialog.take().unwrap();
        app.handle_dialog_input(dialog, DialogInput::Submit).await.unwrap();
        assert_eq!(app.settings.workspace.terminal_layout, crate::settings::TerminalLayout::Grid);
        // A fully successful batch asks for the next reply with its result as the final user turn.
        let messages = &app.ai.conversation(approved).unwrap().messages;
        assert_eq!(messages[messages.len() - 2].role, Role::Action);
        assert!(app.ai.stream.as_ref().is_some_and(|stream| stream.conversation == approved && stream.control.is_some()));
        app.shutdown().await.unwrap();
        app.store.shutdown().await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn stop_discards_an_unsaved_server_draft_and_saves_nothing() {
        let (_temporary, mut app) = fixture().await;
        run_reply(
            &mut app,
            PermissionLevel::Full,
            "```vyx-action\n{\"action\":\"draft_server\",\"label\":\"staging\",\"hostname\":\"staging.example\"}\n```",
        );
        app.finish_ai_reply();
        app.advance_ai_agent().await;
        assert!(matches!(app.dialog, Some(Dialog::Editor(_))), "the real editor is the approval");
        app.handle_ai_action(Action::Stop).await;
        assert!(app.dialog.is_none());
        assert!(app.ai.agent.is_none());
        assert!(app.state.vault.hosts.is_empty());
        app.shutdown().await.unwrap();
        app.store.shutdown().await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn failed_replies_late_ticks_and_reopened_history_never_run_actions() {
        let (_temporary, mut app) = fixture().await;
        let layout = app.settings.workspace.terminal_layout;
        let id = run_reply(&mut app, PermissionLevel::Full, GRID);
        let run = app.ai.agent.as_ref().unwrap().generation;
        let stream = app.ai.stream.as_ref().unwrap().generation;
        app.handle_ai_event(Event {
            generation: stream,
            kind: EventKind::Finished(Err("provider failed".into())),
        })
        .await;
        assert!(app.ai.agent.is_none());
        app.handle_ai_event(Event {
            generation: run,
            kind: EventKind::AgentTick,
        })
        .await;
        app.handle_ai_action(Action::Select(id)).await;
        app.advance_ai_agent().await;
        assert!(app.ai.agent.is_none() && app.ai.review.is_none() && app.dialog.is_none());
        assert_eq!(app.settings.workspace.terminal_layout, layout);
        app.shutdown().await.unwrap();
        app.store.shutdown().await.unwrap();
    }
}
