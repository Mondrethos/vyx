//! Host-owned AI surface. It emits intent; the application owns all reads, requests and approvals.
use super::{
    form::{self, Field, Form, FormHitRegion},
    render::contains,
    widgets::{self, Button},
};
use crate::{
    ai::{self, AiData, ApiStyle, Capability, Config, Conversation, Feature, PermissionLevel, Profile, ProviderKind, Role},
    shortcuts::{Bindings, Shortcut},
    theme::Palette,
    vault::Secret,
};
use anyhow::{Context, Result, ensure};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use ratatui::{
    Frame,
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;
use zeroize::Zeroizing;
pub const MIN_WIDTH: u16 = ai::MIN_PANEL_WIDTH;
/// Most recent output lines shown per action result block; the rest stay in message details.
const RESULT_PREVIEW_LINES: usize = 12;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Chat,
    Settings,
    Guide,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Addon {
    Missing,
    Disabled,
    Official,
    Development,
    DevelopmentInactive,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Naming {
    Original,
    Ai,
    Manual,
    Paused,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CaptureKind {
    Snapshot,
    Scrollback,
    Metadata,
}
pub struct SessionInfo {
    pub id: Uuid,
    pub label: String,
    pub server: String,
    pub connected: bool,
    pub phase: String,
    pub naming: Naming,
}
pub struct HostInfo {
    pub id: Uuid,
    pub label: String,
    pub address: String,
    pub port: u16,
}
#[derive(Clone)]
pub struct Draft {
    pub token: u64,
    pub attachment: ai::Attachment,
}
/// What an active bounded run is doing, for the panel header and Stop control.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AgentStatus {
    Working { step: u16, limit: u16 },
    Approval,
    Output,
    Connection,
}
impl AgentStatus {
    fn label(self) -> String {
        match self {
            Self::Working { step, limit } => format!("Working · step {step}/{limit}"),
            Self::Approval => "Waiting for approval".into(),
            Self::Output => "Waiting for terminal output".into(),
            Self::Connection => "Waiting for connection".into(),
        }
    }
}
/// An explicit request that checked a provider profile; a failure retries exactly this request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Check {
    Test,
    Models,
    Install,
    SignIn,
    Account,
}
impl Check {
    fn label(self) -> &'static str {
        match self {
            Self::Test => "Connection test",
            Self::Models => "Model discovery",
            Self::Install => "Helper installation",
            Self::SignIn => "Sign-in",
            Self::Account => "Account check",
        }
    }

    fn retry(self, profile: Uuid) -> Action {
        match self {
            Self::Test => Action::TestProfile(profile),
            Self::Models => Action::DiscoverModels(profile),
            Self::Install => Action::InstallCodex(profile),
            Self::SignIn => Action::CodexLogin { profile, method: ai::codex::LoginMethod::DeviceCode },
            Self::Account => Action::CodexStatus(profile),
        }
    }
}
/// Latest outcome of each explicit check by profile: `Ok` summary or `Err` reason.
pub type Checks = BTreeMap<(Uuid, Check), Result<String, String>>;
pub struct View<'a> {
    pub data: &'a AiData,
    pub addon: Addon,
    pub focused: bool,
    pub streaming: Option<Uuid>,
    pub task: Option<&'a str>,
    pub sessions: &'a [SessionInfo],
    pub hosts: &'a [HostInfo],
    pub models: &'a BTreeMap<Uuid, Vec<String>>,
    pub checks: &'a Checks,
    pub suggestions: &'a BTreeMap<Uuid, String>,
    /// Installed-helper metadata presence for Codex profiles, refreshed outside drawing.
    pub helpers: &'a BTreeMap<Uuid, bool>,
    pub agent: Option<AgentStatus>,
    /// Level and scope of the not-yet-sent chat shown when no conversation is selected.
    pub unsent_permission: PermissionLevel,
    pub unsent_sessions: &'a [Uuid],
}
impl View<'_> {
    fn level_and_scope<'b>(&'b self, conversation: Option<&'b Conversation>) -> (PermissionLevel, &'b [Uuid]) {
        conversation.map_or((self.unsent_permission, self.unsent_sessions), |c| (c.permission, c.sessions.as_slice()))
    }
}
pub struct AiRender<'a> {
    pub panel: &'a mut Panel,
    pub view: View<'a>,
}
pub enum Action {
    None,
    Close,
    Unfocus,
    Resize(u16),
    Copy(String),
    New {
        temporary: bool,
    },
    Select(Uuid),
    Rename {
        conversation: Uuid,
        title: String,
    },
    Delete(Uuid),
    DeleteAll,
    Search(String),
    Export {
        conversation: Uuid,
        path: String,
    },
    Send {
        conversation: Option<Uuid>,
        text: String,
        attachments: Vec<Draft>,
    },
    /// Stops the reply, any bounded run, and run-owned reviews.
    Stop,
    Retry(Uuid),
    Regenerate(Uuid),
    Edit {
        conversation: Uuid,
        index: usize,
        text: String,
    },
    SwitchModel {
        conversation: Uuid,
        profile: Uuid,
        model: String,
    },
    Capture {
        session: Uuid,
        kind: CaptureKind,
    },
    Insert {
        session: Uuid,
        command: String,
    },
    Execute {
        session: Uuid,
        command: String,
    },
    Connect {
        host: Uuid,
    },
    Template(usize),
    SuggestTitle {
        conversation: Uuid,
    },
    AcceptTitle {
        session: Uuid,
    },
    RejectTitle {
        session: Uuid,
    },
    PauseNaming(Uuid),
    ResumeNaming(Uuid),
    RestoreTitle(Uuid),
    SetConfig(Config),
    /// The Permissions form; applied only after validation (and Full consent when raised).
    SetPermissions {
        default_permission: PermissionLevel,
        max_permission: PermissionLevel,
        capabilities: BTreeSet<Capability>,
        agent_steps: u16,
    },
    /// Level of the selected (or unsent) chat, bounded by the Settings maximum.
    SetPermission(PermissionLevel),
    /// Adds or removes a live session from the selected (or unsent) chat's scope.
    ToggleScope(Uuid),
    SaveProfile(Profile),
    /// Guided provider setup; `discover` consents to one model-list request after saving.
    SaveSetupProfile {
        profile: Profile,
        discover: bool,
    },
    DeleteProfile(Uuid),
    TestProfile(Uuid),
    DiscoverModels(Uuid),
    InstallCodex(Uuid),
    CodexLogin {
        profile: Uuid,
        method: ai::codex::LoginMethod,
    },
    CodexStatus(Uuid),
    CodexLogout(Uuid),
    CancelTask,
    /// Opens Settings / Extensions at the Vyx AI package.
    OpenExtensionSettings,
}

/// The next thing to do before chatting, computed from the current view without I/O.
/// `Ready` means configuration is complete, not that an account check succeeded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetupStep {
    Activate,
    TurnOn,
    AddProvider,
    ChooseDefault,
    CodexHelper(Uuid),
    SignIn(Uuid),
    ApiKey(Uuid),
    Endpoint(Uuid),
    ChooseModel(Uuid),
    Permissions,
    Ready,
}

const SETUP_STAGES: [&str; 7] = [
    "Activate the Vyx AI package",
    "Turn on Vyx AI and chat",
    "Add a provider",
    "Choose the default provider",
    "Finish provider sign-in, key, or model",
    "Choose permissions",
    "Start chatting",
];

impl SetupStep {
    fn stage(self) -> usize {
        match self {
            Self::Activate => 0,
            Self::TurnOn => 1,
            Self::AddProvider => 2,
            Self::ChooseDefault => 3,
            Self::CodexHelper(_) | Self::SignIn(_) | Self::ApiKey(_) | Self::Endpoint(_) | Self::ChooseModel(_) => 4,
            Self::Permissions => 5,
            Self::Ready => 6,
        }
    }

    fn detail(self) -> &'static str {
        match self {
            Self::Activate => "Review and enable the package in Settings / Extensions. Local settings stay available meanwhile.",
            Self::TurnOn => "Turns on Master AI and the chat switch. Nothing is sent until you send a message.",
            Self::AddProvider => "Choose an API provider or a ChatGPT subscription. Credentials are entered natively.",
            Self::ChooseDefault => "New chats use the default profile. Vyx never falls back to another provider.",
            Self::CodexHelper(_) => "Install the isolated, tool-free Codex helper (reviewed download).",
            Self::SignIn(_) => "Sign in with ChatGPT using a device code. A browser sign-in is also offered.",
            Self::ApiKey(_) => "Enter the API key natively. It is stored only in this device's encrypted state.",
            Self::Endpoint(_) => "Enter the compatible endpoint's base URL.",
            Self::ChooseModel(_) => "Discover models with an explicit request, or enter a model ID manually.",
            Self::Permissions => "Choose what new chats may do and the maximum any chat may reach. Assist is recommended.",
            Self::Ready => "Configuration is complete. Start chatting; account problems still show when a request fails.",
        }
    }
}

pub fn setup_step(view: &View) -> SetupStep {
    let config = &view.data.config;
    if matches!(view.addon, Addon::Disabled | Addon::DevelopmentInactive) {
        return SetupStep::Activate;
    }
    if !config.enabled || !config.is_on(Feature::Chat) {
        return SetupStep::TurnOn;
    }
    if view.data.profiles.is_empty() {
        return SetupStep::AddProvider;
    }
    let Some(profile) = view.data.default_profile() else {
        return SetupStep::ChooseDefault;
    };
    let id = profile.id;
    if profile.kind == ProviderKind::Codex {
        if !view.helpers.get(&id).copied().unwrap_or(false) {
            return SetupStep::CodexHelper(id);
        }
        if profile.codex_auth.is_none() {
            return SetupStep::SignIn(id);
        }
    } else {
        if profile.kind.requires_credential() && profile.credential.is_none() {
            return SetupStep::ApiKey(id);
        }
        if profile.kind == ProviderKind::Compatible && profile.base_url.is_empty() {
            return SetupStep::Endpoint(id);
        }
        if profile.model.is_empty() {
            return SetupStep::ChooseModel(id);
        }
    }
    if !config.permissions_confirmed {
        return SetupStep::Permissions;
    }
    SetupStep::Ready
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Menu {
    Commands,
    Conversations,
    Settings,
    Guide,
    Permissions,
    Features(&'static str),
    Sessions,
    Profiles,
    AddProvider,
    Profile(Uuid),
    Models(Uuid),
    SwitchProfiles,
    Context,
    Session(Uuid),
    Templates,
    Messages,
    Message(usize),
    Attachments,
    Status,
}
impl Menu {
    /// Where Esc and Back go; `None` returns to the chat.
    fn parent(self) -> Option<Self> {
        match self {
            Self::Commands | Self::Settings | Self::Guide | Self::Attachments => None,
            Self::Conversations
            | Self::SwitchProfiles
            | Self::Sessions
            | Self::Context
            | Self::Templates
            | Self::Messages
            | Self::Status => Some(Self::Commands),
            Self::Profiles | Self::Permissions | Self::Features(_) => Some(Self::Settings),
            Self::AddProvider | Self::Profile(_) => Some(Self::Profiles),
            Self::Models(id) => Some(Self::Profile(id)),
            Self::Session(_) => Some(Self::Context),
            Self::Message(_) => Some(Self::Messages),
        }
    }
    /// The header category: 0 chat, 1 commands, 2 settings.
    fn category(self) -> usize {
        let mut menu = self;
        while let Some(parent) = menu.parent() {
            menu = parent;
        }
        match menu {
            Self::Commands => 1,
            Self::Settings | Self::Guide => 2,
            _ => 0,
        }
    }
}
enum Command {
    Emit(Action),
    Menu(Menu),
    Chat,
    Expand,
    Master,
    TurnOn,
    Toggle(Feature),
    Limits,
    Permissions,
    Default(Uuid),
    Profile(Profile),
    Setup(Profile),
    Rename,
    Search,
    Export,
    Switch(Uuid),
    Model(Uuid, String),
    ManualModel(Uuid),
    Edit(usize),
    Attachment(usize),
    RemoveAttachment(usize),
    StartChatting,
    /// Runs `action` and returns to the guide once the application acknowledges it.
    Guided(Box<Command>),
}
struct Row {
    label: String,
    detail: String,
    command: Command,
}
impl Row {
    fn new(label: impl Into<String>, detail: impl Into<String>, command: Command) -> Self {
        Self {
            label: label.into(),
            detail: detail.into(),
            command,
        }
    }
}
enum EditForm {
    Profile(Profile),
    /// Short guided form: name, API key where accepted, base URL for compatible endpoints.
    Setup(Profile),
    Model(Profile),
    Limits,
    Permissions,
    Rename(Uuid),
    Search,
    Export(Uuid),
    Switch { conversation: Uuid, profile: Uuid },
}
struct FormState {
    kind: EditForm,
    form: Form,
}
#[derive(Clone, Copy)]
enum Hit {
    Commands,
    Chat,
    Settings,
    Send,
    Stop,
    Close,
    Composer,
    Transcript,
    Row(usize),
    Attachments,
    Back,
    Permission,
    Sessions,
}

#[derive(Default)]
struct Composer {
    text: Zeroizing<String>,
    cursor: usize,
}
impl Composer {
    fn set(&mut self, text: &str) {
        self.text = Zeroizing::new(text.to_owned());
        self.cursor = self.text.len();
    }
    fn insert(&mut self, text: &str) {
        let remaining = ai::MAX_MESSAGE_BYTES.saturating_sub(self.text.len());
        let filtered: String = text
            .chars()
            .filter(|c| !c.is_control() || matches!(c, '\n' | '\t'))
            .collect();
        let mut end = filtered.len().min(remaining);
        while !filtered.is_char_boundary(end) {
            end -= 1;
        }
        self.text.insert_str(self.cursor, &filtered[..end]);
        self.cursor += end;
    }
    fn key(&mut self, key: KeyEvent, bindings: &Bindings) {
        let previous = self.text[..self.cursor]
            .char_indices()
            .next_back()
            .map_or(0, |(n, _)| n);
        let next = self.text[self.cursor..]
            .chars()
            .next()
            .map_or(self.cursor, |c| self.cursor + c.len_utf8());
        if bindings.matches(Shortcut::CursorLeft, key) {
            self.cursor = previous;
        } else if bindings.matches(Shortcut::CursorRight, key) {
            self.cursor = next;
        } else if bindings.matches(Shortcut::Home, key) {
            self.cursor = self.text[..self.cursor].rfind('\n').map_or(0, |n| n + 1);
        } else if bindings.matches(Shortcut::End, key) {
            self.cursor += self.text[self.cursor..]
                .find('\n')
                .unwrap_or(self.text.len() - self.cursor);
        } else if bindings.matches(Shortcut::Backspace, key) {
            self.text.replace_range(previous..self.cursor, "");
            self.cursor = previous;
        } else if bindings.matches(Shortcut::Delete, key) {
            self.text.replace_range(self.cursor..next, "");
        } else if bindings.matches(Shortcut::ClearField, key) {
            self.set("");
        } else if bindings.matches(Shortcut::AiNewline, key) {
            self.insert("\n");
        } else if bindings.matches(Shortcut::AiUp, key) || bindings.matches(Shortcut::AiDown, key) {
            let start = self.text[..self.cursor].rfind('\n').map_or(0, |n| n + 1);
            let column = self.text[start..self.cursor].chars().count();
            let destination = if bindings.matches(Shortcut::AiUp, key) {
                (start > 0).then(|| {
                    let end = start - 1;
                    (self.text[..end].rfind('\n').map_or(0, |n| n + 1), end)
                })
            } else {
                self.text[self.cursor..].find('\n').map(|n| {
                    let begin = self.cursor + n + 1;
                    (
                        begin,
                        begin
                            + self.text[begin..]
                                .find('\n')
                                .unwrap_or(self.text.len() - begin),
                    )
                })
            };
            if let Some((begin, end)) = destination {
                self.cursor = begin
                    + self.text[begin..end]
                        .char_indices()
                        .nth(column)
                        .map_or(end - begin, |(n, _)| n);
            }
        } else if let KeyCode::Char(c) = key.code
            && !key
                .modifiers
                .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
            && !c.is_control()
        {
            self.insert(&c.to_string());
        }
    }
}

pub struct Panel {
    open: bool,
    expanded: bool,
    area: Rect,
    selected: Option<Uuid>,
    composer: Composer,
    editing: Option<(Uuid, usize)>,
    drafts: Vec<Draft>,
    attachment: Option<(usize, Composer)>,
    reviewed: BTreeSet<u64>,
    menu: Option<Menu>,
    rows: Vec<Row>,
    row: usize,
    rebuild: bool,
    form: Option<FormState>,
    form_hits: Vec<FormHitRegion>,
    hits: Vec<(Rect, Hit)>,
    search: Option<Vec<Uuid>>,
    status: String,
    error: bool,
    scroll: u16,
    transcript_focus: bool,
    /// A profile form whose values stay until the application acknowledges the save.
    pending_save: Option<Uuid>,
    /// A flow started from the setup guide returns there once it completes.
    guide_return: bool,
}
impl Default for Panel {
    fn default() -> Self {
        Self::new()
    }
}
impl Panel {
    pub fn new() -> Self {
        Self {
            open: false,
            expanded: false,
            area: Rect::default(),
            selected: None,
            composer: Composer::default(),
            editing: None,
            drafts: Vec::new(),
            reviewed: BTreeSet::new(),
            attachment: None,
            menu: None,
            rows: Vec::new(),
            row: 0,
            rebuild: true,
            form: None,
            form_hits: Vec::new(),
            hits: Vec::new(),
            search: None,
            status: String::new(),
            error: false,
            scroll: 0,
            transcript_focus: false,
            pending_save: None,
            guide_return: false,
        }
    }
    pub fn has_error(&self) -> bool {
        self.error
    }
    pub fn open(&mut self, tab: Tab) {
        self.open = true;
        self.menu = match tab {
            Tab::Chat => None,
            Tab::Settings => Some(Menu::Settings),
            Tab::Guide => Some(Menu::Guide),
        };
        self.form = None;
        self.pending_save = None;
        self.guide_return = false;
        self.row = 0;
        self.rebuild = true;
    }
    pub fn close(&mut self) {
        self.open = false;
        self.form = None;
        self.pending_save = None;
        self.guide_return = false;
        self.attachment = None;
        self.drafts.clear();
        self.reviewed.clear();
        self.composer.set("");
        self.editing = None;
    }
    pub fn is_open(&self) -> bool {
        self.open
    }
    pub fn expanded(&self) -> bool {
        self.expanded
    }
    pub fn selected(&self) -> Option<Uuid> {
        self.selected
    }
    pub fn select(&mut self, conversation: Option<Uuid>) {
        self.selected = conversation;
        self.sent();
        self.menu = None;
        self.form = None;
        self.pending_save = None;
        self.scroll = 0;
        self.rebuild = true;
    }
    /// The application stored the profile from the open profile or setup form.
    pub fn profile_saved(&mut self, id: Uuid) {
        if self.pending_save.take() != Some(id) {
            return;
        }
        self.form = None;
        if std::mem::take(&mut self.guide_return) {
            self.navigate(Menu::Guide);
        } else if !matches!(self.menu, Some(Menu::Models(_))) {
            self.navigate(Menu::Profile(id));
        }
        self.rebuild = true;
    }
    /// The save failed or its routing review was declined: keep every value and show why.
    pub fn profile_save_failed(&mut self, message: String) {
        self.pending_save = None;
        match &mut self.form {
            Some(state) if matches!(state.kind, EditForm::Profile(_) | EditForm::Setup(_) | EditForm::Model(_)) => {
                state.form.error = message;
            }
            _ => self.set_error(message),
        }
    }
    /// The application applied the Permissions form.
    pub fn permissions_applied(&mut self) {
        if matches!(self.form.as_ref().map(|state| &state.kind), Some(EditForm::Permissions)) {
            self.form = None;
            if std::mem::take(&mut self.guide_return) {
                self.navigate(Menu::Guide);
            } else {
                self.navigate(Menu::Settings);
            }
        }
    }
    /// Keeps the Permissions draft and shows why it was not applied.
    pub fn permissions_failed(&mut self, message: String) {
        match &mut self.form {
            Some(state) if matches!(state.kind, EditForm::Permissions) => state.form.error = message,
            _ => self.set_error(message),
        }
    }
    /// Opens the Permissions form, for example when a level is chosen before confirmation.
    pub fn open_permissions(&mut self, view: &View) {
        self.navigate(Menu::Permissions);
        self.form = Some(permissions_form(&view.data.config));
    }
    pub fn add_attachment(&mut self, draft: Draft) {
        self.reviewed.remove(&draft.token);
        let token = draft.token;
        if let Some(existing) = self.drafts.iter_mut().find(|d| d.token == draft.token) {
            *existing = draft;
        } else {
            self.drafts.push(draft);
        }
        let index = self
            .drafts
            .iter()
            .position(|draft| draft.token == token)
            .expect("attachment inserted");
        let mut editor = Composer::default();
        editor.set(&self.drafts[index].attachment.text);
        self.attachment = Some((index, editor));
        self.menu = Some(Menu::Attachments);
        self.row = 0;
        self.rebuild = true;
    }
    pub fn retain_attachments(&mut self, mut keep: impl FnMut(&Draft) -> bool) {
        self.drafts.retain(|d| keep(d));
        self.reviewed
            .retain(|token| self.drafts.iter().any(|d| d.token == *token));
        self.attachment = None;
        self.rebuild = true;
    }
    pub fn insert(&mut self, text: &str) {
        self.composer.insert(text);
        self.menu = None;
    }
    pub fn sent(&mut self) {
        self.composer.set("");
        self.drafts.clear();
        self.reviewed.clear();
        self.attachment = None;
        self.editing = None;
        self.scroll = 0;
    }
    pub fn set_status(&mut self, text: String) {
        self.status = text;
        self.error = false;
        self.rebuild = true;
    }
    pub fn set_error(&mut self, text: String) {
        self.status = text;
        self.error = true;
        self.rebuild = true;
    }
    /// Configuration, task, or package state changed: guide and setting rows must recompute.
    pub fn invalidate(&mut self) {
        self.rebuild = true;
    }
    pub fn set_search(&mut self, results: Option<Vec<Uuid>>) {
        self.search = results;
        self.menu = Some(Menu::Conversations);
        self.row = 0;
        self.rebuild = true;
    }
    pub fn reset(&mut self) {
        *self = Self::new();
    }
    fn conversation<'a>(&self, view: &'a View) -> Option<&'a Conversation> {
        self.selected
            .and_then(|id| view.data.conversations.iter().find(|c| c.id == id))
    }
    fn navigate(&mut self, menu: Menu) {
        self.menu = Some(menu);
        self.row = 0;
        self.rebuild = true;
        self.form = None;
        self.pending_save = None;
    }
    /// Esc and Back: one level up, or out of menus to the chat.
    fn back(&mut self) {
        self.attachment = None;
        match self.menu.and_then(Menu::parent) {
            Some(parent) => self.navigate(parent),
            None => {
                self.menu = None;
                self.guide_return = false;
            }
        }
    }
    /// The chip and the permission shortcut: next level up to the ceiling, or the
    /// Permissions form while permissions are unconfirmed.
    fn cycle_permission(&mut self, view: &View) -> Action {
        let config = &view.data.config;
        if !config.permissions_confirmed {
            self.open_permissions(view);
            return Action::None;
        }
        let (current, _) = view.level_and_scope(self.conversation(view));
        let next = PermissionLevel::ALL
            .iter()
            .cycle()
            .skip_while(|level| **level != current)
            .skip(1)
            .find(|level| **level <= config.max_permission)
            .copied()
            .unwrap_or(PermissionLevel::ChatOnly);
        Action::SetPermission(next)
    }
    fn emit_send(&mut self) -> Action {
        if self
            .drafts
            .iter()
            .any(|draft| !self.reviewed.contains(&draft.token))
        {
            self.navigate(Menu::Attachments);
            self.set_error("Review and keep each exact attachment before sending.".into());
            return Action::None;
        }
        if let Some((conversation, index)) = self.editing {
            Action::Edit {
                conversation,
                index,
                text: self.composer.text.to_string(),
            }
        } else {
            Action::Send {
                conversation: self.selected,
                text: self.composer.text.to_string(),
                attachments: self.drafts.clone(),
            }
        }
    }
    pub fn paste(&mut self, text: &str, _view: &View) -> Action {
        if let Some(form) = &mut self.form {
            form.form.paste(text);
        } else if let Some((_, editor)) = &mut self.attachment {
            editor.insert(text);
        } else if self.menu.is_none() {
            self.composer.insert(text);
        }
        Action::None
    }
    pub fn key(&mut self, key: KeyEvent, bindings: &Bindings, view: &View) -> Action {
        if bindings.matches(Shortcut::AiStop, key) {
            return if view.task.is_some() && view.streaming.is_none() && view.agent.is_none() {
                Action::CancelTask
            } else {
                Action::Stop
            };
        }
        if let Some(form) = &mut self.form {
            let action = form.form.key(key, bindings);
            return self.form_action(action, view);
        }
        if let Some((index, editor)) = &mut self.attachment {
            if bindings.matches(Shortcut::Cancel, key) {
                self.attachment = None;
                return Action::None;
            }
            if bindings.matches(Shortcut::AiSend, key) {
                if let Some(draft) = self.drafts.get_mut(*index) {
                    draft.attachment.text = editor.text.to_string();
                    self.reviewed.insert(draft.token);
                }
                self.attachment = None;
                self.set_status(
                    "Attachment reviewed. Send includes exactly the edited attachment below."
                        .into(),
                );
                return Action::None;
            }
            editor.key(key, bindings);
            return Action::None;
        }
        if bindings.matches(Shortcut::AiCommands, key) {
            self.navigate(Menu::Commands);
            return Action::None;
        }
        if bindings.matches(Shortcut::AiPermission, key) {
            return self.cycle_permission(view);
        }
        if bindings.matches(Shortcut::Cancel, key) {
            if self.menu.is_some() {
                self.back();
                return Action::None;
            }
            return Action::Unfocus;
        }
        if self.menu.is_some() {
            if self.rebuild {
                self.build_rows(view);
            }
            if bindings.matches(Shortcut::AiUp, key) {
                self.row = self.row.saturating_sub(1);
            } else if bindings.matches(Shortcut::AiDown, key) {
                self.row = (self.row + 1).min(self.rows.len().saturating_sub(1));
            } else if bindings.matches(Shortcut::AiPageUp, key) {
                self.row = self.row.saturating_sub(10);
            } else if bindings.matches(Shortcut::AiPageDown, key) {
                self.row = (self.row + 10).min(self.rows.len().saturating_sub(1));
            } else if bindings.matches(Shortcut::AiSend, key) {
                return self.activate(view);
            }
            return Action::None;
        }
        if bindings.matches(Shortcut::AiNextArea, key)
            || bindings.matches(Shortcut::AiPreviousArea, key)
        {
            self.transcript_focus = !self.transcript_focus;
            return Action::None;
        }
        if bindings.matches(Shortcut::AiPageUp, key) {
            self.scroll = self.scroll.saturating_add(10);
            return Action::None;
        }
        if bindings.matches(Shortcut::AiPageDown, key) {
            self.scroll = self.scroll.saturating_sub(10);
            return Action::None;
        }
        if self.transcript_focus {
            if bindings.matches(Shortcut::AiSend, key) {
                self.navigate(Menu::Messages);
            } else if bindings.matches(Shortcut::AiUp, key) {
                self.scroll = self.scroll.saturating_add(1);
            } else if bindings.matches(Shortcut::AiDown, key) {
                self.scroll = self.scroll.saturating_sub(1);
            }
            return Action::None;
        }
        if bindings.matches(Shortcut::AiSend, key) {
            return self.emit_send();
        }
        self.composer.key(key, bindings);
        Action::None
    }
    pub fn mouse(&mut self, mouse: MouseEvent, view: &View) -> Action {
        if let Some(form) = &mut self.form {
            let action = form.form.mouse(mouse, &self.form_hits);
            return self.form_action(action, view);
        }
        if matches!(
            mouse.kind,
            MouseEventKind::ScrollUp | MouseEventKind::ScrollDown
        ) {
            let up = mouse.kind == MouseEventKind::ScrollUp;
            if self.menu.is_some() {
                self.row = if up {
                    self.row.saturating_sub(3)
                } else {
                    (self.row + 3).min(self.rows.len().saturating_sub(1))
                };
            } else {
                self.scroll = if up {
                    self.scroll.saturating_add(3)
                } else {
                    self.scroll.saturating_sub(3)
                };
            }
            return Action::None;
        }
        if mouse.kind != MouseEventKind::Down(MouseButton::Left) {
            return Action::None;
        }
        let hit = self
            .hits
            .iter()
            .rev()
            .find(|(area, _)| contains(*area, mouse.column, mouse.row))
            .map(|(_, hit)| *hit);
        match hit {
            Some(Hit::Close) => Action::Close,
            Some(Hit::Send) => {
                if let Some((index, editor)) = self.attachment.take() {
                    if let Some(draft) = self.drafts.get_mut(index) {
                        draft.attachment.text = editor.text.to_string();
                        self.reviewed.insert(draft.token);
                    }
                    self.set_status("Attachment reviewed; Send includes the edited text.".into());
                    Action::None
                } else {
                    self.emit_send()
                }
            }
            Some(Hit::Stop) => {
                if view.task.is_some() && view.streaming.is_none() && view.agent.is_none() {
                    Action::CancelTask
                } else {
                    Action::Stop
                }
            }
            Some(Hit::Commands) => {
                self.navigate(Menu::Commands);
                Action::None
            }
            Some(Hit::Settings) => {
                self.navigate(Menu::Settings);
                Action::None
            }
            Some(Hit::Chat) => {
                self.menu = None;
                self.attachment = None;
                self.guide_return = false;
                Action::None
            }
            Some(Hit::Attachments) => {
                self.navigate(Menu::Attachments);
                Action::None
            }
            Some(Hit::Permission) => self.cycle_permission(view),
            Some(Hit::Sessions) => {
                self.navigate(Menu::Sessions);
                Action::None
            }
            Some(Hit::Row(index)) => {
                self.row = index;
                self.activate(view)
            }
            Some(Hit::Composer) => {
                self.transcript_focus = false;
                Action::None
            }
            Some(Hit::Transcript) => {
                self.transcript_focus = true;
                Action::None
            }
            Some(Hit::Back) => {
                self.back();
                Action::None
            }
            None => Action::None,
        }
    }
    fn build_rows(&mut self, view: &View) {
        self.rebuild = false;
        let mut rows = Vec::new();
        let mut add = |label: String, detail: String, command: Command| {
            rows.push(Row::new(label, detail, command))
        };
        let emit = Command::Emit;
        let nav = Command::Menu;
        let conversation = self.conversation(view);
        let mut select = None;
        match self.menu.unwrap_or(Menu::Commands) {
            Menu::Commands => {
                add(
                    "New conversation".into(),
                    "Encrypted local history; outside vault sync.".into(),
                    emit(Action::New { temporary: false }),
                );
                add(
                    "New temporary conversation".into(),
                    "No messages saved; leaving or closing discards this chat.".into(),
                    emit(Action::New { temporary: true }),
                );
                add(
                    "Conversations / local search".into(),
                    "Open, search, rename or delete retained chats.".into(),
                    nav(Menu::Conversations),
                );
                add(
                    "Sessions in this chat".into(),
                    "Choose which open sessions this chat may address. Switching tabs never changes it.".into(),
                    nav(Menu::Sessions),
                );
                add(
                    "Setup guide".into(),
                    "Step-by-step: activation, provider, sign-in or key, model, and permissions.".into(),
                    nav(Menu::Guide),
                );
                add(
                    "Provider profiles and settings".into(),
                    "Permissions, profiles, chat features, naming, history and limits.".into(),
                    nav(Menu::Settings),
                );
                add(
                    "Prompt templates".into(),
                    "Inserts a prompt; never sends anything by itself.".into(),
                    nav(Menu::Templates),
                );
                add(
                    "Capture context and session names".into(),
                    "Preview a session's screen, output, or metadata for review before sending.".into(),
                    nav(Menu::Context),
                );
                add(
                    format!("Review attachments ({})", self.drafts.len()),
                    ai::REDACTION_DISCLAIMER.into(),
                    nav(Menu::Attachments),
                );
                add(
                    "View / copy full status".into(),
                    "Inspect the complete last status or error locally.".into(),
                    nav(Menu::Status),
                );
                add(
                    "Expand / restore panel".into(),
                    "Full workspace chat without closing SSH sessions.".into(),
                    Command::Expand,
                );
                if let Some(c) = conversation {
                    add(
                        "Messages / copy / command proposals".into(),
                        "Review individual message text and fenced code blocks.".into(),
                        nav(Menu::Messages),
                    );
                    add(
                        "Retry last prompt".into(),
                        "Explicitly requests another reply. Existing history is preserved.".into(),
                        emit(Action::Retry(c.id)),
                    );
                    add(
                        "Regenerate in a new branch".into(),
                        "The original conversation is unchanged.".into(),
                        emit(Action::Regenerate(c.id)),
                    );
                    add("Switch provider / model (review)".into(), "Preview which history will go to the new recipient; nothing sent on switch.".into(), nav(Menu::SwitchProfiles));
                    add(
                        "Suggest session tab title".into(),
                        "Explicit provider request for the first in-scope session's tab.".into(),
                        emit(Action::SuggestTitle { conversation: c.id }),
                    );
                    add(
                        "Rename conversation".into(),
                        "Local conversation name, independent of session tabs.".into(),
                        Command::Rename,
                    );
                    add(
                        "Export plaintext transcript".into(),
                        ai::EXPORT_WARNING.into(),
                        Command::Export,
                    );
                    add(
                        "Delete conversation (review)".into(),
                        "Deletes local history, not existing exports.".into(),
                        emit(Action::Delete(c.id)),
                    );
                }
                if view.streaming.is_some() || view.agent.is_some() {
                    add(
                        "Stop reply and actions".into(),
                        "Stops the reply and any queued actions. Already submitted terminal input is not undone; charges are not reversed.".into(),
                        emit(Action::Stop),
                    );
                }
                if view.task.is_some() {
                    add(
                        "Cancel current operation".into(),
                        "Stops the explicit test, discovery, install, or sign-in request.".into(),
                        emit(Action::CancelTask),
                    );
                }
                add("Close chat panel".into(), "SSH stays connected. Closing ends any run; a background reply may only finish its text.".into(), emit(Action::Close));
            }
            Menu::Conversations => {
                add(
                    "Search local history".into(),
                    "Search is local; it does not call any provider.".into(),
                    Command::Search,
                );
                add(
                    "Clear search".into(),
                    "Show all conversations.".into(),
                    emit(Action::Search(String::new())),
                );
                for c in view
                    .data
                    .conversations
                    .iter()
                    .rev()
                    .filter(|c| self.search.as_ref().is_none_or(|ids| ids.contains(&c.id)))
                {
                    add(
                        c.display_title(),
                        format!(
                            "{} · {} messages{}{}",
                            ai::format_timestamp(c.updated_at),
                            c.messages.len(),
                            if c.temporary {
                                " · TEMPORARY"
                            } else {
                                " · encrypted local"
                            },
                            if c.parent_id.is_some() {
                                " · branch"
                            } else {
                                ""
                            }
                        ),
                        emit(Action::Select(c.id)),
                    );
                }
            }
            Menu::Settings => {
                let step = setup_step(view);
                add(
                    "Setup guide".into(),
                    if step == SetupStep::Ready {
                        "Setup is complete. Review each step or run an explicit connection test.".into()
                    } else {
                        format!("Next: {}", SETUP_STAGES[step.stage()])
                    },
                    nav(Menu::Guide),
                );
                add(
                    format!("Master AI: {}", on(view.data.config.enabled)),
                    if view.addon == Addon::DevelopmentInactive {
                        "Local settings are available. Review the development package in Settings / Extensions before AI requests."
                    } else {
                        "Off stops inference, capture, naming, and every action."
                    }.into(),
                    Command::Master,
                );
                let config = &view.data.config;
                add(
                    "Permissions".into(),
                    if config.permissions_confirmed {
                        format!(
                            "New chats: {} · maximum: {} · {} of 5 capabilities · {} steps",
                            config.default_permission.label(),
                            config.max_permission.label(),
                            config.capabilities.len(),
                            config.agent_steps
                        )
                    } else {
                        "Not set up: every chat is Chat only until you apply permissions.".into()
                    },
                    Command::Permissions,
                );
                add(
                    "Provider profiles".into(),
                    "API billing and subscriptions are distinct; credentials stay native.".into(),
                    nav(Menu::Profiles),
                );
                for (group, detail) in [
                    ("Chat", "Chat, streaming, assistance topics, templates, background replies."),
                    ("Session names", "Title suggestions and automatic tab and conversation naming."),
                    ("History", "Local search, export, and deleting history."),
                    ("Usage", "Usage indicators, context and retention limits, token budget, panel width."),
                ] {
                    add(
                        if group == "Usage" { "Usage and limits".into() } else { group.into() },
                        detail.into(),
                        nav(Menu::Features(group)),
                    );
                }
            }
            Menu::Features(group) => {
                for feature in Feature::ALL.into_iter().filter(|feature| feature.group() == group) {
                    let reason = view.data.config.blocked_reason(feature).unwrap_or_default();
                    add(
                        format!("{}: {}", feature.label(), on(view.data.config.is_on(feature))),
                        format!("{} {}", feature.description(), reason),
                        Command::Toggle(feature),
                    );
                }
                match group {
                    "History" => add(
                        "Delete all history (review)".into(),
                        "Encrypted messages on this device only; exports are not removed.".into(),
                        emit(Action::DeleteAll),
                    ),
                    "Usage" => add(
                        "Context / history / usage limits".into(),
                        "Context characters, retention, token budget warning, panel width, server prefix in tab names.".into(),
                        Command::Limits,
                    ),
                    _ => {}
                }
            }
            Menu::Permissions => {
                add(
                    "Edit permissions".into(),
                    "Default for new chats, maximum allowed, capabilities, and the agent step limit.".into(),
                    Command::Permissions,
                );
            }
            Menu::Sessions => {
                let (_, scope) = view.level_and_scope(conversation);
                for session in view.sessions {
                    let included = scope.contains(&session.id);
                    let primary = scope.first() == Some(&session.id);
                    add(
                        format!("[{}] {}", if included { "x" } else { " " }, session.label),
                        format!(
                            "{} · {}{}",
                            session.server,
                            session.phase,
                            if primary { " · primary" } else { "" }
                        ),
                        emit(Action::ToggleScope(session.id)),
                    );
                }
                if view.sessions.is_empty() {
                    add(
                        "No open sessions".into(),
                        "Open a session from the sidebar, then include it here.".into(),
                        Command::Chat,
                    );
                }
            }
            Menu::Guide => {
                let step = setup_step(view);
                let current = step.stage();
                let busy = view.task;
                for (stage, title) in SETUP_STAGES.iter().enumerate() {
                    let (marker, detail, command) = match stage.cmp(&current) {
                        std::cmp::Ordering::Less => ("✓", "Done.".to_owned(), revisit(stage, view)),
                        std::cmp::Ordering::Equal => match busy {
                            Some(task) if step != SetupStep::Ready => (
                                "▸",
                                format!("Busy: {task} Cancel it to continue."),
                                emit(Action::None),
                            ),
                            _ => ("▸", step.detail().to_owned(), guide_command(step, view)),
                        },
                        std::cmp::Ordering::Greater => ("·", "Pending.".to_owned(), emit(Action::None)),
                    };
                    add(format!("{marker} {title}"), detail, command);
                }
                select = Some(current);
                if busy.is_some() {
                    add(
                        "Cancel current operation".into(),
                        "Stops the running test, discovery, install, or sign-in.".into(),
                        emit(Action::CancelTask),
                    );
                }
                if let SetupStep::SignIn(id) = step
                    && busy.is_none()
                {
                    add(
                        "Sign in with a browser instead".into(),
                        "Vyx shows the official sign-in link for you to open; the callback must reach this computer.".into(),
                        Command::Guided(Box::new(emit(Action::CodexLogin { profile: id, method: ai::codex::LoginMethod::Browser }))),
                    );
                }
                if let Some(profile) = view.data.default_profile() {
                    let mut failed = false;
                    for ((id, check), outcome) in view.checks {
                        if let (true, Err(reason)) = (*id == profile.id, outcome) {
                            failed = true;
                            add(format!("{} failed — retry", check.label()), reason.clone(), emit(check.retry(profile.id)));
                        }
                    }
                    if failed {
                        add(
                            if profile.kind == ProviderKind::Codex { "Sign-in and account options" } else { "Edit profile" }.into(),
                            "Change the key, endpoint, model, or sign-in. Vyx never switches billing after an error.".into(),
                            nav(Menu::Profile(profile.id)),
                        );
                    }
                    if step.stage() > 3 {
                        let last = match view.checks.get(&(profile.id, Check::Test)) {
                            Some(Ok(text)) => text.clone(),
                            Some(Err(reason)) => format!("failed: {reason}"),
                            None => "not run".into(),
                        };
                        add(
                            "Test connection (explicit request)".into(),
                            format!("Contacts {} now. Last result: {last}", profile.recipient()),
                            emit(Action::TestProfile(profile.id)),
                        );
                    }
                }
                add(
                    "Providers and advanced settings".into(),
                    "All profile fields, other providers, and every Vyx AI setting.".into(),
                    nav(Menu::Profiles),
                );
            }
            Menu::Profiles | Menu::SwitchProfiles => {
                let switching = matches!(self.menu, Some(Menu::SwitchProfiles));
                if !switching {
                    add(
                        "Add provider profile".into(),
                        "Choose a separate subscription or API connection.".into(),
                        nav(Menu::AddProvider),
                    );
                }
                for p in &view.data.profiles {
                    let failure = view.checks.iter().find_map(|((id, check), outcome)| match outcome {
                        Err(reason) if *id == p.id => Some(format!("{} failed: {reason}", check.label())),
                        _ => None,
                    });
                    let summary = failure
                        .or_else(|| view.checks.get(&(p.id, Check::Test)).and_then(|outcome| outcome.clone().ok()))
                        .unwrap_or_else(|| "Not tested".into());
                    let detail = format!("{} · {}\n{summary}", p.billing_label(), p.model_label());
                    add(
                        format!(
                            "{}{}",
                            p.name,
                            if view.data.config.default_profile == Some(p.id) {
                                " [default]"
                            } else {
                                ""
                            }
                        ),
                        detail,
                        if switching {
                            Command::Switch(p.id)
                        } else {
                            nav(Menu::Profile(p.id))
                        },
                    );
                }
                if !switching {
                    add(
                        "Anthropic subscription availability".into(),
                        ai::ANTHROPIC_SUBSCRIPTION_NOTICE.into(),
                        emit(Action::None),
                    );
                    add(
                        ai::PROVIDER_REQUEST_GUIDANCE.into(),
                        format!("{}\n{}", ai::PROVIDER_REQUEST_URL, ai::PROVIDER_REQUEST_DETAILS),
                        emit(Action::Copy(ai::PROVIDER_REQUEST_URL.into())),
                    );
                }
            }
            Menu::AddProvider => {
                for kind in ProviderKind::ALL {
                    let profile = Profile::new(kind);
                    add(
                        kind.label().into(),
                        kind.billing_notice().into(),
                        if kind == ProviderKind::Codex {
                            emit(Action::SaveSetupProfile { profile, discover: false })
                        } else {
                            Command::Setup(profile)
                        },
                    );
                }
                add(
                    ai::PROVIDER_REQUEST_GUIDANCE.into(),
                    format!("{}\n{}", ai::PROVIDER_REQUEST_URL, ai::PROVIDER_REQUEST_DETAILS),
                    emit(Action::Copy(ai::PROVIDER_REQUEST_URL.into())),
                );
            }
            Menu::Profile(id) => {
                if let Some(p) = view.data.profiles.iter().find(|p| p.id == id) {
                    add(
                        if p.kind == ProviderKind::Codex {
                            "Edit subscription profile"
                        } else {
                            "Edit profile / replace credential"
                        }
                        .into(),
                        p.kind.billing_notice().into(),
                        Command::Profile(p.clone()),
                    );
                    add(
                        "Set as default for new conversations".into(),
                        "Existing conversations never switch silently.".into(),
                        Command::Default(id),
                    );
                    if p.kind == ProviderKind::Codex {
                        let installed = view.helpers.get(&id).copied().unwrap_or(false);
                        add(
                            if installed { "Helper installed; checked when used" } else { "Install isolated Codex helper (review)" }.into(),
                            if installed {
                                "Choose to reinstall or repair it (review). Every launch still verifies the helper."
                            } else {
                                "Optional Vyx-managed component; no separate Codex CLI installation. Installation does not sign in."
                            }.into(),
                            emit(Action::InstallCodex(id)),
                        );
                        add("Sign in with ChatGPT — device code".into(),
                            "Explicit subscription sign-in for this profile. Open the displayed verification URL yourself; Cancel stops sign-in.".into(),
                            emit(Action::CodexLogin { profile: id, method: ai::codex::LoginMethod::DeviceCode }));
                        add("Sign in with ChatGPT — browser".into(),
                            "Explicit browser sign-in; Vyx displays a URL and does not open it automatically.".into(),
                            emit(Action::CodexLogin { profile: id, method: ai::codex::LoginMethod::Browser }));
                        add("Check subscription account".into(), "Check this profile's Vyx-owned account only; never import an existing Codex account.".into(), emit(Action::CodexStatus(id)));
                        add("Sign out of this subscription profile".into(), "Remove this profile's saved subscription credentials; standalone Codex is unaffected.".into(), emit(Action::CodexLogout(id)));
                        add(
                            "Test connection".into(),
                            "Explicit subscription account check; no inference or server context."
                                .into(),
                            emit(Action::TestProfile(id)),
                        );
                        add(
                            "Choose model (optional)".into(),
                            "Blank uses the Codex default model. Discovery is optional and explicit.".into(),
                            nav(Menu::Models(id)),
                        );
                    } else {
                        add(
                            "Test connection".into(),
                            "Explicit network/account check, no server context.".into(),
                            emit(Action::TestProfile(id)),
                        );
                        add(
                            "Choose or enter model".into(),
                            "Discovered models, an explicit discovery request, or a manual model ID.".into(),
                            nav(Menu::Models(id)),
                        );
                        let mut cleared = p.clone();
                        cleared.credential = None;
                        add(
                            "Remove saved API credential".into(),
                            "Disconnects this profile without deleting conversation history."
                                .into(),
                            emit(Action::SaveProfile(cleared)),
                        );
                    }
                    add(
                        "Delete profile (review)".into(),
                        "Remove its credential; conversations need a reviewed provider switch."
                            .into(),
                        emit(Action::DeleteProfile(id)),
                    );
                }
            }
            Menu::Models(id) => {
                if let Some(p) = view.data.profiles.iter().find(|p| p.id == id) {
                    if let Some(models) = view.models.get(&id) {
                        for model in models {
                            add(
                                format!("{}{model}", if *model == p.model { "[current] " } else { "" }),
                                "Use this model for new conversations of this profile.".into(),
                                Command::Model(id, model.clone()),
                            );
                        }
                    }
                    if p.kind == ProviderKind::Codex {
                        add(
                            "Use Codex default model".into(),
                            "Leaves the model blank so the helper chooses its default.".into(),
                            Command::Model(id, String::new()),
                        );
                    }
                    add(
                        "Discover models (explicit request)".into(),
                        format!("Asks {} for its model list now. Manual IDs remain supported.", p.recipient()),
                        emit(Action::DiscoverModels(id)),
                    );
                    add(
                        "Enter model ID manually".into(),
                        "For endpoints that do not list models, or a model you already know.".into(),
                        Command::ManualModel(id),
                    );
                }
            }
            Menu::Context => {
                for session in view.sessions {
                    add(
                        session.label.clone(),
                        format!(
                            "{} · {}",
                            session.server,
                            if session.connected {
                                "connected"
                            } else {
                                "not connected"
                            }
                        ),
                        nav(Menu::Session(session.id)),
                    );
                }
                for host in view.hosts {
                    add(
                        format!("Connect: {}", host.label),
                        format!(
                            "{}:{} · fresh native approval required",
                            host.address, host.port
                        ),
                        emit(Action::Connect { host: host.id }),
                    );
                }
            }
            Menu::Session(id) => {
                if let Some(session) = view.sessions.iter().find(|s| s.id == id) {
                    for (name, kind) in [
                        ("Preview visible terminal snapshot", CaptureKind::Snapshot),
                        ("Preview bounded recent output", CaptureKind::Scrollback),
                        ("Preview server metadata", CaptureKind::Metadata),
                    ] {
                        add(
                            name.into(),
                            format!(
                                "{} · {}\n{}",
                                session.label,
                                session.server,
                                ai::REDACTION_DISCLAIMER
                            ),
                            emit(Action::Capture { session: id, kind }),
                        );
                    }
                    if let Some(title) = view.suggestions.get(&id) {
                        add(
                            format!("Accept title: {title}"),
                            "Changes only this open session's label.".into(),
                            emit(Action::AcceptTitle { session: id }),
                        );
                        add(
                            "Reject suggested title".into(),
                            "Keeps the existing label.".into(),
                            emit(Action::RejectTitle { session: id }),
                        );
                    }
                    add(
                        "Pause AI naming".into(),
                        "This session only. Manual names stay pinned.".into(),
                        emit(Action::PauseNaming(id)),
                    );
                    add("Resume AI naming / unpin manual title".into(), "Explicitly permits later replies to update this tab.".into(), emit(Action::ResumeNaming(id)));
                    add("Restore original session label".into(), "Restores the local session label and pauses AI naming. Saved server untouched.".into(), emit(Action::RestoreTitle(id)));
                }
            }
            Menu::Templates => {
                for (index, template) in ai::TEMPLATES.iter().enumerate() {
                    add(
                        template.name.into(),
                        template.prompt.into(),
                        emit(Action::Template(index)),
                    );
                }
            }
            Menu::Messages => {
                if let Some(c) = conversation {
                    for (index, message) in c.messages.iter().enumerate() {
                        add(
                            format!(
                                "{} · {}",
                                message.role.label(),
                                ai::bounded_text(&message.text, 70)
                            ),
                            "Open for full-text copy, edit/resend or exact command-block review."
                                .into(),
                            nav(Menu::Message(index)),
                        );
                    }
                }
            }
            Menu::Message(index) => {
                if let Some(c) = conversation
                    && let Some(message) = c.messages.get(index)
                {
                    add(
                        "Copy full message".into(),
                        "Explicit clipboard request to your terminal.".into(),
                        emit(Action::Copy(message.text.clone())),
                    );
                    if message.role == Role::User {
                        add(
                            "Edit and resend in a new branch".into(),
                            "The original history is preserved. Enter sends the edited prompt."
                                .into(),
                            Command::Edit(index),
                        );
                    }
                    // Only ordinary assistant code blocks are offered; action blocks are never
                    // runnable from the transcript, and user or result text is not a proposal.
                    let blocks = if message.role == Role::Assistant {
                        ai::code_blocks(&message.text).into_iter().filter(|block| block.language != ai::actions::ACTION_FENCE).collect()
                    } else {
                        Vec::new()
                    };
                    for (n, block) in blocks.into_iter().enumerate() {
                        add(
                            format!("Copy code block {}", n + 1),
                            block.text.clone(),
                            emit(Action::Copy(block.text.clone())),
                        );
                        for session in view.sessions.iter().filter(|s| s.connected) {
                            add(
                                format!("Insert block {} into {} (review)", n + 1, session.label),
                                format!("{}\n{}", session.server, block.text),
                                emit(Action::Insert {
                                    session: session.id,
                                    command: block.text.clone(),
                                }),
                            );
                            add(
                                format!("Run block {} on {} (review)", n + 1, session.label),
                                format!(
                                    "{}\n{}\nFresh approval for this command only.",
                                    session.server, block.text
                                ),
                                emit(Action::Execute {
                                    session: session.id,
                                    command: block.text.clone(),
                                }),
                            );
                        }
                    }
                }
            }
            Menu::Attachments => {
                for (index, draft) in self.drafts.iter().enumerate() {
                    add(
                        format!(
                            "{}: {}",
                            if self.reviewed.contains(&draft.token) {
                                "Reviewed — edit"
                            } else {
                                "Review required"
                            },
                            draft.attachment.source
                        ),
                        format!(
                            "Session {} · {}\n{}",
                            draft.attachment.session_id,
                            ai::format_timestamp(draft.attachment.captured_at),
                            ai::REDACTION_DISCLAIMER
                        ),
                        Command::Attachment(index),
                    );
                    add(
                        format!("Remove attachment {}", index + 1),
                        "This context will not be sent.".into(),
                        Command::RemoveAttachment(index),
                    );
                }
            }
            Menu::Status => {
                add(
                    "Copy full status".into(),
                    "Explicit clipboard request; terminal clipboard support is required.".into(),
                    emit(Action::Copy(self.status.clone())),
                );
                for (index, line) in self.status.lines().enumerate() {
                    add(
                        format!("{}: {}", index + 1, ai::bounded_text(line, 60)),
                        line.into(),
                        emit(Action::None),
                    );
                }
            }
        }
        if rows.is_empty() {
            rows.push(Row::new(
                "Nothing here yet",
                "Return to chat or choose another command.",
                Command::Chat,
            ));
        }
        self.rows = rows;
        if let Some(row) = select {
            self.row = row;
        }
        self.row = self.row.min(self.rows.len().saturating_sub(1));
    }
    fn activate(&mut self, view: &View) -> Action {
        let Some(row) = self.rows.get_mut(self.row) else {
            return Action::None;
        };
        let command = std::mem::replace(&mut row.command, Command::Emit(Action::None));
        self.rebuild = true;
        self.run(command, view)
    }
    fn run(&mut self, command: Command, view: &View) -> Action {
        match command {
            Command::Emit(action) => {
                if let Action::SaveProfile(profile) | Action::SaveSetupProfile { profile, .. } = &action {
                    self.pending_save = Some(profile.id);
                }
                if !matches!(
                    action,
                    Action::None
                        | Action::SetConfig(_)
                        | Action::SetPermission(_)
                        | Action::ToggleScope(_)
                        | Action::SaveProfile(_)
                        | Action::SaveSetupProfile { .. }
                        | Action::TestProfile(_)
                        | Action::DiscoverModels(_)
                        | Action::InstallCodex(_)
                        | Action::CodexStatus(_)
                        | Action::CodexLogin { .. }
                        | Action::CodexLogout(_)
                        | Action::CancelTask
                        | Action::OpenExtensionSettings
                ) {
                    self.menu = None;
                }
                action
            }
            Command::Menu(menu) => {
                let guided = self.guide_return;
                self.navigate(menu);
                self.guide_return = guided && menu != Menu::Guide;
                Action::None
            }
            Command::Chat => {
                self.menu = None;
                self.guide_return = false;
                Action::None
            }
            Command::Expand => {
                self.expanded = !self.expanded;
                self.menu = None;
                Action::None
            }
            Command::Master => {
                let mut config = view.data.config.clone();
                config.enabled = !config.enabled;
                Action::SetConfig(config)
            }
            Command::TurnOn => {
                let mut config = view.data.config.clone();
                config.enabled = true;
                config.set(Feature::Chat, true);
                Action::SetConfig(config)
            }
            Command::Toggle(feature) => {
                let mut config = view.data.config.clone();
                config.toggle(feature);
                Action::SetConfig(config)
            }
            Command::Default(id) => {
                let mut config = view.data.config.clone();
                config.default_profile = Some(id);
                if std::mem::take(&mut self.guide_return) {
                    self.navigate(Menu::Guide);
                }
                Action::SetConfig(config)
            }
            Command::Limits => {
                let c = &view.data.config;
                let mut form = Form::new(
                    "AI limits and local history",
                    vec![
                        Field::text("Context characters", c.context_chars.to_string()),
                        Field::text(
                            "Retention days (blank = unlimited)",
                            c.retention_days.map(|n| n.to_string()).unwrap_or_default(),
                        ),
                        Field::text(
                            "Token budget warning (blank = none)",
                            c.budget_tokens.map(|n| n.to_string()).unwrap_or_default(),
                        ),
                        Field::text("Panel width", c.panel_width.to_string()),
                        Field::toggle("Server prefix in tab names", c.title_prefix),
                    ],
                );
                form.description = "History is always encrypted and never vault-synced. Subscription quotas are not dollar budgets. Retention deletes local history, not exports.".into();
                self.form = Some(FormState {
                    kind: EditForm::Limits,
                    form,
                });
                Action::None
            }
            Command::Permissions => {
                self.open_permissions(view);
                Action::None
            }
            Command::Profile(profile) => {
                self.open_profile(profile);
                Action::None
            }
            Command::Setup(profile) => {
                self.open_setup(profile);
                Action::None
            }
            Command::Rename => {
                if let Some(c) = self.conversation(view) {
                    self.form = Some(FormState {
                        kind: EditForm::Rename(c.id),
                        form: Form::new(
                            "Rename conversation",
                            vec![Field::text("Title", c.display_title())],
                        ),
                    });
                }
                Action::None
            }
            Command::Search => {
                self.form = Some(FormState {
                    kind: EditForm::Search,
                    form: Form::new(
                        "Search encrypted local history",
                        vec![Field::text("Search text", "")],
                    ),
                });
                Action::None
            }
            Command::Export => {
                if let Some(c) = self.conversation(view) {
                    let mut form = Form::new(
                        "Export transcript",
                        vec![Field::text("New absolute file path", "")],
                    );
                    form.description = ai::EXPORT_WARNING.into();
                    form.submit = "Review export".into();
                    self.form = Some(FormState {
                        kind: EditForm::Export(c.id),
                        form,
                    });
                }
                Action::None
            }
            Command::Switch(profile) => {
                if let Some(c) = self.conversation(view)
                    && let Some(p) = view.data.profiles.iter().find(|p| p.id == profile)
                {
                    let mut form = Form::new(
                        "Switch provider / model",
                        vec![Field::text("Model ID", &p.model)],
                    );
                    form.description = format!(
                        "{} · {}\nNext: preview exactly which conversation history goes to this recipient.",
                        p.name,
                        p.billing_label()
                    );
                    form.submit = "Review switch".into();
                    self.form = Some(FormState {
                        kind: EditForm::Switch {
                            conversation: c.id,
                            profile,
                        },
                        form,
                    });
                }
                Action::None
            }
            Command::Model(id, model) => {
                if let Some(p) = view.data.profiles.iter().find(|p| p.id == id) {
                    let mut p = p.clone();
                    p.model = model;
                    self.pending_save = Some(id);
                    return Action::SaveProfile(p);
                }
                Action::None
            }
            Command::ManualModel(id) => {
                if let Some(p) = view.data.profiles.iter().find(|p| p.id == id) {
                    let mut form = Form::new(
                        format!("Model for {}", p.name),
                        vec![Field::text("Model ID", &p.model)
                            .with_hint("Exactly as the provider names it, for example gpt-5 or my-local-model.")],
                    );
                    form.description = "Saving changes only this profile's model for new conversations. Existing conversations keep theirs.".into();
                    form.submit = "Use model".into();
                    self.form = Some(FormState { kind: EditForm::Model(p.clone()), form });
                }
                Action::None
            }
            Command::Edit(index) => {
                if let Some(c) = self.conversation(view)
                    && let Some(m) = c.messages.get(index)
                {
                    self.composer.set(&m.text);
                    self.editing = Some((c.id, index));
                    self.drafts.clear();
                    self.menu = None;
                    self.transcript_focus = false;
                    self.set_status("Editing prompt; Send creates a visible branch. Original history is unchanged.".into());
                }
                Action::None
            }
            Command::Attachment(index) => {
                if let Some(draft) = self.drafts.get(index) {
                    self.reviewed.remove(&draft.token);
                    let mut editor = Composer::default();
                    editor.set(&draft.attachment.text);
                    self.attachment = Some((index, editor));
                }
                Action::None
            }
            Command::RemoveAttachment(index) => {
                if index < self.drafts.len() {
                    let draft = self.drafts.remove(index);
                    self.reviewed.remove(&draft.token);
                    self.attachment = None;
                }
                Action::None
            }
            Command::StartChatting => {
                self.menu = None;
                self.guide_return = false;
                self.transcript_focus = false;
                self.set_status("Ready. Type a message and send it; the permission chip shows what this chat may do on its own.".into());
                Action::None
            }
            Command::Guided(inner) => {
                self.guide_return = true;
                self.run(*inner, view)
            }
        }
    }
    fn open_profile(&mut self, p: Profile) {
        let mut form = Form::new(
            format!("Provider: {}", p.kind.label()),
            vec![
                Field::text("Profile name", &p.name),
                Field::text("Base URL", &p.base_url),
                Field::text("Model ID (manual or discovered)", &p.model),
                Field::secret("Replace API key (blank keeps saved key)", ""),
                Field::toggle("Remove saved key", false),
                Field::inline(
                    "Request API",
                    ApiStyle::ALL.iter().map(|s| s.label().into()).collect(),
                    usize::from(p.api_style == ApiStyle::Responses),
                ),
                Field::text("Maximum output tokens", p.max_output_tokens.to_string()),
                Field::text(
                    "Temperature (blank = provider default)",
                    p.temperature.map(|n| n.to_string()).unwrap_or_default(),
                ),
                Field::text(
                    "Reasoning effort (blank = provider default)",
                    p.reasoning_effort.as_deref().unwrap_or(""),
                ),
                Field::toggle("Streaming", p.streaming),
                Field::text(
                    "Vyx Codex helper path (blank = managed)",
                    p.codex_path.as_deref().unwrap_or(""),
                ),
            ],
        );
        form.fields[1].visible = p.kind == ProviderKind::Compatible;
        form.fields[3].visible = p.kind != ProviderKind::Codex;
        form.fields[4].visible = p.kind != ProviderKind::Codex;
        form.fields[5].visible = matches!(p.kind, ProviderKind::OpenAi | ProviderKind::Compatible);
        form.fields[6].visible = p.kind != ProviderKind::Codex;
        form.fields[7].visible = p.kind != ProviderKind::Codex;
        form.fields[8].visible = !p.kind.reasoning_efforts().is_empty();
        form.fields[10].visible = p.kind == ProviderKind::Codex;
        form.description = if p.kind == ProviderKind::Codex {
            format!(
                "{}\nUses the optional isolated Vyx Codex helper, not an existing Codex CLI/account. Install the helper and sign in from the profile page. A blank model uses the Codex default model.",
                p.kind.billing_notice()
            )
        } else {
            format!(
                "{}\nCredentials are native-only. Optional model controls are sent only when explicitly set; support varies by model. Leave unsupported controls blank.",
                p.kind.billing_notice()
            )
        };
        self.form = Some(FormState {
            kind: EditForm::Profile(p),
            form,
        });
    }
    /// The short guided form: name, API key where accepted, base URL for compatible endpoints.
    fn open_setup(&mut self, p: Profile) {
        let key_label = if p.kind.requires_credential() { "API key" } else { "API key (optional)" };
        let mut form = Form::new(
            format!("Set up {}", p.kind.label()),
            vec![
                Field::text("Name", &p.name),
                Field::secret(key_label, "").with_hint(if p.credential.is_some() {
                    "Leave blank to keep the saved key. Stored only in this device's encrypted state."
                } else {
                    "Stored only in this device's encrypted state; never shown again."
                }),
                Field::text("Base URL", &p.base_url)
                    .with_hint("For example https://models.example/v1, or http://127.0.0.1:8080/v1 on this computer."),
            ],
        );
        form.fields[1].visible = p.kind.accepts_credential();
        form.fields[2].visible = p.kind == ProviderKind::Compatible;
        form.description = format!(
            "{}\nSave and discover models stores this profile and makes one model-list request. If listing fails or is unsupported, enter a model ID instead.",
            p.kind.billing_notice()
        );
        form.submit = "Save and discover models".into();
        self.form = Some(FormState { kind: EditForm::Setup(p), form });
    }
    fn form_action(&mut self, action: form::Action, view: &View) -> Action {
        match action {
            form::Action::Continue => {
                // A lower ceiling clamps the draft default immediately.
                if let Some(FormState { kind: EditForm::Permissions, form }) = &mut self.form
                    && form.fields[0].choice > form.fields[1].choice
                {
                    form.fields[0].choice = form.fields[1].choice;
                }
                Action::None
            }
            form::Action::Cancel => {
                self.form = None;
                self.pending_save = None;
                if std::mem::take(&mut self.guide_return) {
                    self.navigate(Menu::Guide);
                } else if self.menu == Some(Menu::Permissions) {
                    self.back();
                }
                Action::None
            }
            form::Action::Submit => {
                let result = self.submit_form(view);
                match result {
                    Ok(action) => {
                        let acknowledged = matches!(
                            self.form.as_ref().map(|state| &state.kind),
                            Some(EditForm::Profile(_) | EditForm::Setup(_) | EditForm::Model(_) | EditForm::Permissions)
                        );
                        if acknowledged {
                            if let Action::SaveProfile(profile) | Action::SaveSetupProfile { profile, .. } = &action {
                                self.pending_save = Some(profile.id);
                            }
                        } else {
                            self.form = None;
                        }
                        self.rebuild = true;
                        action
                    }
                    Err(error) => {
                        if let Some(form) = &mut self.form {
                            form.form.error = error.to_string();
                        }
                        Action::None
                    }
                }
            }
        }
    }
    fn submit_form(&self, view: &View) -> Result<Action> {
        let state = self.form.as_ref().context("No form")?;
        let f = &state.form;
        Ok(match &state.kind {
            EditForm::Profile(original) => {
                let mut p = original.clone();
                p.name = f.value(0).trim().into();
                p.base_url = f.value(1).trim().into();
                p.model = f.value(2).trim().into();
                if f.fields[4].checked() {
                    p.credential = None;
                }
                if !f.value(3).is_empty() {
                    p.credential = Some(Secret::new(f.value(3)));
                }
                p.api_style = ApiStyle::ALL[f.fields[5].choice];
                p.max_output_tokens = f
                    .value(6)
                    .parse()
                    .context("Maximum output tokens must be an integer")?;
                p.temperature = optional_number(f.value(7), "Temperature must be a number")?;
                p.reasoning_effort =
                    (!f.value(8).trim().is_empty()).then(|| f.value(8).trim().into());
                p.streaming = f.fields[9].checked();
                p.codex_path = (!f.value(10).trim().is_empty()).then(|| f.value(10).trim().into());
                p.validate()?;
                Action::SaveProfile(p)
            }
            EditForm::Setup(original) => {
                let mut p = original.clone();
                p.name = f.value(0).trim().into();
                if p.kind.accepts_credential() && !f.value(1).is_empty() {
                    p.credential = Some(Secret::new(f.value(1)));
                }
                if p.kind == ProviderKind::Compatible {
                    p.base_url = f.value(2).trim().into();
                    ensure!(!p.base_url.is_empty(), "Enter the endpoint's base URL");
                }
                ensure!(
                    !p.kind.requires_credential() || p.credential.is_some(),
                    "Enter the API key for {}",
                    p.kind.label()
                );
                p.validate()?;
                Action::SaveSetupProfile { profile: p, discover: true }
            }
            EditForm::Model(original) => {
                let mut p = original.clone();
                p.model = f.value(0).trim().into();
                ensure!(
                    !p.model.is_empty() || p.kind == ProviderKind::Codex,
                    "Enter a model ID"
                );
                p.validate()?;
                Action::SaveProfile(p)
            }
            EditForm::Limits => {
                let mut c = view.data.config.clone();
                c.context_chars = f
                    .value(0)
                    .parse()
                    .context("Context limit must be an integer")?;
                c.retention_days = optional_number(f.value(1), "Retention must be an integer")?;
                c.budget_tokens = optional_number(f.value(2), "Budget must be an integer")?;
                c.panel_width = f.value(3).parse().context("Width must be an integer")?;
                c.title_prefix = f.fields[4].checked();
                c.validate()?;
                Action::SetConfig(c)
            }
            EditForm::Permissions => {
                let level = |field: usize| PermissionLevel::ALL.get(f.fields[field].choice).copied().unwrap_or_default();
                let capabilities = Capability::ALL
                    .into_iter()
                    .enumerate()
                    .filter(|(index, _)| f.fields[2 + index].checked())
                    .map(|(_, capability)| capability)
                    .collect();
                let agent_steps = f
                    .value(7)
                    .trim()
                    .parse::<u16>()
                    .ok()
                    .filter(|steps| (1..=ai::MAX_AGENT_STEPS).contains(steps))
                    .with_context(|| format!("Agent step limit must be a whole number from 1 to {}", ai::MAX_AGENT_STEPS))?;
                ensure!(level(0) <= level(1), "The default for new chats cannot exceed the maximum allowed");
                Action::SetPermissions {
                    default_permission: level(0),
                    max_permission: level(1),
                    capabilities,
                    agent_steps,
                }
            }
            EditForm::Rename(id) => Action::Rename {
                conversation: *id,
                title: f.value(0).into(),
            },
            EditForm::Search => Action::Search(f.value(0).into()),
            EditForm::Export(id) => Action::Export {
                conversation: *id,
                path: f.value(0).into(),
            },
            EditForm::Switch {
                conversation,
                profile,
            } => Action::SwitchModel {
                conversation: *conversation,
                profile: *profile,
                model: f.value(0).trim().into(),
            },
        })
    }
    fn button(&mut self, frame: &mut Frame, area: Rect, label: &str, hit: Hit, palette: &Palette) {
        frame.render_widget(
            Paragraph::new(widgets::fit(label, area.width)).style(Style::default().fg(palette.accent)),
            area,
        );
        self.hits.push((area, hit));
    }
    pub fn draw(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        view: &View,
        bindings: &Bindings,
        palette: &Palette,
    ) {
        self.area = area;
        self.hits.clear();
        self.form_hits.clear();
        let block = Block::default()
            .title(if matches!(view.addon, Addon::Development | Addon::DevelopmentInactive) {
                " Vyx AI · unverified development "
            } else {
                " Vyx AI "
            })
            .borders(Borders::ALL)
            .border_style(Style::default().fg(if view.focused {
                palette.accent
            } else {
                palette.border
            }))
            .style(palette.style());
        let inner = block.inner(area);
        frame.render_widget(block, area);
        if inner.width < 8 || inner.height < 5 {
            return;
        }
        let category = self.menu.map_or(0, Menu::category);
        let header = [
            Button::secondary("Chat"),
            Button::secondary("Commands"),
            Button::secondary("Settings"),
            Button::secondary("Close"),
        ];
        let targets = [Hit::Chat, Hit::Commands, Hit::Settings, Hit::Close];
        let hits = &mut self.hits;
        let header_rows = widgets::draw_buttons(
            frame,
            Rect { height: inner.height.min(2), ..inner },
            &header,
            Some(category),
            palette,
            |index, rect| hits.push((rect, targets[index])),
        );
        let status_height = if self.status.is_empty() {
            0
        } else {
            (Paragraph::new(self.status.as_str()).wrap(Wrap { trim: false }).line_count(inner.width) as u16)
                .min(3)
                .min(inner.height.saturating_sub(header_rows + 4))
        };
        if status_height > 0 {
            frame.render_widget(
                Paragraph::new(self.status.as_str())
                    .wrap(Wrap { trim: false })
                    .style(Style::default().fg(if self.error { palette.error } else { palette.muted })),
                Rect::new(inner.x, inner.bottom() - status_height, inner.width, status_height),
            );
        }
        let spacer = u16::from(inner.height > header_rows + status_height + 8);
        let top = inner.y + header_rows + spacer;
        let body = Rect::new(
            inner.x,
            top,
            inner.width,
            inner.bottom().saturating_sub(status_height).saturating_sub(top),
        );
        if let Some(form) = &self.form {
            form.form
                .draw_panel(frame, body, bindings, &mut self.form_hits, palette);
            return;
        }
        if let Some((index, editor)) = &self.attachment {
            let title = self
                .drafts
                .get(*index)
                .map(|d| {
                    format!(
                        "{} · {}",
                        d.attachment.source,
                        ai::format_timestamp(d.attachment.captured_at)
                    )
                })
                .unwrap_or_default();
            let editor_area = Rect::new(body.x, body.y, body.width, body.height.saturating_sub(3));
            draw_editor(frame, editor_area, editor, &title, view.focused, palette);
            frame.render_widget(
                Paragraph::new(ai::REDACTION_DISCLAIMER)
                    .wrap(Wrap { trim: false })
                    .style(Style::default().fg(palette.warning)),
                Rect::new(body.x, body.bottom().saturating_sub(3), body.width, 2),
            );
            self.button(
                frame,
                Rect::new(body.x, body.bottom().saturating_sub(1), body.width, 1),
                &format!("[Keep reviewed attachment: {}]", bindings.primary(Shortcut::AiSend)),
                Hit::Send,
                palette,
            );
            return;
        }
        if self.menu.is_some() {
            if self.rebuild {
                self.build_rows(view);
            }
            let detail_height = 6.min(body.height / 2);
            let count = usize::from(body.height.saturating_sub(detail_height + 1)).max(1);
            let start = self.row.saturating_sub(count - 1);
            for (offset, index) in (start..self.rows.len()).take(count).enumerate() {
                let row_area = Rect::new(body.x, body.y + offset as u16, body.width, 1);
                let row = &self.rows[index];
                let selected = self.row == index;
                let style = if selected {
                    Style::default()
                        .fg(palette.accent)
                        .add_modifier(Modifier::BOLD | Modifier::REVERSED)
                } else {
                    palette.style()
                };
                frame.render_widget(Paragraph::new(widgets::fit(&row.label, row_area.width)).style(style), row_area);
                self.hits.push((row_area, Hit::Row(index)));
            }
            if let Some(row) = self.rows.get(self.row) {
                frame.render_widget(
                    Paragraph::new(row.detail.as_str())
                        .wrap(Wrap { trim: false })
                        .style(Style::default().fg(palette.muted)),
                    Rect::new(
                        body.x,
                        body.bottom().saturating_sub(detail_height + 1),
                        body.width,
                        detail_height,
                    ),
                );
            }
            let help = format!(
                "{} choose · {} back · {}/{}",
                bindings.primary(Shortcut::AiSend),
                bindings.primary(Shortcut::Cancel),
                self.row + 1,
                self.rows.len()
            );
            self.button(
                frame,
                Rect::new(body.x, body.bottom().saturating_sub(1), body.width, 1),
                &help,
                Hit::Back,
                palette,
            );
            return;
        }
        let conversation = self.conversation(view);
        let config = &view.data.config;
        let profile = conversation
            .and_then(|c| c.profile_id)
            .or(config.default_profile)
            .and_then(|id| view.data.profiles.iter().find(|p| p.id == id));
        let state = match view.agent {
            Some(agent) => agent.label(),
            None if view.addon == Addon::Disabled => "Package disabled".into(),
            None if view.addon == Addon::DevelopmentInactive => "Development review required".into(),
            None if !config.enabled => "AI off".into(),
            None if view.streaming.is_some() => "Replying".into(),
            None => "Ready".into(),
        };
        let summary = match profile {
            Some(p) => format!(
                "{state} · {} · {} · {}",
                p.name,
                conversation
                    .map(|c| c.model.as_str())
                    .filter(|model| !model.is_empty())
                    .unwrap_or_else(|| p.model_label()),
                if p.kind == ProviderKind::Codex { "Subscription" } else { "API billing" }
            ),
            None => format!("{state} · No provider · open the setup guide"),
        };
        frame.render_widget(
            Paragraph::new(widgets::fit(&summary, body.width)).style(Style::default().fg(palette.accent)),
            Rect { height: body.height.min(1), ..body },
        );
        let (level, scope) = view.level_and_scope(conversation);
        let effective = config.effective_permission(level);
        let permission = if !config.permissions_confirmed {
            "Permissions: set up".to_owned()
        } else if effective < level {
            format!("{} (limited to {})", level.label(), effective.label())
        } else {
            effective.label().to_owned()
        };
        let live = scope.iter().filter(|id| view.sessions.iter().any(|session| session.id == **id)).count();
        let sessions = format!("Sessions: {live}");
        let chips = [Button::secondary(&permission), Button::secondary(&sessions)];
        let chip_targets = [Hit::Permission, Hit::Sessions];
        let hits = &mut self.hits;
        let chip_rows = widgets::draw_buttons(
            frame,
            Rect::new(body.x, body.y + 1, body.width, body.height.saturating_sub(1).min(2)),
            &chips,
            None,
            palette,
            |index, rect| hits.push((rect, chip_targets[index])),
        );
        let header_height = 1 + chip_rows;
        let composer_height = 6.min(body.height.saturating_sub(header_height + 4));
        let composer_area = Rect::new(
            body.x,
            body.bottom().saturating_sub(composer_height + 1),
            body.width,
            composer_height,
        );
        let transcript = Rect::new(
            body.x,
            body.y + header_height,
            body.width,
            composer_area.y.saturating_sub(body.y + header_height + 1),
        );
        let mut lines = Vec::new();
        if let Some(c) = conversation {
            lines.push(Line::styled(
                format!(
                    "{}{}{}",
                    c.display_title(),
                    if c.temporary {
                        " · TEMPORARY"
                    } else {
                        " · encrypted local"
                    },
                    if c.parent_id.is_some() {
                        " · branch"
                    } else {
                        ""
                    }
                ),
                Style::default().fg(palette.accent),
            ));
            let omitted = ai::context_start(&c.messages, config.context_chars);
            if omitted > 0 {
                lines.push(Line::styled(
                    format!(
                        "Next request omits {omitted} earlier message(s) at the context limit."
                    ),
                    Style::default().fg(palette.warning),
                ));
            }
            let streaming = view.streaming == Some(c.id);
            let last = c.messages.len().saturating_sub(1);
            for (index, message) in c.messages.iter().enumerate() {
                let (label, color) = match message.role {
                    Role::User => ("You", palette.accent),
                    Role::Assistant => ("Vyx AI", palette.accent),
                    Role::Action => ("Vyx actions", palette.info),
                    Role::System => ("Vyx", palette.muted),
                };
                lines.push(Line::styled(label, Style::default().fg(color).add_modifier(Modifier::BOLD)));
                match message.role {
                    Role::Assistant => assistant_markdown(&message.text, streaming && index == last, &mut lines, palette),
                    Role::Action => action_preview(&message.text, &mut lines, palette),
                    Role::User | Role::System => markdown(&message.text, &mut lines, palette),
                }
                lines.push(Line::default());
            }
            if config.allows(Feature::Usage) {
                let usage = c.usage();
                lines.push(Line::styled(
                    if c.messages.iter().any(|message| message.usage.is_some()) {
                        format!(
                            "Reported tokens: {} in / {} out · {}",
                            usage.input_tokens,
                            usage.output_tokens,
                            usage.cost_usd.map_or_else(
                                || "cost unavailable".into(),
                                |n| format!("reported cost ${n:.6}")
                            )
                        )
                    } else {
                        "Token usage unavailable · cost unavailable".into()
                    },
                    Style::default().fg(palette.muted),
                ));
            }
        } else if setup_step(view) != SetupStep::Ready {
            lines.push(Line::styled(
                format!("Setup: {}", SETUP_STAGES[setup_step(view).stage()]),
                Style::default().fg(palette.warning).add_modifier(Modifier::BOLD),
            ));
            lines.push(Line::from(format!(
                "Open the setup guide from Settings, or press {} for commands.",
                bindings.primary(Shortcut::AiCommands)
            )));
        } else {
            lines.push(Line::from("Ask a question, or choose a prompt template."));
            lines.push(Line::from(match effective {
                PermissionLevel::ChatOnly => "Chat only: only your text and reviewed attachments are shared.",
                PermissionLevel::Assist => "Assist: in-scope sessions are read automatically; every change asks first.",
                PermissionLevel::Full => "Full control: ordinary actions on in-scope sessions run without asking.",
            }));
        }
        let paragraph = Paragraph::new(lines).wrap(Wrap { trim: false });
        let total = paragraph
            .line_count(transcript.width)
            .min(usize::from(u16::MAX)) as u16;
        let offset = total
            .saturating_sub(transcript.height)
            .saturating_sub(self.scroll);
        frame.render_widget(paragraph.scroll((offset, 0)), transcript);
        self.hits.push((transcript, Hit::Transcript));
        if composer_area.y > body.y + header_height && !self.drafts.is_empty() {
            let label = format!(
                "Attachments: {} · review/edit before Send",
                self.drafts.len()
            );
            self.button(
                frame,
                Rect::new(body.x, composer_area.y - 1, body.width, 1),
                &label,
                Hit::Attachments,
                palette,
            );
        }
        draw_editor(
            frame,
            composer_area,
            &self.composer,
            if self.editing.is_some() {
                "Edit prompt → new branch"
            } else {
                "Message"
            },
            view.focused && !self.transcript_focus,
            palette,
        );
        self.hits.push((composer_area, Hit::Composer));
        let busy = view.streaming.is_some() || view.task.is_some() || view.agent.is_some();
        let mut controls = vec![Button::primary("Send")];
        if busy {
            controls.push(Button::danger("Stop"));
        }
        let bottom = Rect::new(body.x, body.bottom().saturating_sub(1), body.width, 1);
        let control_targets = [Hit::Send, Hit::Stop];
        let hits = &mut self.hits;
        let mut used = 0;
        widgets::draw_buttons(frame, bottom, &controls, None, palette, |index, rect| {
            used = used.max(rect.right() - bottom.x);
            hits.push((rect, control_targets[index]));
        });
        let hints: Vec<String> = [
            (Shortcut::AiSend, "send"),
            (Shortcut::AiNewline, "newline"),
            (Shortcut::AiCommands, "commands"),
            (Shortcut::AiPermission, "permission"),
        ]
        .into_iter()
        .filter(|(shortcut, _)| !bindings.primary(*shortcut).is_empty())
        .map(|(shortcut, name)| format!("{} {name}", bindings.primary(shortcut)))
        .collect();
        let hint = if busy {
            format!("{} stops · submitted input is not undone", bindings.primary(Shortcut::AiStop))
        } else {
            hints.join(" · ")
        };
        let hint_area = Rect::new(bottom.x + used + 1, bottom.y, bottom.width.saturating_sub(used + 1), 1);
        frame.render_widget(
            Paragraph::new(widgets::fit(&hint, hint_area.width)).style(Style::default().fg(palette.muted)),
            hint_area,
        );
    }
}

fn permissions_form(config: &Config) -> FormState {
    let levels: Vec<String> = PermissionLevel::ALL.iter().map(|level| level.label().to_owned()).collect();
    let index = |level: PermissionLevel| PermissionLevel::ALL.iter().position(|candidate| *candidate == level).unwrap_or(0);
    let mut fields = vec![
        Field::inline("Default for new chats", levels.clone(), index(config.default_permission))
            .with_hint("Each chat can change its level later, up to the maximum."),
        Field::inline("Maximum allowed", levels, index(config.max_permission))
            .with_hint("No chat may exceed this. Raising it to Full control asks for confirmation."),
    ];
    for capability in Capability::ALL {
        fields.push(
            Field::toggle(capability.label(), config.capabilities.contains(&capability)).with_hint(match capability {
                Capability::ReadOutput => "Off: commands may still run, but results report only submission status. Earlier shared text stays in history; start a new chat to exclude it.",
                Capability::RunCommands => "Typing, Enter, and keys in in-scope sessions. High-risk or unclassifiable input always asks first.",
                Capability::Sessions => "Open saved servers (normal host-key and credential prompts) and close sessions.",
                Capability::TabsLayout => "Focus and rename in-scope tabs and change the terminal layout.",
                Capability::ServerDrafts => "Opens the real server editor; nothing is saved until you press Save.",
            }),
        );
    }
    fields.push(
        Field::text("Agent step limit", config.agent_steps.to_string())
            .with_hint("Actions one request may attempt, reads included (1–100). Then send a message to continue."),
    );
    let mut form = Form::new("Vyx AI permissions", fields);
    form.description = "Chat only never shares anything automatically. Assist reads in-scope sessions and asks before every change. Full control runs ordinary actions without asking; high-risk or unclassifiable input, and closing sessions the chat did not open, still ask. Capabilities apply only above Chat only.".into();
    form.submit = "Apply".into();
    FormState { kind: EditForm::Permissions, form }
}

/// What Enter does on the current setup step.
fn guide_command(step: SetupStep, view: &View) -> Command {
    let guided = |command: Command| Command::Guided(Box::new(command));
    match step {
        SetupStep::Activate => Command::Emit(Action::OpenExtensionSettings),
        SetupStep::TurnOn => Command::TurnOn,
        SetupStep::AddProvider => guided(Command::Menu(Menu::AddProvider)),
        SetupStep::ChooseDefault => guided(Command::Menu(Menu::Profiles)),
        SetupStep::CodexHelper(id) => guided(Command::Emit(Action::InstallCodex(id))),
        SetupStep::SignIn(id) => guided(Command::Emit(Action::CodexLogin { profile: id, method: ai::codex::LoginMethod::DeviceCode })),
        SetupStep::ApiKey(id) | SetupStep::Endpoint(id) => match view.data.profile(id) {
            Some(profile) => guided(Command::Setup(profile.clone())),
            None => Command::Emit(Action::None),
        },
        SetupStep::ChooseModel(id) => guided(Command::Menu(Menu::Models(id))),
        SetupStep::Permissions => guided(Command::Permissions),
        SetupStep::Ready => Command::StartChatting,
    }
}

/// Completed setup stages stay reachable for review.
fn revisit(stage: usize, view: &View) -> Command {
    match stage {
        0 => Command::Emit(Action::OpenExtensionSettings),
        1 => Command::Menu(Menu::Settings),
        2 => Command::Menu(Menu::Profiles),
        3 => Command::Menu(Menu::Profiles),
        4 => view.data.config.default_profile.map_or(Command::Menu(Menu::Profiles), |id| Command::Menu(Menu::Profile(id))),
        5 => Command::Guided(Box::new(Command::Permissions)),
        _ => Command::StartChatting,
    }
}

/// Assistant text with action blocks shown as compact summaries; raw JSON stays available
/// through message details. A block still streaming is a neutral pending summary.
fn assistant_markdown<'a>(text: &'a str, streaming: bool, lines: &mut Vec<Line<'a>>, palette: &Palette) {
    let mut cursor = 0;
    for (range, summary) in ai::actions::action_summaries(text, streaming) {
        markdown(&text[cursor..range.start], lines, palette);
        lines.push(Line::styled(format!("▸ {summary}"), Style::default().fg(palette.info)));
        cursor = range.end;
    }
    markdown(&text[cursor..], lines, palette);
}

/// An action result in the transcript: every action's status lines, and for each output block
/// only its most recent lines; the full text stays in message details.
fn action_preview<'a>(text: &'a str, lines: &mut Vec<Line<'a>>, palette: &Palette) {
    let style = Style::default().fg(palette.foreground);
    let flush = |output: &mut Vec<&'a str>, lines: &mut Vec<Line<'a>>| {
        let hidden = output.len().saturating_sub(RESULT_PREVIEW_LINES);
        if hidden > 0 {
            lines.push(Line::styled(
                format!("… {hidden} earlier line(s) in message details"),
                Style::default().fg(palette.muted),
            ));
        }
        lines.extend(output.drain(..).skip(hidden).map(|line| Line::styled(line, style)));
    };
    let mut output = Vec::new();
    let mut fence = None;
    for line in text.lines() {
        match fence {
            Some(close) if line == close => {
                flush(&mut output, lines);
                lines.push(Line::styled(line, style));
                fence = None;
            }
            Some(_) => output.push(line),
            None => {
                let ticks = line.len() - line.trim_start_matches('`').len();
                if ticks >= 3 && &line[ticks..] == "text" {
                    fence = Some(&line[..ticks]);
                }
                lines.push(Line::styled(line, style));
            }
        }
    }
    flush(&mut output, lines);
}
fn on(value: bool) -> &'static str {
    if value { "On" } else { "Off" }
}
fn optional_number<T: std::str::FromStr>(value: &str, message: &'static str) -> Result<Option<T>> {
    if value.trim().is_empty() {
        Ok(None)
    } else {
        value
            .trim()
            .parse()
            .map(Some)
            .map_err(|_| anyhow::anyhow!(message))
    }
}
fn draw_editor(
    frame: &mut Frame,
    area: Rect,
    editor: &Composer,
    title: &str,
    focused: bool,
    palette: &Palette,
) {
    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(if focused {
            palette.accent
        } else {
            palette.border
        }));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.width == 0 || inner.height == 0 {
        return;
    }
    let before = &editor.text[..editor.cursor];
    let line = before.chars().filter(|c| *c == '\n').count();
    let column = before
        .rsplit('\n')
        .next()
        .map_or(0, |s| Span::raw(s).width());
    let top = line.saturating_sub(usize::from(inner.height) - 1);
    let left = column.saturating_sub(usize::from(inner.width) - 1);
    frame.render_widget(
        Paragraph::new(editor.text.as_str())
            .scroll((
                top.min(u16::MAX as usize) as u16,
                left.min(u16::MAX as usize) as u16,
            ))
            .style(palette.style()),
        inner,
    );
    if focused {
        frame.set_cursor_position((
            inner.x + (column - left).min(usize::from(inner.width) - 1) as u16,
            inner.y + (line - top).min(usize::from(inner.height) - 1) as u16,
        ));
    }
}
fn markdown<'a>(text: &'a str, lines: &mut Vec<Line<'a>>, palette: &Palette) {
    let mut code = false;
    for line in text.lines() {
        if line.trim_start().starts_with("```") || line.trim_start().starts_with("~~~") {
            code = !code;
            lines.push(Line::styled(line, Style::default().fg(palette.muted)));
            continue;
        }
        if code {
            lines.push(Line::styled(line, Style::default().fg(palette.accent)));
        } else if let Some(heading) = line
            .strip_prefix("# ")
            .or_else(|| line.strip_prefix("## "))
            .or_else(|| line.strip_prefix("### "))
        {
            lines.push(Line::styled(
                heading,
                Style::default().add_modifier(Modifier::BOLD),
            ));
        } else {
            let spans = line
                .split("**")
                .enumerate()
                .map(|(n, part)| {
                    if n % 2 == 1 {
                        Span::styled(part, Style::default().add_modifier(Modifier::BOLD))
                    } else {
                        Span::raw(part)
                    }
                })
                .collect::<Vec<_>>();
            lines.push(Line::from(spans));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Fixture {
        data: AiData,
        models: BTreeMap<Uuid, Vec<String>>,
        checks: Checks,
        suggestions: BTreeMap<Uuid, String>,
        helpers: BTreeMap<Uuid, bool>,
    }

    impl Fixture {
        fn view(&self) -> View<'_> {
            View {
                data: &self.data,
                addon: Addon::Official,
                focused: true,
                streaming: None,
                task: None,
                sessions: &[],
                hosts: &[],
                models: &self.models,
                checks: &self.checks,
                suggestions: &self.suggestions,
                helpers: &self.helpers,
                agent: None,
                unsent_permission: PermissionLevel::ChatOnly,
                unsent_sessions: &[],
            }
        }
    }

    fn draft(token: u64, text: &str) -> Draft {
        Draft {
            token,
            attachment: ai::Attachment {
                session_id: Uuid::nil(),
                source: "terminal snapshot".into(),
                captured_at: 1,
                text: text.into(),
            },
        }
    }

    #[test]
    fn cancelling_attachment_review_cannot_send_captured_text() {
        let fixture = Fixture::default();
        let view = fixture.view();
        let bindings = Bindings::default();
        let mut panel = Panel::new();
        panel.insert("Explain this");
        panel.add_attachment(draft(1, "unreviewed terminal text"));
        panel.key(
            KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE),
            &bindings,
            &view,
        );
        assert!(matches!(panel.emit_send(), Action::None));
        assert!(panel.has_error());
        panel.navigate(Menu::Attachments);
        panel.build_rows(&view);
        panel.activate(&view);
        let (_, editor) = panel.attachment.as_mut().unwrap();
        editor.set("only deliberately approved text");
        panel.key(
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
            &bindings,
            &view,
        );
        let Action::Send {
            text, attachments, ..
        } = panel.emit_send()
        else {
            panic!("reviewed send");
        };
        assert_eq!(text, "Explain this");
        assert_eq!(
            attachments[0].attachment.text,
            "only deliberately approved text"
        );
        panel.add_attachment(draft(1, "new snapshot requires new review"));
        assert!(matches!(panel.emit_send(), Action::None));
    }

    #[test]
    fn attachment_mouse_review_keeps_exact_text_and_revocation_removes_it() {
        let fixture = Fixture::default();
        let view = fixture.view();
        let mut panel = Panel::new();
        panel.add_attachment(draft(8, "original"));
        panel.attachment.as_mut().unwrap().1.set("reviewed λ text");
        panel.hits.push((Rect::new(5, 5, 10, 1), Hit::Send));
        let action = panel.mouse(
            MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Left),
                column: 5,
                row: 5,
                modifiers: KeyModifiers::NONE,
            },
            &view,
        );
        assert!(matches!(action, Action::None));
        let Action::Send { attachments, .. } = panel.emit_send() else {
            panic!("reviewed send");
        };
        assert_eq!(attachments[0].attachment.text, "reviewed λ text");
        panel.retain_attachments(|_| false);
        let Action::Send { attachments, .. } = panel.emit_send() else {
            panic!("send without stale context");
        };
        assert!(attachments.is_empty());
    }

    #[test]
    fn stop_remains_available_inside_attachment_and_profile_editors() {
        let fixture = Fixture::default();
        let view = fixture.view();
        let bindings = Bindings::default();
        let mut panel = Panel::new();
        panel.add_attachment(draft(1, "capture"));
        let stop = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
        assert!(matches!(panel.key(stop, &bindings, &view), Action::Stop));
        panel.open_profile(Profile::new(ProviderKind::Compatible));
        assert!(matches!(panel.key(stop, &bindings, &view), Action::Stop));
    }

    #[test]
    fn action_previews_keep_every_status_and_the_latest_output_lines() {
        let output = (1..=30).map(|line| format!("line {line}")).collect::<Vec<_>>().join("\n");
        let outcome = |action: &str, status: &str, output: Option<String>| ai::actions::Outcome {
            action: action.into(),
            target: "web (10.0.0.1:22)".into(),
            approval: "automatic",
            status: status.into(),
            output,
            captured_at: None,
        };
        let text = ai::actions::format_results(
            &[
                outcome("Run in s1: ./build", "Submitted.", Some(output)),
                outcome("Run stopped", "Stopped because permissions changed.", None),
            ],
            24_000,
        );
        let mut lines = Vec::new();
        action_preview(&text, &mut lines, &crate::theme::default_theme().palette);
        let shown: Vec<String> = lines.iter().map(ToString::to_string).collect();
        assert!(shown.iter().any(|line| line.contains("Stopped because permissions changed.")));
        assert!(shown.iter().any(|line| line == "line 30") && shown.iter().any(|line| line == "line 19"));
        assert!(!shown.iter().any(|line| line == "line 18"));
        assert!(shown.iter().any(|line| line.contains("18 earlier line(s) in message details")));
    }
}
