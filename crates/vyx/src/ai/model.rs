//! Host-owned Vyx AI data: provider profiles, feature switches, and local conversation history.
//!
//! `AiData` is stored only inside the encrypted device-local `LocalState`. It never joins the
//! synchronized `Vault`, sync uploads, conflict snapshots, or guest-visible extension state.
//! Temporary conversations are live-only: serializing one fails, and store commits drop them.

use std::{
    collections::{BTreeSet, HashSet},
    fmt::{self, Write as _},
    fs::{self, OpenOptions},
    io::{self, Write},
    net::IpAddr,
    os::unix::fs::OpenOptionsExt,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail, ensure};
use reqwest::Url;
use serde::{Deserialize, Deserializer, Serialize, Serializer, ser::Error as _};
use uuid::Uuid;

use crate::vault::Secret;

/// Official issue form for provider requests. Vyx never pre-fills it with account or server data.
pub const PROVIDER_REQUEST_URL: &str = "https://github.com/Mondrethos/vyx/issues/new";
pub const PROVIDER_REQUEST_GUIDANCE: &str = "Missing a provider? Open an issue to request support.";
pub const PROVIDER_REQUEST_DETAILS: &str = "Include the provider name, its public API and authentication documentation, and the capabilities you need. Never include API keys, tokens, server logs, or credentials.";
pub const ANTHROPIC_SUBSCRIPTION_NOTICE: &str = "Claude subscription sign-in is not available. Anthropic requires prior approval before third-party products offer claude.ai login or subscription usage limits, and Vyx does not extract subscription tokens or imitate another client. Use an Anthropic API key instead; its usage is billed to your Anthropic API account.";
pub const REDACTION_DISCLAIMER: &str = "Automatic redaction is best effort and cannot guarantee that this text is free of secrets. Review it before sending.";
pub const EXPORT_WARNING: &str = "Transcript exports are unencrypted plaintext files outside the vault. They may contain commands, server output, or other sensitive data.";
/// Prompt for an explicitly requested one-shot title suggestion.
pub const TITLE_REQUEST: &str = "Suggest a concise title of two to four words for the task in this conversation, such as \"logs\", \"backup check\", or \"deploy review\". Reply with only the title.";

pub const MAX_PROFILES: usize = 32;
pub const MAX_CONVERSATIONS: usize = 500;
pub const MAX_MESSAGES: usize = 1_000;
/// Largest stored message text, in UTF-8 bytes.
pub const MAX_MESSAGE_BYTES: usize = 1024 * 1024;
/// Largest serialized AI section of the local state. The synced vault document is capped
/// separately, so retained AI history can never push local state past the envelope limit.
pub const MAX_STORED_BYTES: usize = 6 * 1024 * 1024;
pub const MAX_NAME_CHARS: usize = 64;
pub const MAX_TITLE_CHARS: usize = 80;
pub const MAX_TAB_TITLE_CHARS: usize = 40;
pub const MAX_MODEL_CHARS: usize = 256;
pub const MAX_URL_CHARS: usize = 2_048;
pub const MAX_CREDENTIAL_CHARS: usize = 4_096;
/// Vyx-owned Codex auth JSON, retained only inside encrypted local state.
pub const MAX_CODEX_AUTH_BYTES: usize = 64 * 1024;
pub const MAX_PATH_CHARS: usize = 4_096;
pub const DEFAULT_MAX_OUTPUT_TOKENS: u32 = 8_192;
pub const MAX_OUTPUT_TOKENS: u32 = 1_000_000;
pub const DEFAULT_CONTEXT_CHARS: usize = 32_000;
pub const MIN_CONTEXT_CHARS: usize = 2_000;
pub const MAX_CONTEXT_CHARS: usize = 250_000;
/// Chat panel width in terminal columns.
pub const DEFAULT_PANEL_WIDTH: u16 = 56;
pub const MIN_PANEL_WIDTH: u16 = 32;
pub const MAX_PANEL_WIDTH: u16 = 160;
pub const MAX_RETENTION_DAYS: u32 = 3_650;
/// Sessions one chat may address; AI-opened sessions count toward it.
pub const MAX_SCOPE_SESSIONS: usize = 8;
pub const DEFAULT_AGENT_STEPS: u16 = 20;
pub const MAX_AGENT_STEPS: u16 = 100;

const SECONDS_PER_DAY: u64 = 86_400;
const REDACTED: &str = "[REDACTED]";
const REDACTED_PRIVATE_KEY: &str = "[REDACTED PRIVATE KEY]";

/// Current time in unix seconds.
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderKind {
    #[serde(rename = "openai")]
    OpenAi,
    Codex,
    Anthropic,
    #[serde(rename = "openrouter")]
    OpenRouter,
    Compatible,
}

impl ProviderKind {
    pub const ALL: [Self; 5] = [
        Self::OpenAi,
        Self::Codex,
        Self::Anthropic,
        Self::OpenRouter,
        Self::Compatible,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::OpenAi => "OpenAI API",
            Self::Codex => "ChatGPT subscription (Codex)",
            Self::Anthropic => "Anthropic API",
            Self::OpenRouter => "OpenRouter",
            Self::Compatible => "OpenAI-compatible endpoint",
        }
    }

    /// Short billing mode shown beside every conversation.
    pub fn billing_label(self) -> &'static str {
        match self {
            Self::OpenAi => "OpenAI API billing",
            Self::Codex => "ChatGPT Codex entitlement",
            Self::Anthropic => "Anthropic API billing",
            Self::OpenRouter => "OpenRouter billing",
            Self::Compatible => "Endpoint-defined billing",
        }
    }

    pub fn billing_notice(self) -> &'static str {
        match self {
            Self::OpenAi => {
                "Usage is billed to your OpenAI API account, not a ChatGPT subscription."
            }
            Self::Codex => super::codex::BILLING_NOTICE,
            Self::Anthropic => "Usage is billed to your Anthropic API account.",
            Self::OpenRouter => {
                "Usage is billed to your OpenRouter account. Routed models differ in pricing, parameters, and tool support."
            }
            Self::Compatible => {
                "Billing, data handling, and supported features are defined by this endpoint's operator. Unsupported features are labeled, never assumed."
            }
        }
    }

    /// Base URL including the API version prefix; requests append paths such as
    /// `chat/completions`, `responses`, `messages`, or `models`. Empty when the user supplies it
    /// (compatible endpoints) or no HTTP endpoint is used (Codex).
    pub fn default_base_url(self) -> &'static str {
        match self {
            Self::OpenAi => "https://api.openai.com/v1",
            Self::Anthropic => "https://api.anthropic.com/v1",
            Self::OpenRouter => "https://openrouter.ai/api/v1",
            Self::Codex | Self::Compatible => "",
        }
    }

    pub fn default_api_style(self) -> ApiStyle {
        match self {
            Self::OpenAi | Self::Codex => ApiStyle::Responses,
            Self::Anthropic | Self::OpenRouter | Self::Compatible => ApiStyle::ChatCompletions,
        }
    }

    /// Whether requests need a stored API key. Codex authenticates through its own sign-in, and a
    /// compatible endpoint may be keyless (for example a server on this computer).
    pub fn requires_credential(self) -> bool {
        matches!(self, Self::OpenAi | Self::Anthropic | Self::OpenRouter)
    }

    pub fn accepts_credential(self) -> bool {
        self != Self::Codex
    }

    /// Whether the user chooses the endpoint. Built-in providers always use their official
    /// endpoint, so a key can never be sent elsewhere by accident.
    pub fn configurable_endpoint(self) -> bool {
        self == Self::Compatible
    }

    /// Whether both OpenAI request styles can be chosen for this connection.
    pub fn selectable_api_style(self) -> bool {
        matches!(self, Self::OpenAi | Self::Compatible)
    }

    /// Highest accepted temperature, or `None` when the connection has no temperature control.
    pub fn max_temperature(self) -> Option<f64> {
        match self {
            Self::Codex => None,
            Self::Anthropic => Some(1.0),
            Self::OpenAi | Self::OpenRouter | Self::Compatible => Some(2.0),
        }
    }

    /// Accepted reasoning effort values; an unset effort uses the model default.
    pub fn reasoning_efforts(self) -> &'static [&'static str] {
        match self {
            Self::OpenAi | Self::Codex | Self::OpenRouter => {
                &["none", "minimal", "low", "medium", "high", "xhigh"]
            }
            Self::Anthropic | Self::Compatible => &["low", "medium", "high"],
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiStyle {
    ChatCompletions,
    Responses,
}

impl ApiStyle {
    pub const ALL: [Self; 2] = [Self::ChatCompletions, Self::Responses];

    pub fn label(self) -> &'static str {
        match self {
            Self::ChatCompletions => "Chat Completions",
            Self::Responses => "Responses",
        }
    }
}

/// A provider connection owned by the native host. `Debug` never shows the credential.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Profile {
    pub id: Uuid,
    pub name: String,
    pub kind: ProviderKind,
    pub base_url: String,
    pub api_style: ApiStyle,
    pub credential: Option<Secret>,
    /// Empty until the user picks or discovers a model; Codex then uses its default model.
    pub model: String,
    pub max_output_tokens: u32,
    #[serde(default, with = "exact_float")]
    pub temperature: Option<f64>,
    pub reasoning_effort: Option<String>,
    pub streaming: bool,
    /// Explicitly selected, verified Vyx helper; `None` uses the managed optional runtime.
    pub codex_path: Option<String>,
    /// Official-login credentials from Vyx's isolated helper, never ambient Codex state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub codex_auth: Option<Secret>,
}

impl Profile {
    pub fn new(kind: ProviderKind) -> Self {
        Self {
            id: Uuid::new_v4(),
            name: kind.label().to_owned(),
            kind,
            base_url: kind.default_base_url().to_owned(),
            api_style: kind.default_api_style(),
            credential: None,
            model: String::new(),
            max_output_tokens: DEFAULT_MAX_OUTPUT_TOKENS,
            temperature: None,
            reasoning_effort: None,
            streaming: true,
            codex_path: None,
            codex_auth: None,
        }
    }

    pub fn billing_label(&self) -> &'static str {
        self.kind.billing_label()
    }

    /// Structural validity for saving. A profile may still lack a key, endpoint, or model; see
    /// [`Profile::ready`].
    pub fn validate(&self) -> Result<()> {
        ensure!(!self.id.is_nil(), "Profile ID cannot be nil");
        validate_label("Profile name", &self.name, MAX_NAME_CHARS)?;
        validate_base_url(self.kind, &self.base_url)?;
        ensure!(
            self.kind.selectable_api_style() || self.api_style == self.kind.default_api_style(),
            "{} does not offer a choice of request style",
            self.kind.label()
        );
        if let Some(credential) = &self.credential {
            ensure!(
                self.kind.accepts_credential(),
                "{} signs in through Codex and never stores an API key",
                self.kind.label()
            );
            validate_credential(credential)?;
        }
        if let Some(auth) = &self.codex_auth {
            ensure!(
                self.kind == ProviderKind::Codex,
                "Only Codex subscription profiles store sign-in credentials"
            );
            validate_codex_auth(auth)?;
        }
        validate_model(&self.model)?;
        ensure!(
            (1..=MAX_OUTPUT_TOKENS).contains(&self.max_output_tokens),
            "Maximum output tokens must be between 1 and {MAX_OUTPUT_TOKENS}"
        );
        if let Some(temperature) = self.temperature {
            let maximum = self
                .kind
                .max_temperature()
                .with_context(|| format!("{} does not accept a temperature", self.kind.label()))?;
            ensure!(
                valid_temperature(self.kind, temperature),
                "Temperature must be between 0 and {maximum}"
            );
        }
        if let Some(effort) = &self.reasoning_effort {
            ensure!(
                self.kind.reasoning_efforts().contains(&effort.as_str()),
                "{} does not accept reasoning effort {effort:?}",
                self.kind.label()
            );
        }
        if let Some(path) = &self.codex_path {
            ensure!(
                self.kind == ProviderKind::Codex,
                "Only Codex profiles select a Vyx Codex helper"
            );
            validate_codex_path(path)?;
        }
        Ok(())
    }

    /// Everything a request needs: a valid profile with its key, endpoint, and model.
    pub fn ready(&self) -> Result<()> {
        self.validate()?;
        if self.kind.requires_credential() {
            ensure!(self.credential.is_some(), "Add an API key to {}", self.name);
        }
        if self.kind == ProviderKind::Compatible {
            ensure!(
                !self.base_url.is_empty(),
                "Enter the base URL for {}",
                self.name
            );
        }
        if self.kind != ProviderKind::Codex {
            ensure!(!self.model.is_empty(), "Choose a model for {}", self.name);
        }
        Ok(())
    }

    /// Absolute URL for `path` below this profile's validated base URL.
    pub fn endpoint(&self, path: &str) -> Result<Url> {
        validate_base_url(self.kind, &self.base_url)?;
        ensure!(
            !self.base_url.is_empty(),
            "{} has no HTTP endpoint configured",
            self.name
        );
        let url = format!(
            "{}/{}",
            self.base_url.trim_end_matches('/'),
            path.trim_start_matches('/')
        );
        Url::parse(&url).context("Invalid provider endpoint")
    }

    /// Short diagnostic label only; omits routing paths and must not be used as consent identity.
    pub fn recipient(&self) -> String {
        if self.kind == ProviderKind::Codex {
            return format!("{} via the isolated Vyx Codex helper", self.name);
        }
        let host = Url::parse(&self.base_url).ok().and_then(|url| {
            let host = url.host_str()?.to_owned();
            Some(match url.port() {
                Some(port) => format!("{host}:{port}"),
                None => host,
            })
        });
        match host {
            Some(host) => format!("{} ({host})", self.name),
            None => format!("{} (endpoint not configured)", self.name),
        }
    }

    pub fn model_label(&self) -> &str {
        if !self.model.is_empty() {
            &self.model
        } else if self.kind == ProviderKind::Codex {
            "Codex default model"
        } else {
            "No model selected"
        }
    }

    fn repair(&mut self) {
        if validate_label("Profile name", &self.name, MAX_NAME_CHARS).is_err() {
            self.name = sanitize_title(&self.name, MAX_NAME_CHARS)
                .unwrap_or_else(|| self.kind.label().to_owned());
        }
        if validate_base_url(self.kind, &self.base_url).is_err() {
            self.base_url = self.kind.default_base_url().to_owned();
        }
        if !self.kind.selectable_api_style() {
            self.api_style = self.kind.default_api_style();
        }
        if self.credential.as_ref().is_some_and(|credential| {
            !self.kind.accepts_credential() || validate_credential(credential).is_err()
        }) {
            self.credential = None;
        }
        if self.codex_auth.as_ref().is_some_and(|auth| {
            self.kind != ProviderKind::Codex || validate_codex_auth(auth).is_err()
        }) {
            self.codex_auth = None;
        }
        if validate_model(&self.model).is_err() {
            self.model.clear();
        }
        self.max_output_tokens = self.max_output_tokens.clamp(1, MAX_OUTPUT_TOKENS);
        if self
            .temperature
            .is_some_and(|temperature| !valid_temperature(self.kind, temperature))
        {
            self.temperature = None;
        }
        if self
            .reasoning_effort
            .as_deref()
            .is_some_and(|effort| !self.kind.reasoning_efforts().contains(&effort))
        {
            self.reasoning_effort = None;
        }
        if self.codex_path.as_deref().is_some_and(|path| {
            self.kind != ProviderKind::Codex || validate_codex_path(path).is_err()
        }) {
            self.codex_path = None;
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Feature {
    Chat,
    Streaming,
    Explanations,
    Troubleshooting,
    Runbooks,
    Review,
    Templates,
    HistorySearch,
    Export,
    TitleSuggestions,
    AutoTitle,
    AutoConversationTitle,
    Usage,
    BackgroundReply,
}

const NEEDS_NOTHING: &[&[Feature]] = &[];
const NEEDS_CHAT: &[&[Feature]] = &[&[Feature::Chat]];

impl Feature {
    /// Every switch in settings order, grouped by [`Feature::group`].
    pub const ALL: [Self; 14] = [
        Self::Chat,
        Self::Streaming,
        Self::Explanations,
        Self::Troubleshooting,
        Self::Runbooks,
        Self::Review,
        Self::Templates,
        Self::BackgroundReply,
        Self::TitleSuggestions,
        Self::AutoTitle,
        Self::AutoConversationTitle,
        Self::HistorySearch,
        Self::Export,
        Self::Usage,
    ];

    /// Settings groups in display order.
    pub const GROUPS: [&'static str; 4] = ["Chat", "Session names", "History", "Usage"];

    pub fn label(self) -> &'static str {
        match self {
            Self::Chat => "Slideout chat",
            Self::Streaming => "Streaming replies",
            Self::Explanations => "Command explanations",
            Self::Troubleshooting => "Troubleshooting",
            Self::Runbooks => "Runbook generation",
            Self::Review => "Script and config review",
            Self::Templates => "Prompt templates",
            Self::HistorySearch => "Local history search",
            Self::Export => "Transcript export",
            Self::TitleSuggestions => "Tab title suggestions",
            Self::AutoTitle => "Automatic tab naming",
            Self::AutoConversationTitle => "Automatic conversation naming",
            Self::Usage => "Usage indicators",
            Self::BackgroundReply => "Finish replies while closed",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Self::Chat => {
                "Open the AI chat beside your sessions. What it may do on its own is set by Permissions."
            }
            Self::Streaming => {
                "Show replies as they arrive when the provider supports it. Stop stays available."
            }
            Self::Explanations => {
                "Explain commands, flags, output, errors, and pasted configuration when you ask."
            }
            Self::Troubleshooting => {
                "Diagnose SSH, service, resource, network, container, and permission problems."
            }
            Self::Runbooks => {
                "Draft step-by-step maintenance, upgrade, backup, and recovery runbooks."
            }
            Self::Review => {
                "Review pasted scripts and configuration and propose corrections."
            }
            Self::Templates => {
                "Offer reusable prompts for recurring server tasks. Templates only insert text."
            }
            Self::HistorySearch => {
                "Search conversations kept on this device. Searching never contacts a provider."
            }
            Self::Export => {
                "Allow exporting a conversation to an unencrypted plaintext file when you choose to."
            }
            Self::TitleSuggestions => {
                "Suggest a concise session tab title when you ask, for you to accept or reject."
            }
            Self::AutoTitle => {
                "Rename in-scope session tabs from replies you already requested, when the chat may manage tabs. Manual titles stay pinned."
            }
            Self::AutoConversationTitle => {
                "Name conversations from replies you already requested; no separate naming requests."
            }
            Self::Usage => {
                "Show token and cost information when the provider reports it. Unknown values are labeled unavailable."
            }
            Self::BackgroundReply => {
                "Let a reply you already requested finish while the panel is closed. It never runs actions or starts a new turn; locking or detaching still cancels."
            }
        }
    }

    /// Settings section: one of [`Feature::GROUPS`].
    pub fn group(self) -> &'static str {
        match self {
            Self::Chat
            | Self::Streaming
            | Self::Explanations
            | Self::Troubleshooting
            | Self::Runbooks
            | Self::Review
            | Self::Templates
            | Self::BackgroundReply => "Chat",
            Self::TitleSuggestions | Self::AutoTitle | Self::AutoConversationTitle => {
                "Session names"
            }
            Self::HistorySearch | Self::Export => "History",
            Self::Usage => "Usage",
        }
    }

    /// Recommended default once Vyx AI is enabled.
    pub fn default_enabled(self) -> bool {
        matches!(
            self,
            Self::Chat
                | Self::Streaming
                | Self::Explanations
                | Self::Troubleshooting
                | Self::Runbooks
                | Self::Review
                | Self::Templates
                | Self::HistorySearch
                | Self::Usage
        )
    }

    /// Prerequisites: each group needs at least one allowed member.
    pub fn requires(self) -> &'static [&'static [Feature]] {
        match self {
            Self::Chat => NEEDS_NOTHING,
            _ => NEEDS_CHAT,
        }
    }
}

/// How much a chat may do on its own. Ordered, so a ceiling caps every chat at or below it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionLevel {
    /// Conversation only: typed text and explicitly reviewed attachments, no automatic access.
    #[default]
    ChatOnly,
    /// Reads in-scope sessions automatically; every change waits for native approval.
    Assist,
    /// Ordinary actions run automatically; high-risk or unclassifiable input still needs approval.
    Full,
}

impl PermissionLevel {
    pub const ALL: [Self; 3] = [Self::ChatOnly, Self::Assist, Self::Full];

    pub fn label(self) -> &'static str {
        match self {
            Self::ChatOnly => "Chat only",
            Self::Assist => "Assist",
            Self::Full => "Full control",
        }
    }
}

/// Automatic authority a chat above Chat only may use; each is checked when an action runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    ReadOutput,
    RunCommands,
    Sessions,
    TabsLayout,
    ServerDrafts,
}

impl Capability {
    pub const ALL: [Self; 5] = [Self::ReadOutput, Self::RunCommands, Self::Sessions, Self::TabsLayout, Self::ServerDrafts];

    pub fn label(self) -> &'static str {
        match self {
            Self::ReadOutput => "Share terminal output automatically",
            Self::RunCommands => "Run commands and send keys",
            Self::Sessions => "Open and close sessions",
            Self::TabsLayout => "Manage tabs and layout",
            Self::ServerDrafts => "Draft saved servers (review required)",
        }
    }
}

/// Global Vyx AI settings. Per-conversation choices may only restrict these further.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Master switch; nothing runs while it is off.
    pub enabled: bool,
    #[serde(deserialize_with = "deserialize_features")]
    pub features: BTreeSet<Feature>,
    pub default_profile: Option<Uuid>,
    /// Upper bound on characters of conversation and attached context sent in one request.
    pub context_chars: usize,
    /// Delete retained conversations not updated for this many days.
    pub retention_days: Option<u32>,
    /// Warn once a conversation's reported token usage approaches this budget.
    pub budget_tokens: Option<u64>,
    pub panel_width: u16,
    /// Prefix AI tab titles with the local server label (`api · logs`).
    pub title_prefix: bool,
    /// Level new chats start at. Field-level default: a saved configuration that predates
    /// permissions reads as Chat only, never the fresh-install recommendation.
    #[serde(default, deserialize_with = "deserialize_level")]
    pub default_permission: PermissionLevel,
    /// Ceiling no chat may exceed; only Settings can raise it.
    #[serde(default, deserialize_with = "deserialize_level")]
    pub max_permission: PermissionLevel,
    #[serde(deserialize_with = "deserialize_capabilities")]
    pub capabilities: BTreeSet<Capability>,
    /// Actions (reads included) one run may attempt before asking for a new message.
    pub agent_steps: u16,
    /// Set only by applying the Permissions form; until then every chat is Chat only.
    #[serde(default)]
    pub permissions_confirmed: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            enabled: false,
            features: Feature::ALL
                .into_iter()
                .filter(|feature| feature.default_enabled())
                .collect(),
            default_profile: None,
            context_chars: DEFAULT_CONTEXT_CHARS,
            retention_days: None,
            budget_tokens: None,
            panel_width: DEFAULT_PANEL_WIDTH,
            title_prefix: true,
            default_permission: PermissionLevel::Assist,
            max_permission: PermissionLevel::Assist,
            capabilities: Capability::ALL.into_iter().collect(),
            agent_steps: DEFAULT_AGENT_STEPS,
            permissions_confirmed: false,
        }
    }
}

impl Config {
    /// Whether `feature` may operate now: the master switch, the feature, and its prerequisites
    /// are all on. Native reads, requests, and actions must check this at the moment they run.
    pub fn allows(&self, feature: Feature) -> bool {
        self.enabled
            && self.features.contains(&feature)
            && feature
                .requires()
                .iter()
                .all(|group| group.iter().any(|required| self.allows(*required)))
    }

    /// The switch position, independent of the master switch and prerequisites.
    pub fn is_on(&self, feature: Feature) -> bool {
        self.features.contains(&feature)
    }

    /// Flips a feature switch and returns its new position.
    pub fn toggle(&mut self, feature: Feature) -> bool {
        let on = !self.features.remove(&feature);
        if on {
            self.features.insert(feature);
        }
        on
    }

    pub fn set(&mut self, feature: Feature, on: bool) {
        if on {
            self.features.insert(feature);
        } else {
            self.features.remove(&feature);
        }
    }

    /// Why `feature` cannot operate even when switched on, for settings explanations.
    pub fn blocked_reason(&self, feature: Feature) -> Option<String> {
        if !self.enabled {
            return Some("Vyx AI is turned off".to_owned());
        }
        feature
            .requires()
            .iter()
            .find(|group| !group.iter().any(|required| self.allows(*required)))
            .map(|group| {
                let names: Vec<&str> = group.iter().map(|required| required.label()).collect();
                format!("Requires {}", names.join(" or "))
            })
    }

    /// What a chat at `chosen` may do right now: Chat only unless Vyx AI, Chat, and confirmed
    /// permissions are on, and never above the configured ceiling.
    pub fn effective_permission(&self, chosen: PermissionLevel) -> PermissionLevel {
        if self.allows(Feature::Chat) && self.permissions_confirmed {
            chosen.min(self.max_permission)
        } else {
            PermissionLevel::ChatOnly
        }
    }

    /// Whether `level` grants `capability` automatically. Chat only grants none.
    pub fn grants(&self, level: PermissionLevel, capability: Capability) -> bool {
        level > PermissionLevel::ChatOnly && self.capabilities.contains(&capability)
    }

    /// Budget warning for a conversation's reported token usage, from 80% of the budget.
    pub fn budget_warning(&self, used_tokens: u64) -> Option<String> {
        let budget = self.budget_tokens?;
        if used_tokens >= budget {
            Some(format!(
                "This conversation reached its {budget}-token budget ({used_tokens} tokens reported)"
            ))
        } else if used_tokens >= budget - budget / 5 {
            Some(format!(
                "This conversation used {used_tokens} of its {budget}-token budget"
            ))
        } else {
            None
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            (MIN_CONTEXT_CHARS..=MAX_CONTEXT_CHARS).contains(&self.context_chars),
            "Context limit must be between {MIN_CONTEXT_CHARS} and {MAX_CONTEXT_CHARS} characters"
        );
        if let Some(days) = self.retention_days {
            ensure!(
                (1..=MAX_RETENTION_DAYS).contains(&days),
                "History retention must be between 1 and {MAX_RETENTION_DAYS} days"
            );
        }
        ensure!(
            self.budget_tokens != Some(0),
            "Token budget must be positive"
        );
        ensure!(
            (MIN_PANEL_WIDTH..=MAX_PANEL_WIDTH).contains(&self.panel_width),
            "Chat panel width must be between {MIN_PANEL_WIDTH} and {MAX_PANEL_WIDTH} columns"
        );
        ensure!(
            self.default_permission <= self.max_permission,
            "The default for new chats cannot exceed the maximum allowed"
        );
        ensure!(
            (1..=MAX_AGENT_STEPS).contains(&self.agent_steps),
            "Agent step limit must be between 1 and {MAX_AGENT_STEPS}"
        );
        Ok(())
    }

    fn repair(&mut self) {
        self.context_chars = self
            .context_chars
            .clamp(MIN_CONTEXT_CHARS, MAX_CONTEXT_CHARS);
        self.retention_days = self
            .retention_days
            .map(|days| days.clamp(1, MAX_RETENTION_DAYS));
        if self.budget_tokens == Some(0) {
            self.budget_tokens = None;
        }
        self.panel_width = self.panel_width.clamp(MIN_PANEL_WIDTH, MAX_PANEL_WIDTH);
        self.default_permission = self.default_permission.min(self.max_permission);
        self.agent_steps = self.agent_steps.clamp(1, MAX_AGENT_STEPS);
    }
}

/// Unknown switches written by a newer build are ignored instead of blocking vault unlock.
fn deserialize_features<'de, D>(deserializer: D) -> Result<BTreeSet<Feature>, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(Vec::<serde_json::Value>::deserialize(deserializer)?
        .into_iter()
        .filter_map(|value| serde_json::from_value(value).ok())
        .collect())
}

/// Absent or unrecognized levels read as Chat only, so no saved state gains authority.
fn deserialize_level<'de, D>(deserializer: D) -> Result<PermissionLevel, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(serde_json::from_value(serde_json::Value::deserialize(deserializer)?).unwrap_or_default())
}

/// Unknown capability names are ignored, as with feature switches.
fn deserialize_capabilities<'de, D>(deserializer: D) -> Result<BTreeSet<Capability>, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(Vec::<serde_json::Value>::deserialize(deserializer)?
        .into_iter()
        .filter_map(|value| serde_json::from_value(value).ok())
        .collect())
}

/// A built-in reusable prompt. Templates insert text only; they never grant tools or run commands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Template {
    pub name: &'static str,
    /// Assistance feature the template relies on, in addition to [`Feature::Templates`].
    pub feature: Feature,
    pub prompt: &'static str,
}

impl Template {
    pub fn allowed(&self, config: &Config) -> bool {
        config.allows(Feature::Templates) && config.allows(self.feature)
    }
}

pub const TEMPLATES: &[Template] = &[
    Template {
        name: "Explain a command",
        feature: Feature::Explanations,
        prompt: "Explain what this command does, flag by flag, including its side effects and risks:\n\n",
    },
    Template {
        name: "Explain output or an error",
        feature: Feature::Explanations,
        prompt: "Explain this output or error message and what it means for the server:\n\n",
    },
    Template {
        name: "Diagnose an SSH failure",
        feature: Feature::Troubleshooting,
        prompt: "Diagnose this SSH connection or authentication failure. List the likely causes in order and how to verify each one:\n\n",
    },
    Template {
        name: "Troubleshoot a service",
        feature: Feature::Troubleshooting,
        prompt: "Help me troubleshoot a service that is failing or misbehaving. Start with read-only diagnostic commands and explain what their output would show:\n\n",
    },
    Template {
        name: "Find resource usage",
        feature: Feature::Troubleshooting,
        prompt: "Help me find what is using CPU, memory, or disk space on this server. Start with read-only commands and explain how to interpret their output.",
    },
    Template {
        name: "Write a runbook",
        feature: Feature::Runbooks,
        prompt: "Write a step-by-step runbook for the task below. Include prerequisites, a backup or rollback point, verification after each step, and the risks:\n\n",
    },
    Template {
        name: "Review a script or config",
        feature: Feature::Review,
        prompt: "Review this script or configuration for bugs, security problems, and risky behavior. Propose corrections as a diff; do not assume they will be applied:\n\n",
    },
    Template {
        name: "Summarize for a handoff",
        feature: Feature::Troubleshooting,
        prompt: "Summarize this conversation as troubleshooting notes for a handoff: symptoms, findings, actions taken, and open questions.",
    },
];

const BASE_SYSTEM_PROMPT: &str = "You are Vyx AI, the assistant built into Vyx, a terminal workspace for SSH servers. Help with server administration: explain commands and output, diagnose problems, review scripts and configuration, and plan maintenance.";

const CHAT_ONLY_PROMPT: &str = "This chat is set to Chat only. You cannot see terminals, files, credentials, or saved servers unless the user includes them in a message, and you cannot run commands or change anything. The user reviews every suggestion, and Vyx requires a separate native confirmation for each individual command.";

const SUGGESTION_PROMPT: &str = "Put each proposed shell command for the user in its own fenced code block with a language tag such as sh; such suggestions are never run automatically. Explain what a command does, its expected effect, and its risks. Prefer read-only diagnostics before changes, and include verification and rollback steps for risky changes. Never ask for passwords, private keys, API keys, or tokens; if they appear, tell the user to remove them.";

/// Instructions sent as the first system message of every request. Chat only (`control` is
/// `None`) receives no inventory or action schema; Assist and Full receive the request-bound
/// inventory and rules from `control`. Native checks, not this text, enforce permissions.
pub(crate) fn system_prompt(config: &Config, control: Option<&crate::ai::actions::ControlContext<'_>>) -> String {
    let mut prompt = String::from(BASE_SYSTEM_PROMPT);
    prompt.push_str("\n\n");
    match control {
        Some(control) => prompt.push_str(&crate::ai::actions::control_prompt(control, config.context_chars)),
        None => prompt.push_str(CHAT_ONLY_PROMPT),
    }
    prompt.push_str("\n\n");
    prompt.push_str(SUGGESTION_PROMPT);
    let disabled: Vec<&str> = [
        Feature::Explanations,
        Feature::Troubleshooting,
        Feature::Runbooks,
        Feature::Review,
    ]
    .into_iter()
    .filter(|feature| !config.allows(*feature))
    .map(Feature::label)
    .collect();
    if !disabled.is_empty() {
        let _ = write!(
            prompt,
            "\n\nThe user turned off these Vyx assistance features: {}. Decline requests that need them and mention that they can be enabled in Settings / Extensions / Vyx AI.",
            disabled.join(", ")
        );
    }
    if config.allows(Feature::AutoTitle) || config.allows(Feature::AutoConversationTitle) {
        prompt.push_str("\n\nEnd every reply with a final line of the form [title: <two to four words>] naming the current task, for example [title: backup check].");
    }
    prompt
}

/// Structured suggestion carried by a trailing `[name: value]` line of a completed reply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Directive {
    Title(String),
}

/// Splits trailing directive lines from a completed reply. Returns the reply body to display and
/// the directives in their original order. Directives are suggestions for native review only.
pub fn take_directives(reply: &str) -> (&str, Vec<Directive>) {
    let mut body = reply.trim_end();
    let mut directives = Vec::new();
    loop {
        let start = body.rfind('\n').map_or(0, |index| index + 1);
        let Some(inner) = body[start..]
            .trim()
            .strip_prefix('[')
            .and_then(|line| line.strip_suffix(']'))
        else {
            break;
        };
        let Some((name, value)) = inner.split_once(':') else {
            break;
        };
        let Some(value) = sanitize_title(value, MAX_TITLE_CHARS) else {
            break;
        };
        let directive = match name.trim().to_ascii_lowercase().as_str() {
            "title" => Directive::Title(value),
            _ => break,
        };
        directives.push(directive);
        body = body[..start].trim_end();
    }
    directives.reverse();
    (body, directives)
}

/// A fenced code block from a reply; its exact text is what native review shows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodeBlock {
    pub language: String,
    pub text: String,
}

/// Closed fenced code blocks in order. An unclosed block (for example mid-stream) is omitted.
pub fn code_blocks(markdown: &str) -> Vec<CodeBlock> {
    let mut blocks = Vec::new();
    visit_code_fences(markdown, |language, body, _, closed| {
        if closed {
            let text = if body.contains('\r') { body.lines().collect::<Vec<_>>().join("\n") } else { body.to_owned() };
            blocks.push(CodeBlock { language: language.to_owned(), text });
        }
    });
    blocks
}

/// Walks fenced code blocks in order without copying them. `visit` receives the info token,
/// the body between the fences, the full source range including both fences, and whether the
/// block was closed; an unfinished block (for example mid-stream) runs to the end of the text.
/// Fences follow CommonMark's backtick/tilde width and three-space indentation rules.
pub(crate) fn visit_code_fences<'a>(markdown: &'a str, mut visit: impl FnMut(&'a str, &'a str, std::ops::Range<usize>, bool)) {
    struct Open<'a> {
        fence: char,
        width: usize,
        info: &'a str,
        start: usize,
        body_start: usize,
        body_end: usize,
    }

    let mut open: Option<Open<'a>> = None;
    let mut offset = 0;
    for raw in markdown.split_inclusive('\n') {
        let line_start = offset;
        offset += raw.len();
        let line = raw.strip_suffix('\n').unwrap_or(raw);
        let line = line.strip_suffix('\r').unwrap_or(line);
        let trimmed = line.trim_start();
        let fence = (line.len() - trimmed.len() <= 3)
            .then(|| trimmed.chars().next())
            .flatten()
            .filter(|first| matches!(first, '`' | '~'));
        let width = fence.map_or(0, |fence| {
            trimmed.chars().take_while(|c| *c == fence).count()
        });
        if let Some(block) = &mut open {
            if fence == Some(block.fence)
                && width >= block.width
                && trimmed[width..].trim().is_empty()
            {
                let block = open.take().expect("an open block was matched");
                visit(block.info, &markdown[block.body_start..block.body_end], block.start..offset, true);
            } else {
                block.body_end = line_start + line.len();
            }
            continue;
        }
        if let Some(fence) = fence
            && width >= 3
            && !(fence == '`' && trimmed[width..].contains('`'))
        {
            open = Some(Open {
                fence,
                width,
                info: trimmed[width..].split_whitespace().next().unwrap_or_default(),
                start: line_start,
                body_start: offset,
                body_end: offset,
            });
        }
    }
    if let Some(block) = open {
        visit(block.info, &markdown[block.body_start..block.body_end], block.start..markdown.len(), false);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    User,
    Assistant,
    System,
    /// Results of actions Vyx performed for the previous reply. Sent to providers as user
    /// data, never as instructions.
    Action,
}

impl Role {
    pub fn label(self) -> &'static str {
        match self {
            Self::User => "You",
            Self::Assistant => "Assistant",
            Self::System => "Vyx",
            Self::Action => "Vyx actions",
        }
    }

    /// Turns a provider sees as user input: typed prompts and action results.
    pub fn is_user_turn(self) -> bool {
        matches!(self, Self::User | Self::Action)
    }
}

/// Provider-reported usage. Unknown values stay unknown; costs are never estimated here.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Usage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    #[serde(default, with = "exact_float")]
    pub cost_usd: Option<f64>,
}

impl Usage {
    pub fn total_tokens(&self) -> u64 {
        self.input_tokens.saturating_add(self.output_tokens)
    }

    /// Sum of reports. The cost stays known only if every counted report included one.
    pub fn sum<'a>(reports: impl IntoIterator<Item = &'a Usage>) -> Usage {
        let mut total = Usage {
            cost_usd: Some(0.0),
            ..Usage::default()
        };
        let mut counted = false;
        for report in reports {
            counted = true;
            total.input_tokens = total.input_tokens.saturating_add(report.input_tokens);
            total.output_tokens = total.output_tokens.saturating_add(report.output_tokens);
            total.cost_usd = total
                .cost_usd
                .zip(report.cost_usd)
                .map(|(sum, cost)| sum + cost)
                .filter(|sum| sum.is_finite());
        }
        if !counted {
            total.cost_usd = None;
        }
        total
    }

    pub fn label(&self) -> String {
        let mut label = format!("{} in · {} out", self.input_tokens, self.output_tokens);
        match self.cost_usd {
            Some(cost) => {
                let _ = write!(label, " · ${cost:.4} reported");
            }
            None => label.push_str(" · cost unavailable"),
        }
        label
    }

    fn valid(&self) -> bool {
        self.cost_usd
            .is_none_or(|cost| cost.is_finite() && cost >= 0.0)
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct Message {
    pub id: Uuid,
    pub role: Role,
    pub text: String,
    pub created_at: u64,
    pub usage: Option<Usage>,
}

impl fmt::Debug for Message {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Message")
            .field("id", &self.id)
            .field("role", &self.role)
            .field("text", &format_args!("<{} bytes>", self.text.len()))
            .field("created_at", &self.created_at)
            .field("usage", &self.usage)
            .finish()
    }
}

impl Message {
    pub fn new(role: Role, text: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            role,
            text: text.into(),
            created_at: now(),
            usage: None,
        }
    }

    /// Appends streamed text up to [`MAX_MESSAGE_BYTES`]; returns false once the text was cut.
    pub fn append(&mut self, delta: &str) -> bool {
        let room = MAX_MESSAGE_BYTES.saturating_sub(self.text.len());
        if delta.len() <= room {
            self.text.push_str(delta);
            return true;
        }
        self.text.push_str(&delta[..floor_boundary(delta, room)]);
        false
    }
}

/// Index of the oldest message sent with a request: the newest messages whose text fits in
/// `context_chars`, always including the newest one and starting at a user message. Earlier
/// messages are omitted and should be reported as such.
pub fn context_start(messages: &[Message], context_chars: usize) -> usize {
    let Some(last) = messages.len().checked_sub(1) else {
        return 0;
    };
    let mut start = last;
    let mut used = messages[last].text.chars().count();
    while start > 0 {
        let size = messages[start - 1].text.chars().count();
        if used.saturating_add(size) > context_chars {
            break;
        }
        used += size;
        start -= 1;
    }
    while start < last && !messages[start].role.is_user_turn() {
        start += 1;
    }
    start
}

/// Context captured from a session for explicit review. It is sent only as reviewed user text.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attachment {
    pub session_id: Uuid,
    /// What was captured and from where, e.g. "terminal snapshot · api".
    pub source: String,
    pub captured_at: u64,
    pub text: String,
}

impl fmt::Debug for Attachment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Attachment")
            .field("session_id", &self.session_id)
            .field("source", &self.source)
            .field("captured_at", &self.captured_at)
            .field("text", &format_args!("<{} bytes>", self.text.len()))
            .finish()
    }
}

impl Attachment {
    /// Captured text prepared for preview: redacted first, then bounded to `limit` characters.
    pub fn new(session_id: Uuid, source: impl Into<String>, text: &str, limit: usize) -> Self {
        Self {
            session_id,
            source: source.into(),
            captured_at: now(),
            text: bounded_text(&redact(text), limit),
        }
    }

    /// The reviewed attachment exactly as it is embedded in the user's message.
    pub fn to_prompt(&self) -> String {
        let fence = fence_for(&self.text);
        format!(
            "Context from {} (captured {}):\n{fence}text\n{}\n{fence}",
            self.source,
            format_timestamp(self.captured_at),
            self.text
        )
    }
}

fn fence_for(text: &str) -> String {
    let mut longest = 0;
    let mut run = 0;
    for character in text.chars() {
        if character == '`' {
            run += 1;
            longest = longest.max(run);
        } else {
            run = 0;
        }
    }
    "`".repeat((longest + 1).max(3))
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Conversation {
    /// Declared first so serializing a temporary conversation fails before any content is written.
    #[serde(default, serialize_with = "refuse_temporary")]
    pub temporary: bool,
    pub id: Uuid,
    /// Empty until the user or opted-in automatic naming sets it; see [`Conversation::display_title`].
    pub title: String,
    pub profile_id: Option<Uuid>,
    pub model: String,
    /// Live sessions this chat may address, primary first; runtime IDs, emptied when they end.
    #[serde(default)]
    pub sessions: Vec<Uuid>,
    pub messages: Vec<Message>,
    pub parent_id: Option<Uuid>,
    pub created_at: u64,
    pub updated_at: u64,
    /// Chosen level; the effective level is also capped by Settings. Old chats read as Chat only.
    #[serde(default, deserialize_with = "deserialize_level")]
    pub permission: PermissionLevel,
    pub naming_paused: bool,
}

fn refuse_temporary<S>(temporary: &bool, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if *temporary {
        return Err(S::Error::custom(
            "temporary conversations are never persisted",
        ));
    }
    serializer.serialize_bool(false)
}

impl Conversation {
    pub fn new(profile: Option<&Profile>, temporary: bool) -> Self {
        let created_at = now();
        Self {
            temporary,
            id: Uuid::new_v4(),
            title: String::new(),
            profile_id: profile.map(|profile| profile.id),
            model: profile
                .map(|profile| profile.model.clone())
                .unwrap_or_default(),
            sessions: Vec::new(),
            messages: Vec::new(),
            parent_id: None,
            created_at,
            updated_at: created_at,
            permission: PermissionLevel::ChatOnly,
            naming_paused: false,
        }
    }

    /// The stored title, or the start of the first prompt, or "New chat". Display only.
    pub fn display_title(&self) -> String {
        if !self.title.is_empty() {
            return self.title.clone();
        }
        self.messages
            .iter()
            .find(|message| message.role == Role::User)
            .and_then(|message| sanitize_title(&message.text, 48))
            .unwrap_or_else(|| "New chat".to_owned())
    }

    /// A visible branch holding `messages[..index]`, used to edit and resend or regenerate
    /// without rewriting this conversation. It keeps the chosen level and scope, never a run.
    pub fn branch(&self, index: usize) -> Result<Self> {
        ensure!(
            index <= self.messages.len(),
            "Message {index} is outside this conversation"
        );
        let created_at = now();
        Ok(Self {
            temporary: self.temporary,
            id: Uuid::new_v4(),
            title: format!("{} (branch)", self.display_title())
                .chars()
                .take(MAX_TITLE_CHARS)
                .collect(),
            profile_id: self.profile_id,
            model: self.model.clone(),
            sessions: self.sessions.clone(),
            messages: self.messages[..index].to_vec(),
            parent_id: Some(self.id),
            created_at,
            updated_at: created_at,
            permission: self.permission,
            naming_paused: self.naming_paused,
        })
    }

    /// Replaces the scope with unique, non-nil sessions in order, keeping at most
    /// [`MAX_SCOPE_SESSIONS`].
    pub fn set_scope(&mut self, sessions: impl IntoIterator<Item = Uuid>) {
        self.sessions.clear();
        for session in sessions {
            if self.sessions.len() == MAX_SCOPE_SESSIONS {
                break;
            }
            if !session.is_nil() && !self.sessions.contains(&session) {
                self.sessions.push(session);
            }
        }
    }

    pub fn push(&mut self, message: Message) -> Result<()> {
        ensure!(
            self.messages.len() < MAX_MESSAGES,
            "This conversation reached {MAX_MESSAGES} messages; start a new conversation or branch it"
        );
        ensure!(
            message.text.len() <= MAX_MESSAGE_BYTES,
            "Message exceeds the {MAX_MESSAGE_BYTES}-byte limit"
        );
        self.updated_at = self.updated_at.max(message.created_at);
        self.messages.push(message);
        Ok(())
    }

    pub fn usage(&self) -> Usage {
        Usage::sum(
            self.messages
                .iter()
                .filter_map(|message| message.usage.as_ref()),
        )
    }

    /// Markdown transcript for an explicit export. Temporary conversations are never written.
    pub fn transcript(&self, profile: Option<&Profile>) -> Result<String> {
        ensure!(
            !self.temporary,
            "Temporary chats are never written to disk; copy the text you need instead"
        );
        let mut text = String::new();
        let _ = writeln!(text, "# {}\n", self.display_title());
        let _ = writeln!(text, "- Started: {}", format_timestamp(self.created_at));
        let _ = writeln!(text, "- Exported: {}", format_timestamp(now()));
        match profile {
            Some(profile) => {
                let _ = writeln!(
                    text,
                    "- Provider: {} ({})",
                    profile.name,
                    profile.kind.label()
                );
            }
            None => text.push_str("- Provider: removed profile\n"),
        }
        if !self.model.is_empty() {
            let _ = writeln!(text, "- Model: {}", self.model);
        }
        let _ = writeln!(text, "\n> {EXPORT_WARNING}");
        for message in &self.messages {
            let _ = write!(
                text,
                "\n## {} · {}\n\n{}\n",
                message.role.label(),
                format_timestamp(message.created_at),
                message.text.trim_end()
            );
        }
        Ok(text)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(!self.id.is_nil(), "Conversation ID cannot be nil");
        ensure!(
            self.parent_id != Some(self.id),
            "A conversation cannot branch from itself"
        );
        validate_text("Conversation title", &self.title, MAX_TITLE_CHARS)?;
        validate_model(&self.model)?;
        ensure!(
            self.created_at <= self.updated_at,
            "Conversation timestamps are out of order"
        );
        ensure!(
            self.messages.len() <= MAX_MESSAGES,
            "A conversation holds at most {MAX_MESSAGES} messages"
        );
        ensure!(
            self.sessions.len() <= MAX_SCOPE_SESSIONS
                && !self.sessions.iter().any(Uuid::is_nil)
                && self.sessions.iter().collect::<HashSet<_>>().len() == self.sessions.len(),
            "A conversation addresses at most {MAX_SCOPE_SESSIONS} distinct sessions"
        );
        for message in &self.messages {
            ensure!(
                message.text.len() <= MAX_MESSAGE_BYTES,
                "Message exceeds the {MAX_MESSAGE_BYTES}-byte limit"
            );
            ensure!(
                message.usage.as_ref().is_none_or(Usage::valid),
                "Message usage is invalid"
            );
        }
        Ok(())
    }

    fn repair(&mut self) {
        if validate_text("Conversation title", &self.title, MAX_TITLE_CHARS).is_err() {
            self.title = sanitize_title(&self.title, MAX_TITLE_CHARS).unwrap_or_default();
        }
        if validate_model(&self.model).is_err() {
            self.model.clear();
        }
        if self.parent_id == Some(self.id) {
            self.parent_id = None;
        }
        self.updated_at = self.updated_at.max(self.created_at);
        let sessions = std::mem::take(&mut self.sessions);
        self.set_scope(sessions);
        if self.messages.len() > MAX_MESSAGES {
            let excess = self.messages.len() - MAX_MESSAGES;
            self.messages.drain(..excess);
        }
        for message in &mut self.messages {
            if message.text.len() > MAX_MESSAGE_BYTES {
                let cut = floor_boundary(&message.text, MAX_MESSAGE_BYTES);
                message.text.truncate(cut);
            }
            if message.usage.as_ref().is_some_and(|usage| !usage.valid()) {
                message.usage = None;
            }
        }
    }
}

/// History removed by [`AiData::prune_history`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Pruned {
    pub conversations: usize,
    pub messages: usize,
}

impl Pruned {
    pub fn is_empty(self) -> bool {
        self.conversations == 0 && self.messages == 0
    }
}

/// Device-local AI state inside the encrypted `LocalState`; never part of the synced vault.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct AiData {
    pub config: Config,
    pub profiles: Vec<Profile>,
    /// Retained conversations plus, in the app's working copy only, temporary ones.
    pub conversations: Vec<Conversation>,
}

impl AiData {
    pub fn is_default(&self) -> bool {
        static DEFAULT: std::sync::LazyLock<AiData> = std::sync::LazyLock::new(AiData::default);
        self == &*DEFAULT
    }

    pub fn profile(&self, id: Uuid) -> Option<&Profile> {
        self.profiles.iter().find(|profile| profile.id == id)
    }

    pub fn profile_mut(&mut self, id: Uuid) -> Option<&mut Profile> {
        self.profiles.iter_mut().find(|profile| profile.id == id)
    }

    /// The configured default profile. There is deliberately no fallback to another provider.
    pub fn default_profile(&self) -> Option<&Profile> {
        self.config.default_profile.and_then(|id| self.profile(id))
    }

    pub fn conversation(&self, id: Uuid) -> Option<&Conversation> {
        self.conversations
            .iter()
            .find(|conversation| conversation.id == id)
    }

    pub fn conversation_mut(&mut self, id: Uuid) -> Option<&mut Conversation> {
        self.conversations
            .iter_mut()
            .find(|conversation| conversation.id == id)
    }

    /// Adds or replaces a validated profile; the first profile becomes the default. A profile
    /// never changes provider, so existing conversations cannot silently change recipient kind.
    pub fn put_profile(&mut self, profile: Profile) -> Result<()> {
        profile.validate()?;
        if let Some(existing) = self.profile_mut(profile.id) {
            ensure!(
                existing.kind == profile.kind,
                "A profile cannot change provider; create a new profile instead"
            );
            *existing = profile;
            return Ok(());
        }
        ensure!(
            self.profiles.len() < MAX_PROFILES,
            "At most {MAX_PROFILES} provider profiles are supported"
        );
        if self.config.default_profile.is_none() {
            self.config.default_profile = Some(profile.id);
        }
        self.profiles.push(profile);
        Ok(())
    }

    /// Removes a profile and its stored credential. Conversations that used it keep their history
    /// but must choose a profile explicitly before sending again.
    pub fn remove_profile(&mut self, id: Uuid) -> bool {
        let before = self.profiles.len();
        self.profiles.retain(|profile| profile.id != id);
        if self.profiles.len() == before {
            return false;
        }
        if self.config.default_profile == Some(id) {
            self.config.default_profile = None;
        }
        for conversation in &mut self.conversations {
            if conversation.profile_id == Some(id) {
                conversation.profile_id = None;
            }
        }
        true
    }

    pub fn remove_conversation(&mut self, id: Uuid) -> bool {
        let before = self.conversations.len();
        self.conversations
            .retain(|conversation| conversation.id != id);
        self.conversations.len() != before
    }

    /// Deletes every conversation, temporary ones included. Returns how many were deleted.
    pub fn clear_history(&mut self) -> usize {
        let deleted = self.conversations.len();
        self.conversations.clear();
        deleted
    }

    /// Conversations whose title or messages contain `query` (case-insensitive), newest first.
    /// Empty unless local history search is allowed.
    pub fn search(&self, query: &str) -> Vec<Uuid> {
        let needle: String = query.trim().chars().flat_map(char::to_lowercase).collect();
        if needle.is_empty() || !self.config.allows(Feature::HistorySearch) {
            return Vec::new();
        }
        let mut found: Vec<&Conversation> = self
            .conversations
            .iter()
            .filter(|conversation| {
                contains_ignore_case(&conversation.display_title(), &needle)
                    || conversation
                        .messages
                        .iter()
                        .any(|message| contains_ignore_case(&message.text, &needle))
            })
            .collect();
        found.sort_by(|left, right| right.updated_at.cmp(&left.updated_at));
        found
            .into_iter()
            .map(|conversation| conversation.id)
            .collect()
    }

    /// Reported usage of messages created at or after `since`, counting shared branch history once.
    pub fn usage_since(&self, since: u64) -> Usage {
        let mut counted = HashSet::new();
        Usage::sum(
            self.conversations
                .iter()
                .flat_map(|conversation| &conversation.messages)
                .filter(|message| message.created_at >= since)
                .filter(|message| counted.insert(message.id))
                .filter_map(|message| message.usage.as_ref()),
        )
    }

    /// Writes a plaintext transcript to a new file readable only by this user. Requires the
    /// transcript export feature, never overwrites, and refuses temporary conversations.
    pub fn export_transcript(&self, conversation_id: Uuid, path: &Path) -> Result<()> {
        ensure!(
            self.config.allows(Feature::Export),
            "Transcript export is turned off"
        );
        let conversation = self
            .conversation(conversation_id)
            .context("The conversation no longer exists")?;
        let profile = conversation.profile_id.and_then(|id| self.profile(id));
        let transcript = conversation.transcript(profile)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("create transcript {}", path.display()))?;
        let written = file
            .write_all(transcript.as_bytes())
            .and_then(|()| file.sync_all());
        if let Err(error) = written {
            drop(file);
            let _ = fs::remove_file(path);
            return Err(error).with_context(|| format!("write transcript {}", path.display()));
        }
        Ok(())
    }

    /// Drops live-only content. Store commits call this, so persisted state never holds a
    /// temporary conversation.
    pub fn normalize(&mut self) {
        self.conversations
            .retain(|conversation| !conversation.temporary);
    }

    /// Applies the retention limit and storage caps to retained history. The least recently
    /// updated conversations go first; a single conversation larger than the storage cap loses
    /// its oldest messages instead. Temporary conversations are never stored and are untouched.
    pub fn prune_history(&mut self, now: u64) -> Pruned {
        let before = self.conversations.len();
        if let Some(days) = self.config.retention_days {
            let cutoff = now.saturating_sub(u64::from(days).saturating_mul(SECONDS_PER_DAY));
            self.conversations
                .retain(|conversation| conversation.temporary || conversation.updated_at >= cutoff);
        }

        let mut retained: Vec<(u64, Uuid, usize)> = self
            .conversations
            .iter()
            .filter(|conversation| !conversation.temporary)
            .map(|conversation| {
                (
                    conversation.updated_at,
                    conversation.id,
                    serialized_len(conversation).saturating_add(1),
                )
            })
            .collect();
        retained.sort_unstable();
        let mut total = self.stored_len();
        let mut count = retained.len();
        let mut removed = HashSet::new();
        for &(_, id, size) in &retained[..retained.len().saturating_sub(1)] {
            if count <= MAX_CONVERSATIONS && total <= MAX_STORED_BYTES {
                break;
            }
            removed.insert(id);
            total = total.saturating_sub(size);
            count -= 1;
        }
        if !removed.is_empty() {
            self.conversations
                .retain(|conversation| !removed.contains(&conversation.id));
        }

        let mut pruned = Pruned {
            conversations: before - self.conversations.len(),
            messages: 0,
        };
        if total > MAX_STORED_BYTES {
            let newest = retained.last().map(|&(_, id, _)| id);
            if let Some(conversation) = newest.and_then(|id| self.conversation_mut(id)) {
                let mut count = 0;
                for message in &conversation.messages {
                    if total <= MAX_STORED_BYTES && message.role == Role::User {
                        break;
                    }
                    total = total.saturating_sub(serialized_len(message));
                    if count + 1 < conversation.messages.len() {
                        total = total.saturating_sub(1);
                    }
                    count += 1;
                }
                conversation.messages.drain(..count);
                pruned.messages = count;
            }
        }
        pruned
    }

    /// Serialized size of the persisted form, which never includes temporary conversations.
    pub fn stored_len(&self) -> usize {
        #[derive(Serialize)]
        struct Stored<'a> {
            config: &'a Config,
            profiles: &'a [Profile],
            #[serde(serialize_with = "serialize_retained")]
            conversations: &'a [Conversation],
        }

        fn serialize_retained<S>(
            conversations: &[Conversation],
            serializer: S,
        ) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            serializer.collect_seq(
                conversations
                    .iter()
                    .filter(|conversation| !conversation.temporary),
            )
        }

        serialized_len(&Stored {
            config: &self.config,
            profiles: &self.profiles,
            conversations: &self.conversations,
        })
    }

    /// Storage invariants for the working copy and the persisted form alike.
    pub fn validate(&self) -> Result<()> {
        self.config.validate()?;
        ensure!(
            self.profiles.len() <= MAX_PROFILES,
            "At most {MAX_PROFILES} provider profiles are supported"
        );
        let mut profiles = HashSet::new();
        for profile in &self.profiles {
            profile.validate()?;
            ensure!(
                profiles.insert(profile.id),
                "Provider profile IDs must be unique"
            );
        }
        if let Some(id) = self.config.default_profile {
            ensure!(
                profiles.contains(&id),
                "The default provider profile does not exist"
            );
        }
        let mut conversations = HashSet::new();
        for conversation in &self.conversations {
            conversation.validate()?;
            ensure!(
                conversations.insert(conversation.id),
                "Conversation IDs must be unique"
            );
        }
        let retained = self
            .conversations
            .iter()
            .filter(|conversation| !conversation.temporary)
            .count();
        ensure!(
            retained <= MAX_CONVERSATIONS,
            "Local history is limited to {MAX_CONVERSATIONS} conversations"
        );
        ensure!(
            self.stored_len() <= MAX_STORED_BYTES,
            "AI history exceeds the {} MiB local storage limit; delete older conversations or set a retention limit",
            MAX_STORED_BYTES / (1024 * 1024)
        );
        Ok(())
    }

    /// Makes AI data loaded from disk valid without failing: invalid values are reset and invalid
    /// entries dropped, so AI settings can never keep the vault from unlocking. Deterministic, and
    /// a no-op for valid data.
    pub fn repair(&mut self) {
        self.config.repair();
        let mut profiles = HashSet::new();
        self.profiles.retain_mut(|profile| {
            profile.repair();
            !profile.id.is_nil() && profiles.insert(profile.id)
        });
        self.profiles.truncate(MAX_PROFILES);
        if self
            .config
            .default_profile
            .is_some_and(|id| self.profile(id).is_none())
        {
            self.config.default_profile = None;
        }
        self.normalize();
        let mut conversations = HashSet::new();
        self.conversations.retain_mut(|conversation| {
            conversation.repair();
            !conversation.id.is_nil() && conversations.insert(conversation.id)
        });
        // Time zero applies only the storage caps, never the time-based retention limit.
        self.prune_history(0);
    }
}

/// Live-only AI naming state for open session tabs. Never serialized: labels belong to the open
/// session, and AI names never change the saved server or the remote hostname.
#[derive(Debug, Default)]
pub struct SessionNames {
    pinned: HashSet<Uuid>,
}

impl SessionNames {
    /// Sanitized tab title for an AI suggestion, or `None` while the session is pinned.
    pub fn suggest(&self, id: Uuid, title: &str) -> Option<String> {
        if self.pinned.contains(&id) {
            return None;
        }
        sanitize_title(title, MAX_TAB_TITLE_CHARS)
    }

    /// A manual rename pins the title until AI naming is explicitly resumed.
    pub fn manual(&mut self, id: Uuid) {
        self.pinned.insert(id);
    }

    pub fn resume(&mut self, id: Uuid) {
        self.pinned.remove(&id);
    }

    pub fn pinned(&self, id: Uuid) -> bool {
        self.pinned.contains(&id)
    }

    /// Returns the original label to show again. Like a manual title, it stays pinned.
    pub fn restore(&mut self, id: Uuid, original: &str) -> String {
        self.pinned.insert(id);
        original.to_owned()
    }

    /// Forgets a closed session.
    pub fn forget(&mut self, id: Uuid) {
        self.pinned.remove(&id);
    }
}

/// First non-blank line of `text` as a printable single-line title of at most `max_chars`, with
/// quotes, Markdown emphasis, a `title:` prefix, and invisible formatting characters removed.
pub fn sanitize_title(text: &str, max_chars: usize) -> Option<String> {
    let line = text.lines().map(str::trim).find(|line| !line.is_empty())?;
    let line = strip_prefix_ignore_case(line, "title:").unwrap_or(line);
    let line = line.trim_matches(|character: char| {
        character.is_whitespace()
            || matches!(character, '"' | '\'' | '`' | '*' | '_' | '#' | '[' | ']')
    });
    let mut title = String::new();
    let mut count = 0;
    let mut pending_space = false;
    for character in line.chars() {
        if character.is_whitespace() || character.is_control() || is_invisible_format(character) {
            pending_space = count > 0;
            continue;
        }
        let needed = if pending_space { 2 } else { 1 };
        if count + needed > max_chars {
            break;
        }
        if pending_space {
            title.push(' ');
            pending_space = false;
        }
        title.push(character);
        count += needed;
    }
    (!title.is_empty()).then_some(title)
}

/// Tab title from an AI task suggestion, optionally prefixed with the local server label
/// (`api · logs`). The server label is local UI data and is never sent to a provider for this.
pub fn compose_tab_title(server: Option<&str>, task: &str, prefix: bool) -> Option<String> {
    let task = sanitize_title(task, MAX_TAB_TITLE_CHARS)?;
    let server = server
        .filter(|_| prefix)
        .and_then(|server| sanitize_title(server, MAX_TAB_TITLE_CHARS));
    let title = match server {
        Some(server) if !task.to_lowercase().starts_with(&server.to_lowercase()) => {
            format!("{server} · {task}")
        }
        _ => task,
    };
    Some(title.chars().take(MAX_TAB_TITLE_CHARS).collect())
}

/// `YYYY-MM-DD HH:MM UTC` for unix seconds.
pub fn format_timestamp(seconds: u64) -> String {
    let (year, month, day) = civil_from_days(seconds / SECONDS_PER_DAY);
    let second_of_day = seconds % SECONDS_PER_DAY;
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02} UTC",
        second_of_day / 3_600,
        second_of_day % 3_600 / 60
    )
}

/// Proleptic Gregorian date for days since 1970-01-01.
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let shifted = days + 719_468;
    let era = shifted / 146_097;
    let day_of_era = shifted % 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + u64::from(month <= 2);
    (year, month, day)
}

/// `text` limited to `max_chars` characters (UTF-8 safe). Longer text keeps its beginning and its
/// most recent end around a visible `[… N characters omitted …]` marker.
pub fn bounded_text(text: &str, max_chars: usize) -> String {
    let total = text.chars().count();
    if total <= max_chars {
        return text.to_owned();
    }
    let marker = |omitted: usize| format!("\n[… {omitted} characters omitted …]\n");
    let reserved = marker(total).chars().count();
    if max_chars <= reserved {
        return text.chars().take(max_chars).collect();
    }
    let kept = max_chars - reserved;
    let head = kept / 3;
    let tail = kept - head;
    let head_end = char_offset(text, head);
    let tail_start = char_offset(text, total - tail);
    let mut bounded = String::with_capacity(head_end + reserved * 3 + (text.len() - tail_start));
    bounded.push_str(&text[..head_end]);
    bounded.push_str(&marker(total - head - tail));
    bounded.push_str(&text[tail_start..]);
    bounded
}

/// Best-effort removal of likely secrets before text is previewed or shared: private key blocks,
/// credential assignments and headers, passwords in URLs, and well-known token formats. It cannot
/// recognize every secret; always show [`REDACTION_DISCLAIMER`] with the reviewed text.
pub fn redact(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    let mut in_private_key = false;
    for line in text.split_inclusive('\n') {
        let body = line.trim_end_matches(['\r', '\n']);
        let ending = &line[body.len()..];
        if in_private_key {
            if private_key_marker(body, "-----END") {
                in_private_key = false;
                output.push_str(ending);
            }
            continue;
        }
        if private_key_marker(body, "-----BEGIN") {
            in_private_key = !private_key_marker(body, "-----END");
            output.push_str(REDACTED_PRIVATE_KEY);
            if !in_private_key {
                output.push_str(ending);
            }
            continue;
        }
        if private_key_marker(body, "-----END") {
            // The block began before this excerpt, e.g. above a terminal snapshot.
            drop_trailing_key_material(&mut output);
            output.push_str(REDACTED_PRIVATE_KEY);
            output.push_str(ending);
            continue;
        }
        redact_line(body, &mut output);
        output.push_str(ending);
    }
    output
}

const SENSITIVE_KEYS: &[&str] = &[
    "password",
    "passwd",
    "passphrase",
    "secret",
    "token",
    "apikey",
    "accesskey",
    "privatekey",
    "authorization",
    "credential",
    "cookie",
    "sessionid",
];
const AUTH_SCHEMES: &[&str] = &["bearer", "basic", "token", "bot"];
const TOKEN_PREFIXES: &[&str] = &[
    "sk-",
    "sk_live_",
    "sk_test_",
    "rk_live_",
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "github_pat_",
    "glpat-",
    "xoxb-",
    "xoxp-",
    "xoxa-",
    "xoxs-",
    "xapp-",
    "tskey-",
    "hf_",
    "npm_",
    "pypi-",
    "AIza",
    "ya29.",
];

fn private_key_marker(line: &str, marker: &str) -> bool {
    line.contains(marker) && line.contains("PRIVATE KEY")
}

/// Removes the visible tail of a private key whose BEGIN line is outside the excerpt: the line
/// just before END, then full-width base64 lines above it.
fn drop_trailing_key_material(output: &mut String) {
    let mut minimum = 4;
    loop {
        let trimmed = output.trim_end_matches(['\r', '\n']);
        let start = trimmed.rfind('\n').map_or(0, |index| index + 1);
        let line = &trimmed[start..];
        if line.len() < minimum
            || !line
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
        {
            return;
        }
        output.truncate(start);
        minimum = 40;
    }
}

fn redact_line(line: &str, output: &mut String) {
    let bytes = line.as_bytes();
    let mut copied = 0;
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index..].starts_with(b"://") {
            let authority = index + 3;
            let end = bytes[authority..]
                .iter()
                .position(|&byte| {
                    byte.is_ascii_whitespace()
                        || matches!(byte, b'/' | b'?' | b'#' | b'"' | b'\'' | b'<' | b'>')
                })
                .map_or(bytes.len(), |offset| authority + offset);
            if let Some(at) = line[authority..end].rfind('@') {
                if let Some(colon) = line[authority..authority + at].find(':') {
                    let secret = authority + colon + 1;
                    let secret_end = authority + at;
                    if secret < secret_end {
                        push_redacted(line, output, &mut copied, secret, secret_end);
                    }
                }
            }
            index = end;
            continue;
        }
        if !is_word_byte(bytes[index]) {
            index += 1;
            continue;
        }
        let start = index;
        while index < bytes.len() && is_word_byte(bytes[index]) {
            index += 1;
        }
        let word = &line[start..index];
        if looks_like_token(word) {
            push_redacted(line, output, &mut copied, start, index);
            continue;
        }
        let value = if word.eq_ignore_ascii_case("bearer") {
            separated_value(line, index)
                .filter(|(value_start, value_end)| value_end - value_start >= 12)
        } else if is_sensitive_key(word) {
            assigned_value(line, index).or_else(|| {
                if word.starts_with("--") {
                    separated_value(line, index)
                } else {
                    None
                }
            })
        } else {
            None
        };
        if let Some((value_start, value_end)) = value {
            push_redacted(line, output, &mut copied, value_start, value_end);
            index = value_end;
        }
    }
    output.push_str(&line[copied..]);
}

fn push_redacted(line: &str, output: &mut String, copied: &mut usize, start: usize, end: usize) {
    output.push_str(&line[*copied..start]);
    output.push_str(REDACTED);
    *copied = end;
}

fn is_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'+' | b'/')
}

fn is_sensitive_key(word: &str) -> bool {
    let mut buffer = [0_u8; 64];
    let mut length = 0;
    for byte in word.bytes().filter(u8::is_ascii_alphanumeric) {
        if length == buffer.len() {
            return false;
        }
        buffer[length] = byte.to_ascii_lowercase();
        length += 1;
    }
    let key = &buffer[..length];
    let contains = |needle: &[u8]| key.windows(needle.len()).any(|window| window == needle);
    // Plural "tokens" counts usage (max_tokens, input_tokens), not credentials.
    SENSITIVE_KEYS.iter().any(|needle| {
        contains(needle.as_bytes()) && !(*needle == "token" && contains(b"tokens".as_slice()))
    }) || matches!(key, b"pass" | b"pw")
}

fn looks_like_token(word: &str) -> bool {
    let word = word.trim_end_matches('.');
    let prefixed = TOKEN_PREFIXES
        .iter()
        .any(|prefix| word.len() >= prefix.len() + 16 && word.starts_with(prefix));
    let aws_access_key = word.len() == 20
        && (word.starts_with("AKIA") || word.starts_with("ASIA"))
        && word
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit());
    let jwt = word.starts_with("eyJ")
        && word.len() >= 32
        && word.bytes().filter(|&byte| byte == b'.').count() >= 2;
    prefixed || aws_access_key || jwt
}

/// Value after `key = value` or `key: value`, where `key_end` follows the key word.
fn assigned_value(line: &str, key_end: usize) -> Option<(usize, usize)> {
    let bytes = line.as_bytes();
    let mut index = key_end;
    if matches!(bytes.get(index), Some(b'"' | b'\'')) {
        index += 1;
    }
    index = skip_blanks(bytes, index);
    match bytes.get(index) {
        Some(b'=') if bytes.get(index + 1) != Some(&b'=') => {}
        Some(b':')
            if bytes.get(index + 1) != Some(&b':') && !bytes[index..].starts_with(b"://") => {}
        _ => return None,
    }
    value_at(line, skip_blanks(bytes, index + 1))
}

/// Value after `--password value` or `Bearer value`.
fn separated_value(line: &str, key_end: usize) -> Option<(usize, usize)> {
    let bytes = line.as_bytes();
    let start = skip_blanks(bytes, key_end);
    if start == key_end || bytes.get(start) == Some(&b'-') {
        return None;
    }
    value_at(line, start)
}

/// Extent of a credential value: a quoted value up to its closing quote, or one token. An
/// authorization scheme such as `Bearer` stays visible and the credential after it is redacted.
/// Shell variable references are not literal secrets and stay visible.
fn value_at(line: &str, start: usize) -> Option<(usize, usize)> {
    let bytes = line.as_bytes();
    let (start, end) = match bytes.get(start) {
        None => return None,
        Some(&quote @ (b'"' | b'\'')) => {
            let open = start + 1;
            let mut close = open;
            while close < bytes.len() && bytes[close] != quote {
                close += if bytes[close] == b'\\' && close + 1 < bytes.len() {
                    2
                } else {
                    1
                };
            }
            (open, close)
        }
        Some(_) => {
            let end = token_end(bytes, start);
            let word = &line[start..end];
            if AUTH_SCHEMES
                .iter()
                .any(|scheme| word.eq_ignore_ascii_case(scheme))
            {
                let next = skip_blanks(bytes, end);
                if next == end {
                    return None;
                }
                (next, token_end(bytes, next))
            } else {
                (start, end)
            }
        }
    };
    (start < end && bytes[start] != b'$').then_some((start, end))
}

fn token_end(bytes: &[u8], start: usize) -> usize {
    bytes[start..]
        .iter()
        .position(|&byte| {
            byte.is_ascii_whitespace()
                || matches!(
                    byte,
                    b',' | b';' | b'&' | b'"' | b'\'' | b')' | b']' | b'}' | b'<' | b'>'
                )
        })
        .map_or(bytes.len(), |offset| start + offset)
}

fn skip_blanks(bytes: &[u8], mut index: usize) -> usize {
    while matches!(bytes.get(index), Some(b' ' | b'\t')) {
        index += 1;
    }
    index
}

fn contains_ignore_case(haystack: &str, lowercase_needle: &str) -> bool {
    haystack.char_indices().any(|(start, _)| {
        let mut rest = haystack[start..].chars().flat_map(char::to_lowercase);
        lowercase_needle
            .chars()
            .all(|expected| rest.next() == Some(expected))
    })
}

fn strip_prefix_ignore_case<'a>(text: &'a str, prefix: &str) -> Option<&'a str> {
    text.get(..prefix.len())
        .filter(|head| head.eq_ignore_ascii_case(prefix))
        .map(|_| &text[prefix.len()..])
}

fn is_invisible_format(character: char) -> bool {
    matches!(
        character,
        '\u{00AD}' | '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2069}' | '\u{FEFF}'
    )
}

fn char_offset(text: &str, chars: usize) -> usize {
    text.char_indices()
        .nth(chars)
        .map_or(text.len(), |(offset, _)| offset)
}

fn floor_boundary(text: &str, index: usize) -> usize {
    if index >= text.len() {
        return text.len();
    }
    let mut index = index;
    while !text.is_char_boundary(index) {
        index -= 1;
    }
    index
}

fn serialized_len<T: Serialize + ?Sized>(value: &T) -> usize {
    struct Counter(usize);

    impl Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0 = self.0.saturating_add(bytes.len());
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let mut counter = Counter(0);
    match serde_json::to_writer(&mut counter, value) {
        Ok(()) => counter.0,
        Err(_) => usize::MAX,
    }
}

fn validate_text(field: &str, value: &str, max_chars: usize) -> Result<()> {
    ensure!(
        !value.chars().any(char::is_control),
        "{field} cannot contain control characters"
    );
    ensure!(
        value.chars().count() <= max_chars,
        "{field} cannot exceed {max_chars} characters"
    );
    Ok(())
}

fn validate_label(field: &str, value: &str, max_chars: usize) -> Result<()> {
    ensure!(!value.trim().is_empty(), "{field} cannot be blank");
    validate_text(field, value, max_chars)
}

fn validate_model(model: &str) -> Result<()> {
    validate_text("Model ID", model, MAX_MODEL_CHARS)?;
    ensure!(
        model.trim() == model,
        "Model ID cannot start or end with spaces"
    );
    Ok(())
}

/// Errors never include the credential itself.
fn validate_credential(credential: &Secret) -> Result<()> {
    let value = credential.expose();
    ensure!(!value.is_empty(), "API key cannot be empty");
    ensure!(
        value.chars().count() <= MAX_CREDENTIAL_CHARS,
        "API key cannot exceed {MAX_CREDENTIAL_CHARS} characters"
    );
    ensure!(
        !value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace()),
        "API key cannot contain spaces or control characters"
    );
    Ok(())
}

/// Accept only managed ChatGPT credentials; no API account, external token mode, or
/// partial login may be persisted as a usable subscription.
pub(super) fn validate_codex_auth(auth: &Secret) -> Result<()> {
    let value = auth.expose();
    ensure!(
        !value.is_empty() && value.len() <= MAX_CODEX_AUTH_BYTES,
        "Codex sign-in credentials exceed the supported size"
    );
    let value: serde_json::Value = serde_json::from_str(value)
        .map_err(|_| anyhow::anyhow!("Codex sign-in credentials are invalid"))?;
    ensure!(
        value["auth_mode"] == "chatgpt"
            && [
                "OPENAI_API_KEY",
                "agent_identity",
                "personal_access_token",
                "bedrock_api_key",
                "bedrock_access_keys"
            ]
            .iter()
            .all(|key| value.get(*key).is_none_or(serde_json::Value::is_null)),
        "Codex subscription profiles accept only ChatGPT sign-in credentials"
    );
    let tokens = &value["tokens"];
    for key in ["id_token", "access_token", "refresh_token"] {
        ensure!(
            tokens[key].as_str().is_some_and(|token| !token.is_empty()),
            "Codex sign-in credentials are incomplete"
        );
    }
    ensure!(
        tokens.get("account_id").is_none_or(|value| {
            value.is_null() || value.as_str().is_some_and(|id| !id.is_empty())
        }),
        "Codex sign-in credentials have an invalid account identifier"
    );
    Ok(())
}

fn validate_codex_path(path: &str) -> Result<()> {
    validate_label("Vyx Codex helper path", path, MAX_PATH_CHARS)?;
    ensure!(
        Path::new(path).is_absolute(),
        "Vyx Codex helper path must be absolute"
    );
    Ok(())
}

fn valid_temperature(kind: ProviderKind, temperature: f64) -> bool {
    kind.max_temperature()
        .is_some_and(|maximum| temperature.is_finite() && (0.0..=maximum).contains(&temperature))
}

/// Built-in providers are pinned to their official endpoint; Codex has none; a compatible endpoint
/// must use HTTPS unless it is on this computer, and never embeds credentials in the URL.
fn validate_base_url(kind: ProviderKind, url: &str) -> Result<()> {
    match kind {
        ProviderKind::Codex => ensure!(
            url.is_empty(),
            "Codex uses its local app server, not an HTTP endpoint"
        ),
        ProviderKind::OpenAi | ProviderKind::Anthropic | ProviderKind::OpenRouter => ensure!(
            url == kind.default_base_url(),
            "{} always uses {}; add an OpenAI-compatible profile for other endpoints",
            kind.label(),
            kind.default_base_url()
        ),
        ProviderKind::Compatible => {
            if !url.is_empty() {
                validate_compatible_url(url)?;
            }
        }
    }
    Ok(())
}

fn validate_compatible_url(value: &str) -> Result<()> {
    ensure!(
        value.chars().count() <= MAX_URL_CHARS,
        "Base URL cannot exceed {MAX_URL_CHARS} characters"
    );
    ensure!(
        !value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace()),
        "Base URL cannot contain spaces or control characters"
    );
    let url = Url::parse(value).context("Base URL is not a valid URL")?;
    ensure!(
        url.username().is_empty() && url.password().is_none(),
        "Put credentials in the API key field, not in the URL"
    );
    ensure!(
        url.query().is_none() && url.fragment().is_none(),
        "Base URL cannot contain a query or fragment"
    );
    let host = url.host_str().context("Base URL needs a host")?;
    match url.scheme() {
        "https" => Ok(()),
        "http" if is_loopback_host(host) => Ok(()),
        "http" => bail!(
            "Use https:// for remote endpoints; plain http:// is allowed only for this computer (localhost)"
        ),
        _ => bail!("Base URL must use https://"),
    }
}

fn is_loopback_host(host: &str) -> bool {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

/// Floats are stored as their exact shortest decimal text: standard JSON float parsing is only
/// best-effort, and a changed value after a round trip would make on-disk state differ from the
/// active state.
mod exact_float {
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};

    pub fn serialize<S>(value: &Option<f64>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(value) => serializer.serialize_str(&value.to_string()),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<f64>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<String>::deserialize(deserializer)?
            .map(|text| text.parse::<f64>().map_err(D::Error::custom))
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn conversation(at: u64, text: &str) -> Conversation {
        let mut conversation = Conversation::new(None, false);
        conversation.created_at = at;
        conversation.updated_at = at;
        let mut message = Message::new(Role::User, text);
        message.created_at = at;
        conversation.push(message).unwrap();
        conversation
    }

    #[test]
    fn saved_state_without_confirmed_permissions_grants_no_authority() {
        // A configuration saved before permissions existed reads as Chat only, never as the
        // fresh-install recommendation, and unknown values cannot grant anything.
        let old: Config = serde_json::from_value(serde_json::json!({
            "enabled": true,
            "features": ["chat"],
        }))
        .unwrap();
        assert_eq!(old.default_permission, PermissionLevel::ChatOnly);
        assert_eq!(old.max_permission, PermissionLevel::ChatOnly);
        assert!(!old.permissions_confirmed);
        assert_eq!(old.effective_permission(PermissionLevel::Full), PermissionLevel::ChatOnly);
        let unknown: Config = serde_json::from_value(serde_json::json!({
            "enabled": true,
            "features": ["chat"],
            "default_permission": "root",
            "max_permission": "everything",
            "capabilities": ["read_output", "format_disks"],
            "permissions_confirmed": true,
        }))
        .unwrap();
        assert_eq!(unknown.max_permission, PermissionLevel::ChatOnly);
        assert_eq!(unknown.capabilities, [Capability::ReadOutput].into_iter().collect());
        assert_eq!(unknown.effective_permission(PermissionLevel::Full), PermissionLevel::ChatOnly);
        let chat: Conversation = serde_json::from_value(serde_json::json!({
            "id": Uuid::new_v4(), "title": "", "profile_id": null, "model": "",
            "session_id": Uuid::new_v4(), "auto_context": true, "messages": [],
            "parent_id": null, "created_at": 1, "updated_at": 1, "naming_paused": false,
        }))
        .unwrap();
        assert_eq!(chat.permission, PermissionLevel::ChatOnly);
        assert!(chat.sessions.is_empty(), "an old binding never becomes scope");

        // Fresh installs recommend Assist, but nothing applies until the user confirms.
        let mut config = Config {
            enabled: true,
            ..Config::default()
        };
        assert_eq!(config.max_permission, PermissionLevel::Assist);
        assert_eq!(config.effective_permission(PermissionLevel::Assist), PermissionLevel::ChatOnly);
        config.permissions_confirmed = true;
        assert_eq!(config.effective_permission(PermissionLevel::Full), PermissionLevel::Assist);
        assert!(!config.grants(PermissionLevel::ChatOnly, Capability::ReadOutput));
        config.capabilities.remove(&Capability::RunCommands);
        assert!(!config.grants(PermissionLevel::Assist, Capability::RunCommands));
        config.set(Feature::Chat, false);
        assert_eq!(config.effective_permission(PermissionLevel::Assist), PermissionLevel::ChatOnly);

        config.set(Feature::Chat, true);
        config.default_permission = PermissionLevel::Full;
        assert!(config.validate().is_err(), "the default cannot exceed the maximum");
        config.agent_steps = 0;
        config.repair();
        assert_eq!(config.default_permission, PermissionLevel::Assist);
        assert_eq!(config.agent_steps, 1);
        config.validate().unwrap();
    }

    #[test]
    fn temporary_content_cannot_be_serialized_or_exported_even_as_a_branch() {
        let mut temporary = conversation(10, "never-persist-this-prompt");
        temporary.title = "never-persist-this-title".into();
        temporary.temporary = true;
        let mut bytes = Vec::new();
        assert!(serde_json::to_writer(&mut bytes, &temporary).is_err());
        let partial = String::from_utf8(bytes).unwrap();
        assert!(!partial.contains("never-persist"));
        let branch = temporary.branch(1).unwrap();
        assert!(branch.temporary);
        assert!(serde_json::to_vec(&branch).is_err());
        assert!(branch.transcript(None).is_err());
        let data = AiData {
            conversations: vec![temporary, branch],
            ..AiData::default()
        };
        assert!(serde_json::to_vec(&data).is_err());
    }

    #[test]
    fn branching_keeps_the_source_and_its_chosen_level_and_scope() {
        let mut source = conversation(10, "first question");
        source.set_scope([Uuid::new_v4(), Uuid::nil()]);
        source.permission = PermissionLevel::Assist;
        source.profile_id = Some(Uuid::new_v4());
        source.model = "chosen-model".into();
        source.naming_paused = true;
        source
            .push(Message::new(Role::Assistant, "first answer"))
            .unwrap();
        source
            .push(Message::new(Role::User, "edit this question"))
            .unwrap();
        let original = source.clone();
        let mut branch = source.branch(2).unwrap();
        assert_ne!(branch.id, source.id);
        assert_eq!(branch.parent_id, Some(source.id));
        assert_eq!(branch.messages, source.messages[..2]);
        assert_eq!(source.sessions.len(), 1, "nil sessions never enter scope");
        assert_eq!(branch.sessions, source.sessions);
        assert_eq!(branch.permission, PermissionLevel::Assist);
        assert_eq!(branch.profile_id, source.profile_id);
        assert_eq!(branch.model, source.model);
        assert!(branch.naming_paused);
        branch
            .push(Message::new(Role::User, "replacement question"))
            .unwrap();
        assert_eq!(source, original);
        assert_eq!(branch.messages[2].text, "replacement question");
        assert!(source.branch(4).is_err());
    }

    #[test]
    fn retention_keeps_the_cutoff_and_future_chats_without_touching_temporary_content() {
        let at = SECONDS_PER_DAY * 3;
        let old = conversation(at - SECONDS_PER_DAY - 1, "expired");
        let boundary = conversation(at - SECONDS_PER_DAY, "still retained");
        let future = conversation(at + 1, "future clock");
        let mut temporary = conversation(0, "live only");
        temporary.temporary = true;
        let expected = vec![boundary.id, future.id, temporary.id];
        let mut data = AiData {
            conversations: vec![old, boundary, future, temporary],
            ..AiData::default()
        };
        data.config.retention_days = Some(1);
        assert_eq!(
            data.prune_history(at),
            Pruned {
                conversations: 1,
                messages: 0
            }
        );
        assert_eq!(
            data.conversations
                .iter()
                .map(|chat| chat.id)
                .collect::<Vec<_>>(),
            expected
        );
    }

    #[test]
    fn history_caps_remove_oldest_chats_and_whole_old_turns() {
        let mut data = AiData::default();
        data.conversations = (0..=MAX_CONVERSATIONS)
            .rev()
            .map(|at| conversation(at as u64, "question"))
            .collect();
        let oldest = data.conversations.last().unwrap().id;
        assert_eq!(data.prune_history(0).conversations, 1);
        assert!(data.conversation(oldest).is_none());
        assert_eq!(data.conversations.len(), MAX_CONVERSATIONS);

        let mut chat = Conversation::new(None, false);
        for index in 0..7 {
            let role = if index % 2 == 0 {
                Role::User
            } else {
                Role::Assistant
            };
            chat.push(Message::new(role, "x".repeat(MAX_MESSAGE_BYTES)))
                .unwrap();
        }
        let remaining = chat.messages[2].id;
        data.conversations = vec![chat];
        assert!(data.stored_len() > MAX_STORED_BYTES);
        assert_eq!(data.prune_history(0).messages, 2);
        assert_eq!(data.conversations[0].messages[0].id, remaining);
        assert!(data.stored_len() <= MAX_STORED_BYTES);
    }

    #[test]
    fn one_message_with_large_json_escaping_cannot_block_storage_or_repair() {
        let chat = conversation(10, &"\0".repeat(MAX_MESSAGE_BYTES));
        let mut data = AiData {
            conversations: vec![chat],
            ..AiData::default()
        };
        assert!(data.stored_len() > MAX_STORED_BYTES);
        data.repair();
        assert!(data.conversations[0].messages.is_empty());
        assert!(data.stored_len() <= MAX_STORED_BYTES);
        data.validate().unwrap();
    }

    #[test]
    fn removing_a_provider_never_falls_back_to_another_recipient() {
        let mut data = AiData::default();
        let first = Profile::new(ProviderKind::OpenAi);
        let second = Profile::new(ProviderKind::Anthropic);
        let first_id = first.id;
        data.conversations
            .push(Conversation::new(Some(&first), false));
        data.put_profile(first).unwrap();
        data.put_profile(second).unwrap();
        let replacement = Profile {
            id: first_id,
            ..Profile::new(ProviderKind::Compatible)
        };
        assert!(data.put_profile(replacement).is_err());
        assert_eq!(data.profile(first_id).unwrap().kind, ProviderKind::OpenAi);
        assert!(data.remove_profile(first_id));
        assert!(data.default_profile().is_none());
        assert!(data.conversations[0].profile_id.is_none());
        assert_eq!(data.profiles[0].kind, ProviderKind::Anthropic);
    }

    #[test]
    fn local_search_obeys_its_switch_and_searches_messages_newest_first() {
        let mut older = conversation(10, "unexpected ÉCHEC in output");
        older.title = "Older".into();
        let mut newer = conversation(20, "other content");
        newer.title = "Échec diagnosis".into();
        let expected = vec![newer.id, older.id];
        let mut data = AiData {
            conversations: vec![older, newer, conversation(30, "no match")],
            ..AiData::default()
        };
        data.config.enabled = true;
        assert_eq!(data.search(" échec "), expected);
        data.config.set(Feature::HistorySearch, false);
        assert!(data.search("échec").is_empty());
        assert!(data.remove_conversation(expected[0]));
        data.config.set(Feature::HistorySearch, true);
        assert_eq!(data.search("échec"), vec![expected[1]]);
        assert_eq!(data.clear_history(), 2);
        assert!(data.search("échec").is_empty());
    }

    #[test]
    fn transcript_export_is_explicit_private_and_never_clobbers() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("transcript.txt");
        let mut profile = Profile::new(ProviderKind::OpenAi);
        profile.credential = Some(Secret::new("private-provider-credential"));
        let mut chat = conversation(10, "shared question");
        chat.profile_id = Some(profile.id);
        chat.push(Message::new(Role::Assistant, "shared answer"))
            .unwrap();
        let id = chat.id;
        let mut data = AiData {
            profiles: vec![profile],
            conversations: vec![chat],
            ..AiData::default()
        };
        assert!(data.export_transcript(id, &path).is_err());
        assert!(!path.exists());
        data.config.enabled = true;
        data.config.set(Feature::Export, true);
        data.export_transcript(id, &path).unwrap();
        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("shared question"));
        assert!(content.contains("shared answer"));
        assert!(!content.contains("private-provider-credential"));
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(data.export_transcript(id, &path).is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), content);
        let temporary_path = directory.path().join("temporary.txt");
        data.conversations[0].temporary = true;
        assert!(data.export_transcript(id, &temporary_path).is_err());
        assert!(!temporary_path.exists());
    }

    #[test]
    fn usage_counts_branched_messages_once_and_preserves_unknown_costs() {
        let mut source = conversation(10, "question");
        let mut answer = Message::new(Role::Assistant, "answer");
        answer.created_at = 11;
        answer.usage = Some(Usage {
            input_tokens: 10,
            output_tokens: 20,
            cost_usd: Some(0.1),
        });
        source.push(answer).unwrap();
        let mut branch = source.branch(2).unwrap();
        let mut next = Message::new(Role::Assistant, "new answer");
        next.created_at = 21;
        next.usage = Some(Usage {
            input_tokens: 30,
            output_tokens: 40,
            cost_usd: None,
        });
        branch.push(next).unwrap();
        let data = AiData {
            conversations: vec![source, branch],
            ..AiData::default()
        };
        assert_eq!(
            data.usage_since(0),
            Usage {
                input_tokens: 40,
                output_tokens: 60,
                cost_usd: None
            }
        );
        assert_eq!(
            data.usage_since(20),
            Usage {
                input_tokens: 30,
                output_tokens: 40,
                cost_usd: None
            }
        );
        assert_eq!(data.usage_since(22), Usage::default());
        let large = Usage {
            input_tokens: u64::MAX,
            output_tokens: 1,
            cost_usd: Some(f64::MAX),
        };
        let total = Usage::sum([&large, &large]);
        assert_eq!(total.total_tokens(), u64::MAX);
        assert_eq!(total.cost_usd, None);
    }

    #[test]
    fn budget_thresholds_do_not_overflow_or_round_down() {
        let mut config = Config {
            budget_tokens: Some(101),
            ..Config::default()
        };
        assert!(config.budget_warning(80).is_none());
        assert!(config.budget_warning(81).is_some());
        config.budget_tokens = Some(u64::MAX);
        assert!(config.budget_warning(u64::MAX / 2).is_none());
        assert!(config.budget_warning(u64::MAX - u64::MAX / 5).is_some());
    }

    #[test]
    fn context_and_stream_limits_preserve_utf8_and_the_latest_question() {
        let mut message = Message::new(Role::Assistant, "x".repeat(MAX_MESSAGE_BYTES - 1));
        assert!(!message.append("é"));
        assert_eq!(message.text.len(), MAX_MESSAGE_BYTES - 1);
        assert!(message.append("x"));
        assert_eq!(message.text.len(), MAX_MESSAGE_BYTES);
        let input = "é".repeat(100);
        let bounded = bounded_text(&input, 60);
        assert!(bounded.chars().count() <= 60);
        assert!(bounded.starts_with('é') && bounded.ends_with('é'));
        assert!(bounded.contains("omitted"));
        let messages = vec![
            Message::new(Role::User, "old question"),
            Message::new(Role::Assistant, "old answer"),
            Message::new(Role::User, "new question"),
        ];
        assert_eq!(context_start(&messages, 30), 2);
        assert_eq!(context_start(&messages, 1), 2);
        assert_eq!(context_start(&messages, 100), 0);
    }

    #[test]
    fn redaction_removes_likely_secrets_without_hiding_usage_or_shell_references() {
        for (input, secret) in [
            ("PASSWORD=hunter2", "hunter2"),
            (r#"{"api_key":"confidential-value"}"#, "confidential-value"),
            (r#"{"password":"first\"still-secret"}"#, "still-secret"),
            (
                "Authorization: Bearer confidential-bearer",
                "confidential-bearer",
            ),
            ("connect https://alice:paßword@example.test/db", "paßword"),
            ("--password 'literal secret'", "literal secret"),
            (
                "token sk-abcdefghijklmnopqrstuv",
                "sk-abcdefghijklmnopqrstuv",
            ),
            (
                "-----BEGIN PRIVATE KEY-----\nQUJDREVGR0g=\n-----END PRIVATE KEY-----\n",
                "QUJDREVGR0g=",
            ),
            (
                "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=\n-----END PRIVATE KEY-----\n",
                "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=",
            ),
        ] {
            let redacted = redact(input);
            assert!(!redacted.contains(secret), "{input}");
            assert!(redacted.contains("REDACTED"));
        }
        let safe = "input_tokens=123\nmax_tokens=4096\npassword=$PASSWORD\nUnicode: 雪";
        assert_eq!(redact(safe), safe);
    }

    #[test]
    fn copied_code_and_reviewed_context_keep_their_exact_content() {
        let blocks =
            code_blocks("```sh\n\nprintf 'first'\n\nprintf 'second'\n```\n```sh\nincomplete");
        assert_eq!(
            blocks,
            vec![CodeBlock {
                language: "sh".into(),
                text: "\nprintf 'first'\n\nprintf 'second'".into(),
            }]
        );
        let attachment = Attachment {
            session_id: Uuid::new_v4(),
            source: "chosen session".into(),
            captured_at: 0,
            text: "```\nreviewed text\n\n".into(),
        };
        assert!(
            attachment
                .to_prompt()
                .contains("````text\n```\nreviewed text\n\n\n````")
        );
    }

    #[test]
    fn subscription_auth_is_local_redacted_and_rejects_api_or_partial_credentials() {
        let mut profile = Profile::new(ProviderKind::Codex);
        let old_profile = serde_json::to_value(&profile).unwrap();
        assert!(old_profile.get("codex_auth").is_none());
        let restored: Profile = serde_json::from_value(old_profile).unwrap();
        assert!(restored.codex_auth.is_none());
        let auth = serde_json::json!({
            "auth_mode": "chatgpt", "OPENAI_API_KEY": null,
            "tokens": {"id_token": "private-id-fixture", "access_token": "private-access-fixture",
                "refresh_token": "private-refresh-fixture", "account_id": "account-fixture"}
        });
        profile.codex_auth = Some(Secret::new(auth.to_string()));
        profile.validate().unwrap();
        assert!(!format!("{profile:?}").contains("private-"));
        let restored: Profile =
            serde_json::from_slice(&serde_json::to_vec(&profile).unwrap()).unwrap();
        assert_eq!(restored.codex_auth, profile.codex_auth);
        let mut optional_account = auth.clone();
        optional_account["tokens"]
            .as_object_mut()
            .unwrap()
            .remove("account_id");
        validate_codex_auth(&Secret::new(optional_account.to_string())).unwrap();
        optional_account["tokens"]["account_id"] = serde_json::Value::Null;
        validate_codex_auth(&Secret::new(optional_account.to_string())).unwrap();
        optional_account["tokens"]["account_id"] = serde_json::json!("");
        assert!(validate_codex_auth(&Secret::new(optional_account.to_string())).is_err());
        for key in [
            "agent_identity",
            "personal_access_token",
            "bedrock_api_key",
            "bedrock_access_keys",
        ] {
            let mut mixed = auth.clone();
            mixed[key] = serde_json::json!({"token": "private-alternate-fixture"});
            assert!(validate_codex_auth(&Secret::new(mixed.to_string())).is_err());
        }
        for invalid in [
            serde_json::json!({"auth_mode": "apikey", "OPENAI_API_KEY": "private-api-fixture"}),
            serde_json::json!({"auth_mode": "chatgpt", "tokens": {"access_token": "private-access-fixture"}}),
            serde_json::json!({"auth_mode": "chatgptAuthTokens", "tokens": auth["tokens"]}),
        ] {
            profile.codex_auth = Some(Secret::new(invalid.to_string()));
            let error = profile.validate().unwrap_err();
            assert!(!format!("{error:#}").contains("private-"));
        }
        profile.codex_auth = Some(Secret::new(auth.to_string()));
        profile.kind = ProviderKind::OpenAi;
        profile.repair();
        assert!(profile.codex_auth.is_none());
    }

    #[test]
    fn provider_endpoints_require_transport_security_and_cannot_embed_credentials() {
        let mut profile = Profile::new(ProviderKind::Compatible);
        for endpoint in [
            "https://models.example.test/v1",
            "http://127.0.0.1:8181/v1",
            "http://[::1]:8181/v1",
        ] {
            profile.base_url = endpoint.into();
            profile.validate().unwrap();
        }
        for endpoint in [
            "http://models.example.test/v1",
            "https://user:password@example.test/v1",
            "https://example.test/v1?api_key=secret",
            "https://example.test/v1#fragment",
            "file:///tmp/provider",
        ] {
            profile.base_url = endpoint.into();
            assert!(profile.validate().is_err(), "{endpoint}");
        }
        profile = Profile::new(ProviderKind::OpenAi);
        profile.base_url = "https://other.example.test/v1".into();
        assert!(profile.validate().is_err());
        profile = Profile::new(ProviderKind::Codex);
        profile.credential = Some(Secret::new("must-not-be-api-billing"));
        assert!(profile.validate().is_err());
    }
}
