//! Public, nonsecret extension contracts and host-owned authorization snapshots.
use std::{collections::{BTreeMap, BTreeSet}, fmt, io::{Read, Write}};

use anyhow::{Result, bail, ensure};
use serde::{Deserialize, Serialize, de::{self, DeserializeOwned, MapAccess, SeqAccess, Visitor}};
use serde_json::Value;
use uuid::Uuid;

pub const MAX_FRAME_BYTES: usize = 1024 * 1024;
pub const MAX_JSON_DEPTH: usize = 32;
pub const MAX_STATE_BYTES: usize = 64 * 1024;
pub const MAX_CALLS_PER_EVENT: u64 = 32;
pub const MAX_ITEMS: usize = 4096;

/// Scan before deserialization so excessively nested input never recurses first.
pub fn validate_json_depth(bytes: &[u8]) -> Result<()> {
    let mut depth = 0usize;
    let mut quoted = false;
    let mut escaped = false;
    for &byte in bytes {
        if quoted {
            if escaped { escaped = false; }
            else if byte == b'\\' { escaped = true; }
            else if byte == b'"' { quoted = false; }
        } else {
            match byte {
                b'"' => quoted = true,
                b'{' | b'[' => { depth += 1; ensure!(depth <= MAX_JSON_DEPTH, "JSON depth limit exceeded"); }
                b'}' | b']' => { depth = depth.checked_sub(1).ok_or_else(|| anyhow::anyhow!("unbalanced JSON"))?; }
                _ => {}
            }
        }
    }
    ensure!(!quoted && depth == 0, "truncated JSON");
    Ok(())
}

// serde_json::Value ordinarily accepts duplicate keys. Reject them at every
// nesting level, including arbitrary state and submit values.
struct UniqueValue(Value);
impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D: de::Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct UniqueVisitor;
        impl<'de> Visitor<'de> for UniqueVisitor {
            type Value = UniqueValue;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result { f.write_str("JSON with unique object keys") }
            fn visit_bool<E: de::Error>(self, v: bool) -> std::result::Result<Self::Value, E> { Ok(UniqueValue(Value::Bool(v))) }
            fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<Self::Value, E> { Ok(UniqueValue(v.into())) }
            fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<Self::Value, E> { Ok(UniqueValue(v.into())) }
            fn visit_f64<E: de::Error>(self, v: f64) -> std::result::Result<Self::Value, E> {
                serde_json::Number::from_f64(v).map(|n| UniqueValue(Value::Number(n))).ok_or_else(|| E::custom("invalid JSON number"))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Self::Value, E> { Ok(UniqueValue(Value::String(v.into()))) }
            fn visit_string<E: de::Error>(self, v: String) -> std::result::Result<Self::Value, E> { Ok(UniqueValue(Value::String(v))) }
            fn visit_unit<E: de::Error>(self) -> std::result::Result<Self::Value, E> { Ok(UniqueValue(Value::Null)) }
            fn visit_none<E: de::Error>(self) -> std::result::Result<Self::Value, E> { self.visit_unit() }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> std::result::Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(value) = seq.next_element::<UniqueValue>()? { values.push(value.0); }
                Ok(UniqueValue(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<Self::Value, A::Error> {
                let mut values = serde_json::Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if values.contains_key(&key) { return Err(de::Error::custom("duplicate JSON key")); }
                    values.insert(key, map.next_value::<UniqueValue>()?.0);
                }
                Ok(UniqueValue(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(UniqueVisitor)
    }
}

pub fn parse_json<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    ensure!(bytes.len() <= MAX_FRAME_BYTES, "JSON size limit exceeded");
    validate_json_depth(bytes)?;
    let value: UniqueValue = serde_json::from_slice(bytes)?;
    Ok(serde_json::from_value(value.0)?)
}

pub fn read_frame<R: Read, T: DeserializeOwned>(reader: &mut R) -> Result<T> {
    read_frame_bounded(reader, MAX_FRAME_BYTES)
}

pub fn read_frame_bounded<R: Read, T: DeserializeOwned>(reader: &mut R, limit: usize) -> Result<T> {
    let mut header = [0; 4];
    reader.read_exact(&mut header)?;
    let len = u32::from_le_bytes(header) as usize;
    ensure!(len > 0 && len <= limit.min(MAX_FRAME_BYTES), "invalid frame length");
    let mut bytes = vec![0; len];
    reader.read_exact(&mut bytes)?;
    parse_json(&bytes)
}

struct BoundedBytes { bytes: Vec<u8>, limit: usize }
impl Write for BoundedBytes {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(std::io::Error::other("JSON size limit exceeded"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
}

pub fn json_bytes_bounded<T: Serialize>(value: &T, limit: usize) -> Result<Vec<u8>> {
    let mut buffer = BoundedBytes { bytes: Vec::new(), limit: limit.min(MAX_FRAME_BYTES) };
    serde_json::to_writer(&mut buffer, value)?;
    validate_json_depth(&buffer.bytes)?;
    Ok(buffer.bytes)
}

pub fn write_frame<W: Write, T: Serialize>(writer: &mut W, value: &T) -> Result<()> {
    write_frame_bounded(writer, value, MAX_FRAME_BYTES)
}

pub fn write_frame_bounded<W: Write, T: Serialize>(writer: &mut W, value: &T, limit: usize) -> Result<()> {
    let bytes = json_bytes_bounded(value, limit)?;
    writer.write_all(&(bytes.len() as u32).to_le_bytes())?;
    writer.write_all(&bytes)?;
    writer.flush()?;
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
pub enum Permission {
    #[serde(rename = "hosts.read")] HostsRead,
    #[serde(rename = "sessions.read")] SessionsRead,
    #[serde(rename = "tailscale.read")] TailscaleRead,
    #[serde(rename = "terminal.propose")] TerminalPropose,
    #[serde(rename = "connections.propose")] ConnectionsPropose,
    #[serde(rename = "hosts.propose")] HostsPropose,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode { PermissionDenied, StaleTarget, InvalidArgument, Unavailable, LimitExceeded, Cancelled, RuntimeFailed }

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolError { pub code: ErrorCode, pub message: String }

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub enum Method {
    #[serde(rename = "hosts.list")] HostsList,
    #[serde(rename = "sessions.list")] SessionsList,
    #[serde(rename = "tailscale.status")] TailscaleStatus,
}
impl Method {
    pub fn permission(self) -> Permission {
        match self { Self::HostsList => Permission::HostsRead, Self::SessionsList => Permission::SessionsRead, Self::TailscaleStatus => Permission::TailscaleRead }
    }
}

/// Constructed only from the currently reviewed package and current local grants.
/// Declarations are not authority; both sets must independently permit every use.
#[derive(Clone, Debug, Default)]
pub struct Permissions { declared: BTreeSet<Permission>, granted: BTreeSet<Permission> }
impl Permissions {
    pub fn new(declared: impl IntoIterator<Item = Permission>, granted: impl IntoIterator<Item = Permission>) -> Self {
        Self { declared: declared.into_iter().collect(), granted: granted.into_iter().collect() }
    }
    pub fn require(&self, permission: Permission) -> std::result::Result<(), ProtocolError> {
        if self.declared.contains(&permission) && self.granted.contains(&permission) { Ok(()) }
        else { Err(ProtocolError { code: ErrorCode::PermissionDenied, message: "Permission is not currently granted".into() }) }
    }
    pub fn authorize_method(&self, method: Method) -> std::result::Result<(), ProtocolError> { self.require(method.permission()) }
    pub fn authorize_proposal(&self, proposal: &Proposal) -> std::result::Result<(), ProtocolError> {
        match proposal {
            Proposal::InsertCommand { .. } => self.require(Permission::TerminalPropose),
            Proposal::ConnectSaved { .. } => self.require(Permission::ConnectionsPropose),
            Proposal::ConnectTailnet { .. } => { self.require(Permission::TailscaleRead)?; self.require(Permission::ConnectionsPropose) }
            Proposal::SaveTailnet { .. } => { self.require(Permission::TailscaleRead)?; self.require(Permission::HostsPropose) }
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Bootstrap { pub protocol_version: u32, pub runtime_version: String }

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum OpenReason { Launch, Reload }

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", rename_all_fields = "camelCase", deny_unknown_fields)]
pub enum Event {
    Open { command_id: String, reason: OpenReason },
    Action { action_id: String, #[serde(default, skip_serializing_if = "Option::is_none")] item_id: Option<String> },
    Submit { action_id: String, values: BTreeMap<String, FormValue> },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum FormValue { Text(String), Toggle(bool) }

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase", rename_all_fields = "camelCase", deny_unknown_fields)]
pub enum ParentMessage {
    Event { id: u64, event: Event, state: Value },
    Response { event_id: u64, id: u64, #[serde(default, deserialize_with = "present_json", skip_serializing_if = "Option::is_none")] value: Option<Value>, #[serde(default, skip_serializing_if = "Option::is_none")] error: Option<ProtocolError> },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase", rename_all_fields = "camelCase", deny_unknown_fields)]
pub enum GuestMessage {
    Request { event_id: u64, id: u64, method: Method },
    Result { event_id: u64, result: ExtensionResult },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase", rename_all_fields = "camelCase", deny_unknown_fields)]
pub enum WorkerMessage {
    Ready,
    Request { event_id: u64, id: u64, method: Method },
    Result { event_id: u64, result: ExtensionResult },
    Failure { #[serde(default, skip_serializing_if = "Option::is_none")] event_id: Option<u64>, error: ProtocolError },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionResult {
    pub view: View,
    #[serde(default, deserialize_with = "present_json", skip_serializing_if = "Option::is_none")]
    pub state: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposal: Option<Proposal>,
}

fn present_json<'de, D: de::Deserializer<'de>>(deserializer: D) -> std::result::Result<Option<Value>, D::Error> {
    Value::deserialize(deserializer).map(Some)
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
pub enum View {
    List { title: String, #[serde(default)] searchable: bool, items: Vec<ListItem>, #[serde(default)] actions: Vec<Action> },
    Detail { title: String, fields: Vec<DetailField>, #[serde(default)] actions: Vec<Action> },
    Form { title: String, fields: Vec<FormField>, #[serde(default)] actions: Vec<Action> },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Action { pub id: String, pub label: String }

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ListItem {
    pub id: String,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subtitle: Option<String>,
    #[serde(default)]
    pub metadata: Vec<DetailField>,
    #[serde(default)]
    pub actions: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DetailField { pub label: String, pub value: String }

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase", rename_all_fields = "camelCase", deny_unknown_fields)]
pub enum FormField {
    Text { id: String, label: String, #[serde(default)] value: String, max_length: usize },
    Select { id: String, label: String, options: Vec<SelectOption>, #[serde(default, skip_serializing_if = "Option::is_none")] value: Option<String> },
    Toggle { id: String, label: String, #[serde(default)] value: bool },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SelectOption { pub id: String, pub label: String }

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConnectionMode { TailscaleSsh, StandardSsh }

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", rename_all_fields = "camelCase", deny_unknown_fields)]
pub enum Proposal {
    InsertCommand { session_id: Uuid, command: String },
    ConnectSaved { host_id: Uuid },
    ConnectTailnet { node_ref: String, mode: ConnectionMode },
    SaveTailnet { node_ref: String, mode: ConnectionMode },
}

fn bidi_control(c: char) -> bool { matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}') }
pub fn sanitize_display(text: &str) -> String { text.chars().filter(|c| !c.is_control() && !bidi_control(*c)).collect() }
pub fn validate_display_text(text: &str, max_chars: usize) -> Result<()> {
    ensure!(text.chars().count() <= max_chars, "display text limit exceeded");
    Ok(())
}
fn display(text: &mut String, max_chars: usize) -> Result<()> {
    validate_display_text(text, max_chars)?;
    sanitize_display_in_place(text);
    Ok(())
}
pub fn sanitize_display_in_place(text: &mut String) {
    text.retain(|c| !c.is_control() && !bidi_control(c));
}
pub fn validate_id(id: &str) -> Result<()> {
    ensure!(!id.trim().is_empty() && id.len() <= 256, "invalid ID length");
    ensure!(!id.chars().any(|c| c.is_control() || bidi_control(c) || matches!(c, '\u{2028}' | '\u{2029}')), "invalid ID character");
    Ok(())
}
pub fn validate_terminal_command(command: &str) -> Result<()> {
    ensure!(!command.is_empty() && command.len() <= 8192, "command must contain 1 to 8192 bytes");
    ensure!(!command.chars().any(|c| c.is_control() || bidi_control(c) || matches!(c, '\u{2028}' | '\u{2029}')), "command contains terminal controls or line separators");
    Ok(())
}
impl Proposal {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::InsertCommand { session_id, command } => { ensure!(!session_id.is_nil(), "invalid session ID"); validate_terminal_command(command) }
            Self::ConnectSaved { host_id } => { ensure!(!host_id.is_nil(), "invalid host ID"); Ok(()) }
            Self::ConnectTailnet { node_ref, .. } | Self::SaveTailnet { node_ref, .. } => validate_id(node_ref),
        }
    }
}

impl View {
    pub fn actions(&self) -> &[Action] {
        match self { Self::List { actions, .. } | Self::Detail { actions, .. } | Self::Form { actions, .. } => actions }
    }
    /// Validate raw lengths before sanitizing display-only fields. Identifiers,
    /// state, entered form values and proposals are never silently rewritten.
    pub fn validate_and_sanitize(&mut self) -> Result<()> {
        let (title, actions) = match self {
            Self::List { title, actions, .. } | Self::Detail { title, actions, .. } | Self::Form { title, actions, .. } => (title, actions),
        };
        display(title, 256)?;
        ensure!(actions.len() <= 16, "action limit exceeded");
        let mut action_ids = BTreeSet::new();
        for action in actions {
            validate_id(&action.id)?;
            ensure!(action_ids.insert(action.id.clone()), "duplicate action ID");
            display(&mut action.label, 256)?;
        }
        match self {
            Self::List { items, .. } => {
                ensure!(items.len() <= MAX_ITEMS, "item limit exceeded");
                let mut ids = BTreeSet::new();
                for item in items {
                    validate_id(&item.id)?;
                    ensure!(ids.insert(&item.id), "duplicate item ID");
                    display(&mut item.title, 256)?;
                    if let Some(subtitle) = &mut item.subtitle { display(subtitle, 256)?; }
                    validate_details(&mut item.metadata)?;
                    ensure!(item.actions.len() <= 16, "item action limit exceeded");
                    let mut references = BTreeSet::new();
                    for id in &item.actions {
                        ensure!(action_ids.contains(id) && references.insert(id), "invalid item action reference");
                    }
                }
            }
            Self::Detail { fields, .. } => validate_details(fields)?,
            Self::Form { fields, .. } => {
                ensure!(fields.len() <= 24, "form field limit exceeded");
                let mut ids = BTreeSet::new();
                for field in fields {
                    let (id, label) = match field {
                        FormField::Text { id, label, .. } | FormField::Select { id, label, .. } | FormField::Toggle { id, label, .. } => (id, label),
                    };
                    validate_id(id)?;
                    ensure!(ids.insert(id.clone()), "duplicate field ID");
                    display(label, 256)?;
                    match field {
                        FormField::Text { value, max_length, .. } => {
                            ensure!(*max_length > 0 && *max_length <= 8192 && value.len() <= *max_length, "invalid text field bounds");
                            ensure!(!value.chars().any(|c| c.is_control() || bidi_control(c)), "invalid form value");
                        }
                        FormField::Select { options, value, .. } => {
                            ensure!(!options.is_empty() && options.len() <= MAX_ITEMS, "invalid select option count");
                            let mut option_ids = BTreeSet::new();
                            for option in options {
                                validate_id(&option.id)?;
                                ensure!(option_ids.insert(option.id.clone()), "duplicate select option ID");
                                display(&mut option.label, 256)?;
                            }
                            if let Some(value) = value { ensure!(option_ids.contains(value), "select value is not an option"); }
                        }
                        FormField::Toggle { .. } => {}
                    }
                }
            }
        }
        Ok(())
    }
}
fn validate_details(fields: &mut [DetailField]) -> Result<()> {
    ensure!(fields.len() <= MAX_ITEMS, "detail field limit exceeded");
    for field in fields {
        display(&mut field.label, 256)?;
        ensure!(field.value.len() <= 8192, "detail value limit exceeded");
        display(&mut field.value, 8192)?;
    }
    Ok(())
}
impl ExtensionResult {
    pub fn validate_and_sanitize(&mut self) -> Result<()> {
        json_bytes_bounded(self, MAX_FRAME_BYTES)?;
        if let Some(state) = &self.state { json_bytes_bounded(state, MAX_STATE_BYTES)?; }
        if let Some(proposal) = &self.proposal { proposal.validate()?; }
        self.view.validate_and_sanitize()
    }
}

impl Event {
    /// The parent validates events against its current manifest/view; guests do
    /// not select command/action targets or invent form fields.
    pub fn validate(&self, manifest: &super::package::Manifest, current_view: Option<&View>) -> Result<()> {
        match self {
            Self::Open { command_id, .. } => ensure!(manifest.declares_command(command_id), "undeclared command"),
            Self::Action { action_id, item_id } => {
                let view = current_view.ok_or_else(|| anyhow::anyhow!("no current view"))?;
                ensure!(view.actions().iter().any(|a| &a.id == action_id), "undeclared action");
                if let Some(item_id) = item_id {
                    let View::List { items, .. } = view else { bail!("item action requires a list"); };
                    ensure!(items.iter().any(|item| &item.id == item_id && item.actions.contains(action_id)), "undeclared item action");
                }
            }
            Self::Submit { action_id, values } => {
                let Some(View::Form { fields, actions, .. }) = current_view else { bail!("submit requires a form"); };
                ensure!(actions.iter().any(|a| &a.id == action_id), "undeclared submit action");
                ensure!(values.len() == fields.len(), "form fields do not match");
                for field in fields {
                    match field {
                        FormField::Text { id, max_length, .. } => {
                            let Some(FormValue::Text(value)) = values.get(id) else { bail!("text field type mismatch"); };
                            ensure!(value.len() <= *max_length, "text field limit exceeded");
                        }
                        FormField::Select { id, options, .. } => {
                            let Some(FormValue::Text(value)) = values.get(id) else { bail!("select field type mismatch"); };
                            ensure!(options.iter().any(|o| &o.id == value), "invalid select value");
                        }
                        FormField::Toggle { id, .. } => ensure!(matches!(values.get(id), Some(FormValue::Toggle(_))), "toggle field type mismatch"),
                    }
                }
            }
        }
        Ok(())
    }
}

/// Never deserialized from guest messages. These identities are minted by the
/// parent's channel owner and invalidated before lifecycle cancellation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Binding { pub extension_id: String, pub digest: String, pub grant_generation: u64, pub view_generation: u64 }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Provenance { CommandLaunch, Action, Submission, AutomaticReload }
impl Provenance {
    fn matches(self, event: &Event) -> bool {
        matches!((self, event), (Self::CommandLaunch, Event::Open { reason: OpenReason::Launch, .. }) | (Self::Action, Event::Action { .. }) | (Self::Submission, Event::Submit { .. }) | (Self::AutomaticReload, Event::Open { reason: OpenReason::Reload, .. }))
    }
}

#[derive(Debug)]
pub struct ProposalSnapshot {
    binding: Binding,
    event_id: u64,
    provenance: Provenance,
    proposal: Option<Proposal>,
}
impl ProposalSnapshot {
    pub fn new(binding: Binding, event_id: u64, provenance: Provenance, event: &Event, proposal: Proposal, permissions: &Permissions) -> Result<Self> {
        ensure!(event_id > 0 && provenance.matches(event), "invalid event provenance");
        ensure!(provenance != Provenance::AutomaticReload, "automatic reload cannot propose actions");
        proposal.validate()?;
        permissions.authorize_proposal(&proposal).map_err(|error| anyhow::anyhow!("{:?}: {}", error.code, error.message))?;
        Ok(Self { binding, event_id, provenance, proposal: Some(proposal) })
    }
    pub fn proposal(&self) -> Option<&Proposal> { self.proposal.as_ref() }
    pub fn binding(&self) -> &Binding { &self.binding }
    pub fn event_id(&self) -> u64 { self.event_id }
    pub fn provenance(&self) -> Provenance { self.provenance }
    /// Call synchronously after host target/authentication/vault freshness checks
    /// and before closing the originating surface. A consumed operation is no
    /// longer owned by the extension lifecycle.
    pub fn consume(&mut self, current: &Binding, permissions: &Permissions) -> Result<Proposal> {
        ensure!(&self.binding == current, "stale proposal generation");
        let proposal = self.proposal.as_ref().ok_or_else(|| anyhow::anyhow!("proposal already consumed"))?;
        permissions.authorize_proposal(proposal).map_err(|error| anyhow::anyhow!("{:?}: {}", error.code, error.message))?;
        Ok(self.proposal.take().expect("checked above"))
    }
}

// These wire DTOs intentionally cannot contain credentials, terminal contents,
// local principals, host keys, authentication URLs or raw status documents.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostMetadata {
    pub id: Uuid, pub label: String, pub address: String, pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")] pub category: Option<String>,
    pub authentication_mode: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SessionMetadata {
    pub id: Uuid, pub label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")] pub host_id: Option<Uuid>,
    pub phase: SessionPhase,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SessionPhase { Connecting, Authenticating, Connected, Disconnected, Failed }
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TailscaleStatus {
    pub state: TailscaleState,
    #[serde(default, skip_serializing_if = "Option::is_none")] pub tailnet_name: Option<String>,
    pub peers: Vec<TailscalePeer>,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TailscaleState { Running, Stopped, SignedOut, NeedsApproval, Unavailable }
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TailscalePeer {
    pub node_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")] pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")] pub dns_name: Option<String>,
    pub addresses: Vec<std::net::IpAddr>,
    pub online: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")] pub last_seen: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")] pub os: Option<String>,
    #[serde(default)] pub tags: Vec<String>,
    pub ssh_host_keys_available: bool,
}

impl ParentMessage {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Event { id, state, .. } => {
                ensure!(*id > 0, "invalid event ID");
                json_bytes_bounded(state, MAX_STATE_BYTES)?;
            }
            Self::Response { event_id, id, value, error } => {
                ensure!(*event_id > 0 && *id > 0, "invalid response ID");
                ensure!(value.is_some() != error.is_some(), "response requires exactly one value or error");
                if let Some(error) = error { ensure!(error.message.len() <= 8192, "error message limit exceeded"); }
            }
        }
        Ok(())
    }
}

impl HostMetadata {
    pub fn validate_and_sanitize(&mut self) -> Result<()> {
        ensure!(!self.id.is_nil() && self.port > 0, "invalid host metadata");
        display(&mut self.label, 256)?;
        display(&mut self.address, 256)?;
        display(&mut self.authentication_mode, 256)?;
        if let Some(category) = &mut self.category { display(category, 256)?; }
        Ok(())
    }
}
impl SessionMetadata {
    pub fn validate_and_sanitize(&mut self) -> Result<()> {
        ensure!(!self.id.is_nil() && !self.host_id.is_some_and(|id| id.is_nil()), "invalid session metadata");
        display(&mut self.label, 256)
    }
}
pub fn is_tailscale_address(address: &std::net::IpAddr) -> bool {
    match address {
        std::net::IpAddr::V4(ip) => (u32::from(*ip) & 0xffc0_0000) == 0x6440_0000,
        std::net::IpAddr::V6(ip) => ip.segments()[..3] == [0xfd7a, 0x115c, 0xa1e0],
    }
}
impl TailscaleStatus {
    pub fn validate_and_sanitize(&mut self) -> Result<()> {
        ensure!(self.peers.len() <= MAX_ITEMS, "peer limit exceeded");
        if let Some(name) = &mut self.tailnet_name { display(name, 256)?; }
        let mut refs = BTreeSet::new();
        for peer in &mut self.peers {
            validate_id(&peer.node_ref)?;
            ensure!(refs.insert(&peer.node_ref), "duplicate node reference");
            for value in [&mut peer.name, &mut peer.dns_name, &mut peer.last_seen, &mut peer.os].into_iter().flatten() {
                display(value, 256)?;
            }
            ensure!(peer.addresses.len() <= 16 && peer.addresses.iter().all(is_tailscale_address), "invalid Tailscale address");
            ensure!(peer.tags.len() <= 256, "tag limit exceeded");
            for tag in &mut peer.tags { display(tag, 256)?; }
        }
        json_bytes_bounded(self, MAX_FRAME_BYTES)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn result(view: Value) -> ExtensionResult {
        parse_json(&serde_json::to_vec(&json!({"view":view})).unwrap()).unwrap()
    }
    fn binding() -> Binding {
        Binding { extension_id: "org.example.test".into(), digest: "a".repeat(64), grant_generation: 1, view_generation: 2 }
    }
    fn proposal() -> Proposal {
        Proposal::InsertCommand { session_id: Uuid::from_u128(1), command: "printf '%s' hello".into() }
    }

    #[test]
    fn frames_reject_duplicate_keys_deep_truncated_and_oversized_data() {
        assert!(parse_json::<Value>(br#"{"state":{"x":1,"x":2}}"#).is_err());
        let deep = format!("{}0{}", "[".repeat(33), "]".repeat(33));
        assert!(parse_json::<Value>(deep.as_bytes()).is_err());
        let mut oversized = ((MAX_FRAME_BYTES + 1) as u32).to_le_bytes().as_slice().to_vec();
        assert!(read_frame::<_, Value>(&mut oversized.as_slice()).is_err());
        oversized = vec![10, 0, 0, 0, b'{', b'}'];
        assert!(read_frame::<_, Value>(&mut oversized.as_slice()).is_err());
        let original = json!({"escaped":"[\\\"{", "state":{"x":[true,null]}});
        let mut frame = Vec::new();
        write_frame(&mut frame, &original).unwrap();
        assert_eq!(read_frame::<_, Value>(&mut frame.as_slice()).unwrap(), original);
    }

    #[test]
    fn omitted_and_null_state_have_distinct_meanings() {
        let omitted: ExtensionResult = parse_json(br#"{"view":{"kind":"detail","title":"Hi","fields":[]}}"#).unwrap();
        let null: ExtensionResult = parse_json(br#"{"view":{"kind":"detail","title":"Hi","fields":[]},"state":null}"#).unwrap();
        assert!(omitted.state.is_none());
        assert_eq!(null.state, Some(Value::Null));
        assert!(parse_json::<ExtensionResult>(br#"{"view":{"kind":"detail","title":"Hi","fields":[]},"exec":"whoami"}"#).is_err());
    }

    #[test]
    fn views_reject_duplicates_unknown_references_and_secret_field_types() {
        let mut duplicate = result(json!({"kind":"list","title":"List","items":[{"id":"same","title":"A"},{"id":"same","title":"B"}]}));
        assert!(duplicate.validate_and_sanitize().is_err());
        let mut missing = result(json!({"kind":"list","title":"List","items":[{"id":"one","title":"A","actions":["absent"]}]}));
        assert!(missing.validate_and_sanitize().is_err());
        assert!(parse_json::<View>(br#"{"kind":"form","title":"Login","fields":[{"kind":"password","id":"p","label":"Password"}]}"#).is_err());
        let mut bounded = result(json!({"kind":"form","title":"Text","fields":[{"kind":"text","id":"f","label":"F","maxLength":2,"value":"abc"}]}));
        assert!(bounded.validate_and_sanitize().is_err());
    }

    #[test]
    fn sanitize_display_but_never_rewrite_commands() {
        let mut display_result = result(json!({"kind":"detail","title":"\u{1b}[31mHello\u{202e}","fields":[]}));
        display_result.validate_and_sanitize().unwrap();
        let View::Detail { title, .. } = display_result.view else { unreachable!() };
        assert_eq!(title, "[31mHello");
        for control in ["\r", "\n", "\u{7f}", "\u{85}", "\u{2028}", "\u{2029}", "\u{202e}", "\u{2066}", "\u{1b}"] {
            assert!(validate_terminal_command(&format!("echo a{control}echo b")).is_err());
        }
        assert!(validate_terminal_command(&"a".repeat(8193)).is_err());
        validate_terminal_command("echo 'hello 世界'").unwrap();
    }

    #[test]
    fn grants_are_not_declarations_and_snapshots_are_one_shot() {
        let declared = [Permission::TerminalPropose];
        assert!(Permissions::new(declared, []).authorize_proposal(&proposal()).is_err());
        assert!(Permissions::new([], declared).authorize_proposal(&proposal()).is_err());
        let allowed = Permissions::new(declared, declared);
        let reload = Event::Open { command_id: "browse".into(), reason: OpenReason::Reload };
        assert!(ProposalSnapshot::new(binding(), 1, Provenance::AutomaticReload, &reload, proposal(), &allowed).is_err());
        assert!(ProposalSnapshot::new(binding(), 1, Provenance::CommandLaunch, &reload, proposal(), &allowed).is_err());
        let launch = Event::Open { command_id: "browse".into(), reason: OpenReason::Launch };
        let mut snapshot = ProposalSnapshot::new(binding(), 1, Provenance::CommandLaunch, &launch, proposal(), &allowed).unwrap();
        let mut stale = binding();
        stale.grant_generation += 1;
        assert!(snapshot.consume(&stale, &allowed).is_err());
        assert!(snapshot.consume(&binding(), &Permissions::default()).is_err());
        assert_eq!(snapshot.consume(&binding(), &allowed).unwrap(), proposal());
        assert!(snapshot.consume(&binding(), &allowed).is_err());
    }

    #[test]
    fn tailnet_proposals_need_both_capabilities_and_addresses_are_private() {
        let proposal = Proposal::ConnectTailnet { node_ref: "opaque".into(), mode: ConnectionMode::TailscaleSsh };
        let read_only = Permissions::new([Permission::TailscaleRead, Permission::ConnectionsPropose], [Permission::TailscaleRead]);
        assert!(read_only.authorize_proposal(&proposal).is_err());
        for address in ["100.64.0.0", "100.127.255.255", "fd7a:115c:a1e0::1"] {
            assert!(is_tailscale_address(&address.parse().unwrap()));
        }
        for address in ["100.63.255.255", "100.128.0.0", "127.0.0.1", "fd7a:115c:a1e1::1"] {
            assert!(!is_tailscale_address(&address.parse().unwrap()));
        }
    }

    #[test]
    fn state_and_detail_byte_limits_apply_before_sanitization() {
        let mut result = ExtensionResult {
            view: View::Detail { title: "Detail".into(), fields: vec![], actions: vec![] },
            state: Some(Value::String("a".repeat(MAX_STATE_BYTES))),
            proposal: None,
        };
        assert!(result.validate_and_sanitize().is_err());
        result.state = None;
        result.view = View::Detail {
            title: "Detail".into(),
            fields: vec![DetailField { label: "Value".into(), value: "\u{1b}".repeat(8193) }],
            actions: vec![],
        };
        assert!(result.validate_and_sanitize().is_err());
    }

    #[test]
    fn submissions_cannot_invent_fields_or_bypass_select_options() {
        let manifest = super::super::package::Manifest {
            schema_version: 1, api_version: 1, id: "org.example.test".into(),
            name: "Test".into(), description: "".into(), version: "1.0.0".into(),
            permissions: vec![],
            commands: vec![super::super::package::Command { id: "open".into(), title: "Open".into(), description: "".into() }],
        };
        let view = View::Form {
            title: "Choice".into(),
            fields: vec![FormField::Select {
                id: "choice".into(), label: "Choice".into(),
                options: vec![SelectOption { id: "one".into(), label: "One".into() }], value: None,
            }],
            actions: vec![Action { id: "submit".into(), label: "Submit".into() }],
        };
        for values in [json!({"choice":"two"}), json!({"unknown":"one"}), json!({"choice":true})] {
            let event: Event = serde_json::from_value(json!({"kind":"submit","actionId":"submit","values":values})).unwrap();
            assert!(event.validate(&manifest, Some(&view)).is_err());
        }
        let event: Event = serde_json::from_value(json!({"kind":"submit","actionId":"submit","values":{"choice":"one"}})).unwrap();
        event.validate(&manifest, Some(&view)).unwrap();
        assert!(Event::Open { command_id: "missing".into(), reason: OpenReason::Launch }.validate(&manifest, None).is_err());
    }

    #[test]
    fn null_rpc_value_is_present_but_ambiguous_response_is_invalid() {
        let response: ParentMessage = parse_json(br#"{"kind":"response","eventId":1,"id":1,"value":null}"#).unwrap();
        response.validate().unwrap();
        let response: ParentMessage = parse_json(br#"{"kind":"response","eventId":1,"id":1}"#).unwrap();
        assert!(response.validate().is_err());
        let response: ParentMessage = parse_json(br#"{"kind":"response","eventId":1,"id":1,"value":null,"error":{"code":"UNAVAILABLE","message":"no"}}"#).unwrap();
        assert!(response.validate().is_err());
    }
}
