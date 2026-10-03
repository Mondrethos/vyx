use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fmt::Write as _;
use std::net::IpAddr;

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::ai::AiData;

pub const SCHEMA_VERSION: u32 = 3;
pub const PASSWORD_SCHEMA_VERSION: u32 = 2;

#[derive(Clone, PartialEq, Eq)]
pub struct Secret(Zeroizing<String>);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    pub fn expose(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

impl Serialize for Secret {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.expose())
    }
}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer).map(Self::new)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Vault {
    pub schema_version: u32,
    pub id: Uuid,
    pub snapshot_id: Uuid,
    pub categories: Vec<Category>,
    pub credentials: Vec<Credential>,
    pub hosts: Vec<Host>,
    pub snippets: Vec<Snippet>,
    pub known_hosts: Vec<KnownHost>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Category {
    pub id: Uuid,
    pub label: String,
    pub parent_id: Option<Uuid>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credential {
    pub id: Uuid,
    pub label: String,
    pub username: String,
    pub auth: Auth,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Auth {
    Password {
        password: Secret,
    },
    PrivateKey {
        pem: Secret,
        passphrase: Option<Secret>,
    },
    Agent,
    KeyboardInteractive,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostTransport {
    #[default]
    Direct,
    Tailscale,
}

impl HostTransport {
    pub fn is_direct(&self) -> bool {
        *self == Self::Direct
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TailscaleIdentity {
    #[serde(deserialize_with = "deserialize_stable_id")]
    pub tailnet_id: String,
    #[serde(deserialize_with = "deserialize_stable_id")]
    pub node_id: String,
}

fn validate_stable_id(value: &str) -> Result<()> {
    validate_nonblank_text("Tailscale stable identity", value)?;
    ensure!(value.len() <= 128, "Tailscale stable identity exceeds 128 bytes");
    Ok(())
}

fn deserialize_stable_id<'de, D>(deserializer: D) -> std::result::Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    validate_stable_id(&value).map_err(serde::de::Error::custom)?;
    Ok(value)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum HostAuth {
    Credential { credential_id: Uuid },
    Password { username: String, password: Secret },
    Tailscale {
        username: String,
        tailscale: TailscaleIdentity,
    },
}

impl HostAuth {
    pub fn credential_id(&self) -> Option<Uuid> {
        match self {
            Self::Credential { credential_id } => Some(*credential_id),
            Self::Password { .. } | Self::Tailscale { .. } => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Host {
    pub id: Uuid,
    pub label: String,
    pub hostname: String,
    pub port: u16,
    pub category_id: Option<Uuid>,
    #[serde(skip_serializing_if = "HostTransport::is_direct")]
    pub transport: HostTransport,
    #[serde(flatten)]
    pub auth: HostAuth,
}

fn deserialize_present<'de, D, T>(deserializer: D) -> std::result::Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

impl<'de> Deserialize<'de> for Host {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct RawHost {
            id: Uuid,
            label: String,
            hostname: String,
            port: u16,
            category_id: Option<Uuid>,
            #[serde(default)]
            transport: HostTransport,
            #[serde(default, deserialize_with = "deserialize_present")]
            credential_id: Option<Uuid>,
            #[serde(default, deserialize_with = "deserialize_present")]
            username: Option<String>,
            #[serde(default, deserialize_with = "deserialize_present")]
            password: Option<Secret>,
            #[serde(default, deserialize_with = "deserialize_present")]
            tailscale: Option<TailscaleIdentity>,
        }

        let raw = RawHost::deserialize(deserializer)?;
        let auth = match (raw.credential_id, raw.username, raw.password, raw.tailscale) {
            (Some(credential_id), None, None, None) => HostAuth::Credential { credential_id },
            (None, Some(username), Some(password), None) => HostAuth::Password { username, password },
            (None, Some(username), None, Some(tailscale)) => {
                HostAuth::Tailscale { username, tailscale }
            }
            _ => {
                return Err(serde::de::Error::custom(
                    "host requires exactly one complete credential, password, or Tailscale authentication",
                ));
            }
        };
        validate_tailscale_auth(&auth, raw.transport, raw.port)
            .map_err(serde::de::Error::custom)?;

        Ok(Self {
            id: raw.id,
            label: raw.label,
            hostname: raw.hostname,
            port: raw.port,
            category_id: raw.category_id,
            transport: raw.transport,
            auth,
        })
    }
}

fn validate_tailscale_auth(auth: &HostAuth, transport: HostTransport, port: u16) -> Result<()> {
    if let HostAuth::Tailscale { username, tailscale } = auth {
        ensure!(
            transport == HostTransport::Tailscale && port == 22,
            "keyless Tailscale authentication requires Tailscale transport and port 22"
        );
        validate_nonblank_text("Tailscale username", username)?;
        ensure!(username.len() <= 256, "Tailscale username exceeds 256 bytes");
        validate_stable_id(&tailscale.tailnet_id)?;
        validate_stable_id(&tailscale.node_id)?;
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snippet {
    pub id: Uuid,
    pub label: String,
    pub command: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnownHost {
    pub hostname: String,
    pub port: u16,
    pub public_key_openssh: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalState {
    pub vault: Vault,
    pub sync: Option<SyncState>,
    /// Device-local AI profiles, settings, and retained chats. Never synchronized: sync, export,
    /// and conflict paths carry only `vault`. Omitted while unused so older builds still open it.
    #[serde(default, skip_serializing_if = "AiData::is_default")]
    pub ai: AiData,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncState {
    pub url: String,
    pub token: Secret,
    pub base_etag: Option<String>,
    pub base_snapshot_id: Option<Uuid>,
    pub base_content_sha256: Option<String>,
    pub pending_upload: Option<PendingUpload>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingUpload {
    pub snapshot_id: Uuid,
    pub envelope_sha256: String,
    pub content_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum LocalDocument {
    Local { state: LocalState },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum VaultDocument {
    Vault { vault: Vault },
}

impl Vault {
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            id: Uuid::new_v4(),
            snapshot_id: Uuid::new_v4(),
            categories: Vec::new(),
            credentials: Vec::new(),
            hosts: Vec::new(),
            snippets: Vec::new(),
            known_hosts: Vec::new(),
        }
    }

    pub fn normalize(&mut self) {
        let required_schema = self.hosts.iter().fold(1, |required, host| {
            let version = if host.transport == HostTransport::Tailscale
                || matches!(&host.auth, HostAuth::Tailscale { .. })
            {
                SCHEMA_VERSION
            } else if matches!(&host.auth, HostAuth::Password { .. }) {
                PASSWORD_SCHEMA_VERSION
            } else {
                1
            };
            required.max(version)
        });
        // Unsupported versions must remain unsupported rather than being repaired here.
        if (1..=SCHEMA_VERSION).contains(&self.schema_version) {
            self.schema_version = self.schema_version.max(required_schema);
        }

        self.categories.sort_unstable_by_key(|entry| entry.id);
        self.credentials.sort_unstable_by_key(|entry| entry.id);
        self.hosts.sort_unstable_by_key(|entry| entry.id);
        self.snippets.sort_unstable_by_key(|entry| entry.id);

        for host in &mut self.hosts {
            if let Ok(canonical) = canonical_hostname(&host.hostname) {
                host.hostname = canonical;
            }
        }
        for known_host in &mut self.known_hosts {
            if let Ok(canonical) = canonical_hostname(&known_host.hostname) {
                known_host.hostname = canonical;
            }
        }
        self.known_hosts.sort_unstable_by(|left, right| {
            (&left.hostname, left.port).cmp(&(&right.hostname, right.port))
        });
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            (1..=SCHEMA_VERSION).contains(&self.schema_version),
            "unsupported vault schema version {}",
            self.schema_version
        );
        ensure!(!self.id.is_nil(), "vault ID cannot be nil");
        ensure!(
            !self.snapshot_id.is_nil(),
            "vault snapshot ID cannot be nil"
        );

        let mut entity_ids = HashSet::with_capacity(
            self.categories.len() + self.credentials.len() + self.hosts.len() + self.snippets.len(),
        );
        for (kind, id) in self
            .categories
            .iter()
            .map(|entry| ("category", entry.id))
            .chain(
                self.credentials
                    .iter()
                    .map(|entry| ("credential", entry.id)),
            )
            .chain(self.hosts.iter().map(|entry| ("host", entry.id)))
            .chain(self.snippets.iter().map(|entry| ("snippet", entry.id)))
        {
            ensure!(!id.is_nil(), "{kind} ID cannot be nil");
            ensure!(entity_ids.insert(id), "duplicate entity UUID {id}");
        }

        let category_ids: HashSet<_> = self.categories.iter().map(|entry| entry.id).collect();
        let credential_ids: HashSet<_> = self.credentials.iter().map(|entry| entry.id).collect();

        for category in &self.categories {
            validate_label("category", &category.label)?;
            if let Some(parent_id) = category.parent_id {
                ensure!(
                    category_ids.contains(&parent_id),
                    "category {} refers to missing parent {parent_id}",
                    category.id
                );
            }
        }
        validate_category_acyclic(&self.categories)?;

        for credential in &self.credentials {
            validate_label("credential", &credential.label)?;
            validate_nonblank_text("credential username", &credential.username)?;
        }

        for host in &self.hosts {
            validate_label("host", &host.label)?;
            canonical_hostname(&host.hostname)
                .with_context(|| format!("host {} has an invalid hostname", host.id))?;
            ensure!(host.port != 0, "host {} has invalid port 0", host.id);
            validate_tailscale_auth(&host.auth, host.transport, host.port)?;
            if host.transport == HostTransport::Tailscale {
                ensure!(
                    self.schema_version >= SCHEMA_VERSION,
                    "Tailscale transport requires schema version {SCHEMA_VERSION}"
                );
            }
            if let Some(category_id) = host.category_id {
                ensure!(
                    category_ids.contains(&category_id),
                    "host {} refers to missing category {category_id}",
                    host.id
                );
            }
            match &host.auth {
                HostAuth::Credential { credential_id } => ensure!(
                    credential_ids.contains(credential_id),
                    "host {} refers to missing credential {}",
                    host.id,
                    credential_id
                ),
                HostAuth::Password { username, .. } => {
                    ensure!(
                        self.schema_version >= PASSWORD_SCHEMA_VERSION,
                        "host {} direct password authentication requires schema version {}",
                        host.id,
                        PASSWORD_SCHEMA_VERSION
                    );
                    validate_nonblank_text("host username", username)?;
                }
                HostAuth::Tailscale { .. } => {}
            }
        }

        for snippet in &self.snippets {
            validate_label("snippet", &snippet.label)?;
            ensure!(
                !contains_control(&snippet.command),
                "snippet {} command contains a control character",
                snippet.id
            );
        }

        let mut endpoints = HashSet::with_capacity(self.known_hosts.len());
        for known_host in &self.known_hosts {
            let hostname = canonical_hostname(&known_host.hostname)
                .context("known-host entry has an invalid hostname")?;
            ensure!(known_host.port != 0, "known-host entry has invalid port 0");
            validate_nonblank_text("known-host public key", &known_host.public_key_openssh)?;
            ensure!(
                endpoints.insert((hostname, known_host.port)),
                "duplicate known-host endpoint"
            );
        }

        Ok(())
    }

    pub fn content_sha256(&self) -> Result<String> {
        let mut vault = self.clone();
        vault.normalize();
        vault.validate()?;
        let document = VaultDocument::Vault { vault };
        let serialized = Zeroizing::new(
            serde_json::to_vec(&document).context("could not serialize vault document")?,
        );
        Ok(sha256(serialized.as_slice()))
    }
}

impl LocalState {
    pub fn new(vault: Vault, sync: Option<SyncState>) -> Self {
        Self {
            vault,
            sync,
            ai: AiData::default(),
        }
    }

    /// Canonical persisted form: normalized vault records and no live-only AI conversations.
    pub fn normalize(&mut self) {
        self.vault.normalize();
        self.ai.normalize();
    }

    pub fn validate(&self) -> Result<()> {
        self.vault.validate()?;
        if let Some(sync) = &self.sync {
            validate_nonblank_text("sync URL", &sync.url)?;
            ensure!(
                !sync.token.expose().is_empty() && !contains_control(sync.token.expose()),
                "sync token is invalid"
            );

            let base_fields = [
                sync.base_etag.is_some(),
                sync.base_snapshot_id.is_some(),
                sync.base_content_sha256.is_some(),
            ];
            ensure!(
                base_fields.iter().all(|present| *present)
                    || base_fields.iter().all(|present| !*present),
                "sync base checkpoint is incomplete"
            );
            if let Some(etag) = &sync.base_etag {
                ensure!(is_strong_sha256_etag(etag), "sync base ETag is invalid");
            }
            if let Some(snapshot_id) = sync.base_snapshot_id {
                ensure!(!snapshot_id.is_nil(), "sync base snapshot ID cannot be nil");
            }
            if let Some(content_sha256) = &sync.base_content_sha256 {
                ensure!(
                    is_lower_sha256(content_sha256),
                    "sync base content digest is invalid"
                );
            }
            if let Some(pending) = &sync.pending_upload {
                ensure!(
                    !pending.snapshot_id.is_nil(),
                    "pending upload snapshot ID cannot be nil"
                );
                ensure!(
                    is_lower_sha256(&pending.envelope_sha256),
                    "pending upload envelope digest is invalid"
                );
                ensure!(
                    is_lower_sha256(&pending.content_sha256),
                    "pending upload content digest is invalid"
                );
            }
        }
        self.ai.validate()
    }
}

pub fn canonical_hostname(hostname: &str) -> Result<String> {
    ensure!(!hostname.is_empty(), "hostname cannot be blank");
    ensure!(
        !hostname.chars().any(char::is_whitespace),
        "hostname cannot contain whitespace"
    );
    ensure!(
        !contains_control(hostname),
        "hostname contains a control character"
    );
    ensure!(
        !hostname.contains('@'),
        "hostname must not include a username"
    );
    ensure!(
        !hostname.starts_with('[') && !hostname.ends_with(']'),
        "IP addresses must be stored without brackets"
    );

    if let Ok(address) = hostname.parse::<IpAddr>() {
        return Ok(address.to_string());
    }

    ensure!(
        !hostname
            .chars()
            .any(|character| matches!(character, ':' | '/' | '\\' | '?' | '#')),
        "hostname must not be a URL or include a port"
    );
    ensure!(hostname.is_ascii(), "DNS hostname must be ASCII");

    let canonical = hostname
        .strip_suffix('.')
        .unwrap_or(hostname)
        .to_ascii_lowercase();
    ensure!(!canonical.is_empty(), "hostname cannot be blank");
    ensure!(canonical.len() <= 253, "DNS hostname is too long");
    for label in canonical.split('.') {
        ensure!(!label.is_empty(), "DNS hostname contains an empty label");
        ensure!(label.len() <= 63, "DNS hostname label is too long");
        ensure!(
            label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-'),
            "DNS hostname contains an invalid character"
        );
        ensure!(
            label.as_bytes().first() != Some(&b'-') && label.as_bytes().last() != Some(&b'-'),
            "DNS hostname label cannot begin or end with a hyphen"
        );
    }

    Ok(canonical)
}

pub fn sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    encoded
}

fn validate_category_acyclic(categories: &[Category]) -> Result<()> {
    let parents: HashMap<_, _> = categories
        .iter()
        .map(|category| (category.id, category.parent_id))
        .collect();
    let mut states = HashMap::<Uuid, u8>::with_capacity(categories.len());

    for category in categories {
        if states.get(&category.id) == Some(&2) {
            continue;
        }
        let mut current = Some(category.id);
        let mut path = Vec::new();
        while let Some(id) = current {
            match states.get(&id).copied() {
                Some(1) => bail!("category hierarchy contains a cycle"),
                Some(2) => break,
                _ => {
                    states.insert(id, 1);
                    path.push(id);
                    current = parents[&id];
                }
            }
        }
        for id in path {
            states.insert(id, 2);
        }
    }
    Ok(())
}

fn validate_label(kind: &str, label: &str) -> Result<()> {
    validate_nonblank_text(&format!("{kind} label"), label)
}

fn validate_nonblank_text(field: &str, value: &str) -> Result<()> {
    ensure!(!value.trim().is_empty(), "{field} cannot be blank");
    ensure!(
        !contains_control(value),
        "{field} contains a control character"
    );
    Ok(())
}

fn contains_control(value: &str) -> bool {
    value.chars().any(char::is_control)
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_strong_sha256_etag(value: &str) -> bool {
    value.len() == 66
        && value.starts_with('"')
        && value.ends_with('"')
        && is_lower_sha256(&value[1..65])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn credential(id: Uuid) -> Credential {
        Credential {
            id,
            label: "Login".to_owned(),
            username: "user".to_owned(),
            auth: Auth::Agent,
        }
    }

    #[test]
    fn rejects_dangling_references() {
        let mut vault = Vault::new();
        vault.hosts.push(Host {
            id: Uuid::new_v4(),
            label: "Server".to_owned(),
            hostname: "example.test".to_owned(),
            port: 22,
            category_id: None,
            transport: HostTransport::Direct,
            auth: HostAuth::Credential {
                credential_id: Uuid::new_v4(),
            },
        });

        assert!(vault.validate().is_err());
    }

    #[test]
    fn rejects_category_cycles() {
        let mut vault = Vault::new();
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        vault.categories = vec![
            Category {
                id: first,
                label: "First".to_owned(),
                parent_id: Some(second),
            },
            Category {
                id: second,
                label: "Second".to_owned(),
                parent_id: Some(first),
            },
        ];

        assert!(vault.validate().is_err());
    }

    #[test]
    fn snapshot_serialization_is_canonical() {
        let mut left = Vault::new();
        let credential_a = Uuid::new_v4();
        let credential_b = Uuid::new_v4();
        left.credentials = vec![credential(credential_b), credential(credential_a)];
        left.known_hosts = vec![
            KnownHost {
                hostname: "B.EXAMPLE.test.".to_owned(),
                port: 22,
                public_key_openssh: "ssh-ed25519 BBBB".to_owned(),
            },
            KnownHost {
                hostname: "a.example.test".to_owned(),
                port: 2222,
                public_key_openssh: "ssh-ed25519 AAAA".to_owned(),
            },
        ];

        let mut right = left.clone();
        right.credentials.reverse();
        right.known_hosts.reverse();
        right.known_hosts[0].hostname = "A.EXAMPLE.TEST.".to_owned();
        right.known_hosts[1].hostname = "b.example.test".to_owned();

        assert_eq!(
            left.content_sha256().unwrap(),
            right.content_sha256().unwrap()
        );

        left.normalize();
        right.normalize();
        let left_json = serde_json::to_vec(&VaultDocument::Vault { vault: left }).unwrap();
        let right_json = serde_json::to_vec(&VaultDocument::Vault { vault: right }).unwrap();
        assert_eq!(left_json, right_json);
    }

    #[test]
    fn legacy_documents_keep_wire_bytes_schema_and_content_hash() {
        let fixtures = [
            (
                r#"{"kind":"vault","vault":{"schema_version":1,"id":"00000000-0000-0000-0000-000000000001","snapshot_id":"00000000-0000-0000-0000-000000000002","categories":[],"credentials":[{"id":"00000000-0000-0000-0000-000000000004","label":"Login","username":"alice","auth":{"kind":"agent"}}],"hosts":[{"id":"00000000-0000-0000-0000-000000000003","label":"Server","hostname":"example.test","port":22,"category_id":null,"credential_id":"00000000-0000-0000-0000-000000000004"}],"snippets":[],"known_hosts":[]}}"#,
                "b11a7bdb86e75c604bb337906eedaa86e8efbb6b909c811af6588a161e4d61f0",
            ),
            (
                r#"{"kind":"vault","vault":{"schema_version":2,"id":"00000000-0000-0000-0000-000000000001","snapshot_id":"00000000-0000-0000-0000-000000000002","categories":[],"credentials":[],"hosts":[{"id":"00000000-0000-0000-0000-000000000003","label":"Server","hostname":"example.test","port":22,"category_id":null,"username":"alice","password":"  exact secret\n"}],"snippets":[],"known_hosts":[]}}"#,
                "41db7b9e7469467a495a092415caca4cf5f555f6ca1dfbb96789163d4f69aea9",
            ),
        ];
        for (wire, expected_hash) in fixtures {
            let VaultDocument::Vault { mut vault } = serde_json::from_str(wire).unwrap();
            assert_eq!(vault.hosts[0].transport, HostTransport::Direct);
            vault.normalize();
            vault.validate().unwrap();
            assert_eq!(vault.content_sha256().unwrap(), expected_hash);
            assert_eq!(
                serde_json::to_string(&VaultDocument::Vault { vault }).unwrap(),
                wire
            );
        }
    }

    fn tailscale_host_wire() -> serde_json::Value {
        serde_json::json!({
            "id": Uuid::from_u128(3),
            "label": "Tailnet server",
            "hostname": "server.example.ts.net",
            "port": 22,
            "category_id": null,
            "transport": "tailscale",
            "username": "alice",
            "tailscale": { "tailnet_id": "tailnet-stable", "node_id": "node-stable" }
        })
    }

    #[test]
    fn tailscale_auth_rejects_partial_mixed_null_and_unknown_fields() {
        let wire = tailscale_host_wire();
        let host: Host = serde_json::from_value(wire.clone()).unwrap();
        assert_eq!(host.auth.credential_id(), None);
        assert_eq!(serde_json::to_value(&host).unwrap(), wire);

        for field in ["transport", "username", "tailscale"] {
            let mut missing = wire.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert!(serde_json::from_value::<Host>(missing).is_err());
            let mut null = wire.clone();
            null[field] = serde_json::Value::Null;
            assert!(serde_json::from_value::<Host>(null).is_err());
        }
        for (field, value) in [
            ("credential_id", serde_json::json!(Uuid::from_u128(4))),
            ("password", serde_json::json!("secret")),
            ("unexpected", serde_json::json!(true)),
            ("transport", serde_json::json!("direct")),
            ("transport", serde_json::json!("other")),
            ("port", serde_json::json!(2222)),
        ] {
            let mut invalid = wire.clone();
            invalid[field] = value;
            assert!(serde_json::from_value::<Host>(invalid).is_err());
        }
        for identity in [
            serde_json::json!({}),
            serde_json::json!({"tailnet_id": "tailnet-stable"}),
            serde_json::json!({"node_id": "node-stable"}),
            serde_json::json!({"tailnet_id": null, "node_id": "node-stable"}),
            serde_json::json!({"tailnet_id": "tailnet-stable", "node_id": null}),
            serde_json::json!({"tailnet_id": "tailnet-stable", "node_id": "node-stable", "extra": true}),
        ] {
            let mut invalid = wire.clone();
            invalid["tailscale"] = identity;
            assert!(serde_json::from_value::<Host>(invalid).is_err());
        }
    }

    #[test]
    fn tailscale_identity_and_username_enforce_utf8_byte_bounds_and_text_policy() {
        for (pointer, limit) in [
            ("/username", 256),
            ("/tailscale/tailnet_id", 128),
            ("/tailscale/node_id", 128),
        ] {
            let mut wire = tailscale_host_wire();
            *wire.pointer_mut(pointer).unwrap() = serde_json::json!("é".repeat(limit / 2));
            assert!(serde_json::from_value::<Host>(wire.clone()).is_ok());
            for value in [
                String::new(),
                " \t ".to_owned(),
                "a\nb".to_owned(),
                "a\u{7f}b".to_owned(),
                "a\u{85}b".to_owned(),
                "é".repeat(limit / 2 + 1),
            ] {
                *wire.pointer_mut(pointer).unwrap() = serde_json::json!(value);
                assert!(serde_json::from_value::<Host>(wire.clone()).is_err());
            }
        }
    }

    #[test]
    fn schema_normalization_is_minimal_monotonic_and_validates_native_hosts() {
        let keyless: Host = serde_json::from_value(tailscale_host_wire()).unwrap();
        for starting_schema in 1..=3 {
            let mut vault = Vault::new();
            vault.schema_version = starting_schema;
            vault.normalize();
            assert_eq!(vault.schema_version, starting_schema);
            vault.hosts.push(Host {
                transport: HostTransport::Direct,
                auth: HostAuth::Password {
                    username: "alice".to_owned(),
                    password: Secret::new(""),
                },
                ..keyless.clone()
            });
            vault.normalize();
            assert_eq!(vault.schema_version, starting_schema.max(2));
            vault.validate().unwrap();
            vault.hosts[0].transport = HostTransport::Tailscale;
            if starting_schema < 3 {
                assert!(vault.validate().is_err());
            }
            vault.normalize();
            assert_eq!(vault.schema_version, 3);
            vault.validate().unwrap();
            vault.hosts[0] = keyless.clone();
            vault.validate().unwrap();
            vault.hosts.clear();
            vault.normalize();
            assert_eq!(vault.schema_version, 3);
        }
        let mut vault = Vault::new();
        vault.hosts.push(keyless);
        vault.hosts[0].transport = HostTransport::Direct;
        assert!(vault.validate().is_err());
        vault.hosts[0].transport = HostTransport::Tailscale;
        vault.hosts[0].port = 2222;
        assert!(vault.validate().is_err());
        vault.hosts[0].port = 22;
        if let HostAuth::Tailscale { tailscale, .. } = &mut vault.hosts[0].auth {
            tailscale.node_id.clear();
        }
        assert!(vault.validate().is_err());
        for unsupported in [0, 4] {
            vault.hosts.clear();
            vault.schema_version = unsupported;
            vault.normalize();
            assert_eq!(vault.schema_version, unsupported);
            assert!(vault.validate().is_err());
        }
    }

    #[test]
    fn host_auth_wire_format_is_strict_and_legacy_serialization_is_stable() {
        let id = Uuid::new_v4();
        let credential_id = Uuid::new_v4();
        let host = Host {
            id,
            label: "Server".to_owned(),
            hostname: "example.test".to_owned(),
            port: 22,
            category_id: None,
            transport: HostTransport::Direct,
            auth: HostAuth::Credential { credential_id },
        };
        let serialized = serde_json::to_string(&host).unwrap();
        assert_eq!(
            serialized,
            format!(
                r#"{{"id":"{id}","label":"Server","hostname":"example.test","port":22,"category_id":null,"credential_id":"{credential_id}"}}"#
            )
        );
        let parsed: Host = serde_json::from_str(&serialized).unwrap();
        assert_eq!(parsed, host);
        assert_eq!(parsed.auth.credential_id(), Some(credential_id));

        let prefix = format!(
            r#"{{"id":"{id}","label":"Server","hostname":"example.test","port":22,"category_id":null"#
        );
        let invalid = [
            format!("{prefix}}}"),
            format!(r#"{prefix},"username":"user"}}"#),
            format!(r#"{prefix},"password":"secret"}}"#),
            format!(
                r#"{prefix},"credential_id":"{credential_id}","username":"user","password":"secret"}}"#
            ),
            format!(r#"{prefix},"credential_id":"{credential_id}","username":null}}"#),
            format!(
                r#"{prefix},"credential_id":"{credential_id}","unexpected":true}}"#
            ),
        ];
        for document in invalid {
            assert!(serde_json::from_str::<Host>(&document).is_err());
        }
    }

    #[test]
    fn direct_password_username_uses_text_validation_policy() {
        for username in ["", "   ", "user\nname"] {
            let mut vault = Vault::new();
            vault.hosts.push(Host {
                id: Uuid::new_v4(),
                label: "Server".to_owned(),
                hostname: "example.test".to_owned(),
                port: 22,
                category_id: None,
                transport: HostTransport::Direct,
                auth: HostAuth::Password {
                    username: username.to_owned(),
                    password: Secret::new(""),
                },
            });

            assert!(vault.validate().is_err());
        }
    }

    #[test]
    fn secret_debug_is_redacted_and_serde_is_plain_string() {
        let secret = Secret::new("highly-sensitive");
        assert!(!format!("{secret:?}").contains(secret.expose()));
        assert_eq!(
            serde_json::to_string(&secret).unwrap(),
            "\"highly-sensitive\""
        );
    }
}
