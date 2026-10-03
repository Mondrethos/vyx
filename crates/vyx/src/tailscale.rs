//! Host-only Tailscale discovery and transport. No CLI input comes from extension code.
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::CString,
    fmt, io,
    net::IpAddr,
    os::unix::{ffi::OsStrExt, fs::PermissionsExt},
    path::{Path, PathBuf},
    pin::Pin,
    process::Stdio,
    task::{Context, Poll},
    time::Duration,
};

use russh::keys::PublicKey;
use serde::Deserialize;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, DuplexStream, ReadBuf},
    process::Command,
    sync::{oneshot, watch},
    task::JoinHandle,
};
use uuid::Uuid;

use crate::extensions::contract::{self, TailscalePeer, TailscaleState, TailscaleStatus};

const STATUS_LIMIT: usize = 4 * 1024 * 1024;
const STDERR_LIMIT: usize = 16 * 1024;
const STATUS_TIMEOUT: Duration = Duration::from_secs(5);

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    MissingExecutable,
    InvalidExecutable,
    Unreachable,
    Stopped,
    SignedOut,
    NeedsApproval,
    UnsupportedStatus,
    EmptyPeers,
    InvalidIdentity,
    InvalidAddress,
    InvalidKeys,
    StaleTarget,
    AmbiguousTarget,
    Timeout,
    OutputLimit,
    Cancelled,
    Transport,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::MissingExecutable => "Tailscale CLI not found. Install Tailscale or choose its absolute executable path in Settings / Tailscale transport.",
            Self::InvalidExecutable => "Tailscale CLI path must resolve to a regular executable at an absolute path.",
            Self::Unreachable => "Tailscale daemon is unavailable. Start Tailscale outside Vyx and refresh.",
            Self::Stopped => "Tailscale is stopped. Start it outside Vyx and refresh.",
            Self::SignedOut => "Tailscale is signed out. Sign in outside Vyx and refresh.",
            Self::NeedsApproval => "This Tailscale machine needs approval. Ask your tailnet administrator, then refresh.",
            Self::UnsupportedStatus => "Tailscale returned an unsupported status document. Check the installed Tailscale version.",
            Self::EmptyPeers => "No peer devices are visible in this tailnet. Check device sharing and policy outside Vyx.",
            Self::InvalidIdentity => "Tailscale status lacks an unambiguous stable tailnet, local account, or device identity.",
            Self::InvalidAddress => "The target must match an advertised Tailscale IP or full MagicDNS name; public addresses and short names are not allowed.",
            Self::InvalidKeys => "This device has no valid Tailscale-distributed SSH host keys. Keyless SSH cannot continue.",
            Self::StaleTarget => "The Tailscale account, device, or reviewed endpoint changed. Refresh and review the target again.",
            Self::AmbiguousTarget => "More than one Tailscale device matches this target. Refresh and choose an unambiguous device.",
            Self::Timeout => "Tailscale status timed out after five seconds. Check the local daemon and refresh.",
            Self::OutputLimit => "Tailscale output exceeded its safety limit.",
            Self::Cancelled => "Tailscale operation cancelled.",
            Self::Transport => "Tailscale userspace transport failed. Check the local daemon and target.",
        })
    }
}
impl std::error::Error for Error {}

#[derive(Clone, Debug)]
pub struct Adapter { path: PathBuf }

impl Adapter {
    pub fn discover(override_path: Option<&Path>) -> Result<Self> {
        if let Some(path) = override_path {
            return executable(path).map(|path| Self { path }).ok_or(Error::InvalidExecutable);
        }
        if let Some(path) = std::env::var_os("PATH") {
            for directory in std::env::split_paths(&path).filter(|path| path.is_absolute()) {
                if let Some(path) = executable(&directory.join("tailscale")) { return Ok(Self { path }); }
            }
        }
        #[cfg(target_os = "macos")]
        for path in ["/usr/local/bin/tailscale", "/Applications/Tailscale.app/Contents/MacOS/Tailscale"] {
            if let Some(path) = executable(Path::new(path)) { return Ok(Self { path }); }
        }
        Err(Error::MissingExecutable)
    }

    pub fn path(&self) -> &Path { &self.path }

    fn command(&self) -> Result<Command> {
        if executable(&self.path).as_ref() != Some(&self.path) { return Err(Error::InvalidExecutable); }
        let mut command = Command::new(&self.path);
        command.env_clear().current_dir("/").kill_on_drop(true)
            .env("LANG", "C").env("LC_ALL", "C").env("TAILSCALE_BE_CLI", "1")
            .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
        for name in ["HOME", "USER"] {
            if let Some(value) = std::env::var_os(name) { command.env(name, value); }
        }
        Ok(command)
    }

    /// Dropping this future cancels the supervisor too; it always kills and reaps its child.
    pub async fn status(&self, cancel: &mut watch::Receiver<bool>) -> Result<Snapshot> {
        if *cancel.borrow() { return Err(Error::Cancelled); }
        let mut child = self.command()?.args(["status", "--json"]).spawn().map_err(|_| Error::Unreachable)?;
        let stdout = child.stdout.take().ok_or(Error::Unreachable)?;
        let stderr = child.stderr.take().ok_or(Error::Unreachable)?;
        let (stop, mut stopped) = oneshot::channel();
        let _guard = StopOnDrop(Some(stop));
        let mut cancel = cancel.clone();
        let task = tokio::spawn(async move {
            let result = tokio::select! {
                _ = &mut stopped => Err(Error::Cancelled),
                _ = cancelled(&mut cancel) => Err(Error::Cancelled),
                _ = tokio::time::sleep(STATUS_TIMEOUT) => Err(Error::Timeout),
                result = async {
                    let (out, _, status) = tokio::try_join!(
                        read_bounded(stdout, STATUS_LIMIT),
                        drain_bounded(stderr, STDERR_LIMIT),
                        async { child.wait().await.map_err(|_| Error::Unreachable) },
                    )?;
                    if !status.success() { return Err(Error::Unreachable); }
                    Ok(out)
                } => result,
            };
            let _ = child.start_kill();
            let _ = child.wait().await;
            result
        });
        let bytes = task.await.map_err(|_| Error::Unreachable)??;
        Snapshot::parse(&bytes)
    }

    /// Only the Linux userspace route uses nc. The returned owner must live with the SSH session.
    pub async fn nc(&self, address: IpAddr, port: u16, mut cancel: watch::Receiver<bool>) -> Result<(NcStream, NcOwner)> {
        if !cfg!(target_os = "linux") { return Err(Error::Transport); }
        if !contract::is_tailscale_address(&address) || port == 0 { return Err(Error::InvalidAddress); }
        if *cancel.borrow() { return Err(Error::Cancelled); }
        let mut child = self.command()?.args(["nc", &address.to_string(), &port.to_string()])
            .stdin(Stdio::piped()).spawn().map_err(|_| Error::Transport)?;
        let input = child.stdin.take().ok_or(Error::Transport)?;
        let output = child.stdout.take().ok_or(Error::Transport)?;
        let stderr = child.stderr.take().ok_or(Error::Transport)?;
        let (stream, mut bridge) = tokio::io::duplex(16 * 1024);
        let (stop, mut stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut pipes = ChildPipes { input, output };
            let result = tokio::select! {
                _ = &mut stopped => Ok(()),
                _ = cancelled(&mut cancel) => Ok(()),
                result = tokio::io::copy_bidirectional(&mut bridge, &mut pipes) => result.map(|_| ()).map_err(|_| Error::Transport),
                result = async {
                    drain_bounded(stderr, STDERR_LIMIT).await?;
                    // Closing stderr is not a transport disconnect.
                    std::future::pending::<Result<()>>().await
                } => result,
            };
            drop(pipes);
            drop(bridge);
            let _ = child.start_kill();
            let _ = child.wait().await;
            result
        });
        Ok((NcStream(stream), NcOwner { stop: StopOnDrop(Some(stop)), task: Some(task) }))
    }
}

fn executable(path: &Path) -> Option<PathBuf> {
    if !path.is_absolute() { return None; }
    let path = path.canonicalize().ok()?;
    let metadata = path.metadata().ok()?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 { return None; }
    let native = CString::new(path.as_os_str().as_bytes()).ok()?;
    // SAFETY: `native` is a valid NUL-terminated path and remains alive for the call.
    (unsafe { libc::access(native.as_ptr(), libc::X_OK) } == 0).then_some(path)
}

async fn cancelled(cancel: &mut watch::Receiver<bool>) {
    loop {
        if *cancel.borrow_and_update() || cancel.changed().await.is_err() { return; }
    }
}
async fn read_bounded(mut reader: impl AsyncRead + Unpin, limit: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut buffer = [0; 8192];
    loop {
        let count = reader.read(&mut buffer).await.map_err(|_| Error::Unreachable)?;
        if count == 0 { return Ok(bytes); }
        if bytes.len() + count > limit { return Err(Error::OutputLimit); }
        bytes.extend_from_slice(&buffer[..count]);
    }
}
async fn drain_bounded(mut reader: impl AsyncRead + Unpin, limit: usize) -> Result<()> {
    let mut total = 0;
    let mut buffer = [0; 8192];
    loop {
        let count = reader.read(&mut buffer).await.map_err(|_| Error::Unreachable)?;
        if count == 0 { return Ok(()); }
        total += count;
        if total > limit { return Err(Error::OutputLimit); }
    }
}
struct StopOnDrop(Option<oneshot::Sender<()>>);
impl Drop for StopOnDrop {
    fn drop(&mut self) { if let Some(stop) = self.0.take() { let _ = stop.send(()); } }
}

pub struct NcOwner { stop: StopOnDrop, task: Option<JoinHandle<Result<()>>> }
impl NcOwner {
    pub async fn close(mut self) -> Result<()> {
        if let Some(stop) = self.stop.0.take() { let _ = stop.send(()); }
        if let Some(task) = self.task.take() { task.await.map_err(|_| Error::Transport)? } else { Ok(()) }
    }
}
pub struct NcStream(DuplexStream);
impl AsyncRead for NcStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buffer: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buffer)
    }
}
impl AsyncWrite for NcStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> { Pin::new(&mut self.0).poll_write(cx, bytes) }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> { Pin::new(&mut self.0).poll_flush(cx) }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> { Pin::new(&mut self.0).poll_shutdown(cx) }
}
struct ChildPipes { input: tokio::process::ChildStdin, output: tokio::process::ChildStdout }
impl AsyncRead for ChildPipes {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buffer: &mut ReadBuf<'_>) -> Poll<io::Result<()>> { Pin::new(&mut self.output).poll_read(cx, buffer) }
}
impl AsyncWrite for ChildPipes {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> { Pin::new(&mut self.input).poll_write(cx, bytes) }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> { Pin::new(&mut self.input).poll_flush(cx) }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> { Pin::new(&mut self.input).poll_shutdown(cx) }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalPrincipal { pub id: String, pub user_id: u64 }

#[derive(Clone, Debug)]
pub struct ResolvedNode {
    pub tailnet_id: String,
    pub node_id: String,
    pub principal: LocalPrincipal,
    pub address: IpAddr,
    pub dns_name: Option<String>,
    pub name: Option<String>,
    pub online: bool,
    pub userspace_networking: bool,
    pub host_keys: Vec<PublicKey>,
    keys_valid: bool,
}
impl ResolvedNode {
    pub fn require_ssh_keys(&self) -> Result<()> {
        if self.keys_valid && !self.host_keys.is_empty() { Ok(()) } else { Err(Error::InvalidKeys) }
    }
    /// Availability is a warning, not a security identity. Everything used to dial/trust is compared.
    pub fn ensure_fresh(&self, fresh: &Self) -> Result<()> {
        if self.tailnet_id != fresh.tailnet_id || self.node_id != fresh.node_id
            || self.principal != fresh.principal || self.address != fresh.address
            || self.dns_name != fresh.dns_name || self.userspace_networking != fresh.userspace_networking
            || self.keys_valid != fresh.keys_valid || self.host_keys.len() != fresh.host_keys.len()
            || !self.host_keys.iter().all(|key| fresh.host_keys.iter().any(|other| key.key_data() == other.key_data()))
            || !fresh.host_keys.iter().all(|key| self.host_keys.iter().any(|other| key.key_data() == other.key_data())) {
            return Err(Error::StaleTarget);
        }
        Ok(())
    }
}

pub struct Snapshot {
    tailnet_id: String,
    tailnet_name: Option<String>,
    principal: LocalPrincipal,
    tun: bool,
    peers: Vec<Peer>,
}
struct Peer {
    id: String,
    name: Option<String>,
    dns_name: Option<String>,
    addresses: Vec<IpAddr>,
    online: bool,
    last_seen: Option<String>,
    os: Option<String>,
    tags: Vec<String>,
    host_keys: Vec<PublicKey>,
    keys_valid: bool,
}

/// A new map is created for each discovery generation. Never serialize this host-only map.
#[derive(Default)]
pub struct NodeReferences { nodes: BTreeMap<String, ResolvedNode> }
impl NodeReferences {
    pub fn resolve(&self, node_ref: &str, fresh: &Snapshot) -> Result<ResolvedNode> {
        let previous = self.nodes.get(node_ref).ok_or(Error::StaleTarget)?;
        let resolved = fresh.resolve_identity(&previous.tailnet_id, &previous.node_id)?;
        previous.ensure_fresh(&resolved)?;
        Ok(resolved)
    }
}

impl Snapshot {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > STATUS_LIMIT { return Err(Error::OutputLimit); }
        let raw: RawStatus = serde_json::from_slice(bytes).map_err(|_| Error::UnsupportedStatus)?;
        match raw.backend_state {
            BackendState::Running => {},
            BackendState::Stopped | BackendState::Starting => return Err(Error::Stopped),
            BackendState::NeedsLogin => return Err(Error::SignedOut),
            BackendState::NoState => return Err(Error::Unreachable),
            BackendState::NeedsMachineAuth => return Err(Error::NeedsApproval),
            BackendState::Unknown => return Err(Error::UnsupportedStatus),
        }
        let tailnet = raw.current_tailnet.ok_or(Error::InvalidIdentity)?;
        let tailnet_id = stable_id(tailnet.stable_id)?;
        let own = raw.self_node.ok_or(Error::InvalidIdentity)?;
        let principal = LocalPrincipal { id: stable_id(own.id)?, user_id: own.user_id.ok_or(Error::InvalidIdentity)? };
        if principal.user_id == 0 { return Err(Error::InvalidIdentity); }
        let tun = raw.tun.ok_or(Error::UnsupportedStatus)?;
        let raw_peers = raw.peer.ok_or(Error::UnsupportedStatus)?.0;
        if raw_peers.is_empty() { return Err(Error::EmptyPeers); }
        let mut ids = BTreeSet::new();
        let mut peers = Vec::with_capacity(raw_peers.len());
        for raw in raw_peers.into_values() {
            let id = stable_id(raw.id)?;
            if !ids.insert(id.clone()) || id == principal.id { return Err(Error::InvalidIdentity); }
            let mut addresses = raw.tailscale_ips.ok_or(Error::InvalidAddress)?;
            if addresses.is_empty() || addresses.len() > 16 || !addresses.iter().all(contract::is_tailscale_address) {
                return Err(Error::InvalidAddress);
            }
            addresses.sort_by_key(|ip| (ip.is_ipv6(), *ip));
            addresses.dedup();
            let parsed_keys = raw.ssh_host_keys.unwrap_or_default().into_iter().map(|key| parse_host_key(&key)).collect::<Result<Vec<_>>>();
            let keys_valid = parsed_keys.is_ok();
            let host_keys = parsed_keys.unwrap_or_default();
            let dns_name = raw.dns_name.filter(|value| !value.is_empty()).map(|value| canonical_dns(&value)).transpose()?;
            peers.push(Peer { id, name: display(raw.host_name), dns_name, addresses,
                online: raw.online.ok_or(Error::UnsupportedStatus)?, last_seen: display(raw.last_seen), os: display(raw.os),
                tags: raw.tags.unwrap_or_default().into_iter().take(256).filter_map(|tag| display(Some(tag))).collect(),
                host_keys, keys_valid });
        }
        Ok(Self { tailnet_id, tailnet_name: display(tailnet.name), principal, tun, peers })
    }

    pub fn references(&self) -> Result<(TailscaleStatus, NodeReferences)> {
        let mut refs = NodeReferences::default();
        let mut peers = Vec::with_capacity(self.peers.len());
        for peer in &self.peers {
            let node_ref = Uuid::new_v4().to_string();
            refs.nodes.insert(node_ref.clone(), self.resolve_peer(peer, peer.addresses[0]));
            peers.push(TailscalePeer { node_ref, name: peer.name.clone(), dns_name: peer.dns_name.clone(), addresses: peer.addresses.clone(),
                online: peer.online, last_seen: peer.last_seen.clone(), os: peer.os.clone(), tags: peer.tags.clone(),
                ssh_host_keys_available: peer.keys_valid && !peer.host_keys.is_empty() });
        }
        let mut status = TailscaleStatus { state: TailscaleState::Running, tailnet_name: self.tailnet_name.clone(), peers };
        status.validate_and_sanitize().map_err(|_| Error::OutputLimit)?;
        Ok((status, refs))
    }

    pub fn resolve_identity(&self, tailnet_id: &str, node_id: &str) -> Result<ResolvedNode> {
        if tailnet_id != self.tailnet_id { return Err(Error::StaleTarget); }
        let peer = self.peers.iter().find(|peer| peer.id == node_id).ok_or(Error::StaleTarget)?;
        Ok(self.resolve_peer(peer, peer.addresses[0]))
    }

    pub fn resolve_address(&self, address: &str) -> Result<ResolvedNode> {
        let ip = address.parse::<IpAddr>().ok();
        if ip.is_some_and(|ip| !contract::is_tailscale_address(&ip)) { return Err(Error::InvalidAddress); }
        let dns = if ip.is_none() { Some(canonical_dns(address)?) } else { None };
        let mut matches = self.peers.iter().filter(|peer| match ip {
            Some(ip) => peer.addresses.contains(&ip),
            None => peer.dns_name.as_ref() == dns.as_ref(),
        });
        let peer = matches.next().ok_or(Error::StaleTarget)?;
        if matches.next().is_some() { return Err(Error::AmbiguousTarget); }
        Ok(self.resolve_peer(peer, ip.unwrap_or(peer.addresses[0])))
    }

    fn resolve_peer(&self, peer: &Peer, address: IpAddr) -> ResolvedNode {
        ResolvedNode { tailnet_id: self.tailnet_id.clone(), node_id: peer.id.clone(), principal: self.principal.clone(),
            address, dns_name: peer.dns_name.clone(), name: peer.name.clone(), online: peer.online,
            userspace_networking: cfg!(target_os = "linux") && !self.tun,
            host_keys: peer.host_keys.clone(), keys_valid: peer.keys_valid }
    }
}

pub fn parse_host_key(value: &str) -> Result<PublicKey> {
    if value.len() > 16 * 1024 || value.chars().any(|ch| ch.is_control()) { return Err(Error::InvalidKeys); }
    // Distributed host keys have no comments/options. Certificates are deliberately not accepted.
    let mut fields = value.split(' ');
    let algorithm = fields.next().ok_or(Error::InvalidKeys)?;
    let encoded = fields.next().ok_or(Error::InvalidKeys)?;
    if encoded.is_empty() || fields.next().is_some() || algorithm.contains("-cert-") { return Err(Error::InvalidKeys); }
    PublicKey::from_openssh(value).map_err(|_| Error::InvalidKeys)
}
fn stable_id(value: Option<String>) -> Result<String> {
    let value = value.ok_or(Error::InvalidIdentity)?;
    if value.is_empty() || value.len() > 128 || value.chars().any(|ch| ch.is_control() || ch.is_whitespace() || is_bidi(ch)) { return Err(Error::InvalidIdentity); }
    Ok(value)
}
fn canonical_dns(value: &str) -> Result<String> {
    let value = value.strip_suffix('.').unwrap_or(value);
    if value.len() > 253 || !value.contains('.') || value.split('.').any(|label| label.is_empty() || label.len() > 63
        || label.starts_with('-') || label.ends_with('-') || !label.bytes().all(|ch| ch.is_ascii_alphanumeric() || ch == b'-')) {
        return Err(Error::InvalidAddress);
    }
    Ok(value.to_ascii_lowercase())
}
fn is_bidi(ch: char) -> bool { matches!(ch, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}') }
fn display(value: Option<String>) -> Option<String> {
    value.map(|value| value.chars().filter(|ch| !ch.is_control() && !is_bidi(*ch)).take(256).collect::<String>()).filter(|value| !value.is_empty())
}

#[derive(Deserialize)]
enum BackendState {
    Running,
    Stopped,
    Starting,
    NeedsLogin,
    NeedsMachineAuth,
    NoState,
    #[serde(other)]
    Unknown,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RawStatus {
    backend_state: BackendState,
    #[serde(rename = "TUN")] tun: Option<bool>,
    current_tailnet: Option<RawTailnet>,
    #[serde(rename = "Self")] self_node: Option<RawSelf>,
    peer: Option<RawPeers>,
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RawTailnet { name: Option<String>, #[serde(rename = "StableID")] stable_id: Option<String> }
#[derive(Deserialize)]
struct RawSelf { #[serde(rename = "ID")] id: Option<String>, #[serde(rename = "UserID")] user_id: Option<u64> }
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RawPeer {
    #[serde(rename = "ID")] id: Option<String>,
    host_name: Option<String>,
    #[serde(rename = "DNSName")] dns_name: Option<String>,
    #[serde(rename = "TailscaleIPs")] tailscale_ips: Option<Vec<IpAddr>>,
    online: Option<bool>,
    last_seen: Option<String>,
    #[serde(rename = "OS")] os: Option<String>,
    tags: Option<Vec<String>>,
    #[serde(rename = "sshHostKeys")] ssh_host_keys: Option<Vec<String>>,
}

struct RawPeers(BTreeMap<String, RawPeer>);
impl<'de> Deserialize<'de> for RawPeers {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = RawPeers;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a bounded map of uniquely keyed peers")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> std::result::Result<Self::Value, A::Error> {
                let mut peers = BTreeMap::new();
                while let Some(key) = map.next_key::<String>()? {
                    if peers.len() >= 4096 || peers.contains_key(&key) {
                        return Err(serde::de::Error::custom("duplicate or excess peers"));
                    }
                    peers.insert(key, map.next_value()?);
                }
                Ok(RawPeers(peers))
            }
        }
        deserializer.deserialize_map(Visitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};
    #[cfg(target_os = "linux")]
    use tokio::io::AsyncWriteExt;

    fn fixture() -> Value {
        json!({
            "BackendState": "Running", "TUN": true,
            "CurrentTailnet": { "Name": "example.ts.net", "StableID": "tailnet-one" },
            "Self": { "ID": "local-one", "UserID": 123 },
            "Peer": { "nodekey:private": {
                "ID": "peer-one", "HostName": "server", "DNSName": "Server.Example.ts.net.",
                "TailscaleIPs": ["fd7a:115c:a1e0::7", "100.100.1.7"],
                "Online": true, "OS": "linux", "sshHostKeys": [],
                "UserID": 456, "LoginName": "private@example.com"
            }},
            "AuthURL": "https://private.example/auth"
        })
    }
    fn snapshot(value: &Value) -> Result<Snapshot> {
        Snapshot::parse(&serde_json::to_vec(value).unwrap())
    }
    fn script(body: &str) -> (tempfile::TempDir, Adapter) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("tailscale-fixture");
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let adapter = Adapter::discover(Some(&path)).unwrap();
        (directory, adapter)
    }

    #[test]
    fn references_are_generation_scoped_and_private_data_stays_private() {
        let snapshot = snapshot(&fixture()).unwrap();
        let (public, refs) = snapshot.references().unwrap();
        let encoded = serde_json::to_string(&public).unwrap();
        for private in ["tailnet-one", "peer-one", "local-one", "private@example", "AuthURL", "nodekey:"] {
            assert!(!encoded.contains(private));
        }
        let node = refs.resolve(&public.peers[0].node_ref, &snapshot).unwrap();
        assert_eq!(node.address, "100.100.1.7".parse::<IpAddr>().unwrap());
        let (_, next_refs) = snapshot.references().unwrap();
        assert!(matches!(next_refs.resolve(&public.peers[0].node_ref, &snapshot), Err(Error::StaleTarget)));
        assert_eq!(node.require_ssh_keys(), Err(Error::InvalidKeys));
    }

    #[test]
    fn identity_principal_and_endpoint_changes_invalidate_reviews() {
        let original = snapshot(&fixture()).unwrap();
        let (public, refs) = original.references().unwrap();
        for (pointer, replacement) in [
            ("/CurrentTailnet/StableID", json!("tailnet-two")),
            ("/Self/ID", json!("local-two")),
            ("/Self/UserID", json!(987)),
            ("/Peer/nodekey:private/ID", json!("peer-two")),
            ("/Peer/nodekey:private/TailscaleIPs", json!(["100.100.1.8"])),
            ("/Peer/nodekey:private/DNSName", json!("new.example.ts.net")),
        ] {
            let mut changed = fixture();
            *changed.pointer_mut(pointer).unwrap() = replacement;
            assert!(matches!(refs.resolve(&public.peers[0].node_ref, &snapshot(&changed).unwrap()), Err(Error::StaleTarget)));
        }
        let mut offline = fixture();
        offline["Peer"]["nodekey:private"]["Online"] = json!(false);
        assert!(!refs.resolve(&public.peers[0].node_ref, &snapshot(&offline).unwrap()).unwrap().online);
    }

    #[test]
    fn exact_addresses_and_full_dns_resolve_without_public_dns_or_short_names() {
        let parsed = snapshot(&fixture()).unwrap();
        let dns = parsed.resolve_address("SERVER.EXAMPLE.TS.NET.").unwrap();
        assert_eq!(dns.address, "100.100.1.7".parse::<IpAddr>().unwrap());
        assert_eq!(parsed.resolve_address("fd7a:115c:a1e0::7").unwrap().address, "fd7a:115c:a1e0::7".parse::<IpAddr>().unwrap());
        for address in ["server", "8.8.8.8", "100.128.0.1", "fd7a:115c:a1e1::7", "elsewhere.example.net", "-x.example.net"] {
            assert!(parsed.resolve_address(address).is_err());
        }
        let mut duplicate = fixture();
        let mut peer = duplicate["Peer"]["nodekey:private"].clone();
        peer["ID"] = json!("peer-two");
        duplicate["Peer"]["nodekey:other"] = peer;
        let duplicate = snapshot(&duplicate).unwrap();
        assert!(matches!(duplicate.resolve_address("100.100.1.7"), Err(Error::AmbiguousTarget)));
        assert!(matches!(duplicate.resolve_address("server.example.ts.net"), Err(Error::AmbiguousTarget)));
    }

    #[test]
    fn security_fields_fail_closed_and_backend_errors_are_distinct() {
        for (backend, expected) in [("Stopped", Error::Stopped), ("NeedsLogin", Error::SignedOut),
            ("NeedsMachineAuth", Error::NeedsApproval), ("Unrecognized", Error::UnsupportedStatus)] {
            assert!(matches!(snapshot(&json!({"BackendState":backend})), Err(error) if error == expected));
        }
        for (pointer, replacement) in [
            ("/CurrentTailnet/StableID", Value::Null), ("/Self/ID", json!(" ")), ("/Self/UserID", json!(0)),
            ("/Peer/nodekey:private/ID", json!("a".repeat(129))),
            ("/Peer/nodekey:private/TailscaleIPs", json!(["127.0.0.1"])),
            ("/Peer/nodekey:private/TailscaleIPs", Value::Null),
        ] {
            let mut broken = fixture();
            *broken.pointer_mut(pointer).unwrap() = replacement;
            assert!(snapshot(&broken).is_err());
        }
        let mut duplicate = fixture();
        duplicate["Peer"]["other"] = duplicate["Peer"]["nodekey:private"].clone();
        assert!(matches!(snapshot(&duplicate), Err(Error::InvalidIdentity)));
        let mut empty = fixture();
        empty["Peer"] = json!({});
        assert!(matches!(snapshot(&empty), Err(Error::EmptyPeers)));
        assert!(serde_json::from_str::<RawPeers>(r#"{"a":{},"a":{}}"#).is_err());
    }

    #[test]
    fn malformed_and_multiline_keys_cannot_be_used_for_keyless_auth() {
        let public = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILagOJFgwaMNhBWQINinKOXmqS4Gh5NgxgriXwdOoINJ";
        assert_eq!(parse_host_key(public).unwrap().to_openssh().unwrap(), public);
        for invalid in [format!("{public}\n"), format!("{public} comment"), public.replace("ssh-ed25519", "ssh-ed25519-cert-v01@openssh.com"), "ssh-ed25519 invalid".to_owned()] {
            assert!(parse_host_key(&invalid).is_err());
        }
        let mut raw = fixture();
        raw["Peer"]["nodekey:private"]["sshHostKeys"] = json!([public, "malformed"]);
        let node = snapshot(&raw).unwrap().resolve_identity("tailnet-one", "peer-one").unwrap();
        assert_eq!(node.require_ssh_keys(), Err(Error::InvalidKeys));
    }

    #[tokio::test]
    async fn fixed_status_invocation_and_output_limits() {
        let body = format!(
            "[ \"$#\" = 2 ] && [ \"$1\" = status ] && [ \"$2\" = --json ] || exit 9\n[ \"$LANG\" = C ] && [ \"$LC_ALL\" = C ] && [ \"$TAILSCALE_BE_CLI\" = 1 ] || exit 8\nprintf '%s' '{}'",
            fixture(),
        );
        let (_directory, adapter) = script(&body);
        let (_sender, mut cancel) = watch::channel(false);
        let snapshot = adapter.status(&mut cancel).await.unwrap();
        assert_eq!(snapshot.resolve_identity("tailnet-one", "peer-one").unwrap().address, "100.100.1.7".parse::<IpAddr>().unwrap());
        let (_directory, adapter) = script("while :; do printf 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' >&2; done");
        assert!(matches!(adapter.status(&mut cancel).await, Err(Error::OutputLimit)));
    }

    #[tokio::test]
    async fn status_cancellation_reaps_the_child() {
        let (directory, adapter) = script("while :; do :; done");
        let path = directory.path().join("pid");
        std::fs::write(adapter.path(), format!("#!/bin/sh\nprintf '%s' \"$$\" > '{}'\nwhile :; do :; done\n", path.display())).unwrap();
        let (sender, mut cancel) = watch::channel(false);
        let task = tokio::spawn(async move { adapter.status(&mut cancel).await });
        let pid: i32 = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Some(pid) = std::fs::read_to_string(&path).ok().and_then(|value| value.parse().ok()) {
                    break pid;
                }
                tokio::task::yield_now().await;
            }
        }).await.unwrap();
        sender.send(true).unwrap();
        assert!(matches!(task.await.unwrap(), Err(Error::Cancelled)));
        assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::ESRCH));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn userspace_transport_forwards_bytes_and_closes_without_stderr() {
        let (_directory, adapter) = script("[ \"$#\" = 3 ] && [ \"$1\" = nc ] && [ \"$2\" = 100.100.1.7 ] && [ \"$3\" = 22 ] || exit 9\nexec 2>&-\nexec /bin/cat");
        let (_sender, cancel) = watch::channel(false);
        let (mut stream, owner) = adapter.nc("100.100.1.7".parse().unwrap(), 22, cancel).await.unwrap();
        stream.write_all(b"ssh-fixture\0\r\n").await.unwrap();
        let mut bytes = [0; 14];
        tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut bytes)).await.unwrap().unwrap();
        assert_eq!(&bytes, b"ssh-fixture\0\r\n");
        owner.close().await.unwrap();
        assert_eq!(stream.read(&mut bytes).await.unwrap(), 0);
    }

    #[test]
    fn executable_override_rejects_relative_directory_and_nonexecutable_paths() {
        assert!(matches!(Adapter::discover(Some(Path::new("tailscale"))), Err(Error::InvalidExecutable)));
        let directory = tempfile::tempdir().unwrap();
        assert!(matches!(Adapter::discover(Some(directory.path())), Err(Error::InvalidExecutable)));
        let path = directory.path().join("not-executable");
        std::fs::write(&path, "not executable").unwrap();
        assert!(matches!(Adapter::discover(Some(&path)), Err(Error::InvalidExecutable)));
    }
}
