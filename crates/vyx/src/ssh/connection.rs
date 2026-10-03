use super::*;
use std::{io, path::PathBuf, task::{Context as TaskContext, Poll}};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use crate::{tailscale::{Adapter, NcOwner, NcStream, ResolvedNode}, vault::{HostTransport, TailscaleIdentity}};

/// Reconnection metadata deliberately contains no passwords or private keys.
#[derive(Clone, Debug)]
pub enum ReconnectAuth {
    Credential(Uuid),
    Password { username: String },
    Tailscale { username: String, identity: TailscaleIdentity },
}
#[derive(Clone, Debug)]
pub struct ConnectionTarget {
    pub label: String,
    pub address: String,
    pub port: u16,
    pub transport: HostTransport,
    pub auth: ReconnectAuth,
}
impl ConnectionTarget {
    pub fn draft(&self) -> Host {
        Host { id: Uuid::new_v4(), label: self.label.clone(), hostname: self.address.clone(), port: self.port, transport: self.transport, category_id: None,
            auth: match &self.auth {
                ReconnectAuth::Credential(id) => HostAuth::Credential { credential_id: *id },
                ReconnectAuth::Password { username } => HostAuth::Password { username: username.clone(), password: Secret::new("") },
                ReconnectAuth::Tailscale { username, identity } => HostAuth::Tailscale { username: username.clone(), tailscale: identity.clone() },
            }
        }
    }
}
/// Host-private, one-shot connection. Login material moves into the transport task.
pub struct PreparedConnection {
    pub(super) host_id: Option<Uuid>,
    pub(super) target: ConnectionTarget,
    pub(super) login: Login,
    pub(super) cli_path: Option<PathBuf>,
    pub(super) reviewed: Option<ResolvedNode>,
}
impl PreparedConnection {
    pub fn saved(host: &Host, credentials: &[Credential], cli_path: Option<PathBuf>) -> Result<Self> {
        let (login, auth) = match &host.auth {
            HostAuth::Credential { credential_id } => {
                let credential = credentials.iter().find(|credential| credential.id == *credential_id).context("Saved credential no longer exists")?;
                (Login { username: credential.username.clone(), auth: LoginMode::Standard(credential.auth.clone()) }, ReconnectAuth::Credential(*credential_id))
            }
            HostAuth::Password { username, password } => (Login { username: username.clone(), auth: LoginMode::Standard(Auth::Password { password: password.clone() }) }, ReconnectAuth::Password { username: username.clone() }),
            HostAuth::Tailscale { username, tailscale } => {
                ensure!(host.transport == HostTransport::Tailscale && host.port == 22, "Tailscale SSH requires Tailscale transport and port 22");
                (Login { username: username.clone(), auth: LoginMode::TailscaleNone }, ReconnectAuth::Tailscale { username: username.clone(), identity: tailscale.clone() })
            }
        };
        Ok(Self { host_id: Some(host.id), target: ConnectionTarget { label: host.label.clone(), address: canonical_hostname(&host.hostname)?, port: host.port, transport: host.transport, auth }, login, cli_path, reviewed: None })
    }
    pub fn temporary(host: &Host, credentials: &[Credential], cli_path: Option<PathBuf>, reviewed: Option<ResolvedNode>) -> Result<Self> {
        let mut prepared = Self::saved(host, credentials, cli_path)?;
        prepared.host_id = None;
        prepared.reviewed = reviewed;
        Ok(prepared)
    }
    pub fn with_reviewed(mut self, node: ResolvedNode) -> Self {
        self.reviewed = Some(node);
        self
    }
}

pub(super) enum Transport { Tcp(TcpStream), Nc(NcStream) }
impl AsyncRead for Transport {
    fn poll_read(self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() { Self::Tcp(stream) => Pin::new(stream).poll_read(cx, buf), Self::Nc(stream) => Pin::new(stream).poll_read(cx, buf) }
    }
}
impl AsyncWrite for Transport {
    fn poll_write(self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match self.get_mut() { Self::Tcp(stream) => Pin::new(stream).poll_write(cx, buf), Self::Nc(stream) => Pin::new(stream).poll_write(cx, buf) }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() { Self::Tcp(stream) => Pin::new(stream).poll_flush(cx), Self::Nc(stream) => Pin::new(stream).poll_flush(cx) }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() { Self::Tcp(stream) => Pin::new(stream).poll_shutdown(cx), Self::Nc(stream) => Pin::new(stream).poll_shutdown(cx) }
    }
}
pub(super) struct TransportOwner {
    tcp: Option<std::net::TcpStream>,
    nc: Option<NcOwner>,
    stop: Option<oneshot::Sender<()>>,
    watcher: Option<tokio::task::JoinHandle<()>>,
}
impl TransportOwner {
    pub async fn shutdown(&mut self) {
        if let Some(tcp) = self.tcp.take() { let _ = tcp.shutdown(Shutdown::Both); }
        if let Some(nc) = self.nc.take() { let _ = nc.close().await; }
        if let Some(stop) = self.stop.take() { let _ = stop.send(()); }
        if let Some(watcher) = self.watcher.take() { let _ = watcher.await; }
    }
}
impl Drop for TransportOwner {
    fn drop(&mut self) {
        if let Some(tcp) = &self.tcp { let _ = tcp.shutdown(Shutdown::Both); }
        if let Some(stop) = self.stop.take() { let _ = stop.send(()); }
    }
}
pub(super) async fn open(prepared: &PreparedConnection, budget: &mut NetworkBudget, cancel: &mut watch::Receiver<bool>) -> Result<(Transport, TransportOwner, Option<Vec<PublicKey>>)> {
    let target = &prepared.target;
    let adapter = if target.transport == HostTransport::Tailscale { Some(Adapter::discover(prepared.cli_path.as_deref())?) } else { None };
    let resolved = if let Some(adapter) = &adapter {
        let status = adapter.status(cancel).await?;
        let resolved = match &target.auth {
            ReconnectAuth::Tailscale { identity, .. } => status.resolve_identity(&identity.tailnet_id, &identity.node_id)?,
            _ => status.resolve_address(&target.address)?,
        };
        if let Some(reviewed) = &prepared.reviewed { reviewed.ensure_fresh(&resolved)?; }
        Some(resolved)
    } else { None };
    let keys = if matches!(prepared.login.auth, LoginMode::TailscaleNone) {
        let resolved = resolved.as_ref().context("Keyless SSH requires a resolved Tailscale destination")?;
        resolved.require_ssh_keys()?;
        Some(resolved.host_keys.clone())
    } else { None };
    if let Some(resolved) = &resolved {
        if resolved.userspace_networking {
            let (stream, owner) = adapter.as_ref().unwrap().nc(resolved.address, target.port, cancel.clone()).await?;
            return Ok((Transport::Nc(stream), TransportOwner { tcp: None, nc: Some(owner), stop: None, watcher: None }, keys));
        }
    }
    let connect = async {
        match &resolved {
            Some(node) => TcpStream::connect((node.address, target.port)).await,
            None => TcpStream::connect((target.address.as_str(), target.port)).await,
        }
    };
    let stream = network_call(budget, cancel, connect, "Could not connect to the SSH server").await.map_err(|error| match error {
        super::OperationError::Cancelled => anyhow!("SSH connection cancelled"),
        super::OperationError::TimedOut => anyhow!("SSH connection timed out"),
        super::OperationError::Failed(error) => anyhow!(error),
    })?;
    stream.set_nodelay(true)?;
    let standard = stream.into_std()?;
    let shutdown = standard.try_clone()?;
    let cancellation_socket = shutdown.try_clone()?;
    let stream = TcpStream::from_std(standard)?;
    let (stop, mut stopped) = oneshot::channel();
    let mut cancellation = cancel.clone();
    let watcher = tokio::spawn(async move {
        tokio::select! { _ = wait_cancelled(&mut cancellation) => { let _ = cancellation_socket.shutdown(Shutdown::Both); }, _ = &mut stopped => {} }
    });
    Ok((Transport::Tcp(stream), TransportOwner { tcp: Some(shutdown), nc: None, stop: Some(stop), watcher: Some(watcher) }, keys))
}
