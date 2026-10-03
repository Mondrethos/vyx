use super::*;
use crate::{extensions::{contract::{Binding, ConnectionMode, ErrorCode, Proposal, ProposalSnapshot, ProtocolError}, manager::Manager}, tailscale::{Adapter, NodeReferences, ResolvedNode, Snapshot}, vault::{Host, HostAuth, HostTransport, TailscaleIdentity}};
use tokio::sync::oneshot;
use serde_json::Value;
use crate::ui::actions::ExtensionReview;

pub(super) struct Draft {
    pub proposal: Option<ProposalSnapshot>,
    pub resolved: Option<ResolvedNode>,
    pub save: bool,
    pub vault_snapshot: Uuid,
    pub saved_host_id: Option<Uuid>,
    /// The ended tab a temporary reconnect replaces; revalidated at final acceptance.
    pub replaces: Option<Uuid>,
}
pub(super) enum Outcome {
    Broker { binding: Binding, reply: oneshot::Sender<Result<Value, ProtocolError>>, status: Result<Snapshot> },
    Preview { proposal: ProposalSnapshot, status: Result<Snapshot> },
    Reconnect { host: Host, replaces: Uuid, status: Result<Snapshot> },
    SavedPreview { proposal: ProposalSnapshot, host_id: Uuid, vault_snapshot: Uuid, status: Result<Snapshot> },
    Final { draft: Draft, host: Host, existing: Option<Uuid>, status: Result<Option<Snapshot>> },
}
pub(super) struct NativeEvent { generation: u64, id: u64, outcome: Outcome }
pub(super) struct State {
    pub sender: mpsc::Sender<NativeEvent>,
    pub receiver: mpsc::Receiver<NativeEvent>,
    generation: u64,
    next_id: u64,
    jobs: HashMap<u64, watch::Sender<bool>>,
    pub references: Option<(Binding, NodeReferences)>,
    pub draft: Option<Draft>,
    pub waiting: bool,
}
impl State {
    pub fn new() -> Self {
        let (sender, receiver) = mpsc::channel(16);
        Self { sender, receiver, generation: 0, next_id: 0, jobs: HashMap::new(), references: None, draft: None, waiting: false }
    }
    pub fn cancel_requests(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        for (_, cancel) in self.jobs.drain() { cancel.send_replace(true); }
        self.draft = None;
        self.waiting = false;
    }
    pub fn close(&mut self) { self.cancel_requests(); self.references = None; }
    fn job(&mut self) -> Result<(u64, u64, watch::Receiver<bool>, mpsc::Sender<NativeEvent>)> {
        ensure!(self.jobs.len() < 16, "Native Tailscale work queue is full");
        self.next_id = self.next_id.checked_add(1).context("Native request IDs exhausted")?;
        let (cancel, receiver) = watch::channel(false);
        self.jobs.insert(self.next_id, cancel);
        Ok((self.generation, self.next_id, receiver, self.sender.clone()))
    }
}
impl Drop for State { fn drop(&mut self) { self.close(); } }
async fn status(path: Option<std::path::PathBuf>, cancel: &mut watch::Receiver<bool>) -> Result<Snapshot> {
    Ok(Adapter::discover(path.as_deref())?.status(cancel).await?)
}
impl App {
    pub(super) fn request_tailnet_status(&mut self, binding: Binding, reply: oneshot::Sender<Result<Value, ProtocolError>>) {
        let Ok((generation, id, mut cancel, sender)) = self.tailnet.job() else {
            let _ = reply.send(Err(ProtocolError { code: ErrorCode::LimitExceeded, message: "Native work queue full".into() }));
            return;
        };
        let path = self.settings.tailscale_cli_path.clone();
        tokio::spawn(async move {
            let status = status(path, &mut cancel).await;
            let _ = sender.send(NativeEvent { generation, id, outcome: Outcome::Broker { binding, reply, status } }).await;
        });
    }
    pub(super) fn request_tailnet_preview(&mut self, proposal: ProposalSnapshot) -> Result<()> {
        let (generation, id, mut cancel, sender) = self.tailnet.job()?;
        let path = self.settings.tailscale_cli_path.clone();
        tokio::spawn(async move {
            let status = status(path, &mut cancel).await;
            let _ = sender.send(NativeEvent { generation, id, outcome: Outcome::Preview { proposal, status } }).await;
        });
        if let Some(surface) = &mut self.extension_surface { surface.set_busy(true); }
        Ok(())
    }
    pub(super) async fn handle_tailnet_event(&mut self, event: NativeEvent) {
        self.tailnet.jobs.remove(&event.id);
        if event.generation != self.tailnet.generation || !self.attached { return; }
        match event.outcome {
            Outcome::Broker { binding, reply, status } => {
                let result = (|| -> Result<Value> {
                    let manager = self.extensions.as_ref().context("Extension closed")?;
                    manager.authorize(&binding, crate::extensions::contract::Method::TailscaleStatus).map_err(|error| anyhow!("{}",error.message))?;
                    let (normalized, references) = status?.references()?;
                    self.tailnet.references = Some((binding, references));
                    Ok(serde_json::to_value(normalized)?)
                })().map_err(|error| ProtocolError { code: ErrorCode::Unavailable, message: crate::extensions::contract::sanitize_display(&format!("{error:#}")) });
                let _ = reply.send(result);
            }
            Outcome::Preview { proposal, status } => {
                let result = self.tailnet_preview(proposal, status);
                if let Some(surface) = &mut self.extension_surface { surface.set_busy(false); }
                if let Err(error) = result { self.set_dialog(message("Tailscale destination unavailable", error)); }
            }
            Outcome::Reconnect { mut host, replaces, status } => {
                self.tailnet.waiting = false;
                self.dialog = None;
                let result = (|| {
                    let resolved = resolve_host(&host, &status?)?;
                    if matches!(host.auth, HostAuth::Tailscale { .. }) {
                        host.hostname = resolved.dns_name.clone().unwrap_or_else(|| resolved.address.to_string());
                    }
                    self.open_temporary_draft(host, Some(resolved), replaces)
                })();
                if let Err(error) = result { self.set_dialog(message("Temporary reconnect unavailable", error)); }
            }
            Outcome::SavedPreview { proposal, host_id, vault_snapshot, status } => {
                let result = self.review_saved_tailnet(proposal, host_id, vault_snapshot, status);
                if let Some(surface) = &mut self.extension_surface { surface.set_busy(false); }
                if let Err(error) = result { self.set_dialog(message("Saved destination unavailable", error)); }
            }
            Outcome::Final { draft, host, existing, status } => {
                self.tailnet.waiting = false;
                if matches!(self.dialog, Some(Dialog::Message { .. })) { self.dialog = None; }
                let result = self.complete_tailnet_acceptance(draft, host, existing, status).await;
                if let Err(error) = result { self.set_dialog(message("Tailscale action failed", error)); }
            }
        }
        self.mark_dirty();
    }
    fn tailnet_preview(&mut self, proposal: ProposalSnapshot, status: Result<Snapshot>) -> Result<()> {
        ensure!(self.dialog.is_none() && self.menu.is_none(), "Another host dialog is active; repeat the device action afterward");
        let manager = self.extensions.as_ref().context("Extension closed")?;
        let permissions = manager.permissions(proposal.binding())?;
        permissions.authorize_proposal(proposal.proposal().context("Proposal consumed")?).map_err(|error| anyhow!("{}",error.message))?;
        let (node_ref, mode, save) = match proposal.proposal().context("Proposal consumed")? {
            Proposal::ConnectTailnet { node_ref, mode } => (node_ref, *mode, false),
            Proposal::SaveTailnet { node_ref, mode } => (node_ref, *mode, true),
            _ => anyhow::bail!("Not a Tailscale proposal"),
        };
        let (binding, references) = self.tailnet.references.as_ref().context("Refresh the device browser; references expired")?;
        ensure!(binding == proposal.binding(), "STALE_TARGET: device references belong to a previous surface");
        let resolved = references.resolve(node_ref, &status?)?;
        if mode == ConnectionMode::TailscaleSsh { resolved.require_ssh_keys()?; }
        let address = resolved.dns_name.clone().unwrap_or_else(|| resolved.address.to_string());
        let label = resolved.name.clone().unwrap_or_else(|| address.clone());
        let auth = if mode == ConnectionMode::TailscaleSsh {
            HostAuth::Tailscale { username: String::new(), tailscale: TailscaleIdentity { tailnet_id: resolved.tailnet_id.clone(), node_id: resolved.node_id.clone() } }
        } else if let Some(credential) = self.state.vault.credentials.first() {
            HostAuth::Credential { credential_id: credential.id }
        } else { HostAuth::Password { username: String::new(), password: crate::vault::Secret::new("") } };
        let host = Host { id: Uuid::new_v4(), label, hostname: address, port: 22, transport: HostTransport::Tailscale, auth, category_id: None };
        let mut editor = Editor::host_draft(&self.state.vault, &host)?;
        editor.form.title = if save { "Import selected Tailscale server" } else { "Connect once to Tailscale device" }.into();
        editor.form.submit = "Review destination".into();
        editor.form.description = format!("Extension: {}. {} {} No connection or vault write occurs before final approval.", proposal.binding().extension_id,
            if mode == ConnectionMode::TailscaleSsh { "Keyless Tailscale SSH: username only; port 22; Tailscale-distributed keys." } else { "Standard SSH targets the ordinary SSH service. On port 22, enabled Tailscale SSH may intercept it. No mode fallback." },
            if resolved.online { "Online is not proof of SSH policy authorization." } else { "Device is offline; authorization is unknown." });
        self.tailnet.draft = Some(Draft { proposal: Some(proposal), resolved: Some(resolved), save, vault_snapshot: self.state.vault.snapshot_id, saved_host_id: None, replaces: None });
        self.set_dialog(Dialog::ConnectionDraft(editor));
        Ok(())
    }
    pub(super) fn reconfirm_temporary(&mut self, index: usize) -> Result<()> {
        let session = self.sessions.get(index).context("Session no longer exists")?;
        let replaces = session.id;
        let mut host = session.destination.draft();
        host.label = session.label.clone();
        if host.transport == HostTransport::Tailscale {
            let (generation, id, mut cancel, sender) = self.tailnet.job()?;
            let path = self.settings.tailscale_cli_path.clone();
            self.tailnet.waiting = true;
            self.set_dialog(message("Refreshing temporary destination", "Resolving the destination before opening its reconnect draft. Esc or Enter cancels."));
            tokio::spawn(async move {
                let status = status(path, &mut cancel).await;
                let _ = sender.send(NativeEvent { generation, id, outcome: Outcome::Reconnect { host, replaces, status } }).await;
            });
            return Ok(());
        }
        self.open_temporary_draft(host, None, replaces)
    }
    fn open_temporary_draft(&mut self, host: Host, resolved: Option<ResolvedNode>, replaces: Uuid) -> Result<()> {
        let mut editor = Editor::host_draft(&self.state.vault, &host)?;
        editor.form.title = "Reconnect temporary session".into();
        editor.form.submit = "Review destination".into();
        editor.form.description = "Temporary sessions require fresh confirmation and credentials. Tailscale identity is refreshed before connecting; passwords are not retained for reconnect.".into();
        self.tailnet.draft = Some(Draft { proposal: None, resolved, save: false, vault_snapshot: self.state.vault.snapshot_id, saved_host_id: None, replaces: Some(replaces) });
        self.set_dialog(Dialog::ConnectionDraft(editor));
        Ok(())
    }
    pub(super) async fn submit_connection_draft(&mut self, mut editor: Editor) {
        let result = editor.mutation(&self.state.vault).await;
        let result = result.and_then(|mutation| {
            let Mutation::PutHost { host, .. } = mutation else { anyhow::bail!("Connection draft is not a server"); };
            let draft = self.tailnet.draft.as_ref().context("Connection draft expired")?;
            ensure!(draft.vault_snapshot == self.state.vault.snapshot_id, "Vault changed; review a fresh server draft");
            if let Some(resolved) = &draft.resolved && draft.proposal.is_some() {
                // The selected identity cannot silently become an editable alias.
                let original = resolved.dns_name.as_deref().map(str::to_owned).unwrap_or_else(|| resolved.address.to_string());
                ensure!(crate::vault::canonical_hostname(&original)? == host.hostname, "Selected device address changed; choose the destination again");
                ensure!(host.transport == HostTransport::Tailscale, "Selected-device proposals require Tailscale routing; change routing later in the saved-server editor");
                let original_mode = draft.proposal.as_ref().and_then(ProposalSnapshot::proposal).map(|proposal| match proposal { Proposal::ConnectTailnet { mode, .. } | Proposal::SaveTailnet { mode, .. } => *mode, _ => ConnectionMode::StandardSsh });
                ensure!(original_mode != Some(ConnectionMode::TailscaleSsh) || matches!(host.auth, HostAuth::Tailscale { .. }), "Authentication mode changed; explicitly choose Connect with standard SSH in the device browser");
            }
            let existing = draft.save.then(|| self.state.vault.hosts.iter().find(|saved| same_destination(saved, &host)).map(|saved| saved.id)).flatten();
            let auth = match &host.auth {
                HostAuth::Credential { credential_id } => {
                    let credential = self.state.vault.credentials.iter().find(|credential| credential.id == *credential_id).context("Selected credential removed")?;
                    format!("{} (saved credential: {})", credential.username, credential.label)
                }
                HostAuth::Password { username, .. } => format!("{username} (server password; not shown)"),
                HostAuth::Tailscale { username, tailscale } => format!("{username} (keyless Tailscale SSH)\nTailnet: {}\nStable node: {}", tailscale.tailnet_id, tailscale.node_id),
            };
            let warning = if draft.save && self.state.vault.schema_version < 3 { "\nCOMPATIBILITY: Saving Tailscale routing upgrades this synchronized vault to schema 3. Older Vyx clients cannot read it. Upgrade all clients before saving. Cancellation does not upgrade the vault." } else { "" };
            let title = if existing.is_some() { "Matching server already saved" } else if draft.save { "Save selected server" } else { "Connect once" };
            let action = if existing.is_some() { "Open existing editor" } else if draft.save { "Save server" } else { "Connect" };
            let source = draft.proposal.as_ref().map(|proposal| format!("Extension: {}\nPackage: {}\n", proposal.binding().extension_id, proposal.binding().digest)).unwrap_or_default();
            let content = format!("{source}Label: {}\nDestination: {}:{}\nRouting: {:?}\nUsername / authentication: {}\n\n{}{}", host.label, host.hostname, host.port, host.transport, auth,
                if existing.is_some() { "Nothing will be overwritten. Open the matching saved-server editor and save changes explicitly." } else if draft.save { "Save only; this does not connect." } else { "Connect once; no server record is created." }, warning);
            let draft = self.tailnet.draft.take().context("Connection draft expired")?;
            self.extension_review = Some(super::extensions::PendingReview::Tailnet { draft, host, existing });
            self.set_dialog(Dialog::ExtensionReview(ExtensionReview::new(title, content, action)));
            Ok(())
        });
        if let Err(error) = result { editor.form.error = safe_text(&format!("{error:#}")); self.set_dialog(Dialog::ConnectionDraft(editor)); }
    }
    pub(super) fn start_tailnet_acceptance(&mut self, draft: Draft, host: Host, existing: Option<Uuid>) -> Result<()> {
        let (generation, id, mut cancel, sender) = self.tailnet.job()?;
        let path = self.settings.tailscale_cli_path.clone();
        self.tailnet.waiting = true;
        self.set_dialog(message("Checking reviewed destination", "Refreshing local Tailscale identity before final acceptance. Esc or Enter cancels before handoff."));
        tokio::spawn(async move {
            let status = if host.transport == HostTransport::Tailscale { status(path, &mut cancel).await.map(Some) } else { Ok(None) };
            let _ = sender.send(NativeEvent { generation, id, outcome: Outcome::Final { draft, host, existing, status } }).await;
        });
        Ok(())
    }
    async fn complete_tailnet_acceptance(&mut self, mut draft: Draft, host: Host, existing: Option<Uuid>, status: Result<Option<Snapshot>>) -> Result<()> {
        ensure!(self.attached && !self.store.is_uncertain(), "Workspace or vault is not writable");
        ensure!(self.state.vault.snapshot_id == draft.vault_snapshot, "STALE_TARGET: vault changed; review again");
        if let Some(old) = draft.replaces {
            ensure!(self.sessions.iter().any(|session| session.id == old && !session.is_live()),
                "STALE_TARGET: the session being reconnected closed or changed; nothing was opened");
        }
        let resolved = match status? {
            Some(status) => {
                let fresh = match &host.auth {
                    HostAuth::Tailscale { tailscale, .. } => status.resolve_identity(&tailscale.tailnet_id, &tailscale.node_id)?,
                    _ => status.resolve_address(&host.hostname)?,
                };
                if let Some(reviewed) = &draft.resolved { reviewed.ensure_fresh(&fresh)?; }
                if matches!(host.auth, HostAuth::Tailscale { .. }) { fresh.require_ssh_keys()?; }
                Some(fresh)
            }
            None => None,
        };
        let permissions = if let Some(proposal) = &draft.proposal {
            Some(self.extensions.as_ref().context("Extension closed")?.permissions(proposal.binding())?)
        } else { None };
        // Prepare the accepted host operation before revoking the extension. No
        // await separates freshness, one-shot consumption and authority handoff.
        let prepared = if !draft.save && existing.is_none() {
            if let Some(id) = draft.saved_host_id {
                ensure!(host.id == id, "Saved destination changed");
                let mut prepared = crate::ssh::PreparedConnection::saved(&host, &self.state.vault.credentials, self.settings.tailscale_cli_path.clone())?;
                if let Some(resolved) = resolved { prepared = prepared.with_reviewed(resolved); }
                Some(prepared)
            } else {
                Some(crate::ssh::PreparedConnection::temporary(&host, &self.state.vault.credentials, self.settings.tailscale_cli_path.clone(), resolved)?)
            }
        } else { None };
        if let Some(proposal) = &mut draft.proposal {
            let binding = self.extensions.as_ref().and_then(Manager::binding).context("Extension closed")?;
            proposal.consume(binding, permissions.as_ref().unwrap())?;
        }
        let snapshot = draft.vault_snapshot;
        self.close_extensions();
        if let Some(id) = existing {
            self.set_dialog(Dialog::Editor(Editor::host(&self.state.vault, Some(id), None)?));
        } else if let Some(prepared) = prepared {
            self.connect_prepared(prepared, draft.replaces)?;
        } else {
            let (id, label) = (host.id, host.label.clone());
            let state = self.store.commit(true, move |state| {
                ensure!(state.vault.snapshot_id == snapshot, "Vault changed after review; nothing was saved");
                Mutation::PutHost { host, create: true }.apply(state)
            }).await?;
            self.adopt_state(state);
            self.catalog.reveal(RowKey::Host(id));
            self.notify_success(format!("Saved {label}; no connection was opened"));
        }
        Ok(())
    }
    pub(super) fn request_saved_tailnet_preview(&mut self, proposal: ProposalSnapshot, host_id: Uuid) -> Result<()> {
        let (generation, id, mut cancel, sender) = self.tailnet.job()?;
        let vault_snapshot = self.state.vault.snapshot_id;
        let path = self.settings.tailscale_cli_path.clone();
        tokio::spawn(async move {
            let status = status(path, &mut cancel).await;
            let _ = sender.send(NativeEvent { generation, id, outcome: Outcome::SavedPreview { proposal, host_id, vault_snapshot, status } }).await;
        });
        if let Some(surface) = &mut self.extension_surface { surface.set_busy(true); }
        Ok(())
    }
    fn review_saved_tailnet(&mut self, proposal: ProposalSnapshot, host_id: Uuid, vault_snapshot: Uuid, status: Result<Snapshot>) -> Result<()> {
        ensure!(self.dialog.is_none() && self.menu.is_none(), "Another dialog is active; repeat the saved-server action");
        ensure!(self.state.vault.snapshot_id == vault_snapshot, "Saved destination changed; review again");
        let manager = self.extensions.as_ref().context("Extension closed")?;
        manager.permissions(proposal.binding())?.authorize_proposal(proposal.proposal().context("Proposal consumed")?).map_err(|error| anyhow!("{}", error.message))?;
        let host = self.state.vault.hosts.iter().find(|host| host.id == host_id).context("Saved destination removed")?;
        let resolved = resolve_host(host, &status?)?;
        let authentication = match &host.auth {
            HostAuth::Tailscale { username, tailscale } => format!("{username} (keyless Tailscale SSH)\nTailnet: {}\nStable node: {}", tailscale.tailnet_id, tailscale.node_id),
            HostAuth::Password { username, .. } => format!("{username} (server password)"),
            HostAuth::Credential { credential_id } => {
                let credential = self.state.vault.credentials.iter().find(|credential| credential.id == *credential_id).context("Saved credential removed")?;
                format!("{} (saved credential: {})", credential.username, credential.label)
            }
        };
        let content = format!("Extension: {}\nPackage: {}\nSaved server: {}\nReviewed address: {}:{}\nFresh dial IP: {}\nRouting: Tailscale\nAuthentication: {}\n\nOnline: {} (not a policy authorization verdict).\nConnect only after reviewing. No vault write or session switch occurs before acceptance.", proposal.binding().extension_id, proposal.binding().digest, host.label, host.hostname, host.port, resolved.address, authentication, resolved.online);
        let host = host.clone();
        let draft = Draft { proposal: Some(proposal), resolved: Some(resolved), save: false, vault_snapshot, saved_host_id: Some(host_id), replaces: None };
        self.extension_review = Some(super::extensions::PendingReview::Tailnet { draft, host, existing: None });
        self.set_dialog(Dialog::ExtensionReview(ExtensionReview::new("Connect saved Tailscale server", content, "Connect")));
        Ok(())
    }
}
fn resolve_host(host: &Host, status: &Snapshot) -> Result<ResolvedNode> {
    let resolved = match &host.auth {
        HostAuth::Tailscale { tailscale, .. } => status.resolve_identity(&tailscale.tailnet_id, &tailscale.node_id)?,
        _ => status.resolve_address(&host.hostname)?,
    };
    if matches!(host.auth, HostAuth::Tailscale { .. }) { resolved.require_ssh_keys()?; }
    Ok(resolved)
}
fn same_destination(saved: &Host, candidate: &Host) -> bool {
    if let (HostAuth::Tailscale { username: left, tailscale: left_id }, HostAuth::Tailscale { username: right, tailscale: right_id }) = (&saved.auth, &candidate.auth) {
        return left == right && left_id == right_id;
    }
    saved.transport == candidate.transport && saved.hostname.eq_ignore_ascii_case(&candidate.hostname) && saved.port == candidate.port && match (&saved.auth, &candidate.auth) {
        (HostAuth::Credential { credential_id: left }, HostAuth::Credential { credential_id: right }) => left == right,
        (HostAuth::Password { username: left, .. }, HostAuth::Password { username: right, .. }) => left == right,
        _ => false,
    }
}
