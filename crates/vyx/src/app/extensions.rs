use super::*;
use crate::{extensions::{contract::{self, ErrorCode, HostMetadata, Method, OpenReason, Proposal, ProposalSnapshot, ProtocolError, SessionMetadata, View}, manager::{Development, Manager, ManagerEvent}, registry::{PersistenceOutcome, Snapshot}}, ui::{actions::ExtensionReview, extensions::{ExtensionEntry, ExtensionSurface, ManagementAction, SurfaceAction}}};
use std::path::PathBuf;
use serde_json::Value;

pub(super) enum PendingReview {
    Package { snapshot: Snapshot, previous: Option<String>, development: Option<PathBuf> },
    Runtime { release: crate::extensions::distribution::RuntimeRelease, enable: Option<super::extension_downloads::Enable> },
    Proposal { snapshot: ProposalSnapshot, vault_snapshot: Uuid, session_label: Option<String> },
    Tailnet { draft: super::tailscale::Draft, host: crate::vault::Host, existing: Option<Uuid> },
    SchemaUpgrade { mutation: Mutation, vault_snapshot: Uuid },
}

pub(super) async fn next_event(manager: &mut Option<Manager>) -> Option<ManagerEvent> {
    let Some(manager) = manager else { return pending().await; };
    loop {
        tokio::select! {
            event = manager.events.recv() => return event,
            _ = tokio::time::sleep_until(manager.next_scan), if manager.watching() => manager.scan(),
        }
    }
}
fn protocol_error(code: ErrorCode, message: impl Into<String>) -> ProtocolError { ProtocolError { code, message: message.into() } }
pub(super) fn persisted(outcome: PersistenceOutcome) -> Result<()> {
    match outcome {
        PersistenceOutcome::Durable => Ok(()),
        PersistenceOutcome::BeforePublishFailure(message) => anyhow::bail!("Not saved: {message}. Revoked extensions remain disabled here; unsaved revocation may not survive restart. Retry in Settings / Extensions."),
        PersistenceOutcome::PublishedUncertain(message) => anyhow::bail!("Publication durability uncertain: {message}. Activation is blocked; Retry reconciles the actual registry. This is not a rollback; unsaved revocation may not survive restart."),
    }
}
impl App {
    pub(super) fn extension_entries(&self) -> Vec<ExtensionEntry> {
        let Some(manager) = &self.extensions else { return Vec::new(); };
        manager.registry.entries().iter().map(|entry| {
            let development = manager.development.get(&entry.id);
            ExtensionEntry {
                manifest: entry.manifest.clone(), digest: entry.digest.clone(), enabled: entry.enabled,
                grants: entry.approved_permissions.clone(),
                official: entry.source.as_ref().is_some_and(|source| source.is_official()),
                repository: entry.source.as_ref().map(|source| source.repository.clone()),
                // An unattached remembered source still prefills its next review.
                development: development.is_some(),
                development_path: development.map(|dev| dev.path.clone()).or_else(|| entry.development_path.clone()),
                status: if manager.registry.is_blocked() { "Registry needs Retry; activation blocked".into() }
                    else if development.is_some_and(|dev| dev.replacement.is_some()) { "Development rebuild available; review and Reload".into() }
                    else if let Err(error) = ai::check_native_entry(manager, entry) { error.to_string() }
                    else { String::new() },
                diagnostics: manager.diagnostics.get(&entry.id).map(|text| vec![text.clone()]).unwrap_or_default(),
                trust_rebuilds: development.is_some_and(|dev| dev.trusted_permissions.is_some()),
                reload_available: development.is_some_and(|dev| dev.replacement.is_some()),
                native: ai::native_entry(manager, entry).is_some(),
            }
        }).collect()
    }
    pub(super) fn refresh_extension_entries(&mut self) {
        self.revalidate_ai();
        let entries = self.extension_entries();
        if let Some(menu) = &mut self.menu { menu.set_extensions(entries); }
    }
    pub(super) fn close_extensions(&mut self) {
        self.cancel_ai_review(None);
        self.extension_downloads.cancel();
        let waiting = self.tailnet.waiting;
        self.tailnet.close();
        if let Some(manager) = &mut self.extensions { manager.close(); }
        self.extension_surface = None;
        self.extension_review = None;
        if matches!(self.dialog, Some(Dialog::ExtensionReview(_) | Dialog::ExtensionDownload(_) | Dialog::ConnectionDraft(_))) || waiting { self.dialog = None; }
        if matches!(self.quit_dialog, Some(Dialog::ExtensionReview(_) | Dialog::ExtensionDownload(_) | Dialog::ConnectionDraft(_))) { self.quit_dialog = None; }
    }
    pub(super) fn open_extension_picker(&mut self) {
        self.close_extensions();
        if self.extensions.is_none() {
            self.set_dialog(message("Extensions unavailable", self.extension_error.as_deref().unwrap_or("The extension registry is unavailable")));
            return;
        }
        self.menu = None;
        self.search = None;
        self.mouse_capture = None;
        self.extension_surface = Some(ExtensionSurface::picker(self.extension_entries().into_iter().filter(|entry| entry.enabled).collect()));
        self.mark_dirty();
    }
    pub(super) async fn handle_extension_surface(&mut self, action: SurfaceAction) {
        let result = match action {
            SurfaceAction::None => Ok(()),
            SurfaceAction::Close => { self.close_extensions(); Ok(()) },
            SurfaceAction::Reload => self.reload_extension(),
            SurfaceAction::Launch { extension_id, command_id } => {
                let entry = self.extension_entries().into_iter().find(|entry| entry.manifest.id == extension_id);
                match entry {
                    Some(entry) if matches!(entry.manifest.id.as_str(), ai::OFFICIAL_ID | ai::DEVELOPMENT_ID) => self.launch_ai(&extension_id, &entry.digest, &command_id),
                    Some(entry) => {
                        if self.extensions.as_ref().is_some_and(|manager| manager.runtime.is_none()) {
                            if let Err(error) = self.request_extension_runtime(Some(super::extension_downloads::Enable { id: entry.manifest.id, digest: entry.digest, grants: entry.grants })) {
                                self.extension_failure(error);
                            }
                            return;
                        }
                        let result = self.extensions.as_mut().context("Extensions unavailable").and_then(|manager| manager.launch(&extension_id, &command_id, OpenReason::Launch));
                        if result.is_ok() {
                            match ExtensionSurface::open(entry, View::Detail { title: "Loading".into(), fields: Vec::new(), actions: Vec::new() }) {
                                Ok(mut surface) => { surface.set_busy(true); self.extension_surface = Some(surface); }
                                Err(error) => return self.extension_failure(error),
                            }
                        }
                        result
                    }
                    None => Err(anyhow!("The extension is no longer installed")),
                }
            }
            SurfaceAction::Event(event) => {
                let result = self.extensions.as_mut().context("Extensions unavailable").and_then(|manager| manager.dispatch(event));
                if result.is_ok() { if let Some(surface) = &mut self.extension_surface { surface.set_busy(true); } }
                result
            }
        };
        if let Err(error) = result { self.extension_failure(error); }
        self.mark_dirty();
    }
    fn extension_failure(&mut self, error: impl std::fmt::Display) {
        self.tailnet.close();
        if let Some(manager) = &mut self.extensions { manager.invalidate(); }
        let message = contract::sanitize_display(&error.to_string());
        if let Some(surface) = &mut self.extension_surface { surface.set_busy(false); surface.set_error(message); }
        else { self.set_dialog(super::message("Extension error", message)); }
        self.mark_dirty();
    }
    pub(super) async fn handle_extension_event(&mut self, event: ManagerEvent) {
        match event {
            ManagerEvent::Development { binding, snapshot } => {
                let changed = self.extensions.as_mut().context("Extensions unavailable").and_then(|manager| manager.development_snapshot(&binding, snapshot));
                match changed {
                    Ok(true) => {
                        self.extension_review = None;
                        if matches!(self.dialog, Some(Dialog::ExtensionReview(_))) { self.dialog = None; }
                        self.tailnet.close();
                        if matches!(self.dialog, Some(Dialog::ConnectionDraft(_))) { self.dialog = None; }
                        self.extension_failure("Development package changed. Old authority revoked; explicitly Reload the immutable rebuild.");
                    }
                    Ok(false) => {}
                    Err(error) => self.notify_warning(format!("Development rebuild unavailable: {error:#}")),
                }
            }
            ManagerEvent::Started { binding, cancellation } => {
                if let Some(manager) = &mut self.extensions { manager.started(&binding, cancellation); } else { cancellation.cancel(); }
            }
            ManagerEvent::Request { binding, request, reply } => {
                let method = request.method;
                let authorized = self.extensions.as_ref()
                    .ok_or_else(|| protocol_error(ErrorCode::Cancelled, "Extension closed"))
                    .and_then(|manager| manager.authorize(&binding, method).map(|()| method));
                match authorized {
                    Ok(Method::TailscaleStatus) => self.request_tailnet_status(binding, reply),
                    Ok(method) => { let _ = reply.send(self.extension_broker(method)); }
                    Err(error) => { let _ = reply.send(Err(error)); }
                }
            }
            ManagerEvent::Finished { binding, event, provenance, event_id, result, diagnostics } => {
                let Some(manager) = &mut self.extensions else { return; };
                if !manager.current(&binding) { return; }
                if let Err(error) = manager.finish(&binding, &result, diagnostics) { self.extension_failure(error); return; }
                match result {
                    Ok(result) => {
                        if let Some(surface) = &mut self.extension_surface {
                            surface.set_busy(false);
                            if let Err(error) = surface.set_view(result.view) { self.extension_failure(error); return; }
                        }
                        if let Some(proposal) = result.proposal {
                            let review = (|| {
                                let manager = self.extensions.as_ref().context("Extension closed")?;
                                let permissions = manager.permissions(&binding)?;
                                ProposalSnapshot::new(binding, event_id, provenance, &event, proposal, &permissions)
                            })();
                            match review.and_then(|review| self.preview_extension_proposal(review)) {
                                Ok(()) => {}
                                Err(error) => self.extension_failure(error),
                            }
                        }
                    }
                    Err(error) => self.extension_failure(error),
                }
            }
        }
        self.refresh_extension_entries();
        self.mark_dirty();
    }
    fn extension_broker(&self, method: Method) -> Result<Value, ProtocolError> {
        let result: Result<Value> = match method {
            Method::HostsList => {
                let hosts: Result<Vec<_>> = self.state.vault.hosts.iter().map(|host| {
                    let mut metadata = HostMetadata { id: host.id, label: host.label.clone(), address: host.hostname.clone(), port: host.port, category: host.category_id.map(|id| crate::ui::actions::category_path(&self.state.vault, id)), authentication_mode: match &host.auth { crate::vault::HostAuth::Credential { .. } => "Saved credential", crate::vault::HostAuth::Password { .. } => "Server password", crate::vault::HostAuth::Tailscale { .. } => "Tailscale SSH" }.into() };
                    metadata.validate_and_sanitize()?;
                    Ok(metadata)
                }).collect();
                hosts.and_then(|hosts| Ok(serde_json::to_value(hosts)?))
            }
            Method::SessionsList => {
                let sessions: Result<Vec<_>> = self.sessions.iter().map(|session| {
                    let mut metadata = SessionMetadata { id: session.id, label: session.label.clone(), host_id: session.host_id, phase: match &session.view.lock().phase { SessionPhase::Connecting => contract::SessionPhase::Connecting, SessionPhase::Authenticating => contract::SessionPhase::Authenticating, SessionPhase::Connected => contract::SessionPhase::Connected, SessionPhase::Closed { .. } => contract::SessionPhase::Disconnected, SessionPhase::Error(_) => contract::SessionPhase::Failed } };
                    metadata.validate_and_sanitize()?;
                    Ok(metadata)
                }).collect();
                sessions.and_then(|sessions| Ok(serde_json::to_value(sessions)?))
            }
            Method::TailscaleStatus => unreachable!("Native status is dispatched asynchronously before metadata projection"),
        };
        result.map_err(|error| protocol_error(ErrorCode::Unavailable, contract::sanitize_display(&format!("{error:#}"))))
    }
    fn preview_extension_proposal(&mut self, snapshot: ProposalSnapshot) -> Result<()> {
        ensure!(self.attached && self.dialog.is_none() && self.menu.is_none() && self.extension_review.is_none(), "Another host dialog is active; repeat the extension action after closing it");
        let manager = self.extensions.as_ref().context("Extension closed")?;
        let binding = manager.binding().context("Extension closed")?;
        let provenance = format!("Extension: {}\nPackage SHA-256: {}\n", binding.extension_id, binding.digest);
        let (review, session_label) = match snapshot.proposal().context("Proposal already consumed")? {
            Proposal::InsertCommand { session_id, command } => {
                let session = self.sessions.iter().find(|session| session.id == *session_id && session_connected(session)).context("STALE_TARGET: target session is no longer connected")?;
                let endpoint = format!("{}:{}", session.destination.address, session.destination.port);
                (ExtensionReview::new("Insert without Enter", format!("{provenance}Session: {}\nSession UUID: {}\nEndpoint: {endpoint}\n\nInserts the exact command above without Enter. Verify the shell/prompt: a remote application can interpret ordinary text immediately.", contract::sanitize_display(&session.label), session.id), "Insert without Enter").with_payload(command.as_str()), Some(session.label.clone()))
            }
            Proposal::ConnectSaved { host_id } => {
                ensure!(!self.store.is_uncertain(), "Vault durability is uncertain; retry the save before connecting");
                let host = self.state.vault.hosts.iter().find(|host| host.id == *host_id).context("STALE_TARGET: saved destination removed")?;
                if host.transport == crate::vault::HostTransport::Tailscale {
                    let id = *host_id;
                    return self.request_saved_tailnet_preview(snapshot, id);
                }
                let (username, authentication) = match &host.auth {
                    crate::vault::HostAuth::Credential { credential_id } => {
                        let credential = self.state.vault.credentials.iter().find(|credential| credential.id == *credential_id).context("Saved credential removed")?;
                        (credential.username.as_str(), credential.label.as_str())
                    }
                    crate::vault::HostAuth::Password { username, .. } => (username.as_str(), "Server password"),
                    crate::vault::HostAuth::Tailscale { username, .. } => (username.as_str(), "Keyless Tailscale SSH; distributed host keys"),
                };
                (ExtensionReview::new("Connect to saved server", format!("{provenance}Saved server: {}\nDestination: {}:{}\nUsername: {}\nAuthentication: {}\n\nConnect only after reviewing this destination. Cancellation does not connect or switch sessions.", contract::sanitize_display(&host.label), contract::sanitize_display(&host.hostname), host.port, contract::sanitize_display(username), contract::sanitize_display(authentication)), "Connect"), None)
            }
            Proposal::ConnectTailnet { .. } | Proposal::SaveTailnet { .. } => return self.request_tailnet_preview(snapshot),
        };
        self.extension_review = Some(PendingReview::Proposal { snapshot, vault_snapshot: self.state.vault.snapshot_id, session_label });
        self.set_dialog(Dialog::ExtensionReview(review));
        Ok(())
    }
    pub(super) async fn accept_extension_review(&mut self, _review: ExtensionReview) {
        let Some(review) = self.extension_review.take() else { self.extension_failure("Review expired; repeat the action"); return; };
        let result = match review {
            PendingReview::Package { snapshot, previous, development } => self.publish_extension_candidate(snapshot, previous, development),
            PendingReview::Runtime { release, enable } => self.install_extension_runtime(release, enable),
            PendingReview::Tailnet { draft, host, existing } => self.start_tailnet_acceptance(draft, host, existing),
            PendingReview::SchemaUpgrade { mutation, vault_snapshot } => self.approve_schema_upgrade(mutation, vault_snapshot).await,
            PendingReview::Proposal { mut snapshot, vault_snapshot, session_label } => (|| {
                ensure!(self.attached && !self.store.is_uncertain(), "Vault or workspace is not available for approval");
                ensure!(self.state.vault.snapshot_id == vault_snapshot, "STALE_TARGET: vault changed; review again");
                let manager = self.extensions.as_ref().context("Extension closed")?;
                let binding = manager.binding().context("Extension closed")?.clone();
                let permissions = manager.permissions(&binding)?;
                // Prepare exact bytes/target while authority is still current, then
                // consume and hand off synchronously without an intervening await.
                match snapshot.proposal().context("Proposal already consumed")? {
                    Proposal::InsertCommand { session_id, command } => {
                        let session = self.sessions.iter().find(|session| session.id == *session_id && session_connected(session)).context("STALE_TARGET: target session closed")?;
                        ensure!(session_label.as_deref() == Some(session.label.as_str()), "STALE_TARGET: session label changed; review again");
                        let id = session.id;
                        let bytes = session.view.lock().terminal.paste(command);
                        snapshot.consume(&binding, &permissions)?;
                        self.queue_input(id, bytes)?;
                        self.notify_success("Extension command inserted without Enter into the reviewed session");
                    }
                    Proposal::ConnectSaved { host_id } => {
                        let host = self.state.vault.hosts.iter().find(|host| host.id == *host_id).context("Saved destination removed")?;
                        let prepared = crate::ssh::PreparedConnection::saved(host, &self.state.vault.credentials, self.settings.tailscale_cli_path.clone())?;
                        snapshot.consume(&binding, &permissions)?;
                        self.connect_prepared(prepared, None)?;
                    }
                    _ => anyhow::bail!("STALE_TARGET: unsupported reviewed operation"),
                }
                self.close_extensions();
                Ok(())
            })(),
        };
        if let Err(error) = result { self.set_dialog(message("Extension action failed", error)); }
        else { self.restore_focused_mode(); }
        self.refresh_extension_entries();
        self.mark_dirty();
    }
    pub(super) fn requires_schema_upgrade(&self, mutation: &Mutation) -> bool {
        self.state.vault.schema_version < 3 && matches!(mutation, Mutation::PutHost { host, .. } if host.transport == crate::vault::HostTransport::Tailscale || matches!(host.auth, crate::vault::HostAuth::Tailscale { .. }))
    }
    pub(super) fn review_schema_upgrade(&mut self, mutation: Mutation) {
        self.extension_review = Some(PendingReview::SchemaUpgrade { mutation, vault_snapshot: self.state.vault.snapshot_id });
        self.set_dialog(Dialog::ExtensionReview(ExtensionReview::new("Vault compatibility upgrade", "Saving this Tailscale server upgrades the synchronized vault to schema 3. Older Vyx clients cannot read it. Upgrade all clients before saving. Cancellation leaves the vault unchanged.".into(), "Upgrade and save")));
    }
    async fn approve_schema_upgrade(&mut self, mutation: Mutation, vault_snapshot: Uuid) -> Result<()> {
        ensure!(self.attached && !self.store.is_uncertain(), "Vault is not writable");
        let saved = match &mutation {
            Mutation::PutHost { host, .. } => Some((host.id, host.label.clone())),
            _ => None,
        };
        let state = self.store.commit(true, move |state| {
            ensure!(state.vault.snapshot_id == vault_snapshot, "Vault changed after compatibility review; nothing was saved");
            mutation.apply(state)
        }).await?;
        self.adopt_state(state);
        match saved {
            Some((id, label)) => {
                self.catalog.reveal(RowKey::Host(id));
                self.notify_success(format!("Saved {label}; synchronized vault now requires schema-3-compatible clients"));
                self.ai_host_saved(id);
            }
            None => self.notify_success("Saved; synchronized vault now requires schema-3-compatible clients"),
        }
        Ok(())
    }
    fn publish_extension_candidate(&mut self, snapshot: Snapshot, previous: Option<String>, development: Option<PathBuf>) -> Result<()> {
        let manager = self.extensions.as_mut().context("Extensions unavailable")?;
        let reload = development.as_ref().and_then(|_| manager.binding())
            .filter(|binding| binding.extension_id == snapshot.manifest.id)
            .and_then(|_| manager.command()).map(str::to_owned);
        manager.close();
        let id = snapshot.manifest.id.clone();
        let digest = snapshot.digest.clone();
        let permissions = snapshot.manifest.permissions.clone();
        // Identical packages need no new bytes. Only an explicit development review
        // remembers its source, published together with the reviewed digest; no
        // path changes existing grants.
        let unchanged = previous.as_deref() == Some(digest.as_str())
            && manager.registry.entries().iter().any(|entry| entry.id == id
                && entry.digest == digest && entry.source == snapshot.source);
        let rebind = development.is_some() && unchanged;
        let path = development.as_deref();
        if unchanged {
            manager.registry.load(&digest)?;
            if let Some(path) = path { persisted(manager.registry.set_development_path(&id, &digest, path)?)?; }
        } else {
            let outcome = match previous {
                Some(previous) => manager.registry.update(&id, &previous, snapshot, permissions, true, path)?,
                None => manager.registry.install_snapshot(snapshot, path)?,
            };
            persisted(outcome)?;
        }
        match development {
            Some(path) => { manager.development.insert(id.clone(), Development { path, digest, trusted_permissions: None, replacement: None, candidate: None }); }
            // An ordinary replacement ends any development attachment.
            None if !unchanged => { manager.development.remove(&id); }
            None => {}
        }
        if let Some(command) = reload {
            manager.launch(&id, &command, OpenReason::Reload)?;
            let entry = self.extension_entries().into_iter().find(|entry| entry.manifest.id == id).context("Updated package removed")?;
            let mut surface = ExtensionSurface::open(entry, View::Detail { title: "Reloading".into(), fields: Vec::new(), actions: Vec::new() })?;
            surface.set_busy(true);
            self.extension_surface = Some(surface);
            self.menu = None;
        } else {
            self.extension_surface = None;
            self.notify_info(if rebind { "Development package reattached. Its reviewed path and digest are remembered across restarts; enablement and grants are unchanged." }
                else if unchanged { "Package already installed. No update applied; enablement and grants are unchanged. For development activation, choose Load development package on the package page." }
                else { "Package saved locally. New installations stay disabled until permission approval." });
            self.open_extension_settings(Some(id.as_str()));
        }
        Ok(())
    }
    pub(super) async fn handle_extension_management(&mut self, action: ManagementAction) {
        let result = self.extension_management(action);
        if let Err(error) = result {
            if let Some(menu) = &mut self.menu { menu.set_error(safe_text(&format!("{error:#}"))); }
            else { self.set_dialog(message("Extension management failed", error)); }
        }
        self.refresh_extension_entries();
        self.mark_dirty();
    }
    fn extension_management(&mut self, action: ManagementAction) -> Result<()> {
        match action {
            ManagementAction::BrowseRepository { repository } => self.browse_extension_repository(repository),
            ManagementAction::Download { entry } => self.download_extension_package(entry),
            ManagementAction::DownloadRuntime => self.request_extension_runtime(None),
            ManagementAction::Install { path } => self.review_extension_package(path, None, false),
            ManagementAction::LoadDevelopment { path } => self.review_extension_package(path, None, true),
            ManagementAction::Update { extension_id, digest, path } => {
                let manager = self.extensions.as_ref().context("Extensions unavailable")?;
                ensure!(manager.registry.entries().iter().any(|entry| entry.id == extension_id && entry.digest == digest), "Package changed; reopen update review");
                self.review_extension_package(path, Some((extension_id, digest)), false)
            }
            ManagementAction::Enable { extension_id, digest, grants } => {
                let manager = self.extensions.as_ref().context("Extensions unavailable")?;
                let entry = manager.registry.entries().iter()
                    .find(|entry| entry.id == extension_id && entry.digest == digest)
                    .context("Package changed; review permissions again")?;
                let native = ai::check_native_entry(manager, entry)?;
                if !native && self.extensions.as_ref().is_some_and(|manager| manager.runtime.is_none()) {
                    return self.request_extension_runtime(Some(super::extension_downloads::Enable { id: extension_id, digest, grants }));
                }
                let manager = self.extensions.as_mut().context("Extensions unavailable")?;
                manager.close(); persisted(manager.registry.enable(&extension_id, &digest, grants)?)
            }
            ManagementAction::Disable { extension_id } => {
                self.close_extensions();
                let manager = self.extensions.as_mut().context("Extensions unavailable")?;
                // Rebuild trust is session-only consent; even a failed disable ends it.
                if let Some(development) = manager.development.get_mut(&extension_id) {
                    development.trusted_permissions = None;
                    development.replacement = None;
                    development.candidate = None;
                }
                persisted(manager.registry.revoke(&extension_id)?)
            }
            ManagementAction::Remove { extension_id } => {
                self.close_extensions();
                let manager = self.extensions.as_mut().context("Extensions unavailable")?;
                persisted(manager.registry.remove(&extension_id)?)?;
                manager.development.remove(&extension_id);
                Ok(())
            }
            ManagementAction::Retry { .. } => {
                let manager = self.extensions.as_mut().context("Extensions unavailable")?;
                persisted(manager.registry.retry()?)?;
                manager.attach_remembered();
                Ok(())
            }
            ManagementAction::TrustRebuilds { extension_id, digest, trusted } => {
                let manager = self.extensions.as_mut().context("Extensions unavailable")?;
                let entry = manager.registry.entries().iter().find(|entry| entry.id == extension_id && entry.digest == digest).context("Package changed; review permissions again")?;
                let ceiling = entry.approved_permissions.clone();
                let development = manager.development.get_mut(&extension_id).context("Not a development package")?;
                development.trusted_permissions = trusted.then_some(ceiling);
                Ok(())
            }
            ManagementAction::Reload { extension_id } => {
                ensure!(self.extensions.as_ref().and_then(Manager::binding).is_some_and(|binding| binding.extension_id == extension_id), "Open this extension before Reload");
                self.reload_extension()
            }
        }
    }
    fn reload_extension(&mut self) -> Result<()> {
        self.tailnet.close();
        let manager = self.extensions.as_mut().context("Extensions unavailable")?;
        let id = manager.binding().context("Open an extension before Reload")?.extension_id.clone();
        let command = manager.command().context("No active extension command")?.to_owned();
        let replacement = manager.development.get_mut(&id).and_then(|development| development.replacement.take());
        if let Some(snapshot) = replacement {
            let development = manager.development.get(&id).context("Development path removed")?;
            let path = development.path.clone();
            let ceiling = development.trusted_permissions.clone();
            let previous = development.digest.clone();
            let trusted = snapshot.manifest.id == id && ceiling.as_ref().is_some_and(|ceiling| snapshot.manifest.permissions.iter().all(|permission| ceiling.contains(permission)));
            if trusted {
                let digest = snapshot.digest.clone();
                let grants = snapshot.manifest.permissions.clone();
                manager.close();
                // Session trust never becomes remembered approval for changed bytes.
                persisted(manager.registry.update(&id, &previous, snapshot, grants, true, None)?)?;
                let development = manager.development.get_mut(&id).unwrap();
                development.digest = digest;
                development.candidate = None;
                manager.launch(&id, &command, OpenReason::Reload)?;
                let entry = self.extension_entries().into_iter().find(|entry| entry.manifest.id == id).context("Updated extension removed")?;
                let mut surface = ExtensionSurface::open(entry, View::Detail { title: "Reloading".into(), fields: Vec::new(), actions: Vec::new() })?;
                surface.set_busy(true);
                self.extension_surface = Some(surface);
                self.menu = None;
                return Ok(());
            }
            // ID changes are separate installs; permission growth always gets
            // explicit review. Never reuse the old development ceiling.
            manager.development.get_mut(&id).unwrap().trusted_permissions = None;
            return self.review_extension_package(path, None, true);
        }
        manager.reload()?;
        self.menu = None;
        if let Some(surface) = &mut self.extension_surface { surface.set_busy(true); }
        Ok(())
    }
    fn review_extension_package(&mut self, path: PathBuf, previous: Option<(String, String)>, development: bool) -> Result<()> {
        // Review (and remember) the absolute source path, independent of the working directory.
        let path = std::path::absolute(&path).context("Resolve package path")?;
        let manager = self.extensions.as_ref().context("Extensions unavailable")?;
        let snapshot = manager.registry.read_source(&path)?;
        self.review_extension_snapshot(snapshot, previous, development.then_some(path))
    }
    pub(super) fn review_extension_snapshot(&mut self, snapshot: Snapshot, previous: Option<(String, String)>, development: Option<PathBuf>) -> Result<()> {
        let manager = self.extensions.as_ref().context("Extensions unavailable")?;
        if let Some((id, _)) = &previous { ensure!(*id == snapshot.manifest.id, "Update extension ID differs; install it as a separate extension"); }
        let old = manager.registry.entries().iter().find(|entry| entry.id == snapshot.manifest.id);
        let previous = previous.map(|(_, digest)| digest).or_else(|| old.map(|entry| entry.digest.clone()));
        let requested = &snapshot.manifest.permissions;
        let old_permissions = old.map(|entry| entry.manifest.permissions.as_slice()).unwrap_or_default();
        let describe = crate::ui::extensions::permission;
        let added = requested.iter().filter(|permission| !old_permissions.contains(permission)).map(|permission| describe(*permission)).collect::<Vec<_>>().join("\n");
        let removed = old_permissions.iter().filter(|permission| !requested.contains(permission)).map(|permission| describe(*permission)).collect::<Vec<_>>().join("\n");
        let requested = requested.iter().map(|permission| describe(*permission)).collect::<Vec<_>>().join("\n");
        let source = if development.is_some() { "Unverified / Development".into() }
            else if let Some(source) = &snapshot.source {
                format!("{} · {} · {}", if source.is_official() { "Vyx release" } else { "Unverified GitHub publisher" }, source.repository, source.tag)
            } else { "Unverified local package".into() };
        let same = old.is_some_and(|entry| entry.digest == snapshot.digest && entry.source == snapshot.source);
        let content = format!("{}\nID: {}\nVersion: {}\nSHA-256: {}\nSource: {}\n\n{}\n\nRequested permissions:\n{}\n\nAdded:\n{}\n\nRemoved:\n{}\n\nInstallation copies immutable bytes without executing code. {}{}",
            snapshot.manifest.name, snapshot.manifest.id, snapshot.manifest.version, snapshot.digest,
            source, snapshot.manifest.description, requested, added, removed,
            if development.is_some() && same {
                "Approving remembers this development path for this exact digest, including after restart, without changing enablement or grants."
            } else if same {
                "This package is already installed. Approval leaves enablement and grants unchanged. To activate a local development build, cancel and choose Load development package on its package page."
            } else if previous.is_some() { "Approving this update grants all listed permissions to this exact new digest and enables the package." }
            else { "A new package remains disabled until you review and approve Enable." },
            if development.is_some() && !same {
                " Vyx remembers this reviewed path and digest across restarts; a changed or missing file needs review again."
            } else { "" });
        self.extension_review = Some(PendingReview::Package { snapshot, previous, development });
        self.menu = None;
        self.set_dialog(Dialog::ExtensionReview(ExtensionReview::new("Review extension package", content, "Approve package")));
        Ok(())
    }
}
