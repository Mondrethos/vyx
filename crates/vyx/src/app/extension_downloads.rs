//! Host-owned catalog/download jobs. Guest code cannot choose native runtime sources.
use super::*;
use std::{future::Future, path::{Path, PathBuf}};
use crate::{extensions::{contract::Permission, distribution::{self, CatalogEntry, RuntimeRelease}, registry::Snapshot, runtime::WorkerExecutable}, ui::actions::ExtensionReview};

#[derive(Clone)]
pub(super) struct Enable {
    pub id: String,
    pub digest: String,
    pub grants: Vec<Permission>,
}

pub(super) enum Outcome {
    Catalog { repository: String, result: Result<Vec<CatalogEntry>> },
    Package(Result<Snapshot>),
    RuntimeReview { enable: Option<Enable>, result: Result<RuntimeRelease> },
    RuntimeInstalled { enable: Option<Enable>, result: Result<WorkerExecutable> },
}
pub(super) struct Event { generation: u64, outcome: Outcome }
struct Job { cancel: watch::Sender<bool>, task: tokio::task::JoinHandle<()> }
impl Drop for Job {
    fn drop(&mut self) {
        let _ = self.cancel.send(true);
        self.task.abort();
    }
}
pub(super) struct Downloads {
    directory: PathBuf,
    generation: u64,
    job: Option<Job>,
    sender: mpsc::Sender<Event>,
    pub receiver: mpsc::Receiver<Event>,
}
impl Downloads {
    pub fn new(directory: &Path) -> Self {
        let (sender, receiver) = mpsc::channel(16);
        Self { directory: directory.to_owned(), generation: 0, job: None, sender, receiver }
    }
    pub fn cancel(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        self.job = None;
    }
    fn start<F, Fut>(&mut self, work: F)
    where F: FnOnce(watch::Receiver<bool>) -> Fut + Send + 'static,
          Fut: Future<Output = Outcome> + Send + 'static {
        self.cancel();
        let generation = self.generation;
        let (cancel, cancelled) = watch::channel(false);
        let sender = self.sender.clone();
        let task = tokio::spawn(async move {
            let outcome = work(cancelled).await;
            let _ = sender.send(Event { generation, outcome }).await;
        });
        self.job = Some(Job { cancel, task });
    }
}

impl App {
    fn extension_download_visible(&self) -> bool {
        self.attached && matches!(self.dialog, Some(Dialog::ExtensionDownload(_)))
            && self.menu.as_ref().is_none_or(WorkspaceMenu::is_extensions)
    }
    pub(super) fn cancel_hidden_extension_download(&mut self) {
        if self.extension_downloads.job.is_some() && !self.extension_download_visible() {
            self.cancel_extension_download();
        }
    }
    pub(super) fn cancel_extension_download(&mut self) {
        self.extension_downloads.cancel();
        if matches!(self.dialog, Some(Dialog::ExtensionDownload(_))) { self.dialog = None; }
        if matches!(self.quit_dialog, Some(Dialog::ExtensionDownload(_))) { self.quit_dialog = None; }
        if let Some(menu) = &mut self.menu { menu.set_extension_notice(Notice::info("Download cancelled; no extension was enabled.")); }
        self.restore_focused_mode();
        self.mark_dirty();
    }
    fn download_progress(&mut self, title: &str, description: String) {
        let mut review = ExtensionReview::new(title,
            format!("{}\n\nCancel download stops this request. No extension runs or gains permissions while downloading.", safe_text(&description)), "Cancel download");
        // Esc cancels the download too; a separate Cancel button would only repeat it.
        review.form.cancel.clear();
        self.set_dialog(Dialog::ExtensionDownload(review));
    }
    pub(super) fn browse_extension_repository(&mut self, repository: String) -> Result<()> {
        ensure!(self.attached, "Workspace is detached");
        self.close_extensions();
        if let Some(menu) = &mut self.menu { menu.set_extension_loading("Loading GitHub extension catalog…".into()); }
        self.download_progress("Browse extensions", format!("Reading published extension metadata from {repository}. Repositories and their descriptions are not publisher verification."));
        self.extension_downloads.start(move |cancel| async move {
            let result = distribution::browse(repository.clone(), cancel).await;
            Outcome::Catalog { repository, result }
        });
        Ok(())
    }
    pub(super) fn download_extension_package(&mut self, entry: CatalogEntry) -> Result<()> {
        ensure!(self.attached, "Workspace is detached");
        self.close_extensions();
        self.download_progress("Download extension package", format!("{} {}\nRepository: {}\nRelease: {}\nBytes: {}\nSHA-256: {}\n\nThe exact package and its permissions will be reviewed before installation.",
            entry.manifest.name, entry.manifest.version, entry.source.repository, entry.source.tag, entry.bytes, entry.digest));
        self.extension_downloads.start(move |cancel| async move {
            Outcome::Package(distribution::download(entry, cancel).await)
        });
        Ok(())
    }
    pub(super) fn request_extension_runtime(&mut self, enable: Option<Enable>) -> Result<()> {
        ensure!(self.attached && !self.store.is_uncertain(), "Workspace is not available for approval");
        if let Some(enable) = &enable { self.check_extension_enable(enable)?; }
        self.close_extensions();
        self.download_progress("Extension runtime information", format!("Looking up the optional sandbox worker for Vyx {} from {}.\n\nCore Vyx needs no helper. Extensions require this separate, Vyx-managed executable. Its size, version and checksum will be shown before you approve downloading it.", env!("CARGO_PKG_VERSION"), distribution::OFFICIAL_REPOSITORY));
        self.extension_downloads.start(move |cancel| async move {
            Outcome::RuntimeReview { enable, result: distribution::runtime_release(cancel).await }
        });
        Ok(())
    }
    pub(super) fn install_extension_runtime(&mut self, release: RuntimeRelease, enable: Option<Enable>) -> Result<()> {
        ensure!(self.attached && !self.store.is_uncertain(), "Workspace is not available for approval");
        if let Some(enable) = &enable { self.check_extension_enable(enable)?; }
        let directory = self.extension_downloads.directory.clone();
        self.close_extensions();
        self.download_progress("Downloading extension runtime", format!("Vyx {} · {}\nRepository: {}\nBytes: {}\nSHA-256: {}\n\nThis installs the optional native sandbox worker, not Node.js or Javy. A completed runtime download may remain cached even if you cancel before enabling an extension.", release.version, release.target, release.source.repository, release.bytes, release.digest));
        self.extension_downloads.start(move |cancel| async move {
            Outcome::RuntimeInstalled { enable, result: distribution::install_runtime(directory, release, cancel).await }
        });
        Ok(())
    }
    fn check_extension_enable(&self, enable: &Enable) -> Result<()> {
        let manager = self.extensions.as_ref().context("Extensions unavailable")?;
        ensure!(!manager.registry.is_blocked(), "Registry needs persistence Retry");
        let entry = manager.registry.entries().iter().find(|entry| entry.id == enable.id && entry.digest == enable.digest)
            .context("Package changed; review permissions again")?;
        ensure!(!entry.id.starts_with("com.vyx.") || entry.source.as_ref().is_some_and(|source| source.is_official()),
            "legacy Vyx extension requires a reviewed official-store update before enabling");
        ensure!(entry.manifest.permissions.len() == enable.grants.len()
            && entry.manifest.permissions.iter().all(|permission| enable.grants.contains(permission)), "Permissions changed; review again");
        Ok(())
    }
    pub(super) async fn handle_extension_download(&mut self, event: Event) {
        if event.generation != self.extension_downloads.generation || self.extension_downloads.job.is_none() { return; }
        if !self.extension_download_visible() { self.cancel_extension_download(); return; }
        self.extension_downloads.job = None;
        self.dialog = None;
        let result: Result<()> = (|| {
            match event.outcome {
                Outcome::Catalog { repository, result } => {
                    let entries = result?;
                    self.menu.as_mut().context("Extension browser closed")?.set_extension_catalog(repository, entries);
                }
                Outcome::Package(result) => self.review_extension_snapshot(result?, None, None)?,
                Outcome::RuntimeReview { enable, result } => {
                    let release = result?;
                    if let Some(enable) = &enable { self.check_extension_enable(enable)?; }
                    let permission_notice = enable.as_ref().map_or_else(|| "No extension will be enabled by this download.".into(), |enable| format!("After a verified download, enable {} with the permissions you just reviewed. It will not run until you open its command.", enable.id));
                    let content = format!("Optional native extension worker\nVersion: {}\nPlatform: {}\nRepository: {}\nRelease: {}\nAsset: {}\nBytes: {}\nSHA-256: {}\n\nCore Vyx remains standalone. Enabling extensions requires this additional executable; no system runtime or package manager is needed. The worker is downloaded only from Vyx's own release, never from an extension repository.\n\n{}",
                        release.version, release.target, release.source.repository, release.source.tag, release.source.asset, release.bytes, release.digest, permission_notice);
                    self.extension_review = Some(extensions::PendingReview::Runtime { release, enable });
                    self.menu = None;
                    self.set_dialog(Dialog::ExtensionReview(ExtensionReview::new("Download extension runtime?", content, "Download runtime")));
                }
                Outcome::RuntimeInstalled { enable, result } => {
                    let executable = result?;
                    ensure!(self.attached && !self.store.is_uncertain(), "Workspace became unavailable; runtime may be cached but no extension was enabled");
                    if let Some(enable) = &enable { self.check_extension_enable(enable)?; }
                    let manager = self.extensions.as_mut().context("Extensions unavailable")?;
                    manager.runtime = Some(executable);
                    self.extension_error = None;
                    // A runtime-only installation has no affected package to land on.
                    let affected = enable.as_ref().map(|enable| enable.id.clone());
                    if let Some(enable) = enable {
                        extensions::persisted(manager.registry.enable(&enable.id, &enable.digest, enable.grants)?)?;
                        self.notify_success("Runtime installed and extension enabled. Open its command with the Extensions shortcut.");
                    } else {
                        self.notify_success("Extension runtime installed. Extensions still require explicit permission approval.");
                    }
                    self.open_extension_settings(affected.as_deref());
                }
            }
            Ok(())
        })();
        if let Err(error) = result {
            let error = safe_text(&format!("{error:#}"));
            // One inline error on the open Extensions page, not an extra dialog.
            match &mut self.menu {
                Some(menu) => menu.set_error(error),
                None => self.set_dialog(message("Extension download failed", error)),
            }
        }
        self.refresh_extension_entries();
        self.restore_focused_mode();
        self.mark_dirty();
    }
}
