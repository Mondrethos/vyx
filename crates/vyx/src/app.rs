mod ai;
mod extensions;
mod extension_downloads;
mod tailscale;

use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow, ensure};
use crossterm::event::{
    Event, KeyEvent, MouseButton, MouseEvent, MouseEventKind,
};
use futures_util::future::pending;
use ratatui::layout::Rect;
use tokio::sync::{Notify, mpsc, watch};
use uuid::Uuid;

use crate::{
    input::{
        Focus, InputMode, InputQueue, PrefixAction, PrefixContext, SidebarAction, is_key_input,
        is_local_scrollback, prefix_action, sidebar_action,
    },
    screen::{Screen, ScreenEvent, safe_text},
    settings::{LockSessions, Motion, Settings, TerminalLayout, WorkspaceSettings},
    shortcuts::{Bindings, Shortcut},
    ssh::{PromptRequest, ReconnectAuth, Session, SessionPhase},
    sync::{SyncChoice, SyncController, SyncStatus},
    ui::{
        actions::{
            AddMenu, ConfirmAction, ConfirmDialog, Dialog, DialogInput, Editor, Mutation,
            SnippetDialog, SyncQuestionDialog, auth_label, category_path, routing_label,
        },
        catalog::{Catalog, RowKey, Section, SessionEntry},
        form::Field,
        lock::{UnlockOptions, UnlockRequest},
        menu::{MenuAction, MenuMode, WorkspaceMenu},
        render::{
            HitRegion, HitTarget, NARROW_COLUMNS, RenderOutput, RenderRequest, ai_width, contains, draw,
            sidebar_width, too_small,
        },
        terminal_layout::PaneResize,
        widgets::{Notice, NoticeKind},
    },
    update::UpdateMonitor,
    vault::{Directory, LocalState, Store, Vault},
};

const FRAME_INTERVAL: Duration = Duration::from_millis(34);
const DOUBLE_CLICK: Duration = Duration::from_millis(500);
const RECOVERY_NOTICE: &str = "Passphrase reset. Save a new recovery file in Settings / Security; previous files no longer unlock this vault.";
/// Info and success notices clear on their own after this long.
const NOTICE_SHORT: Duration = Duration::from_secs(6);
/// Warnings and errors last longer, or until meaningful input after `NOTICE_GRACE`.
const NOTICE_LONG: Duration = Duration::from_secs(20);
const NOTICE_GRACE: Duration = Duration::from_secs(1);

pub async fn run(screen: &mut Screen, store: Store, settings: Settings, directory: Arc<Directory>, recovered: bool, setup_created: bool) -> Result<()> {
    App::run(screen, store, settings, directory, recovered, setup_created).await
}

pub struct App {
    extensions: Option<crate::extensions::manager::Manager>,
    extension_error: Option<String>,
    extension_surface: Option<crate::ui::extensions::ExtensionSurface>,
    extension_review: Option<extensions::PendingReview>,
    extension_downloads: extension_downloads::Downloads,
    tailnet: tailscale::State,
    ai: ai::State,
    store: Store,
    state: Arc<LocalState>,
    snapshots: watch::Receiver<Arc<LocalState>>,
    catalog: Catalog,
    sessions: Vec<Session>,
    input_queues: HashMap<Uuid, InputQueue>,
    active_session: Option<usize>,
    prompt_sender: mpsc::Sender<PromptRequest>,
    prompts: mpsc::Receiver<PromptRequest>,
    prompt_queue: VecDeque<PromptRequest>,
    dirty_notify: Arc<Notify>,
    sync: SyncController,
    updates: UpdateMonitor,
    update_notice: Option<String>,
    dialog: Option<Dialog>,
    settings: Settings,
    menu: Option<WorkspaceMenu>,
    search: Option<CatalogSearch>,
    mode: InputMode,
    prefix_page: usize,
    focus: Focus,
    mouse_capture: Option<MouseCapture>,
    sidebar_overlay: bool,
    /// The frontend is below the minimum size; only resize, detach, and quit controls work.
    too_small: bool,
    /// The first narrow frame has been seen, so the sidebar overlay no longer opens by itself.
    narrow_overlay_checked: bool,
    dirty: bool,
    attached: bool,
    attachment_generation: u64,
    detaching: bool,
    last_activity: Instant,
    lock_disconnected: bool,
    quit_confirming: bool,
    quit_dialog: Option<Dialog>,
    last_draw: Instant,
    unlock_reveal_started: Option<Instant>,
    render: RenderOutput,
    notice: Option<Notice>,
    /// The current notice reports uncertain durability and stays until a save is confirmed.
    notice_until_saved: bool,
    /// Recovery guidance outranks ordinary notices until a new recovery file is saved.
    recovery_guidance: Option<String>,
    sync_detail: String,
    quitting: bool,
    last_click: Option<(RowKey, Instant)>,
}

#[derive(Clone, Copy)]
enum MouseCapture {
    SidebarResize(u16),
    PaneResize(PaneResize),
    /// Live AI panel width while its divider is dragged; saved once on release.
    AiResize(u16),
    LocalPress,
    Ai,
    Terminal { session_id: Uuid, button: MouseButton, area: Rect },
}

struct CatalogSearch {
    field: Field,
    previous_filter: String,
    previous_selection: Option<RowKey>,
}

impl App {
    pub async fn run(screen: &mut Screen, mut store: Store, mut settings: Settings, directory: Arc<Directory>, mut recovered: bool, mut setup_created: bool) -> Result<()> {
        loop {
            let (locked, next_settings) = {
                let mut app = Self::new(store, settings, directory.path()).await;
                if std::mem::take(&mut setup_created) { app.open_menu(MenuMode::SetupCreated); }
                if recovered { app.recovery_guidance = Some(RECOVERY_NOTICE.into()); }
                let result = app.run_loop(screen).await;
                let stopped = app.store.shutdown().await;
                result?;
                stopped?;
                (app.lock_disconnected, app.settings)
            };
            if !locked {
                return Ok(());
            }
            settings = next_settings;
            match crate::ui::lock::unlock(
                screen, &settings.bindings, &settings.theme.palette, UnlockOptions {
                    title: "Vault locked",
                    description: "Locked after inactivity. SSH sessions were disconnected, unsaved forms discarded, and the vault unloaded.",
                    live_sessions: 0, confirm_quit: true, allow_recovery: true,
                    motion: settings.workspace.motion,
                },
                |request| async {
                    match request {
                        UnlockRequest::Passphrase(passphrase) => directory.unlock(passphrase).await,
                        UnlockRequest::Recovery { file, new } => directory.recover(file, new).await,
                    }
                },
            ).await? {
                Some(unlocked) => { store = unlocked.value; recovered = unlocked.recovered; }
                None => return Ok(()),
            }
        }
    }

    async fn new(store: Store, settings: Settings, data_dir: &std::path::Path) -> Self {
        let state = store.snapshot();
        let snapshots = store.subscribe();
        let dirty_notify = Arc::new(Notify::new());
        let (prompt_sender, prompts) = mpsc::channel(32);
        let mut sync = SyncController::new(store.clone(), Arc::clone(&dirty_notify));
        if !store.is_uncertain() {
            sync.request(false);
        }
        let cache_directory = data_dir.to_owned();
        let runtime = tokio::task::spawn_blocking(move || crate::extensions::distribution::cached_runtime(&cache_directory))
            .await.context("check extension runtime cache").and_then(|result| result);
        let (extensions, extension_error) = match crate::extensions::manager::Manager::open(data_dir) {
            Ok(mut manager) => {
                let error = match runtime {
                    Ok(runtime) => { manager.runtime = runtime; None }
                    Err(error) => Some(safe_text(&format!("Extension runtime cache unavailable: {error:#}. Use Settings / Extensions to download it again."))),
                };
                (Some(manager), error)
            }
            Err(error) => (None, Some(safe_text(&format!("{error:#}")))),
        };
        let mut app = Self {
            extensions,
            extension_error,
            extension_surface: None,
            extension_review: None,
            extension_downloads: extension_downloads::Downloads::new(data_dir),
            tailnet: tailscale::State::new(),
            ai: ai::State::new(&state.ai, data_dir),
            store,
            state,
            snapshots,
            catalog: Catalog::default(),
            sessions: Vec::new(),
            input_queues: HashMap::new(),
            active_session: None,
            prompt_sender,
            prompts,
            prompt_queue: VecDeque::new(),
            dirty_notify,
            sync,
            updates: UpdateMonitor::new(),
            update_notice: None,
            dialog: None,
            settings,
            menu: None,
            search: None,
            mode: InputMode::Sidebar,
            prefix_page: 0,
            focus: Focus::Sidebar,
            mouse_capture: None,
            sidebar_overlay: false,
            too_small: false,
            narrow_overlay_checked: false,
            dirty: true,
            last_draw: Instant::now() - FRAME_INTERVAL,
            unlock_reveal_started: None,
            render: RenderOutput::default(),
            notice: None,
            notice_until_saved: false,
            recovery_guidance: None,
            sync_detail: String::new(),
            quitting: false,
            last_click: None,
            attached: false,
            attachment_generation: 0,
            detaching: false,
            last_activity: Instant::now(),
            lock_disconnected: false,
            quit_confirming: false,
            quit_dialog: None,
        };
        app.update_sync_detail();
        app
    }

    async fn run_loop(&mut self, screen: &mut Screen) -> Result<()> {
        self.update_attachment(screen);
        self.arm_unlock_reveal();
        let loop_result: Result<()> = async {
            while !self.quitting {
                self.update_attachment(screen);
                self.expire_notice();
                self.cancel_hidden_extension_download();
                self.revalidate_ai();
                self.check_ai_review();
                self.resume_ai_agent().await;
                if self.idle_expired() {
                    self.lock_idle(screen).await?;
                    continue;
                }
                if self.detaching {
                    self.detaching = false;
                    screen.detach();
                    self.set_attached(false);
                    continue;
                }
                self.flush_ai(screen).await;
                self.flush_input();
                self.activate_waiting_dialog();
                if self.attached && self.dialog.is_none() && self.search.is_none() && self.menu.is_none() {
                    if let Some(server) = screen.take_connect_request() {
                        if let Err(error) = self.connect_named_host(&server) {
                            self.set_dialog(message("Cannot connect", error));
                        }
                    }
                }
                if self.attached && (self.dirty || self.unlock_reveal_started.is_some()) && self.last_draw.elapsed() >= FRAME_INTERVAL {
                    self.draw(screen).await?;
                    continue;
                }
                match self.next_event(screen).await? {
                    AppEvent::Screen(None) => self.quitting = true,
                    AppEvent::Screen(Some(ScreenEvent::Input(event))) => self.handle_screen_event(event, screen.size()).await?,
                    AppEvent::Screen(Some(ScreenEvent::ConnectRequested)) => {}
                    AppEvent::Idle => self.lock_idle(screen).await?,
                    AppEvent::Dirty => self.mark_dirty(),
                    AppEvent::UpdateChanged => {
                        self.update_notice = self
                            .updates
                            .available()
                            .map(|tag| format!(" Update {tag} · vyx update "));
                        self.mark_dirty();
                    }
                    AppEvent::Snapshot => self.receive_snapshot(),
                    AppEvent::Prompt(Some(request)) => {
                        self.prompt_queue.push_back(request);
                        self.activate_waiting_dialog();
                        self.mark_dirty();
                    }
                    AppEvent::Prompt(None) => {}
                    AppEvent::Extension(Some(event)) => self.handle_extension_event(event).await,
                    AppEvent::Extension(None) => {}
                    AppEvent::Tailnet(Some(event)) => self.handle_tailnet_event(event).await,
                    AppEvent::Tailnet(None) => {}
                    AppEvent::ExtensionDownload(Some(event)) => self.handle_extension_download(event).await,
                    AppEvent::ExtensionDownload(None) => {}
                    AppEvent::Ai(Some(event)) => self.handle_ai_event(event).await,
                    AppEvent::Ai(None) => {}
                    AppEvent::SyncTick => {
                        self.update_sync_detail();
                        self.activate_waiting_dialog();
                        self.mark_dirty();
                    }
                    AppEvent::PromptCancelled => {
                        if let Some(mut dialog) = self.dialog.take() {
                            dialog.cancel_prompt();
                        }
                        self.restore_focused_mode();
                        self.activate_waiting_dialog();
                        self.mark_dirty();
                    }
                    AppEvent::Frame if self.attached => self.draw(screen).await?,
                    AppEvent::Frame => {}
                    AppEvent::NoticeExpired => self.expire_notice(),
                }
                self.update_attachment(screen);
            }
            Ok(())
        }
        .await;
        let shutdown_result = self.shutdown().await;
        if let Err(error) = loop_result {
            let _ = shutdown_result;
            return Err(error);
        }
        shutdown_result
    }

    async fn next_event(&mut self, screen: &mut Screen) -> Result<AppEvent> {
        let idle_seconds = self.settings.security.idle_timeout_seconds;
        let idle_deadline = self.last_activity + Duration::from_secs(u64::from(idle_seconds));
        let frame_deadline = self.last_draw + FRAME_INTERVAL;
        let frame_pending = self.attached && (self.dirty || self.unlock_reveal_started.is_some());
        let notice_deadline = self.notice.as_ref().and_then(|notice| notice.expires_at);
        let notice_wake = notice_deadline.unwrap_or(frame_deadline);
        let Self {
            dirty_notify,
            snapshots,
            prompts,
            sync,
            updates,
            dialog,
            extensions,
            tailnet,
            extension_downloads,
            ai,
            ..
        } = self;
        tokio::select! {
            event = screen.next_event() => Ok(AppEvent::Screen(event?)),
            _ = tokio::time::sleep_until(idle_deadline.into()), if idle_seconds > 0 => Ok(AppEvent::Idle),
            _ = dirty_notify.notified() => Ok(AppEvent::Dirty),
            changed = snapshots.changed() => {
                changed.map_err(|_| anyhow!("Vault snapshot publisher stopped"))?;
                Ok(AppEvent::Snapshot)
            }
            request = prompts.recv() => Ok(AppEvent::Prompt(request)),
            _ = sync.tick() => Ok(AppEvent::SyncTick),
            _ = updates.changed() => Ok(AppEvent::UpdateChanged),
            _ = wait_for_prompt_cancellation(dialog) => Ok(AppEvent::PromptCancelled),
            event = extensions::next_event(extensions) => Ok(AppEvent::Extension(event)),
            event = tailnet.receiver.recv() => Ok(AppEvent::Tailnet(event)),
            event = extension_downloads.receiver.recv() => Ok(AppEvent::ExtensionDownload(event)),
            event = ai.receiver.recv() => Ok(AppEvent::Ai(event)),
            _ = tokio::time::sleep_until(frame_deadline.into()), if frame_pending => Ok(AppEvent::Frame),
            _ = tokio::time::sleep_until(notice_wake.into()), if notice_deadline.is_some() => Ok(AppEvent::NoticeExpired),
        }
    }

    fn notify(&mut self, kind: NoticeKind, text: impl Into<String>) {
        let lifetime = match kind {
            NoticeKind::Info | NoticeKind::Success => NOTICE_SHORT,
            NoticeKind::Warning | NoticeKind::Error => NOTICE_LONG,
        };
        self.notice = Some(Notice::new(kind, safe_text(&text.into())).expiring(lifetime));
        self.notice_until_saved = false;
        self.mark_dirty();
    }

    fn notify_info(&mut self, text: impl Into<String>) {
        self.notify(NoticeKind::Info, text);
    }

    fn notify_success(&mut self, text: impl Into<String>) {
        self.notify(NoticeKind::Success, text);
    }

    fn notify_warning(&mut self, text: impl Into<String>) {
        self.notify(NoticeKind::Warning, text);
    }

    fn notify_error(&mut self, text: impl Into<String>) {
        self.notify(NoticeKind::Error, text);
    }

    /// Uncertain-save details stay visible until a later save confirms durability.
    fn notify_uncertain(&mut self, text: impl Into<String>) {
        self.notice = Some(Notice::warning(safe_text(&text.into())));
        self.notice_until_saved = true;
        self.mark_dirty();
    }

    fn expire_notice(&mut self) {
        let expired = match &self.notice {
            Some(_) if self.notice_until_saved => !self.store.is_uncertain(),
            Some(notice) => notice.expires_at.is_some_and(|deadline| deadline <= Instant::now()),
            None => false,
        };
        if expired {
            self.notice = None;
            self.notice_until_saved = false;
            self.mark_dirty();
        }
    }

    /// Meaningful input dismisses a timed warning or error once it has been visible briefly.
    fn dismiss_notice_on_input(&mut self) {
        if self.notice.as_ref().is_some_and(|notice| {
            matches!(notice.kind, NoticeKind::Warning | NoticeKind::Error)
                && notice.expires_at.is_some()
                && notice.created_at.elapsed() >= NOTICE_GRACE
        }) {
            self.notice = None;
            self.mark_dirty();
        }
    }

    fn idle_expired(&self) -> bool {
        let seconds = self.settings.security.idle_timeout_seconds;
        seconds > 0 && self.last_activity.elapsed() >= Duration::from_secs(u64::from(seconds))
    }

    async fn lock_idle(&mut self, screen: &mut Screen) -> Result<()> {
        self.suspend_ai();
        self.flush_ai(screen).await;
        self.close_extensions();
        self.cancel_unfinished_authentication();
        self.unlock_reveal_started = None;
        self.close_prefix();
        self.mouse_capture = None;
        self.last_click = None;
        self.input_queues.clear();
        for session in &self.sessions {
            session.set_visible(false);
        }
        if self.settings.security.lock_sessions == LockSessions::Disconnect {
            if screen.is_attached() {
                screen.draw(|frame| {
                    let area = frame.area();
                    crate::ui::theming::clear(frame, area, &self.settings.theme.palette);
                    frame.render_widget(ratatui::widgets::Paragraph::new("Locking vault and disconnecting SSH sessions…"), area);
                }).await?;
            }
            self.lock_disconnected = true;
            self.quitting = true;
        } else {
            let live = self.sessions.iter().filter(|session| session.is_live()).count();
            let unlocked = crate::ui::lock::unlock(
                screen, &self.settings.bindings, &self.settings.theme.palette, UnlockOptions {
                    title: "Vault locked",
                    description: "Locked after inactivity. SSH sessions are still running. The decrypted vault remains in this process's memory.",
                    live_sessions: live, confirm_quit: true, allow_recovery: self.state.sync.is_none(),
                    motion: self.settings.workspace.motion,
                },
                |request| async {
                    match request {
                        UnlockRequest::Passphrase(passphrase) => self.store.verify_passphrase(passphrase).await.map(|()| None),
                        UnlockRequest::Recovery { file, new } => self.store.recover_passphrase(file, new).await,
                    }
                },
            ).await?;
            self.quitting = unlocked.is_none();
            self.last_activity = Instant::now();
            self.receive_snapshot();
            self.update_attachment(screen);
            if let Some(outcome) = unlocked {
                if outcome.recovered {
                    self.recovery_guidance = Some(outcome.value.map_or_else(|| RECOVERY_NOTICE.into(),
                        |warning| format!("{} {RECOVERY_NOTICE}", safe_text(&warning))));
                }
                self.arm_unlock_reveal();
            }
            self.mark_dirty();
        }
        Ok(())
    }

    fn arm_unlock_reveal(&mut self) {
        self.unlock_reveal_started = (self.attached && self.settings.workspace.motion == Motion::Full)
            .then(Instant::now);
    }

    fn update_attachment(&mut self, screen: &Screen) {
        if self.attachment_generation != screen.attachment_generation() {
            // A watch receiver can coalesce a rapid detach/attach into just Attached.
            self.set_attached(false);
            self.attachment_generation = screen.attachment_generation();
        }
        self.set_attached(screen.is_attached());
    }

    fn set_attached(&mut self, attached: bool) {
        if self.attached == attached {
            return;
        }
        self.attached = attached;
        self.unlock_reveal_started = None;
        self.last_click = None;
        self.mouse_capture = None;
        if attached {
            self.last_draw = Instant::now() - FRAME_INTERVAL;
            self.mark_dirty();
        } else {
            self.suspend_ai();
            self.close_extensions();
            self.cancel_unfinished_authentication();
            for session in &self.sessions {
                session.set_visible(false);
            }
            self.close_prefix();
        }
    }

    fn rebuild_catalog(&mut self) {
        self.catalog.rebuild(&self.state.vault, self.sessions.iter().map(|session| SessionEntry {
            id: session.id,
            label: &session.label,
        }));
    }

    async fn draw(&mut self, screen: &mut Screen) -> Result<()> {
        if !self.attached {
            return Ok(());
        }
        self.rebuild_catalog();
        let commands = self.prefix_context();
        let status = self.sync.status();
        let sync_label = status.label().to_owned();
        let state = Arc::clone(&self.state);
        let focus = self.focus;
        self.prepare_ai_unsent();
        let (ai_addon, _) = self.ai_addon();
        let ai_sessions = if self.ai.is_open() { self.ai_sessions() } else { Vec::new() };
        let ai_hosts = if self.ai.is_open() { self.ai_hosts() } else { Vec::new() };
        let ai_width = match self.mouse_capture {
            Some(MouseCapture::AiResize(width)) => Some(width),
            _ => None,
        };
        let prefix = matches!(self.mode, InputMode::Prefix { .. });
        // Menus, dialogs, search, and the prefix bar take keys before the panel, so its
        // composer must not keep the terminal cursor beneath them.
        let ai_keyboard = focus == Focus::Ai
            && self.mode == InputMode::Ai
            && self.menu.is_none()
            && self.extension_surface.is_none()
            && !self.quit_confirming;
        if prefix || self.menu.is_some() || self.dialog.is_some() || self.settings.workspace.motion != Motion::Full {
            self.unlock_reveal_started = None;
        }
        let sampled_at = Instant::now();
        let unlock_reveal = self.unlock_reveal_started
            .map(|started| sampled_at.saturating_duration_since(started))
            .filter(|elapsed| *elapsed < Duration::from_millis(420));
        let mut narrow_frame = false;
        let prefix_page = self.prefix_page;
        let workspace = self.settings.workspace;
        let theme = self.settings.theme;
        let sidebar_width = match self.mouse_capture {
            Some(MouseCapture::SidebarResize(width)) => width,
            _ => workspace.sidebar_width,
        };
        let sidebar_overlay = self.sidebar_overlay;
        // The first narrow frame of an empty workspace opens the sidebar overlay unless the
        // sidebar was saved collapsed; after that only explicit toggles change it.
        let first_overlay = !self.narrow_overlay_checked
            && focus == Focus::Sidebar
            && self.sessions.is_empty()
            && !workspace.sidebar_collapsed;
        let pane_resize = match self.mouse_capture {
            Some(MouseCapture::PaneResize(resize)) => Some(resize),
            _ => None,
        };
        let terminal_sizes = &self.settings.terminal_sizes;
        let active_session = self.active_session;
        let notice = self.notice.as_ref();
        let guidance = self.recovery_guidance.as_deref();
        let sync_detail = self.sync_detail.as_str();
        let update_notice = self.update_notice.as_deref();
        let uncertain = self.store.is_uncertain();
        let dialog = self.dialog.as_mut();
        let search = self.search.as_ref().map(|search| &search.field);
        let quit_confirming = self.quit_confirming;
        let menu = &mut self.menu;
        let extension_surface = &mut self.extension_surface;
        let bindings = &self.settings.bindings;
        let sessions = &self.sessions;
        let catalog = &mut self.catalog;
        let ai = &mut self.ai;
        let output = &mut self.render;
        screen
            .draw(|frame| {
                let area = frame.area();
                narrow_frame = !too_small(area.width, area.height) && area.width < NARROW_COLUMNS;
                draw(frame, RenderRequest {
                    catalog: &mut *catalog,
                    state: &state,
                    sessions,
                    active_session,
                    focus,
                    prefix,
                    prefix_page,
                    commands,
                    workspace,
                    theme,
                    terminal_sizes,
                    pane_resize,
                    sidebar_width,
                    sidebar_overlay: sidebar_overlay || (first_overlay && narrow_frame),
                    sync_label: &sync_label,
                    sync_detail,
                    notice,
                    guidance,
                    update_notice,
                    uncertain,
                    dialog,
                    search,
                    bindings,
                    menu: if quit_confirming { None } else { menu.as_mut() },
                    extension_surface: extension_surface.as_mut(),
                    unlock_reveal,
                    ai: (ai_addon != crate::ui::ai::Addon::Missing)
                        .then(|| ai.render(ai_addon, ai_keyboard, &ai_sessions, &ai_hosts)),
                    ai_width,
                }, output);
            })
            .await?;
        if self.render.too_small || unlock_reveal.is_none() { self.unlock_reveal_started = None; }
        self.last_draw = Instant::now();
        self.dirty = false;
        if narrow_frame && !self.narrow_overlay_checked {
            self.narrow_overlay_checked = true;
            self.sidebar_overlay |= first_overlay;
        }
        if self.render.narrow {
            if self.search.is_some() {
                self.sidebar_overlay = true;
            }
        } else {
            self.sidebar_overlay = false;
        }
        let mut panes = self.render.terminals.iter().peekable();
        for session in &self.sessions {
            let pane = panes.next_if(|pane| pane.session_id == session.id);
            session.set_visible(pane.is_some());
            if let Some(pane) = pane {
                if session.resize(pane.inner.height, pane.inner.width) {
                    self.dirty = true;
                }
            }
        }
        Ok(())
    }

    fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    fn receive_snapshot(&mut self) {
        let snapshot = Arc::clone(&self.snapshots.borrow_and_update());
        self.adopt_state(snapshot);
    }

    fn adopt_state(&mut self, state: Arc<LocalState>) {
        if state.vault.snapshot_id != self.state.vault.snapshot_id {
            self.catalog.invalidate();
            self.sync.edited();
        }
        self.state = state;
        self.update_sync_detail();
        self.mark_dirty();
    }

    fn update_sync_detail(&mut self) {
        self.sync_detail = match self.sync.status() {
            SyncStatus::Error(error) => safe_text(&error),
            SyncStatus::Conflict => {
                "Local and server snapshots differ; choose a resolution.".to_owned()
            }
            SyncStatus::Pending => {
                "Synchronization is pending; local data remains saved.".to_owned()
            }
            SyncStatus::Syncing => "Synchronizing an encrypted snapshot…".to_owned(),
            SyncStatus::Synced => "Local and server snapshots match.".to_owned(),
            SyncStatus::LocalOnly => "This vault is stored only on this device.".to_owned(),
        };
    }

    fn activate_waiting_dialog(&mut self) {
        let changed = refresh_authentication_dialog(&mut self.dialog, &self.sessions)
            | refresh_authentication_dialog(&mut self.quit_dialog, &self.sessions)
            | refresh_snippet_target(&mut self.dialog, &self.sessions)
            | refresh_snippet_target(&mut self.quit_dialog, &self.sessions);
        if changed {
            if !matches!(self.mode, InputMode::Prefix { .. }) { self.restore_focused_mode(); }
            self.mark_dirty();
        }
        if !self.attached { return; }
        if self.dialog.is_some() || self.search.is_some() || self.menu.is_some() {
            return;
        }
        while let Some(request) = self.prompt_queue.pop_front() {
            let session_live = self
                .sessions
                .iter()
                .any(|session| session.id == request.session_id && session.is_live());
            if !session_live || *request.cancelled.borrow() {
                let _ = request.response.send(None);
                continue;
            }
            self.set_dialog(Dialog::Prompt(crate::ui::actions::PromptDialog::new(
                request,
            )));
            return;
        }
        let notice = self.sessions.iter().find_map(|session| {
            let view = session.view.lock();
            let notice = view.auth_notice.as_ref()?;
            let identity = match &session.destination.auth {
                crate::ssh::ReconnectAuth::Tailscale { identity, .. } => format!("\nTailnet: {}\nStable node: {}", identity.tailnet_id, identity.node_id),
                _ => String::new(),
            };
            let mut content = format!("Session: {}\nSession UUID: {}\nDestination: {}:{}{}\n\nVerified Tailscale SSH server message. Open HTTPS check links manually in your browser; Vyx never opens or fetches them. Authentication continues without dismissing this notice. Cancel closes this connection.\n\n", safe_text(&session.label), session.id, safe_text(&session.destination.address), session.destination.port, identity);
            let content_start = content.len();
            content.push_str(&notice.text);
            let mut review = crate::ui::actions::ExtensionReview::new("Verified Tailscale SSH server message", content, "Cancel connection");
            // Esc cancels the connection too; a separate Cancel button would only repeat it.
            review.form.cancel.clear();
            Some(Dialog::AuthenticationNotice { session_id: session.id, review, content_start })
        });
        if let Some(notice) = notice { self.set_dialog(notice); return; }
        if let Some(question) = self.sync.take_question() {
            self.set_dialog(Dialog::SyncQuestion(SyncQuestionDialog::new(question)));
        }
    }
    fn cancel_unfinished_authentication(&mut self) {
        for session in &self.sessions { session.cancel_unfinished_authentication(); }
        if matches!(self.dialog, Some(Dialog::AuthenticationNotice { .. })) { self.dialog = None; }
        if matches!(self.quit_dialog, Some(Dialog::AuthenticationNotice { .. })) { self.quit_dialog = None; }
    }

    async fn cancel_authentication_notice(&mut self, id: Uuid) -> Result<()> {
        self.ai_session_invalidated(id);
        if let Some(session) = self.sessions.iter_mut().find(|session| session.id == id) { session.close().await?; }
        self.restore_focused_mode();
        Ok(())
    }

    fn set_dialog(&mut self, dialog: Dialog) {
        self.unlock_reveal_started = None;
        if matches!(self.mouse_capture, Some(MouseCapture::SidebarResize(_) | MouseCapture::PaneResize(_) | MouseCapture::AiResize(_) | MouseCapture::Ai)) {
            self.mouse_capture = Some(MouseCapture::LocalPress);
        }
        self.dialog = Some(dialog);
        self.mode = InputMode::Modal;
        self.mark_dirty();
    }

    fn restore_focused_mode(&mut self) {
        if self.focus == Focus::Ai && !self.ai.is_open() {
            self.focus = if self.active_session.is_some_and(|index| index < self.sessions.len()) { Focus::Terminal } else { Focus::Sidebar };
        }
        if self.dialog.is_none() {
            self.mode = InputMode::focused(self.focus);
        }
    }

    async fn handle_screen_event(&mut self, event: Event, (columns, rows): (u16, u16)) -> Result<()> {
        // Gate on the frontend's current size: hit regions may still describe a larger frame.
        self.too_small = too_small(columns, rows);
        let activity = match &event {
            Event::Key(key) => is_key_input(*key),
            Event::Paste(_) => true,
            Event::Mouse(mouse) => matches!(mouse.kind, MouseEventKind::Down(_) | MouseEventKind::Drag(_)
                | MouseEventKind::ScrollUp | MouseEventKind::ScrollDown | MouseEventKind::ScrollLeft | MouseEventKind::ScrollRight),
            _ => false,
        };
        if activity {
            self.last_activity = Instant::now();
            self.dismiss_notice_on_input();
        }
        if activity || matches!(event, Event::Resize(_, _)) {
            if self.unlock_reveal_started.take().is_some() { self.mark_dirty(); }
        }
        if !matches!(&event, Event::Mouse(_)) {
            self.last_click = None;
            if matches!(self.mouse_capture, Some(MouseCapture::SidebarResize(_) | MouseCapture::PaneResize(_) | MouseCapture::AiResize(_) | MouseCapture::Ai)) {
                self.mouse_capture = Some(MouseCapture::LocalPress);
                self.mark_dirty();
                if matches!(&event, Event::Key(key) if self.settings.bindings.matches(Shortcut::Cancel, *key)) {
                    return Ok(());
                }
            }
        }
        match event {
            Event::Key(key) if is_key_input(key) => self.handle_key(key).await,
            Event::Paste(text) => self.handle_paste(text).await,
            Event::Mouse(mouse) => self.handle_mouse(mouse).await,
            Event::Resize(_, _) => {
                self.mark_dirty();
                Ok(())
            }
            Event::FocusGained | Event::FocusLost => {
                self.mark_dirty();
                Ok(())
            }
            _ => Ok(()),
        }
    }

    async fn handle_key(&mut self, key: KeyEvent) -> Result<()> {
        if matches!(self.mode, InputMode::Prefix { .. }) {
            let action = prefix_action(key, &self.settings.bindings);
            if action != PrefixAction::Consume {
                return self.handle_prefix(action).await;
            }
            if self.render.prefix_pages > 1 {
                if self.settings.bindings.matches(Shortcut::MenuPageUp, key) {
                    self.page_prefix(-1);
                    return Ok(());
                }
                if self.settings.bindings.matches(Shortcut::MenuPageDown, key) {
                    self.page_prefix(1);
                    return Ok(());
                }
            }
            // An unbound chord closes the bar and is never forwarded; a key that bindings
            // cannot express, such as a lone modifier, leaves the bar open.
            if let Some(label) = crate::shortcuts::key_label(key) {
                self.close_prefix();
                self.notify_info(format!("No command bound to {label}"));
            }
            return Ok(());
        }
        let overlay = self.menu.is_some() || self.dialog.is_some() || self.search.is_some() || self.extension_surface.is_some();
        if self.settings.bindings.matches_prefix(key, overlay) {
            self.start_prefix(key);
            return Ok(());
        }
        if self.quit_confirming {
            return self.handle_dialog_key(key).await;
        }
        if self.too_small {
            // Nothing but size guidance is visible, so no key may reach a hidden destination.
            return Ok(());
        }
        if let Some(menu) = &mut self.menu {
            let action = menu.key(key, &self.settings.bindings, self.settings.workspace, &self.state, self.settings.theme);
            self.handle_menu_action(action).await;
            return Ok(());
        }
        if self.dialog.is_some() {
            return self.handle_dialog_key(key).await;
        }
        if let Some(surface) = &mut self.extension_surface {
            let action = surface.key(key, &self.settings.bindings);
            self.handle_extension_surface(action).await;
            return Ok(());
        }
        if self.search.is_some() {
            self.handle_search_key(key);
            return Ok(());
        }
        if (self.store.is_uncertain() || self.ai.needs_save_retry())
            && self.settings.bindings.matches(Shortcut::RetrySave, key)
        {
            self.retry_save().await;
            self.mark_dirty();
            return Ok(());
        }
        match self.focus {
            Focus::Sidebar => self.handle_sidebar(sidebar_action(key, &self.settings.bindings)).await,
            Focus::Terminal => self.handle_terminal_key(key).await,
            Focus::Ai => self.handle_ai_key(key).await,
        }
    }

    async fn handle_dialog_key(&mut self, key: KeyEvent) -> Result<()> {
        let Some(mut dialog) = self.dialog.take() else {
            return Ok(());
        };
        let input = dialog.input(key, &self.settings.bindings);
        self.handle_dialog_input(dialog, input).await
    }

    async fn handle_dialog_input(&mut self, mut dialog: Dialog, input: DialogInput) -> Result<()> {
        match input {
            DialogInput::Continue => self.dialog = Some(dialog),
            DialogInput::Cancel => {
                let ai_review = matches!(&dialog, Dialog::ExtensionReview(review) if self.ai_review_matches(review));
                if ai_review {
                    self.dismiss_ai_review();
                } else {
                    if self.tailnet.waiting || matches!(dialog, Dialog::ConnectionDraft(_) | Dialog::ExtensionReview(_)) { self.tailnet.cancel_requests(); }
                    if matches!(dialog, Dialog::ExtensionReview(_)) { self.extension_review = None; }
                }
                if self.quit_confirming {
                    self.quit_confirming = false;
                    self.dialog = self.quit_dialog.take();
                    self.restore_focused_mode();
                    self.mark_dirty();
                    return Ok(());
                }
                match &mut dialog {
                    Dialog::Prompt(prompt) => prompt.respond(false),
                    Dialog::ExtensionDownload(_) => self.cancel_extension_download(),
                    Dialog::AuthenticationNotice { session_id, .. } => self.cancel_authentication_notice(*session_id).await?,
                    Dialog::SyncQuestion(_) => {
                        self.sync.answer(SyncChoice::Cancel);
                        self.update_sync_detail();
                    }
                    _ => {}
                }
                self.restore_focused_mode();
            }
            DialogInput::Submit => self.submit_dialog(dialog).await?,
        }
        self.activate_waiting_dialog();
        self.mark_dirty();
        Ok(())
    }

    async fn submit_dialog(&mut self, dialog: Dialog) -> Result<()> {
        match dialog {
            Dialog::ExtensionReview(review) if self.ai_review_matches(&review) => self.accept_ai_review().await,
            Dialog::ExtensionReview(review) => self.accept_extension_review(review).await,
            Dialog::ExtensionDownload(_) => self.cancel_extension_download(),
            Dialog::AuthenticationNotice { session_id, .. } => self.cancel_authentication_notice(session_id).await?,
            Dialog::ConnectionDraft(editor) => self.submit_connection_draft(editor).await,
            Dialog::Editor(mut editor) => match editor.mutation(&self.state.vault).await {
                Ok(mutation) if self.requires_schema_upgrade(&mutation) => self.review_schema_upgrade(mutation),
                Ok(mutation) => match self.commit_mutation(mutation).await {
                    Ok(()) => self.restore_focused_mode(),
                    Err(error) if self.store.is_uncertain() => {
                        self.notify_uncertain(format!("Save durability uncertain: {error:#}"));
                        self.restore_focused_mode();
                    }
                    Err(error) => {
                        let mut dialog = Dialog::Editor(editor);
                        dialog.set_error(format!("{error:#}"));
                        self.dialog = Some(dialog);
                    }
                },
                Err(error) => {
                    let mut dialog = Dialog::Editor(editor);
                    dialog.set_error(format!("{error:#}"));
                    self.dialog = Some(dialog);
                }
            },
            Dialog::AddMenu(menu) => {
                let result = if menu.form.fields[0].choice == 0 {
                    Editor::host(&self.state.vault, None, menu.parent)
                } else {
                    Editor::category(&self.state.vault, None, menu.parent)
                };
                match result {
                    Ok(editor) => self.set_dialog(Dialog::Editor(editor)),
                    Err(error) => self.set_dialog(message("Cannot add record", error)),
                }
            }
            Dialog::Confirm(confirm) => self.perform_confirm(confirm).await?,
            Dialog::Prompt(mut prompt) => {
                prompt.respond(true);
                self.restore_focused_mode();
            }
            Dialog::Snippet(snippet) => match snippet.target.filter(|_| snippet.available) {
                Some(target) => match self.insert_snippet(target, &snippet.command).await {
                    Ok(()) => {
                        self.notify_success(format!("Inserted '{}' without Enter", snippet.command));
                        self.restore_focused_mode();
                    }
                    Err(error) => self.set_dialog(message("Cannot insert snippet", error)),
                },
                None => self.dialog = Some(Dialog::Snippet(snippet)),
            },
            Dialog::SyncQuestion(question) => {
                self.sync.answer(question.choice());
                self.update_sync_detail();
                self.restore_focused_mode();
            }
            Dialog::RenameSession { session_id, mut form } => {
                let name = safe_text(form.value(0).trim());
                if name.trim().is_empty() {
                    form.error = "Session name cannot be blank.".into();
                    self.dialog = Some(Dialog::RenameSession { session_id, form });
                } else if let Some(session) = self.sessions.iter_mut().find(|session| session.id == session_id) {
                    session.label = name;
                    self.ai_session_renamed(session_id);
                    self.catalog.invalidate();
                    self.restore_focused_mode();
                } else {
                    self.set_dialog(message("Cannot rename session", "The session no longer exists."));
                }
            }
            Dialog::Preview { .. } | Dialog::Message { .. } => self.restore_focused_mode(),
        }
        Ok(())
    }

    async fn perform_confirm(&mut self, confirm: ConfirmDialog) -> Result<()> {
        let result = match confirm.action {
            ConfirmAction::DeleteCategory(id) => {
                self.commit_mutation(Mutation::DeleteCategory { id }).await
            }
            ConfirmAction::DeleteCredential(id) => {
                self.commit_mutation(Mutation::DeleteCredential { id })
                    .await
            }
            ConfirmAction::DeleteHost(id) => {
                self.commit_mutation(Mutation::DeleteHost { id }).await
            }
            ConfirmAction::DeleteSnippet(id) => {
                self.commit_mutation(Mutation::DeleteSnippet { id }).await
            }
            ConfirmAction::ForgetHostKey { hostname, port } => {
                self.commit_mutation(Mutation::ForgetHostKey { hostname, port })
                    .await
            }
            ConfirmAction::CloseSession(id) => self.close_session(id).await,
            ConfirmAction::DisableSync => {
                let result = self.sync.disable().await;
                if result.is_ok() {
                    self.adopt_state(self.store.snapshot());
                    self.notify_success("Synchronization disabled; local vault preserved");
                }
                result
            }
            ConfirmAction::Quit => {
                self.quitting = true;
                Ok(())
            }
        };
        match result {
            Ok(()) => self.restore_focused_mode(),
            Err(error) if self.store.is_uncertain() => {
                self.notify_uncertain(format!("Save durability uncertain: {error:#}"));
                self.restore_focused_mode();
            }
            Err(error) => {
                self.set_dialog(message("Action failed", error));
            }
        }
        Ok(())
    }

    async fn commit_mutation(&mut self, mutation: Mutation) -> Result<()> {
        // Captured before the mutation moves into the store: a save reveals its row, and a
        // removal names what it removed while selection falls back to the nearest row.
        let saved_host = match &mutation {
            Mutation::PutHost { host, .. } => Some(host.id),
            _ => None,
        };
        let vault = &self.state.vault;
        let removed = |kind: &str, label: Option<&str>| match label {
            Some(label) => format!("Deleted {kind} {label}"),
            None => format!("Deleted {kind}"),
        };
        let (reveal, notice) = match &mutation {
            Mutation::PutCategory { category, .. } => (Some(RowKey::Category(category.id)), format!("Saved {}", category.label)),
            Mutation::PutCredential { credential, .. } => (Some(RowKey::Credential(credential.id)), format!("Saved {}", credential.label)),
            Mutation::PutHost { host, .. } => (Some(RowKey::Host(host.id)), format!("Saved {}", host.label)),
            Mutation::PutSnippet { snippet, .. } => (Some(RowKey::Snippet(snippet.id)), format!("Saved {}", snippet.label)),
            Mutation::DeleteCategory { id } => (None, removed("category", vault.categories.iter().find(|entry| entry.id == *id).map(|entry| entry.label.as_str()))),
            Mutation::DeleteCredential { id } => (None, removed("credential", vault.credentials.iter().find(|entry| entry.id == *id).map(|entry| entry.label.as_str()))),
            Mutation::DeleteHost { id } => (None, removed("server", vault.hosts.iter().find(|entry| entry.id == *id).map(|entry| entry.label.as_str()))),
            Mutation::DeleteSnippet { id } => (None, removed("snippet", vault.snippets.iter().find(|entry| entry.id == *id).map(|entry| entry.label.as_str()))),
            Mutation::ForgetHostKey { hostname, port } => (None, format!("Forgot the trusted key for {hostname}:{port}")),
        };
        let state = self
            .store
            .commit(true, move |state| mutation.apply(state))
            .await?;
        self.adopt_state(state);
        if let Some(key) = reveal {
            self.catalog.reveal(key);
        }
        self.notify_success(notice);
        if let Some(host) = saved_host {
            self.ai_host_saved(host);
        }
        Ok(())
    }

    fn start_prefix(&mut self, key: KeyEvent) {
        self.mode = InputMode::Prefix { previous: self.focus, key };
        self.prefix_page = 0;
        self.last_click = None;
        self.mark_dirty();
    }

    fn close_prefix(&mut self) {
        if let InputMode::Prefix { previous, .. } = self.mode {
            self.focus = previous;
            if self.focus == Focus::Ai && !self.ai.is_open() {
                self.focus = if self.active_session.is_some_and(|index| index < self.sessions.len()) { Focus::Terminal } else { Focus::Sidebar };
            }
            self.mode = if self.dialog.is_some() {
                InputMode::Modal
            } else if self.search.is_some() {
                InputMode::Search
            } else {
                InputMode::focused(self.focus)
            };
            self.prefix_page = 0;
            self.mark_dirty();
        }
    }

    fn page_prefix(&mut self, delta: isize) {
        let pages = self.render.prefix_pages.max(1);
        self.prefix_page = (self.prefix_page.min(pages - 1) as isize + delta)
            .rem_euclid(pages as isize) as usize;
        self.mark_dirty();
    }

    /// Workspace facts that decide which prefix commands apply. The command bar renders
    /// from the same context, so dimmed commands are exactly the ones dispatch refuses.
    fn prefix_context(&self) -> PrefixContext {
        let previous = match self.mode {
            InputMode::Prefix { previous, .. } => previous,
            _ => self.focus,
        };
        let active = self.active_session.and_then(|index| self.sessions.get(index));
        PrefixContext {
            quit_confirming: self.quit_confirming,
            too_small: self.too_small,
            overlay: self.menu.is_some() || self.dialog.is_some() || self.search.is_some() || self.extension_surface.is_some(),
            switch_over_dialog: matches!(self.dialog, Some(Dialog::ExtensionReview(_) | Dialog::AuthenticationNotice { .. })),
            detach_over_overlay: (self.menu.is_none()
                && (self.extension_surface.is_some() || matches!(self.dialog, Some(Dialog::AuthenticationNotice { .. }))))
                || matches!(self.dialog, Some(Dialog::ExtensionDownload(_)))
                || matches!(&self.dialog, Some(Dialog::ExtensionReview(review)) if self.ai_review_matches(review)),
            sessions: self.sessions.len(),
            active_session: active.is_some(),
            literal_target: previous == Focus::Terminal && active.is_some_and(session_connected),
        }
    }

    async fn handle_prefix(&mut self, action: PrefixAction) -> Result<()> {
        let InputMode::Prefix { key: prefix, .. } = self.mode else {
            return Ok(());
        };
        if !action.applicable(&self.prefix_context()) {
            return Ok(());
        }
        self.close_prefix();
        match action {
            PrefixAction::ToggleSidebar => self.toggle_sidebar(),
            PrefixAction::CycleLayout => self.cycle_terminal_layout(),
            PrefixAction::NextSession => self.switch_session(1),
            PrefixAction::PreviousSession => self.switch_session(-1),
            PrefixAction::CloseSession => self.request_close_active().await?,
            PrefixAction::Sync => self.request_sync(),
            PrefixAction::Detach => self.detaching = true,
            PrefixAction::Quit => self.request_quit(),
            PrefixAction::Shortcuts => self.open_menu(MenuMode::Shortcuts),
            PrefixAction::Settings => self.open_menu(MenuMode::Settings),
            PrefixAction::Extensions => self.open_extension_picker(),
            PrefixAction::AiChat => self.toggle_ai(),
            PrefixAction::AiFocus => self.focus_ai(),
            PrefixAction::LiteralPrefix => {
                let bytes = self.active_session.and_then(|index| self.sessions.get(index))
                    .filter(|session| session_connected(session))
                    .and_then(|session| session.view.lock().terminal.key(prefix));
                if let Some(bytes) = bytes {
                    self.send_active(bytes).await?;
                }
            }
            PrefixAction::Cancel | PrefixAction::Consume => {}
        }
        self.mark_dirty();
        Ok(())
    }

    fn open_menu(&mut self, mode: MenuMode) {
        if self.quit_confirming {
            return;
        }
        self.close_prefix();
        self.last_click = None;
        self.menu = Some(WorkspaceMenu::new(mode, self.settings.security, &self.state));
        if let Some(menu) = &mut self.menu { menu.set_tailscale_cli_path(self.settings.tailscale_cli_path.clone()); }
        self.refresh_extension_entries();
        self.mark_dirty();
    }

    /// Opens Settings on an installed package: its sidebar child while enabled,
    /// otherwise its detail under Extensions. `None` or an unknown ID opens the
    /// Extensions list rather than a guessed child.
    fn open_extension_settings(&mut self, id: Option<&str>) {
        if self.quit_confirming {
            return;
        }
        self.open_menu(MenuMode::Settings);
        if let Some(menu) = &mut self.menu { menu.show_extension(id.unwrap_or_default()); }
    }

    async fn handle_menu_action(&mut self, action: MenuAction) {
        match action {
            MenuAction::None => {}
            MenuAction::Close => self.menu = None,
            MenuAction::Extension(action) => self.handle_extension_management(action).await,
            MenuAction::OpenAi => self.open_ai(crate::ui::ai::Tab::Settings),
            MenuAction::SaveTailscaleCliPath(path) => {
                let result = self.settings.save_tailscale_cli_path(path);
                if let Some(menu) = &mut self.menu {
                    match result {
                        Ok(warning) => { menu.set_tailscale_cli_path(self.settings.tailscale_cli_path.clone()); menu.saved(warning); }
                        Err(error) => menu.set_error(safe_text(&format!("Cannot save Tailscale setting: {error:#}"))),
                    }
                }
            }
            MenuAction::SaveBindings(bindings) => {
                let result = self.settings.save_bindings(bindings);
                if let Some(menu) = &mut self.menu {
                    match result {
                        Ok(warning) => menu.saved(warning),
                        Err(error) => menu.set_error(safe_text(&format!("Cannot save shortcuts: {error:#}"))),
                    }
                }
            }
            MenuAction::SaveWorkspace(workspace) => {
                let result = self.save_workspace_preferences(workspace);
                if let Some(menu) = &mut self.menu {
                    match result {
                        Ok(warning) => menu.saved(warning),
                        Err(error) => menu.set_error(safe_text(&format!("Cannot save workspace settings: {error:#}"))),
                    }
                }
            }
            MenuAction::SaveTheme(theme) => {
                let result = self.settings.save_theme(theme);
                if let Some(menu) = &mut self.menu {
                    match result {
                        Ok(warning) => menu.saved(warning),
                        Err(error) => menu.set_error(safe_text(&format!("Cannot save theme: {error:#}"))),
                    }
                }
            }
            MenuAction::SaveSecurity(security) => {
                let result = self.settings.save_security(security);
                if let Some(menu) = &mut self.menu {
                    match result {
                        Ok(warning) => {
                            self.last_activity = Instant::now();
                            menu.security_saved(security, warning);
                        }
                        Err(error) => menu.set_error(safe_text(&format!("Cannot save security settings: {error:#}"))),
                    }
                }
            }
            MenuAction::ChangePassphrase { current, new } => {
                let result = self.store.change_passphrase(current, new).await;
                if let Some(menu) = &mut self.menu {
                    match result {
                        Ok(warning) => menu.saved(warning),
                        Err(error) => menu.set_error(safe_text(&format!("Cannot change passphrase: {error:#}"))),
                    }
                }
            }
            MenuAction::SaveRecoveryFile { current, destination } => {
                let result = self.store.save_recovery_file(current, destination).await;
                if result.is_ok() {
                    self.recovery_guidance = None;
                }
                if let Some(menu) = &mut self.menu {
                    match result {
                        Ok(warning) => menu.saved(warning),
                        Err(error) => menu.set_error(safe_text(&format!("Cannot save recovery file: {error:#}"))),
                    }
                }
            }
            MenuAction::ConfigureSync { url, token } => {
                match self.sync.configure(url, token).await {
                    Ok(()) => {
                        self.notify_success("Sync settings saved");
                        self.adopt_state(self.store.snapshot());
                        if let Some(menu) = &mut self.menu {
                            menu.saved(None);
                        }
                    }
                    Err(error) => {
                        if let Some(menu) = &mut self.menu {
                            menu.set_error(safe_text(&format!("{error:#}")));
                        }
                    }
                }
            }
        }
        self.mark_dirty();
    }

    fn toggle_sidebar(&mut self) {
        if !self.render.narrow && !self.settings.workspace.sidebar_collapsed && self.focus != Focus::Sidebar {
            self.focus = Focus::Sidebar;
            self.restore_focused_mode();
        } else {
            let expanded = if self.render.narrow {
                self.sidebar_overlay
            } else {
                !self.settings.workspace.sidebar_collapsed
            };
            self.set_sidebar_expanded(!expanded);
        }
    }

    fn save_workspace_preferences(&mut self, workspace: WorkspaceSettings) -> Result<Option<String>> {
        let was_collapsed = self.settings.workspace.sidebar_collapsed;
        let warning = self.settings.save_workspace(workspace)?;
        if was_collapsed != workspace.sidebar_collapsed {
            self.sidebar_overlay = self.render.narrow && !workspace.sidebar_collapsed;
            if self.dialog.is_none() && self.search.is_none() {
                self.focus = if workspace.sidebar_collapsed { Focus::Terminal } else { Focus::Sidebar };
                self.restore_focused_mode();
            }
        }
        self.mark_dirty();
        Ok(warning)
    }

    /// Saves and applies a terminal layout. A save error leaves the previous layout in place.
    fn set_terminal_layout(&mut self, layout: TerminalLayout) -> Result<Option<String>> {
        self.save_workspace_preferences(WorkspaceSettings { terminal_layout: layout, ..self.settings.workspace })
    }

    fn cycle_terminal_layout(&mut self) {
        self.close_prefix();
        self.last_click = None;
        let terminal_layout = match self.settings.workspace.terminal_layout {
            TerminalLayout::Single => TerminalLayout::SideBySide,
            TerminalLayout::SideBySide => TerminalLayout::Stacked,
            TerminalLayout::Stacked => TerminalLayout::Grid,
            TerminalLayout::Grid => TerminalLayout::Single,
        };
        match self.set_terminal_layout(terminal_layout) {
            Ok(Some(warning)) => self.notify_warning(warning),
            Ok(None) => self.notify_info(format!("Layout: {}", terminal_layout.label())),
            Err(error) => self.notify_error(format!("Cannot save terminal layout: {error:#}")),
        }
        self.mark_dirty();
    }

    fn set_sidebar_expanded(&mut self, expanded: bool) {
        let workspace = WorkspaceSettings {
            sidebar_collapsed: !expanded,
            ..self.settings.workspace
        };
        if workspace != self.settings.workspace {
            match self.save_workspace_preferences(workspace) {
                Ok(Some(warning)) => self.notify_warning(warning),
                Ok(None) => {}
                Err(error) => {
                    self.notify_error(format!("Cannot save sidebar preferences: {error:#}"));
                    self.mark_dirty();
                    return;
                }
            }
        }
        if !expanded && self.search.is_some() {
            self.finish_search(false);
        }
        self.sidebar_overlay = expanded && self.render.narrow;
        self.focus = if expanded { Focus::Sidebar } else { Focus::Terminal };
        self.restore_focused_mode();
        self.mark_dirty();
    }

    fn switch_session(&mut self, delta: isize) {
        if self.sessions.is_empty() {
            return;
        }
        let current = self.active_session.unwrap_or(0);
        let next = if delta < 0 {
            (current + self.sessions.len() - 1) % self.sessions.len()
        } else {
            (current + 1) % self.sessions.len()
        };
        self.activate_session(next);
    }

    fn activate_session(&mut self, index: usize) {
        if index >= self.sessions.len() {
            return;
        }
        self.active_session = Some(index);
        self.focus = Focus::Terminal;
        self.sidebar_overlay = false;
        self.mode = InputMode::Terminal;
        self.mark_dirty();
    }

    async fn request_close_active(&mut self) -> Result<()> {
        if let Some(id) = self
            .active_session
            .and_then(|index| self.sessions.get(index))
            .map(|session| session.id)
        {
            self.request_close_session(id).await?;
        }
        Ok(())
    }

    async fn request_close_session(&mut self, id: Uuid) -> Result<()> {
        let Some(session) = self.sessions.iter().find(|session| session.id == id) else {
            return Ok(());
        };
        if session.is_live() {
            self.set_dialog(Dialog::Confirm(ConfirmDialog::new(
                "Close live session",
                format!("Close '{}'? Remote programs will be disconnected unless they run in a remote multiplexer.", session.label),
                "Close session",
                ConfirmAction::CloseSession(session.id),
            )));
        } else {
            self.close_session(id).await?;
        }
        self.mark_dirty();
        Ok(())
    }

    fn request_quit(&mut self) {
        if self.quit_confirming {
            return;
        }
        let live = self.sessions.iter().filter(|session| session.is_live()).count();
        self.quit_dialog = self.dialog.take();
        self.quit_confirming = true;
        self.set_dialog(Dialog::Confirm(ConfirmDialog::new(
            "Quit vyx",
            if live == 0 { "Stop this workspace? Unsaved form changes will be discarded.".to_owned() }
            else { format!("Disconnect {live} live SSH session(s) and stop this workspace? Remote programs may stop unless they run in a remote multiplexer.") },
            "Quit and disconnect",
            ConfirmAction::Quit,
        )));
    }

    async fn handle_sidebar(&mut self, action: SidebarAction) -> Result<()> {
        // Writes are refused while durability is uncertain, matching the action buttons that
        // Retry save replaces. Clearing a filter never writes, so it is never refused.
        if self.store.is_uncertain()
            && self.catalog.selected_key().is_some_and(|key| action.changes_saved_state(&key))
        {
            let retry = self.settings.bindings.primary(Shortcut::RetrySave);
            self.notify_warning(format!("Save durability uncertain; {retry} Retry save before changing saved records"));
            return Ok(());
        }
        match action {
            SidebarAction::Previous => self.catalog.move_selection(-1),
            SidebarAction::Next => self.catalog.move_selection(1),
            SidebarAction::Collapse => self.catalog.collapse_selected(&self.state.vault),
            SidebarAction::Expand => self.catalog.expand_selected(),
            SidebarAction::Activate => self.activate_selected().await?,
            SidebarAction::Add => self.add_selected(),
            SidebarAction::Edit => self.edit_selected(),
            SidebarAction::Delete => self.delete_selected(),
            SidebarAction::CloseSession => {
                if let Some(RowKey::Session(id)) = self.catalog.selected_key() {
                    self.request_close_session(id).await?;
                }
            }
            SidebarAction::Filter => self.start_search(),
            SidebarAction::ClearFilter => self.clear_filter(),
            SidebarAction::Inspect => self.preview_selected(),
            SidebarAction::ForgetHostKey => self.forget_selected_host_key(),
            SidebarAction::Sync => self.request_sync(),
            SidebarAction::RetrySave if self.store.is_uncertain() => self.retry_save().await,
            SidebarAction::RetrySave => {}
            SidebarAction::Quit => self.request_quit(),
            SidebarAction::None => {}
        }
        self.mark_dirty();
        Ok(())
    }

    /// Read-only details of the selected row. Credentials show names and kinds, never secrets
    /// or key material; headers summarize their section.
    fn preview_selected(&mut self) {
        let Some(key) = self.catalog.selected_key() else {
            return;
        };
        let vault = &self.state.vault;
        let activate = self.settings.bindings.primary(Shortcut::SidebarActivate);
        let (title, body) = match key {
            RowKey::Host(id) => return self.set_dialog(Dialog::preview(id)),
            RowKey::Session(id) => {
                let Some(session) = self.sessions.iter().find(|session| session.id == id) else {
                    return;
                };
                if let Some(host) = session.host_id {
                    return self.set_dialog(Dialog::preview(host));
                }
                let destination = &session.destination;
                let authentication = match &destination.auth {
                    ReconnectAuth::Credential(credential) => vault.credentials.iter()
                        .find(|entry| entry.id == *credential)
                        .map_or_else(
                            || "saved credential that no longer exists".to_owned(),
                            |entry| format!("{} from saved credential {} as {}", auth_label(&entry.auth), entry.label, entry.username),
                        ),
                    ReconnectAuth::Password { username } => format!("Password for this server only, as {username}"),
                    ReconnectAuth::Tailscale { username, .. } => format!("Keyless Tailscale SSH as {username}"),
                };
                ("Temporary connection", format!(
                    "Session: {} · UUID: {} · Destination: {}:{} · Routing: {} · Authentication: {authentication}. Reconnecting requires a fresh host-owned confirmation.",
                    session.label, session.id, destination.address, destination.port, routing_label(destination.transport),
                ))
            }
            RowKey::Credential(id) => {
                let Some(credential) = vault.credentials.iter().find(|entry| entry.id == id) else {
                    return;
                };
                let users = vault.hosts.iter().filter(|host| host.auth.credential_id() == Some(id)).count();
                ("Credential", format!(
                    "{} · Username: {} · Authentication: {} · Used by {}. Passwords and key contents are never shown.",
                    credential.label, credential.username, auth_label(&credential.auth), counted(users, "saved server", "saved servers"),
                ))
            }
            RowKey::Category(id) => {
                let Some(category) = vault.categories.iter().find(|entry| entry.id == id) else {
                    return;
                };
                let servers = vault.hosts.iter().filter(|host| host.category_id == Some(id)).count();
                let children = vault.categories.iter().filter(|entry| entry.parent_id == Some(id)).count();
                ("Category", format!(
                    "{} · Path: {} · {} directly inside · {}.",
                    category.label, category_path(vault, id), counted(servers, "server", "servers"),
                    counted(children, "child category", "child categories"),
                ))
            }
            RowKey::Snippet(id) => {
                let Some(snippet) = vault.snippets.iter().find(|entry| entry.id == id) else {
                    return;
                };
                ("Snippet", format!(
                    "{} · Command: {} · Insert ({activate}) types it into the active connected session without Enter.",
                    snippet.label, snippet.command,
                ))
            }
            RowKey::Section(Section::Sessions) => ("Sessions", format!(
                "{} open, {} connected. Connect a saved server to open an embedded SSH terminal; ended sessions can be reconnected or closed.",
                counted(self.sessions.len(), "session", "sessions"),
                self.sessions.iter().filter(|session| session_connected(session)).count(),
            )),
            RowKey::Section(Section::Servers) => ("Servers", format!(
                "{} in {}. Add creates a server or a category; Connect ({activate}) opens a session.",
                counted(vault.hosts.len(), "saved server", "saved servers"),
                counted(vault.categories.len(), "category", "categories"),
            )),
            RowKey::Ungrouped => ("Ungrouped servers", format!(
                "{} without a category. Add creates a server or a top-level category.",
                counted(vault.hosts.iter().filter(|host| host.category_id.is_none()).count(), "saved server", "saved servers"),
            )),
            RowKey::Section(Section::Credentials) => ("Credentials", format!(
                "{}. Servers refer to them by name; secrets stay encrypted in the vault.",
                counted(vault.credentials.len(), "reusable credential", "reusable credentials"),
            )),
            RowKey::Section(Section::Tools) | RowKey::Snippets => ("Snippets", format!(
                "{}. A snippet is a single-line command typed into a connected session without Enter.",
                counted(vault.snippets.len(), "snippet", "snippets"),
            )),
            RowKey::Section(Section::Sync) | RowKey::Sync => ("Synchronization", format!(
                "Status: {} · Server: {}. {}",
                self.sync.status().label(),
                self.state.sync.as_ref().map_or("not configured", |sync| sync.url.as_str()),
                self.sync_detail,
            )),
        };
        self.set_dialog(message(title, body));
    }

    fn start_search(&mut self) {
        self.search = Some(CatalogSearch {
            field: Field::text("Search", self.catalog.filter()),
            previous_filter: self.catalog.filter().to_owned(),
            previous_selection: self.catalog.selected_key(),
        });
        self.focus = Focus::Sidebar;
        self.sidebar_overlay = self.render.narrow;
        self.mode = InputMode::Search;
        self.mark_dirty();
    }

    fn handle_search_key(&mut self, key: KeyEvent) {
        let bindings = &self.settings.bindings;
        if bindings.matches(Shortcut::SearchKeep, key) {
            self.finish_search(false);
        } else if bindings.matches(Shortcut::SearchCancel, key) {
            self.finish_search(true);
        } else if bindings.matches(Shortcut::SearchPrevious, key) {
            self.catalog.move_selection(-1);
        } else if bindings.matches(Shortcut::SearchNext, key) {
            self.catalog.move_selection(1);
        } else {
            if let Some(search) = &mut self.search {
                search.field.key(key, bindings);
            }
            self.update_search_filter();
        }
        self.mark_dirty();
    }

    /// Every changed query rebuilds the list and selects its first matching record; with no
    /// match only section headers remain. An emptied query returns to where search began.
    fn update_search_filter(&mut self) {
        let Some(search) = &self.search else {
            return;
        };
        let query = search.field.value.trim();
        if self.catalog.filter() == query {
            return;
        }
        let query = query.to_owned();
        let origin = search.previous_selection.clone();
        self.catalog.set_filter(query);
        self.rebuild_catalog();
        if self.catalog.filter().is_empty() {
            if let Some(key) = origin {
                self.catalog.select(&key);
            }
        } else {
            self.catalog.select_first_match();
        }
    }

    fn finish_search(&mut self, cancel: bool) {
        if let Some(search) = self.search.take() {
            if cancel {
                self.catalog.set_filter(search.previous_filter);
                self.rebuild_catalog();
                if let Some(key) = search.previous_selection {
                    self.catalog.select(&key);
                }
            } else if self.catalog.filter().is_empty() {
                self.catalog.set_filter_origin(None);
            } else if search.previous_filter.is_empty() {
                // The first kept filter remembers where browsing was, for Clear filter.
                self.catalog.set_filter_origin(search.previous_selection);
            }
        }
        if self.settings.workspace.sidebar_collapsed {
            self.sidebar_overlay = false;
        }
        self.focus = Focus::Sidebar;
        self.mode = InputMode::Sidebar;
    }

    /// Clears a kept filter and returns to the row selected before it, if that row remains.
    fn clear_filter(&mut self) {
        if self.catalog.clear_filter() {
            self.rebuild_catalog();
        }
    }

    async fn activate_selected(&mut self) -> Result<()> {
        match self.catalog.selected_key() {
            Some(RowKey::Section(Section::Sync)) | Some(RowKey::Sync) => self.open_menu(MenuMode::Sync),
            Some(RowKey::Section(_))
            | Some(RowKey::Category(_))
            | Some(RowKey::Ungrouped)
            | Some(RowKey::Snippets) => {
                self.catalog.toggle_selected();
            }
            Some(RowKey::Session(id)) => {
                if let Some(index) = self.sessions.iter().position(|session| session.id == id) {
                    self.activate_session(index);
                }
            }
            Some(RowKey::Host(id)) => {
                if let Err(error) = self.connect_host(id, None) {
                    self.set_dialog(message("Cannot connect", error));
                }
            }
            Some(RowKey::Snippet(id)) => self.preview_snippet(id),
            Some(RowKey::Credential(_)) | None => {}
        }
        Ok(())
    }

    fn add_selected(&mut self) {
        let selected = self.catalog.selected_key();
        let dialog = match selected {
            Some(RowKey::Section(Section::Credentials)) | Some(RowKey::Credential(_)) => {
                Editor::credential(&self.state.vault, None).map(Dialog::Editor)
            }
            Some(RowKey::Section(Section::Tools))
            | Some(RowKey::Snippets)
            | Some(RowKey::Snippet(_)) => {
                Editor::snippet(&self.state.vault, None).map(Dialog::Editor)
            }
            Some(RowKey::Category(id)) => Ok(Dialog::AddMenu(AddMenu::new(Some(id)))),
            Some(RowKey::Host(id)) => {
                let parent = self
                    .state
                    .vault
                    .hosts
                    .iter()
                    .find(|host| host.id == id)
                    .and_then(|host| host.category_id);
                Ok(Dialog::AddMenu(AddMenu::new(parent)))
            }
            Some(RowKey::Section(Section::Servers)) | Some(RowKey::Ungrouped) => {
                Ok(Dialog::AddMenu(AddMenu::new(None)))
            }
            _ => return,
        };
        match dialog {
            Ok(dialog) => self.set_dialog(dialog),
            Err(error) => self.set_dialog(message("Cannot add record", error)),
        }
    }

    fn rename_session(&mut self, id: Uuid) {
        if let Some(session) = self.sessions.iter().find(|session| session.id == id) {
            let dialog = Dialog::rename_session(id, &session.label);
            self.last_click = None;
            self.set_dialog(dialog);
        }
    }

    fn edit_selected(&mut self) {
        let dialog = match self.catalog.selected_key() {
            Some(RowKey::Session(id)) => {
                self.rename_session(id);
                return;
            }
            Some(RowKey::Category(id)) => {
                Editor::category(&self.state.vault, Some(id), None).map(Dialog::Editor)
            }
            Some(RowKey::Credential(id)) => {
                Editor::credential(&self.state.vault, Some(id)).map(Dialog::Editor)
            }
            Some(RowKey::Host(id)) => {
                Editor::host(&self.state.vault, Some(id), None).map(Dialog::Editor)
            }
            Some(RowKey::Snippet(id)) => {
                Editor::snippet(&self.state.vault, Some(id)).map(Dialog::Editor)
            }
            Some(RowKey::Sync) | Some(RowKey::Section(Section::Sync)) => {
                self.open_menu(MenuMode::Sync);
                return;
            }
            _ => return,
        };
        match dialog {
            Ok(dialog) => self.set_dialog(dialog),
            Err(error) => self.set_dialog(message("Cannot edit record", error)),
        }
    }

    fn delete_selected(&mut self) {
        let dialog = match self.catalog.selected_key() {
            Some(RowKey::Category(id)) => {
                let Some(category) = self
                    .state
                    .vault
                    .categories
                    .iter()
                    .find(|entry| entry.id == id)
                else {
                    return;
                };
                Dialog::Confirm(ConfirmDialog::new(
                    "Delete category",
                    format!(
                        "Delete '{}'? Immediate child categories and servers will be reparented; no server is deleted.",
                        category.label
                    ),
                    "Delete category",
                    ConfirmAction::DeleteCategory(id),
                ))
            }
            Some(RowKey::Credential(id)) => {
                let Some(credential) = self
                    .state
                    .vault
                    .credentials
                    .iter()
                    .find(|entry| entry.id == id)
                else {
                    return;
                };
                let references: Vec<_> = self
                    .state
                    .vault
                    .hosts
                    .iter()
                    .filter(|host| host.auth.credential_id() == Some(id))
                    .map(|host| host.label.as_str())
                    .collect();
                if !references.is_empty() {
                    self.set_dialog(Dialog::message(
                        "Credential is in use",
                        format!(
                            "'{}' is used by: {}. Reassign those servers before deleting it.",
                            credential.label,
                            references.join(", ")
                        ),
                    ));
                    return;
                }
                Dialog::Confirm(ConfirmDialog::new(
                    "Delete credential",
                    format!("Delete credential '{}'?", credential.label),
                    "Delete credential",
                    ConfirmAction::DeleteCredential(id),
                ))
            }
            Some(RowKey::Host(id)) => {
                let Some(host) = self.state.vault.hosts.iter().find(|entry| entry.id == id) else {
                    return;
                };
                Dialog::Confirm(ConfirmDialog::new(
                    "Delete server",
                    format!(
                        "Delete saved server '{}'? Already-open sessions retain their connection snapshot and remain open.",
                        host.label
                    ),
                    "Delete server",
                    ConfirmAction::DeleteHost(id),
                ))
            }
            Some(RowKey::Snippet(id)) => {
                let Some(snippet) = self
                    .state
                    .vault
                    .snippets
                    .iter()
                    .find(|entry| entry.id == id)
                else {
                    return;
                };
                Dialog::Confirm(ConfirmDialog::new(
                    "Delete snippet",
                    format!("Delete snippet '{}'?", snippet.label),
                    "Delete snippet",
                    ConfirmAction::DeleteSnippet(id),
                ))
            }
            Some(RowKey::Sync) | Some(RowKey::Section(Section::Sync))
                if self.state.sync.is_some() =>
            {
                Dialog::Confirm(ConfirmDialog::new(
                    "Disable synchronization",
                    "Remove the saved origin, token, and checkpoint from this device? The local vault and the server's existing encrypted copy are preserved.",
                    "Disable sync",
                    ConfirmAction::DisableSync,
                ))
            }
            _ => return,
        };
        self.set_dialog(dialog);
    }

    fn forget_selected_host_key(&mut self) {
        let Some(RowKey::Host(id)) = self.catalog.selected_key() else {
            return;
        };
        let Some(host) = self.state.vault.hosts.iter().find(|entry| entry.id == id) else {
            return;
        };
        if matches!(host.auth, crate::vault::HostAuth::Tailscale { .. }) {
            self.set_dialog(message("Tailscale SSH host keys", "This keyless server uses Tailscale-distributed keys. Ordinary Forget key does not apply."));
            return;
        }
        let trusted = self.state.vault.known_hosts.iter().any(|known| {
            known.port == host.port && known.hostname.eq_ignore_ascii_case(&host.hostname)
        });
        if !trusted {
            self.set_dialog(Dialog::message("No saved key", "This server has no trusted host key to forget."));
            return;
        }
        self.set_dialog(Dialog::Confirm(ConfirmDialog::new(
            "Forget trusted key",
            format!("Forget the trusted key for {}:{}? The next connection must present and receive approval for a fresh key.", host.hostname, host.port),
            "Forget key",
            ConfirmAction::ForgetHostKey { hostname: host.hostname.clone(), port: host.port },
        )));
    }

    fn connect_named_host(&mut self, name: &str) -> Result<()> {
        let id = saved_host_id(&self.state.vault, name)?;
        let live_match = |index: usize| {
            self.sessions[index].host_id == Some(id) && self.sessions[index].is_live()
        };
        let existing = self.active_session.filter(|&index| live_match(index))
            .or_else(|| (0..self.sessions.len()).find(|&index| live_match(index)));
        if let Some(index) = existing {
            self.activate_session(index);
            Ok(())
        } else {
            self.connect_host(id, None)
        }
    }

    /// Opens a saved server; with `replaces`, the ended tab with that ID is replaced in place.
    fn connect_host(&mut self, id: Uuid, replaces: Option<Uuid>) -> Result<()> {
        let host = self
            .state
            .vault
            .hosts
            .iter()
            .find(|host| host.id == id)
            .context("The selected server no longer exists")?;
        let prepared = crate::ssh::PreparedConnection::saved(host, &self.state.vault.credentials, self.settings.tailscale_cli_path.clone())?;
        self.connect_prepared(prepared, replaces)
    }

    /// Opens a session. With `replaces`, the named tab must still exist and must have ended;
    /// the replacement is created first, so a failure leaves the old tab unchanged. The old
    /// session's approvals, queued input, prompts, and naming never transfer to the new UUID.
    fn connect_prepared(&mut self, prepared: crate::ssh::PreparedConnection, replaces: Option<Uuid>) -> Result<()> {
        let replace_index = replaces.map(|old| {
            let index = self.sessions.iter().position(|session| session.id == old)
                .context("The session to reconnect no longer exists")?;
            ensure!(!self.sessions[index].is_live(), "The session to reconnect is still running");
            Ok(index)
        }).transpose()?;
        let (count, index) = match replace_index {
            Some(index) => (self.sessions.len(), index),
            None => (self.sessions.len() + 1, self.sessions.len()),
        };
        let (rows, columns) = if let Some(area) = self.render.terminal_area {
            self.render.pane_layout.arrange(
                area,
                self.settings.workspace.terminal_layout,
                count,
                index,
                &self.settings.terminal_sizes,
                None,
            );
            self.render.pane_layout.panes()
                .find(|(pane, _)| *pane == index)
                .map(|(_, area)| (area.height.saturating_sub(2).max(1), area.width.saturating_sub(2).max(1)))
                .unwrap_or((24, 80))
        } else {
            (24, 80)
        };
        let mut session = Session::connect(
            prepared,
            self.store.clone(),
            rows.max(1),
            columns.max(1),
            self.prompt_sender.clone(),
            Arc::clone(&self.dirty_notify),
        )?;
        session.label = self.unique_tab_label(&session.label, replaces);
        if let Some(index) = replace_index {
            let old = self.sessions[index].id;
            self.ai_session_closed(old);
            self.input_queues.remove(&old);
            self.cancel_prompts_for(old);
            self.ai_session_opened(session.id, &session.label);
            // Dropping the ended session cancels anything left of its transport.
            drop(std::mem::replace(&mut self.sessions[index], session));
        } else {
            self.ai_session_opened(session.id, &session.label);
            self.sessions.push(session);
        }
        self.active_session = Some(index);
        self.catalog.invalidate();
        self.focus = Focus::Terminal;
        self.mode = InputMode::Terminal;
        self.sidebar_overlay = false;
        self.notice = None;
        self.mark_dirty();
        Ok(())
    }

    /// `base` when no other open tab uses it, otherwise `base (N)` with the smallest free N ≥ 2,
    /// shortening `base` so the suffix fits the tab-title limit. Saved servers are never renamed.
    fn unique_tab_label(&self, base: &str, replaces: Option<Uuid>) -> String {
        let taken = |label: &str| self.sessions.iter().any(|session| Some(session.id) != replaces && session.label == label);
        if !taken(base) {
            return base.to_owned();
        }
        (2..)
            .map(|number| {
                let suffix = format!(" ({number})");
                let keep = crate::ai::MAX_TAB_TITLE_CHARS.saturating_sub(suffix.chars().count());
                base.chars().take(keep).chain(suffix.chars()).collect::<String>()
            })
            .find(|candidate| !taken(candidate))
            .expect("a finite tab list leaves a free suffix")
    }

    fn preview_snippet(&mut self, id: Uuid) {
        let Some(snippet) = self
            .state
            .vault
            .snippets
            .iter()
            .find(|snippet| snippet.id == id)
        else {
            return;
        };
        let target = self
            .active_session
            .and_then(|index| self.sessions.get(index))
            .filter(|session| session_connected(session));
        self.set_dialog(Dialog::Snippet(SnippetDialog::new(
            snippet.command.clone(),
            target.map(|session| (session.id, session.label.clone())),
        )));
    }

    async fn insert_snippet(&mut self, session_id: Uuid, command: &str) -> Result<()> {
        let index = self
            .sessions
            .iter()
            .position(|session| session.id == session_id && session_connected(session))
            .context("The target session is no longer connected")?;
        let bytes = {
            let view = self.sessions[index].view.lock();
            view.terminal.paste(command)
        };
        self.queue_input(session_id, bytes)?;
        self.activate_session(index);
        Ok(())
    }

    /// Replaces an ended tab with a fresh connection to the same destination. Saved servers
    /// reconnect directly; temporary destinations require a fresh reviewed draft first.
    fn reconnect_session(&mut self, id: Uuid) -> Result<()> {
        let index = self.sessions.iter().position(|session| session.id == id).context("The session no longer exists")?;
        ensure!(!self.sessions[index].is_live(), "The session is still running");
        match self.sessions[index].host_id {
            Some(host_id) => self.connect_host(host_id, Some(id)),
            None => self.reconfirm_temporary(index),
        }
    }

    async fn handle_terminal_key(&mut self, key: KeyEvent) -> Result<()> {
        if !self.store.is_uncertain() && self.settings.bindings.matches(Shortcut::Reconnect, key) {
            if let Some(id) = self.active_session.and_then(|index| self.sessions.get(index))
                .filter(|session| !session.is_live())
                .map(|session| session.id)
            {
                if let Err(error) = self.reconnect_session(id) {
                    self.set_dialog(message("Cannot reconnect", error));
                }
                return Ok(());
            }
        }
        let Some(index) = self.active_session else {
            return Ok(());
        };
        let Some(session) = self.sessions.get(index) else {
            return Ok(());
        };
        if let Some(delta) = is_local_scrollback(key, &self.settings.bindings) {
            let mut view = session.view.lock();
            view.terminal.scroll(delta);
            drop(view);
            self.mark_dirty();
            return Ok(());
        }
        if !session_connected(session) {
            // Never buffered: a key for a session that cannot receive it is reported instead.
            let notice = unsent_input_notice(session, &self.settings.bindings);
            self.notify_info(notice);
            return Ok(());
        }
        let bytes = {
            let view = session.view.lock();
            view.terminal.key(key)
        };
        if let Some(bytes) = bytes {
            if let Err(error) = self.queue_input(session.id, bytes) {
                self.notify_error(format!("Session input failed: {error:#}"));
                self.mark_dirty();
            }
        }
        Ok(())
    }

    async fn handle_paste(&mut self, text: String) -> Result<()> {
        if self.too_small || self.quit_confirming || matches!(self.mode, InputMode::Prefix { .. }) {
            return Ok(());
        }
        if let Some(menu) = &mut self.menu {
            menu.paste(&text);
            self.mark_dirty();
            return Ok(());
        }
        if let Some(dialog) = &mut self.dialog {
            dialog.paste(&text);
            self.mark_dirty();
            return Ok(());
        }
        if let Some(surface) = &mut self.extension_surface {
            surface.paste(&text);
            self.mark_dirty();
            return Ok(());
        }
        if let Some(search) = &mut self.search {
            search.field.paste(&text);
            self.update_search_filter();
            self.mark_dirty();
            return Ok(());
        }
        if self.focus == Focus::Ai {
            self.handle_ai_paste(&text).await;
            return Ok(());
        }
        if self.focus != Focus::Terminal {
            return Ok(());
        }
        let Some(session) = self
            .active_session
            .and_then(|index| self.sessions.get(index))
        else {
            return Ok(());
        };
        if !session_connected(session) {
            let notice = unsent_input_notice(session, &self.settings.bindings);
            self.notify_info(notice);
            return Ok(());
        }
        let bytes = {
            let view = session.view.lock();
            view.terminal.paste(&text)
        };
        if let Err(error) = self.queue_input(session.id, bytes) {
            self.notify_error(format!("Session paste failed: {error:#}"));
            self.mark_dirty();
        }
        Ok(())
    }

    async fn handle_mouse(&mut self, mouse: MouseEvent) -> Result<()> {
        if self.too_small {
            return self.handle_too_small_mouse(mouse).await;
        }
        if let Some(MouseCapture::Terminal { session_id, button, area }) = self.mouse_capture {
            if mouse.kind == MouseEventKind::Drag(button) || mouse.kind == MouseEventKind::Up(button) {
                if mouse.kind == MouseEventKind::Up(button) {
                    self.mouse_capture = None;
                }
                let area = self.render.terminals.iter()
                    .find(|pane| pane.session_id == session_id)
                    .map_or(area, |pane| pane.inner);
                let mut captured = mouse;
                captured.column = mouse.column.clamp(area.x, area.right().saturating_sub(1));
                captured.row = mouse.row.clamp(area.y, area.bottom().saturating_sub(1));
                self.handle_terminal_mouse(session_id, captured, area);
                return Ok(());
            }
            if matches!(mouse.kind, MouseEventKind::Down(_)) {
                self.mouse_capture = None;
            }
        } else if let Some(gesture) = self.mouse_capture {
            if matches!(gesture, MouseCapture::Ai) {
                if mouse.kind == MouseEventKind::Up(MouseButton::Left) {
                    self.mouse_capture = None;
                }
                self.handle_ai_mouse(mouse).await;
                return Ok(());
            }
            match mouse.kind {
                MouseEventKind::Drag(MouseButton::Left) => {
                    if let MouseCapture::SidebarResize(_) = gesture {
                        let width = sidebar_width(self.render.columns, mouse.column.saturating_add(1), self.render.narrow);
                        self.mouse_capture = Some(MouseCapture::SidebarResize(width));
                        self.mark_dirty();
                    } else if let MouseCapture::AiResize(_) = gesture
                        && let Some(bounds) = self.render.ai_bounds
                    {
                        let width = ai_width(bounds.width, bounds.right().saturating_sub(mouse.column));
                        self.mouse_capture = Some(MouseCapture::AiResize(width));
                        self.mark_dirty();
                    } else if let MouseCapture::PaneResize(mut resize) = gesture {
                        resize.update(mouse.column, mouse.row);
                        self.mouse_capture = Some(MouseCapture::PaneResize(resize));
                        self.mark_dirty();
                    } else if matches!(gesture, MouseCapture::LocalPress)
                        && !matches!(self.mode, InputMode::Prefix { .. })
                        && let Some(menu) = &mut self.menu
                    {
                        let action = menu.mouse(mouse, &self.settings.bindings, self.settings.workspace, &self.state, self.settings.theme);
                        self.handle_menu_action(action).await;
                    }
                    return Ok(());
                }
                MouseEventKind::Up(MouseButton::Left) => {
                    self.mouse_capture = None;
                    if let MouseCapture::SidebarResize(width) = gesture {
                        let workspace = WorkspaceSettings { sidebar_width: width, ..self.settings.workspace };
                        if workspace != self.settings.workspace {
                            match self.save_workspace_preferences(workspace) {
                                Ok(Some(warning)) => self.notify_warning(warning),
                                Ok(None) => {}
                                Err(error) => self.notify_error(format!("Cannot save sidebar width: {error:#}")),
                            }
                        }
                    } else if let MouseCapture::AiResize(width) = gesture {
                        // One save on release; an unchanged width saves nothing.
                        self.handle_ai_action(crate::ui::ai::Action::Resize(width)).await;
                    } else if let MouseCapture::PaneResize(mut resize) = gesture {
                        resize.update(mouse.column, mouse.row);
                        if let Some(sizes) = self.render.pane_layout.resized(resize, &self.settings.terminal_sizes) {
                            match self.settings.save_terminal_sizes(sizes) {
                                Ok(Some(warning)) => self.notify_warning(warning),
                                Ok(None) => {}
                                Err(error) => self.notify_error(format!("Cannot save terminal sizes: {error:#}")),
                            }
                        }
                    } else if matches!(gesture, MouseCapture::LocalPress)
                        && !matches!(self.mode, InputMode::Prefix { .. })
                        && let Some(menu) = &mut self.menu
                    {
                        let action = menu.mouse(mouse, &self.settings.bindings, self.settings.workspace, &self.state, self.settings.theme);
                        self.handle_menu_action(action).await;
                    }
                    self.mark_dirty();
                    return Ok(());
                }
                MouseEventKind::Down(_) => {
                    self.mouse_capture = None;
                    self.mark_dirty();
                }
                _ => return Ok(()),
            }
        }
        if self.quit_confirming && !matches!(self.mode, InputMode::Prefix { .. }) {
            if mouse.kind == MouseEventKind::Down(MouseButton::Left) {
                self.mouse_capture = Some(MouseCapture::LocalPress);
            }
            if let Some(mut dialog) = self.dialog.take() {
                let input = dialog.mouse(mouse, &self.render.form_hits);
                return self.handle_dialog_input(dialog, input).await;
            }
            return Ok(());
        }
        let hit = self.render.hits.iter().rev()
            .find(|hit| contains(hit.area, mouse.column, mouse.row))
            .cloned();
        if mouse.kind == MouseEventKind::Down(MouseButton::Left) {
            // A local press owns its release even if it closes an overlay or changes the layout.
            if matches!(self.mode, InputMode::Prefix { .. })
                || self.menu.is_some() || self.dialog.is_some() || self.search.is_some() || self.extension_surface.is_some()
                || hit.as_ref().is_none_or(|hit| !matches!(&hit.target, HitTarget::Terminal(_)))
            {
                self.mouse_capture = Some(MouseCapture::LocalPress);
            }
            if matches!(hit.as_ref().map(|hit| &hit.target), Some(HitTarget::PrefixToggle)) {
                if matches!(self.mode, InputMode::Prefix { .. }) {
                    self.close_prefix();
                } else if let Some(prefix) = self.settings.bindings.primary_event(Shortcut::Prefix) {
                    self.start_prefix(prefix);
                }
                return Ok(());
            }
            match hit.as_ref().map(|hit| &hit.target) {
                Some(&HitTarget::PrefixCommand(action @ (PrefixAction::Settings | PrefixAction::Shortcuts))) => {
                    if action.applicable(&self.prefix_context()) {
                        self.open_menu(if action == PrefixAction::Settings { MenuMode::Settings } else { MenuMode::Shortcuts });
                    }
                    return Ok(());
                }
                Some(HitTarget::PrefixPanel) => return Ok(()),
                _ => {}
            }
        }
        if matches!(self.mode, InputMode::Prefix { .. }) {
            match mouse.kind {
                MouseEventKind::Down(MouseButton::Left) => {
                    match hit.as_ref().map(|hit| &hit.target) {
                        Some(HitTarget::PrefixCommand(action)) => return self.handle_prefix(*action).await,
                        Some(HitTarget::PrefixPage(delta)) => self.page_prefix(*delta),
                        Some(HitTarget::PrefixPanel) => {}
                        _ => self.close_prefix(),
                    }
                }
                MouseEventKind::ScrollUp => self.page_prefix(-1),
                MouseEventKind::ScrollDown => self.page_prefix(1),
                _ => {}
            }
            return Ok(());
        }
        if let Some(menu) = &mut self.menu {
            let action = menu.mouse(mouse, &self.settings.bindings, self.settings.workspace, &self.state, self.settings.theme);
            self.handle_menu_action(action).await;
            return Ok(());
        }
        if let Some(mut dialog) = self.dialog.take() {
            let input = dialog.mouse(mouse, &self.render.form_hits);
            return self.handle_dialog_input(dialog, input).await;
        }
        if let Some(surface) = &mut self.extension_surface {
            let action = surface.mouse(mouse, &self.settings.bindings);
            self.handle_extension_surface(action).await;
            return Ok(());
        }
        if mouse.kind == MouseEventKind::Down(MouseButton::Left) {
            match hit.as_ref().map(|hit| &hit.target) {
                Some(HitTarget::SidebarToggle) => {
                    self.last_click = None;
                    self.set_sidebar_expanded(self.render.sidebar_divider.is_none());
                    return Ok(());
                }
                Some(HitTarget::SidebarResize) => {
                    self.last_click = None;
                    self.mouse_capture = Some(MouseCapture::SidebarResize(self.settings.workspace.sidebar_width));
                    return Ok(());
                }
                Some(HitTarget::AiResize) => {
                    self.last_click = None;
                    if let (Some(divider), Some(bounds)) = (self.render.ai_divider, self.render.ai_bounds) {
                        self.mouse_capture = Some(MouseCapture::AiResize(bounds.right().saturating_sub(divider.x)));
                    }
                    return Ok(());
                }
                _ => {}
            }
        }
        if self.search.is_some() {
            let target = hit.as_ref().map(|hit| &hit.target);
            match mouse.kind {
                // Search itself, empty sidebar space, and dead space keep the query being typed.
                MouseEventKind::Down(_) if matches!(target, None | Some(HitTarget::Search | HitTarget::SidebarBackground)) => {
                    return Ok(());
                }
                // Any other click keeps the filter, then acts on exactly what was clicked.
                MouseEventKind::Down(_) => self.finish_search(false),
                // The wheel scrolls results or the AI panel without leaving search.
                MouseEventKind::ScrollUp | MouseEventKind::ScrollDown
                    if self.ai_mouse_inside(&mouse)
                        || self.render.sidebar.is_some_and(|area| contains(area, mouse.column, mouse.row)) => {}
                _ => return Ok(()),
            }
        }
        if self.ai_mouse_inside(&mouse) {
            if mouse.kind == MouseEventKind::Down(MouseButton::Left) {
                self.mouse_capture = Some(MouseCapture::Ai);
            }
            self.handle_ai_mouse(mouse).await;
            return Ok(());
        }
        if matches!(
            mouse.kind,
            MouseEventKind::ScrollUp | MouseEventKind::ScrollDown
        ) && self
            .render
            .sidebar
            .is_some_and(|area| contains(area, mouse.column, mouse.row))
        {
            self.catalog
                .move_selection(if mouse.kind == MouseEventKind::ScrollUp {
                    -3
                } else {
                    3
                });
            self.mark_dirty();
            return Ok(());
        }
        let Some(HitRegion { area, target }) = hit else {
            return Ok(());
        };
        match target {
            HitTarget::RenameTab(id) if mouse.kind == MouseEventKind::Down(MouseButton::Left) => {
                self.rename_session(id);
            }
            HitTarget::Tab(id) | HitTarget::RenameTab(id)
                if mouse.kind == MouseEventKind::Down(MouseButton::Right) =>
            {
                self.rename_session(id);
            }
            HitTarget::Sidebar(RowKey::Session(id))
                if mouse.kind == MouseEventKind::Down(MouseButton::Right) =>
            {
                self.catalog.select(&RowKey::Session(id));
                self.focus = Focus::Sidebar;
                self.rename_session(id);
            }
            HitTarget::PaneResize(divider) if mouse.kind == MouseEventKind::Down(MouseButton::Left) => {
                self.last_click = None;
                self.close_prefix();
                self.mouse_capture = Some(MouseCapture::PaneResize(divider.start(mouse.column, mouse.row)));
                self.mark_dirty();
            }
            HitTarget::Search if mouse.kind == MouseEventKind::Down(MouseButton::Left) => {
                self.last_click = None;
                self.start_search();
            }
            HitTarget::ClearFilter if mouse.kind == MouseEventKind::Down(MouseButton::Left) => {
                self.last_click = None;
                self.focus = Focus::Sidebar;
                self.mode = InputMode::Sidebar;
                self.clear_filter();
                self.mark_dirty();
            }
            HitTarget::Sidebar(key) if mouse.kind == MouseEventKind::Down(MouseButton::Left) => {
                let double = self.last_click.as_ref().is_some_and(|(previous, time)| {
                    previous == &key && time.elapsed() <= DOUBLE_CLICK
                });
                self.catalog.select(&key);
                self.focus = Focus::Sidebar;
                self.mode = InputMode::Sidebar;
                self.last_click = Some((key, Instant::now()));
                if double {
                    self.activate_selected().await?;
                    self.last_click = None;
                }
                self.mark_dirty();
            }
            HitTarget::Tab(id) | HitTarget::TabOverflow(id)
                if mouse.kind == MouseEventKind::Down(MouseButton::Left) =>
            {
                // A tab click only focuses; arrangement changes through the Layout control.
                if let Some(index) = self.sessions.iter().position(|session| session.id == id) {
                    self.activate_session(index);
                }
            }
            HitTarget::CycleLayout if mouse.kind == MouseEventKind::Down(MouseButton::Left) => {
                self.cycle_terminal_layout();
            }
            HitTarget::Reconnect(id) if mouse.kind == MouseEventKind::Down(MouseButton::Left) => {
                self.last_click = None;
                if let Err(error) = self.reconnect_session(id) {
                    self.set_dialog(message("Cannot reconnect", error));
                }
            }
            HitTarget::Pane(id) if mouse.kind == MouseEventKind::Down(MouseButton::Left) => {
                if let Some(index) = self.sessions.iter().position(|session| session.id == id) {
                    self.activate_session(index);
                }
            }
            HitTarget::CloseTab(id) if mouse.kind == MouseEventKind::Down(MouseButton::Left) => {
                self.last_click = None;
                self.request_close_session(id).await?;
            }
            HitTarget::SidebarAction { key, action }
                if mouse.kind == MouseEventKind::Down(MouseButton::Left) =>
            {
                self.last_click = None;
                if self.catalog.select(&key) {
                    self.focus = Focus::Sidebar;
                    self.mode = InputMode::Sidebar;
                    self.handle_sidebar(action).await?;
                }
            }
            HitTarget::SidebarBackground
                if mouse.kind == MouseEventKind::Down(MouseButton::Left) =>
            {
                self.last_click = None;
                self.focus = Focus::Sidebar;
                self.mode = InputMode::Sidebar;
                self.mark_dirty();
            }
            HitTarget::Terminal(id) => self.handle_terminal_mouse(id, mouse, area),
            _ => {}
        }
        Ok(())
    }

    /// Below the minimum size only the footer's command controls respond, and among the
    /// commands only Detach, Quit, and Cancel apply. Pointer input never reaches a terminal.
    async fn handle_too_small_mouse(&mut self, mouse: MouseEvent) -> Result<()> {
        self.mouse_capture = None;
        let prefix = matches!(self.mode, InputMode::Prefix { .. });
        match mouse.kind {
            MouseEventKind::Down(MouseButton::Left) => {}
            MouseEventKind::ScrollUp if prefix => {
                self.page_prefix(-1);
                return Ok(());
            }
            MouseEventKind::ScrollDown if prefix => {
                self.page_prefix(1);
                return Ok(());
            }
            _ => return Ok(()),
        }
        let target = self.render.hits.iter().rev()
            .find(|hit| contains(hit.area, mouse.column, mouse.row))
            .map(|hit| hit.target.clone());
        match target {
            Some(HitTarget::PrefixToggle) if prefix => self.close_prefix(),
            Some(HitTarget::PrefixToggle) => {
                if let Some(key) = self.settings.bindings.primary_event(Shortcut::Prefix) {
                    self.start_prefix(key);
                }
            }
            Some(HitTarget::PrefixCommand(action)) if prefix => return self.handle_prefix(action).await,
            Some(HitTarget::PrefixPage(delta)) if prefix => self.page_prefix(delta),
            Some(HitTarget::PrefixPanel) => {}
            _ if prefix => self.close_prefix(),
            _ => {}
        }
        Ok(())
    }

    fn handle_terminal_mouse(&mut self, id: Uuid, mouse: MouseEvent, area: Rect) {
        let Some(index) = self.sessions.iter().position(|session| session.id == id) else {
            return;
        };
        if let MouseEventKind::Down(button) = mouse.kind {
            self.activate_session(index);
            self.mouse_capture = Some(MouseCapture::Terminal { session_id: id, button, area });
        }
        let session = &self.sessions[index];
        let connected = session_connected(session);
        let (bytes, local_scroll) = {
            let mut view = session.view.lock();
            let encoded = connected
                .then(|| view.terminal.mouse(mouse, area))
                .flatten();
            match encoded {
                Some(bytes) => (Some(bytes), false),
                None if mouse.kind == MouseEventKind::ScrollUp => {
                    view.terminal.scroll(3);
                    (None, true)
                }
                None if mouse.kind == MouseEventKind::ScrollDown => {
                    view.terminal.scroll(-3);
                    (None, true)
                }
                None => (None, false),
            }
        };
        if let Some(bytes) = bytes {
            if let Err(error) = self.queue_input(id, bytes) {
                self.notify_error(format!("Session mouse input failed: {error:#}"));
                self.mark_dirty();
            }
        }
        if local_scroll {
            self.mark_dirty();
        }
    }

    async fn send_active(&mut self, bytes: Vec<u8>) -> Result<()> {
        if let Some(session) = self
            .active_session
            .and_then(|index| self.sessions.get(index))
            .filter(|session| session_connected(session))
        {
            if let Err(error) = self.queue_input(session.id, bytes) {
                self.notify_error(format!("Session input failed: {error:#}"));
                self.mark_dirty();
            }
        }
        Ok(())
    }

    /// Every non-AI input path to a session; a run working in that session stops first.
    fn queue_input(&mut self, session_id: Uuid, bytes: Vec<u8>) -> Result<()> {
        let forwarded = !bytes.is_empty();
        if forwarded {
            self.ai_user_input(session_id);
        }
        self.input_queues
            .entry(session_id)
            .or_default()
            .push(bytes)?;
        // Forwarded input lands on the live screen, so leave local history first.
        if forwarded && let Some(session) = self.sessions.iter().find(|session| session.id == session_id) {
            let mut view = session.view.lock();
            if view.terminal.screen().scrollback() > 0 {
                view.terminal.reset_scrollback();
                self.dirty = true;
            }
        }
        self.flush_input();
        Ok(())
    }

    fn flush_input(&mut self) {
        let mut closed = false;
        for session in &self.sessions {
            let Some(queue) = self.input_queues.get_mut(&session.id) else {
                continue;
            };
            while !queue.is_empty() {
                match session.try_input_slot() {
                    Ok(slot) => {
                        slot.send(queue.next_chunk());
                    }
                    Err(mpsc::error::TrySendError::Full(())) => break,
                    Err(mpsc::error::TrySendError::Closed(())) => {
                        *queue = InputQueue::default();
                        closed = true;
                    }
                }
            }
        }
        self.input_queues.retain(|_, queue| !queue.is_empty());
        if closed {
            self.notify_error("Session input transport closed");
        }
    }

    /// Synchronizes when sync is configured; otherwise opens its setup.
    fn request_sync(&mut self) {
        if self.store.is_uncertain() {
            self.notify_warning("Save durability uncertain; Retry save before synchronizing");
        } else if self.state.sync.is_none() {
            self.open_menu(MenuMode::Sync);
        } else {
            self.sync.request(true);
            self.notify_info("Synchronization requested");
            self.update_sync_detail();
        }
    }

    async fn retry_save(&mut self) {
        match self.store.retry_save().await {
            Ok(()) => {
                self.notify_success("Save durability confirmed");
                self.adopt_state(self.store.snapshot());
                self.retry_ai_save().await;
                // Resume configured sync quietly; confirming a local save never opens setup.
                if self.state.sync.is_some() {
                    self.sync.request(true);
                    self.update_sync_detail();
                }
            }
            Err(error) => self.notify_error(format!("Retry save failed: {error:#}")),
        }
    }

    async fn close_session(&mut self, id: Uuid) -> Result<()> {
        self.input_queues.remove(&id);
        self.ai_session_closed(id);
        self.cancel_prompts_for(id);
        let index = self
            .sessions
            .iter()
            .position(|session| session.id == id)
            .context("The session no longer exists")?;
        let mut session = self.sessions.remove(index);
        let close_result = session.close().await;
        self.active_session = match self.active_session {
            None => None,
            Some(_) if self.sessions.is_empty() => None,
            Some(active) if active > index => Some(active - 1),
            Some(active) if active == index => Some(index.min(self.sessions.len() - 1)),
            Some(active) => Some(active),
        };
        if self.sessions.is_empty() && self.focus != Focus::Ai {
            self.focus = Focus::Sidebar;
            self.mode = InputMode::Sidebar;
            self.sidebar_overlay = self.render.narrow;
        }
        self.catalog.invalidate();
        self.notify_info("Session closed");
        close_result
    }

    fn cancel_prompts_for(&mut self, session_id: Uuid) {
        if self.dialog.as_ref().and_then(Dialog::prompt_session) == Some(session_id) {
            if let Some(mut dialog) = self.dialog.take() {
                dialog.cancel_prompt();
            }
            self.restore_focused_mode();
        }
        let mut remaining = VecDeque::with_capacity(self.prompt_queue.len());
        while let Some(request) = self.prompt_queue.pop_front() {
            if request.session_id == session_id {
                let _ = request.response.send(None);
            } else {
                remaining.push_back(request);
            }
        }
        self.prompt_queue = remaining;
    }

    async fn shutdown(&mut self) -> Result<()> {
        let mut first_error = self.shutdown_ai().await.err();
        self.close_extensions();
        self.input_queues.clear();
        self.updates.shutdown().await;
        if let Some(mut dialog) = self.quit_dialog.take() {
            dialog.cancel_prompt();
        }
        if let Some(mut dialog) = self.dialog.take() {
            dialog.cancel_prompt();
        }
        while let Some(request) = self.prompt_queue.pop_front() {
            let _ = request.response.send(None);
        }
        while let Some(mut session) = self.sessions.pop() {
            if let Err(error) = session.close().await {
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
        }
        while let Ok(request) = self.prompts.try_recv() {
            let _ = request.response.send(None);
        }
        if let Err(error) = self.sync.shutdown().await {
            if first_error.is_none() {
                first_error = Some(error);
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

fn saved_host_id(vault: &Vault, name: &str) -> Result<Uuid> {
    let mut matches = vault.hosts.iter().filter(|host| host.label == name);
    let host = matches.next().with_context(|| {
        format!("No saved server named '{name}'. Names are case-sensitive; open vyx to add or rename a server.")
    })?;
    ensure!(
        matches.next().is_none(),
        "More than one saved server is named '{name}'. Rename one in vyx before connecting by name."
    );
    Ok(host.id)
}

fn session_connected(session: &Session) -> bool {
    let view = session.view.lock();
    matches!(&view.phase, SessionPhase::Connected)
}

/// Why input for `session` was reported instead of queued: it is still connecting or has ended.
fn unsent_input_notice(session: &Session, bindings: &Bindings) -> String {
    if session.is_live() {
        return format!("{} is still connecting; input was not sent", session.label);
    }
    match bindings.primary(Shortcut::Reconnect) {
        "" => format!("{} has ended; input was not sent", session.label),
        key => format!("{} has ended; input was not sent. {key} reconnects", session.label),
    }
}

fn counted(count: usize, one: &str, many: &str) -> String {
    format!("{count} {}", if count == 1 { one } else { many })
}

fn refresh_authentication_dialog(dialog: &mut Option<Dialog>, sessions: &[Session]) -> bool {
    let Some(Dialog::AuthenticationNotice { session_id, review, content_start }) = dialog else { return false; };
    if let Some(session) = sessions.iter().find(|session| session.id == *session_id) {
        let view = session.view.lock();
        if let Some(notice) = &view.auth_notice {
            if review.content.get(*content_start..) == Some(notice.text.as_str()) { return false; }
            review.content.truncate(*content_start);
            review.content.push_str(&notice.text);
            return true;
        }
    }
    *dialog = None;
    true
}

/// Keeps a snippet dialog's Insert enabled only while its fixed target is connected.
fn refresh_snippet_target(dialog: &mut Option<Dialog>, sessions: &[Session]) -> bool {
    let Some(Dialog::Snippet(snippet)) = dialog else { return false; };
    let available = snippet.target.is_some_and(|id| {
        sessions.iter().any(|session| session.id == id && session_connected(session))
    });
    std::mem::replace(&mut snippet.available, available) != available
}

async fn wait_for_prompt_cancellation(dialog: &mut Option<Dialog>) {
    let Some(Dialog::Prompt(prompt)) = dialog else {
        pending::<()>().await;
        return;
    };
    loop {
        if *prompt.cancelled.borrow() {
            return;
        }
        if prompt.cancelled.changed().await.is_err() {
            return;
        }
    }
}

fn message(title: &str, error: impl std::fmt::Display) -> Dialog {
    Dialog::message(title, safe_text(&format!("{error:#}")))
}

enum AppEvent {
    Extension(Option<crate::extensions::manager::ManagerEvent>),
    Tailnet(Option<tailscale::NativeEvent>),
    ExtensionDownload(Option<extension_downloads::Event>),
    Ai(Option<ai::Event>),
    Screen(Option<ScreenEvent>),
    Idle,
    Dirty,
    Snapshot,
    Prompt(Option<PromptRequest>),
    SyncTick,
    UpdateChanged,
    PromptCancelled,
    Frame,
    NoticeExpired,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyModifiers};
    use ratatui::{Terminal, backend::TestBackend, buffer::Buffer};
    use crate::vault::{Category, Host, HostAuth, HostTransport, Secret};

    // Encrypted temporary state only; the release monitor stops before it is ever polled.
    async fn fixture() -> (tempfile::TempDir, App) {
        let temporary = tempfile::tempdir().unwrap();
        let directory = Directory::open(temporary.path().join("state")).unwrap();
        let store = directory
            .create(Secret::new("isolated workspace regression passphrase"))
            .await
            .unwrap();
        let settings = Settings::load(directory.path()).unwrap();
        let mut app = App::new(store, settings, directory.path()).await;
        app.updates.shutdown().await;
        app.attached = true;
        (temporary, app)
    }

    /// A saved server on a closed loopback port, so its sessions never reach a server.
    fn server(id: u128, label: &str, category_id: Option<Uuid>) -> Host {
        Host {
            id: Uuid::from_u128(id),
            label: label.to_owned(),
            hostname: "127.0.0.1".to_owned(),
            port: 1,
            transport: HostTransport::Direct,
            category_id,
            auth: HostAuth::Password { username: "fixture".to_owned(), password: Secret::new("fixture-only") },
        }
    }

    async fn save(app: &mut App, edit: impl FnOnce(&mut Vault) + Send + 'static) {
        let state = app.store.commit(true, move |state| {
            edit(&mut state.vault);
            Ok(())
        }).await.unwrap();
        app.adopt_state(state);
        app.rebuild_catalog();
    }

    /// Draws the workspace the way `App::draw` does and refreshes the app's hit regions.
    fn render(app: &mut App, width: u16, height: u16) -> Buffer {
        app.rebuild_catalog();
        let commands = app.prefix_context();
        let state = Arc::clone(&app.state);
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(|frame| {
            draw(frame, RenderRequest {
                catalog: &mut app.catalog,
                state: &state,
                sessions: &app.sessions,
                active_session: app.active_session,
                focus: app.focus,
                prefix: matches!(app.mode, InputMode::Prefix { .. }),
                prefix_page: app.prefix_page,
                commands,
                workspace: app.settings.workspace,
                terminal_sizes: &app.settings.terminal_sizes,
                pane_resize: None,
                sidebar_width: app.settings.workspace.sidebar_width,
                sidebar_overlay: app.sidebar_overlay,
                sync_label: "Local only",
                sync_detail: "",
                notice: app.notice.as_ref(),
                guidance: None,
                update_notice: None,
                uncertain: false,
                dialog: app.dialog.as_mut(),
                search: app.search.as_ref().map(|search| &search.field),
                bindings: &app.settings.bindings,
                theme: app.settings.theme,
                menu: None,
                extension_surface: None,
                unlock_reveal: None,
                ai: None,
                ai_width: None,
            }, &mut app.render);
        }).unwrap();
        terminal.backend().buffer().clone()
    }

    fn text(buffer: &Buffer) -> String {
        let area = buffer.area;
        (area.top()..area.bottom())
            .map(|y| (area.left()..area.right()).map(|x| buffer[(x, y)].symbol()).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn hit(app: &App, wanted: impl Fn(&HitTarget) -> bool) -> Rect {
        app.render.hits.iter().rev().find(|hit| wanted(&hit.target)).expect("the control was drawn").area
    }

    async fn click(app: &mut App, area: Rect) {
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: area.x,
            row: area.y,
            modifiers: KeyModifiers::NONE,
        }).await.unwrap();
    }

    async fn press(app: &mut App, code: KeyCode, modifiers: KeyModifiers) {
        app.handle_key(KeyEvent::new(code, modifiers)).await.unwrap();
    }

    /// One connected session showing `back` lines of local history.
    async fn scrolled_back_session(back: i32) -> (tempfile::TempDir, App) {
        let (temporary, mut app) = fixture().await;
        save(&mut app, |vault| vault.hosts.push(server(1, "first", None))).await;
        app.connect_host(Uuid::from_u128(1), None).unwrap();
        let mut view = app.sessions[0].view.lock();
        view.phase = SessionPhase::Connected;
        for line in 0..100 {
            view.terminal.process(format!("line {line}\r\n").as_bytes());
        }
        view.terminal.scroll(back);
        drop(view);
        (temporary, app)
    }

    fn scrollback(app: &App) -> usize {
        app.sessions[0].view.lock().terminal.screen().scrollback()
    }

    #[tokio::test(flavor = "current_thread")]
    async fn mouse_search_keeps_the_filter_and_acts_on_the_clicked_row() {
        let (_temporary, mut app) = fixture().await;
        let (alpha, beta) = (Uuid::from_u128(1), Uuid::from_u128(2));
        save(&mut app, |vault| vault.hosts.extend([server(1, "alpha-db", None), server(2, "beta-db", None), server(3, "web", None)])).await;
        app.start_search();
        for character in "db".chars() {
            press(&mut app, KeyCode::Char(character), KeyModifiers::NONE).await;
        }
        assert_eq!(app.catalog.selected_key(), Some(RowKey::Host(alpha)), "a changed query selects its first match");
        render(&mut app, 100, 30);
        let row = hit(&app, |target| matches!(target, HitTarget::Sidebar(RowKey::Host(id)) if *id == beta));
        click(&mut app, row).await;
        assert!(app.search.is_none());
        assert_eq!(app.catalog.filter(), "db");
        assert_eq!(app.catalog.selected_key(), Some(RowKey::Host(beta)));
        // The kept filter leaves the rows in place, so clicking again opens that exact server.
        click(&mut app, row).await;
        assert_eq!(app.sessions.iter().map(|session| session.host_id).collect::<Vec<_>>(), [Some(beta)]);
        app.shutdown().await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn clearing_a_kept_filter_restores_rows_and_the_earlier_selection() {
        let (_temporary, mut app) = fixture().await;
        let web = RowKey::Host(Uuid::from_u128(3));
        save(&mut app, |vault| vault.hosts.extend([server(1, "alpha-db", None), server(3, "web", None)])).await;
        for pointer in [false, true] {
            assert!(app.catalog.select(&web));
            press(&mut app, KeyCode::Char('/'), KeyModifiers::NONE).await;
            for character in "db".chars() {
                press(&mut app, KeyCode::Char(character), KeyModifiers::NONE).await;
            }
            press(&mut app, KeyCode::Enter, KeyModifiers::NONE).await;
            assert!(app.search.is_none());
            assert!(!app.catalog.rows().iter().any(|row| row.key == web));
            if pointer {
                // Esc customized for an older action leaves the Clear filter key unbound;
                // the Clear control still works.
                app.settings.bindings = Bindings::default().with_binding(Shortcut::SidebarActivate, "Enter, Esc").unwrap();
                render(&mut app, 100, 30);
                let clear = hit(&app, |target| matches!(target, HitTarget::ClearFilter));
                click(&mut app, clear).await;
            } else {
                press(&mut app, KeyCode::Esc, KeyModifiers::NONE).await;
            }
            assert_eq!(app.catalog.filter(), "");
            assert!(app.catalog.rows().iter().any(|row| row.key == web));
            assert_eq!(app.catalog.selected_key(), Some(web.clone()));
        }
        app.shutdown().await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn saving_a_nested_server_reveals_its_row() {
        let (_temporary, mut app) = fixture().await;
        let (parent, child) = (Uuid::from_u128(10), Uuid::from_u128(11));
        save(&mut app, move |vault| {
            vault.categories.push(Category { id: parent, label: "Parent".into(), parent_id: None });
            vault.categories.push(Category { id: child, label: "Child".into(), parent_id: Some(parent) });
            vault.hosts.push(server(1, "elsewhere", None));
        }).await;
        // Categories start collapsed, and a kept filter hides the destination too.
        app.catalog.set_filter("elsewhere".into());
        app.rebuild_catalog();
        app.commit_mutation(Mutation::PutHost { host: server(12, "nested", Some(child)), create: true }).await.unwrap();
        app.rebuild_catalog();
        let nested = RowKey::Host(Uuid::from_u128(12));
        assert_eq!(app.catalog.filter(), "");
        assert_eq!(app.catalog.selected_key(), Some(nested.clone()));
        let keys: Vec<_> = app.catalog.rows().iter().map(|row| row.key.clone()).collect();
        let position = |key: RowKey| keys.iter().position(|entry| *entry == key).unwrap();
        assert!(position(RowKey::Category(parent)) < position(RowKey::Category(child)));
        assert!(position(RowKey::Category(child)) < position(nested));
        assert!(app.notice.as_ref().is_some_and(|notice| notice.kind == NoticeKind::Success && notice.text.contains("nested")));
        app.shutdown().await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn reconnect_replaces_an_ended_tab_without_adding_one() {
        let (_temporary, mut app) = fixture().await;
        let (first, second) = (Uuid::from_u128(1), Uuid::from_u128(2));
        save(&mut app, |vault| vault.hosts.extend([server(1, "first", None), server(2, "second", None)])).await;
        app.connect_host(first, None).unwrap();
        app.connect_host(second, None).unwrap();
        let ended = app.sessions[0].id;
        app.sessions[0].view.lock().phase = SessionPhase::Closed { status: Some(0), signal: None };
        app.activate_session(0);
        render(&mut app, 120, 40);
        let reconnect = hit(&app, |target| matches!(target, HitTarget::Reconnect(id) if *id == ended));
        click(&mut app, reconnect).await;
        assert_eq!(app.sessions.iter().map(|session| session.host_id).collect::<Vec<_>>(), [Some(first), Some(second)]);
        assert_ne!(app.sessions[0].id, ended);
        assert_eq!(app.active_session, Some(0));
        app.shutdown().await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn layout_control_cycles_arrangement_while_tab_clicks_only_focus() {
        let (_temporary, mut app) = fixture().await;
        save(&mut app, |vault| vault.hosts.extend([server(1, "first", None), server(2, "second", None)])).await;
        app.connect_host(Uuid::from_u128(1), None).unwrap();
        app.connect_host(Uuid::from_u128(2), None).unwrap();
        let focused = app.sessions[1].id;
        render(&mut app, 120, 40);
        assert_eq!(app.render.terminals.len(), 1);
        let tab = hit(&app, |target| matches!(target, HitTarget::Tab(id) if *id == focused));
        click(&mut app, tab).await;
        assert_eq!(app.settings.workspace.terminal_layout, TerminalLayout::Single, "re-clicking the focused tab keeps the layout");
        assert_eq!((app.active_session, app.focus), (Some(1), Focus::Terminal));
        let layout = hit(&app, |target| matches!(target, HitTarget::CycleLayout));
        click(&mut app, layout).await;
        assert_eq!(app.settings.workspace.terminal_layout, TerminalLayout::SideBySide);
        render(&mut app, 120, 40);
        assert_eq!(app.render.terminals.len(), 2);
        app.shutdown().await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn forwarded_typing_returns_from_scrollback_first() {
        let (_temporary, mut app) = scrolled_back_session(10).await;
        assert!(text(&render(&mut app, 120, 40)).contains("Scrollback +10 · type to return"));
        press(&mut app, KeyCode::Char('x'), KeyModifiers::NONE).await;
        assert_eq!(scrollback(&app), 0);
        assert!(!text(&render(&mut app, 120, 40)).contains("Scrollback"));
        app.shutdown().await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_too_small_frame_forwards_no_input_but_still_quits() {
        let (_temporary, mut app) = scrolled_back_session(10).await;
        app.too_small = true;
        press(&mut app, KeyCode::Char('x'), KeyModifiers::NONE).await;
        app.handle_paste("pasted".into()).await.unwrap();
        assert_eq!(scrollback(&app), 10, "nothing was forwarded to the hidden terminal");
        press(&mut app, KeyCode::Char('b'), KeyModifiers::CONTROL).await;
        press(&mut app, KeyCode::Char('q'), KeyModifiers::NONE).await;
        assert!(app.quit_confirming);
        app.shutdown().await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn an_unbound_prefix_chord_closes_the_bar_without_reaching_ssh() {
        let (_temporary, mut app) = scrolled_back_session(10).await;
        press(&mut app, KeyCode::Char('b'), KeyModifiers::CONTROL).await;
        assert!(matches!(app.mode, InputMode::Prefix { .. }));
        press(&mut app, KeyCode::Char('z'), KeyModifiers::NONE).await;
        assert_eq!(app.mode, InputMode::Terminal);
        assert_eq!(scrollback(&app), 10, "the chord was not forwarded");
        assert!(app.notice.as_ref().is_some_and(|notice| notice.text.contains('z')));
        app.shutdown().await.unwrap();
    }

    #[test]
    fn named_connections_require_a_unique_full_label() {
        let primary = Host {
            id: Uuid::from_u128(1),
            label: "rpnation".to_owned(),
            hostname: "example.test".to_owned(),
            port: 22,
            transport: crate::vault::HostTransport::Direct,
            category_id: None,
            auth: crate::vault::HostAuth::Credential { credential_id: Uuid::from_u128(10) },
        };
        let mut vault = Vault::new();
        vault.hosts = vec![
            primary.clone(),
            Host { id: Uuid::from_u128(2), label: "rpnation backup".to_owned(), ..primary.clone() },
        ];
        assert_eq!(saved_host_id(&vault, "rpnation").unwrap(), primary.id);
        assert!(saved_host_id(&vault, "rpn").is_err());
        assert!(saved_host_id(&vault, "RPNation").is_err());
        assert!(saved_host_id(&vault, "example.test").is_err());
        vault.hosts.push(Host { id: Uuid::from_u128(3), ..primary });
        assert!(saved_host_id(&vault, "rpnation").is_err());
    }
}
