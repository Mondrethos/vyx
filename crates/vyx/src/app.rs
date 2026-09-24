use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow};
use crossterm::event::{
    Event, KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
};
use futures_util::future::pending;
use tokio::sync::{Notify, mpsc, watch};
use uuid::Uuid;

use crate::{
    input::{
        Focus, InputMode, InputQueue, PrefixAction, SidebarAction, is_ctrl_b, is_key_input,
        is_local_scrollback, prefix_action, sidebar_action,
    },
    screen::{Screen, safe_text},
    ssh::{PromptRequest, Session, SessionPhase},
    sync::{SyncChoice, SyncController, SyncStatus},
    ui::{
        actions::{
            AddMenu, ConfirmAction, ConfirmDialog, Dialog, DialogInput, Editor, FilterDialog,
            Mutation, SnippetDialog, SyncQuestionDialog, SyncSetupDialog,
        },
        catalog::{Catalog, RowKey, Section, SessionEntry},
        render::{HitRegion, HitTarget, RenderOutput, RenderRequest, contains, draw},
    },
    update::UpdateMonitor,
    vault::{LocalState, Secret, Store},
};

const FRAME_INTERVAL: Duration = Duration::from_millis(34);
const DOUBLE_CLICK: Duration = Duration::from_millis(500);

pub async fn run(screen: &mut Screen, store: Store) -> Result<()> {
    App::run(screen, store).await
}

pub struct App {
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
    mode: InputMode,
    focus: Focus,
    sidebar_visible: bool,
    sidebar_overlay: bool,
    dirty: bool,
    attached: bool,
    attachment_generation: u64,
    detaching: bool,
    last_draw: Instant,
    render: RenderOutput,
    last_terminal_size: Option<(u16, u16)>,
    notice: String,
    sync_detail: String,
    quitting: bool,
    last_click: Option<(RowKey, Instant)>,
}

impl App {
    pub async fn run(screen: &mut Screen, store: Store) -> Result<()> {
        let mut app = Self::new(store);
        app.run_loop(screen).await
    }

    fn new(store: Store) -> Self {
        let state = store.snapshot();
        let snapshots = store.subscribe();
        let dirty_notify = Arc::new(Notify::new());
        let (prompt_sender, prompts) = mpsc::channel(32);
        let mut sync = SyncController::new(store.clone(), Arc::clone(&dirty_notify));
        if !store.is_uncertain() {
            sync.request(false);
        }
        let mut app = Self {
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
            mode: InputMode::Sidebar,
            focus: Focus::Sidebar,
            sidebar_visible: true,
            sidebar_overlay: false,
            dirty: true,
            last_draw: Instant::now() - FRAME_INTERVAL,
            render: RenderOutput::default(),
            last_terminal_size: None,
            notice: "Ctrl+B d detach · Ctrl+B ? help".to_owned(),
            sync_detail: String::new(),
            quitting: false,
            last_click: None,
            attached: false,
            attachment_generation: 0,
            detaching: false,
        };
        app.update_sync_detail();
        app
    }

    async fn run_loop(&mut self, screen: &mut Screen) -> Result<()> {
        self.update_attachment(screen);
        let loop_result: Result<()> = async {
            while !self.quitting {
                self.update_attachment(screen);
                if self.detaching {
                    self.detaching = false;
                    screen.detach();
                    self.set_attached(false);
                    continue;
                }
                self.flush_input();
                self.activate_waiting_dialog();
                if self.attached && self.dirty && self.last_draw.elapsed() >= FRAME_INTERVAL {
                    self.draw(screen).await?;
                    continue;
                }
                match self.next_event(screen).await? {
                    AppEvent::Screen(None) => self.quitting = true,
                    AppEvent::Screen(Some(event)) => self.handle_screen_event(event).await?,
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
        let frame_deadline = self.last_draw + FRAME_INTERVAL;
        let frame_pending = self.attached && self.dirty;
        let Self {
            dirty_notify,
            snapshots,
            prompts,
            sync,
            updates,
            dialog,
            ..
        } = self;
        tokio::select! {
            event = screen.next_event() => Ok(AppEvent::Screen(event?)),
            _ = dirty_notify.notified() => Ok(AppEvent::Dirty),
            changed = snapshots.changed() => {
                changed.map_err(|_| anyhow!("Vault snapshot publisher stopped"))?;
                Ok(AppEvent::Snapshot)
            }
            request = prompts.recv() => Ok(AppEvent::Prompt(request)),
            _ = sync.tick() => Ok(AppEvent::SyncTick),
            _ = updates.changed() => Ok(AppEvent::UpdateChanged),
            _ = wait_for_prompt_cancellation(dialog) => Ok(AppEvent::PromptCancelled),
            _ = tokio::time::sleep_until(frame_deadline.into()), if frame_pending => Ok(AppEvent::Frame),
        }
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
        self.last_click = None;
        if attached {
            for (position, session) in self.sessions.iter().enumerate() {
                session.set_visible(self.active_session == Some(position));
            }
            self.last_draw = Instant::now() - FRAME_INTERVAL;
            self.mark_dirty();
        } else {
            for session in &self.sessions {
                session.set_visible(false);
            }
            if let InputMode::Prefix { previous } = self.mode {
                self.focus = previous;
                self.mode = InputMode::focused(previous);
            }
        }
    }

    async fn draw(&mut self, screen: &mut Screen) -> Result<()> {
        if !self.attached {
            return Ok(());
        }
        let session_entries = self.sessions.iter().map(|session| SessionEntry {
            id: session.id,
            label: &session.label,
        });
        self.catalog.rebuild(&self.state.vault, session_entries);
        let status = self.sync.status();
        let sync_label = status.label().to_owned();
        let state = Arc::clone(&self.state);
        let focus = self.focus;
        let prefix = matches!(self.mode, InputMode::Prefix { .. });
        let sidebar_visible = self.sidebar_visible;
        let sidebar_overlay = self.sidebar_overlay;
        let active_session = self.active_session;
        let notice = self.notice.as_str();
        let sync_detail = self.sync_detail.as_str();
        let update_notice = self.update_notice.as_deref();
        let uncertain = self.store.is_uncertain();
        let dialog = self.dialog.as_ref();
        let sessions = &self.sessions;
        let catalog = &mut self.catalog;
        let mut rendered = None;
        screen
            .draw(|frame| {
                rendered = Some(draw(
                    frame,
                    RenderRequest {
                        catalog: &mut *catalog,
                        state: &state,
                        sessions,
                        active_session,
                        focus,
                        prefix,
                        sidebar_visible,
                        sidebar_overlay,
                        sync_label: &sync_label,
                        sync_detail,
                        notice,
                        update_notice,
                        uncertain,
                        dialog,
                    },
                ));
            })
            .await?;
        self.render = rendered.context("Workspace renderer did not produce a layout")?;
        self.last_draw = Instant::now();
        self.dirty = false;
        if self.render.narrow {
            if !self.sidebar_overlay && self.focus == Focus::Sidebar {
                self.focus = Focus::Terminal;
                self.mode = InputMode::Terminal;
                self.dirty = true;
            }
        } else {
            self.sidebar_overlay = false;
        }
        if let Some(area) = self.render.terminal_inner {
            let size = (area.height.max(1), area.width.max(1));
            if self.last_terminal_size != Some(size) {
                for session in &self.sessions {
                    session.resize(size.0, size.1);
                }
                self.last_terminal_size = Some(size);
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
        if self.dialog.is_some() {
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
        if let Some(question) = self.sync.take_question() {
            self.set_dialog(Dialog::SyncQuestion(SyncQuestionDialog::new(question)));
        }
    }

    fn set_dialog(&mut self, dialog: Dialog) {
        self.dialog = Some(dialog);
        self.mode = InputMode::Modal;
        self.mark_dirty();
    }

    fn restore_focused_mode(&mut self) {
        if self.dialog.is_none() {
            self.mode = InputMode::focused(self.focus);
        }
    }

    async fn handle_screen_event(&mut self, event: Event) -> Result<()> {
        if !matches!(&event, Event::Mouse(_)) {
            self.last_click = None;
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
        if self.dialog.is_some() {
            return self.handle_dialog_key(key).await;
        }
        if let InputMode::Prefix { previous } = self.mode {
            return self.handle_prefix(key, previous).await;
        }
        if is_ctrl_b(key) {
            self.mode = InputMode::Prefix {
                previous: self.focus,
            };
            self.mark_dirty();
            return Ok(());
        }
        if self.store.is_uncertain()
            && key.code == KeyCode::Char('r')
            && key.modifiers == KeyModifiers::NONE
        {
            self.retry_save().await;
            self.mark_dirty();
            return Ok(());
        }
        match self.focus {
            Focus::Sidebar => self.handle_sidebar(sidebar_action(key)).await,
            Focus::Terminal => self.handle_terminal_key(key).await,
        }
    }

    async fn handle_dialog_key(&mut self, key: KeyEvent) -> Result<()> {
        let Some(mut dialog) = self.dialog.take() else {
            return Ok(());
        };
        match dialog.input(key) {
            DialogInput::Continue => self.dialog = Some(dialog),
            DialogInput::Cancel => {
                match &mut dialog {
                    Dialog::Prompt(prompt) => prompt.respond(false),
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
            Dialog::Editor(editor) => match editor.mutation(&self.state.vault).await {
                Ok(mutation) => match self.commit_mutation(mutation).await {
                    Ok(()) => self.restore_focused_mode(),
                    Err(error) if self.store.is_uncertain() => {
                        self.notice = safe_text(&format!("Save durability uncertain: {error:#}"));
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
            Dialog::Filter(filter) => {
                self.catalog.set_filter(filter.form.value(0).to_owned());
                self.restore_focused_mode();
            }
            Dialog::Confirm(confirm) => self.perform_confirm(confirm).await?,
            Dialog::Prompt(mut prompt) => {
                prompt.respond(true);
                self.restore_focused_mode();
            }
            Dialog::Snippet(snippet) => {
                if let Some(target) = snippet.target {
                    match self.insert_snippet(target, &snippet.command).await {
                        Ok(()) => {
                            self.notice = format!("Inserted '{}' without Enter", snippet.command);
                            self.restore_focused_mode();
                        }
                        Err(error) => self.set_dialog(message("Cannot insert snippet", error)),
                    }
                } else {
                    self.dialog = Some(Dialog::Snippet(snippet));
                }
            }
            Dialog::SyncSetup(setup) => {
                let url = setup.form.value(0).trim().to_owned();
                let token = Secret::new(setup.form.value(1));
                match self.sync.configure(url, token).await {
                    Ok(()) => {
                        self.notice = "Sync settings saved".to_owned();
                        self.adopt_state(self.store.snapshot());
                        self.restore_focused_mode();
                    }
                    Err(error) => {
                        let mut dialog = Dialog::SyncSetup(setup);
                        dialog.set_error(format!("{error:#}"));
                        self.dialog = Some(dialog);
                    }
                }
            }
            Dialog::SyncQuestion(question) => {
                self.sync.answer(question.choice());
                self.update_sync_detail();
                self.restore_focused_mode();
            }
            Dialog::Help | Dialog::Message { .. } => self.restore_focused_mode(),
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
                    self.notice = "Synchronization disabled; local vault preserved".to_owned();
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
                self.notice = safe_text(&format!("Save durability uncertain: {error:#}"));
                self.restore_focused_mode();
            }
            Err(error) => {
                self.set_dialog(message("Action failed", error));
            }
        }
        Ok(())
    }

    async fn commit_mutation(&mut self, mutation: Mutation) -> Result<()> {
        let state = self
            .store
            .commit(true, move |state| mutation.apply(state))
            .await?;
        self.notice = "Saved locally".to_owned();
        self.adopt_state(state);
        Ok(())
    }

    async fn handle_prefix(&mut self, key: KeyEvent, previous: Focus) -> Result<()> {
        self.mode = InputMode::focused(previous);
        self.focus = previous;
        match prefix_action(key) {
            PrefixAction::ToggleSidebar => self.toggle_sidebar(),
            PrefixAction::NextSession => self.switch_session(1),
            PrefixAction::PreviousSession => self.switch_session(-1),
            PrefixAction::CloseSession => self.request_close_active().await?,
            PrefixAction::Sync => self.request_sync(),
            PrefixAction::Detach => self.detaching = true,
            PrefixAction::Quit => self.request_quit(),
            PrefixAction::Help => self.set_dialog(Dialog::Help),
            PrefixAction::LiteralPrefix => self.send_active(vec![0x02]).await?,
            PrefixAction::Cancel | PrefixAction::Consume => {}
        }
        self.mark_dirty();
        Ok(())
    }

    fn toggle_sidebar(&mut self) {
        if self.render.narrow {
            self.sidebar_overlay = !self.sidebar_overlay;
            self.focus = if self.sidebar_overlay {
                Focus::Sidebar
            } else {
                Focus::Terminal
            };
        } else if self.sidebar_visible && self.focus == Focus::Sidebar {
            self.sidebar_visible = false;
            self.focus = Focus::Terminal;
        } else if self.sidebar_visible {
            self.focus = Focus::Sidebar;
        } else {
            self.sidebar_visible = true;
            self.focus = Focus::Sidebar;
        }
        self.mode = InputMode::focused(self.focus);
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
        if let Some(current) = self
            .active_session
            .and_then(|index| self.sessions.get(index))
        {
            current.set_visible(false);
        }
        self.active_session = Some(index);
        self.sessions[index].set_visible(self.attached);
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
        let live = self
            .sessions
            .iter()
            .filter(|session| session.is_live())
            .count();
        if live == 0 {
            self.quitting = true;
        } else {
            self.set_dialog(Dialog::Confirm(ConfirmDialog::new(
                "Quit vyx",
                format!("{live} live session(s) will be disconnected. Quit?"),
                "Quit and disconnect",
                ConfirmAction::Quit,
            )));
        }
    }

    async fn handle_sidebar(&mut self, action: SidebarAction) -> Result<()> {
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
            SidebarAction::Filter => {
                self.set_dialog(Dialog::Filter(FilterDialog::new(self.catalog.filter())))
            }
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

    async fn activate_selected(&mut self) -> Result<()> {
        match self.catalog.selected_key() {
            Some(RowKey::Section(Section::Sync)) | Some(RowKey::Sync) => self.open_sync_setup(),
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
                if let Err(error) = self.connect_host(id) {
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

    fn edit_selected(&mut self) {
        let dialog = match self.catalog.selected_key() {
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
                self.open_sync_setup();
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
                    .filter(|host| host.credential_id == id)
                    .map(|host| host.label.as_str())
                    .collect();
                if !references.is_empty() {
                    self.set_dialog(Dialog::Message {
                        title: "Credential is in use".to_owned(),
                        body: format!(
                            "'{}' is used by: {}. Reassign those servers before deleting it.",
                            credential.label,
                            references.join(", ")
                        ),
                    });
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
        let trusted = self.state.vault.known_hosts.iter().any(|known| {
            known.port == host.port && known.hostname.eq_ignore_ascii_case(&host.hostname)
        });
        if !trusted {
            self.set_dialog(Dialog::Message {
                title: "No saved key".to_owned(),
                body: "This server has no trusted host key to forget.".to_owned(),
            });
            return;
        }
        self.set_dialog(Dialog::Confirm(ConfirmDialog::new(
            "Forget trusted key",
            format!("Forget the trusted key for {}:{}? The next connection must present and receive approval for a fresh key.", host.hostname, host.port),
            "Forget key",
            ConfirmAction::ForgetHostKey { hostname: host.hostname.clone(), port: host.port },
        )));
    }

    fn open_sync_setup(&mut self) {
        let (url, token) = self
            .state
            .sync
            .as_ref()
            .map(|sync| (sync.url.as_str(), sync.token.expose()))
            .unwrap_or(("", ""));
        self.set_dialog(Dialog::SyncSetup(SyncSetupDialog::new(url, token)));
    }

    fn connect_host(&mut self, id: Uuid) -> Result<()> {
        let host = self
            .state
            .vault
            .hosts
            .iter()
            .find(|host| host.id == id)
            .cloned()
            .context("The selected server no longer exists")?;
        let credential = self
            .state
            .vault
            .credentials
            .iter()
            .find(|credential| credential.id == host.credential_id)
            .cloned()
            .context("The selected server's credential no longer exists")?;
        let (rows, columns) = self.last_terminal_size.unwrap_or((24, 80));
        if let Some(active) = self
            .active_session
            .and_then(|index| self.sessions.get(index))
        {
            active.set_visible(false);
        }
        let session = Session::connect(
            host,
            credential,
            self.store.clone(),
            rows.max(1),
            columns.max(1),
            self.prompt_sender.clone(),
            Arc::clone(&self.dirty_notify),
        );
        session.set_visible(self.attached);
        self.sessions.push(session);
        self.active_session = Some(self.sessions.len() - 1);
        self.catalog.invalidate();
        self.focus = Focus::Terminal;
        self.mode = InputMode::Terminal;
        self.sidebar_overlay = false;
        self.notice = "Ctrl+B d detach · Ctrl+B ? help".to_owned();
        self.mark_dirty();
        Ok(())
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
        self.set_dialog(Dialog::Snippet(SnippetDialog {
            command: snippet.command.clone(),
            target: target.map(|session| session.id),
            target_label: target
                .map(|session| session.label.clone())
                .unwrap_or_default(),
        }));
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

    async fn handle_terminal_key(&mut self, key: KeyEvent) -> Result<()> {
        if key.code == KeyCode::Char('r') {
            if let Some(index) = self.active_session {
                if self
                    .sessions
                    .get(index)
                    .is_some_and(|session| !session.is_live())
                {
                    let host_id = self.sessions[index].host_id;
                    match self.connect_host(host_id) {
                        Ok(()) => return Ok(()),
                        Err(error) => {
                            self.set_dialog(message("Cannot reconnect", error));
                            return Ok(());
                        }
                    }
                }
            }
        }
        let Some(index) = self.active_session else {
            return Ok(());
        };
        let Some(session) = self.sessions.get(index) else {
            return Ok(());
        };
        if let Some(delta) = is_local_scrollback(key) {
            let mut view = session.view.lock();
            view.terminal.scroll(delta);
            drop(view);
            self.mark_dirty();
            return Ok(());
        }
        if !session_connected(session) {
            return Ok(());
        }
        let bytes = {
            let view = session.view.lock();
            view.terminal.key(key)
        };
        if let Some(bytes) = bytes {
            if let Err(error) = self.queue_input(session.id, bytes) {
                self.notice = safe_text(&format!("Session input failed: {error:#}"));
                self.mark_dirty();
            }
        }
        Ok(())
    }

    async fn handle_paste(&mut self, text: String) -> Result<()> {
        if let Some(dialog) = &mut self.dialog {
            dialog.paste(&text);
            self.mark_dirty();
            return Ok(());
        }
        if self.focus != Focus::Terminal {
            return Ok(());
        }
        let Some(session) = self
            .active_session
            .and_then(|index| self.sessions.get(index))
            .filter(|session| session_connected(session))
        else {
            return Ok(());
        };
        let bytes = {
            let view = session.view.lock();
            view.terminal.paste(&text)
        };
        if let Err(error) = self.queue_input(session.id, bytes) {
            self.notice = safe_text(&format!("Session paste failed: {error:#}"));
            self.mark_dirty();
        }
        Ok(())
    }

    async fn handle_mouse(&mut self, mouse: MouseEvent) -> Result<()> {
        if self.dialog.is_some() {
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
        let target = self
            .render
            .hits
            .iter()
            .rev()
            .find(|hit| contains(hit.area, mouse.column, mouse.row))
            .cloned();
        let Some(HitRegion { area, target }) = target else {
            return Ok(());
        };
        match target {
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
            HitTarget::Tab(id) if mouse.kind == MouseEventKind::Down(MouseButton::Left) => {
                if let Some(index) = self.sessions.iter().position(|session| session.id == id) {
                    self.activate_session(index);
                }
            }
            HitTarget::CloseTab(id) if mouse.kind == MouseEventKind::Down(MouseButton::Left) => {
                self.last_click = None;
                self.request_close_session(id).await?;
            }
            HitTarget::Detach if mouse.kind == MouseEventKind::Down(MouseButton::Left) => {
                self.last_click = None;
                self.detaching = true;
            }
            HitTarget::Quit if mouse.kind == MouseEventKind::Down(MouseButton::Left) => {
                self.last_click = None;
                self.request_quit();
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
            HitTarget::Terminal => {
                self.focus = Focus::Terminal;
                self.mode = InputMode::Terminal;
                self.sidebar_overlay = false;
                let Some(session) = self
                    .active_session
                    .and_then(|index| self.sessions.get(index))
                else {
                    return Ok(());
                };
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
                    if let Err(error) = self.queue_input(session.id, bytes) {
                        self.notice = safe_text(&format!("Session mouse input failed: {error:#}"));
                        self.mark_dirty();
                    }
                }
                if local_scroll {
                    self.mark_dirty();
                }
            }
            _ => {}
        }
        Ok(())
    }

    async fn send_active(&mut self, bytes: Vec<u8>) -> Result<()> {
        if let Some(session) = self
            .active_session
            .and_then(|index| self.sessions.get(index))
            .filter(|session| session_connected(session))
        {
            if let Err(error) = self.queue_input(session.id, bytes) {
                self.notice = safe_text(&format!("Session input failed: {error:#}"));
                self.mark_dirty();
            }
        }
        Ok(())
    }

    fn queue_input(&mut self, session_id: Uuid, bytes: Vec<u8>) -> Result<()> {
        self.input_queues
            .entry(session_id)
            .or_default()
            .push(bytes)?;
        self.flush_input();
        Ok(())
    }

    fn flush_input(&mut self) {
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
                        self.notice = "Session input transport closed".to_owned();
                        self.dirty = true;
                    }
                }
            }
        }
        self.input_queues.retain(|_, queue| !queue.is_empty());
    }

    fn request_sync(&mut self) {
        if self.store.is_uncertain() {
            self.notice = "Save durability uncertain; Retry save before synchronizing".to_owned();
        } else {
            self.sync.request(true);
            self.notice = "Synchronization requested".to_owned();
            self.update_sync_detail();
        }
    }

    async fn retry_save(&mut self) {
        match self.store.retry_save().await {
            Ok(()) => {
                self.notice = "Save durability confirmed".to_owned();
                self.adopt_state(self.store.snapshot());
                self.request_sync();
            }
            Err(error) => self.notice = safe_text(&format!("Retry save failed: {error:#}")),
        }
    }

    async fn close_session(&mut self, id: Uuid) -> Result<()> {
        self.input_queues.remove(&id);
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
        for (position, session) in self.sessions.iter().enumerate() {
            session.set_visible(self.attached && self.active_session == Some(position));
        }
        if self.sessions.is_empty() {
            self.focus = Focus::Sidebar;
            self.mode = InputMode::Sidebar;
            self.sidebar_visible = true;
            self.sidebar_overlay = self.render.narrow;
        }
        self.catalog.invalidate();
        self.notice = "Session closed".to_owned();
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
        self.input_queues.clear();
        self.updates.shutdown().await;
        if let Some(mut dialog) = self.dialog.take() {
            dialog.cancel_prompt();
        }
        while let Some(request) = self.prompt_queue.pop_front() {
            let _ = request.response.send(None);
        }
        let mut first_error = None;
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

fn session_connected(session: &Session) -> bool {
    let view = session.view.lock();
    matches!(&view.phase, SessionPhase::Connected)
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
    Dialog::Message {
        title: title.to_owned(),
        body: safe_text(&format!("{error:#}")),
    }
}

enum AppEvent {
    Screen(Option<Event>),
    Dirty,
    Snapshot,
    Prompt(Option<PromptRequest>),
    SyncTick,
    UpdateChanged,
    PromptCancelled,
    Frame,
}
