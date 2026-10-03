use std::path::PathBuf;
use crossterm::event::{KeyEvent, MouseButton, MouseEvent, MouseEventKind};
use ratatui::{
    Frame,
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Paragraph, Wrap},
};

use crate::{
    extensions::distribution::CatalogEntry,
    screen::safe_text,
    settings::{IconMode, LockSessions, Motion, SecuritySettings, TerminalLayout, WorkspaceSettings},
    shortcuts::{Bindings, Shortcut},
    theme::{Palette, Theme, THEMES},
    ui::{
        actions::SyncSetupDialog,
        form::{Action as FormAction, Field, Form, FormHitRegion},
        extensions::{ExtensionEntry, ExtensionsMenu, ManagementAction, ManagementResult},
        icons::Icon,
        render::contains,
        security::{SecurityAction, SecurityMenu},
        setup::{SetupAction, SetupEntry, SetupWizard},
        shortcuts::{ShortcutAction, ShortcutMenu, ShortcutMode},
        themes::{ThemeAction, ThemeMenu},
        theming::clear,
        widgets::{Button, Notice, draw_buttons, keyed_captions},
    },
    vault::{LocalState, Secret},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MenuMode {
    Shortcuts,
    Settings,
    Sync,
    SetupCreated,
}

pub enum MenuAction {
    None,
    Close,
    SaveBindings(Bindings),
    SaveWorkspace(WorkspaceSettings),
    SaveTheme(&'static Theme),
    SaveSecurity(SecuritySettings),
    SaveTailscaleCliPath(Option<PathBuf>),
    ChangePassphrase { current: Secret, new: Secret },
    SaveRecoveryFile { current: Secret, destination: PathBuf },
    ConfigureSync { url: String, token: Secret },
    Extension(ManagementAction),
    /// Open the native Vyx AI settings for the installed reserved package.
    OpenAi,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Section {
    Workspace,
    Themes,
    Security,
    Shortcuts,
    Sync,
    Tailscale,
    Setup,
    Extensions,
}

impl Section {
    /// Enabled extension packages follow as children of the last section.
    const ALL: [Self; 8] = [Self::Workspace, Self::Themes, Self::Security, Self::Shortcuts, Self::Sync, Self::Tailscale, Self::Setup, Self::Extensions];

    fn title(self) -> &'static str {
        match self {
            Self::Workspace => "Workspace",
            Self::Themes => "Themes",
            Self::Security => "Security",
            Self::Shortcuts => "Keyboard shortcuts",
            Self::Sync => "Vault synchronization",
            Self::Setup => "Setup wizard",
            Self::Extensions => "Extensions",
            Self::Tailscale => "Tailscale transport",
        }
    }

    fn icon(self) -> Icon {
        match self {
            Self::Workspace => Icon::Workspace,
            Self::Themes => Icon::Theme,
            Self::Security => Icon::Security,
            Self::Shortcuts => Icon::Shortcuts,
            Self::Sync => Icon::Sync,
            Self::Setup => Icon::Settings,
            Self::Extensions => Icon::Folder,
            Self::Tailscale => Icon::Settings,
        }
    }

    fn description(self) -> &'static str {
        match self {
            Self::Workspace => {
                "Set the sidebar width and arrange terminal panes without reconnecting SSH."
            }
            Self::Themes => {
                "Choose a dark or light Tinted palette. Preview first, then apply it to the app and SSH terminals."
            }
            Self::Security => {
                "Change a local vault passphrase. Set an idle timeout and choose whether locking disconnects SSH sessions."
            }
            Self::Shortcuts => {
                "Review, customize, and reset the keyboard bindings used throughout Vyx."
            }
            Self::Sync => {
                "Connect this encrypted vault to a synchronization server."
            }
            Self::Setup => "Review storage, recovery protection, and getting started without resetting your vault.",
            Self::Extensions => "Browse GitHub release catalogs, install packages, review permissions, manage development packages and inspect diagnostics.",
            Self::Tailscale => "Choose the local Tailscale executable. This setting is not synchronized and never changes your tailnet.",
        }
    }
}

#[derive(Clone, Copy)]
enum RootTarget {
    Section(usize),
    Open,
    Close,
}

#[derive(Clone, Copy)]
struct RootHit {
    area: Rect,
    target: RootTarget,
}

/// What going back from the focused page does, for the shell's footer hint.
enum PageKind {
    /// Unsaved form values that going back discards.
    Draft,
    /// The setup guide: going back returns one step; leaving the section discards it.
    Guide,
    /// Actions save as they happen; going back with this key loses nothing.
    Immediate(Shortcut),
}

struct WorkspaceEditor {
    form: Form,
    hits: Vec<FormHitRegion>,
}

impl WorkspaceEditor {
    fn new(workspace: WorkspaceSettings) -> Self {
        let layout_choice = TerminalLayout::ALL
            .iter()
            .position(|layout| *layout == workspace.terminal_layout)
            .unwrap_or_default();
        let mut form = Form::new(
            "Settings / Workspace",
            vec![
                Field::text("Sidebar width", workspace.sidebar_width.to_string())
                    .with_hint("Width in terminal columns (20–80)."),
                Field::inline(
                    "Sidebar state",
                    vec!["Expanded".to_owned(), "Collapsed".to_owned()],
                    usize::from(workspace.sidebar_collapsed),
                ).with_hint("Collapse the sidebar to leave more room for terminals."),
                Field::inline(
                    "Terminal layout",
                    TerminalLayout::ALL
                        .iter()
                        .map(|layout| layout.label().to_owned())
                        .collect(),
                    layout_choice,
                )
                .with_hint(
                    "Single, split, or grid panes. Drag pane dividers to resize.",
                ),
                Field::inline(
                    "Icons",
                    IconMode::ALL.iter().map(|mode| mode.label().to_owned()).collect(),
                    usize::from(workspace.icon_mode == IconMode::NerdFont),
                )
                .with_hint("Codicons needs an icon font. Plain works in every terminal."),
                Field::inline(
                    "Animation",
                    Motion::ALL.iter().map(|motion| motion.label().to_owned()).collect(),
                    Motion::ALL.iter().position(|motion| *motion == workspace.motion).unwrap_or_default(),
                ).with_hint("Reduce or disable motion without changing the layout."),
            ],
        );
        form.description =
            "Arrange your workspace without reconnecting SSH. Save applies changes; Discard returns to the sections without them.".to_owned();
        form.submit = "Save workspace".to_owned();
        form.cancel = "Discard".to_owned();
        Self {
            form,
            hits: Vec::new(),
        }
    }

    fn candidate(&mut self) -> Option<WorkspaceSettings> {
        let width = match self.form.value(0).trim().parse::<u16>() {
            Ok(width) => width,
            Err(_) => {
                self.form.error = "Sidebar width must be a whole number.".to_owned();
                return None;
            }
        };
        let terminal_layout = match TerminalLayout::ALL
            .get(self.form.fields[2].choice)
            .copied()
        {
            Some(layout) => layout,
            None => {
                self.form.error = "Choose a valid terminal layout.".to_owned();
                return None;
            }
        };
        let candidate = WorkspaceSettings {
            sidebar_width: width,
            sidebar_collapsed: self.form.fields[1].choice == 1,
            terminal_layout,
            icon_mode: IconMode::ALL[self.form.fields[3].choice],
            motion: Motion::ALL[self.form.fields[4].choice],
        };
        if let Err(error) = candidate.validate() {
            self.form.error = safe_text(&format!("{error:#}"));
            return None;
        }
        Some(candidate)
    }
}

struct TailscaleEditor {
    form: Form,
    hits: Vec<FormHitRegion>,
}

impl TailscaleEditor {
    fn new(path: Option<&std::path::Path>) -> Self {
        let selected = match crate::tailscale::Adapter::discover(path) {
            Ok(adapter) => format!("Selected executable: {}", safe_text(&adapter.path().display().to_string())),
            Err(error) => error.to_string(),
        };
        let mut form = Form::new("Settings / Tailscale transport", vec![
            Field::text("CLI executable override", path.map(|path| path.display().to_string()).unwrap_or_default())
                .with_hint("Absolute executable path. Leave blank to discover Tailscale from PATH."),
        ]);
        form.description = format!("{selected}\nLocal setting only. Older Vyx settings readers cannot load a configured override; clear it before downgrading.");
        form.submit = "Save Tailscale settings".to_owned();
        form.cancel = "Discard".to_owned();
        Self { form, hits: Vec::new() }
    }

    fn candidate(&mut self) -> MenuAction {
        let value = self.form.value(0).trim();
        let path = (!value.is_empty()).then(|| PathBuf::from(value));
        if let Some(path) = &path {
            if let Err(error) = crate::tailscale::Adapter::discover(Some(path)) {
                self.form.error = error.to_string();
                return MenuAction::None;
            }
        }
        MenuAction::SaveTailscaleCliPath(path)
    }
}

struct SyncEditor {
    dialog: SyncSetupDialog,
    hits: Vec<FormHitRegion>,
}

impl SyncEditor {
    fn new(state: &LocalState) -> Self {
        let (url, token) = state
            .sync
            .as_ref()
            .map_or(("", ""), |sync| (sync.url.as_str(), sync.token.expose()));
        let mut dialog = SyncSetupDialog::new(url, token);
        dialog.form.cancel = "Discard".to_owned();
        Self { dialog, hits: Vec::new() }
    }

    fn candidate(&self) -> MenuAction {
        MenuAction::ConfigureSync {
            url: self.dialog.form.value(0).trim().to_owned(),
            token: Secret::new(self.dialog.form.value(1)),
        }
    }
}

enum Page {
    Root,
    Workspace(WorkspaceEditor),
    Themes(ThemeMenu),
    Security(SecurityMenu),
    Shortcuts(ShortcutMenu),
    Sync(SyncEditor),
    Setup(SetupWizard),
    Extensions(ExtensionsMenu),
    Tailscale(TailscaleEditor),
}

pub struct WorkspaceMenu {
    page: Page,
    selected: usize,
    // Inactive sections retain drafts, except Setup; Back discards the active section.
    cached: [Option<Page>; Section::ALL.len()],
    editing: bool,
    wide: bool,
    standalone: bool,
    navigation: Rect,
    content: Rect,
    security: SecuritySettings,
    notice: Option<Notice>,
    hits: Vec<RootHit>,
    area: Rect,
    navigation_offset: usize,
    extensions: Vec<ExtensionEntry>,
    tailscale_cli_path: Option<PathBuf>,
}

impl WorkspaceMenu {
    pub fn new(mode: MenuMode, security: SecuritySettings, state: &LocalState) -> Self {
        let (page, selected) = match mode {
            MenuMode::Shortcuts => (
                Page::Shortcuts(ShortcutMenu::new(ShortcutMode::Reference)),
                Section::Shortcuts as usize,
            ),
            MenuMode::Settings => (Page::Root, 0),
            MenuMode::Sync => (Page::Sync(SyncEditor::new(state)), Section::Sync as usize),
            MenuMode::SetupCreated => (
                Page::Setup(SetupWizard::new(SetupEntry::Created, state.sync.is_none())),
                Section::Setup as usize,
            ),
        };
        Self {
            page,
            selected,
            cached: std::array::from_fn(|_| None),
            editing: mode != MenuMode::Settings,
            wide: false,
            standalone: matches!(mode, MenuMode::Shortcuts | MenuMode::SetupCreated),
            navigation: Rect::default(),
            content: Rect::default(),
            security,
            notice: None,
            hits: Vec::new(),
            area: Rect::default(),
            navigation_offset: 0,
            extensions: Vec::new(),
            tailscale_cli_path: None,
        }
    }

    pub fn set_extensions(&mut self, entries: Vec<ExtensionEntry>) {
        if let Page::Extensions(menu) = &mut self.page { menu.set_entries(entries.clone()); }
        if let Some(Page::Extensions(menu)) = &mut self.cached[Section::Extensions as usize] { menu.set_entries(entries.clone()); }
        let previous = std::mem::replace(&mut self.extensions, entries);
        // Selection follows the package, never its old position.
        let selected = self.selected.checked_sub(Section::ALL.len()).and_then(|index| children(&previous).nth(index));
        if let Some(entry) = selected {
            match self.child_index(&entry.manifest.id) {
                Some(index) => self.selected = index,
                None => {
                    // Its open page now manages the package from Extensions: the detail
                    // while installed, otherwise the list. Compact navigation keeps
                    // showing the sections.
                    self.selected = Section::Extensions as usize;
                    if let Page::Extensions(menu) = &mut self.page {
                        menu.release();
                        self.cached[Section::Extensions as usize] = None;
                    }
                }
            }
        }
        // Root hits address children by position; any change in the enabled sequence stales them.
        if !children(&previous).map(|entry| &entry.manifest.id).eq(children(&self.extensions).map(|entry| &entry.manifest.id)) {
            self.hits.clear();
        }
    }

    /// Opens a package's Settings page: its child while enabled, otherwise its detail
    /// under Extensions. An unknown ID opens the Extensions list.
    pub fn show_extension(&mut self, id: &str) {
        let previous = self.selected;
        let child = self.child_index(id);
        self.selected = child.unwrap_or(Section::Extensions as usize);
        self.switch_section(previous);
        let entries = self.extensions.clone();
        let menu = if child.is_some() { ExtensionsMenu::for_entry(entries, id) }
            else if self.extensions.iter().any(|entry| entry.manifest.id == id) { ExtensionsMenu::manage(entries, id) }
            else { ExtensionsMenu::new(entries) };
        self.page = Page::Extensions(menu);
        self.editing = true;
        self.hits.clear();
    }

    fn child(&self, index: usize) -> Option<&ExtensionEntry> {
        index.checked_sub(Section::ALL.len()).and_then(|index| children(&self.extensions).nth(index))
    }

    fn child_index(&self, id: &str) -> Option<usize> {
        children(&self.extensions).position(|entry| entry.manifest.id == id).map(|index| Section::ALL.len() + index)
    }

    fn section_count(&self) -> usize { Section::ALL.len() + children(&self.extensions).count() }

    fn section_row(index: usize) -> usize { index + usize::from(index >= Section::Extensions as usize) }

    pub fn is_extensions(&self) -> bool {
        self.editing && matches!(self.page, Page::Extensions(_))
    }

    pub fn set_extension_catalog(&mut self, repository: String, entries: Vec<CatalogEntry>) {
        if let Page::Extensions(menu) = &mut self.page { menu.set_catalog(repository, entries); }
    }

    pub fn set_extension_loading(&mut self, message: String) {
        if let Page::Extensions(menu) = &mut self.page { menu.set_loading(message); }
    }

    /// Extension feedback for the open Extensions page, otherwise for the menu.
    pub fn set_extension_notice(&mut self, notice: Notice) {
        match &mut self.page {
            Page::Extensions(menu) => menu.set_notice(notice),
            _ => self.notice = Some(notice),
        }
    }

    pub fn set_tailscale_cli_path(&mut self, path: Option<PathBuf>) {
        self.tailscale_cli_path = path;
        if let Page::Tailscale(editor) = &mut self.page {
            *editor = TailscaleEditor::new(self.tailscale_cli_path.as_deref());
        }
        self.cached[Section::Tailscale as usize] = None;
    }

    pub fn key(
        &mut self,
        key: KeyEvent,
        bindings: &Bindings,
        workspace: WorkspaceSettings,
        state: &LocalState,
        theme: &'static Theme,
    ) -> MenuAction {
        if !self.editing {
            return self.root_key(key, bindings, workspace, state, theme);
        }
        // A Saved or error notice describes the previous action; any input on the page
        // makes it stale.
        self.notice = None;
        let mut back = false;
        let action = match &mut self.page {
            Page::Root => unreachable!(),
            Page::Tailscale(editor) => match editor.form.key(key, bindings) {
                FormAction::Continue => MenuAction::None,
                FormAction::Submit => editor.candidate(),
                FormAction::Cancel => { back = true; MenuAction::None },
            },
            Page::Extensions(menu) => match menu.key(key, bindings) {
                ManagementResult::None => MenuAction::None,
                ManagementResult::Back => { back = true; MenuAction::None },
                ManagementResult::OpenAi => MenuAction::OpenAi,
                ManagementResult::Action(action) => MenuAction::Extension(action),
            },
            Page::Workspace(editor) => match editor.form.key(key, bindings) {
                FormAction::Continue => MenuAction::None,
                FormAction::Submit => editor
                    .candidate()
                    .map_or(MenuAction::None, MenuAction::SaveWorkspace),
                FormAction::Cancel => {
                    back = true;
                    MenuAction::None
                }
            },
            Page::Themes(menu) => match menu.key(key, bindings, theme) {
                ThemeAction::None => MenuAction::None,
                ThemeAction::Apply(theme) => MenuAction::SaveTheme(theme),
                ThemeAction::Back => {
                    back = true;
                    MenuAction::None
                }
            },
            Page::Security(menu) => match menu.key(key, bindings) {
                SecurityAction::None => MenuAction::None,
                SecurityAction::Save(settings) => MenuAction::SaveSecurity(settings),
                SecurityAction::ChangePassphrase { current, new } => MenuAction::ChangePassphrase { current, new },
                SecurityAction::SaveRecoveryFile { current, destination } => MenuAction::SaveRecoveryFile { current, destination },
                SecurityAction::Back => {
                    back = true;
                    MenuAction::None
                }
            },
            Page::Setup(menu) => match menu.key(key, bindings) {
                SetupAction::None => MenuAction::None,
                SetupAction::Close => MenuAction::Close,
                SetupAction::SaveRecoveryFile { current, destination } => MenuAction::SaveRecoveryFile { current, destination },
                SetupAction::Back => { back = true; MenuAction::None }
            },
            Page::Shortcuts(menu) => {
                let editing = menu.is_editing();
                match menu.key(key, bindings) {
                    ShortcutAction::None => MenuAction::None,
                    ShortcutAction::Close if editing || menu.is_editing() => {
                        back = true;
                        MenuAction::None
                    }
                    ShortcutAction::Close => MenuAction::Close,
                    ShortcutAction::Save(candidate) => MenuAction::SaveBindings(candidate),
                }
            }
            Page::Sync(editor) => match editor.dialog.form.key(key, bindings) {
                FormAction::Continue => MenuAction::None,
                FormAction::Submit => editor.candidate(),
                FormAction::Cancel => {
                    back = true;
                    MenuAction::None
                }
            },
        };
        if back {
            self.back_to_root();
        }
        action
    }

    pub fn mouse(
        &mut self,
        mouse: MouseEvent,
        bindings: &Bindings,
        workspace: WorkspaceSettings,
        state: &LocalState,
        theme: &'static Theme,
    ) -> MenuAction {
        if self.wide {
            if contains(self.navigation, mouse.column, mouse.row)
                || self.hits.iter().any(|hit| contains(hit.area, mouse.column, mouse.row))
            {
                return self.root_mouse(mouse, workspace, state, theme);
            }
            if contains(self.content, mouse.column, mouse.row) {
                if mouse.kind == MouseEventKind::Down(MouseButton::Left) {
                    self.editing = true;
                }
            } else if !self.editing {
                return MenuAction::None;
            }
        } else if !self.editing {
            return self.root_mouse(mouse, workspace, state, theme);
        }
        if matches!(mouse.kind, MouseEventKind::Down(_) | MouseEventKind::ScrollUp | MouseEventKind::ScrollDown) {
            self.notice = None;
        }
        // Several input events can arrive before the newly selected pane is drawn.
        self.ensure_page(workspace, state, theme);
        let mut back = false;
        let action = match &mut self.page {
            Page::Root => unreachable!(),
            Page::Tailscale(editor) => match editor.form.mouse(mouse, &editor.hits) {
                FormAction::Continue => MenuAction::None,
                FormAction::Submit => editor.candidate(),
                FormAction::Cancel => { back = true; MenuAction::None },
            },
            Page::Extensions(menu) => match menu.mouse(mouse, bindings) {
                ManagementResult::None => MenuAction::None,
                ManagementResult::Back => { back = true; MenuAction::None },
                ManagementResult::OpenAi => MenuAction::OpenAi,
                ManagementResult::Action(action) => MenuAction::Extension(action),
            },
            Page::Workspace(editor) => match editor.form.mouse(mouse, &editor.hits) {
                FormAction::Continue => MenuAction::None,
                FormAction::Submit => editor
                    .candidate()
                    .map_or(MenuAction::None, MenuAction::SaveWorkspace),
                FormAction::Cancel => {
                    back = true;
                    MenuAction::None
                }
            },
            Page::Themes(menu) => match menu.mouse(mouse, theme) {
                ThemeAction::None => MenuAction::None,
                ThemeAction::Apply(theme) => MenuAction::SaveTheme(theme),
                ThemeAction::Back => {
                    back = true;
                    MenuAction::None
                }
            },
            Page::Security(menu) => match menu.mouse(mouse) {
                SecurityAction::None => MenuAction::None,
                SecurityAction::Save(settings) => MenuAction::SaveSecurity(settings),
                SecurityAction::ChangePassphrase { current, new } => MenuAction::ChangePassphrase { current, new },
                SecurityAction::SaveRecoveryFile { current, destination } => MenuAction::SaveRecoveryFile { current, destination },
                SecurityAction::Back => {
                    back = true;
                    MenuAction::None
                }
            },
            Page::Setup(menu) => match menu.mouse(mouse) {
                SetupAction::None => MenuAction::None,
                SetupAction::Close => MenuAction::Close,
                SetupAction::SaveRecoveryFile { current, destination } => MenuAction::SaveRecoveryFile { current, destination },
                SetupAction::Back => { back = true; MenuAction::None }
            },
            Page::Shortcuts(menu) => {
                let editing = menu.is_editing();
                match menu.mouse(mouse, bindings) {
                    ShortcutAction::None => MenuAction::None,
                    ShortcutAction::Close if editing || menu.is_editing() => {
                        back = true;
                        MenuAction::None
                    }
                    ShortcutAction::Close => MenuAction::Close,
                    ShortcutAction::Save(candidate) => MenuAction::SaveBindings(candidate),
                }
            }
            Page::Sync(editor) => match editor.dialog.form.mouse(mouse, &editor.hits) {
                FormAction::Continue => MenuAction::None,
                FormAction::Submit => editor.candidate(),
                FormAction::Cancel => {
                    back = true;
                    MenuAction::None
                }
            },
        };
        if back {
            self.back_to_root();
        }
        action
    }

    pub fn paste(&mut self, text: &str) {
        if !self.editing {
            return;
        }
        self.notice = None;
        match &mut self.page {
            Page::Workspace(editor) => editor.form.paste(text),
            Page::Tailscale(editor) => editor.form.paste(text),
            Page::Themes(menu) => menu.paste(text),
            Page::Security(menu) => menu.paste(text),
            Page::Setup(menu) => menu.paste(text),
            Page::Shortcuts(menu) => menu.paste(text),
            Page::Sync(editor) => editor.dialog.form.paste(text),
            Page::Extensions(menu) => menu.paste(text),
            Page::Root => {}
        }
    }

    pub fn draw(
        &mut self,
        frame: &mut Frame,
        bounds: Rect,
        bindings: &Bindings,
        workspace: WorkspaceSettings,
        state: &LocalState,
        theme: &'static Theme,
    ) {
        self.wide = !self.standalone && bounds.width >= 100 && bounds.height >= 20;
        self.navigation = Rect::default();
        self.content = Rect::default();
        self.hits.clear();
        if self.wide || !self.editing {
            self.draw_root(frame, bounds, bindings, workspace, state, theme);
            return;
        }
        let mut area = menu_bounds(bounds);
        if self.notice.is_some() && area.height > 0 {
            self.draw_notice(frame, Rect::new(area.x, area.bottom() - 1, area.width, 1), &theme.palette);
            area.height -= 1;
        }
        self.draw_page(frame, area, bindings, theme, true);
    }

    /// `active` is false while section navigation owns the keyboard beside this page.
    fn draw_page(&mut self, frame: &mut Frame, bounds: Rect, bindings: &Bindings, theme: &'static Theme, active: bool) {
        let palette = &theme.palette;
        match &mut self.page {
            Page::Root => {}
            Page::Tailscale(editor) => {
                editor.hits.clear();
                editor.form.draw_settings(frame, bounds, bindings, &mut editor.hits, palette, active);
            }
            Page::Workspace(editor) => {
                editor.hits.clear();
                editor.form.draw_settings(frame, bounds, bindings, &mut editor.hits, palette, active);
            }
            Page::Themes(menu) => menu.draw(frame, bounds, bindings, theme, active),
            Page::Security(menu) => menu.draw(frame, bounds, bindings, palette, active),
            Page::Setup(menu) => menu.draw(frame, bounds, bindings, palette, active),
            Page::Shortcuts(menu) => menu.draw(frame, bounds, bindings, palette, active),
            Page::Extensions(menu) => menu.draw(frame, bounds, bindings, palette, active),
            Page::Sync(editor) => {
                editor.hits.clear();
                editor.dialog.form.draw_settings(frame, bounds, bindings, &mut editor.hits, palette, active);
            }
        }
    }

    fn page_kind(&self) -> PageKind {
        match &self.page {
            Page::Workspace(_) | Page::Tailscale(_) | Page::Sync(_) => PageKind::Draft,
            Page::Security(menu) if menu.has_draft() => PageKind::Draft,
            Page::Shortcuts(menu) if menu.has_draft() => PageKind::Draft,
            Page::Shortcuts(menu) if menu.has_form() => PageKind::Immediate(Shortcut::Cancel),
            Page::Setup(_) => PageKind::Guide,
            Page::Extensions(_) => PageKind::Immediate(Shortcut::Cancel),
            Page::Root | Page::Themes(_) | Page::Security(_) | Page::Shortcuts(_) => PageKind::Immediate(Shortcut::SettingsClose),
        }
    }

    pub fn saved(&mut self, warning: Option<String>) {
        if let Page::Extensions(menu) = &mut self.page {
            menu.saved();
        }
        if let Page::Setup(menu) = &mut self.page {
            menu.saved(warning);
            return;
        }
        if let Page::Security(menu) = &mut self.page {
            menu.saved(self.security, warning);
            return;
        }
        if let Page::Themes(menu) = &mut self.page {
            menu.saved(warning);
            return;
        }
        if let Page::Shortcuts(menu) = &mut self.page {
            menu.saved(warning);
            return;
        }
        match &mut self.page {
            Page::Workspace(editor) => editor.form.error.clear(),
            Page::Tailscale(editor) => editor.form.error.clear(),
            Page::Sync(editor) => {
                editor.dialog.form.error.clear();
                // Synchronization changes whether local passphrase changes are available.
                self.cached[Section::Security as usize] = None;
            }
            _ => {}
        }
        self.notice = Some(match warning {
            Some(warning) => Notice::warning(format!("Saved; {}", safe_text(&warning))),
            None => Notice::success("Saved."),
        });
    }

    pub fn security_saved(&mut self, settings: SecuritySettings, warning: Option<String>) {
        self.security = settings;
        self.saved(warning);
    }

    pub fn set_error(&mut self, error: String) {
        let error = safe_text(&error);
        match &mut self.page {
            Page::Workspace(editor) => editor.form.error = error,
            Page::Tailscale(editor) => editor.form.error = error,
            Page::Themes(menu) => menu.set_error(error),
            Page::Security(menu) => menu.set_error(error),
            Page::Setup(menu) => menu.set_error(error),
            Page::Shortcuts(menu) => menu.set_error(error),
            Page::Sync(editor) => editor.dialog.form.error = error,
            Page::Extensions(menu) => menu.set_error(error),
            Page::Root => {
                self.notice = Some(Notice::error(error));
            }
        }
    }

    fn root_key(
        &mut self,
        key: KeyEvent,
        bindings: &Bindings,
        workspace: WorkspaceSettings,
        state: &LocalState,
        theme: &'static Theme,
    ) -> MenuAction {
        let previous = self.selected;
        if bindings.matches(Shortcut::MenuPrevious, key) {
            self.selected = self.selected.saturating_sub(1);
        } else if bindings.matches(Shortcut::MenuNext, key) {
            self.selected = (self.selected + 1).min(self.section_count() - 1);
        } else if bindings.matches(Shortcut::MenuFirst, key)
            || bindings.matches(Shortcut::MenuPageUp, key)
        {
            self.selected = 0;
        } else if bindings.matches(Shortcut::MenuLast, key)
            || bindings.matches(Shortcut::MenuPageDown, key)
        {
            self.selected = self.section_count() - 1;
        } else if bindings.matches(Shortcut::SettingsEdit, key) {
            self.open_selected(workspace, state, theme);
        } else if bindings.matches(Shortcut::SettingsClose, key) {
            return MenuAction::Close;
        } else if bindings.matches(Shortcut::NextField, key) {
            self.selected = (self.selected + 1) % self.section_count();
        } else if bindings.matches(Shortcut::PreviousField, key) {
            self.selected = (self.selected + self.section_count() - 1) % self.section_count();
        }
        self.switch_section(previous);
        MenuAction::None
    }

    fn root_mouse(
        &mut self,
        mouse: MouseEvent,
        workspace: WorkspaceSettings,
        state: &LocalState,
        theme: &'static Theme,
    ) -> MenuAction {
        if !contains(self.area, mouse.column, mouse.row) {
            return MenuAction::None;
        }
        let previous = self.selected;
        match mouse.kind {
            MouseEventKind::ScrollUp => {
                self.editing = false;
                self.selected = self.selected.saturating_sub(1);
            }
            MouseEventKind::ScrollDown => {
                self.editing = false;
                self.selected = (self.selected + 1).min(self.section_count() - 1);
            }
            MouseEventKind::Down(MouseButton::Left) => {
                let target = self
                    .hits
                    .iter()
                    .rev()
                    .find(|hit| contains(hit.area, mouse.column, mouse.row))
                    .map(|hit| hit.target);
                match target {
                    Some(RootTarget::Section(index)) => {
                        self.selected = index.min(self.section_count() - 1);
                        self.switch_section(previous);
                        self.open_selected(workspace, state, theme);
                        return MenuAction::None;
                    }
                    Some(RootTarget::Open) => self.open_selected(workspace, state, theme),
                    Some(RootTarget::Close) => return MenuAction::Close,
                    None => {}
                }
            }
            _ => {}
        }
        self.switch_section(previous);
        MenuAction::None
    }

    fn open_selected(&mut self, workspace: WorkspaceSettings, state: &LocalState, theme: &'static Theme) {
        self.editing = true;
        self.ensure_page(workspace, state, theme);
    }

    fn switch_section(&mut self, previous: usize) {
        if previous == self.selected {
            return;
        }
        if let Page::Security(menu) = &mut self.page { menu.clear_secrets(); }
        let page = std::mem::replace(&mut self.page, Page::Root);
        if !matches!(page, Page::Root | Page::Setup(_))
            && let Some(cached) = self.cached.get_mut(previous) {
            *cached = Some(page);
        }
        self.page = self.cached.get_mut(self.selected).and_then(Option::take).unwrap_or(Page::Root);
        self.notice = None;
    }

    fn ensure_page(&mut self, workspace: WorkspaceSettings, state: &LocalState, theme: &'static Theme) {
        if !matches!(self.page, Page::Root) {
            return;
        }
        self.notice = None;
        if let Some(id) = self.child(self.selected).map(|entry| entry.manifest.id.clone()) {
            self.page = Page::Extensions(ExtensionsMenu::for_entry(self.extensions.clone(), &id));
            return;
        }
        self.page = match Section::ALL[self.selected] {
            Section::Workspace => Page::Workspace(WorkspaceEditor::new(workspace)),
            Section::Themes => Page::Themes(ThemeMenu::new(theme)),
            Section::Security => Page::Security(SecurityMenu::new(self.security, state.sync.is_none())),
            Section::Shortcuts => Page::Shortcuts(ShortcutMenu::new(ShortcutMode::Edit)),
            Section::Sync => Page::Sync(SyncEditor::new(state)),
            Section::Setup => Page::Setup(SetupWizard::new(SetupEntry::Settings, state.sync.is_none())),
            Section::Extensions => Page::Extensions(ExtensionsMenu::new(self.extensions.clone())),
            Section::Tailscale => Page::Tailscale(TailscaleEditor::new(self.tailscale_cli_path.as_deref())),
        };
    }

    fn back_to_root(&mut self) {
        self.editing = false;
        self.standalone = false;
        self.page = Page::Root;
        self.notice = None;
    }

    fn draw_root(
        &mut self,
        frame: &mut Frame,
        bounds: Rect,
        bindings: &Bindings,
        workspace: WorkspaceSettings,
        state: &LocalState,
        theme: &'static Theme,
    ) {
        let palette = &theme.palette;
        self.hits.clear();
        self.area = menu_bounds(bounds);
        if self.area.width < 2 || self.area.height < 2 {
            return;
        }

        clear(frame, self.area, palette);
        let block = Block::default()
            .title(" Settings ")
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(palette.accent));
        let inner = block.inner(self.area);
        frame.render_widget(block, self.area);
        let inner = Rect::new(inner.x.saturating_add(1), inner.y.saturating_add(1),
            inner.width.saturating_sub(2), inner.height.saturating_sub(1));

        let footer_height = inner.height.min(if inner.height >= 8 { 2 } else { 1 });
        let notice_height = self.notice.as_ref().map_or(0, |notice| {
            notice.rows(inner.width).min(2).min(inner.height.saturating_sub(footer_height))
        });
        let body_height = inner
            .height
            .saturating_sub(footer_height + notice_height);
        let body = Rect::new(inner.x, inner.y, inner.width, body_height);
        let notice_area = Rect::new(inner.x, body.bottom(), inner.width, notice_height);
        let footer = Rect::new(
            inner.x,
            notice_area.bottom(),
            inner.width,
            footer_height,
        );

        if self.wide {
            self.ensure_page(workspace, state, theme);
            let list_width = 29;
            let list = Rect::new(body.x, body.y, list_width, body.height);
            let detail = Rect::new(
                list.right().saturating_add(1),
                body.y,
                body.right().saturating_sub(list.right().saturating_add(1)),
                body.height,
            );
            self.navigation = list;
            self.content = detail;
            self.draw_section_rows(frame, list, workspace.icon_mode, palette);
            self.draw_page(frame, detail, bindings, theme, self.editing);
        } else {
            let rows_height = body.height.saturating_sub(5).max(1).min(body.height)
                .min((self.section_count() + 1) as u16);
            let list = Rect::new(body.x, body.y, body.width, rows_height);
            self.navigation = list;
            self.draw_section_rows(frame, list, workspace.icon_mode, palette);
            let detail_y = list.bottom() + u16::from(list.bottom() < body.bottom());
            let detail = Rect::new(
                body.x,
                detail_y,
                body.width,
                body.bottom().saturating_sub(detail_y),
            );
            self.draw_section_detail(frame, detail, workspace, state, theme);
        }

        self.draw_notice(frame, notice_area, palette);

        let open_caption = if self.wide { "Edit controls" } else { "Open" };
        if footer.height > 1 {
            let key = |action: Shortcut| bindings.primary(action);
            let help = if !self.editing {
                format!("Sections focused · {}/{} select · {} {}",
                    key(Shortcut::MenuPrevious), key(Shortcut::MenuNext),
                    key(Shortcut::SettingsEdit), open_caption.to_lowercase())
            } else {
                match self.page_kind() {
                    PageKind::Draft => format!("Controls focused · {} saves · {} discards unsaved changes · switching sections keeps them",
                        key(Shortcut::Submit), key(Shortcut::Cancel)),
                    PageKind::Guide => format!("Controls focused · {} goes back a step · leaving Setup discards its progress",
                        key(Shortcut::Cancel)),
                    PageKind::Immediate(back) => format!("Controls focused · changes apply immediately · {} goes back", key(back)),
                }
            };
            frame.render_widget(Paragraph::new(crate::ui::widgets::fit(&help, footer.width)).style(Style::default().fg(palette.muted)),
                Rect { height: 1, ..footer });
        }
        let button_area = Rect::new(footer.x, footer.bottom().saturating_sub(1), footer.width, footer.height.min(1));
        let close_key = if self.editing { "" } else { bindings.primary(Shortcut::SettingsClose) };
        let labels = [(open_caption, bindings.primary(Shortcut::SettingsEdit)), ("Close", close_key)];
        let targets = [RootTarget::Open, RootTarget::Close];
        // Focused controls handle keyboard back themselves; only Close remains beside them.
        let first = usize::from(self.editing);
        let captions = keyed_captions(&labels[first..], button_area.width, button_area.height);
        let buttons: Vec<Button<'_>> = captions.iter().zip(&targets[first..])
            .map(|(caption, target)| if matches!(target, RootTarget::Open) { Button::primary(caption) } else { Button::secondary(caption) })
            .collect();
        let hits = &mut self.hits;
        draw_buttons(frame, button_area, &buttons, None, palette,
            |index, area| hits.push(RootHit { area, target: targets[first + index] }));
    }

    fn draw_notice(&self, frame: &mut Frame, area: Rect, palette: &Palette) {
        if let Some(notice) = &self.notice {
            notice.draw(frame, area, palette);
        }
    }

    fn draw_section_rows(&mut self, frame: &mut Frame, area: Rect, mode: IconMode, palette: &Palette) {
        if area.width == 0 || area.height == 0 {
            return;
        }
        let visible = usize::from(area.height);
        let selected_row = Self::section_row(self.selected);
        self.navigation_offset = self.navigation_offset.min((self.section_count() + 1).saturating_sub(visible));
        if selected_row < self.navigation_offset { self.navigation_offset = selected_row; }
        if selected_row >= self.navigation_offset + visible { self.navigation_offset = selected_row + 1 - visible; }
        let rows = Section::ALL.iter().map(|section| (Some(*section), section.icon(), section.title()))
            .chain(children(&self.extensions).map(|entry| (None, Icon::Settings, entry.manifest.name.as_str())));
        for (index, (section, icon, title)) in rows.enumerate() {
            let position = Self::section_row(index);
            if position < self.navigation_offset || position >= self.navigation_offset + visible { continue; }
            let y = area.y + (position - self.navigation_offset) as u16;
            let row = Rect::new(area.x, y, area.width, 1);
            let selected = index == self.selected;
            let style = if selected {
                Style::default().fg(palette.selection_fg).bg(palette.selection_bg).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(palette.muted).bg(palette.background)
            };
            let child = section.is_none();
            let style = if section == Some(Section::Extensions) { style.add_modifier(Modifier::BOLD) } else { style };
            let label = Line::from(vec![
                Span::raw(if selected { "> " } else { "  " }),
                Span::raw(if child { "  " } else { "" }),
                Span::styled(icon.glyph(mode), Style::default().fg(icon.color(palette))),
                Span::raw(" "),
                Span::raw(title),
            ]);
            frame.render_widget(Paragraph::new(label).style(style), Rect { height: 1, ..row });
            self.hits.push(RootHit { area: row, target: RootTarget::Section(index) });
        }
    }

    fn draw_section_detail(
        &self,
        frame: &mut Frame,
        area: Rect,
        workspace: WorkspaceSettings,
        state: &LocalState,
        theme: &Theme,
    ) {
        let palette = &theme.palette;
        if area.width == 0 || area.height == 0 {
            return;
        }
        let (title, description, status) = if let Some(entry) = self.child(self.selected) {
            (entry.manifest.name.as_str(), entry.manifest.description.as_str(),
                format!("{} · {} · Enabled · opening settings does not run extension code",
                    entry.manifest.id, entry.manifest.version))
        } else {
            let section = Section::ALL[self.selected];
            let status = match section {
                Section::Workspace => format!(
                    "Sidebar: {} columns · {} · Terminals: {}",
                    workspace.sidebar_width,
                    if workspace.sidebar_collapsed {
                        "Collapsed"
                    } else {
                        "Expanded"
                    },
                    workspace.terminal_layout.label(),
                ),
                Section::Themes => format!(
                    "Current: {} [{}] · {} · {} bundled themes",
                    theme.name, theme.system, theme.appearance.label(), THEMES.len(),
                ),
                Section::Security => if self.security.idle_timeout_seconds == 0 {
                    "Auto-lock: off".to_owned()
                } else {
                    format!("Auto-lock: {} · {}", self.security.timeout_text(),
                        if self.security.lock_sessions == LockSessions::Disconnect { "disconnect sessions" } else { "keep sessions running" })
                },
                Section::Shortcuts => "Select a command to edit its active key sequence.".to_owned(),
                Section::Sync => state.sync.as_ref().map_or_else(
                    || "This vault is currently local only.".to_owned(),
                    |sync| format!("Server: {} · access token configured", safe_text(&sync.url)),
                ),
                Section::Setup => if state.sync.is_none() {
                    "Current mode: Local (on this device)."
                } else {
                    "Current mode: Synchronized. Local recovery export is unavailable."
                }.to_owned(),
                Section::Extensions => format!("{} installed · {} enabled · permissions stay on this device", self.extensions.len(), children(&self.extensions).count()),
                Section::Tailscale => "Local CLI discovery and routing; no login or policy changes.".to_owned(),
            };
            (section.title(), section.description(), status)
        };
        let lines = vec![
            Line::from(Span::styled(
                title,
                Style::default()
                    .fg(palette.accent)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(description),
            Line::from(""),
            Line::from(Span::styled(status, Style::default().fg(palette.muted))),
        ];
        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), area);
    }
}


/// Enabled packages are Settings children; disabled ones are managed under Extensions.
fn children(entries: &[ExtensionEntry]) -> impl Iterator<Item = &ExtensionEntry> {
    entries.iter().filter(|entry| entry.enabled)
}

fn menu_bounds(bounds: Rect) -> Rect {
    Rect::new(
        bounds.x,
        bounds.y,
        bounds.width,
        bounds.height.saturating_sub(1),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyModifiers};
    use ratatui::{Terminal, backend::TestBackend};
    use crate::{theme::default_theme, vault::Vault};

    fn state() -> LocalState {
        LocalState::new(Vault::new(), None)
    }

    fn draw(menu: &mut WorkspaceMenu, width: u16, height: u16, bindings: &Bindings, workspace: WorkspaceSettings, state: &LocalState) {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(|frame| menu.draw(frame, frame.area(), bindings, workspace, state, default_theme())).unwrap();
    }

    fn key(menu: &mut WorkspaceMenu, code: KeyCode, bindings: &Bindings, workspace: WorkspaceSettings, state: &LocalState) -> MenuAction {
        menu.key(KeyEvent::new(code, KeyModifiers::NONE), bindings, workspace, state, default_theme())
    }
    /// Clicks the visible `[label]` action button of the open extension page.
    fn activate_extension_action(menu: &mut WorkspaceMenu, label: &str, bindings: &Bindings, workspace: WorkspaceSettings, state: &LocalState) -> MenuAction {
        let mut terminal = Terminal::new(TestBackend::new(130, 35)).unwrap();
        terminal.draw(|frame| menu.draw(frame, frame.area(), bindings, workspace, state, default_theme())).unwrap();
        let buffer = terminal.backend().buffer();
        let caption = format!("[{label}]");
        let width = usize::from(buffer.area.width);
        let position = (0..buffer.content.len()).find(|&start| {
            let row_end = (start / width + 1) * width;
            buffer.content[start..row_end].iter().map(|cell| cell.symbol()).collect::<String>().starts_with(&caption)
        }).unwrap_or_else(|| panic!("extension action is unreachable: {label}"));
        menu.mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: (position % width) as u16,
            row: (position / width) as u16,
            modifiers: KeyModifiers::NONE,
        }, bindings, workspace, state, default_theme())
    }


    fn click_section(menu: &mut WorkspaceMenu, index: usize, bindings: &Bindings, workspace: WorkspaceSettings, state: &LocalState) {
        let area = menu.hits.iter().find_map(|hit| match hit.target {
            RootTarget::Section(found) if found == index => Some(hit.area),
            _ => None,
        }).unwrap();
        menu.mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: area.x,
            row: area.y,
            modifiers: KeyModifiers::NONE,
        }, bindings, workspace, state, default_theme());
    }

    fn extension(id: &str, digest: &str) -> ExtensionEntry {
        use crate::extensions::{contract::Permission, package::{Command, Manifest}};
        ExtensionEntry {
            manifest: Manifest { schema_version: 1, api_version: 1, id: id.into(),
                name: "Shared display name".into(), description: "SDK extension".into(), version: "1.0.0".into(),
                permissions: vec![Permission::HostsRead],
                commands: vec![Command { id: "browse".into(), title: "Browse".into(), description: String::new() }] },
            digest: digest.repeat(64), enabled: false, grants: Vec::new(), official: false, repository: None,
            development: false, development_path: None, status: String::new(), diagnostics: Vec::new(),
            trust_rebuilds: false, reload_available: false, native: false,
        }
    }

    #[test]
    fn extension_settings_preserve_identity_and_never_retarget_removed_consent() {
        let state = state();
        let bindings = Bindings::default();
        let workspace = WorkspaceSettings::default();
        let mut menu = WorkspaceMenu::new(MenuMode::Settings, SecuritySettings::default(), &state);
        let first = ExtensionEntry { enabled: true, ..extension("org.example.first", "1") };
        let second = ExtensionEntry { enabled: true, ..extension("org.example.second", "2") };
        menu.set_extensions(vec![first.clone(), second.clone()]);
        key(&mut menu, KeyCode::End, &bindings, workspace, &state);
        key(&mut menu, KeyCode::Enter, &bindings, workspace, &state);
        activate_extension_action(&mut menu, "Remove", &bindings, workspace, &state);
        menu.set_extensions(vec![second.clone(), first.clone()]);
        let MenuAction::Extension(ManagementAction::Remove { extension_id }) =
            key(&mut menu, KeyCode::Enter, &bindings, workspace, &state) else { panic!("review lost after reorder") };
        assert_eq!(extension_id, second.manifest.id);
        draw(&mut menu, 130, 35, &bindings, workspace, &state);
        let second_row = menu.hits.iter().find_map(|hit| match hit.target {
            RootTarget::Section(index) if index == Section::ALL.len() => Some(hit.area),
            _ => None,
        }).unwrap();
        // Disabling the selected child, with its removal pending, keeps the package
        // manageable under Extensions and drops that consent.
        let disabled = ExtensionEntry { enabled: false, ..second.clone() };
        menu.set_extensions(vec![disabled, first.clone()]);
        assert_eq!(menu.selected, Section::Extensions as usize);
        // The vanished child's stale row never selects the package now in its place.
        menu.mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: second_row.x,
            row: second_row.y,
            modifiers: KeyModifiers::NONE,
        }, &bindings, workspace, &state, default_theme());
        assert_eq!(menu.selected, Section::Extensions as usize);
        activate_extension_action(&mut menu, "Review and enable", &bindings, workspace, &state);
        let MenuAction::Extension(ManagementAction::Enable { extension_id, digest, grants }) =
            key(&mut menu, KeyCode::Enter, &bindings, workspace, &state) else { panic!("disabled package is unmanageable") };
        assert_eq!((extension_id, digest, grants), (second.manifest.id, second.digest, second.manifest.permissions));
        menu.set_extensions(vec![first.clone()]);
        // Removal returns to management, not the other extension's approval.
        assert!(matches!(key(&mut menu, KeyCode::Enter, &bindings, workspace, &state), MenuAction::None));
        activate_extension_action(&mut menu, "Disable", &bindings, workspace, &state);
        let MenuAction::Extension(ManagementAction::Disable { extension_id }) =
            key(&mut menu, KeyCode::Enter, &bindings, workspace, &state) else { panic!("fresh review unavailable") };
        assert_eq!(extension_id, first.manifest.id);
    }

    #[test]
    fn extension_settings_open_the_affected_package() {
        let state = state();
        let bindings = Bindings::default();
        let workspace = WorkspaceSettings::default();
        let mut menu = WorkspaceMenu::new(MenuMode::Settings, SecuritySettings::default(), &state);
        let enabled = ExtensionEntry { enabled: true, ..extension("org.example.enabled", "1") };
        let disabled = extension("org.example.disabled", "2");
        menu.set_extensions(vec![disabled.clone(), enabled.clone()]);
        menu.show_extension(&enabled.manifest.id);
        assert_eq!(menu.selected, Section::ALL.len());
        activate_extension_action(&mut menu, "Disable", &bindings, workspace, &state);
        assert!(matches!(key(&mut menu, KeyCode::Enter, &bindings, workspace, &state),
            MenuAction::Extension(ManagementAction::Disable { extension_id }) if extension_id == enabled.manifest.id));
        // A disabled package opens its detail under Extensions; cancelling a review
        // returns to that detail and Back to the installed list, not the sections.
        menu.show_extension(&disabled.manifest.id);
        assert_eq!(menu.selected, Section::Extensions as usize);
        activate_extension_action(&mut menu, "Review and enable", &bindings, workspace, &state);
        key(&mut menu, KeyCode::Esc, &bindings, workspace, &state);
        activate_extension_action(&mut menu, "Review and enable", &bindings, workspace, &state);
        key(&mut menu, KeyCode::Esc, &bindings, workspace, &state);
        key(&mut menu, KeyCode::Esc, &bindings, workspace, &state);
        assert!(menu.is_extensions());
        key(&mut menu, KeyCode::Esc, &bindings, workspace, &state);
        assert!(!menu.is_extensions());
        // Without an affected package, Settings opens the Extensions list.
        menu.show_extension("org.example.missing");
        assert_eq!(menu.selected, Section::Extensions as usize);
        assert!(menu.is_extensions());
        assert!(matches!(key(&mut menu, KeyCode::Esc, &bindings, workspace, &state), MenuAction::None));
        assert!(!menu.is_extensions());
    }

    #[test]
    fn extension_settings_remain_reachable_across_scrolling_resize_and_back() {
        let state = state();
        let bindings = Bindings::default().with_binding(Shortcut::SettingsEdit, "F3").unwrap();
        let workspace = WorkspaceSettings::default();
        let mut menu = WorkspaceMenu::new(MenuMode::Settings, SecuritySettings::default(), &state);
        // Disabled packages are not children: the 32nd enabled package is item 38.
        menu.set_extensions((0..40).map(|index| ExtensionEntry { enabled: index % 5 != 4,
            ..extension(&format!("org.example.item-{index}"), "a") }).collect());
        key(&mut menu, KeyCode::End, &bindings, workspace, &state);
        draw(&mut menu, 60, 12, &bindings, workspace, &state);
        click_section(&mut menu, Section::ALL.len() + 31, &bindings, workspace, &state);
        draw(&mut menu, 130, 35, &bindings, workspace, &state);
        activate_extension_action(&mut menu, "Disable", &bindings, workspace, &state);
        let MenuAction::Extension(ManagementAction::Disable { extension_id }) =
            key(&mut menu, KeyCode::Enter, &bindings, workspace, &state) else { panic!("last entry is unreachable") };
        assert_eq!(extension_id, "org.example.item-38");
        key(&mut menu, KeyCode::Esc, &bindings, workspace, &state);
        key(&mut menu, KeyCode::Esc, &bindings, workspace, &state);
        key(&mut menu, KeyCode::Home, &bindings, workspace, &state);
        key(&mut menu, KeyCode::F(3), &bindings, workspace, &state);
        assert!(matches!(key(&mut menu, KeyCode::Enter, &bindings, workspace, &state), MenuAction::SaveWorkspace(_)));
    }

    #[test]
    fn extension_management_error_survives_its_refresh_until_the_next_input() {
        let state = state();
        let bindings = Bindings::default();
        let workspace = WorkspaceSettings::default();
        let mut menu = WorkspaceMenu::new(MenuMode::Settings, SecuritySettings::default(), &state);
        let package = ExtensionEntry { enabled: true, ..extension("org.example.package", "1") };
        menu.set_extensions(vec![package.clone()]);
        menu.show_extension(&package.manifest.id);
        let shown = |menu: &mut WorkspaceMenu| {
            let mut terminal = Terminal::new(TestBackend::new(130, 35)).unwrap();
            terminal.draw(|frame| menu.draw(frame, frame.area(), &bindings, workspace, &state, default_theme())).unwrap();
            terminal.backend().buffer().content.iter().map(|cell| cell.symbol()).collect::<String>().contains("injected failure")
        };
        // A failed disable still disables in memory; that refresh must not hide why.
        menu.set_error("Not saved: injected failure".into());
        menu.set_extensions(vec![ExtensionEntry { enabled: false, ..package }]);
        assert!(shown(&mut menu));
        key(&mut menu, KeyCode::Down, &bindings, workspace, &state);
        assert!(!shown(&mut menu));
    }

    #[test]
    fn wide_controls_keep_drafts_across_sections_and_resizes_until_save_or_cancel() {
        let state = state();
        let bindings = Bindings::default();
        let workspace = WorkspaceSettings::default();
        let mut menu = WorkspaceMenu::new(MenuMode::Settings, SecuritySettings::default(), &state);
        draw(&mut menu, 130, 35, &bindings, workspace, &state);
        // Navigation focus must not paste into the visible draft.
        menu.paste("99");
        key(&mut menu, KeyCode::Enter, &bindings, workspace, &state);
        let Page::Workspace(editor) = &mut menu.page else { panic!("workspace controls missing") };
        assert_eq!(editor.form.value(0), "28");
        editor.form.fields[0].set_value("45");
        editor.form.fields[3].choice = 1;
        click_section(&mut menu, Section::Themes as usize, &bindings, workspace, &state);
        draw(&mut menu, 130, 35, &bindings, workspace, &state);
        click_section(&mut menu, Section::Workspace as usize, &bindings, workspace, &state);
        draw(&mut menu, 60, 20, &bindings, workspace, &state);
        assert!(!menu.wide);
        let MenuAction::SaveWorkspace(candidate) = key(&mut menu, KeyCode::Enter, &bindings, workspace, &state) else { panic!("save lost after resize") };
        assert_eq!(candidate.sidebar_width, 45);
        assert_eq!(candidate.icon_mode, IconMode::NerdFont);
        menu.saved(None);
        assert!(matches!(menu.page, Page::Workspace(_)));
        let Page::Workspace(editor) = &mut menu.page else { unreachable!() };
        editor.form.fields[0].set_value("70");
        key(&mut menu, KeyCode::Esc, &bindings, candidate, &state);
        draw(&mut menu, 130, 35, &bindings, candidate, &state);
        key(&mut menu, KeyCode::Enter, &bindings, candidate, &state);
        let MenuAction::SaveWorkspace(after_cancel) = key(&mut menu, KeyCode::Enter, &bindings, candidate, &state) else { panic!("workspace not editable") };
        assert_eq!(after_cancel, candidate);
    }

    #[test]
    fn compact_navigation_obeys_custom_bindings_and_invalid_drafts_stay_editable() {
        let state = state();
        let bindings = Bindings::default().with_binding(Shortcut::SettingsEdit, "F3").unwrap();
        let workspace = WorkspaceSettings::default();
        let mut menu = WorkspaceMenu::new(MenuMode::Settings, SecuritySettings::default(), &state);
        draw(&mut menu, 60, 20, &bindings, workspace, &state);
        assert!(matches!(menu.page, Page::Root));
        key(&mut menu, KeyCode::F(3), &bindings, workspace, &state);
        let Page::Workspace(editor) = &mut menu.page else { panic!("custom open ignored") };
        editor.form.fields[0].set_value("19");
        assert!(matches!(key(&mut menu, KeyCode::Enter, &bindings, workspace, &state), MenuAction::None));
        assert!(menu.editing);
        let Page::Workspace(editor) = &mut menu.page else { panic!("invalid draft discarded") };
        assert!(!editor.form.error.is_empty());
        editor.form.fields[0].set_value("40");
        let MenuAction::SaveWorkspace(candidate) = key(&mut menu, KeyCode::Enter, &bindings, workspace, &state) else { panic!("corrected draft cannot save") };
        assert_eq!(candidate.sidebar_width, 40);
    }

    #[test]
    fn section_scroll_and_control_click_in_one_event_burst_routes_to_new_section() {
        let state = state();
        let bindings = Bindings::default();
        let workspace = WorkspaceSettings::default();
        let mut menu = WorkspaceMenu::new(MenuMode::Settings, SecuritySettings::default(), &state);
        draw(&mut menu, 130, 35, &bindings, workspace, &state);
        for _ in 0..4 {
            menu.mouse(MouseEvent {
                kind: MouseEventKind::ScrollDown,
                column: menu.navigation.x,
                row: menu.navigation.y,
                modifiers: KeyModifiers::NONE,
            }, &bindings, workspace, &state, default_theme());
        }
        menu.mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: menu.content.x + 2,
            row: menu.content.y + 2,
            modifiers: KeyModifiers::NONE,
        }, &bindings, workspace, &state, default_theme());
        draw(&mut menu, 130, 35, &bindings, workspace, &state);
        menu.paste("https://sync.example.test");
        let MenuAction::ConfigureSync { url, .. } = key(&mut menu, KeyCode::Enter, &bindings, workspace, &state) else { panic!("input routed to previous section") };
        assert_eq!(url, "https://sync.example.test");
    }
}
