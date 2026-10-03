use std::collections::BTreeMap;

use anyhow::{Context, Result, bail, ensure};
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

const ACTION_COUNT: usize = 76;
/// Actions added after custom bindings could be saved. Their defaults yield to an explicit older
/// customization that already uses the same key in an overlapping context.
const ADDITIVE: [Shortcut; 2] = [Shortcut::SidebarClearFilter, Shortcut::AiPermission];

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[repr(u8)]
#[serde(rename_all = "snake_case")]
pub enum Shortcut {
    Prefix,
    PrefixSidebar,
    PrefixLayout,
    PrefixNextSession,
    PrefixPreviousSession,
    PrefixCloseSession,
    PrefixSync,
    PrefixDetach,
    PrefixQuit,
    PrefixShortcuts,
    PrefixSettings,
    PrefixExtensions,
    PrefixAiChat,
    PrefixAiFocus,
    PrefixLiteral,
    PrefixCancel,
    SidebarPrevious,
    SidebarNext,
    SidebarCollapse,
    SidebarExpand,
    SidebarActivate,
    SidebarAdd,
    SidebarEdit,
    SidebarDelete,
    SidebarCloseSession,
    SidebarSearch,
    SidebarInspect,
    SidebarForgetHostKey,
    SidebarSync,
    SidebarQuit,
    RetrySave,
    Reconnect,
    ScrollUp,
    ScrollDown,
    SearchKeep,
    SearchCancel,
    SearchPrevious,
    SearchNext,
    Submit,
    Cancel,
    NextField,
    PreviousField,
    CursorLeft,
    CursorRight,
    Home,
    End,
    Backspace,
    Delete,
    ClearField,
    PreviousChoice,
    NextChoice,
    AbortStartup,
    MenuPrevious,
    MenuNext,
    MenuPageUp,
    MenuPageDown,
    MenuFirst,
    MenuLast,
    ReferenceClose,
    ReferenceSettings,
    SettingsClose,
    SettingsEdit,
    SettingsReset,
    SettingsResetAll,
    AiSend,
    AiNewline,
    AiStop,
    AiCommands,
    AiNextArea,
    AiPreviousArea,
    AiUp,
    AiDown,
    AiPageUp,
    AiPageDown,
    SidebarClearFilter,
    AiPermission,
}

impl Shortcut {
    pub fn definition(self) -> &'static ShortcutDefinition {
        &DEFINITIONS[self as usize]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Chord {
    code: KeyCode,
    modifiers: KeyModifiers,
}

impl Chord {
    const fn new(code: KeyCode, modifiers: KeyModifiers) -> Self {
        Self { code, modifiers }
    }
}

pub struct ShortcutDefinition {
    pub id: Shortcut,
    pub group: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    defaults: &'static [Chord],
    contexts: u128,
    prefixed: bool,
}

impl ShortcutDefinition {
    /// Built-in keys as shown to the user.
    pub fn default_text(&self) -> String {
        format_chords(self.defaults, " / ")
    }
}

const SIDEBAR: u128 = 1 << 0;
const SIDEBAR_UNCERTAIN: u128 = 1 << 1;
const TERMINAL_LIVE: u128 = 1 << 2;
const TERMINAL_CLOSED: u128 = 1 << 3;
const TERMINAL_UNCERTAIN: u128 = 1 << 4;
const PREFIX_MODE: u128 = 1 << 5;
const SEARCH: u128 = 1 << 6;
const FORM_TEXT: u128 = 1 << 7;
const FORM_CHOICE: u128 = 1 << 8;
const DIALOG: u128 = 1 << 9;
const SNIPPET: u128 = 1 << 10;
const STARTUP_TEXT: u128 = 1 << 11;
const STARTUP_CHOICE: u128 = 1 << 12;
const STARTUP_BUSY: u128 = 1 << 13;
const REFERENCE_LIST: u128 = 1 << 14;
const SETTINGS_LIST: u128 = 1 << 15;
/// The focused Vyx AI panel: its composer, transcript, and pickers.
const CHAT: u128 = 1 << 16;

const PREFIX_CONTEXTS: u128 =
    SIDEBAR | SIDEBAR_UNCERTAIN | TERMINAL_LIVE | TERMINAL_CLOSED | TERMINAL_UNCERTAIN;
const SIDEBAR_CONTEXTS: u128 = SIDEBAR | SIDEBAR_UNCERTAIN;
const TERMINAL_CONTEXTS: u128 = TERMINAL_LIVE | TERMINAL_CLOSED | TERMINAL_UNCERTAIN;
const TEXT_FORM_CONTEXTS: u128 = FORM_TEXT | STARTUP_TEXT;
/// Text-editing actions shared by forms, search, and the AI composer.
const TEXT_CONTEXTS: u128 = TEXT_FORM_CONTEXTS | SEARCH | CHAT;
const CHOICE_FORM_CONTEXTS: u128 = FORM_CHOICE | STARTUP_CHOICE;
const FORM_CONTEXTS: u128 = TEXT_FORM_CONTEXTS | CHOICE_FORM_CONTEXTS;
const SUBMIT_CONTEXTS: u128 = FORM_CONTEXTS | DIALOG | SNIPPET;
const CANCEL_CONTEXTS: u128 = SUBMIT_CONTEXTS | STARTUP_BUSY | CHAT;
const MENU_CONTEXTS: u128 = REFERENCE_LIST | SETTINGS_LIST;

const NONE: KeyModifiers = KeyModifiers::NONE;
const CTRL: KeyModifiers = KeyModifiers::CONTROL;
const SHIFT: KeyModifiers = KeyModifiers::SHIFT;
const ALT: KeyModifiers = KeyModifiers::ALT;

macro_rules! chords {
    ($($code:expr => $mods:expr),+ $(,)?) => {
        &[$(Chord::new($code, $mods)),+]
    };
}

macro_rules! definition {
    ($id:ident, $group:literal, $title:literal, $description:literal, $defaults:expr, $contexts:expr) => {
        ShortcutDefinition {
            id: Shortcut::$id,
            group: $group,
            title: $title,
            description: $description,
            defaults: $defaults,
            contexts: $contexts,
            prefixed: false,
        }
    };
    (prefix $id:ident, $group:literal, $title:literal, $description:literal, $defaults:expr) => {
        ShortcutDefinition {
            id: Shortcut::$id,
            group: $group,
            title: $title,
            description: $description,
            defaults: $defaults,
            contexts: PREFIX_MODE,
            prefixed: true,
        }
    };
}

pub static DEFINITIONS: &[ShortcutDefinition] = &[
    definition!(Prefix, "Global", "Command prefix", "Show prefix commands. Available over menus and forms unless the key is needed for text editing or navigation.", chords![KeyCode::Char('b') => CTRL], PREFIX_CONTEXTS),
    definition!(prefix PrefixSidebar, "Prefix", "Toggle sidebar", "Focus, collapse, or expand the session sidebar.", chords![KeyCode::Char('b') => NONE]),
    definition!(prefix PrefixLayout, "Prefix", "Cycle terminal layout", "Cycle Single, Side by side, Stacked, and Grid; save the layout locally.", chords![KeyCode::Char('l') => NONE]),
    definition!(prefix PrefixNextSession, "Prefix", "Next session", "Focus the next open session.", chords![KeyCode::Char('n') => NONE]),
    definition!(prefix PrefixPreviousSession, "Prefix", "Previous session", "Focus the previous open session.", chords![KeyCode::Char('p') => NONE]),
    definition!(prefix PrefixCloseSession, "Prefix", "Close session", "Close the active session.", chords![KeyCode::Char('x') => NONE]),
    definition!(prefix PrefixSync, "Prefix", "Sync", "Synchronize the vault.", chords![KeyCode::Char('s') => NONE]),
    definition!(prefix PrefixDetach, "Prefix", "Detach", "Detach this client while leaving the workspace running.", chords![KeyCode::Char('d') => NONE]),
    definition!(prefix PrefixQuit, "Prefix", "Quit", "Quit the workspace.", chords![KeyCode::Char('q') => NONE]),
    definition!(prefix PrefixShortcuts, "Prefix", "Shortcut reference", "Open the complete shortcut reference.", chords![KeyCode::Char('?') => NONE]),
    definition!(prefix PrefixSettings, "Prefix", "Settings", "Open the settings menu.", chords![KeyCode::Char(',') => NONE]),
    definition!(prefix PrefixExtensions, "Prefix", "Extensions", "Open the enabled extension command picker without executing code.", chords![KeyCode::Char('e') => NONE]),
    definition!(prefix PrefixAiChat, "Prefix", "AI chat", "Open the Vyx AI chat and focus it; when it is already focused, close it. Shown after Vyx AI is installed.", chords![KeyCode::Char('a') => NONE]),
    definition!(prefix PrefixAiFocus, "Prefix", "Switch AI focus", "Move the keyboard between the Vyx AI panel and the workspace, opening the chat if needed. Typing never reaches SSH while the panel is focused.", chords![KeyCode::Tab => NONE]),
    definition!(prefix PrefixLiteral, "Prefix", "Send literal prefix", "Send the original prefix key to SSH; follows the prefix binding unless overridden.", &[]),
    definition!(prefix PrefixCancel, "Prefix", "Cancel prefix", "Leave prefix mode without running a command.", chords![KeyCode::Esc => NONE]),
    definition!(SidebarPrevious, "Sidebar", "Previous item", "Select the previous sidebar item.", chords![KeyCode::Up => NONE, KeyCode::Char('k') => NONE], SIDEBAR_CONTEXTS),
    definition!(SidebarNext, "Sidebar", "Next item", "Select the next sidebar item.", chords![KeyCode::Down => NONE, KeyCode::Char('j') => NONE], SIDEBAR_CONTEXTS),
    definition!(SidebarCollapse, "Sidebar", "Collapse", "Collapse the selected sidebar group.", chords![KeyCode::Left => NONE], SIDEBAR_CONTEXTS),
    definition!(SidebarExpand, "Sidebar", "Expand", "Expand the selected sidebar group.", chords![KeyCode::Right => NONE], SIDEBAR_CONTEXTS),
    definition!(SidebarActivate, "Sidebar", "Activate", "Open or activate the selected item.", chords![KeyCode::Enter => NONE], SIDEBAR_CONTEXTS),
    definition!(SidebarAdd, "Sidebar", "Add", "Add a server, credential, or snippet.", chords![KeyCode::Char('a') => NONE], SIDEBAR_CONTEXTS),
    definition!(SidebarEdit, "Sidebar", "Edit / rename", "Edit the selected item or rename an open session.", chords![KeyCode::Char('e') => NONE], SIDEBAR_CONTEXTS),
    definition!(SidebarDelete, "Sidebar", "Delete", "Delete the selected item.", chords![KeyCode::Char('d') => NONE], SIDEBAR_CONTEXTS),
    definition!(SidebarCloseSession, "Sidebar", "Close session", "Close the selected open session.", chords![KeyCode::Char('x') => NONE], SIDEBAR_CONTEXTS),
    definition!(SidebarSearch, "Sidebar", "Search", "Search sidebar items.", chords![KeyCode::Char('/') => NONE], SIDEBAR_CONTEXTS),
    definition!(SidebarInspect, "Sidebar", "Inspect", "Inspect the selected item.", chords![KeyCode::Char('i') => NONE], SIDEBAR_CONTEXTS),
    definition!(SidebarForgetHostKey, "Sidebar", "Forget host key", "Forget the selected server's saved host key.", chords![KeyCode::Char('f') => NONE], SIDEBAR_CONTEXTS),
    definition!(SidebarSync, "Sidebar", "Sync", "Synchronize the vault.", chords![KeyCode::Char('s') => NONE], SIDEBAR_CONTEXTS),
    definition!(SidebarQuit, "Sidebar", "Quit", "Quit the workspace.", chords![KeyCode::Char('q') => NONE], SIDEBAR_CONTEXTS),
    definition!(RetrySave, "Recovery", "Retry save", "Retry a vault save whose directory durability is uncertain.", chords![KeyCode::Char('r') => NONE], SIDEBAR_UNCERTAIN | TERMINAL_UNCERTAIN),
    definition!(Reconnect, "Terminal", "Reconnect", "Reconnect a closed or failed terminal session.", chords![KeyCode::Char('r') => NONE], TERMINAL_CLOSED),
    definition!(ScrollUp, "Terminal", "Scroll up", "Scroll the terminal viewport up.", chords![KeyCode::PageUp => SHIFT], TERMINAL_CONTEXTS),
    definition!(ScrollDown, "Terminal", "Scroll down", "Scroll the terminal viewport down.", chords![KeyCode::PageDown => SHIFT], TERMINAL_CONTEXTS),
    definition!(SearchKeep, "Search", "Keep search", "Finish searching and keep the current selection.", chords![KeyCode::Enter => NONE, KeyCode::Tab => NONE], SEARCH),
    definition!(SearchCancel, "Search", "Cancel search", "Cancel searching and restore the previous selection.", chords![KeyCode::Esc => NONE], SEARCH),
    definition!(SearchPrevious, "Search", "Previous result", "Select the previous search result.", chords![KeyCode::Up => NONE], SEARCH),
    definition!(SearchNext, "Search", "Next result", "Select the next search result.", chords![KeyCode::Down => NONE], SEARCH),
    definition!(Submit, "Dialogs and forms", "Submit", "Submit the current form or dialog.", chords![KeyCode::Enter => NONE], SUBMIT_CONTEXTS),
    definition!(Cancel, "Dialogs and forms", "Cancel", "Cancel the current form, dialog, or startup operation. In AI chat, close the open picker or return focus to the workspace.", chords![KeyCode::Esc => NONE], CANCEL_CONTEXTS),
    definition!(NextField, "Dialogs and forms", "Next field", "Focus the next form field.", chords![KeyCode::Tab => NONE, KeyCode::Down => NONE], FORM_CONTEXTS),
    definition!(PreviousField, "Dialogs and forms", "Previous field", "Focus the previous form field.", chords![KeyCode::Tab => SHIFT, KeyCode::Up => NONE], FORM_CONTEXTS),
    definition!(CursorLeft, "Text editing", "Cursor left", "Move the text cursor left.", chords![KeyCode::Left => NONE], TEXT_CONTEXTS),
    definition!(CursorRight, "Text editing", "Cursor right", "Move the text cursor right.", chords![KeyCode::Right => NONE], TEXT_CONTEXTS),
    definition!(Home, "Text editing", "Start of field", "Move to the start of the text field or composer line.", chords![KeyCode::Home => NONE], TEXT_CONTEXTS),
    definition!(End, "Text editing", "End of field", "Move to the end of the text field or composer line.", chords![KeyCode::End => NONE], TEXT_CONTEXTS),
    definition!(Backspace, "Text editing", "Backspace", "Delete the character before the cursor.", chords![KeyCode::Backspace => NONE], TEXT_CONTEXTS),
    definition!(Delete, "Text editing", "Delete", "Delete the character after the cursor.", chords![KeyCode::Delete => NONE], TEXT_CONTEXTS),
    definition!(ClearField, "Text editing", "Clear field", "Clear the current text field or AI composer.", chords![KeyCode::Char('u') => CTRL], TEXT_CONTEXTS),
    definition!(PreviousChoice, "Choice editing", "Previous choice", "Select the previous choice.", chords![KeyCode::Left => NONE], CHOICE_FORM_CONTEXTS),
    definition!(NextChoice, "Choice editing", "Next choice", "Select the next choice.", chords![KeyCode::Right => NONE, KeyCode::Char(' ') => NONE], CHOICE_FORM_CONTEXTS),
    definition!(AbortStartup, "Startup", "Abort startup", "Abort startup from a vault form or while startup work runs.", chords![KeyCode::Char('c') => CTRL], STARTUP_TEXT | STARTUP_CHOICE | STARTUP_BUSY),
    definition!(MenuPrevious, "Menu navigation", "Previous row", "Select the previous menu row; in review and text dialogs, scroll up.", chords![KeyCode::Up => NONE, KeyCode::Char('k') => NONE], MENU_CONTEXTS),
    definition!(MenuNext, "Menu navigation", "Next row", "Select the next menu row; in review and text dialogs, scroll down.", chords![KeyCode::Down => NONE, KeyCode::Char('j') => NONE], MENU_CONTEXTS),
    definition!(MenuPageUp, "Menu navigation", "Previous page", "Move one page toward the start of the menu or dialog text.", chords![KeyCode::PageUp => NONE], MENU_CONTEXTS),
    definition!(MenuPageDown, "Menu navigation", "Next page", "Move one page toward the end of the menu or dialog text.", chords![KeyCode::PageDown => NONE], MENU_CONTEXTS),
    definition!(MenuFirst, "Menu navigation", "First row", "Select the first menu row, or show the start of dialog text.", chords![KeyCode::Home => NONE], MENU_CONTEXTS),
    definition!(MenuLast, "Menu navigation", "Last row", "Select the last menu row, or show the end of dialog text.", chords![KeyCode::End => NONE], MENU_CONTEXTS),
    definition!(ReferenceClose, "Shortcut reference", "Close reference", "Close the shortcut reference.", chords![KeyCode::Esc => NONE], REFERENCE_LIST),
    definition!(ReferenceSettings, "Shortcut reference", "Edit shortcuts", "Open keyboard shortcut settings at the selected action.", chords![KeyCode::Char('e') => NONE], REFERENCE_LIST),
    definition!(SettingsClose, "Settings navigation", "Back or close", "Return to settings sections, or close the settings menu.", chords![KeyCode::Esc => NONE], SETTINGS_LIST),
    definition!(SettingsEdit, "Settings navigation", "Open or edit", "Open a settings section or edit the selected shortcut.", chords![KeyCode::Enter => NONE, KeyCode::Char('e') => NONE], SETTINGS_LIST),
    definition!(SettingsReset, "Shortcut settings", "Reset binding", "Reset the selected action to its default.", chords![KeyCode::Char('r') => NONE], SETTINGS_LIST),
    definition!(SettingsResetAll, "Shortcut settings", "Reset all bindings", "Reset every action to its default.", chords![KeyCode::Char('r') => CTRL], SETTINGS_LIST),
    definition!(AiSend, "AI chat", "Send or activate", "Send the composed message, or open the selected conversation item, command, or picker row.", chords![KeyCode::Enter => NONE], CHAT),
    definition!(AiNewline, "AI chat", "New line", "Insert a line break in the composer. Terminals without Shift+Enter support can use Alt+Enter.", chords![KeyCode::Enter => ALT, KeyCode::Enter => SHIFT], CHAT),
    definition!(AiStop, "AI chat", "Stop reply", "Stop the reply that is streaming. Nothing is sent to SSH.", chords![KeyCode::Char('c') => CTRL], CHAT),
    definition!(AiCommands, "AI chat", "Chat commands", "List every chat command: conversations, context, model, naming, export, and settings.", chords![KeyCode::Char('k') => CTRL], CHAT),
    definition!(AiNextArea, "AI chat", "Next area", "Move between the composer, the conversation, and the toolbar.", chords![KeyCode::Tab => NONE], CHAT),
    definition!(AiPreviousArea, "AI chat", "Previous area", "Move backward between the composer, the conversation, and the toolbar.", chords![KeyCode::Tab => SHIFT], CHAT),
    definition!(AiUp, "AI chat", "Up", "Move up a composer line, conversation item, or list row.", chords![KeyCode::Up => NONE], CHAT),
    definition!(AiDown, "AI chat", "Down", "Move down a composer line, conversation item, or list row.", chords![KeyCode::Down => NONE], CHAT),
    definition!(AiPageUp, "AI chat", "Page up", "Scroll the conversation or list up one page.", chords![KeyCode::PageUp => NONE], CHAT),
    definition!(AiPageDown, "AI chat", "Page down", "Scroll the conversation or list down one page.", chords![KeyCode::PageDown => NONE], CHAT),
    definition!(SidebarClearFilter, "Sidebar", "Clear filter", "Clear a kept sidebar filter and restore the previous selection.", chords![KeyCode::Esc => NONE], SIDEBAR_CONTEXTS),
    definition!(AiPermission, "AI chat", "Change permission", "Cycle this chat's permission level up to the maximum allowed in Settings.", chords![KeyCode::Char('p') => CTRL], CHAT),
];

#[derive(Clone, Debug)]
pub struct Bindings {
    overrides: Vec<Option<Vec<Chord>>>,
    effective: Vec<Vec<Chord>>,
    labels: Vec<String>,
    primaries: Vec<String>,
    sequences: Vec<String>,
}

impl Default for Bindings {
    fn default() -> Self {
        Self::from_overrides(vec![None; ACTION_COUNT])
            .expect("the built-in shortcut registry must be valid")
    }
}

impl Bindings {
    pub fn matches(&self, action: Shortcut, key: KeyEvent) -> bool {
        if key.kind == KeyEventKind::Release {
            return false;
        }
        let Some(chord) = normalize_event(key) else {
            return false;
        };
        self.effective[action as usize].contains(&chord)
    }

    pub fn matches_prefix(&self, key: KeyEvent, over_overlay: bool) -> bool {
        if key.kind == KeyEventKind::Release {
            return false;
        }
        let Some(chord) = normalize_event(key) else { return false; };
        if !self.effective[Shortcut::Prefix as usize].contains(&chord) {
            return false;
        }
        if !over_overlay {
            return true;
        }
        // Existing per-context bindings and printable input keep ownership inside editors.
        if matches!(chord.code, KeyCode::Char(_))
            && !chord.modifiers.intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
        {
            return false;
        }
        let contexts = SEARCH | FORM_CONTEXTS | DIALOG | SNIPPET | MENU_CONTEXTS | CHAT;
        !DEFINITIONS.iter().any(|definition| {
            definition.contexts & contexts != 0
                && self.effective[definition.id as usize].contains(&chord)
        })
    }

    /// All keys for `action`, or "Not bound" when an additive default yielded to a custom key.
    pub fn label(&self, action: Shortcut) -> &str {
        &self.labels[action as usize]
    }

    /// First key for `action`; empty when the action has no effective key.
    pub fn primary(&self, action: Shortcut) -> &str {
        &self.primaries[action as usize]
    }

    pub fn primary_event(&self, action: Shortcut) -> Option<KeyEvent> {
        let chord = self.effective[action as usize].first()?;
        Some(KeyEvent::new(chord.code, chord.modifiers))
    }

    /// A newer action's default left unbound because an older custom binding uses its key.
    pub fn default_yielded(&self, action: Shortcut) -> bool {
        self.overrides[action as usize].is_none() && self.effective[action as usize].is_empty()
    }

    pub fn sequence(&self, action: Shortcut) -> &str {
        &self.sequences[action as usize]
    }

    pub fn edit_text(&self, action: Shortcut) -> String {
        self.effective[action as usize]
            .iter()
            .map(format_chord)
            .collect::<Vec<_>>()
            .join(", ")
    }

    pub fn is_custom(&self, action: Shortcut) -> bool {
        self.overrides[action as usize].is_some()
    }

    pub fn with_binding(&self, action: Shortcut, text: &str) -> Result<Self> {
        let parsed = parse_binding(text)
            .with_context(|| format!("invalid binding for {}", action.definition().title))?;
        let mut overrides = self.overrides.clone();
        overrides[action as usize] = Some(parsed);
        Self::from_overrides(overrides)
    }

    pub fn with_default(&self, action: Shortcut) -> Result<Self> {
        let mut overrides = self.overrides.clone();
        overrides[action as usize] = None;
        Self::from_overrides(overrides)
    }

    fn from_overrides(overrides: Vec<Option<Vec<Chord>>>) -> Result<Self> {
        ensure!(
            DEFINITIONS.len() == ACTION_COUNT && overrides.len() == ACTION_COUNT,
            "shortcut registry has an invalid action count"
        );

        let prefix = overrides[Shortcut::Prefix as usize]
            .as_deref()
            .unwrap_or(Shortcut::Prefix.definition().defaults);
        let mut effective = DEFINITIONS
            .iter()
            .map(|definition| {
                if let Some(custom) = &overrides[definition.id as usize] {
                    custom.clone()
                } else if definition.id == Shortcut::PrefixLiteral {
                    prefix.to_vec()
                } else {
                    definition.defaults.to_vec()
                }
            })
            .collect::<Vec<_>>();
        for action in ADDITIVE {
            let definition = action.definition();
            let yields = overrides[action as usize].is_none()
                && DEFINITIONS.iter().any(|other| {
                    other.id != action
                        && !ADDITIVE.contains(&other.id)
                        && other.contexts & definition.contexts != 0
                        && effective[other.id as usize].iter().any(|chord| definition.defaults.contains(chord))
                });
            if yields {
                effective[action as usize].clear();
            }
        }

        validate_bindings(&effective)?;

        let labels = effective
            .iter()
            .map(|chords| if chords.is_empty() { "Not bound".to_owned() } else { format_chords(chords, " / ") })
            .collect::<Vec<_>>();
        let primaries = effective
            .iter()
            .map(|chords| chords.first().map(format_chord).unwrap_or_default())
            .collect::<Vec<_>>();
        let prefix_label = &labels[Shortcut::Prefix as usize];
        let sequences = DEFINITIONS
            .iter()
            .map(|definition| {
                let label = &labels[definition.id as usize];
                if definition.prefixed {
                    format!("{prefix_label} then {label}")
                } else {
                    label.clone()
                }
            })
            .collect();

        Ok(Self {
            overrides,
            effective,
            labels,
            primaries,
            sequences,
        })
    }

}

impl Serialize for Bindings {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let overrides = DEFINITIONS
            .iter()
            .filter_map(|definition| {
                self.overrides[definition.id as usize]
                    .as_ref()
                    .map(|chords| (definition.id, format_chords(chords, ", ")))
            })
            .collect::<BTreeMap<_, _>>();
        overrides.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Bindings {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let stored = BTreeMap::<Shortcut, String>::deserialize(deserializer)?;
        let mut overrides = vec![None; ACTION_COUNT];
        for (action, text) in stored {
            overrides[action as usize] = Some(
                parse_binding(&text)
                    .map_err(|error| de::Error::custom(format!("{}: {error:#}", action.definition().title)))?,
            );
        }
        Self::from_overrides(overrides).map_err(de::Error::custom)
    }
}

fn validate_bindings(effective: &[Vec<Chord>]) -> Result<()> {
    for (index, definition) in DEFINITIONS.iter().enumerate() {
        ensure!(
            !effective[index].is_empty() || ADDITIVE.contains(&definition.id),
            "{} must have at least one key",
            definition.title
        );
        for later in (index + 1)..DEFINITIONS.len() {
            let other = &DEFINITIONS[later];
            if definition.contexts & other.contexts == 0 {
                continue;
            }
            if let Some(chord) = effective[index]
                .iter()
                .find(|chord| effective[later].contains(chord))
            {
                bail!(
                    "{} conflicts with {} on {}",
                    definition.title,
                    other.title,
                    format_chord(chord)
                );
            }
        }
    }
    Ok(())
}

fn parse_binding(text: &str) -> Result<Vec<Chord>> {
    let mut chords = Vec::new();
    for part in text.split(',') {
        let part = part.trim();
        ensure!(!part.is_empty(), "empty key between commas");
        let chord = parse_chord(part)?;
        ensure!(
            !chords.contains(&chord),
            "duplicate key {}",
            format_chord(&chord)
        );
        chords.push(chord);
    }
    ensure!(!chords.is_empty(), "a binding must contain at least one key");
    Ok(chords)
}

fn parse_chord(text: &str) -> Result<Chord> {
    let pieces = text.split('+').map(str::trim).collect::<Vec<_>>();
    ensure!(
        !pieces.is_empty() && pieces.iter().all(|piece| !piece.is_empty()),
        "malformed key '{text}'"
    );

    let mut modifiers = KeyModifiers::NONE;
    for modifier in &pieces[..pieces.len() - 1] {
        let value = if modifier.eq_ignore_ascii_case("ctrl")
            || modifier.eq_ignore_ascii_case("control")
        {
            KeyModifiers::CONTROL
        } else if modifier.eq_ignore_ascii_case("alt") {
            KeyModifiers::ALT
        } else if modifier.eq_ignore_ascii_case("shift") {
            KeyModifiers::SHIFT
        } else {
            bail!("unknown modifier '{modifier}' in '{text}'");
        };
        ensure!(
            !modifiers.contains(value),
            "duplicate modifier '{modifier}' in '{text}'"
        );
        modifiers.insert(value);
    }

    let key = pieces[pieces.len() - 1];
    let code = parse_key_code(key)?;
    let chord = normalize_code(code, modifiers)
        .ok_or_else(|| anyhow::anyhow!("key '{text}' cannot be represented by the terminal"))?;
    Ok(chord)
}

fn parse_key_code(key: &str) -> Result<KeyCode> {
    let named = if key.eq_ignore_ascii_case("enter") {
        Some(KeyCode::Enter)
    } else if key.eq_ignore_ascii_case("esc") || key.eq_ignore_ascii_case("escape") {
        Some(KeyCode::Esc)
    } else if key.eq_ignore_ascii_case("tab") {
        Some(KeyCode::Tab)
    } else if key.eq_ignore_ascii_case("space") {
        Some(KeyCode::Char(' '))
    } else if key.eq_ignore_ascii_case("comma") {
        Some(KeyCode::Char(','))
    } else if key.eq_ignore_ascii_case("plus") {
        Some(KeyCode::Char('+'))
    } else if key.eq_ignore_ascii_case("backspace") {
        Some(KeyCode::Backspace)
    } else if key.eq_ignore_ascii_case("delete") {
        Some(KeyCode::Delete)
    } else if key.eq_ignore_ascii_case("insert") {
        Some(KeyCode::Insert)
    } else if key.eq_ignore_ascii_case("home") {
        Some(KeyCode::Home)
    } else if key.eq_ignore_ascii_case("end") {
        Some(KeyCode::End)
    } else if key.eq_ignore_ascii_case("up") {
        Some(KeyCode::Up)
    } else if key.eq_ignore_ascii_case("down") {
        Some(KeyCode::Down)
    } else if key.eq_ignore_ascii_case("left") {
        Some(KeyCode::Left)
    } else if key.eq_ignore_ascii_case("right") {
        Some(KeyCode::Right)
    } else if key.eq_ignore_ascii_case("pageup") || key.eq_ignore_ascii_case("page up") {
        Some(KeyCode::PageUp)
    } else if key.eq_ignore_ascii_case("pagedown") || key.eq_ignore_ascii_case("page down") {
        Some(KeyCode::PageDown)
    } else {
        None
    };
    if let Some(code) = named {
        return Ok(code);
    }

    if key.len() >= 2 && matches!(key.as_bytes()[0], b'f' | b'F') {
        if let Ok(number) = key[1..].parse::<u8>() {
            ensure!((1..=24).contains(&number), "function key must be F1 through F24");
            return Ok(KeyCode::F(number));
        }
    }

    let mut characters = key.chars();
    let character = characters
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing key name"))?;
    ensure!(characters.next().is_none(), "unknown key name '{key}'");
    ensure!(
        !character.is_control() && !character.is_whitespace(),
        "use a named key for whitespace or control characters"
    );
    Ok(KeyCode::Char(character))
}

/// A pressed key as shortcut labels show it, or None for keys bindings cannot express.
pub fn key_label(key: KeyEvent) -> Option<String> {
    normalize_event(key).map(|chord| format_chord(&chord))
}

fn normalize_event(key: KeyEvent) -> Option<Chord> {
    normalize_code(key.code, key.modifiers)
}

fn normalize_code(mut code: KeyCode, mut modifiers: KeyModifiers) -> Option<Chord> {
    if modifiers.intersects(KeyModifiers::SUPER | KeyModifiers::HYPER | KeyModifiers::META) {
        return None;
    }

    if code == KeyCode::BackTab {
        code = KeyCode::Tab;
        modifiers.insert(KeyModifiers::SHIFT);
    }

    if let KeyCode::Char(character) = code {
        match character {
            '\t' => {
                code = KeyCode::Tab;
                modifiers = KeyModifiers::NONE;
            }
            '\r' | '\n' => {
                code = KeyCode::Enter;
                modifiers = KeyModifiers::NONE;
            }
            '\u{1b}' => {
                code = KeyCode::Esc;
                modifiers = KeyModifiers::NONE;
            }
            '\u{8}' | '\u{7f}' => {
                code = KeyCode::Backspace;
                modifiers = KeyModifiers::NONE;
            }
            character => {
                let mut canonical = character;
                if character.is_uppercase() {
                    let mut lowercase = character.to_lowercase();
                    let first = lowercase.next().unwrap_or(character);
                    if lowercase.next().is_none() {
                        canonical = first;
                    }
                    if !modifiers.intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) {
                        modifiers.insert(KeyModifiers::SHIFT);
                    }
                }
                if modifiers.contains(KeyModifiers::SHIFT) {
                    if let Some(shifted) = shifted_ascii_character(canonical) {
                        canonical = shifted;
                        modifiers.remove(KeyModifiers::SHIFT);
                    } else if !canonical.is_alphanumeric() {
                        modifiers.remove(KeyModifiers::SHIFT);
                    }
                }
                code = KeyCode::Char(canonical);
            }
        }
    }

    if modifiers == KeyModifiers::CONTROL {
        code = match code {
            KeyCode::Char('i') => KeyCode::Tab,
            KeyCode::Char('m') | KeyCode::Char('j') => KeyCode::Enter,
            KeyCode::Char('[') => KeyCode::Esc,
            KeyCode::Char('h') | KeyCode::Char('?') => KeyCode::Backspace,
            _ => {
                return Some(Chord { code, modifiers });
            }
        };
        modifiers = KeyModifiers::NONE;
    }

    match code {
        KeyCode::Backspace
        | KeyCode::Enter
        | KeyCode::Left
        | KeyCode::Right
        | KeyCode::Up
        | KeyCode::Down
        | KeyCode::Home
        | KeyCode::End
        | KeyCode::PageUp
        | KeyCode::PageDown
        | KeyCode::Tab
        | KeyCode::Delete
        | KeyCode::Insert
        | KeyCode::Esc
        | KeyCode::Char(_) => Some(Chord { code, modifiers }),
        KeyCode::F(number) if (1..=24).contains(&number) => Some(Chord { code, modifiers }),
        _ => None,
    }
}

fn shifted_ascii_character(character: char) -> Option<char> {
    Some(match character {
        '`' => '~',
        '1' => '!',
        '2' => '@',
        '3' => '#',
        '4' => '$',
        '5' => '%',
        '6' => '^',
        '7' => '&',
        '8' => '*',
        '9' => '(',
        '0' => ')',
        '-' => '_',
        '=' => '+',
        '[' => '{',
        ']' => '}',
        '\\' => '|',
        ';' => ':',
        '\'' => '"',
        ',' => '<',
        '.' => '>',
        '/' => '?',
        _ => return None,
    })
}

fn format_chords(chords: &[Chord], separator: &str) -> String {
    chords
        .iter()
        .map(format_chord)
        .collect::<Vec<_>>()
        .join(separator)
}

fn format_chord(chord: &Chord) -> String {
    let mut result = String::new();
    if chord.modifiers.contains(KeyModifiers::CONTROL) {
        result.push_str("Ctrl+");
    }
    if chord.modifiers.contains(KeyModifiers::ALT) {
        result.push_str("Alt+");
    }
    if chord.modifiers.contains(KeyModifiers::SHIFT) {
        result.push_str("Shift+");
    }
    match chord.code {
        KeyCode::Backspace => result.push_str("Backspace"),
        KeyCode::Enter => result.push_str("Enter"),
        KeyCode::Left => result.push_str("Left"),
        KeyCode::Right => result.push_str("Right"),
        KeyCode::Up => result.push_str("Up"),
        KeyCode::Down => result.push_str("Down"),
        KeyCode::Home => result.push_str("Home"),
        KeyCode::End => result.push_str("End"),
        KeyCode::PageUp => result.push_str("PageUp"),
        KeyCode::PageDown => result.push_str("PageDown"),
        KeyCode::Tab => result.push_str("Tab"),
        KeyCode::Delete => result.push_str("Delete"),
        KeyCode::Insert => result.push_str("Insert"),
        KeyCode::Esc => result.push_str("Esc"),
        KeyCode::F(number) => result.push_str(&format!("F{number}")),
        KeyCode::Char(' ') => result.push_str("Space"),
        KeyCode::Char(',') => result.push_str("Comma"),
        KeyCode::Char('+') => result.push_str("Plus"),
        KeyCode::Char(character) if character.is_alphabetic() => {
            if chord.modifiers.is_empty() {
                result.push(character);
            } else {
                let mut uppercase = character.to_uppercase();
                let first = uppercase.next().unwrap_or(character);
                if uppercase.next().is_none() {
                    result.push(first);
                } else {
                    result.push(character);
                }
            }
        }
        KeyCode::Char(character) => result.push(character),
        _ => unreachable!("only representable shortcut codes are stored"),
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(code: KeyCode, modifiers: KeyModifiers) -> KeyEvent {
        KeyEvent::new(code, modifiers)
    }

    #[test]
    fn overlapping_contexts_conflict_without_mutation() {
        let bindings = Bindings::default();
        assert!(bindings.with_binding(Shortcut::SidebarAdd, "q").is_err());
        assert_eq!(bindings.edit_text(Shortcut::SidebarAdd), "a");
        assert!(bindings.matches(
            Shortcut::SidebarAdd,
            key(KeyCode::Char('a'), KeyModifiers::NONE)
        ));
    }

    #[test]
    fn disjoint_contexts_can_reuse_a_key() {
        let bindings = Bindings::default()
            .with_binding(Shortcut::Reconnect, "Ctrl+G")
            .unwrap()
            .with_binding(Shortcut::RetrySave, "Ctrl+G")
            .unwrap();
        let event = key(KeyCode::Char('g'), KeyModifiers::CONTROL);
        assert!(bindings.matches(Shortcut::Reconnect, event));
        assert!(bindings.matches(Shortcut::RetrySave, event));
    }
    #[test]
    fn overlay_prefix_preserves_text_and_existing_context_bindings() {
        let bindings = Bindings::default().with_binding(Shortcut::Prefix, "v").unwrap();
        let text = key(KeyCode::Char('v'), KeyModifiers::NONE);
        assert!(bindings.matches_prefix(text, false));
        assert!(!bindings.matches_prefix(text, true));

        let bindings = Bindings::default().with_binding(Shortcut::Prefix, "F1").unwrap();
        let function = key(KeyCode::F(1), KeyModifiers::NONE);
        assert!(bindings.matches_prefix(function, true));
        let bindings = bindings.with_binding(Shortcut::Submit, "F1").unwrap();
        assert!(bindings.matches_prefix(function, false));
        assert!(!bindings.matches_prefix(function, true));

        let bindings = Bindings::default().with_binding(Shortcut::Prefix, "Ctrl+U").unwrap();
        let clear = key(KeyCode::Char('u'), KeyModifiers::CONTROL);
        assert!(bindings.matches_prefix(clear, false));
        assert!(!bindings.matches_prefix(clear, true));
    }


    #[test]
    fn normalization_handles_legacy_controls_shift_and_release() {
        let bindings = Bindings::default();
        assert!(bindings.matches(
            Shortcut::SearchKeep,
            key(KeyCode::Char('i'), KeyModifiers::CONTROL)
        ));
        assert!(bindings.with_binding(Shortcut::Submit, "Ctrl+I").is_err());

        let shifted = bindings
            .with_binding(Shortcut::SidebarAdd, "Shift+K")
            .unwrap();
        assert!(shifted.matches(
            Shortcut::SidebarAdd,
            key(KeyCode::Char('K'), KeyModifiers::SHIFT)
        ));
        let mut release = key(KeyCode::Char('K'), KeyModifiers::SHIFT);
        release.kind = KeyEventKind::Release;
        assert!(!shifted.matches(Shortcut::SidebarAdd, release));
        assert_eq!(shifted.edit_text(Shortcut::SidebarAdd), "Shift+K");
        let punctuation = bindings
            .with_binding(Shortcut::SidebarAdd, "!")
            .unwrap();
        assert!(punctuation.matches(
            Shortcut::SidebarAdd,
            key(KeyCode::Char('1'), KeyModifiers::SHIFT)
        ));
        let uppercase = bindings.with_binding(Shortcut::SidebarAdd, "Z").unwrap();
        assert!(uppercase.matches(
            Shortcut::SidebarAdd,
            key(KeyCode::Char('Z'), KeyModifiers::NONE)
        ));
        assert!(!uppercase.matches(
            Shortcut::SidebarAdd,
            key(KeyCode::Char('z'), KeyModifiers::NONE)
        ));
    }

    #[test]
    fn literal_prefix_tracks_prefix_until_explicitly_overridden() {
        let bindings = Bindings::default()
            .with_binding(Shortcut::Prefix, "Ctrl+G")
            .unwrap();
        let ctrl_g = key(KeyCode::Char('g'), KeyModifiers::CONTROL);
        assert!(bindings.matches(Shortcut::Prefix, ctrl_g));
        assert!(bindings.matches(Shortcut::PrefixLiteral, ctrl_g));

        let custom_literal = bindings
            .with_binding(Shortcut::PrefixLiteral, "Alt+L")
            .unwrap()
            .with_binding(Shortcut::Prefix, "Ctrl+X")
            .unwrap();
        assert!(custom_literal.matches(
            Shortcut::PrefixLiteral,
            key(KeyCode::Char('l'), KeyModifiers::ALT)
        ));
        assert!(!custom_literal.matches(
            Shortcut::PrefixLiteral,
            key(KeyCode::Char('x'), KeyModifiers::CONTROL)
        ));
        let reset = custom_literal
            .with_default(Shortcut::PrefixLiteral)
            .unwrap();
        assert!(reset.matches(
            Shortcut::PrefixLiteral,
            key(KeyCode::Char('x'), KeyModifiers::CONTROL)
        ));
    }

    #[test]
    fn resetting_a_dynamic_default_surfaces_conflicts_without_mutation() {
        let bindings = Bindings::default()
            .with_binding(Shortcut::PrefixLiteral, "Alt+L")
            .unwrap()
            .with_binding(Shortcut::PrefixSidebar, "Ctrl+B")
            .unwrap();
        assert!(bindings.with_default(Shortcut::PrefixLiteral).is_err());
        assert_eq!(bindings.edit_text(Shortcut::PrefixLiteral), "Alt+L");
    }

    #[test]
    fn additive_defaults_yield_to_older_custom_keys_until_the_conflict_is_removed() {
        // A configuration saved before Clear filter and Change permission existed.
        let stored: Bindings = serde_json::from_str(r#"{"ai_commands":"Ctrl+P","sidebar_activate":"Enter, Esc"}"#).unwrap();
        let ctrl_p = key(KeyCode::Char('p'), KeyModifiers::CONTROL);
        let escape = key(KeyCode::Esc, KeyModifiers::NONE);
        assert!(stored.matches(Shortcut::AiCommands, ctrl_p));
        assert!(stored.matches(Shortcut::SidebarActivate, escape));
        assert!(!stored.matches(Shortcut::AiPermission, ctrl_p));
        assert!(!stored.matches(Shortcut::SidebarClearFilter, escape));
        assert!(stored.default_yielded(Shortcut::AiPermission));
        assert_eq!(stored.label(Shortcut::AiPermission), "Not bound");
        assert!(stored.primary_event(Shortcut::SidebarClearFilter).is_none());
        assert_eq!(serde_json::to_string(&stored).unwrap(), r#"{"sidebar_activate":"Enter, Esc","ai_commands":"Ctrl+P"}"#);

        let restored = stored.with_default(Shortcut::AiCommands).unwrap();
        assert!(restored.matches(Shortcut::AiPermission, ctrl_p));
        assert!(!restored.default_yielded(Shortcut::AiPermission));
        let restored = restored.with_default(Shortcut::SidebarActivate).unwrap();
        assert!(restored.matches(Shortcut::SidebarClearFilter, escape));

        assert!(Bindings::default().with_binding(Shortcut::AiPermission, "Ctrl+K").is_err(), "explicit conflicts still fail");
    }
}
