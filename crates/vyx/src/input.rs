use anyhow::{Result, ensure};
use bytes::Bytes;

use crossterm::event::{KeyEvent, KeyEventKind};

use crate::{shortcuts::{Bindings, Shortcut}, ui::catalog::RowKey};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Focus {
    Sidebar,
    Terminal,
    /// The Vyx AI panel owns the keyboard; no key or paste reaches SSH.
    Ai,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InputMode {
    Sidebar,
    Terminal,
    Ai,
    Search,
    Prefix { previous: Focus, key: KeyEvent },
    Modal,
}

impl InputMode {
    pub fn focused(focus: Focus) -> Self {
        match focus {
            Focus::Sidebar => Self::Sidebar,
            Focus::Terminal => Self::Terminal,
            Focus::Ai => Self::Ai,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrefixAction {
    ToggleSidebar,
    CycleLayout,
    NextSession,
    PreviousSession,
    CloseSession,
    Sync,
    Detach,
    Quit,
    Shortcuts,
    Settings,
    Extensions,
    AiChat,
    AiFocus,
    LiteralPrefix,
    Cancel,
    Consume,
}

impl PrefixAction {
    pub fn allowed_over_overlay(self) -> bool {
        matches!(self, Self::CycleLayout | Self::Quit | Self::Shortcuts | Self::Settings | Self::Extensions | Self::Cancel | Self::Consume)
    }

    /// Whether the command can run now. The command bar dims exactly the commands that
    /// dispatch refuses, so both decide from the same `PrefixContext`.
    pub fn applicable(self, context: &PrefixContext) -> bool {
        if context.quit_confirming {
            return matches!(self, Self::Quit | Self::Cancel | Self::Consume);
        }
        if context.too_small {
            return matches!(self, Self::Detach | Self::Quit | Self::Cancel | Self::Consume);
        }
        let over_overlay = !context.overlay
            || self.allowed_over_overlay()
            || (context.switch_over_dialog && matches!(self, Self::NextSession | Self::PreviousSession))
            || (self == Self::Detach && context.detach_over_overlay);
        over_overlay && match self {
            Self::NextSession | Self::PreviousSession => context.sessions > 1,
            Self::CloseSession => context.active_session,
            Self::LiteralPrefix => context.literal_target,
            _ => true,
        }
    }
}

/// Workspace state that decides which prefix commands apply, captured once per frame or
/// keypress so rendering and dispatch agree.
#[derive(Clone, Copy, Debug, Default)]
pub struct PrefixContext {
    /// The quit confirmation is open; only Quit and Cancel remain.
    pub quit_confirming: bool,
    /// The frame is below the minimum size; only Detach, Quit, and Cancel remain.
    pub too_small: bool,
    /// A menu, dialog, search, or extension surface owns the keyboard.
    pub overlay: bool,
    /// The open dialog lets the user switch sessions behind it.
    pub switch_over_dialog: bool,
    /// The current overlay may be left running while this client detaches.
    pub detach_over_overlay: bool,
    pub sessions: usize,
    pub active_session: bool,
    /// The literal prefix has a receiver: a connected active terminal that had the keyboard
    /// before the bar opened, or the focused AI composer.
    pub literal_target: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SidebarAction {
    Previous,
    Next,
    Collapse,
    Expand,
    Activate,
    Add,
    Edit,
    Delete,
    CloseSession,
    Filter,
    ClearFilter,
    Inspect,
    ForgetHostKey,
    Sync,
    RetrySave,
    Quit,
    None,
}

impl SidebarAction {
    /// Whether the action changes saved records or sync settings. While save durability is
    /// uncertain these are replaced by Retry save, because the vault refuses further writes.
    pub fn changes_saved_state(self, key: &RowKey) -> bool {
        match self {
            Self::Add | Self::Delete | Self::ForgetHostKey | Self::Sync => true,
            Self::Edit => !matches!(key, RowKey::Session(_)),
            _ => false,
        }
    }
}

pub fn is_key_input(key: KeyEvent) -> bool {
    matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat)
}

pub const PREFIX_COMMANDS: &[(Shortcut, PrefixAction)] = &[
    (Shortcut::PrefixSidebar, PrefixAction::ToggleSidebar),
    (Shortcut::PrefixLayout, PrefixAction::CycleLayout),
    (Shortcut::PrefixNextSession, PrefixAction::NextSession),
    (Shortcut::PrefixPreviousSession, PrefixAction::PreviousSession),
    (Shortcut::PrefixCloseSession, PrefixAction::CloseSession),
    (Shortcut::PrefixSync, PrefixAction::Sync),
    (Shortcut::PrefixDetach, PrefixAction::Detach),
    (Shortcut::PrefixQuit, PrefixAction::Quit),
    (Shortcut::PrefixShortcuts, PrefixAction::Shortcuts),
    (Shortcut::PrefixSettings, PrefixAction::Settings),
    (Shortcut::PrefixExtensions, PrefixAction::Extensions),
    (Shortcut::PrefixAiChat, PrefixAction::AiChat),
    (Shortcut::PrefixAiFocus, PrefixAction::AiFocus),
    (Shortcut::PrefixLiteral, PrefixAction::LiteralPrefix),
    (Shortcut::PrefixCancel, PrefixAction::Cancel),
];

pub fn prefix_action(key: KeyEvent, bindings: &Bindings) -> PrefixAction {
    PREFIX_COMMANDS.iter()
        .find_map(|&(shortcut, action)| bindings.matches(shortcut, key).then_some(action))
        .unwrap_or(PrefixAction::Consume)
}

pub fn sidebar_action(key: KeyEvent, bindings: &Bindings) -> SidebarAction {
    [
        (Shortcut::SidebarPrevious, SidebarAction::Previous),
        (Shortcut::SidebarNext, SidebarAction::Next),
        (Shortcut::SidebarCollapse, SidebarAction::Collapse),
        (Shortcut::SidebarExpand, SidebarAction::Expand),
        (Shortcut::SidebarActivate, SidebarAction::Activate),
        (Shortcut::SidebarAdd, SidebarAction::Add),
        (Shortcut::SidebarEdit, SidebarAction::Edit),
        (Shortcut::SidebarDelete, SidebarAction::Delete),
        (Shortcut::SidebarCloseSession, SidebarAction::CloseSession),
        (Shortcut::SidebarSearch, SidebarAction::Filter),
        (Shortcut::SidebarInspect, SidebarAction::Inspect),
        (Shortcut::SidebarForgetHostKey, SidebarAction::ForgetHostKey),
        (Shortcut::SidebarSync, SidebarAction::Sync),
        (Shortcut::SidebarQuit, SidebarAction::Quit),
        (Shortcut::SidebarClearFilter, SidebarAction::ClearFilter),
    ]
    .into_iter()
    .find_map(|(shortcut, action)| bindings.matches(shortcut, key).then_some(action))
    .unwrap_or(SidebarAction::None)
}

pub fn is_local_scrollback(key: KeyEvent, bindings: &Bindings) -> Option<i32> {
    if bindings.matches(Shortcut::ScrollUp, key) {
        Some(12)
    } else if bindings.matches(Shortcut::ScrollDown, key) {
        Some(-12)
    } else {
        None
    }
}

const INPUT_CHUNK: usize = 64 * 1024;

/// Retain one user submission without copying it into a queue of chunks.
/// While it drains, accept at most 64 KiB of additional input in order.
#[derive(Default)]
pub(crate) struct InputQueue {
    head: Bytes,
    following: Vec<u8>,
}

impl InputQueue {
    pub(crate) fn push(&mut self, bytes: Vec<u8>) -> Result<()> {
        if self.is_empty() {
            self.head = bytes.into();
        } else {
            ensure!(
                bytes.len() <= INPUT_CHUNK.saturating_sub(self.following.len()),
                "Terminal input is backed up; this input was not sent. Wait for the remote program or close the session"
            );
            self.following.extend_from_slice(&bytes);
        }
        Ok(())
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.head.is_empty() && self.following.is_empty()
    }

    pub(crate) fn next_chunk(&mut self) -> Bytes {
        if self.head.is_empty() {
            self.head = std::mem::take(&mut self.following).into();
        }
        self.head.split_to(self.head.len().min(INPUT_CHUNK))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_large_paste_stays_ordered_and_bounds_following_input() {
        let mut queue = InputQueue::default();
        queue.push(vec![b'a'; INPUT_CHUNK + 1]).unwrap();
        queue.push(vec![b'b'; INPUT_CHUNK]).unwrap();
        assert!(queue.push(vec![b'x']).is_err());
        let mut received = Vec::new();
        while !queue.is_empty() {
            let chunk = queue.next_chunk();
            assert!(chunk.len() <= INPUT_CHUNK);
            received.extend_from_slice(&chunk);
        }
        let mut expected = vec![b'a'; INPUT_CHUNK + 1];
        expected.extend(vec![b'b'; INPUT_CHUNK]);
        assert_eq!(received, expected);
    }
}
