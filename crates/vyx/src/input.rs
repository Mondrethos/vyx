use anyhow::{Result, ensure};
use bytes::Bytes;

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Focus {
    Sidebar,
    Terminal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InputMode {
    Sidebar,
    Terminal,
    Prefix { previous: Focus },
    Modal,
}

impl InputMode {
    pub fn focused(focus: Focus) -> Self {
        match focus {
            Focus::Sidebar => Self::Sidebar,
            Focus::Terminal => Self::Terminal,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrefixAction {
    ToggleSidebar,
    NextSession,
    PreviousSession,
    CloseSession,
    Sync,
    Detach,
    Quit,
    Help,
    LiteralPrefix,
    Cancel,
    Consume,
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
    ForgetHostKey,
    Sync,
    RetrySave,
    Quit,
    None,
}

pub fn is_key_input(key: KeyEvent) -> bool {
    matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat)
}

pub fn is_ctrl_b(key: KeyEvent) -> bool {
    key.code == KeyCode::Char('b')
        && key.modifiers.contains(KeyModifiers::CONTROL)
        && !key.modifiers.contains(KeyModifiers::ALT)
}

pub fn prefix_action(key: KeyEvent) -> PrefixAction {
    if is_ctrl_b(key) {
        return PrefixAction::LiteralPrefix;
    }
    if key.code == KeyCode::Esc {
        return PrefixAction::Cancel;
    }
    if key
        .modifiers
        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
    {
        return PrefixAction::Consume;
    }
    match key.code {
        KeyCode::Char('b') => PrefixAction::ToggleSidebar,
        KeyCode::Char('n') => PrefixAction::NextSession,
        KeyCode::Char('p') => PrefixAction::PreviousSession,
        KeyCode::Char('x') => PrefixAction::CloseSession,
        KeyCode::Char('s') => PrefixAction::Sync,
        KeyCode::Char('d') => PrefixAction::Detach,
        KeyCode::Char('q') => PrefixAction::Quit,
        KeyCode::Char('?') => PrefixAction::Help,
        _ => PrefixAction::Consume,
    }
}

pub fn sidebar_action(key: KeyEvent) -> SidebarAction {
    if key
        .modifiers
        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
    {
        return SidebarAction::None;
    }
    match key.code {
        KeyCode::Up | KeyCode::Char('k') => SidebarAction::Previous,
        KeyCode::Down | KeyCode::Char('j') => SidebarAction::Next,
        KeyCode::Left => SidebarAction::Collapse,
        KeyCode::Right => SidebarAction::Expand,
        KeyCode::Enter => SidebarAction::Activate,
        KeyCode::Char('a') => SidebarAction::Add,
        KeyCode::Char('e') => SidebarAction::Edit,
        KeyCode::Char('d') => SidebarAction::Delete,
        KeyCode::Char('x') => SidebarAction::CloseSession,
        KeyCode::Char('/') => SidebarAction::Filter,
        KeyCode::Char('f') => SidebarAction::ForgetHostKey,
        KeyCode::Char('s') => SidebarAction::Sync,
        KeyCode::Char('r') => SidebarAction::RetrySave,
        KeyCode::Char('q') => SidebarAction::Quit,
        _ => SidebarAction::None,
    }
}

pub fn is_local_scrollback(key: KeyEvent) -> Option<i32> {
    if key.modifiers == KeyModifiers::SHIFT {
        match key.code {
            KeyCode::PageUp => Some(12),
            KeyCode::PageDown => Some(-12),
            _ => None,
        }
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
