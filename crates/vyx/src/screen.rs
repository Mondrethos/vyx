use std::io::{self, IsTerminal};

use anyhow::{Result, ensure};
use crossterm::{
    cursor::Show,
    event::{
        DisableBracketedPaste, DisableMouseCapture, EnableBracketedPaste, EnableMouseCapture, Event,
    },
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Frame, Terminal, TerminalOptions, Viewport,
    backend::{Backend, ClearType, CrosstermBackend, WindowSize},
    buffer::Cell,
    layout::{Position, Rect, Size},
    text::Span,
};
use tokio::signal::unix::{Signal, SignalKind, signal};

use crate::workspace::{DisplayWriter, Workspace, WorkspaceEvent};

/// The worker has no TTY. Its geometry comes from the attached frontend, not OS queries.
struct WorkspaceBackend {
    inner: CrosstermBackend<DisplayWriter>,
    size: Size,
    cursor: Position,
}

impl Backend for WorkspaceBackend {
    type Error = io::Error;

    fn draw<'a, I>(&mut self, content: I) -> io::Result<()>
    where
        I: Iterator<Item = (u16, u16, &'a Cell)>,
    {
        let mut last = None;
        self.inner.draw(content.inspect(|&(x, y, cell)| last = Some((x, y, cell))))?;
        if let Some((x, y, cell)) = last {
            self.cursor = Position {
                x: x.saturating_add(Span::raw(cell.symbol()).width() as u16)
                    .min(self.size.width.saturating_sub(1)),
                y,
            };
        }
        Ok(())
    }

    fn hide_cursor(&mut self) -> io::Result<()> {
        self.inner.hide_cursor()
    }

    fn show_cursor(&mut self) -> io::Result<()> {
        self.inner.show_cursor()
    }

    fn get_cursor_position(&mut self) -> io::Result<Position> {
        Ok(self.cursor)
    }

    fn set_cursor_position<P: Into<Position>>(&mut self, position: P) -> io::Result<()> {
        let position = position.into();
        self.inner.set_cursor_position(position)?;
        self.cursor = position;
        Ok(())
    }

    fn clear(&mut self) -> io::Result<()> {
        self.inner.clear()
    }

    fn clear_region(&mut self, clear_type: ClearType) -> io::Result<()> {
        self.inner.clear_region(clear_type)
    }

    fn append_lines(&mut self, n: u16) -> io::Result<()> {
        self.inner.append_lines(n)?;
        self.cursor.y = self.cursor.y.saturating_add(n).min(self.size.height.saturating_sub(1));
        Ok(())
    }

    fn size(&self) -> io::Result<Size> {
        Ok(self.size)
    }

    fn window_size(&mut self) -> io::Result<WindowSize> {
        Ok(WindowSize {
            columns_rows: self.size,
            // The IPC protocol reports character cells only.
            pixels: Size { width: 0, height: 0 },
        })
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

pub struct Screen {
    terminal: Terminal<WorkspaceBackend>,
    workspace: Workspace,
    attachment_generation: u64,
    connect_request: Option<String>,
    interrupt: Signal,
    terminate: Signal,
    hangup: Signal,
    quit: Signal,
}

pub enum ScreenEvent {
    Input(Event),
    ConnectRequested,
}

pub fn restore_terminal() {
    let _ = execute!(
        io::stdout(),
        DisableBracketedPaste,
        DisableMouseCapture,
        Show,
        LeaveAlternateScreen
    );
    let _ = disable_raw_mode();
}

/// Only the attached frontend owns the user's physical terminal.
pub struct TerminalGuard;

impl TerminalGuard {
    pub fn enter() -> Result<Self> {
        ensure!(
            io::stdin().is_terminal() && io::stdout().is_terminal(),
            "vyx requires an interactive terminal"
        );
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            restore_terminal();
            previous(info);
        }));
        enable_raw_mode()?;
        if let Err(error) = execute!(
            io::stdout(),
            EnterAlternateScreen,
            EnableMouseCapture,
            EnableBracketedPaste
        ) {
            restore_terminal();
            return Err(error.into());
        }
        Ok(Self)
    }
}

impl Screen {
    pub fn open(workspace: Workspace) -> Result<Self> {
        let terminal = Terminal::with_options(
            WorkspaceBackend {
                inner: CrosstermBackend::new(workspace.writer()),
                size: Size { width: 80, height: 24 },
                cursor: Position { x: 0, y: 0 },
            },
            TerminalOptions {
                viewport: Viewport::Fixed(Rect::new(0, 0, 80, 24)),
            },
        )?;
        Ok(Self {
            terminal,
            workspace,
            attachment_generation: 0,
            connect_request: None,
            interrupt: signal(SignalKind::interrupt())?,
            terminate: signal(SignalKind::terminate())?,
            hangup: signal(SignalKind::hangup())?,
            quit: signal(SignalKind::quit())?,
        })
    }

    pub async fn draw(&mut self, render: impl FnOnce(&mut Frame<'_>)) -> Result<()> {
        self.terminal.draw(render)?;
        // Backend cursor and clear operations also flush, so publish only here.
        self.terminal.backend_mut().inner.writer_mut().publish().await;
        Ok(())
    }

    /// Explicit user copy only. OSC 52 asks the attached frontend terminal to set its
    /// clipboard; terminals may ignore or refuse it, so delivery never confirms a copy.
    pub async fn copy_to_clipboard(&mut self, text: &str) -> Result<()> {
        ensure!(self.is_attached(), "No terminal is attached");
        let sequence = osc52(text)?;
        let writer = self.terminal.backend_mut().inner.writer_mut();
        io::Write::write_all(writer, sequence.as_bytes())?;
        writer.publish().await;
        Ok(())
    }

    pub fn is_attached(&self) -> bool {
        self.workspace.is_attached()
    }

    pub fn attachment_generation(&self) -> u64 {
        self.attachment_generation
    }

    /// Current frontend size as (columns, rows); resize events update it before they arrive.
    pub fn size(&self) -> (u16, u16) {
        let size = self.terminal.backend().size;
        (size.width, size.height)
    }

    /// Fences keyboard, paste and mouse input admitted before authentication completed.
    /// Queued resize, focus, connection requests and attachment/shutdown events survive.
    /// Call synchronously before returning control to an unlocked workspace.
    pub fn fence_authentication_input(&mut self) {
        self.workspace.fence_authentication_input();
    }

    /// Startup retains the request until the vault is unlocked and the app can resolve it.
    pub fn take_connect_request(&mut self) -> Option<String> {
        self.connect_request.take()
    }

    pub fn detach(&self) {
        self.workspace.detach();
    }

    pub async fn finish(&mut self, error: Option<String>) -> Result<()> {
        self.workspace.finish(error).await
    }

    /// Explicit detach is a focus event; worker signals or unexpected client loss end the app.
    pub async fn next_event(&mut self) -> Result<Option<ScreenEvent>> {
        let event = tokio::select! {
            event = self.workspace.next_event() => event,
            _ = self.interrupt.recv() => return Ok(None),
            _ = self.terminate.recv() => return Ok(None),
            _ = self.hangup.recv() => return Ok(None),
            _ = self.quit.recv() => return Ok(None),
        };
        let event = match event {
            Some(WorkspaceEvent::Attached(columns, rows)) => {
                self.attachment_generation = self.attachment_generation.wrapping_add(1);
                self.connect_request = None;
                Event::Resize(columns, rows)
            }
            Some(WorkspaceEvent::Detached) => {
                self.connect_request = None;
                Event::FocusLost
            }
            Some(WorkspaceEvent::Input(event)) => event,
            Some(WorkspaceEvent::Connect(server)) => {
                self.connect_request = Some(server);
                return Ok(Some(ScreenEvent::ConnectRequested));
            }
            None => return Ok(None),
        };
        if let Event::Resize(columns, rows) = event {
            // Even an unchanged size invalidates the previous client's diff buffer.
            self.terminal.backend_mut().size = Size { width: columns, height: rows };
            self.terminal.resize(Rect::new(0, 0, columns, rows))?;
        }
        Ok(Some(ScreenEvent::Input(event)))
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        restore_terminal();
    }
}

/// Remote/UI chrome must never carry terminal controls; cells render plain text only.
pub fn safe_text(text: &str) -> String {
    text.chars()
        .filter_map(|c| match c {
            '\n' | '\r' | '\t' => Some(' '),
            _ if c.is_control() => None,
            _ => Some(c),
        })
        .take(4096)
        .collect()
}

const MAX_CLIPBOARD_BYTES: usize = 64 * 1024;

/// Clipboard text keeps newlines and tabs but never other terminal controls, so a later
/// paste cannot smuggle escape sequences. Base64 keeps the payload inert inside OSC 52.
fn osc52(text: &str) -> Result<String> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let text: String = text.chars()
        .filter(|c| matches!(c, '\n' | '\t') || !(c.is_control() || matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')))
        .collect();
    ensure!(!text.is_empty(), "Nothing to copy");
    ensure!(text.len() <= MAX_CLIPBOARD_BYTES, "Copy is limited to {} KiB", MAX_CLIPBOARD_BYTES / 1024);
    let bytes = text.as_bytes();
    let mut sequence = String::with_capacity(bytes.len().div_ceil(3) * 4 + 8);
    sequence.push_str("\x1b]52;c;");
    for chunk in bytes.chunks(3) {
        let value = chunk.iter().enumerate()
            .fold(0u32, |value, (index, byte)| value | u32::from(*byte) << (16 - 8 * index));
        for index in 0..4 {
            sequence.push(if index <= chunk.len() { char::from(ALPHABET[(value >> (18 - 6 * index) & 63) as usize]) } else { '=' });
        }
    }
    sequence.push('\x07');
    Ok(sequence)
}

#[cfg(test)]
mod tests {
    use super::osc52;

    #[test]
    fn clipboard_payload_is_base64_without_terminal_controls() {
        assert_eq!(osc52("hi\n").unwrap(), "\x1b]52;c;aGkK\x07");
        assert_eq!(osc52("a\tb").unwrap(), "\x1b]52;c;YQli\x07");
        assert_eq!(osc52("ab\x1b]0;x\x07c\u{202e}").unwrap(), osc52("ab]0;xc").unwrap());
        assert!(osc52("\x1b\x07").is_err());
        assert!(osc52(&"a".repeat(64 * 1024 + 1)).is_err());
    }
}
