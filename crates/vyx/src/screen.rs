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
    Frame, Terminal, TerminalOptions, Viewport, backend::CrosstermBackend, layout::Rect,
};
use tokio::signal::unix::{Signal, SignalKind, signal};

use crate::workspace::{DisplayWriter, Workspace, WorkspaceEvent};

pub type Backend = CrosstermBackend<DisplayWriter>;

pub struct Screen {
    terminal: Terminal<Backend>,
    workspace: Workspace,
    attachment_generation: u64,
    interrupt: Signal,
    terminate: Signal,
    hangup: Signal,
    quit: Signal,
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
            CrosstermBackend::new(workspace.writer()),
            TerminalOptions {
                viewport: Viewport::Fixed(Rect::new(0, 0, 80, 24)),
            },
        )?;
        Ok(Self {
            terminal,
            workspace,
            attachment_generation: 0,
            interrupt: signal(SignalKind::interrupt())?,
            terminate: signal(SignalKind::terminate())?,
            hangup: signal(SignalKind::hangup())?,
            quit: signal(SignalKind::quit())?,
        })
    }

    pub async fn draw(&mut self, render: impl FnOnce(&mut Frame<'_>)) -> Result<()> {
        self.terminal.draw(render)?;
        // Backend cursor and clear operations also flush, so publish only here.
        self.terminal.backend_mut().writer_mut().publish().await;
        Ok(())
    }

    pub fn is_attached(&self) -> bool {
        self.workspace.is_attached()
    }

    pub fn attachment_generation(&self) -> u64 {
        self.attachment_generation
    }

    pub fn detach(&self) {
        self.workspace.detach();
    }

    pub async fn finish(&mut self, error: Option<String>) -> Result<()> {
        self.workspace.finish(error).await
    }

    /// Client loss is a focus event; only worker termination ends the application.
    pub async fn next_event(&mut self) -> Result<Option<Event>> {
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
                Event::Resize(columns, rows)
            }
            Some(WorkspaceEvent::Detached) => Event::FocusLost,
            Some(WorkspaceEvent::Input(event)) => event,
            None => return Ok(None),
        };
        if let Event::Resize(columns, rows) = event {
            // Even an unchanged size invalidates the previous client's diff buffer.
            self.terminal.resize(Rect::new(0, 0, columns, rows))?;
        }
        Ok(Some(event))
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
