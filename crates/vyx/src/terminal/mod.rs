mod input;
mod output;
mod replies;

use crossterm::event::{KeyEvent, MouseEvent};
use ratatui::layout::Rect;

use self::{
    output::OscFilter,
    replies::{OriginObserver, TerminalCallbacks, append_reply},
};

const SCROLLBACK_ROWS: usize = 2_000;

/// In-memory terminal emulator state. It owns no file descriptors and performs
/// no outer-terminal I/O; callers explicitly send returned reply bytes to SSH.
pub struct TerminalState {
    parser: vt100::Parser<TerminalCallbacks>,
    observer: OriginObserver,
    osc_filter: OscFilter,
    /// Remote bytes processed so far; quiescence checks compare it, nothing else.
    output_bytes: u64,
}

impl TerminalState {
    pub fn new(rows: u16, cols: u16) -> Self {
        let rows = rows.max(1);
        let cols = cols.max(1);
        Self {
            parser: vt100::Parser::new_with_callbacks(
                rows,
                cols,
                SCROLLBACK_ROWS,
                TerminalCallbacks::default(),
            ),
            observer: OriginObserver::new(rows),
            osc_filter: OscFilter::new(),
            output_bytes: 0,
        }
    }

    pub fn screen(&self) -> &vt100::Screen {
        self.parser.screen()
    }

    /// Total remote output processed, saturating.
    pub fn output_bytes(&self) -> u64 {
        self.output_bytes
    }

    /// Processes remote bytes and returns terminal protocol replies generated
    /// by this input. OSC payload is discarded before reaching either parser.
    pub fn process(&mut self, bytes: &[u8]) -> Vec<u8> {
        let Self {
            parser,
            observer,
            osc_filter,
            output_bytes,
        } = self;
        *output_bytes = output_bytes.saturating_add(bytes.len() as u64);
        let mut replies = Vec::new();
        osc_filter.process(bytes, |filtered| {
            process_filtered(parser, observer, filtered, &mut replies);
        });
        replies
    }

    pub fn resize(&mut self, rows: u16, cols: u16) {
        let rows = rows.max(1);
        let cols = cols.max(1);
        self.parser.screen_mut().set_size(rows, cols);
        self.observer.resize(rows);
    }

    pub fn key(&self, event: KeyEvent) -> Option<Vec<u8>> {
        input::key(self.parser.screen(), event)
    }

    pub fn paste(&self, text: &str) -> Vec<u8> {
        input::paste(self.parser.screen(), text)
    }

    pub fn mouse(&self, event: MouseEvent, area: Rect) -> Option<Vec<u8>> {
        input::mouse(self.parser.screen(), event, area)
    }

    /// Moves through local history. Positive deltas move backward; negative
    /// deltas move toward the live screen.
    pub fn scroll(&mut self, delta: i32) {
        let current = self.parser.screen().scrollback();
        let next = if delta >= 0 {
            current.saturating_add(delta as usize)
        } else {
            current.saturating_sub(delta.unsigned_abs() as usize)
        };
        self.parser.screen_mut().set_scrollback(next);
    }

    pub fn reset_scrollback(&mut self) {
        self.parser.screen_mut().set_scrollback(0);
    }
}

fn process_filtered(
    parser: &mut vt100::Parser<TerminalCallbacks>,
    observer: &mut OriginObserver,
    bytes: &[u8],
    replies: &mut Vec<u8>,
) {
    let mut offset = 0;
    while offset < bytes.len() {
        let (consumed, boundary) = observer.advance(&bytes[offset..]);
        if consumed == 0 {
            break;
        }
        parser.process(&bytes[offset..offset + consumed]);
        observer.apply_boundary(&boundary);
        loop {
            let request = parser.callbacks_mut().take_request();
            let Some(request) = request else {
                break;
            };
            append_reply(replies, request, parser.screen(), observer);
        }
        offset += consumed;
    }
}

#[cfg(test)]
mod tests {
    use crossterm::event::{
        KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers, MouseButton, MouseEvent,
        MouseEventKind,
    };
    use ratatui::layout::Rect;

    use super::TerminalState;

    #[test]
    fn strips_split_and_unterminated_osc_without_leaking_payload() {
        let mut terminal = TerminalState::new(24, 80);

        terminal.process(b"before\x1b");
        terminal.process(b"]2;discarded");
        terminal.process(b" title\x07after");
        assert_eq!(terminal.screen().contents(), "beforeafter");

        terminal.process(b"\r\n\x1b]52;c;");
        let payload = [b'x'; 1024];
        for _ in 0..32 * 1024 {
            assert!(terminal.process(&payload).is_empty());
        }
        terminal.process(b"\x07visible");
        let contents = terminal.screen().contents();
        assert!(contents.ends_with("visible"));
        assert!(!contents.contains("discarded"));
        assert!(!contents.contains("xxxx"));
    }

    #[test]
    fn osc_st_and_following_csi_work_across_boundaries() {
        let mut terminal = TerminalState::new(4, 20);
        terminal.process(b"\x1b]2;hidden\x1b");
        terminal.process(b"\\plain");
        terminal.process(b"\x1b]2;also hidden\x1b");
        terminal.process(b"[31mred");

        assert_eq!(terminal.screen().contents(), "plainred");
        assert_eq!(
            terminal.screen().cell(0, 5).unwrap().fgcolor(),
            vt100::Color::Idx(1)
        );
    }

    #[test]
    fn discarded_osc_cancels_an_incomplete_control_sequence() {
        let mut terminal = TerminalState::new(4, 20);
        terminal.process(b"\x1b[31\x1b]2;hidden");
        terminal.process(b"\x07mvisible");
        assert_eq!(terminal.screen().contents(), "mvisible");
        assert_eq!(
            terminal.screen().cell(0, 0).unwrap().fgcolor(),
            vt100::Color::Default
        );
    }

    #[test]
    fn emits_supported_device_and_status_replies_only() {
        let mut terminal = TerminalState::new(24, 80);
        assert_eq!(terminal.process(b"\x1b[c"), b"\x1b[?1;2c");
        assert_eq!(terminal.process(b"\x1b[>c"), b"\x1b[>0;0;0c");
        assert_eq!(terminal.process(b"\x1b[5n"), b"\x1b[0n");
        assert!(terminal.process(b"\x1b[?5n").is_empty());
    }

    #[test]
    fn cpr_is_origin_relative_and_clamps_pending_wrap() {
        let mut terminal = TerminalState::new(24, 80);
        assert_eq!(
            terminal.process(b"\x1b[5;20r\x1b[?6h\x1b[1;1H\x1b[6n"),
            b"\x1b[1;1R"
        );

        terminal.process(b"\x1bc");
        terminal.process(&[b'a'; 80]);
        assert_eq!(terminal.process(b"\x1b[6n"), b"\x1b[1;80R");
    }

    #[test]
    fn observer_tracks_save_restore_alternate_grid_and_resize() {
        let mut terminal = TerminalState::new(24, 80);
        terminal.process(b"\x1b[5;20r\x1b[?6h\x1b[3;4H\x1b7\x1b[?6l\x1b8");
        assert_eq!(terminal.process(b"\x1b[6n"), b"\x1b[3;4R");

        terminal.process(b"\x1b[?1049h\x1b[10;20r\x1b[?6h\x1b[2;2H");
        assert_eq!(terminal.process(b"\x1b[6n"), b"\x1b[2;2R");
        terminal.process(b"\x1b[?1049l");
        assert_eq!(terminal.process(b"\x1b[6n"), b"\x1b[3;4R");

        terminal.resize(10, 80);
        terminal.resize(30, 80);
        terminal.process(b"\x1b[99;1H");
        assert_eq!(terminal.process(b"\x1b[6n"), b"\x1b[26;1R");
    }

    #[test]
    fn encodes_keys_application_modes_and_paste() {
        let mut terminal = TerminalState::new(24, 80);
        assert_eq!(terminal.paste("plain"), b"plain");
        assert_eq!(
            terminal.key(KeyEvent::new(KeyCode::Char('b'), KeyModifiers::CONTROL)),
            Some(vec![2])
        );
        assert_eq!(
            terminal.key(KeyEvent::new(KeyCode::Char('界'), KeyModifiers::ALT)),
            Some([b"\x1b".as_slice(), "界".as_bytes()].concat())
        );
        assert_eq!(
            terminal.key(KeyEvent::new(KeyCode::Esc, KeyModifiers::ALT)),
            Some(b"\x1b\x1b".to_vec())
        );
        assert_eq!(
            terminal.key(KeyEvent::new(KeyCode::F(12), KeyModifiers::CONTROL)),
            Some(b"\x1b[24;5~".to_vec())
        );
        assert_eq!(
            terminal.key(KeyEvent::new(KeyCode::Up, KeyModifiers::NONE)),
            Some(b"\x1b[A".to_vec())
        );
        terminal.process(b"\x1b[?1h\x1b[?2004h\x1b=");
        assert_eq!(
            terminal.key(KeyEvent::new(KeyCode::Up, KeyModifiers::NONE)),
            Some(b"\x1bOA".to_vec())
        );
        assert_eq!(terminal.paste("a\nb"), b"\x1b[200~a\nb\x1b[201~");

        let keypad = KeyEvent {
            code: KeyCode::Char('7'),
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: KeyEventState::KEYPAD,
        };
        assert_eq!(terminal.key(keypad), Some(b"\x1bOw".to_vec()));
        assert_eq!(
            terminal.key(KeyEvent::new(KeyCode::PageUp, KeyModifiers::SHIFT)),
            None
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn paste_then_enter_does_not_isolate_execution_from_pending_shell_input() {
        use std::{fs::File, io::Write, os::fd::FromRawFd, process::Stdio, time::Duration};

        let (mut master, mut slave) = (-1, -1);
        // SAFETY: openpty initializes both descriptors on success; optional pointers
        // are null. Each returned descriptor is immediately given one owning File.
        let result = unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
            )
        };
        assert_eq!(result, 0, "{}", std::io::Error::last_os_error());
        let (mut master, slave) =
            unsafe { (File::from_raw_fd(master), File::from_raw_fd(slave)) };
        let child = tokio::process::Command::new("/bin/sh")
            .arg("-i")
            .env_clear()
            .stdin(slave)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();

        // A real shell, not a byte-echo fixture: a pending prefix changes the
        // executed command despite exact text submission. Never claim isolation
        // or try to clear input with control keys (a foreground app may own it).
        master.write_all(b"printf 'pending:<%s>\\n' ").unwrap();
        let terminal = TerminalState::new(24, 80);
        master.write_all(&terminal.paste("printf smoke-safe")).unwrap();
        master
            .write_all(
                &terminal
                    .key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
                    .unwrap(),
            )
            .unwrap();
        master.write_all(b"exit\r").unwrap();
        let output = tokio::time::timeout(Duration::from_secs(5), child.wait_with_output())
            .await
            .expect("shell did not exit")
            .unwrap();
        assert!(output.status.success());
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            "pending:<printf>\npending:<smoke-safe>\n"
        );
    }

    #[test]
    fn encodes_mouse_modes_coordinates_and_boundaries() {
        let mut terminal = TerminalState::new(24, 80);
        let area = Rect::new(10, 4, 20, 10);
        let click = MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: 12,
            row: 5,
            modifiers: KeyModifiers::NONE,
        };
        assert_eq!(terminal.mouse(click, area), None);

        terminal.process(b"\x1b[?1000h\x1b[?1006h");
        assert_eq!(terminal.mouse(click, area), Some(b"\x1b[<0;3;2M".to_vec()));
        let release = MouseEvent {
            kind: MouseEventKind::Up(MouseButton::Left),
            ..click
        };
        assert_eq!(
            terminal.mouse(release, area),
            Some(b"\x1b[<0;3;2m".to_vec())
        );
        let outside = MouseEvent {
            column: 30,
            ..click
        };
        assert_eq!(terminal.mouse(outside, area), None);

        terminal.process(b"\x1b[?1006l");
        let edge_area = Rect::new(0, 0, 224, 1);
        let last_default_column = MouseEvent {
            column: 222,
            row: 0,
            ..click
        };
        assert_eq!(
            terminal.mouse(last_default_column, edge_area),
            Some(vec![0x1b, b'[', b'M', 32, 255, 33])
        );
        let beyond_default_encoding = MouseEvent {
            column: 223,
            ..last_default_column
        };
        assert_eq!(terminal.mouse(beyond_default_encoding, edge_area), None);
        terminal.process(b"\x1b[?1005h");
        assert!(terminal.mouse(beyond_default_encoding, edge_area).is_some());
    }

    #[test]
    fn local_scrollback_moves_and_resets() {
        let mut terminal = TerminalState::new(2, 20);
        terminal.process(b"one\r\ntwo\r\nthree");
        terminal.scroll(1);
        assert_eq!(terminal.screen().scrollback(), 1);
        terminal.scroll(-1);
        assert_eq!(terminal.screen().scrollback(), 0);
        terminal.scroll(100);
        assert_eq!(terminal.screen().scrollback(), 1);
        terminal.reset_scrollback();
        assert_eq!(terminal.screen().scrollback(), 0);
    }
}
