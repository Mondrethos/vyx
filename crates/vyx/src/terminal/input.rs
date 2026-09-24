use std::io::Write as _;

use crossterm::event::{
    KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers, MouseButton, MouseEvent,
    MouseEventKind,
};
use ratatui::layout::Rect;
use vt100::{MouseProtocolEncoding, MouseProtocolMode, Screen};

const ESC: u8 = 0x1b;

pub(super) fn key(screen: &Screen, event: KeyEvent) -> Option<Vec<u8>> {
    if event.kind == KeyEventKind::Release
        || event
            .modifiers
            .intersects(KeyModifiers::SUPER | KeyModifiers::HYPER | KeyModifiers::META)
        || (event.modifiers.contains(KeyModifiers::SHIFT)
            && matches!(event.code, KeyCode::PageUp | KeyCode::PageDown))
    {
        return None;
    }

    if screen.application_keypad() && event.state.contains(KeyEventState::KEYPAD) {
        if let Some(bytes) = application_keypad(event.code) {
            return with_alt(bytes, event.modifiers);
        }
    }

    let modifiers = event.modifiers;
    match event.code {
        KeyCode::Char(c) => character(c, modifiers),
        KeyCode::Null => with_alt(vec![0], modifiers),
        KeyCode::Enter => with_alt(vec![b'\r'], modifiers),
        KeyCode::Tab => with_alt(vec![b'\t'], modifiers),
        KeyCode::BackTab => Some(b"\x1b[Z".to_vec()),
        KeyCode::Backspace => with_alt(vec![0x7f], modifiers),
        KeyCode::Esc => with_alt(vec![ESC], modifiers),
        KeyCode::Up => cursor_key(b'A', screen.application_cursor(), modifiers),
        KeyCode::Down => cursor_key(b'B', screen.application_cursor(), modifiers),
        KeyCode::Right => cursor_key(b'C', screen.application_cursor(), modifiers),
        KeyCode::Left => cursor_key(b'D', screen.application_cursor(), modifiers),
        KeyCode::Home => cursor_key(b'H', screen.application_cursor(), modifiers),
        KeyCode::End => cursor_key(b'F', screen.application_cursor(), modifiers),
        KeyCode::Insert => tilde_key(2, modifiers),
        KeyCode::Delete => tilde_key(3, modifiers),
        KeyCode::PageUp => tilde_key(5, modifiers),
        KeyCode::PageDown => tilde_key(6, modifiers),
        KeyCode::F(number) => function_key(number, modifiers),
        KeyCode::KeypadBegin => cursor_key(b'E', screen.application_cursor(), modifiers),
        KeyCode::CapsLock
        | KeyCode::ScrollLock
        | KeyCode::NumLock
        | KeyCode::PrintScreen
        | KeyCode::Pause
        | KeyCode::Menu
        | KeyCode::Media(_)
        | KeyCode::Modifier(_) => None,
    }
}

fn character(c: char, modifiers: KeyModifiers) -> Option<Vec<u8>> {
    let mut bytes = if modifiers.contains(KeyModifiers::CONTROL) {
        vec![control_character(c)?]
    } else {
        let mut encoded = [0_u8; 4];
        c.encode_utf8(&mut encoded).as_bytes().to_vec()
    };
    if modifiers.contains(KeyModifiers::ALT) {
        bytes.insert(0, ESC);
    }
    Some(bytes)
}

fn control_character(c: char) -> Option<u8> {
    match c {
        '@' | '`' | ' ' | '2' => Some(0x00),
        'a'..='z' => Some(c as u8 - b'a' + 1),
        'A'..='Z' => Some(c as u8 - b'A' + 1),
        '[' | '3' => Some(0x1b),
        '\\' | '4' => Some(0x1c),
        ']' | '5' => Some(0x1d),
        '^' | '6' => Some(0x1e),
        '_' | '/' | '-' | '7' => Some(0x1f),
        '?' | '8' => Some(0x7f),
        _ => None,
    }
}

fn with_alt(mut bytes: Vec<u8>, modifiers: KeyModifiers) -> Option<Vec<u8>> {
    if modifiers.contains(KeyModifiers::ALT) {
        bytes.insert(0, ESC);
    }
    Some(bytes)
}

fn modifier_parameter(modifiers: KeyModifiers) -> u8 {
    1 + u8::from(modifiers.contains(KeyModifiers::SHIFT))
        + 2 * u8::from(modifiers.contains(KeyModifiers::ALT))
        + 4 * u8::from(modifiers.contains(KeyModifiers::CONTROL))
}

fn cursor_key(final_byte: u8, application_mode: bool, modifiers: KeyModifiers) -> Option<Vec<u8>> {
    let modifier = modifier_parameter(modifiers);
    if modifier == 1 {
        Some(vec![
            ESC,
            if application_mode { b'O' } else { b'[' },
            final_byte,
        ])
    } else {
        Some(format!("\x1b[1;{modifier}{}", char::from(final_byte)).into_bytes())
    }
}

fn tilde_key(number: u8, modifiers: KeyModifiers) -> Option<Vec<u8>> {
    let modifier = modifier_parameter(modifiers);
    if modifier == 1 {
        Some(format!("\x1b[{number}~").into_bytes())
    } else {
        Some(format!("\x1b[{number};{modifier}~").into_bytes())
    }
}

fn function_key(number: u8, modifiers: KeyModifiers) -> Option<Vec<u8>> {
    let modifier = modifier_parameter(modifiers);
    match number {
        1..=4 if modifier == 1 => Some(vec![ESC, b'O', b'P' + number - 1]),
        1..=4 => Some(format!("\x1b[1;{modifier}{}", char::from(b'P' + number - 1)).into_bytes()),
        5..=12 => {
            let code = [15, 17, 18, 19, 20, 21, 23, 24][usize::from(number - 5)];
            if modifier == 1 {
                Some(format!("\x1b[{code}~").into_bytes())
            } else {
                Some(format!("\x1b[{code};{modifier}~").into_bytes())
            }
        }
        _ => None,
    }
}

fn application_keypad(code: KeyCode) -> Option<Vec<u8>> {
    let final_byte = match code {
        KeyCode::Char('0') => b'p',
        KeyCode::Char('1') => b'q',
        KeyCode::Char('2') => b'r',
        KeyCode::Char('3') => b's',
        KeyCode::Char('4') => b't',
        KeyCode::Char('5') => b'u',
        KeyCode::Char('6') => b'v',
        KeyCode::Char('7') => b'w',
        KeyCode::Char('8') => b'x',
        KeyCode::Char('9') => b'y',
        KeyCode::Char('.') => b'n',
        KeyCode::Char('/') => b'o',
        KeyCode::Char('*') => b'j',
        KeyCode::Char('-') => b'm',
        KeyCode::Char('+') => b'k',
        KeyCode::Char(',') => b'l',
        KeyCode::Char('=') => b'X',
        KeyCode::Enter => b'M',
        _ => return None,
    };
    Some(vec![ESC, b'O', final_byte])
}

pub(super) fn paste(screen: &Screen, text: &str) -> Vec<u8> {
    if screen.bracketed_paste() {
        let mut bytes = Vec::with_capacity(text.len() + 12);
        bytes.extend_from_slice(b"\x1b[200~");
        bytes.extend_from_slice(text.as_bytes());
        bytes.extend_from_slice(b"\x1b[201~");
        bytes
    } else {
        text.as_bytes().to_vec()
    }
}

pub(super) fn mouse(screen: &Screen, event: MouseEvent, area: Rect) -> Option<Vec<u8>> {
    if area.width == 0
        || area.height == 0
        || event
            .modifiers
            .intersects(KeyModifiers::SUPER | KeyModifiers::HYPER | KeyModifiers::META)
        || event.column < area.x
        || event.column >= area.x.saturating_add(area.width)
        || event.row < area.y
        || event.row >= area.y.saturating_add(area.height)
    {
        return None;
    }

    let mode = screen.mouse_protocol_mode();
    if !reported_in_mode(mode, event.kind) {
        return None;
    }

    let x = event.column - area.x + 1;
    let y = event.row - area.y + 1;
    let release = matches!(event.kind, MouseEventKind::Up(_));
    let mut code = mouse_code(event.kind, screen.mouse_protocol_encoding())?;
    code += u16::from(event.modifiers.contains(KeyModifiers::SHIFT)) * 4;
    code += u16::from(event.modifiers.contains(KeyModifiers::ALT)) * 8;
    code += u16::from(event.modifiers.contains(KeyModifiers::CONTROL)) * 16;

    match screen.mouse_protocol_encoding() {
        MouseProtocolEncoding::Sgr => {
            let mut bytes = Vec::with_capacity(24);
            write!(
                bytes,
                "\x1b[<{code};{x};{y}{}",
                if release { 'm' } else { 'M' }
            )
            .expect("writing a mouse report into Vec cannot fail");
            Some(bytes)
        }
        MouseProtocolEncoding::Default => {
            if x > 223 || y > 223 || code > 223 {
                return None;
            }
            Some(vec![
                ESC,
                b'[',
                b'M',
                (code + 32) as u8,
                (x + 32) as u8,
                (y + 32) as u8,
            ])
        }
        MouseProtocolEncoding::Utf8 => {
            let mut bytes = Vec::with_capacity(12);
            bytes.extend_from_slice(b"\x1b[M");
            push_utf8_codepoint(&mut bytes, u32::from(code) + 32)?;
            push_utf8_codepoint(&mut bytes, u32::from(x) + 32)?;
            push_utf8_codepoint(&mut bytes, u32::from(y) + 32)?;
            Some(bytes)
        }
    }
}

fn reported_in_mode(mode: MouseProtocolMode, kind: MouseEventKind) -> bool {
    match mode {
        MouseProtocolMode::None => false,
        MouseProtocolMode::Press => matches!(kind, MouseEventKind::Down(_)),
        MouseProtocolMode::PressRelease => matches!(
            kind,
            MouseEventKind::Down(_)
                | MouseEventKind::Up(_)
                | MouseEventKind::ScrollDown
                | MouseEventKind::ScrollUp
                | MouseEventKind::ScrollLeft
                | MouseEventKind::ScrollRight
        ),
        MouseProtocolMode::ButtonMotion => !matches!(kind, MouseEventKind::Moved),
        MouseProtocolMode::AnyMotion => true,
    }
}

fn mouse_code(kind: MouseEventKind, encoding: MouseProtocolEncoding) -> Option<u16> {
    let encode_button = |button| match button {
        MouseButton::Left => 0,
        MouseButton::Middle => 1,
        MouseButton::Right => 2,
    };
    Some(match kind {
        MouseEventKind::Down(button) => encode_button(button),
        MouseEventKind::Up(button) if encoding == MouseProtocolEncoding::Sgr => {
            encode_button(button)
        }
        MouseEventKind::Up(_) => 3,
        MouseEventKind::Drag(button) => 32 + encode_button(button),
        MouseEventKind::Moved => 35,
        MouseEventKind::ScrollUp => 64,
        MouseEventKind::ScrollDown => 65,
        MouseEventKind::ScrollLeft => 66,
        MouseEventKind::ScrollRight => 67,
    })
}

fn push_utf8_codepoint(output: &mut Vec<u8>, codepoint: u32) -> Option<()> {
    let character = char::from_u32(codepoint)?;
    let mut encoded = [0_u8; 4];
    output.extend_from_slice(character.encode_utf8(&mut encoded).as_bytes());
    Some(())
}
