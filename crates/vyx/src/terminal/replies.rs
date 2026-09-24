use std::io::Write as _;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ReplyRequest {
    PrimaryDeviceAttributes,
    SecondaryDeviceAttributes,
    Status,
    CursorPosition,
}

#[derive(Default)]
pub(super) struct TerminalCallbacks {
    request: Option<ReplyRequest>,
}

impl TerminalCallbacks {
    pub(super) fn take_request(&mut self) -> Option<ReplyRequest> {
        self.request.take()
    }
}

impl vt100::Callbacks for TerminalCallbacks {
    fn unhandled_csi(
        &mut self,
        _screen: &mut vt100::Screen,
        i1: Option<u8>,
        i2: Option<u8>,
        params: &[&[u16]],
        action: char,
    ) {
        if i2.is_some() {
            return;
        }

        let default_parameter = params.is_empty() || one_parameter(params, 0);
        let request = match (i1, action) {
            (None, 'c') if default_parameter => Some(ReplyRequest::PrimaryDeviceAttributes),
            (Some(b'>'), 'c') if default_parameter => Some(ReplyRequest::SecondaryDeviceAttributes),
            (None, 'n') if one_parameter(params, 5) => Some(ReplyRequest::Status),
            (None, 'n') if one_parameter(params, 6) => Some(ReplyRequest::CursorPosition),
            _ => None,
        };
        if let Some(request) = request {
            self.request = Some(request);
        }
    }
}

fn one_parameter(params: &[&[u16]], value: u16) -> bool {
    params.len() == 1 && params[0].len() == 1 && params[0][0] == value
}

#[derive(Clone, Copy, Debug)]
enum MetadataOp {
    None,
    Origin(bool),
    EnterAlternate,
    ExitAlternate,
    EnterAlternate1049,
    ExitAlternate1049,
    SaveCursor,
    RestoreCursor,
    Reset,
    Margins { top: u16, bottom: u16 },
}

const MAX_METADATA_OPS: usize = 32;

pub(super) struct Boundary {
    ops: [MetadataOp; MAX_METADATA_OPS],
    len: usize,
    terminated: bool,
}

impl Default for Boundary {
    fn default() -> Self {
        Self {
            ops: [MetadataOp::None; MAX_METADATA_OPS],
            len: 0,
            terminated: false,
        }
    }
}

impl Boundary {
    fn push(&mut self, op: MetadataOp) {
        if self.len < self.ops.len() {
            self.ops[self.len] = op;
            self.len += 1;
        }
    }
}

impl vte::Perform for Boundary {
    fn csi_dispatch(
        &mut self,
        params: &vte::Params,
        intermediates: &[u8],
        ignore: bool,
        action: char,
    ) {
        self.terminated = true;
        if ignore {
            return;
        }

        if intermediates == b"?" && matches!(action, 'h' | 'l') {
            let enabled = action == 'h';
            for parameter in params {
                match parameter {
                    [6] => self.push(MetadataOp::Origin(enabled)),
                    [47] if enabled => self.push(MetadataOp::EnterAlternate),
                    [47] => self.push(MetadataOp::ExitAlternate),
                    [1049] if enabled => self.push(MetadataOp::EnterAlternate1049),
                    [1049] => self.push(MetadataOp::ExitAlternate1049),
                    _ => {}
                }
            }
        } else if intermediates.is_empty() && action == 'r' {
            let mut parameters = params.iter();
            let top = parameters
                .next()
                .and_then(|parameter| parameter.first())
                .copied()
                .unwrap_or(0);
            let bottom = parameters
                .next()
                .and_then(|parameter| parameter.first())
                .copied()
                .unwrap_or(0);
            self.push(MetadataOp::Margins { top, bottom });
        }
    }

    fn esc_dispatch(&mut self, intermediates: &[u8], ignore: bool, byte: u8) {
        self.terminated = true;
        if ignore || !intermediates.is_empty() {
            return;
        }
        match byte {
            b'7' => self.push(MetadataOp::SaveCursor),
            b'8' => self.push(MetadataOp::RestoreCursor),
            b'c' => self.push(MetadataOp::Reset),
            _ => {}
        }
    }

    fn terminated(&self) -> bool {
        self.terminated
    }
}

#[derive(Clone, Copy, Debug)]
struct GridMetadata {
    origin_mode: bool,
    saved_origin_mode: bool,
    scroll_top: u16,
    scroll_bottom: u16,
}

impl GridMetadata {
    fn new(rows: u16) -> Self {
        Self {
            origin_mode: false,
            saved_origin_mode: false,
            scroll_top: 0,
            scroll_bottom: rows - 1,
        }
    }

    fn clear(&mut self, rows: u16) {
        *self = Self::new(rows);
    }

    fn resize(&mut self, old_rows: u16, rows: u16) {
        if self.scroll_bottom == old_rows - 1 {
            self.scroll_bottom = rows - 1;
        }
        if self.scroll_bottom >= rows {
            self.scroll_bottom = rows - 1;
        }
        if self.scroll_bottom < self.scroll_top {
            self.scroll_top = 0;
        }
    }

    fn set_margins(&mut self, rows: u16, top: u16, bottom: u16) {
        let top = if top == 0 { 1 } else { top } - 1;
        let bottom = (if bottom == 0 { rows } else { bottom } - 1).min(rows - 1);
        if top < bottom {
            self.scroll_top = top;
            self.scroll_bottom = bottom;
        } else {
            self.scroll_top = 0;
            self.scroll_bottom = rows - 1;
        }
    }
}

/// Metadata vt100 intentionally does not expose, parsed by the same VTE state
/// machine and updated only after vt100 consumes each complete boundary.
pub(super) struct OriginObserver {
    parser: vte::Parser,
    normal: GridMetadata,
    alternate: GridMetadata,
    alternate_screen: bool,
    rows: u16,
}

impl OriginObserver {
    pub(super) fn new(rows: u16) -> Self {
        Self {
            parser: vte::Parser::new(),
            normal: GridMetadata::new(rows),
            alternate: GridMetadata::new(rows),
            alternate_screen: false,
            rows,
        }
    }

    pub(super) fn advance(&mut self, bytes: &[u8]) -> (usize, Boundary) {
        let mut boundary = Boundary::default();
        let consumed = self.parser.advance_until_terminated(&mut boundary, bytes);
        (consumed, boundary)
    }

    pub(super) fn apply_boundary(&mut self, boundary: &Boundary) {
        self.apply(&boundary.ops[..boundary.len]);
    }

    pub(super) fn resize(&mut self, rows: u16) {
        self.normal.resize(self.rows, rows);
        self.alternate.resize(self.rows, rows);
        self.rows = rows;
    }

    pub(super) fn origin_row(&self, physical_row: u16) -> u16 {
        let grid = self.current();
        if grid.origin_mode {
            physical_row.saturating_sub(grid.scroll_top)
        } else {
            physical_row
        }
    }

    fn apply(&mut self, ops: &[MetadataOp]) {
        for &op in ops {
            match op {
                MetadataOp::None => {}
                MetadataOp::Origin(enabled) => self.current_mut().origin_mode = enabled,
                MetadataOp::EnterAlternate => self.alternate_screen = true,
                MetadataOp::ExitAlternate => self.alternate_screen = false,
                MetadataOp::EnterAlternate1049 => {
                    self.normal.saved_origin_mode = self.normal.origin_mode;
                    self.alternate.clear(self.rows);
                    self.alternate_screen = true;
                }
                MetadataOp::ExitAlternate1049 => {
                    self.alternate_screen = false;
                    self.normal.origin_mode = self.normal.saved_origin_mode;
                }
                MetadataOp::SaveCursor => {
                    let grid = self.current_mut();
                    grid.saved_origin_mode = grid.origin_mode;
                }
                MetadataOp::RestoreCursor => {
                    let grid = self.current_mut();
                    grid.origin_mode = grid.saved_origin_mode;
                }
                MetadataOp::Reset => {
                    self.normal.clear(self.rows);
                    self.alternate.clear(self.rows);
                    self.alternate_screen = false;
                }
                MetadataOp::Margins { top, bottom } => {
                    let rows = self.rows;
                    self.current_mut().set_margins(rows, top, bottom);
                }
            }
        }
    }

    fn current(&self) -> &GridMetadata {
        if self.alternate_screen {
            &self.alternate
        } else {
            &self.normal
        }
    }

    fn current_mut(&mut self) -> &mut GridMetadata {
        if self.alternate_screen {
            &mut self.alternate
        } else {
            &mut self.normal
        }
    }
}

pub(super) fn append_reply(
    output: &mut Vec<u8>,
    request: ReplyRequest,
    screen: &vt100::Screen,
    observer: &OriginObserver,
) {
    match request {
        ReplyRequest::PrimaryDeviceAttributes => output.extend_from_slice(b"\x1b[?1;2c"),
        ReplyRequest::SecondaryDeviceAttributes => output.extend_from_slice(b"\x1b[>0;0;0c"),
        ReplyRequest::Status => output.extend_from_slice(b"\x1b[0n"),
        ReplyRequest::CursorPosition => {
            let (physical_row, physical_col) = screen.cursor_position();
            let (_, cols) = screen.size();
            let row = observer.origin_row(physical_row).saturating_add(1);
            let col = physical_col.min(cols - 1).saturating_add(1);
            write!(output, "\x1b[{row};{col}R")
                .expect("writing a terminal reply into Vec cannot fail");
        }
    }
}
