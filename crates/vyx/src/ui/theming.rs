use ratatui::{
    Frame,
    buffer::Buffer,
    layout::Rect,
    style::{Color, Modifier, Style},
    widgets::Widget,
};

use crate::theme::Palette;

/// Clears an area to explicit theme colors in one pass.
///
/// Ratatui's `Clear` resets cells to the outer terminal defaults, which can
/// leak through light themes. This helper also replaces every symbol and
/// removes every modifier before applying the palette.
pub fn clear(frame: &mut Frame, area: Rect, palette: &Palette) {
    frame.render_widget(ThemedClear { palette }, area);
}

/// The same palette with only its background lifted slightly toward the foreground.
/// Host-owned panels use it to stand apart from SSH terminals, whose ANSI colors stay unchanged.
pub(crate) fn elevated(palette: Palette) -> Palette {
    Palette { background: blend(palette.background, palette.foreground, 0.06), ..palette }
}

pub(crate) fn unit(value: f64) -> f64 {
    value.clamp(0.0, 1.0)
}

/// Linear RGB interpolation; non-RGB colors switch at the midpoint.
pub(crate) fn blend(from: Color, to: Color, amount: f64) -> Color {
    let amount = unit(amount);
    match (from, to) {
        (Color::Rgb(fr, fg, fb), Color::Rgb(tr, tg, tb)) => {
            let channel = |from: u8, to: u8| {
                (f64::from(from) + (f64::from(to) - f64::from(from)) * amount).round() as u8
            };
            Color::Rgb(channel(fr, tr), channel(fg, tg), channel(fb, tb))
        }
        _ => if amount < 0.5 { from } else { to },
    }
}

struct ThemedClear<'a> {
    palette: &'a Palette,
}

impl Widget for ThemedClear<'_> {
    fn render(self, area: Rect, buffer: &mut Buffer) {
        let area = area.intersection(*buffer.area());
        for row in area.top()..area.bottom() {
            for column in area.left()..area.right() {
                let cell = &mut buffer[(column, row)];
                cell.reset();
                cell.set_style(self.palette.style());
            }
        }
    }
}

pub(crate) fn terminal(
    frame: &mut Frame,
    area: Rect,
    screen: &vt100::Screen,
    show_cursor: bool,
    palette: &Palette,
) {
    frame.render_widget(
        ThemedTerminal {
            screen,
            show_cursor,
            palette,
        },
        area,
    );
}

struct ThemedTerminal<'a> {
    screen: &'a vt100::Screen,
    show_cursor: bool,
    palette: &'a Palette,
}

impl Widget for ThemedTerminal<'_> {
    fn render(self, area: Rect, buffer: &mut Buffer) {
        let clipped = area.intersection(*buffer.area());
        for y in clipped.top()..clipped.bottom() {
            let row = y - area.y;
            for x in clipped.left()..clipped.right() {
                let column = x - area.x;
                let Some(source) = self.screen.cell(row, column) else {
                    continue;
                };
                let target = &mut buffer[(x, y)];
                if source.has_contents() {
                    target.set_symbol(source.contents());
                }
                target.set_style(cell_style(source, self.palette));
            }
        }

        if !self.show_cursor || self.screen.hide_cursor() {
            return;
        }
        let (cursor_row, cursor_column) = self.screen.cursor_position();
        let scrollback = u16::try_from(self.screen.scrollback()).unwrap_or(u16::MAX);
        let cursor_row = cursor_row.saturating_add(scrollback);
        if cursor_row >= area.height || cursor_column >= area.width {
            return;
        }
        let x = area.x.saturating_add(cursor_column);
        let y = area.y.saturating_add(cursor_row);
        if !clipped.contains((x, y).into()) {
            return;
        }
        let Some(source) = self.screen.cell(cursor_row, cursor_column) else {
            return;
        };
        let target = &mut buffer[(x, y)];
        if source.has_contents() {
            target.set_style(Style::default().add_modifier(Modifier::REVERSED));
        } else {
            target
                .set_symbol("█")
                .set_style(Style::default().fg(self.palette.muted));
        }
    }
}

fn cell_style(cell: &vt100::Cell, palette: &Palette) -> Style {
    let mut modifiers = Modifier::empty();
    if cell.bold() {
        modifiers |= Modifier::BOLD;
    }
    if cell.italic() {
        modifiers |= Modifier::ITALIC;
    }
    if cell.underline() {
        modifiers |= Modifier::UNDERLINED;
    }
    if cell.inverse() {
        modifiers |= Modifier::REVERSED;
    }
    if cell.dim() {
        modifiers |= Modifier::DIM;
    }
    Style::reset()
        .fg(terminal_color(cell.fgcolor(), palette.foreground, palette))
        .bg(terminal_color(cell.bgcolor(), palette.background, palette))
        .add_modifier(modifiers)
}

fn terminal_color(color: vt100::Color, default: Color, palette: &Palette) -> Color {
    match color {
        vt100::Color::Default => default,
        vt100::Color::Idx(index @ 0..=15) => palette.ansi[usize::from(index)],
        vt100::Color::Idx(index) => Color::Indexed(index),
        vt100::Color::Rgb(red, green, blue) => Color::Rgb(red, green, blue),
    }
}
