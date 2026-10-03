//! Small host-drawn primitives shared by every surface: wrapping buttons, the list
//! scrollbar, display-width fitting, and transient notices. Callers keep their own
//! state and map emitted button indices to their existing actions.

use std::{
    borrow::Cow,
    time::{Duration, Instant},
};

use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::Span,
    widgets::{Paragraph, Wrap},
};

use crate::theme::Palette;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ButtonKind {
    #[default]
    Primary,
    Secondary,
    Danger,
}

#[derive(Clone, Copy, Debug)]
pub struct Button<'a> {
    pub caption: &'a str,
    pub kind: ButtonKind,
    pub enabled: bool,
}

impl<'a> Button<'a> {
    pub const fn new(caption: &'a str, kind: ButtonKind) -> Self {
        Self { caption, kind, enabled: true }
    }

    pub const fn primary(caption: &'a str) -> Self {
        Self::new(caption, ButtonKind::Primary)
    }

    pub const fn secondary(caption: &'a str) -> Self {
        Self::new(caption, ButtonKind::Secondary)
    }

    pub const fn danger(caption: &'a str) -> Self {
        Self::new(caption, ButtonKind::Danger)
    }

    pub const fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }
}

/// Display cells of `text` in a terminal.
pub fn width(text: &str) -> usize {
    Span::raw(text).width()
}

fn char_width(character: char) -> usize {
    let mut buffer = [0; 4];
    width(character.encode_utf8(&mut buffer))
}

/// `text` limited to `width` display cells. A truncated value ends in `…`; text that already
/// fits is borrowed unchanged. UTF-8 characters are never split.
pub fn fit(text: &str, width: u16) -> Cow<'_, str> {
    let limit = usize::from(width);
    if limit == 0 {
        return Cow::Borrowed("");
    }
    if self::width(text) <= limit {
        return Cow::Borrowed(text);
    }
    let mut used = 0;
    let mut end = 0;
    for (index, character) in text.char_indices() {
        let cells = char_width(character);
        if used + cells > limit - 1 {
            break;
        }
        used += cells;
        end = index + character.len_utf8();
    }
    let mut fitted = String::with_capacity(end + '…'.len_utf8());
    fitted.push_str(&text[..end]);
    fitted.push('…');
    Cow::Owned(fitted)
}

/// Positions cells of the given display widths left to right with one-column gaps,
/// wrapping to new rows. Calls `visit(index, row, column, cells)`; returns the row count.
fn place(width: u16, widths: impl Iterator<Item = usize>, mut visit: impl FnMut(usize, u16, u16, u16)) -> u16 {
    if width == 0 {
        return 0;
    }
    let (mut row, mut column, mut rows) = (0u16, 0u16, 0u16);
    for (index, caption_width) in widths.enumerate() {
        let cells = (caption_width + 2).min(usize::from(width)) as u16;
        if column > 0 && u32::from(column) + u32::from(cells) > u32::from(width) {
            row = row.saturating_add(1);
            column = 0;
        }
        visit(index, row, column, cells);
        column = column.saturating_add(cells).saturating_add(1);
        rows = row.saturating_add(1);
    }
    rows
}

/// Rows `draw_buttons` needs for `buttons` at `width` columns, before clipping.
pub fn button_rows(width: u16, buttons: &[Button<'_>]) -> u16 {
    place(width, buttons.iter().map(|button| self::width(button.caption)), |_, _, _, _| {})
}

/// `caption: key` labels when all of them fit in `rows` rows of `width` columns, otherwise
/// the plain captions. An empty key always leaves its caption unchanged.
pub fn keyed_captions<'a>(labels: &[(&'a str, &str)], width: u16, rows: u16) -> Vec<Cow<'a, str>> {
    let keyed: Vec<Cow<'a, str>> = labels.iter()
        .map(|&(caption, key)| if key.is_empty() { Cow::Borrowed(caption) } else { Cow::Owned(format!("{caption}: {key}")) })
        .collect();
    if place(width, keyed.iter().map(|caption| self::width(caption)), |_, _, _, _| {}) <= rows {
        keyed
    } else {
        labels.iter().map(|&(caption, _)| Cow::Borrowed(caption)).collect()
    }
}

fn button_style(button: &Button<'_>, selected: bool, palette: &Palette) -> Style {
    let style = if !button.enabled {
        Style::default().fg(palette.muted)
    } else {
        match button.kind {
            ButtonKind::Primary => Style::default()
                .fg(palette.selection_fg)
                .bg(palette.selection_bg)
                .add_modifier(Modifier::BOLD),
            ButtonKind::Secondary => Style::default().fg(palette.accent),
            ButtonKind::Danger => Style::default().fg(palette.error).add_modifier(Modifier::BOLD),
        }
    };
    if selected && button.enabled {
        style.add_modifier(Modifier::REVERSED | Modifier::BOLD)
    } else {
        style
    }
}

/// Draws `[caption]` buttons that wrap within `area`, keeping the selected button's row
/// visible when rows are clipped. Enabled buttons report `(index, rectangle)` through
/// `emit_hit`; disabled buttons are muted and not clickable. Returns the rows drawn.
pub fn draw_buttons(
    frame: &mut Frame,
    area: Rect,
    buttons: &[Button<'_>],
    selected: Option<usize>,
    palette: &Palette,
    mut emit_hit: impl FnMut(usize, Rect),
) -> u16 {
    if area.width == 0 || area.height == 0 || buttons.is_empty() {
        return 0;
    }
    let mut selected_row = None;
    let total = place(area.width, buttons.iter().map(|button| self::width(button.caption)), |index, row, _, _| {
        if Some(index) == selected {
            selected_row = Some(row);
        }
    });
    let shown = total.min(area.height);
    let first = selected_row.map_or(0, |row| row.saturating_sub(shown - 1)).min(total - shown);
    let buffer = frame.buffer_mut();
    let bounds = *buffer.area();
    place(area.width, buttons.iter().map(|button| self::width(button.caption)), |index, row, column, cells| {
        if row < first || row >= first + shown {
            return;
        }
        let button = &buttons[index];
        let rectangle = Rect::new(area.x + column, area.y + row - first, cells, 1).intersection(bounds);
        if rectangle.is_empty() {
            return;
        }
        let style = button_style(button, Some(index) == selected, palette);
        let caption = fit(button.caption, cells.saturating_sub(2));
        let mut x = rectangle.x;
        for part in ["[", caption.as_ref(), "]"] {
            let remaining = rectangle.right().saturating_sub(x);
            if remaining == 0 {
                break;
            }
            x = buffer.set_stringn(x, rectangle.y, part, usize::from(remaining), style).0;
        }
        if button.enabled {
            emit_hit(index, rectangle);
        }
    });
    shown
}

/// Thumb of a scrollbar drawn in the rightmost column of `area`, for a list showing
/// `area.height` of `total` rows starting at `viewport`. Empty without overflow.
pub fn scrollbar_thumb(area: Rect, viewport: usize, total: usize) -> Rect {
    let track = usize::from(area.height);
    if area.width == 0 || track == 0 || total <= track {
        return Rect::default();
    }
    let thumb = (track * track / total).clamp(1, track);
    let travel = track - thumb;
    let maximum = total - track;
    let start = viewport.min(maximum) * travel / maximum;
    Rect::new(area.right() - 1, area.y + start as u16, 1, thumb as u16)
}

/// One-column scrollbar in the rightmost column of `area`; nothing without overflow.
pub fn draw_scrollbar(frame: &mut Frame, area: Rect, viewport: usize, total: usize, palette: &Palette) {
    let thumb = scrollbar_thumb(area, viewport, total);
    if thumb.is_empty() {
        return;
    }
    let buffer = frame.buffer_mut();
    let bounds = *buffer.area();
    for y in area.top()..area.bottom() {
        let position = (thumb.x, y);
        if !bounds.contains(position.into()) {
            continue;
        }
        let in_thumb = y >= thumb.top() && y < thumb.bottom();
        buffer[position]
            .set_symbol(if in_thumb { "█" } else { "│" })
            .set_style(Style::default().fg(if in_thumb { palette.accent } else { palette.border }));
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoticeKind {
    Info,
    Success,
    Warning,
    Error,
}

impl NoticeKind {
    pub fn color(self, palette: &Palette) -> Color {
        match self {
            Self::Info => palette.info,
            Self::Success => palette.success,
            Self::Warning => palette.warning,
            Self::Error => palette.error,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Notice {
    pub kind: NoticeKind,
    pub text: String,
    pub created_at: Instant,
    pub expires_at: Option<Instant>,
}

impl Notice {
    pub fn new(kind: NoticeKind, text: impl Into<String>) -> Self {
        Self { kind, text: text.into(), created_at: Instant::now(), expires_at: None }
    }

    pub fn info(text: impl Into<String>) -> Self {
        Self::new(NoticeKind::Info, text)
    }

    pub fn success(text: impl Into<String>) -> Self {
        Self::new(NoticeKind::Success, text)
    }

    pub fn warning(text: impl Into<String>) -> Self {
        Self::new(NoticeKind::Warning, text)
    }

    pub fn error(text: impl Into<String>) -> Self {
        Self::new(NoticeKind::Error, text)
    }

    pub fn expiring(mut self, after: Duration) -> Self {
        self.expires_at = Some(self.created_at + after);
        self
    }

    pub fn style(&self, palette: &Palette) -> Style {
        Style::default().fg(self.kind.color(palette))
    }

    /// Wrapped rows needed to show this notice at `width` columns.
    pub fn rows(&self, width: u16) -> u16 {
        Paragraph::new(self.text.as_str()).wrap(Wrap { trim: false }).line_count(width.max(1)).min(usize::from(u16::MAX)) as u16
    }

    /// Wrapped notice text in its kind's color.
    pub fn draw(&self, frame: &mut Frame, area: Rect, palette: &Palette) {
        if area.is_empty() {
            return;
        }
        frame.render_widget(
            Paragraph::new(self.text.as_str()).style(self.style(palette)).wrap(Wrap { trim: false }),
            area,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::theme::default_theme;

    #[test]
    fn fit_measures_display_cells_without_splitting_characters() {
        assert!(matches!(fit("short", 5), Cow::Borrowed("short")));
        assert_eq!(fit("界界界", 5), "界界…");
        assert_eq!(fit("abcdef", 1), "…");
        assert_eq!(fit("abcdef", 0), "");
        assert_eq!(fit("é界z", 3), "é…");
    }

    #[test]
    fn buttons_wrap_keep_the_selection_visible_and_skip_disabled_hits() {
        let palette = default_theme().palette;
        let buttons = [
            Button::primary("First"),
            Button::secondary("Second").enabled(false),
            Button::danger("Third"),
            Button::secondary("Fourth"),
        ];
        assert_eq!(button_rows(16, &buttons), 2);
        let mut terminal = ratatui::Terminal::new(ratatui::backend::TestBackend::new(16, 1)).unwrap();
        let mut hits = Vec::new();
        let mut rows = 0;
        terminal.draw(|frame| {
            rows = draw_buttons(frame, Rect::new(0, 0, 16, 1), &buttons, Some(3), &palette, |index, area| hits.push((index, area)));
        }).unwrap();
        assert_eq!(rows, 1);
        // The second row is shown so that the selected fourth button stays visible.
        assert_eq!(hits.iter().map(|(index, _)| *index).collect::<Vec<_>>(), [2, 3]);
        assert!(hits.iter().all(|(_, area)| area.bottom() <= 1));
        let mut terminal = ratatui::Terminal::new(ratatui::backend::TestBackend::new(40, 1)).unwrap();
        hits.clear();
        terminal.draw(|frame| {
            draw_buttons(frame, Rect::new(0, 0, 40, 1), &buttons, None, &palette, |index, area| hits.push((index, area)));
        }).unwrap();
        assert_eq!(hits.iter().map(|(index, _)| *index).collect::<Vec<_>>(), [0, 2, 3], "disabled buttons are not clickable");
    }

    #[test]
    fn scrollbar_has_no_thumb_without_overflow() {
        let area = Rect::new(0, 0, 10, 4);
        assert!(scrollbar_thumb(area, 0, 4).is_empty());
        assert!(scrollbar_thumb(Rect::new(0, 0, 10, 0), 0, 9).is_empty());
        let top = scrollbar_thumb(area, 0, 8);
        let bottom = scrollbar_thumb(area, 4, 8);
        assert_eq!((top.x, top.y, top.height), (9, 0, 2));
        assert_eq!(bottom.bottom(), area.bottom());
    }
}
