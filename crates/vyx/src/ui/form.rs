use std::borrow::Cow;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use ratatui::{
    Frame,
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Paragraph, Wrap},
};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    shortcuts::{Bindings, Shortcut},
    theme::Palette,
    ui::{
        render::contains,
        theming,
        widgets::{self, Button, ButtonKind},
    },
};

const MAX_FIELD_BYTES: usize = 64 * 1024;
/// Longer errors wrap to this many rows; the controls stay reachable below them.
const MAX_ERROR_ROWS: u16 = 3;

/// How a field draws and accepts input. `choices`/`choice` remain the selected-value contract.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Presentation {
    /// Text or secret input, or a cycling choice when `choices` is not empty.
    #[default]
    Standard,
    /// Every choice drawn as a clickable segment when they fit; otherwise a cycling choice.
    Inline,
    /// `[x]`/`[ ]` checkbox; choice 1 is checked.
    Toggle,
    /// Muted value that cannot be focused or edited.
    ReadOnly,
}

pub struct Field {
    pub label: String,
    pub value: Zeroizing<String>,
    pub secret: bool,
    pub choices: Vec<String>,
    pub choice: usize,
    pub visible: bool,
    pub hint: &'static str,
    pub presentation: Presentation,
    cursor: usize,
}

impl Field {
    pub fn text(label: impl Into<String>, value: impl Into<String>) -> Self {
        let value = value.into();
        let cursor = value.len();
        Self {
            label: label.into(),
            value: Zeroizing::new(value),
            secret: false,
            choices: Vec::new(),
            choice: 0,
            visible: true,
            hint: "",
            presentation: Presentation::Standard,
            cursor,
        }
    }
    pub fn secret(label: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            secret: true,
            ..Self::text(label, value)
        }
    }
    pub fn select(label: impl Into<String>, choices: Vec<String>, choice: usize) -> Self {
        Self {
            choices,
            choice,
            ..Self::text(label, "")
        }
    }
    /// A short list of choices shown side by side.
    pub fn inline(label: impl Into<String>, choices: Vec<String>, choice: usize) -> Self {
        Self { presentation: Presentation::Inline, ..Self::select(label, choices, choice) }
    }
    /// An on/off checkbox. `selected()` reads "On" or "Off".
    pub fn toggle(label: impl Into<String>, checked: bool) -> Self {
        Self {
            presentation: Presentation::Toggle,
            ..Self::select(label, vec!["Off".to_owned(), "On".to_owned()], usize::from(checked))
        }
    }
    /// A value shown for reference only; it is skipped by keyboard focus.
    pub fn read_only(label: impl Into<String>, value: impl Into<String>) -> Self {
        Self { presentation: Presentation::ReadOnly, ..Self::text(label, value) }
    }
    pub fn selected(&self) -> &str {
        self.choices
            .get(self.choice)
            .map(String::as_str)
            .unwrap_or("")
    }
    pub fn checked(&self) -> bool {
        self.choice == 1
    }
    /// Visible and accepts focus.
    pub fn editable(&self) -> bool {
        self.visible && self.presentation != Presentation::ReadOnly
    }
    fn is_choice(&self) -> bool {
        !self.choices.is_empty() && self.presentation != Presentation::ReadOnly
    }
    /// A choice the mouse wheel may change while it is focused.
    fn wheel_changes_choice(&self) -> bool {
        matches!(self.presentation, Presentation::Standard | Presentation::Inline) && self.choices.len() > 1
    }

    pub fn with_hint(mut self, hint: &'static str) -> Self {
        self.hint = hint;
        self
    }

    pub fn set_value(&mut self, value: &str) {
        self.value.zeroize();
        self.value.push_str(value);
        self.cursor = self.value.len();
    }

    /// Applies a key; returns whether the value or choice changed.
    pub fn key(&mut self, key: KeyEvent, bindings: &Bindings) -> bool {
        match self.presentation {
            Presentation::ReadOnly => return false,
            Presentation::Toggle => {
                let space = key.code == KeyCode::Char(' ')
                    && !key.modifiers.intersects(KeyModifiers::CONTROL | KeyModifiers::ALT);
                return (space
                    || bindings.matches(Shortcut::PreviousChoice, key)
                    || bindings.matches(Shortcut::NextChoice, key))
                    && self.choose(1);
            }
            Presentation::Standard | Presentation::Inline => {}
        }
        if !self.choices.is_empty() {
            if bindings.matches(Shortcut::PreviousChoice, key) {
                return self.choose(-1);
            }
            if bindings.matches(Shortcut::NextChoice, key) {
                return self.choose(1);
            }
            return false;
        }
        if bindings.matches(Shortcut::CursorLeft, key) {
            self.cursor = self.previous_boundary();
        } else if bindings.matches(Shortcut::CursorRight, key) {
            self.cursor = self.next_boundary();
        } else if bindings.matches(Shortcut::Home, key) {
            self.cursor = 0;
        } else if bindings.matches(Shortcut::End, key) {
            self.cursor = self.value.len();
        } else if bindings.matches(Shortcut::Backspace, key) {
            let previous = self.previous_boundary();
            if previous == self.cursor {
                return false;
            }
            self.value.replace_range(previous..self.cursor, "");
            self.cursor = previous;
            return true;
        } else if bindings.matches(Shortcut::Delete, key) {
            let next = self.next_boundary();
            if next == self.cursor {
                return false;
            }
            self.value.replace_range(self.cursor..next, "");
            return true;
        } else if bindings.matches(Shortcut::ClearField, key) {
            let changed = !self.value.is_empty();
            self.value.clear();
            self.cursor = 0;
            return changed;
        } else if let KeyCode::Char(c) = key.code
            && !key.modifiers.intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
            && !c.is_control()
            && self.value.len() + c.len_utf8() <= MAX_FIELD_BYTES
        {
            self.value.insert(self.cursor, c);
            self.cursor += c.len_utf8();
            return true;
        }
        false
    }

    /// Moves the choice by `delta`, wrapping; returns whether it changed.
    fn choose(&mut self, delta: isize) -> bool {
        if self.choices.len() < 2 || !self.is_choice() {
            return false;
        }
        self.choice = (self.choice as isize + delta).rem_euclid(self.choices.len() as isize) as usize;
        true
    }

    fn set_choice(&mut self, choice: usize) -> bool {
        if !self.is_choice() || choice >= self.choices.len() || choice == self.choice {
            return false;
        }
        self.choice = choice;
        true
    }

    /// Inserts printable text at the cursor; returns whether anything was inserted.
    pub fn paste(&mut self, text: &str) -> bool {
        if !self.choices.is_empty() || self.presentation == Presentation::ReadOnly {
            return false;
        }
        let remaining = MAX_FIELD_BYTES.saturating_sub(self.value.len());
        let filtered;
        let text = if text.chars().any(char::is_control) {
            let mut length = 0;
            filtered = Zeroizing::new(text.chars().filter(|c| !c.is_control()).take_while(|c| {
                length += c.len_utf8();
                length <= remaining
            }).collect::<String>());
            filtered.as_str()
        } else {
            text
        };
        let mut end = text.len().min(remaining);
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        self.value.insert_str(self.cursor, &text[..end]);
        self.cursor += end;
        end > 0
    }

    fn previous_boundary(&self) -> usize {
        self.value[..self.cursor].char_indices().next_back().map_or(0, |(index, _)| index)
    }

    fn next_boundary(&self) -> usize {
        self.value[self.cursor..].chars().next().map_or(self.cursor, |c| self.cursor + c.len_utf8())
    }

    /// Inline segment rectangles when every choice fits in `area`.
    fn segments(&self, area: Rect) -> Option<Vec<Rect>> {
        if self.presentation != Presentation::Inline || self.choices.len() < 2 || area.height == 0 {
            return None;
        }
        let mut x = area.x;
        let mut segments = Vec::with_capacity(self.choices.len());
        for choice in &self.choices {
            let width = u16::try_from(widgets::width(choice) + 2).ok()?;
            if x.checked_add(width)? > area.right() {
                return None;
            }
            segments.push(Rect::new(x, area.y, width, 1));
            x = x.saturating_add(width + 1);
        }
        Some(segments)
    }

    /// The cycling `[<] (n/m) choice [>]` control is used for this choice field.
    fn cycles(&self, area: Rect) -> bool {
        self.is_choice() && self.choices.len() > 1 && self.presentation != Presentation::Toggle && self.segments(area).is_none()
    }

    pub fn draw_input(&self, frame: &mut Frame, area: Rect, focused: bool, palette: &Palette) {
        if area.width == 0 || area.height == 0 {
            return;
        }
        match self.presentation {
            Presentation::ReadOnly => {
                frame.render_widget(
                    Paragraph::new(widgets::fit(&self.value, area.width)).style(Style::default().fg(palette.muted)),
                    area,
                );
                return;
            }
            Presentation::Toggle => {
                let text = if self.checked() { "[x] On" } else { "[ ] Off" };
                frame.render_widget(Paragraph::new(widgets::fit(text, area.width)).style(palette.style()), area);
                return;
            }
            Presentation::Standard | Presentation::Inline => {}
        }
        if let Some(segments) = self.segments(area) {
            for (index, (segment, choice)) in segments.into_iter().zip(&self.choices).enumerate() {
                let style = if index == self.choice {
                    Style::default().fg(palette.background).bg(palette.foreground).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(palette.muted)
                };
                frame.render_widget(Paragraph::new(format!(" {choice} ")).style(style), segment);
            }
            return;
        }
        if !self.choices.is_empty() {
            if self.choices.len() == 1 {
                frame.render_widget(Paragraph::new(widgets::fit(self.selected(), area.width)).style(palette.style()), area);
                return;
            }
            let (previous, next) = choice_buttons(area);
            let style = Style::default().fg(palette.accent);
            frame.render_widget(Paragraph::new("[<]").style(style), previous);
            frame.render_widget(Paragraph::new("[>]").style(style), next);
            let label = format!("({}/{}) {}", self.choice + 1, self.choices.len(), self.selected());
            let label_area = Rect::new(previous.right() + 1, area.y, next.x.saturating_sub(previous.right() + 2), 1);
            frame.render_widget(Paragraph::new(widgets::fit(&label, label_area.width)).style(palette.style()), label_area);
            return;
        }
        let cursor_column;
        if self.secret {
            let width = usize::from(area.width);
            let visible = if focused {
                cursor_column = self.value[..self.cursor].chars().count().min(width - 1);
                cursor_column + self.value[self.cursor..].chars().take(width - cursor_column).count()
            } else {
                cursor_column = 0;
                self.value.chars().take(width).count()
            };
            frame.render_widget(Paragraph::new("*".repeat(visible)).style(palette.style()), area);
        } else {
            let mut start = 0;
            if focused {
                let mut width = 0;
                start = self.cursor;
                for (index, c) in self.value[..self.cursor].char_indices().rev() {
                    let next_width = Span::raw(&self.value[index..index + c.len_utf8()]).width();
                    if width + next_width >= usize::from(area.width) {
                        break;
                    }
                    width += next_width;
                    start = index;
                }
            }
            cursor_column = if focused { Span::raw(&self.value[start..self.cursor]).width() } else { 0 };
            frame.render_widget(Paragraph::new(&self.value[start..]).style(palette.style()), area);
        }
        if focused {
            frame.set_cursor_position((area.x + cursor_column.min(usize::from(area.width - 1)) as u16, area.y));
        }
    }
}

#[derive(Clone, Copy)]
enum FormTarget {
    /// The field area below all fields; only the wheel uses it.
    Body,
    Field(usize),
    PreviousChoice(usize),
    NextChoice(usize),
    Choice(usize, usize),
    Toggle(usize),
    Submit,
    Cancel,
}

pub struct FormHitRegion {
    area: Rect,
    target: FormTarget,
}

fn choice_buttons(area: Rect) -> (Rect, Rect) {
    let width = area.width.min(3);
    (
        Rect::new(area.x, area.y, width, area.height.min(1)),
        Rect::new(area.right() - width, area.y, width, area.height.min(1)),
    )
}

/// `title` within `width` cells. Leftmost ` / ` ancestors of a breadcrumb such as
/// `Settings / Security / Auto-lock` are dropped only while it does not fit; the remaining
/// page name is ellipsized as a last resort.
pub fn breadcrumb(title: &str, width: u16) -> Cow<'_, str> {
    let mut rest = title;
    while widgets::width(rest) > usize::from(width) {
        let Some((_, tail)) = rest.split_once(" / ") else { break };
        rest = tail;
    }
    widgets::fit(rest, width)
}

pub struct Form {
    pub title: String,
    pub description: String,
    pub fields: Vec<Field>,
    pub focus: usize,
    pub error: String,
    pub submit: String,
    /// An empty caption hides the Cancel button; the Cancel key still cancels.
    pub cancel: String,
    pub submit_kind: ButtonKind,
}

#[derive(PartialEq, Eq)]
pub enum Action {
    Continue,
    Submit,
    Cancel,
}

enum FormBounds {
    Dialog(Rect),
    Panel(Rect),
    Settings(Rect, bool),
}

/// Rows the form needs before clipping, for a given outer width.
struct Metrics {
    count: usize,
    description_rows: u16,
    height: u16,
}

impl Form {
    pub fn new(title: impl Into<String>, fields: Vec<Field>) -> Self {
        let focus = fields.iter().position(Field::editable).unwrap_or(0);
        Self {
            title: title.into(),
            description: String::new(),
            fields,
            focus,
            error: String::new(),
            submit: "Save".into(),
            cancel: "Cancel".into(),
            submit_kind: ButtonKind::Primary,
        }
    }
    pub fn value(&self, index: usize) -> &str {
        &self.fields[index].value
    }

    /// Moves focus to the next editable field in `direction`, without wrapping.
    fn step_focus(&mut self, direction: isize) {
        let mut index = self.focus;
        loop {
            let Some(next) = index.checked_add_signed(direction).filter(|next| *next < self.fields.len()) else {
                return;
            };
            index = next;
            if self.fields[index].editable() {
                self.focus = index;
                return;
            }
        }
    }

    pub fn key(&mut self, key: KeyEvent, bindings: &Bindings) -> Action {
        if bindings.matches(Shortcut::Cancel, key) {
            return Action::Cancel;
        }
        if bindings.matches(Shortcut::Submit, key) {
            return Action::Submit;
        }
        let count = self.fields.len();
        if count == 0 {
            return Action::Continue;
        }
        let backwards = bindings.matches(Shortcut::PreviousField, key);
        if backwards || bindings.matches(Shortcut::NextField, key) {
            for step in 1..=count {
                let next = if backwards {
                    (self.focus + count - step) % count
                } else {
                    (self.focus + step) % count
                };
                if self.fields[next].editable() {
                    self.focus = next;
                    break;
                }
            }
        } else if self.fields.get_mut(self.focus).is_some_and(|field| field.key(key, bindings)) {
            self.error.clear();
        }
        Action::Continue
    }
    pub fn paste(&mut self, text: &str) {
        if self.fields.get_mut(self.focus).is_some_and(|field| field.paste(text)) {
            self.error.clear();
        }
    }

    pub fn mouse(&mut self, mouse: MouseEvent, hits: &[FormHitRegion]) -> Action {
        let Some(hit) = hits.iter().rev().find(|hit| contains(hit.area, mouse.column, mouse.row)) else {
            return Action::Continue;
        };
        let field = match hit.target {
            FormTarget::Field(index) | FormTarget::PreviousChoice(index) | FormTarget::NextChoice(index)
            | FormTarget::Choice(index, _) | FormTarget::Toggle(index) => Some(index),
            FormTarget::Body | FormTarget::Submit | FormTarget::Cancel => None,
        };
        let changed = match mouse.kind {
            MouseEventKind::Down(MouseButton::Left) => {
                if let Some(index) = field.filter(|index| self.fields.get(*index).is_some_and(Field::editable)) {
                    self.focus = index;
                }
                let Some(field) = field.and_then(|index| self.fields.get_mut(index)) else {
                    return match hit.target {
                        FormTarget::Submit => Action::Submit,
                        FormTarget::Cancel => Action::Cancel,
                        _ => Action::Continue,
                    };
                };
                match hit.target {
                    FormTarget::PreviousChoice(_) => field.choose(-1),
                    FormTarget::NextChoice(_) | FormTarget::Toggle(_) => field.choose(1),
                    FormTarget::Choice(_, choice) => field.set_choice(choice),
                    _ => false,
                }
            }
            MouseEventKind::ScrollUp | MouseEventKind::ScrollDown
                if !matches!(hit.target, FormTarget::Submit | FormTarget::Cancel) =>
            {
                let delta = if mouse.kind == MouseEventKind::ScrollUp { -1 } else { 1 };
                match field {
                    Some(index) if index == self.focus && self.fields[index].wheel_changes_choice() => {
                        self.fields[index].choose(delta)
                    }
                    _ => {
                        self.step_focus(delta);
                        false
                    }
                }
            }
            _ => false,
        };
        if changed {
            self.error.clear();
        }
        Action::Continue
    }

    pub fn draw(
        &self,
        frame: &mut Frame,
        bounds: Rect,
        bindings: &Bindings,
        hits: &mut Vec<FormHitRegion>,
        palette: &Palette,
    ) {
        self.draw_layout(frame, FormBounds::Dialog(bounds), bindings, hits, palette);
    }

    pub fn draw_panel(
        &self,
        frame: &mut Frame,
        bounds: Rect,
        bindings: &Bindings,
        hits: &mut Vec<FormHitRegion>,
        palette: &Palette,
    ) {
        self.draw_layout(frame, FormBounds::Panel(bounds), bindings, hits, palette);
    }

    /// Settings use the available pane, with extra spacing when it fits. An inactive page
    /// (navigation owns the keyboard) draws no cursor or focus marker.
    pub fn draw_settings(
        &self,
        frame: &mut Frame,
        bounds: Rect,
        bindings: &Bindings,
        hits: &mut Vec<FormHitRegion>,
        palette: &Palette,
        active: bool,
    ) {
        self.draw_layout(frame, FormBounds::Settings(bounds, active), bindings, hits, palette);
    }

    /// Preferred dialog height, before clipping or the two-row outer margin.
    /// `width` is the outer bounds width, as supplied to `draw`.
    pub fn preferred_dialog_height(&self, width: u16) -> u16 {
        let description = Paragraph::new(self.description.as_str()).wrap(Wrap { trim: false });
        self.layout_metrics(width.saturating_sub(4).min(84), u16::MAX, &description).height
    }

    fn buttons(&self) -> Vec<Button<'_>> {
        let mut buttons = vec![Button::new(&self.submit, self.submit_kind)];
        if !self.cancel.is_empty() {
            buttons.push(Button::secondary(&self.cancel));
        }
        buttons
    }

    /// Hint rows below the buttons; none for a form without fields.
    fn hint_rows(count: usize, inner_width: u16) -> u16 {
        match count {
            0 => 0,
            _ if inner_width >= 60 => 1,
            _ => 2,
        }
    }

    fn error_rows(&self, inner_width: u16) -> u16 {
        if self.error.is_empty() {
            return 0;
        }
        (Paragraph::new(self.error.as_str()).wrap(Wrap { trim: false }).line_count(inner_width.max(1)) as u16)
            .clamp(1, MAX_ERROR_ROWS)
    }

    fn layout_metrics(&self, width: u16, max_description_height: u16, description: &Paragraph<'_>) -> Metrics {
        let inner_width = width.saturating_sub(2);
        let count = self.fields.iter().filter(|field| field.visible).count();
        let description_rows = if self.description.is_empty() { 0 } else {
            description.line_count(inner_width)
                .min(usize::from(max_description_height)) as u16
        };
        let footer_rows = widgets::button_rows(inner_width, &self.buttons()).max(1)
            + Self::hint_rows(count, inner_width);
        let height = (count.min(usize::from(u16::MAX)) as u16)
            .saturating_mul(3)
            .saturating_add(description_rows)
            .saturating_add(footer_rows + 2 + self.error_rows(inner_width));
        Metrics { count, description_rows, height }
    }

    /// Keys that apply to the focused field, highest priority first.
    fn hints(&self, bindings: &Bindings) -> Vec<String> {
        let mut hints = vec![format!("{} submit", bindings.primary(Shortcut::Submit))];
        if !self.cancel.is_empty() {
            hints.push(format!("{} {}", bindings.primary(Shortcut::Cancel), self.cancel.to_lowercase()));
        }
        if self.fields.iter().filter(|field| field.editable()).count() > 1 {
            hints.push(format!("{} next field", bindings.primary(Shortcut::NextField)));
        }
        match self.fields.get(self.focus).filter(|field| field.editable()) {
            Some(field) if field.presentation == Presentation::Toggle => {
                hints.push(format!("Space/{} toggle", bindings.primary(Shortcut::NextChoice)));
            }
            Some(field) if field.is_choice() && field.choices.len() > 1 => {
                hints.push(format!("{}/{} choose", bindings.primary(Shortcut::PreviousChoice), bindings.primary(Shortcut::NextChoice)));
            }
            Some(field) if field.choices.is_empty() => {
                hints.push(format!("{}/{} move", bindings.primary(Shortcut::CursorLeft), bindings.primary(Shortcut::CursorRight)));
                hints.push(format!("{}/{} start/end", bindings.primary(Shortcut::Home), bindings.primary(Shortcut::End)));
                hints.push(format!("{} delete", bindings.primary(Shortcut::Delete)));
                hints.push(format!("{} clear", bindings.primary(Shortcut::ClearField)));
            }
            _ => {}
        }
        hints
    }

    /// Packs hints into at most `rows` lines of `width` cells; lower-priority hints that do not
    /// fit are omitted rather than clipped.
    fn hint_lines(&self, bindings: &Bindings, width: u16, rows: u16) -> Vec<String> {
        let mut lines: Vec<String> = Vec::new();
        let width = usize::from(width);
        for hint in self.hints(bindings) {
            let hint_width = widgets::width(&hint);
            if hint_width > width {
                continue;
            }
            if let Some(line) = lines.last_mut()
                && widgets::width(line) + 3 + hint_width <= width
            {
                line.push_str(" · ");
                line.push_str(&hint);
            } else if lines.len() < usize::from(rows) {
                lines.push(hint);
            }
        }
        lines
    }

    fn draw_layout(
        &self,
        frame: &mut Frame,
        layout: FormBounds,
        bindings: &Bindings,
        hits: &mut Vec<FormHitRegion>,
        palette: &Palette,
    ) {
        let (bounds, panel, settings, active) = match layout {
            FormBounds::Dialog(bounds) => (bounds, false, false, true),
            FormBounds::Panel(bounds) => (bounds, true, false, true),
            FormBounds::Settings(bounds, active) => (bounds, true, true, active),
        };
        let width = if panel { bounds.width } else { bounds.width.saturating_sub(4).min(84) };
        let description = Paragraph::new(self.description.as_str()).wrap(Wrap { trim: false });
        let Metrics { count, description_rows, height: preferred_height } = self.layout_metrics(width, bounds.height, &description);
        let area = if panel {
            bounds
        } else {
            let height = preferred_height.min(bounds.height.saturating_sub(2));
            Rect::new(
                bounds.x + (bounds.width - width) / 2,
                bounds.y + (bounds.height - height) / 2,
                width,
                height,
            )
        };
        theming::clear(frame, area, palette);
        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(if settings { BorderType::Rounded } else { BorderType::Plain })
            .style(palette.style())
            .border_style(Style::default().fg(palette.accent));
        let mut inner = block.inner(area);
        if settings && inner.width >= 40 {
            inner.x += 2;
            inner.width = inner.width.saturating_sub(4).min(96);
        }
        if settings && inner.height >= preferred_height.saturating_add(4) {
            inner.y += 1;
            inner.height -= 2;
        }
        let inline_fields = settings && inner.width >= 68
            && self.fields.iter().filter(|field| field.visible)
                .all(|field| Span::raw(field.label.as_str()).width() <= 24);

        let buttons = self.buttons();
        let button_rows = widgets::button_rows(inner.width, &buttons).max(1);
        let separator = settings && inner.height >= 12;
        let minimum_field_height = if count == 0 { 0 } else { 2 };
        let error_rows = self.error_rows(inner.width);
        // Hints yield first: the buttons, the focused field and the error keep their rows.
        let hint_budget = inner.height
            .saturating_sub(button_rows + u16::from(separator) + minimum_field_height + error_rows);
        let hint_lines = self.hint_lines(bindings, inner.width, Self::hint_rows(count, inner.width).min(hint_budget));
        let footer_height = (button_rows + hint_lines.len() as u16 + u16::from(separator)).min(inner.height);
        let body = Rect {
            height: inner.height - footer_height,
            ..inner
        };
        let footer = Rect::new(inner.x, body.bottom(), inner.width, footer_height);
        let error_height = error_rows.min(body.height.saturating_sub(minimum_field_height));
        let description_height = if settings {
            description.line_count(inner.width.max(1)).min(usize::from(u16::MAX)) as u16
        } else { description_rows };
        let description_height = description_height.min(
            body.height.saturating_sub(error_height + minimum_field_height),
        );
        let gap = u16::from(settings && description_height > 0
            && body.height > description_height + error_height + minimum_field_height);
        let fields_y = body.y + description_height + gap;
        let field_height = body.height.saturating_sub(description_height + gap + error_height);
        let stride = if settings && !inline_fields && usize::from(field_height) >= count.saturating_mul(4) {
            4
        } else { 3 };
        // The final setting needs its control, not a trailing spacer row.
        let trailing_space = if settings { stride - 2 } else { 0 };
        let visible_fields = (usize::from(field_height.saturating_add(trailing_space)) / usize::from(stride)).max(1);
        let position = self.fields[..self.focus.min(self.fields.len())].iter().filter(|field| field.visible).count();
        let start = position.saturating_sub(visible_fields - 1).min(count.saturating_sub(visible_fields));
        let hidden = count > visible_fields && field_height > 0;

        let counter = if hidden {
            format!(" · {}-{}/{count}", start + 1, (start + visible_fields).min(count))
        } else {
            String::new()
        };
        let room = area.width.saturating_sub(4).saturating_sub(widgets::width(&counter).min(usize::from(u16::MAX)) as u16);
        let title = format!(" {}{counter} ", breadcrumb(&self.title, room));
        frame.render_widget(block.title(title), area);
        frame.render_widget(
            description.style(if settings { Style::default().fg(palette.muted) } else { palette.style() }),
            Rect::new(body.x, body.y, body.width, description_height),
        );

        let field_area = Rect::new(body.x, fields_y, body.width.saturating_sub(u16::from(hidden && body.width > 1)), field_height);
        hits.push(FormHitRegion { area: Rect { width: body.width, ..field_area }, target: FormTarget::Body });
        for (row, (index, field)) in self.fields.iter().enumerate()
            .filter(|(_, field)| field.visible)
            .skip(start)
            .take(visible_fields)
            .enumerate()
        {
            let y = fields_y + row as u16 * stride;
            let bottom = body.bottom() - error_height;
            if y >= bottom {
                break;
            }
            hits.push(FormHitRegion {
                area: Rect::new(field_area.x, y, field_area.width, (bottom - y).min(stride - 1)),
                target: FormTarget::Field(index),
            });
            let selected = index == self.focus && active && field.editable();
            let style = if selected {
                Style::default().fg(palette.accent).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(if settings && field.presentation != Presentation::ReadOnly { palette.foreground } else { palette.muted })
            };
            frame.render_widget(
                Paragraph::new(format!("{}{}", if selected { "> " } else { "  " }, field.label)).style(style),
                Rect::new(field_area.x, y, if inline_fields { 26 } else { field_area.width }, 1),
            );
            let input_y = y + u16::from(!inline_fields);
            if input_y < bottom {
                let offset = if inline_fields { 27 } else { 2 };
                let input = Rect::new(field_area.x + offset, input_y, field_area.width.saturating_sub(offset), 1);
                let mut input_palette = *palette;
                input_palette.background = if selected { palette.selection_bg } else { palette.surface };
                input_palette.foreground = if selected { palette.selection_fg } else { palette.foreground };
                input_palette.accent = input_palette.foreground;
                if field.presentation != Presentation::ReadOnly {
                    frame.render_widget(Block::default().style(input_palette.style()), input);
                }
                field.draw_input(frame, input, selected, &input_palette);
                if field.presentation == Presentation::Toggle {
                    hits.push(FormHitRegion { area: Rect { width: input.width.min(7), ..input }, target: FormTarget::Toggle(index) });
                } else if let Some(segments) = field.segments(input) {
                    hits.extend(segments.into_iter().enumerate()
                        .map(|(choice, area)| FormHitRegion { area, target: FormTarget::Choice(index, choice) }));
                } else if field.cycles(input) {
                    let (previous, next) = choice_buttons(input);
                    hits.push(FormHitRegion { area: previous, target: FormTarget::PreviousChoice(index) });
                    hits.push(FormHitRegion { area: next, target: FormTarget::NextChoice(index) });
                }
            }
            let hint_y = input_y + 1;
            if hint_y < bottom {
                let hint_rows = if inline_fields { stride - 2 } else { stride - 3 }.max(1);
                frame.render_widget(
                    Paragraph::new(field.hint).wrap(Wrap { trim: false }).style(Style::default().fg(palette.muted)),
                    Rect::new(field_area.x + 2, hint_y, field_area.width.saturating_sub(2), hint_rows.min(bottom - hint_y)),
                );
            }
        }
        if hidden {
            widgets::draw_scrollbar(frame, Rect { width: body.width, ..field_area }, start, count, palette);
        }
        if error_height > 0 {
            frame.render_widget(
                Paragraph::new(self.error.as_str()).wrap(Wrap { trim: false }).style(Style::default().fg(palette.error)),
                Rect::new(body.x, body.bottom() - error_height, body.width, error_height),
            );
        }
        let footer = if separator && footer.height > 1 {
            frame.render_widget(
                Block::default().borders(Borders::TOP).border_style(Style::default().fg(palette.border)),
                Rect::new(footer.x, footer.y, footer.width, 1),
            );
            Rect::new(footer.x, footer.y + 1, footer.width, footer.height - 1)
        } else { footer };
        let drawn = widgets::draw_buttons(frame, Rect { height: footer.height.min(button_rows), ..footer }, &buttons, None, palette, |index, area| {
            hits.push(FormHitRegion { area, target: if index == 0 { FormTarget::Submit } else { FormTarget::Cancel } });
        });
        // An inactive page keeps the rows, but its keys do not reach it until it is focused.
        if active {
            let hints = Rect::new(footer.x, footer.y + drawn, footer.width, footer.height.saturating_sub(drawn));
            frame.render_widget(
                Paragraph::new(hint_lines.into_iter().map(Line::from).collect::<Vec<_>>()).style(Style::default().fg(palette.muted)),
                hints,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        theme::default_theme,
        ui::actions::{Dialog, DialogInput, Editor, Mutation},
        vault::{Auth, Credential, Host, HostAuth, LocalState, Secret, Vault},
    };
    use uuid::Uuid;

    fn credential(id: Uuid, username: &str, auth: Auth) -> Credential {
        Credential {
            id,
            label: "Shared name".into(),
            username: username.into(),
            auth,
        }
    }

    fn saved_host(id: Uuid, credential_id: Uuid) -> Host {
        Host {
            id,
            label: "Server".into(),
            hostname: "example.test".into(),
            port: 22,
            transport: crate::vault::HostTransport::Direct,
            category_id: None,
            auth: HostAuth::Credential { credential_id },
        }
    }

    fn replace_field(editor: &mut Editor, index: usize, value: &str) {
        editor.form.fields[index].value.clear();
        editor.form.fields[index].value.push_str(value);
    }

    #[tokio::test]
    async fn mouse_reassigns_an_existing_host_to_the_selected_credential_id() {
        let first = Uuid::from_u128(1);
        let second = Uuid::from_u128(2);
        let host_id = Uuid::from_u128(3);
        let mut vault = Vault::new();
        // Deliberately unsorted, identical labels: assignments must follow IDs.
        vault.credentials = [second, first]
            .into_iter()
            .map(|id| credential(id, "user", Auth::Agent))
            .collect();
        vault.hosts.push(saved_host(host_id, second));
        let mut dialog = Dialog::Editor(Editor::host(&vault, Some(host_id), None).unwrap());
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(90, 28)).unwrap();
        let mut hits = Vec::new();
        terminal
            .draw(|frame| {
                dialog.draw(
                    frame,
                    frame.area(),
                    &vault,
                    &Bindings::default(),
                    &mut hits,
                    &default_theme().palette,
                )
            })
            .unwrap();
        let next = hits
            .iter()
            .find(|hit| matches!(hit.target, FormTarget::NextChoice(5)))
            .unwrap();
        let mouse = MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: next.area.x,
            row: next.area.y,
            modifiers: KeyModifiers::NONE,
        };
        dialog.mouse(mouse, &hits);
        // Releasing the button must not advance a second time.
        dialog.mouse(
            MouseEvent {
                kind: MouseEventKind::Up(MouseButton::Left),
                ..mouse
            },
            &hits,
        );
        let Dialog::Editor(mut editor) = dialog else {
            panic!("editor changed")
        };
        let Mutation::PutHost { host, create } = editor.mutation(&vault).await.unwrap() else {
            panic!("server edit produced a different mutation")
        };
        assert!(!create);
        assert_eq!(host.id, host_id);
        assert_eq!(
            host.auth,
            HostAuth::Credential {
                credential_id: first
            }
        );
        assert_eq!(
            vault.hosts[0].auth,
            HostAuth::Credential {
                credential_id: second
            },
            "editing must not bypass Save"
        );
    }

    #[tokio::test]
    async fn host_authentication_transitions_keep_drafts_and_shared_credentials_isolated() {
        let credential_id = Uuid::from_u128(10);
        let host_id = Uuid::from_u128(11);
        let mut vault = Vault::new();
        vault.credentials.push(credential(
            credential_id,
            "shared-user",
            Auth::Password {
                password: Secret::new("shared-secret"),
            },
        ));
        vault.hosts.push(saved_host(host_id, credential_id));

        let mut dialog = Dialog::Editor(Editor::host(&vault, Some(host_id), None).unwrap());
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(90, 40)).unwrap();
        let mut hits = Vec::new();
        terminal
            .draw(|frame| {
                dialog.draw(
                    frame,
                    frame.area(),
                    &vault,
                    &Bindings::default(),
                    &mut hits,
                    &default_theme().palette,
                )
            })
            .unwrap();
        let password_choice = hits
            .iter()
            .find(|hit| matches!(hit.target, FormTarget::Choice(4, 1)))
            .unwrap();
        dialog.mouse(
            MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Left),
                column: password_choice.area.x,
                row: password_choice.area.y,
                modifiers: KeyModifiers::NONE,
            },
            &hits,
        );
        let Dialog::Editor(editor) = &mut dialog else {
            panic!("editor changed")
        };
        assert!(!editor.form.fields[5].visible);
        assert!(editor.form.fields[6].visible);
        assert!(editor.form.fields[7].visible);
        assert_eq!(editor.form.value(6), "shared-user");
        assert_eq!(editor.form.value(7), "", "shared secret must not be copied");
        replace_field(editor, 6, "server-user");
        replace_field(editor, 7, "server-password-plaintext");

        hits.clear();
        terminal
            .draw(|frame| {
                dialog.draw(
                    frame,
                    frame.area(),
                    &vault,
                    &Bindings::default(),
                    &mut hits,
                    &default_theme().palette,
                )
            })
            .unwrap();
        let rendered: String = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect();
        assert!(!rendered.contains("server-password-plaintext"));

        let Dialog::Editor(editor) = &mut dialog else {
            panic!("editor changed")
        };
        let mutation = editor.mutation(&vault).await.unwrap();
        let Mutation::PutHost { host, create } = &mutation else {
            panic!("server edit produced a different mutation")
        };
        assert!(!*create);
        assert_eq!(host.id, host_id);
        let HostAuth::Password { username, password } = &host.auth else {
            panic!("server did not switch to its own password")
        };
        assert_eq!(username, "server-user");
        assert_eq!(password.expose(), "server-password-plaintext");
        assert_eq!(vault.hosts[0], saved_host(host_id, credential_id));
        let Auth::Password { password } = &vault.credentials[0].auth else {
            panic!("shared credential auth changed")
        };
        assert_eq!(password.expose(), "shared-secret");

        let mut state = LocalState::new(vault, None);
        mutation.apply(&mut state).unwrap();
        let vault = state.vault;
        let mut dialog = Dialog::Editor(Editor::host(&vault, Some(host_id), None).unwrap());
        let Dialog::Editor(editor) = &mut dialog else {
            panic!("editor changed")
        };
        assert_eq!(editor.form.fields[4].choice, 1);
        assert_eq!(editor.form.value(6), "server-user");
        assert_eq!(editor.form.value(7), "server-password-plaintext");
        editor.form.focus = 4;
        assert_eq!(
            dialog.input(
                KeyEvent::new(KeyCode::Left, KeyModifiers::NONE),
                &Bindings::default()
            ),
            DialogInput::Continue
        );
        let Dialog::Editor(editor) = &dialog else {
            panic!("editor changed")
        };
        assert!(editor.form.fields[5].visible);
        assert!(!editor.form.fields[6].visible);
        assert!(!editor.form.fields[7].visible);

        dialog.input(
            KeyEvent::new(KeyCode::Right, KeyModifiers::NONE),
            &Bindings::default(),
        );
        let Dialog::Editor(editor) = &dialog else {
            panic!("editor changed")
        };
        assert_eq!(editor.form.value(6), "server-user");
        assert_eq!(editor.form.value(7), "server-password-plaintext");
        dialog.input(
            KeyEvent::new(KeyCode::Left, KeyModifiers::NONE),
            &Bindings::default(),
        );
        let Dialog::Editor(editor) = &mut dialog else {
            panic!("editor changed")
        };
        let mutation = editor.mutation(&vault).await.unwrap();
        let Mutation::PutHost { host, .. } = &mutation else {
            panic!("server edit produced a different mutation")
        };
        assert_eq!(
            host.auth,
            HostAuth::Credential { credential_id },
            "hidden password auth must not be saved"
        );
        let Auth::Password { password } = &vault.credentials[0].auth else {
            panic!("shared credential auth changed")
        };
        assert_eq!(password.expose(), "shared-secret");
        let mut state = LocalState::new(vault, None);
        mutation.apply(&mut state).unwrap();
        let reopened = Editor::host(&state.vault, Some(host_id), None).unwrap();
        assert_eq!(reopened.form.fields[4].choice, 0);
        assert!(reopened.form.fields[5].visible);
        assert!(!reopened.form.fields[6].visible);
        assert!(!reopened.form.fields[7].visible);
    }

    #[tokio::test]
    async fn tailscale_identity_is_bound_until_explicit_standard_conversion() {
        use crate::vault::{HostTransport, TailscaleIdentity};
        let mut vault = Vault::new();
        let id = Uuid::new_v4();
        vault.hosts.push(Host {
            id, label: "Reviewed device".into(), hostname: "device.example.ts.net".into(),
            port: 22, category_id: None, transport: HostTransport::Tailscale,
            auth: HostAuth::Tailscale { username: "alice".into(), tailscale: TailscaleIdentity { tailnet_id: "tailnet".into(), node_id: "node".into() } },
        });
        let mut editor = Editor::host(&vault, Some(id), None).unwrap();
        assert!(!editor.form.fields[1].visible && !editor.form.fields[2].visible);
        assert!(!editor.form.fields[5].visible && !editor.form.fields[7].visible);
        replace_field(&mut editor, 1, "unreviewed-alias.example");
        let Mutation::PutHost { host, .. } = editor.mutation(&vault).await.unwrap() else { panic!("host mutation"); };
        assert_eq!(host.hostname, "device.example.ts.net");
        assert_eq!(host.auth, vault.hosts[0].auth);
        editor.form.focus = 4;
        let mut dialog = Dialog::Editor(editor);
        dialog.input(KeyEvent::new(KeyCode::Left, KeyModifiers::NONE), &Bindings::default());
        let Dialog::Editor(mut editor) = dialog else { panic!("editor"); };
        replace_field(&mut editor, 6, "ordinary-user");
        replace_field(&mut editor, 7, "ordinary-password");
        let Mutation::PutHost { host, .. } = editor.mutation(&vault).await.unwrap() else { panic!("host mutation"); };
        assert_eq!(host.transport, HostTransport::Tailscale);
        assert!(matches!(host.auth, HostAuth::Password { .. }));
        assert_eq!(host.hostname, "unreviewed-alias.example");
        editor.form.focus = 8;
        let mut dialog = Dialog::Editor(editor);
        dialog.input(KeyEvent::new(KeyCode::Left, KeyModifiers::NONE), &Bindings::default());
        let Dialog::Editor(mut editor) = dialog else { panic!("editor"); };
        let Mutation::PutHost { host, .. } = editor.mutation(&vault).await.unwrap() else { panic!("host mutation"); };
        assert_eq!(host.transport, HostTransport::Direct);
        assert_eq!(vault.hosts[0].transport, HostTransport::Tailscale, "draft changes require explicit save");
    }

    #[tokio::test]
    async fn password_host_can_be_created_without_saved_credentials() {
        let vault = Vault::new();
        let mut editor = Editor::host(&vault, None, None).unwrap();
        assert_eq!(editor.form.fields[4].choice, 1);
        assert!(!editor.form.fields[5].visible);
        assert!(editor.form.fields[6].visible);
        assert!(editor.form.fields[7].visible);
        replace_field(&mut editor, 0, "Standalone");
        replace_field(&mut editor, 1, "standalone.example");
        replace_field(&mut editor, 6, "inline-user");
        replace_field(&mut editor, 7, "inline-password-plaintext");

        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(90, 40)).unwrap();
        let mutation = editor.mutation(&vault).await.unwrap();
        let Mutation::PutHost { host, create } = &mutation else {
            panic!("server creation produced a different mutation")
        };
        assert!(*create);
        let HostAuth::Password { username, password } = &host.auth else {
            panic!("server did not use its own password")
        };
        assert_eq!(username, "inline-user");
        assert_eq!(password.expose(), "inline-password-plaintext");

        let host_id = host.id;
        let mut state = LocalState::new(vault, None);
        mutation.apply(&mut state).unwrap();
        assert!(state.vault.credentials.is_empty());
        let saved = state.vault;
        let mut dialog = Dialog::preview(host_id);
        terminal
            .draw(|frame| {
                dialog.draw(
                    frame,
                    frame.area(),
                    &saved,
                    &Bindings::default(),
                    &mut Vec::new(),
                    &default_theme().palette,
                )
            })
            .unwrap();
        let preview: String = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect();
        assert!(preview.contains("inline-user"));
        assert!(!preview.contains("inline-password-plaintext"));
    }

    #[test]
    fn editing_and_pasting_use_utf8_cursor_boundaries() {
        let mut field = Field::text("Name", "a界z");
        field.key(KeyEvent::new(KeyCode::Left, KeyModifiers::NONE), &Bindings::default());
        field.key(KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE), &Bindings::default());
        field.paste("é\n\t");
        assert_eq!(field.value.as_str(), "aéz");
        field.key(KeyEvent::new(KeyCode::Home, KeyModifiers::NONE), &Bindings::default());
        field.key(KeyEvent::new(KeyCode::Delete, KeyModifiers::NONE), &Bindings::default());
        field.key(KeyEvent::new(KeyCode::Right, KeyModifiers::NONE), &Bindings::default());
        field.key(KeyEvent::new(KeyCode::Char('界'), KeyModifiers::NONE), &Bindings::default());
        assert_eq!(field.value.as_str(), "é界z");
        field.key(KeyEvent::new(KeyCode::End, KeyModifiers::NONE), &Bindings::default());
        field.key(KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE), &Bindings::default());
        assert_eq!(field.value.as_str(), "é界");
    }

    #[tokio::test]
    async fn invalid_drafts_focus_the_first_invalid_field_in_display_order() {
        let vault = Vault::new();
        let mut editor = Editor::host(&vault, None, None).unwrap();
        editor.form.focus = 7;
        let steps: [(&[(usize, &str)], usize); 5] = [
            (&[], 0),
            (&[(0, "Web")], 1),
            (&[(1, "web.example"), (2, "0")], 2),
            (&[(2, "2222")], 6),
            (&[(6, "deploy")], 7),
        ];
        for (edits, invalid) in steps {
            for (field, value) in edits {
                replace_field(&mut editor, *field, value);
            }
            assert!(editor.mutation(&vault).await.is_err());
            assert_eq!(editor.form.focus, invalid, "after {edits:?}");
        }
        assert_eq!([editor.form.value(0), editor.form.value(1), editor.form.value(2)], ["Web", "web.example", "2222"]);
        replace_field(&mut editor, 7, "secret");
        assert!(editor.mutation(&vault).await.is_ok());

        let mut credential = Editor::credential(&vault, None).unwrap();
        credential.form.focus = 3;
        assert!(credential.mutation(&vault).await.is_err());
        assert_eq!(credential.form.focus, 0, "labels are checked before secrets");

        let mut snippet = Editor::snippet(&vault, None).unwrap();
        replace_field(&mut snippet, 0, "List");
        replace_field(&mut snippet, 1, " \t ");
        assert!(snippet.mutation(&vault).await.is_err());
        assert_eq!(snippet.form.focus, 1);
        replace_field(&mut snippet, 1, "  ls -la ");
        let Mutation::PutSnippet { snippet, .. } = snippet.mutation(&vault).await.unwrap() else { panic!("snippet") };
        assert_eq!(snippet.command, "  ls -la ", "nonblank commands are kept exactly");
    }

    #[tokio::test]
    async fn private_key_import_expands_only_a_leading_home_tilde() {
        let home = directories::BaseDirs::new().unwrap().home_dir().display().to_string();
        let vault = Vault::new();
        for (input, opened) in [
            ("~/.vyx-test-missing-key", format!("{home}/.vyx-test-missing-key")),
            ("~other/key", "~other/key".to_owned()),
            ("$HOME/key", "$HOME/key".to_owned()),
        ] {
            let mut editor = Editor::credential(&vault, None).unwrap();
            replace_field(&mut editor, 0, "Key");
            replace_field(&mut editor, 1, "deploy");
            editor.form.focus = 2;
            let mut dialog = Dialog::Editor(editor);
            dialog.input(KeyEvent::new(KeyCode::Right, KeyModifiers::NONE), &Bindings::default());
            let Dialog::Editor(mut editor) = dialog else { panic!("editor") };
            replace_field(&mut editor, 4, input);
            let error = format!("{:#}", editor.mutation(&vault).await.err().unwrap());
            assert!(error.starts_with(&format!("Cannot open private key file {opened}:")), "{error}");
            assert_eq!(editor.form.focus, 4);
        }
    }

    #[test]
    fn long_errors_keep_the_focused_field_and_buttons_at_minimum_size() {
        let mut form = Form::new("Edit server", vec![Field::text("Label", ""), Field::text("Port", "22")]);
        form.error = "Port must be a number from 1 to 65535. ".repeat(4);
        let mut terminal = ratatui::Terminal::new(ratatui::backend::TestBackend::new(40, 10)).unwrap();
        let mut hits = Vec::new();
        terminal.draw(|frame| form.draw(frame, frame.area(), &Bindings::default(), &mut hits, &default_theme().palette)).unwrap();
        assert!(hits.iter().any(|hit| matches!(hit.target, FormTarget::Field(0))), "focused field hidden by the error");
        assert!(hits.iter().any(|hit| matches!(hit.target, FormTarget::Submit)));
        let rendered: String = terminal.backend().buffer().content.iter().map(|cell| cell.symbol()).collect();
        assert!(rendered.contains("Port must be"));
    }

    #[test]
    fn confirmation_exposes_the_full_fingerprint() {
        let fingerprint = "SHA256:0123456789abcdefghijklmnopqrstuvwxyzABCDEFG";
        let mut form = Form::new("Confirm", Vec::new());
        form.description = format!(
            "endpoint.example:2222 presented an ssh-ed25519 key: {fingerprint}. Verify it before trusting."
        );
        for (width, height) in [(90, 24), (48, 16)] {
            let mut terminal = ratatui::Terminal::new(
                ratatui::backend::TestBackend::new(width, height),
            ).unwrap();
            terminal.draw(|frame| form.draw(frame, frame.area(), &Bindings::default(), &mut Vec::new(), &default_theme().palette)).unwrap();
            let rendered: String = terminal.backend().buffer().content.iter()
                .flat_map(|cell| cell.symbol().chars())
                .filter(|c| c.is_ascii_alphanumeric() || *c == ':')
                .collect();
            assert!(rendered.contains(fingerprint), "fingerprint hidden at {width}x{height}");
        }
    }

    #[test]
    fn field_limit_never_splits_a_pasted_or_typed_character() {
        let mut field = Field::secret("Secret", "x".repeat(MAX_FIELD_BYTES - 2));
        field.paste("界");
        field.key(KeyEvent::new(KeyCode::Char('界'), KeyModifiers::NONE), &Bindings::default());
        assert_eq!(field.value.as_str(), "x".repeat(MAX_FIELD_BYTES - 2));
        field.paste("é界");
        assert!(field.value.ends_with("xé"));
        assert_eq!(field.value.len(), MAX_FIELD_BYTES);
        field.key(KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE), &Bindings::default());
        assert_eq!(field.value.as_str(), "x".repeat(MAX_FIELD_BYTES - 2));
    }

    /// Draws `dialog` alone and returns the screen, one line per row.
    fn draw_dialog(dialog: &mut Dialog, width: u16, height: u16) -> String {
        let mut terminal = ratatui::Terminal::new(ratatui::backend::TestBackend::new(width, height)).unwrap();
        terminal.draw(|frame| {
            dialog.draw(frame, frame.area(), &Vault::new(), &Bindings::default(), &mut Vec::new(), &default_theme().palette)
        }).unwrap();
        let buffer = terminal.backend().buffer();
        (0..height)
            .map(|y| (0..width).map(|x| buffer[(x, y)].symbol()).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn click(column: u16, row: u16) -> MouseEvent {
        MouseEvent { kind: MouseEventKind::Down(MouseButton::Left), column, row, modifiers: KeyModifiers::NONE }
    }

    #[test]
    fn long_review_payload_is_reachable_by_scrolling_with_actions_visible() {
        use crate::ui::actions::ExtensionReview;
        let tokens: Vec<String> = (0..600).map(|index| format!("m{index:03}")).collect();
        let payload = format!("printf '%s ' {}", tokens.join(" "));
        let bindings = Bindings::default();
        let scroll = |dialog: &Dialog| match dialog {
            Dialog::ExtensionReview(review) => review.state.scroll,
            _ => unreachable!(),
        };
        for (width, height) in [(80, 24), (40, 10)] {
            let review = ExtensionReview::new("Run command", "Target: fixture session.\n\nReason: print markers.".into(), "Run")
                .with_payload(payload.as_str());
            let mut dialog = Dialog::ExtensionReview(review);
            let mut seen = String::new();
            loop {
                seen.push_str(&draw_dialog(&mut dialog, width, height));
                seen.push('\n');
                let Dialog::ExtensionReview(review) = &dialog else { unreachable!() };
                let state = &review.state;
                assert!(state.max_scroll > 0, "the payload overflows at {width}x{height}");
                assert_eq!(state.hits.iter().map(|&(index, _)| index).collect::<Vec<_>>(), [0, 1], "actions hidden at {width}x{height}");
                // Below the scrolled body and above the application status row.
                assert!(state.hits.iter().all(|(_, area)| area.y >= state.body.bottom() && area.bottom() < height));
                let before = state.scroll;
                dialog.input(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE), &bindings);
                if scroll(&dialog) == before {
                    break;
                }
            }
            let missing: Vec<&String> = tokens.iter().filter(|token| !seen.contains(token.as_str())).collect();
            assert!(missing.is_empty(), "unreachable at {width}x{height}: {missing:?}");

            // The wheel scrolls the body, not the buttons.
            let Dialog::ExtensionReview(review) = &dialog else { unreachable!() };
            let (body, button, bottom) = (review.state.body, review.state.hits[0].1, review.state.scroll);
            dialog.mouse(MouseEvent { kind: MouseEventKind::ScrollUp, ..click(button.x, button.y) }, &[]);
            assert_eq!(scroll(&dialog), bottom);
            dialog.mouse(MouseEvent { kind: MouseEventKind::ScrollUp, ..click(body.x, body.y) }, &[]);
            assert!(scroll(&dialog) < bottom);
        }
    }

    #[test]
    fn snippet_insert_is_disabled_without_a_connected_target() {
        use crate::ui::actions::SnippetDialog;
        let bindings = Bindings::default();
        let target = || Some((Uuid::from_u128(7), "web".to_owned()));
        // The last case is a target that disconnected after the dialog opened.
        for (target, connected) in [(None, false), (target(), true), (target(), false)] {
            let mut snippet = SnippetDialog::new("printf ready".into(), target);
            snippet.available = connected;
            let mut dialog = Dialog::Snippet(snippet);
            draw_dialog(&mut dialog, 80, 24);
            let Dialog::Snippet(snippet) = &dialog else { unreachable!() };
            assert_eq!(snippet.state.hits.iter().any(|&(index, _)| index == 0), connected);
            let cancel = snippet.state.hits.iter().find(|&&(index, _)| index == 1).expect("Cancel stays clickable").1;
            let expected = if connected { DialogInput::Submit } else { DialogInput::Continue };
            // Insert is drawn just left of Cancel.
            assert_eq!(dialog.mouse(click(cancel.x - 2, cancel.y), &[]), expected);
            assert_eq!(dialog.input(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE), &bindings), expected);
            assert_eq!(dialog.mouse(click(cancel.x, cancel.y), &[]), DialogInput::Cancel);
        }
    }

    #[test]
    fn sync_question_buttons_submit_their_own_choice() {
        use crate::{sync::{QuestionKind, SyncChoice, SyncQuestion}, ui::actions::SyncQuestionDialog};
        let bindings = Bindings::default();
        let question = |kind| Dialog::SyncQuestion(SyncQuestionDialog::new(SyncQuestion { summary: "Both devices changed.".into(), kind }));
        let choice = |dialog: &Dialog| match dialog {
            Dialog::SyncQuestion(question) => question.choice(),
            _ => unreachable!(),
        };
        for (kind, expected) in [
            (QuestionKind::Conflict, &[SyncChoice::KeepLocal, SyncChoice::UseServer, SyncChoice::Cancel][..]),
            (QuestionKind::Upload, &[SyncChoice::KeepLocal, SyncChoice::Cancel][..]),
        ] {
            let mut dialog = question(kind);
            draw_dialog(&mut dialog, 80, 24);
            let Dialog::SyncQuestion(drawn) = &dialog else { unreachable!() };
            let hits = drawn.state.hits.clone();
            assert_eq!(hits.iter().map(|&(index, _)| index).collect::<Vec<_>>(), (0..expected.len()).collect::<Vec<_>>());
            // A click submits its own button, whichever was highlighted before.
            for (&(_, area), &answer) in hits.iter().zip(expected).rev() {
                assert_eq!(dialog.mouse(click(area.x, area.y), &[]), DialogInput::Submit);
                assert_eq!(choice(&dialog), answer);
            }
        }

        let key = |code| KeyEvent::new(code, KeyModifiers::NONE);
        let mut dialog = question(QuestionKind::Conflict);
        assert_eq!(dialog.input(key(KeyCode::Right), &bindings), DialogInput::Continue);
        assert_eq!(dialog.input(key(KeyCode::Enter), &bindings), DialogInput::Submit);
        assert_eq!(choice(&dialog), SyncChoice::UseServer);
        dialog.input(key(KeyCode::Tab), &bindings);
        dialog.input(key(KeyCode::Tab), &bindings);
        assert_eq!(choice(&dialog), SyncChoice::KeepLocal, "Tab wraps past Cancel");
        dialog.input(key(KeyCode::Left), &bindings);
        assert_eq!(choice(&dialog), SyncChoice::Cancel, "Left wraps to the last button");
        assert_eq!(dialog.input(key(KeyCode::Esc), &bindings), DialogInput::Cancel);
    }
}
