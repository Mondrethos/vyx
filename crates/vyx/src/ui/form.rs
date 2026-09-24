use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
};
use zeroize::Zeroizing;

pub struct Field {
    pub label: String,
    pub value: Zeroizing<String>,
    pub secret: bool,
    pub choices: Vec<String>,
    pub choice: usize,
}

impl Field {
    pub fn text(label: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            value: Zeroizing::new(value.into()),
            secret: false,
            choices: Vec::new(),
            choice: 0,
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
    pub fn selected(&self) -> &str {
        self.choices
            .get(self.choice)
            .map(String::as_str)
            .unwrap_or("")
    }
}

pub struct Form {
    pub title: String,
    pub description: String,
    pub fields: Vec<Field>,
    pub focus: usize,
    pub error: String,
    pub submit: String,
}

#[derive(PartialEq, Eq)]
pub enum Action {
    Continue,
    Submit,
    Cancel,
}

impl Form {
    pub fn new(title: impl Into<String>, fields: Vec<Field>) -> Self {
        Self {
            title: title.into(),
            description: String::new(),
            fields,
            focus: 0,
            error: String::new(),
            submit: "Save".into(),
        }
    }
    pub fn value(&self, index: usize) -> &str {
        &self.fields[index].value
    }
    pub fn key(&mut self, key: KeyEvent) -> Action {
        if key.code == KeyCode::Esc {
            return Action::Cancel;
        }
        if key.code == KeyCode::Enter {
            return Action::Submit;
        }
        let count = self.fields.len();
        if count == 0 {
            return Action::Continue;
        }
        match key.code {
            KeyCode::Tab | KeyCode::Down => self.focus = (self.focus + 1) % count,
            KeyCode::BackTab | KeyCode::Up => self.focus = (self.focus + count - 1) % count,
            _ => {
                let field = &mut self.fields[self.focus];
                if !field.choices.is_empty() {
                    match key.code {
                        KeyCode::Left => {
                            field.choice =
                                (field.choice + field.choices.len() - 1) % field.choices.len()
                        }
                        KeyCode::Right | KeyCode::Char(' ') => {
                            field.choice = (field.choice + 1) % field.choices.len()
                        }
                        _ => (),
                    }
                } else {
                    match key.code {
                        KeyCode::Backspace => {
                            field.value.pop();
                        }
                        KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            field.value.clear()
                        }
                        KeyCode::Char(c)
                            if !key
                                .modifiers
                                .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
                                && !c.is_control() =>
                        {
                            if field.value.len() < 65536 {
                                field.value.push(c);
                            }
                        }
                        _ => (),
                    }
                }
            }
        }
        Action::Continue
    }
    pub fn paste(&mut self, text: &str) {
        if let Some(field) = self.fields.get_mut(self.focus) {
            if field.choices.is_empty() {
                for c in text.chars().filter(|c| !c.is_control()) {
                    if field.value.len() + c.len_utf8() > 65536 {
                        break;
                    }
                    field.value.push(c);
                }
            }
        }
    }
    pub fn draw(&self, frame: &mut Frame, bounds: Rect) {
        let width = bounds.width.saturating_sub(4).min(84);
        let height = (self.fields.len() as u16 * 3 + 9).min(bounds.height.saturating_sub(2));
        let area = Rect::new(
            bounds.x + (bounds.width - width) / 2,
            bounds.y + (bounds.height - height) / 2,
            width,
            height,
        );
        frame.render_widget(Clear, area);
        let block = Block::default()
            .title(format!(" {} ", self.title))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan));
        let inner = block.inner(area);
        frame.render_widget(block, area);
        let compact_help = inner.width < 80;
        let footer_height = if compact_help { 2 } else { 1 }.min(inner.height);
        let body = Rect {
            height: inner.height - footer_height,
            ..inner
        };
        let footer = Rect::new(inner.x, body.bottom(), inner.width, footer_height);
        let available = inner.width.saturating_sub(2) as usize;
        let mut lines = vec![Line::from(self.description.as_str()), Line::from("")];
        let visible_fields = (body.height.saturating_sub(4) as usize / 3).max(1);
        let start = self.focus.saturating_sub(visible_fields - 1);
        for (index, field) in self
            .fields
            .iter()
            .enumerate()
            .skip(start)
            .take(visible_fields)
        {
            let selected = index == self.focus;
            let label_style = if selected {
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Gray)
            };
            lines.push(Line::from(Span::styled(
                format!("{}{}", if selected { "> " } else { "  " }, field.label),
                label_style,
            )));
            let display = if !field.choices.is_empty() {
                format!("< {} >", field.selected())
            } else if field.secret {
                "*".repeat(field.value.chars().count().min(available))
            } else {
                field
                    .value
                    .chars()
                    .rev()
                    .take(available)
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect()
            };
            lines.push(Line::from(format!("  {display}")));
            lines.push(Line::from(""));
        }
        lines.push(Line::from(Span::styled(
            self.error.as_str(),
            Style::default().fg(Color::LightRed),
        )));
        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), body);
        let help = if compact_help {
            vec![
                Line::from(format!("Enter: {}", self.submit)),
                Line::from("Esc: cancel  Tab: next  ←/→: choose  Ctrl+U: clear"),
            ]
        } else {
            vec![Line::from(format!(
                "Enter: {}   Tab: next   ←/→: choose   Ctrl+U: clear   Esc: cancel",
                self.submit
            ))]
        };
        frame.render_widget(Paragraph::new(help), footer);
    }
}
