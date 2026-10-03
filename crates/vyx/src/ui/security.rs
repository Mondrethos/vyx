use std::path::PathBuf;
use anyhow::{Result, bail, ensure};
use crossterm::event::{KeyEvent, MouseButton, MouseEvent, MouseEventKind};
use ratatui::{Frame, layout::Rect, style::{Modifier, Style}, text::Line, widgets::{Block, BorderType, Borders, Paragraph, Wrap}};

use crate::{
    screen::safe_text,
    settings::{LockSessions, SecuritySettings},
    shortcuts::{Bindings, Shortcut},
    theme::Palette,
    ui::{
        form::{Action, Field, Form, FormHitRegion, breadcrumb},
        render::contains,
        theming::clear,
        widgets::{Button, Notice, draw_buttons, keyed_captions},
    },
    vault::Secret,
};

pub enum SecurityAction {
    None,
    Back,
    Save(SecuritySettings),
    ChangePassphrase { current: Secret, new: Secret },
    SaveRecoveryFile { current: Secret, destination: PathBuf },
}

enum Page {
    Choices,
    AutoLock(Form),
    Passphrase(Form),
    RecoveryFile(Form),
}

pub struct SecurityMenu {
    page: Page,
    settings: SecuritySettings,
    local_only: bool,
    selected: usize,
    hits: Vec<FormHitRegion>,
    rows: [Rect; 3],
    open: Rect,
    back: Rect,
    notice: Option<Notice>,
}

impl SecurityMenu {
    pub fn new(settings: SecuritySettings, local_only: bool) -> Self {
        Self {
            page: Page::Choices, settings, local_only, selected: 0,
            hits: Vec::new(), rows: [Rect::default(); 3],
            open: Rect::default(), back: Rect::default(), notice: None,
        }
    }

    fn open_selected(&mut self) {
        self.notice = None;
        if self.selected == 0 {
            let mut form = Form::new("Settings / Security / Auto-lock", vec![
                Field::text("Lock after inactivity", self.settings.timeout_text())
                    .with_hint("30s, 10m, 1h; 0 disables. Maximum 24h."),
                Field::inline("When locking", vec!["Disconnect and lock".into(), "Keep sessions running".into()],
                    usize::from(self.settings.lock_sessions == LockSessions::KeepRunning)),
            ]);
            form.description = "Only your keyboard, paste and mouse actions reset the timer, not SSH output. Disconnect closes sessions, unloads the vault and discards unsaved forms. Keep running hides the workspace but retains the decrypted vault in memory. Explicitly detached workspaces also lock.".into();
            form.submit = "Save".into();
            self.page = Page::AutoLock(form);
        } else if self.local_only && self.selected == 2 {
            self.page = Page::RecoveryFile(recovery_file_form());
        } else if self.local_only {
            let mut form = Form::new("Settings / Security / Change passphrase", vec![
                Field::secret("Current passphrase", ""),
                Field::secret("New passphrase", "").with_hint("At least 16 characters."),
                Field::secret("Repeat new passphrase", ""),
            ]);
            form.description = "Change this local vault's passphrase. Existing SSH sessions stay connected. Existing encrypted backups still need their original passphrase. Previous recovery files will no longer unlock this vault. Save a new recovery file after changing the passphrase.".into();
            form.submit = "Change passphrase".into();
            self.page = Page::Passphrase(form);
        } else {
            self.notice = Some(Notice::warning(if self.selected == 2 {
                "Recovery is available only for local-only vaults; synchronized vaults cannot be reset here."
            } else {
                "Passphrase changes are available only for local-only vaults; synchronized vaults share their encryption identity."
            }));
        }
    }

    fn form_action(&mut self, action: Action) -> SecurityAction {
        if action == Action::Cancel {
            self.page = Page::Choices;
            return SecurityAction::None;
        }
        if action != Action::Submit { return SecurityAction::None; }
        match &mut self.page {
            Page::AutoLock(form) => match parse_timeout(form.value(0)) {
                Ok(idle_timeout_seconds) => SecurityAction::Save(SecuritySettings {
                    idle_timeout_seconds,
                    lock_sessions: if form.fields[1].choice == 0 { LockSessions::Disconnect } else { LockSessions::KeepRunning },
                }),
                Err(error) => { form.error = safe_text(&error.to_string()); SecurityAction::None }
            },
            Page::Passphrase(form) => {
                if form.value(1).chars().count() < 16 {
                    form.error = "Use at least 16 characters for the new passphrase.".into();
                } else if form.value(1) != form.value(2) {
                    form.error = "Passphrases do not match.".into();
                } else {
                    let action = SecurityAction::ChangePassphrase { current: Secret::new(form.value(0)), new: Secret::new(form.value(1)) };
                    for field in &mut form.fields { if field.secret { field.set_value(""); } }
                    return action;
                }
                SecurityAction::None
            }
            Page::RecoveryFile(form) => recovery_file_request(form)
                .map(|(current, destination)| SecurityAction::SaveRecoveryFile { current, destination })
                .unwrap_or(SecurityAction::None),
            Page::Choices => SecurityAction::None,
        }
    }

    pub fn key(&mut self, key: KeyEvent, bindings: &Bindings) -> SecurityAction {
        match &mut self.page {
            Page::AutoLock(form) | Page::Passphrase(form) | Page::RecoveryFile(form) => {
                let action = form.key(key, bindings);
                return self.form_action(action);
            }
            Page::Choices => {}
        }
        if bindings.matches(Shortcut::MenuFirst, key) {
            self.selected = 0;
        } else if bindings.matches(Shortcut::MenuLast, key) {
            self.selected = 2;
        } else if bindings.matches(Shortcut::MenuPrevious, key) {
            self.selected = self.selected.saturating_sub(1);
        } else if bindings.matches(Shortcut::MenuNext, key) {
            self.selected = (self.selected + 1).min(2);
        } else if bindings.matches(Shortcut::SettingsEdit, key) {
            self.open_selected();
            return SecurityAction::None;
        } else if bindings.matches(Shortcut::SettingsClose, key) {
            return SecurityAction::Back;
        } else if bindings.matches(Shortcut::NextField, key) {
            self.selected = (self.selected + 1) % 3;
        } else if bindings.matches(Shortcut::PreviousField, key) {
            self.selected = (self.selected + 2) % 3;
        } else {
            return SecurityAction::None;
        }
        // A saved or unavailable notice describes the previous row's action.
        self.notice = None;
        SecurityAction::None
    }

    pub fn mouse(&mut self, mouse: MouseEvent) -> SecurityAction {
        match &mut self.page {
            Page::AutoLock(form) | Page::Passphrase(form) | Page::RecoveryFile(form) => {
                let action = form.mouse(mouse, &self.hits);
                return self.form_action(action);
            }
            Page::Choices => {}
        }
        match mouse.kind {
            MouseEventKind::ScrollUp => { self.selected = self.selected.saturating_sub(1); self.notice = None; }
            MouseEventKind::ScrollDown => { self.selected = (self.selected + 1).min(2); self.notice = None; }
            MouseEventKind::Down(MouseButton::Left) => {
                if contains(self.back, mouse.column, mouse.row) { return SecurityAction::Back; }
                if contains(self.open, mouse.column, mouse.row) { self.open_selected(); }
                else if let Some(index) = self.rows.iter().position(|area| contains(*area, mouse.column, mouse.row)) {
                    self.selected = index;
                    self.open_selected();
                }
            }
            _ => {}
        }
        SecurityAction::None
    }

    pub fn paste(&mut self, text: &str) {
        if let Page::AutoLock(form) | Page::Passphrase(form) | Page::RecoveryFile(form) = &mut self.page { form.paste(text); }
    }

    pub fn clear_secrets(&mut self) {
        if let Page::AutoLock(form) | Page::Passphrase(form) | Page::RecoveryFile(form) = &mut self.page {
            for field in &mut form.fields { if field.secret { field.set_value(""); } }
        }
    }

    /// An open form whose values Cancel would discard.
    pub fn has_draft(&self) -> bool {
        !matches!(self.page, Page::Choices)
    }

    pub fn saved(&mut self, settings: SecuritySettings, warning: Option<String>) {
        let text = match self.page {
            Page::Passphrase(_) => "Vault passphrase changed. Previous recovery files will no longer unlock this vault. Save a new recovery file after changing the passphrase.",
            Page::RecoveryFile(_) => "Recovery file saved and verified. Keep it separate from the vault.",
            _ => "Auto-lock settings saved.",
        };
        self.settings = settings;
        self.page = Page::Choices;
        self.notice = Some(warning.map_or_else(|| Notice::success(text), |warning| Notice::warning(safe_text(&warning))));
    }

    pub fn set_error(&mut self, error: String) {
        match &mut self.page {
            Page::AutoLock(form) | Page::Passphrase(form) | Page::RecoveryFile(form) => form.error = safe_text(&error),
            Page::Choices => self.notice = Some(Notice::error(safe_text(&error))),
        }
    }

    pub fn draw(&mut self, frame: &mut Frame, area: Rect, bindings: &Bindings, palette: &Palette, active: bool) {
        self.hits.clear();
        clear(frame, area, palette);
        if let Page::AutoLock(form) | Page::Passphrase(form) | Page::RecoveryFile(form) = &self.page {
            form.draw_settings(frame, area, bindings, &mut self.hits, palette, active);
            return;
        }
        self.rows.fill(Rect::default());
        self.open = Rect::default();
        self.back = Rect::default();
        let block = Block::default().title(format!(" {} ", breadcrumb("Settings / Security", area.width.saturating_sub(4))))
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded).border_style(Style::default().fg(palette.border));
        let inner = block.inner(area);
        frame.render_widget(block, area);
        if inner.height < 4 || inner.width == 0 { return; }
        let row_height = if inner.height >= 14 { 2 } else { 1 };
        let top = u16::from(row_height == 2);
        for (index, label) in ["Auto-lock", "Change vault passphrase", "Save recovery file"].iter().enumerate() {
            let row = Rect::new(inner.x + top, inner.y + top + index as u16 * row_height, inner.width.saturating_sub(top * 2), 1);
            let style = if self.selected == index { Style::default().fg(palette.selection_fg).bg(palette.selection_bg).add_modifier(Modifier::BOLD) }
                else if index > 0 && !self.local_only { Style::default().fg(palette.muted) }
                else { palette.style() };
            frame.render_widget(Paragraph::new(format!("{} {label}", if self.selected == index { ">" } else { " " })).style(style), row);
            self.rows[index] = row;
        }
        let footer = Rect::new(inner.x, inner.bottom() - 1, inner.width, 1);
        let details_y = inner.y + top + 3 * row_height;
        let details = Rect::new(inner.x + top, details_y, inner.width.saturating_sub(top * 2), footer.y.saturating_sub(details_y));
        let status = if self.settings.idle_timeout_seconds == 0 { "Auto-lock is off.".to_owned() } else {
            format!("Auto-lock: {} · {}", self.settings.timeout_text(), if self.settings.lock_sessions == LockSessions::Disconnect { "disconnect sessions" } else { "keep sessions running" })
        };
        let description = if self.selected == 0 { "Choose an idle timeout and what happens to SSH sessions. Changes stay on this device." }
            else if !self.local_only && self.selected == 2 { "Recovery is available only for local-only vaults; synchronized vaults cannot be reset here." }
            else if !self.local_only { "Unavailable for synchronized vaults: the encryption identity is shared with other devices." }
            else if self.selected == 2 { "Save an emergency key file before losing your passphrase. Store it separately; it is not a data backup." }
            else { "Change the passphrase protecting this local vault. You will need the current passphrase." };
        let mut lines = vec![Line::from(""), Line::styled(status, Style::default().fg(palette.accent)), Line::from(""), Line::from(description)];
        if let Some(notice) = &self.notice {
            lines.push(Line::styled(notice.text.as_str(), notice.style(palette)));
        }
        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), details);
        let captions = keyed_captions(
            &[("Open", bindings.primary(Shortcut::SettingsEdit)), ("Back", bindings.primary(Shortcut::SettingsClose))],
            footer.width, footer.height,
        );
        let (open, back) = (&mut self.open, &mut self.back);
        draw_buttons(frame, footer, &[Button::primary(&captions[0]), Button::secondary(&captions[1])], None, palette,
            |index, area| if index == 0 { *open = area } else { *back = area });
    }
}

pub(super) fn recovery_file_form() -> Form {
    let mut form = Form::new("Settings / Security / Save recovery file", vec![
        Field::secret("Current passphrase", ""),
        Field::text("Absolute recovery file path", "")
            .with_hint("Choose a new .recovery file outside the vault directory; ~ is not expanded."),
        Field::toggle("I will keep this file separate from my vault", false),
    ]);
    form.description = "This file contains no password, but anyone with it and your encrypted vault can access your secrets. It is not a data backup. Password changes invalidate earlier recovery files. Keep it offline or in a password manager.".into();
    form.submit = "Save recovery file".into();
    form
}

pub(super) fn recovery_file_request(form: &mut Form) -> Option<(Secret, PathBuf)> {
    let destination = PathBuf::from(form.value(1));
    if !destination.is_absolute() {
        form.error = "Choose an absolute recovery file path; ~ is not expanded.".into();
    } else if !form.fields[2].checked() {
        form.error = "Confirm that you will keep this file separate from your vault.".into();
    } else {
        let current = Secret::new(form.value(0));
        form.fields[0].set_value("");
        return Some((current, destination));
    }
    None
}

fn parse_timeout(text: &str) -> Result<u32> {
    let text = text.trim();
    if text == "0" { return Ok(0); }
    let (number, multiplier) = if let Some(value) = text.strip_suffix('s') { (value, 1) }
        else if let Some(value) = text.strip_suffix('m') { (value, 60) }
        else if let Some(value) = text.strip_suffix('h') { (value, 3600) }
        else { bail!("Use seconds, minutes or hours: 30s, 10m, 1h; or 0 to disable."); };
    let seconds = number.parse::<u32>().ok().and_then(|value| value.checked_mul(multiplier));
    ensure!(seconds.is_some_and(|value| (1..=86400).contains(&value)), "Choose a timeout from 1s to 24h, or 0 to disable.");
    Ok(seconds.unwrap())
}
