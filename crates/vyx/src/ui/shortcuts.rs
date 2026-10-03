use crossterm::event::{KeyEvent, MouseButton, MouseEvent, MouseEventKind};
use ratatui::{
    Frame,
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
};

use crate::{
    screen::safe_text,
    shortcuts::{Bindings, Shortcut, DEFINITIONS},
    theme::Palette,
    ui::{
        form::{Action as FormAction, Field, Form, FormHitRegion, breadcrumb},
        render::contains,
        theming,
        widgets::{Button, ButtonKind, Notice, button_rows, draw_buttons, draw_scrollbar, keyed_captions, width},
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShortcutMode {
    Reference,
    Edit,
}

pub enum ShortcutAction {
    None,
    Close,
    Save(Bindings),
}

/// The one inline form over the list: a binding's keys, or the Reset all confirmation.
struct BindingEditor {
    /// The edited action; None confirms resetting every customized binding.
    action: Option<Shortcut>,
    form: Form,
    hits: Vec<FormHitRegion>,
}

#[derive(Clone, Copy)]
enum HitTarget {
    Row(usize),
    Previous,
    Next,
    PageUp,
    PageDown,
    EditShortcuts,
    Edit,
    Reset,
    ResetAll,
    Close,
}

#[derive(Clone, Copy)]
struct HitRegion {
    area: Rect,
    target: HitTarget,
}

pub struct ShortcutMenu {
    mode: ShortcutMode,
    selected: usize,
    viewport: usize,
    viewport_rows: usize,
    editor: Option<BindingEditor>,
    notice: Option<Notice>,
    hits: Vec<HitRegion>,
    area: Rect,
}

impl ShortcutMenu {
    pub fn new(mode: ShortcutMode) -> Self {
        Self {
            mode,
            selected: 0,
            viewport: 0,
            viewport_rows: 1,
            editor: None,
            notice: None,
            hits: Vec::new(),
            area: Rect::default(),
        }
    }

    pub fn is_editing(&self) -> bool {
        self.mode == ShortcutMode::Edit
    }

    /// An open binding editor whose keys Cancel would discard.
    pub fn has_draft(&self) -> bool {
        self.editor.as_ref().is_some_and(|editor| editor.action.is_some())
    }

    /// The binding editor or the Reset all confirmation owns the keyboard.
    pub fn has_form(&self) -> bool {
        self.editor.is_some()
    }

    pub fn key(&mut self, key: KeyEvent, bindings: &Bindings) -> ShortcutAction {
        if let Some(editor) = &mut self.editor {
            let action = editor.form.key(key, bindings);
            return self.editor_action(action, bindings);
        }
        // A Saved or error notice describes the previous action.
        self.notice = None;

        if bindings.matches(Shortcut::MenuPrevious, key) {
            self.move_previous();
        } else if bindings.matches(Shortcut::MenuNext, key) {
            self.move_next();
        } else if bindings.matches(Shortcut::MenuPageUp, key) {
            self.page_up();
        } else if bindings.matches(Shortcut::MenuPageDown, key) {
            self.page_down();
        } else if bindings.matches(Shortcut::MenuFirst, key) {
            self.select_first();
        } else if bindings.matches(Shortcut::MenuLast, key) {
            self.select_last();
        } else {
            let action = match self.mode {
                ShortcutMode::Reference => {
                    if bindings.matches(Shortcut::ReferenceSettings, key)
                        || (bindings.matches(Shortcut::SettingsEdit, key) && !bindings.matches(Shortcut::ReferenceClose, key))
                    {
                        self.start_editing();
                        self.open_editor(bindings);
                        ShortcutAction::None
                    } else if bindings.matches(Shortcut::ReferenceClose, key) {
                        ShortcutAction::Close
                    } else {
                        ShortcutAction::None
                    }
                }
                ShortcutMode::Edit => {
                    if bindings.matches(Shortcut::SettingsEdit, key) {
                        self.open_editor(bindings);
                        ShortcutAction::None
                    } else if bindings.matches(Shortcut::SettingsReset, key) {
                        self.reset_selected(bindings)
                    } else if bindings.matches(Shortcut::SettingsResetAll, key) {
                        self.confirm_reset_all(bindings);
                        ShortcutAction::None
                    } else if bindings.matches(Shortcut::SettingsClose, key) {
                        ShortcutAction::Close
                    } else {
                        ShortcutAction::None
                    }
                }
            };
            if matches!(&action, ShortcutAction::None) && self.editor.is_none() {
                if bindings.matches(Shortcut::NextField, key) {
                    self.move_next();
                } else if bindings.matches(Shortcut::PreviousField, key) {
                    self.move_previous();
                }
            }
            return action;
        }
        ShortcutAction::None
    }

    pub fn paste(&mut self, text: &str) {
        if let Some(editor) = &mut self.editor {
            editor.form.paste(text);
        }
    }

    pub fn mouse(&mut self, mouse: MouseEvent, bindings: &Bindings) -> ShortcutAction {
        if !contains(self.area, mouse.column, mouse.row) {
            return ShortcutAction::None;
        }
        if let Some(editor) = &mut self.editor {
            let action = editor.form.mouse(mouse, &editor.hits);
            return self.editor_action(action, bindings);
        }
        match mouse.kind {
            MouseEventKind::ScrollUp => {
                self.notice = None;
                self.move_previous();
                ShortcutAction::None
            }
            MouseEventKind::ScrollDown => {
                self.notice = None;
                self.move_next();
                ShortcutAction::None
            }
            MouseEventKind::Down(MouseButton::Left) => {
                let target = self
                    .hits
                    .iter()
                    .find(|hit| contains(hit.area, mouse.column, mouse.row))
                    .map(|hit| hit.target);
                target.map_or(ShortcutAction::None, |target| {
                    self.notice = None;
                    self.activate(target, bindings)
                })
            }
            _ => ShortcutAction::None,
        }
    }

    /// `active` is false while Settings navigation owns the keyboard beside this page.
    pub fn draw(
        &mut self,
        frame: &mut Frame,
        bounds: Rect,
        bindings: &Bindings,
        palette: &Palette,
        active: bool,
    ) {
        self.hits.clear();
        self.area = Rect::new(
            bounds.x,
            bounds.y,
            bounds.width,
            bounds.height.saturating_sub(1),
        );
        if self.area.width < 2 || self.area.height < 2 {
            return;
        }

        theming::clear(frame, self.area, palette);
        if let Some(editor) = &mut self.editor {
            editor.hits.clear();
            editor.form.draw_settings(frame, self.area, bindings, &mut editor.hits, palette, active);
            return;
        }

        self.draw_list(frame, bindings, palette);
    }

    pub fn saved(&mut self, warning: Option<String>) {
        let reset = self.editor.take().is_some_and(|editor| editor.action.is_none());
        self.notice = Some(match warning {
            Some(warning) => Notice::warning(format!("Saved; {}", safe_text(&warning))),
            None if reset => Notice::success("Every shortcut uses its default keys again."),
            None => Notice::success("Saved."),
        });
    }

    pub fn set_error(&mut self, error: String) {
        let error = safe_text(&error);
        if let Some(editor) = &mut self.editor {
            editor.form.error = error;
        } else {
            self.notice = Some(Notice::error(error));
        }
    }

    fn activate(&mut self, target: HitTarget, bindings: &Bindings) -> ShortcutAction {
        match target {
            HitTarget::Row(index) => {
                self.selected = index.min(DEFINITIONS.len().saturating_sub(1));
                self.ensure_visible();
                ShortcutAction::None
            }
            HitTarget::Previous => {
                self.move_previous();
                ShortcutAction::None
            }
            HitTarget::Next => {
                self.move_next();
                ShortcutAction::None
            }
            HitTarget::PageUp => {
                self.page_up();
                ShortcutAction::None
            }
            HitTarget::PageDown => {
                self.page_down();
                ShortcutAction::None
            }
            HitTarget::EditShortcuts => {
                self.start_editing();
                self.open_editor(bindings);
                ShortcutAction::None
            }
            HitTarget::Edit => {
                self.open_editor(bindings);
                ShortcutAction::None
            }
            HitTarget::Reset => self.reset_selected(bindings),
            HitTarget::ResetAll => {
                self.confirm_reset_all(bindings);
                ShortcutAction::None
            }
            HitTarget::Close => ShortcutAction::Close,
        }
    }

    fn start_editing(&mut self) {
        self.mode = ShortcutMode::Edit;
        self.notice = None;
    }

    fn open_editor(&mut self, bindings: &Bindings) {
        let Some(definition) = DEFINITIONS.get(self.selected) else {
            return;
        };
        let mut form = Form::new(
            format!("Settings / Keyboard shortcuts / Edit {}", definition.title),
            vec![Field::text(
                "Comma-separated shortcuts",
                bindings.edit_text(definition.id),
            )
            .with_hint("Examples: Ctrl+G, Up, k. At least one shortcut is required.")],
        );
        form.description = format!(
            "{} — {} Changes become active only after Save.",
            definition.group, definition.description
        );
        form.submit = "Save binding".to_owned();
        self.editor = Some(BindingEditor {
            action: Some(definition.id),
            form,
            hits: Vec::new(),
        });
        self.notice = None;
    }

    /// Reset all needs an explicit confirmation that states how many bindings change.
    fn confirm_reset_all(&mut self, bindings: &Bindings) {
        let count = DEFINITIONS.iter().filter(|definition| bindings.is_custom(definition.id)).count();
        if count == 0 {
            self.notice = Some(Notice::info("Nothing to reset: every shortcut already uses its default keys."));
            return;
        }
        let mut form = Form::new("Settings / Keyboard shortcuts / Reset all", Vec::new());
        form.description = format!(
            "Reset {count} customized {} to the default keys? This is saved immediately.",
            if count == 1 { "shortcut" } else { "shortcuts" }
        );
        form.submit = "Reset all".to_owned();
        form.submit_kind = ButtonKind::Danger;
        self.editor = Some(BindingEditor { action: None, form, hits: Vec::new() });
        self.notice = None;
    }

    fn editor_action(&mut self, action: FormAction, bindings: &Bindings) -> ShortcutAction {
        match action {
            FormAction::Continue => ShortcutAction::None,
            FormAction::Submit => self.submit_editor(bindings),
            FormAction::Cancel => {
                self.editor = None;
                ShortcutAction::None
            }
        }
    }

    fn submit_editor(&mut self, bindings: &Bindings) -> ShortcutAction {
        let Some(editor) = &mut self.editor else {
            return ShortcutAction::None;
        };
        let Some(action) = editor.action else {
            return ShortcutAction::Save(Bindings::default());
        };
        match bindings.with_binding(action, editor.form.value(0)) {
            Ok(candidate) => ShortcutAction::Save(candidate),
            Err(error) => {
                editor.form.error = safe_text(&format!("{error:#}"));
                ShortcutAction::None
            }
        }
    }

    fn reset_selected(&mut self, bindings: &Bindings) -> ShortcutAction {
        let Some(definition) = DEFINITIONS.get(self.selected) else {
            return ShortcutAction::None;
        };
        match bindings.with_default(definition.id) {
            Ok(candidate) => ShortcutAction::Save(candidate),
            Err(error) => {
                self.notice = Some(Notice::error(safe_text(&format!("{error:#}"))));
                ShortcutAction::None
            }
        }
    }

    fn move_previous(&mut self) {
        self.selected = self.selected.saturating_sub(1);
        self.ensure_visible();
    }

    fn move_next(&mut self) {
        if !DEFINITIONS.is_empty() {
            self.selected = (self.selected + 1).min(DEFINITIONS.len() - 1);
        }
        self.ensure_visible();
    }

    fn page_up(&mut self) {
        self.selected = self.selected.saturating_sub(self.viewport_rows.max(1));
        self.ensure_visible();
    }

    fn page_down(&mut self) {
        if !DEFINITIONS.is_empty() {
            self.selected = (self.selected + self.viewport_rows.max(1)).min(DEFINITIONS.len() - 1);
        }
        self.ensure_visible();
    }

    fn select_first(&mut self) {
        self.selected = 0;
        self.ensure_visible();
    }

    fn select_last(&mut self) {
        self.selected = DEFINITIONS.len().saturating_sub(1);
        self.ensure_visible();
    }

    fn ensure_visible(&mut self) {
        let rows = self.viewport_rows.max(1);
        if self.selected < self.viewport {
            self.viewport = self.selected;
        } else if self.selected >= self.viewport.saturating_add(rows) {
            self.viewport = self.selected + 1 - rows;
        }
        self.viewport = self
            .viewport
            .min(DEFINITIONS.len().saturating_sub(rows.min(DEFINITIONS.len())));
    }

    fn draw_list(&mut self, frame: &mut Frame, bindings: &Bindings, palette: &Palette) {
        let plain_block = Block::default().borders(Borders::ALL);
        let inner = plain_block.inner(self.area);
        let controls = self.controls(bindings);
        let plain: Vec<Button<'_>> = controls.iter().map(|&(caption, _, kind, _)| Button::new(caption, kind)).collect();
        let control_rows = button_rows(inner.width, &plain).min(3).min(inner.height);
        let status_rows = self.notice.as_ref().map_or(0, |notice| notice.rows(inner.width).min(2))
            .min(inner.height.saturating_sub(control_rows));
        let note_rows = if self.mode == ShortcutMode::Reference {
            let note = Paragraph::new(reference_note(inner.width)).wrap(Wrap { trim: false });
            (note.line_count(inner.width.max(1)) as u16)
                .min(3)
                .min(inner.height.saturating_sub(control_rows + status_rows))
        } else {
            0
        };
        let available = inner
            .height
            .saturating_sub(control_rows + status_rows + note_rows);
        let detail_rows = if available >= 4 {
            3
        } else if available >= 3 {
            2
        } else if available >= 2 {
            1
        } else {
            0
        };
        let list_rows = available.saturating_sub(detail_rows);
        self.viewport_rows = usize::from(list_rows.max(1));
        self.ensure_visible();

        let pages = DEFINITIONS.len().div_ceil(self.viewport_rows.max(1)).max(1);
        let page = (self.selected / self.viewport_rows.max(1)) + 1;
        let position = format!(
            " · {}/{} · page {}/{}",
            self.selected.saturating_add(1).min(DEFINITIONS.len()),
            DEFINITIONS.len(),
            page.min(pages),
            pages
        );
        // The standalone reference keeps its own root; editing happens inside Settings.
        let root = match self.mode {
            ShortcutMode::Reference => "Shortcuts",
            ShortcutMode::Edit => "Settings / Keyboard shortcuts",
        };
        let room = self.area.width.saturating_sub(4).saturating_sub(width(&position).min(usize::from(u16::MAX)) as u16);
        let title = format!(" {}{position} ", breadcrumb(root, room));
        let block = Block::default()
            .title(title)
            .borders(Borders::ALL)
            .style(palette.style())
            .border_style(Style::default().fg(palette.accent));
        frame.render_widget(block, self.area);

        let list_area = Rect::new(inner.x, inner.y, inner.width, list_rows);
        self.draw_rows(frame, list_area, bindings, palette);
        let detail_area = Rect::new(inner.x, list_area.bottom(), inner.width, detail_rows);
        self.draw_details(frame, detail_area, bindings, palette);
        let note_area = Rect::new(inner.x, detail_area.bottom(), inner.width, note_rows);
        if note_rows > 0 {
            frame.render_widget(
                Paragraph::new(reference_note(inner.width))
                    .style(Style::default().fg(palette.muted))
                    .wrap(Wrap { trim: false }),
                note_area,
            );
        }
        let status_area = Rect::new(inner.x, note_area.bottom(), inner.width, status_rows);
        self.draw_notice(frame, status_area, palette);
        let controls_area = Rect::new(inner.x, status_area.bottom(), inner.width, control_rows);
        self.draw_controls(frame, controls_area, &controls, palette);
    }

    fn draw_rows(&mut self, frame: &mut Frame, area: Rect, bindings: &Bindings, palette: &Palette) {
        if area.height == 0 || area.width == 0 {
            return;
        }
        let show_scrollbar = DEFINITIONS.len() > usize::from(area.height) && area.width > 1;
        let row_width = area.width.saturating_sub(u16::from(show_scrollbar));
        for (line, (index, definition)) in DEFINITIONS
            .iter()
            .enumerate()
            .skip(self.viewport)
            .take(usize::from(area.height))
            .enumerate()
        {
            let row_area = Rect::new(area.x, area.y + line as u16, row_width, 1);
            let selected = index == self.selected;
            let marker = if selected { ">" } else { " " };
            let custom = if self.mode == ShortcutMode::Edit && bindings.is_custom(definition.id) {
                "*"
            } else {
                " "
            };
            let text = format!(
                "{marker}{custom} {} · {} — {}",
                definition.group,
                definition.title,
                bindings.sequence(definition.id)
            );
            let style = if selected {
                Style::default()
                    .fg(palette.selection_fg)
                    .bg(palette.selection_bg)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(palette.muted)
            };
            frame.render_widget(Paragraph::new(text).style(style), row_area);
            self.hits.push(HitRegion {
                area: row_area,
                target: HitTarget::Row(index),
            });
        }
        if show_scrollbar {
            draw_scrollbar(frame, area, self.viewport, DEFINITIONS.len(), palette);
        }
    }

    fn draw_details(&self, frame: &mut Frame, area: Rect, bindings: &Bindings, palette: &Palette) {
        if area.height == 0 || area.width == 0 {
            return;
        }
        let Some(definition) = DEFINITIONS.get(self.selected) else {
            return;
        };
        let override_label = if self.mode == ShortcutMode::Edit {
            if bindings.is_custom(definition.id) {
                " · custom override"
            } else {
                " · default"
            }
        } else {
            ""
        };
        let explanation = if bindings.default_yielded(definition.id) {
            Line::styled(
                format!("Default {} is used by a custom key elsewhere; edit or reset that binding, or choose a key here. Mouse and Commands still work.", definition.default_text()),
                Style::default().fg(palette.warning),
            )
        } else {
            Line::from(definition.description)
        };
        let details = vec![
            Line::from(vec![
                Span::styled(
                    format!("{} · {}", definition.group, definition.title),
                    Style::default()
                        .fg(palette.accent)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(override_label, Style::default().fg(palette.warning)),
            ]),
            Line::from(vec![
                Span::styled("Keys: ", Style::default().fg(palette.muted)),
                Span::raw(bindings.sequence(definition.id)),
            ]),
            explanation,
        ];
        frame.render_widget(
            Paragraph::new(details).wrap(Wrap { trim: false }),
            area,
        );
    }

    fn draw_notice(&self, frame: &mut Frame, area: Rect, palette: &Palette) {
        if let Some(notice) = &self.notice {
            notice.draw(frame, area, palette);
        }
    }

    fn controls<'b>(&self, bindings: &'b Bindings) -> Vec<(&'static str, &'b str, ButtonKind, HitTarget)> {
        let mut controls = vec![
            ("Prev", bindings.primary(Shortcut::MenuPrevious), ButtonKind::Secondary, HitTarget::Previous),
            ("Next", bindings.primary(Shortcut::MenuNext), ButtonKind::Secondary, HitTarget::Next),
            ("PgUp", bindings.primary(Shortcut::MenuPageUp), ButtonKind::Secondary, HitTarget::PageUp),
            ("PgDn", bindings.primary(Shortcut::MenuPageDown), ButtonKind::Secondary, HitTarget::PageDown),
        ];
        match self.mode {
            ShortcutMode::Reference => controls.extend([
                ("Edit", bindings.primary(Shortcut::ReferenceSettings), ButtonKind::Primary, HitTarget::EditShortcuts),
                ("Close", bindings.primary(Shortcut::ReferenceClose), ButtonKind::Secondary, HitTarget::Close),
            ]),
            ShortcutMode::Edit => controls.extend([
                ("Edit", bindings.primary(Shortcut::SettingsEdit), ButtonKind::Primary, HitTarget::Edit),
                ("Reset", bindings.primary(Shortcut::SettingsReset), ButtonKind::Secondary, HitTarget::Reset),
                ("Reset all", bindings.primary(Shortcut::SettingsResetAll), ButtonKind::Danger, HitTarget::ResetAll),
                ("Back", bindings.primary(Shortcut::SettingsClose), ButtonKind::Secondary, HitTarget::Close),
            ]),
        }
        controls
    }

    fn draw_controls(&mut self, frame: &mut Frame, area: Rect, controls: &[(&str, &str, ButtonKind, HitTarget)], palette: &Palette) {
        let labels: Vec<(&str, &str)> = controls.iter().map(|&(caption, key, _, _)| (caption, key)).collect();
        let captions = keyed_captions(&labels, area.width, area.height);
        let buttons: Vec<Button<'_>> = captions.iter().zip(controls)
            .map(|(caption, &(_, _, kind, _))| Button::new(caption, kind))
            .collect();
        let hits = &mut self.hits;
        draw_buttons(frame, area, &buttons, None, palette, |index, area| {
            hits.push(HitRegion { area, target: controls[index].3 });
        });
    }
}

fn reference_note(width: u16) -> &'static str {
    if width >= 72 {
        "Mouse clicks/wheel, terminal-emulator paste shortcuts and OS signals are fixed; ordinary SSH keys pass through."
    } else {
        "Mouse/wheel/paste/OS fixed; SSH passes"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::widgets::NoticeKind;
    use crossterm::event::{KeyCode, KeyModifiers};

    fn press(menu: &mut ShortcutMenu, code: KeyCode, modifiers: KeyModifiers, bindings: &Bindings) -> ShortcutAction {
        menu.key(KeyEvent::new(code, modifiers), bindings)
    }

    #[test]
    fn reset_all_resets_only_from_its_confirmation() {
        let mut menu = ShortcutMenu::new(ShortcutMode::Edit);
        let defaults = Bindings::default();
        assert!(matches!(press(&mut menu, KeyCode::Char('r'), KeyModifiers::CONTROL, &defaults), ShortcutAction::None));
        assert!(!menu.has_form(), "nothing to confirm without custom bindings");
        assert_eq!(menu.notice.as_ref().map(|notice| notice.kind), Some(NoticeKind::Info));

        let custom = defaults.with_binding(Shortcut::SidebarSearch, "F2").unwrap();
        assert!(matches!(press(&mut menu, KeyCode::Char('r'), KeyModifiers::CONTROL, &custom), ShortcutAction::None));
        assert!(menu.has_form() && !menu.has_draft());
        assert!(matches!(press(&mut menu, KeyCode::Esc, KeyModifiers::NONE, &custom), ShortcutAction::None));
        assert!(!menu.has_form(), "Esc cancels the confirmation");
        // Enter on the list edits the selected binding instead of resetting anything.
        assert!(matches!(press(&mut menu, KeyCode::Enter, KeyModifiers::NONE, &custom), ShortcutAction::None));
        assert!(menu.has_draft());
        press(&mut menu, KeyCode::Esc, KeyModifiers::NONE, &custom);
        press(&mut menu, KeyCode::Char('r'), KeyModifiers::CONTROL, &custom);
        let ShortcutAction::Save(reset) = press(&mut menu, KeyCode::Enter, KeyModifiers::NONE, &custom) else {
            panic!("the confirmation did not reset");
        };
        assert!(DEFINITIONS.iter().all(|definition| !reset.is_custom(definition.id)));
    }
}

