//! Host-rendered extension surfaces. All callbacks are inert typed intents for App.
use std::{collections::BTreeMap, path::PathBuf};

use anyhow::Result;
use crossterm::event::{KeyEvent, MouseButton, MouseEvent, MouseEventKind};
use ratatui::{Frame, layout::Rect, style::{Modifier, Style}, text::Line, widgets::{Block, Borders, Paragraph, Wrap}};

use crate::{
    extensions::{contract::{Action, DetailField, Event, FormField, FormValue, ListItem, Permission, View, sanitize_display, sanitize_display_in_place}, distribution::{CatalogEntry, OFFICIAL_REPOSITORY}, package::Manifest},
    shortcuts::{Bindings, Shortcut}, theme::Palette,
    ui::{form::{Action as FormAction, Field, Form, FormHitRegion}, render::contains, theming, widgets::{Button, ButtonKind, Notice, button_rows, draw_buttons, width}},
};

/// Action buttons wrap to at most this many rows; the selected action stays visible.
const MAX_ACTION_ROWS: u16 = 3;

#[derive(Clone, Debug)]
pub struct ExtensionEntry {
    pub manifest: Manifest,
    pub digest: String,
    pub enabled: bool,
    pub grants: Vec<Permission>,
    pub official: bool,
    pub repository: Option<String>,
    pub development: bool,
    pub development_path: Option<PathBuf>,
    pub status: String,
    pub diagnostics: Vec<String>,
    pub trust_rebuilds: bool,
    pub reload_available: bool,
    /// Reserved Vyx AI package whose commands open native host UI instead of a guest worker.
    pub native: bool,
}

#[derive(Debug)]
pub enum ManagementAction {
    BrowseRepository { repository: String },
    Download { entry: CatalogEntry },
    DownloadRuntime,
    Install { path: PathBuf },
    Update { extension_id: String, digest: String, path: PathBuf },
    LoadDevelopment { path: PathBuf },
    Enable { extension_id: String, digest: String, grants: Vec<Permission> },
    Disable { extension_id: String },
    Remove { extension_id: String },
    Retry { extension_id: String },
    TrustRebuilds { extension_id: String, digest: String, trusted: bool },
    Reload { extension_id: String },
}

pub enum ManagementResult { None, Back, OpenAi, Action(ManagementAction) }

#[derive(Debug)]
pub enum SurfaceAction {
    None,
    Close,
    Reload,
    Launch { extension_id: String, command_id: String },
    Event(Event),
}

/// Only forms have a toolbar focus: their fields own the navigation keys.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Focus { Content, Search, Toolbar }
#[derive(Clone, Copy)]
enum Target { Row(usize), Action(usize), Search, Details, Back, Reload }

pub struct ExtensionSurface {
    entry: Option<ExtensionEntry>,
    commands: Vec<(String, String)>,
    view: View,
    form: Option<Form>,
    form_hits: Vec<FormHitRegion>,
    filter: Field,
    filtered: Vec<usize>,
    global_actions: Vec<usize>,
    selected: usize,
    offset: usize,
    scroll: u16,
    detail: bool,
    focus: Focus,
    action: usize,
    hits: Vec<(Rect, Target)>,
    area: Rect,
    page_size: usize,
    error: String,
    busy: bool,
    busy_message: String,
    /// Nonblocking management feedback. Data refreshes keep it; the next
    /// deliberate input clears it.
    notice: Option<Notice>,
    /// Host-owned destructive action drawn as a Danger button.
    danger: Option<&'static str>,
}

impl ExtensionSurface {
    /// Construct the picker from host snapshots; this does not start a worker.
    pub fn picker(entries: Vec<ExtensionEntry>) -> Self {
        let mut commands = Vec::new();
        let mut items = Vec::new();
        for entry in entries.into_iter().filter(|entry| entry.enabled) {
            for command in &entry.manifest.commands {
                let id = commands.len().to_string();
                commands.push((entry.manifest.id.clone(), command.id.clone()));
                items.push(ListItem { id, title: sanitize_display(&command.title), subtitle: Some(format!("{} · {}", sanitize_display(&entry.manifest.name), source(&entry))), metadata: vec![DetailField { label: "Description".into(), value: sanitize_display(&command.description) }], actions: vec!["launch".into()] });
            }
        }
        let mut surface = Self::new(None, View::List { title: "Extension commands".into(), searchable: true, items, actions: vec![action("launch", "Open command")] });
        surface.commands = commands;
        surface
    }

    pub fn open(entry: ExtensionEntry, mut view: View) -> Result<Self> {
        view.validate_and_sanitize()?;
        Ok(Self::new(Some(entry), view))
    }

    fn new(entry: Option<ExtensionEntry>, view: View) -> Self {
        let mut surface = Self { entry, commands: Vec::new(), view, form: None, form_hits: Vec::new(), filter: Field::text("Filter", ""), filtered: Vec::new(), global_actions: Vec::new(), selected: 0, offset: 0, scroll: 0, detail: false, focus: Focus::Content, action: 0, hits: Vec::new(), area: Rect::default(), page_size: 1, error: String::new(), busy: false, busy_message: "Working…".into(), notice: None, danger: None };
        surface.prepare();
        surface
    }

    pub fn set_view(&mut self, mut view: View) -> Result<()> {
        view.validate_and_sanitize()?;
        self.view = view;
        self.error.clear();
        self.busy = false;
        self.prepare();
        Ok(())
    }

    pub fn set_error(&mut self, error: String) { self.busy = false; self.error = sanitize_display(&error); }
    pub fn set_busy(&mut self, busy: bool) { self.busy = busy; }

    fn prepare(&mut self) {
        self.form = match &self.view {
            View::Form { title, fields, .. } => Some(Form::new(title, fields.iter().map(|field| match field {
                FormField::Text { label, value, .. } => Field::text(label, value),
                FormField::Select { label, options, value, .. } => Field::select(label, options.iter().map(|option| option.label.clone()).collect(), value.as_ref().and_then(|value| options.iter().position(|option| &option.id == value)).unwrap_or(0)),
                FormField::Toggle { label, value, .. } => Field::toggle(label, *value),
            }).collect())),
            _ => None,
        };
        self.global_actions = self.view.actions().iter().enumerate().filter_map(|(index, action)| {
            let referenced = matches!(&self.view, View::List { items, .. } if items.iter().any(|item| item.actions.contains(&action.id)));
            (!referenced).then_some(index)
        }).collect();
        self.selected = 0;
        self.offset = 0;
        self.scroll = 0;
        self.detail = false;
        self.action = 0;
        self.focus = Focus::Content;
        self.hits.clear();
        self.form_hits.clear();
        self.refilter();
    }

    fn refilter(&mut self) {
        self.filtered.clear();
        if let View::List { items, searchable, .. } = &self.view {
            let query = if *searchable { self.filter.value.to_lowercase() } else { String::new() };
            self.filtered.extend(items.iter().enumerate().filter_map(|(index, item)| {
                (query.is_empty() || item.title.to_lowercase().contains(&query) || item.subtitle.as_ref().is_some_and(|text| text.to_lowercase().contains(&query)) || item.metadata.iter().any(|field| field.value.to_lowercase().contains(&query))).then_some(index)
            }));
        }
        self.selected = self.selected.min(self.filtered.len().saturating_sub(1));
        self.offset = self.offset.min(self.selected);
        self.action = 0;
    }

    fn selected_item(&self) -> Option<&ListItem> {
        match &self.view { View::List { items, .. } => self.filtered.get(self.selected).and_then(|index| items.get(*index)), _ => None }
    }

    fn available_actions(&self) -> Vec<usize> {
        let item = self.selected_item();
        self.view.actions().iter().enumerate().filter_map(|(index, action)| (self.global_actions.contains(&index) || item.is_some_and(|item| item.actions.contains(&action.id))).then_some(index)).collect()
    }

    fn invoke(&mut self, index: usize) -> SurfaceAction {
        if self.busy || !self.error.is_empty() { return SurfaceAction::None; }
        let Some(action) = self.view.actions().get(index) else { return SurfaceAction::None; };
        if !self.available_actions().contains(&index) { return SurfaceAction::None; }
        if !self.commands.is_empty() {
            return self.filtered.get(self.selected).and_then(|index| self.commands.get(*index)).map_or(SurfaceAction::None, |(extension_id, command_id)| SurfaceAction::Launch { extension_id: extension_id.clone(), command_id: command_id.clone() });
        }
        if let (View::Form { fields, .. }, Some(form)) = (&self.view, &mut self.form) {
            let mut values = BTreeMap::new();
            for (index, field) in fields.iter().enumerate() {
                let (id, value) = match field {
                    FormField::Text { id, label, max_length, .. } => {
                        let value = form.value(index);
                        if value.len() > *max_length || sanitize_display(value) != value {
                            form.error = format!("{} must be plain text, at most {} UTF-8 bytes.", label, max_length);
                            return SurfaceAction::None;
                        }
                        (id, FormValue::Text(value.to_owned()))
                    }
                    FormField::Select { id, options, .. } => (id, FormValue::Text(options[form.fields[index].choice].id.clone())),
                    FormField::Toggle { id, .. } => (id, FormValue::Toggle(form.fields[index].checked())),
                };
                values.insert(id.clone(), value);
            }
            return SurfaceAction::Event(Event::Submit { action_id: action.id.clone(), values });
        }
        SurfaceAction::Event(Event::Action { action_id: action.id.clone(), item_id: if self.global_actions.contains(&index) { None } else { self.selected_item().map(|item| item.id.clone()) } })
    }

    pub fn key(&mut self, key: KeyEvent, bindings: &Bindings) -> SurfaceAction {
        // A notice reports the previous operation; deliberate input dismisses it.
        self.notice = None;
        if bindings.matches(Shortcut::Cancel, key) {
            if self.busy { return SurfaceAction::Close; }
            if self.focus == Focus::Search { self.focus = Focus::Content; }
            else if self.detail { self.detail = false; self.scroll = 0; }
            else { return SurfaceAction::Close; }
            return SurfaceAction::None;
        }
        if !self.error.is_empty() {
            return if bindings.matches(Shortcut::Submit, key) { SurfaceAction::Reload } else { SurfaceAction::None };
        }
        if self.busy { return SurfaceAction::None; }
        if self.focus == Focus::Search {
            if bindings.matches(Shortcut::SearchKeep, key) { self.focus = Focus::Content; }
            else if bindings.matches(Shortcut::SearchPrevious, key) { self.selected = self.selected.saturating_sub(1); }
            else if bindings.matches(Shortcut::SearchNext, key) { self.selected = (self.selected + 1).min(self.filtered.len().saturating_sub(1)); }
            else { self.filter.key(key, bindings); self.refilter(); }
            return SurfaceAction::None;
        }
        let actions = self.available_actions();
        if self.focus == Focus::Toolbar {
            if bindings.matches(Shortcut::NextField, key) || bindings.matches(Shortcut::PreviousField, key) { self.focus = Focus::Content; }
            else if bindings.matches(Shortcut::PreviousChoice, key) { self.action = self.action.saturating_sub(1); }
            else if bindings.matches(Shortcut::NextChoice, key) { self.action = (self.action + 1).min(actions.len().saturating_sub(1)); }
            else if bindings.matches(Shortcut::Submit, key) && let Some(index) = actions.get(self.action) { return self.invoke(*index); }
            return SurfaceAction::None;
        }
        // Forms retain native field navigation. Left/right on their toolbar selects a handler.
        if let Some(form) = &mut self.form {
            if (bindings.matches(Shortcut::NextField, key) && form.focus + 1 >= form.fields.len())
                || (bindings.matches(Shortcut::PreviousField, key) && form.focus == 0) { self.focus = Focus::Toolbar; }
            else {
                match form.key(key, bindings) {
                    FormAction::Submit => if let Some(index) = actions.get(self.action) { return self.invoke(*index); },
                    FormAction::Cancel => return SurfaceAction::Close,
                    FormAction::Continue => {},
                }
            }
            return SurfaceAction::None;
        }
        // Left/right select among the action buttons.
        if bindings.matches(Shortcut::PreviousChoice, key) { self.action = self.action.saturating_sub(1); }
        else if bindings.matches(Shortcut::NextChoice, key) { self.action = (self.action + 1).min(actions.len().saturating_sub(1)); }
        else if bindings.matches(Shortcut::SidebarSearch, key) && matches!(self.view, View::List { searchable: true, .. }) { self.focus = Focus::Search; }
        else if bindings.matches(Shortcut::SidebarInspect, key) && self.selected_item().is_some() { self.detail = !self.detail; self.scroll = 0; }
        else if bindings.matches(Shortcut::Submit, key) && let Some(index) = actions.get(self.action) { return self.invoke(*index); }
        else {
            let up = bindings.matches(Shortcut::MenuPrevious, key);
            let down = bindings.matches(Shortcut::MenuNext, key);
            let page_up = bindings.matches(Shortcut::MenuPageUp, key);
            let page_down = bindings.matches(Shortcut::MenuPageDown, key);
            if self.detail || matches!(self.view, View::Detail { .. }) {
                if up || page_up { self.scroll = self.scroll.saturating_sub(if page_up { self.page_size as u16 } else { 1 }); }
                if down || page_down { self.scroll = self.scroll.saturating_add(if page_down { self.page_size as u16 } else { 1 }); }
                if bindings.matches(Shortcut::MenuFirst, key) { self.scroll = 0; }
            } else {
                if up || page_up { self.selected = self.selected.saturating_sub(if page_up { self.page_size } else { 1 }); }
                if down || page_down { self.selected = (self.selected + if page_down { self.page_size } else { 1 }).min(self.filtered.len().saturating_sub(1)); }
                if bindings.matches(Shortcut::MenuFirst, key) { self.selected = 0; }
                if bindings.matches(Shortcut::MenuLast, key) { self.selected = self.filtered.len().saturating_sub(1); }
            }
        }
        SurfaceAction::None
    }

    pub fn paste(&mut self, text: &str) {
        self.notice = None;
        if self.busy || !self.error.is_empty() { return; }
        if let Some(form) = &mut self.form { form.paste(text); }
        else if matches!(self.view, View::List { searchable: true, .. }) { self.filter.paste(text); self.refilter(); self.focus = Focus::Search; }
    }

    pub fn mouse(&mut self, mouse: MouseEvent, _bindings: &Bindings) -> SurfaceAction {
        if !contains(self.area, mouse.column, mouse.row) { return SurfaceAction::None; }
        if matches!(mouse.kind, MouseEventKind::Down(_) | MouseEventKind::ScrollUp | MouseEventKind::ScrollDown) { self.notice = None; }
        if mouse.kind == MouseEventKind::Down(MouseButton::Left) {
            if let Some(target) = self.hits.iter().rev().find(|(area, _)| contains(*area, mouse.column, mouse.row)).map(|(_, target)| *target) {
                match target {
                    Target::Row(index) => { self.selected = index; self.action = 0; self.focus = Focus::Content; },
                    Target::Action(index) => {
                        if self.form.is_some() { self.focus = Focus::Toolbar; }
                        if let Some(position) = self.available_actions().iter().position(|value| *value == index) { self.action = position; }
                        return self.invoke(index);
                    },
                    Target::Search => self.focus = Focus::Search,
                    Target::Details => { self.detail = !self.detail; self.scroll = 0; },
                    Target::Back => return SurfaceAction::Close,
                    Target::Reload => return SurfaceAction::Reload,
                }
                return SurfaceAction::None;
            }
        }
        if let Some(form) = &mut self.form {
            let action = form.mouse(mouse, &self.form_hits);
            if action == FormAction::Cancel { return SurfaceAction::Close; }
            if action == FormAction::Submit && let Some(index) = self.available_actions().get(self.action) { return self.invoke(*index); }
        } else if matches!(mouse.kind, MouseEventKind::ScrollUp | MouseEventKind::ScrollDown) {
            let shortcut = if mouse.kind == MouseEventKind::ScrollUp { Shortcut::MenuPrevious } else { Shortcut::MenuNext };
            // Mouse scrolling is independent of editable search focus and configured chords.
            if self.detail || matches!(self.view, View::Detail { .. }) {
                if shortcut == Shortcut::MenuPrevious { self.scroll = self.scroll.saturating_sub(3); } else { self.scroll = self.scroll.saturating_add(3); }
            } else if shortcut == Shortcut::MenuPrevious { self.selected = self.selected.saturating_sub(1); }
            else { self.selected = (self.selected + 1).min(self.filtered.len().saturating_sub(1)); }
        }
        SurfaceAction::None
    }

    pub fn draw(&mut self, frame: &mut Frame, area: Rect, bindings: &Bindings, palette: &Palette, active: bool) {
        self.area = area;
        self.hits.clear();
        self.form_hits.clear();
        theming::clear(frame, area, palette);
        let title = match &self.view { View::List { title, .. } | View::Detail { title, .. } | View::Form { title, .. } => title };
        let chrome = self.entry.as_ref().map_or_else(|| "Vyx · Extensions".into(), |entry| format!("{} · {}", source(entry), sanitize_display(&entry.manifest.name)));
        frame.render_widget(Block::default().borders(Borders::ALL).title(chrome).style(palette.style()).border_style(Style::default().fg(palette.border)), area);
        let inner = area.inner(ratatui::layout::Margin::new(1, 1));
        if inner.height < 4 || inner.width == 0 { return; }
        let header = Rect::new(inner.x, inner.y, inner.width, 1);
        frame.render_widget(Paragraph::new(title.as_str()).style(Style::default().fg(palette.accent).add_modifier(Modifier::BOLD)), header);
        let actions = self.available_actions();
        self.action = self.action.min(actions.len().saturating_sub(1));
        let failed = !self.error.is_empty();
        // Every available action is a button. Keyboard selection indexes available
        // actions; button hits carry the view's action index.
        let buttons: Vec<Button> = if failed { vec![Button::primary("Reload")] }
            else if self.busy { Vec::new() }
            else {
                actions.iter().map(|index| {
                    let action = &self.view.actions()[*index];
                    Button::new(&action.label, if self.danger == Some(action.id.as_str()) { ButtonKind::Danger } else { ButtonKind::Secondary })
                }).collect()
            };
        let toolbar_rows = if self.busy && !failed { 1 } else { button_rows(inner.width, &buttons).min(MAX_ACTION_ROWS) }
            .min(inner.height.saturating_sub(3));
        let footer = Rect::new(inner.x, inner.bottom() - 1, inner.width, 1);
        let toolbar = Rect::new(inner.x, footer.y - toolbar_rows, inner.width, toolbar_rows);
        let notice_rows = self.notice.as_ref()
            .map_or(0, |notice| notice.rows(inner.width).min(3).min(toolbar.y.saturating_sub(inner.y + 2)));
        let notice_area = Rect::new(inner.x, toolbar.y - notice_rows, inner.width, notice_rows);
        let mut body = Rect::new(inner.x, inner.y + 1, inner.width, notice_area.y.saturating_sub(inner.y + 1));
        let back = match bindings.primary(Shortcut::Cancel) { "" => "Back".to_owned(), key => format!("{key} Back") };
        let mut hints = vec![back.clone()];
        if !failed && !self.busy {
            if self.form.is_some() { hints.extend(hint(&[bindings.primary(Shortcut::NextField)], "Actions")); }
            if actions.len() > 1 { hints.extend(hint(&[bindings.primary(Shortcut::PreviousChoice), bindings.primary(Shortcut::NextChoice)], "Choose")); }
            if !actions.is_empty() { hints.extend(hint(&[bindings.primary(Shortcut::Submit)], "Activate")); }
            if self.selected_item().is_some() { hints.extend(hint(&[bindings.primary(Shortcut::SidebarInspect)], "Details")); }
        }
        frame.render_widget(Paragraph::new(hints.join("  ")), footer);
        self.hits.push((Rect::new(footer.x, footer.y, width(&back).min(usize::from(footer.width)) as u16, 1), Target::Back));
        if let Some(notice) = &self.notice { notice.draw(frame, notice_area, palette); }
        if failed {
            frame.render_widget(Paragraph::new(format!("Extension failed: {}\n{} Reload; {} Close. No automatic restart.", self.error, bindings.label(Shortcut::Submit), bindings.label(Shortcut::Cancel))).wrap(Wrap { trim: false }).style(Style::default().fg(palette.warning)), body);
            let hits = &mut self.hits;
            draw_buttons(frame, toolbar, &buttons, Some(0), palette, |_, area| hits.push((area, Target::Reload)));
            return;
        }
        if self.busy {
            frame.render_widget(Paragraph::new(format!("{} (Back cancels)", self.busy_message)).style(Style::default().fg(palette.warning)), toolbar);
        } else {
            let hits = &mut self.hits;
            draw_buttons(frame, toolbar, &buttons, active.then_some(self.action), palette,
                |position, area| hits.push((area, Target::Action(actions[position]))));
        }
        if let Some(form) = &mut self.form {
            frame.render_widget(Paragraph::new("Extension can read all entered values. Never enter passwords, keys or tokens.").style(Style::default().fg(palette.warning)).wrap(Wrap { trim: false }), Rect::new(body.x, body.y, body.width, 2.min(body.height)));
            body.y += 2.min(body.height); body.height = body.height.saturating_sub(2);
            if let Some(index) = actions.get(self.action) { form.submit.clone_from(&self.view.actions()[*index].label); }
            form.draw_settings(frame, body, bindings, &mut self.form_hits, palette, active);
            return;
        }
        if matches!(self.view, View::List { searchable: true, .. }) && !self.detail {
            let filter = Rect::new(body.x, body.y, body.width, 1);
            frame.render_widget(Paragraph::new(format!("{} Filter: {}", bindings.label(Shortcut::SidebarSearch), sanitize_display(&self.filter.value))).style(if self.focus == Focus::Search { Style::default().fg(palette.accent) } else { palette.style() }), filter);
            self.hits.push((filter, Target::Search));
            body.y += 1; body.height = body.height.saturating_sub(1);
        }
        self.page_size = usize::from(body.height).max(1);
        if self.detail || matches!(self.view, View::Detail { .. }) {
            let fields: &[DetailField] = match &self.view { View::Detail { fields, .. } => fields.as_slice(), _ => self.selected_item().map_or(&[], |item| item.metadata.as_slice()) };
            let mut lines = Vec::new();
            if let Some(item) = self.selected_item() { lines.push(Line::from(item.title.clone())); if let Some(subtitle) = &item.subtitle { lines.push(Line::from(subtitle.clone())); } }
            for field in fields { lines.push(Line::from(format!("{}: {}", field.label, field.value))); }
            let paragraph = Paragraph::new(lines).wrap(Wrap { trim: false });
            let max = paragraph.line_count(body.width).saturating_sub(usize::from(body.height)).min(u16::MAX as usize) as u16;
            self.scroll = self.scroll.min(max);
            frame.render_widget(paragraph.scroll((self.scroll, 0)), body);
        } else if let View::List { items, .. } = &self.view {
            if body.width >= 100 && !self.filtered.is_empty() {
                let list_width = body.width / 2;
                let detail_area = Rect::new(body.x + list_width + 1, body.y, body.width - list_width - 1, body.height);
                if let Some(item) = self.selected_item() {
                    let mut lines = vec![Line::from(item.title.as_str())];
                    if let Some(subtitle) = &item.subtitle { lines.push(Line::from(subtitle.as_str())); }
                    lines.extend(item.metadata.iter().map(|field| Line::from(format!("{}: {}", field.label, field.value))));
                    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), detail_area);
                    self.hits.push((detail_area, Target::Details));
                }
                body.width = list_width;
            }
            self.offset = self.offset.min(self.selected);
            if self.selected >= self.offset + self.page_size { self.offset = self.selected + 1 - self.page_size; }
            if self.filtered.is_empty() {
                let message = if !self.commands.is_empty() { "No matching commands." } else { "No matching items." };
                frame.render_widget(Paragraph::new(message).wrap(Wrap { trim: false }), body);
            }
            for (row, position) in (self.offset..self.filtered.len()).take(self.page_size).enumerate() {
                let item = &items[self.filtered[position]];
                let hit = Rect::new(body.x, body.y + row as u16, body.width, 1);
                let text = match &item.subtitle { Some(subtitle) => format!("{} — {}", item.title, subtitle), None => item.title.clone() };
                frame.render_widget(Paragraph::new(text).style(if position == self.selected { Style::default().fg(palette.background).bg(palette.accent) } else { palette.style() }), hit);
                self.hits.push((hit, Target::Row(position)));
            }
        }
        if self.selected_item().is_some() {
            let width = 9.min(header.width);
            let area = Rect::new(header.right() - width, header.y, width, 1);
            frame.render_widget(Paragraph::new("[Details]"), area);
            self.hits.push((area, Target::Details));
        }
    }
}

fn action(id: &str, label: &str) -> Action { Action { id: id.into(), label: label.into() } }
/// `keys label` for the bound keys; `None` when every key yielded to a custom binding.
fn hint(keys: &[&str], label: &str) -> Option<String> {
    let keys = keys.iter().copied().filter(|key| !key.is_empty()).collect::<Vec<_>>().join("/");
    (!keys.is_empty()).then(|| format!("{keys} {label}"))
}
fn source(entry: &ExtensionEntry) -> &'static str {
    if entry.development { "Unverified · Development" } else if entry.official { "Vyx release" } else { "Unverified publisher" }
}
pub(crate) fn permission(permission: Permission) -> &'static str {
    match permission {
        Permission::HostsRead => "hosts.read — Read saved destinations and authentication labels, never secrets",
        Permission::SessionsRead => "sessions.read — Read session names and phases, never terminal contents",
        Permission::TailscaleRead => "tailscale.read — Read local Tailscale status and device metadata",
        Permission::TerminalPropose => "terminal.propose — Request reviewed command insertion without Enter",
        Permission::ConnectionsPropose => "connections.propose — Request a connection after host-owned review",
        Permission::HostsPropose => "hosts.propose — Request an explicitly saved server draft",
    }
}

enum PathMode { Install, Development, Repository, Update { extension_id: String, digest: String } }
enum ManagementPage { List, Catalog, CatalogDetail(usize), Detail(String), Confirm { entry: ExtensionEntry, operation: &'static str } }

pub struct ExtensionsMenu {
    entries: Vec<ExtensionEntry>,
    surface: ExtensionSurface,
    page: ManagementPage,
    path: Option<(PathMode, Form)>,
    path_hits: Vec<FormHitRegion>,
    repository: String,
    catalog: Vec<CatalogEntry>,
    root_entry: Option<String>,
}

impl ExtensionsMenu {
    pub fn new(entries: Vec<ExtensionEntry>) -> Self {
        let surface = ExtensionSurface::new(None, management_list(&entries));
        Self { entries, surface, page: ManagementPage::List, path: None, path_hits: Vec::new(), repository: OFFICIAL_REPOSITORY.into(), catalog: Vec::new(), root_entry: None }
    }

    /// Package detail hosted by the Extensions category; Back returns to the
    /// installed list. An unknown ID shows the list.
    pub fn manage(entries: Vec<ExtensionEntry>, id: &str) -> Self {
        let mut menu = Self::new(entries);
        menu.page = ManagementPage::Detail(id.to_owned());
        menu.refresh();
        menu
    }

    /// Open an enabled package's own Settings child without starting the extension.
    pub fn for_entry(entries: Vec<ExtensionEntry>, id: &str) -> Self {
        let mut menu = Self::manage(entries, id);
        menu.root_entry = Some(id.to_owned());
        menu
    }

    /// Hosts an enabled child's page under Extensions after that package was
    /// disabled or removed: Back then returns to the installed list.
    pub fn release(&mut self) {
        self.root_entry = None;
    }

    pub fn set_catalog(&mut self, repository: String, entries: Vec<CatalogEntry>) {
        self.repository = repository;
        self.catalog = entries;
        self.path = None;
        self.page = ManagementPage::Catalog;
        self.surface.filter.value.clear();
        self.refresh();
    }

    pub fn set_loading(&mut self, message: String) {
        self.path = None;
        self.surface.busy_message = sanitize_display(&message);
        self.surface.set_busy(true);
    }

    pub fn set_entries(&mut self, entries: Vec<ExtensionEntry>) {
        let changed = match &self.page {
            ManagementPage::List => self.entries.len() != entries.len()
                || self.entries.iter().zip(&entries).any(|(before, after)| !same_entry(before, after)),
            ManagementPage::Detail(id) => match (self.entries.iter().find(|entry| &entry.manifest.id == id), entries.iter().find(|entry| &entry.manifest.id == id)) {
                (Some(before), Some(after)) => !same_entry(before, after),
                _ => true,
            },
            ManagementPage::Catalog | ManagementPage::CatalogDetail(_) => self.entries.len() != entries.len()
                || self.entries.iter().zip(&entries).any(|(before, after)| !same_entry(before, after)),
            ManagementPage::Confirm { entry, .. } => entries.iter().find(|current| current.manifest.id == entry.manifest.id).is_none_or(|current| !same_entry(entry, current)),
        };
        self.entries = entries;
        if !changed || self.surface.busy { return; }
        // A completed mutation or replaced target must not leave actionable stale
        // consent on screen. Unrelated snapshot refreshes keep the current draft.
        if let ManagementPage::Confirm { entry, .. } = &self.page {
            self.page = ManagementPage::Detail(entry.manifest.id.clone());
        }
        let selected_id = self.surface.selected_item().map(|item| item.id.clone());
        self.refresh();
        if let (Some(id), View::List { items, .. }) = (selected_id, &self.surface.view)
            && let Some(position) = self.surface.filtered.iter().position(|index| items[*index].id == id) {
            self.surface.selected = position;
        }
    }

    fn refresh(&mut self) {
        let view = match &self.page {
            ManagementPage::Detail(id) => match self.entries.iter().find(|entry| &entry.manifest.id == id) {
                Some(entry) => management_detail(entry),
                None => { self.page = ManagementPage::List; management_list(&self.entries) },
            },
            ManagementPage::List => management_list(&self.entries),
            ManagementPage::Catalog => catalog_list(&self.repository, &self.catalog, &self.entries),
            ManagementPage::CatalogDetail(index) => match self.catalog.get(*index) {
                Some(entry) => catalog_detail(entry, &self.entries),
                None => { self.page = ManagementPage::Catalog; catalog_list(&self.repository, &self.catalog, &self.entries) },
            },
            ManagementPage::Confirm { .. } => return,
        };
        // These views are constructed by Vyx, not author code.
        self.surface.view = view;
        self.surface.busy = false;
        self.surface.danger = None;
        self.surface.prepare();
    }

    /// Management failures do not block the page; path-form errors stay on their field.
    pub fn set_error(&mut self, error: String) {
        if let Some((_, form)) = &mut self.path { form.error = sanitize_display(&error); }
        else { self.set_notice(Notice::error(error)); }
    }

    /// Survives the data refresh of the same operation; the next deliberate input clears it.
    pub fn set_notice(&mut self, mut notice: Notice) {
        sanitize_display_in_place(&mut notice.text);
        self.surface.busy = false;
        self.surface.notice = Some(notice);
    }

    pub fn key(&mut self, key: KeyEvent, bindings: &Bindings) -> ManagementResult {
        if let Some((_, form)) = &mut self.path {
            let action = form.key(key, bindings);
            return self.path_action(action);
        }
        let action = self.surface.key(key, bindings);
        self.handle(action)
    }

    pub fn mouse(&mut self, mouse: MouseEvent, bindings: &Bindings) -> ManagementResult {
        if let Some((_, form)) = &mut self.path {
            let action = form.mouse(mouse, &self.path_hits);
            return self.path_action(action);
        }
        let action = self.surface.mouse(mouse, bindings);
        self.handle(action)
    }

    pub fn paste(&mut self, text: &str) {
        if let Some((_, form)) = &mut self.path { form.paste(text); }
        else { self.surface.paste(text); }
    }

    pub fn draw(&mut self, frame: &mut Frame, area: Rect, bindings: &Bindings, palette: &Palette, active: bool) {
        if let Some((_, form)) = &self.path {
            self.path_hits.clear();
            form.draw_settings(frame, area, bindings, &mut self.path_hits, palette, active);
        } else { self.surface.draw(frame, area, bindings, palette, active); }
    }

    fn path_action(&mut self, action: FormAction) -> ManagementResult {
        match action {
            FormAction::Continue => ManagementResult::None,
            FormAction::Cancel => { self.path = None; ManagementResult::None },
            FormAction::Submit => {
                let Some((mode, form)) = &mut self.path else { return ManagementResult::None; };
                let value = form.value(0);
                if value.trim().is_empty() || value.chars().any(char::is_control) || sanitize_display(value) != value {
                    form.error = if matches!(mode, PathMode::Repository) { "Enter owner/repo or an HTTPS GitHub repository URL." } else { "Enter a local .vyxext package path." }.into();
                    return ManagementResult::None;
                }
                let action = match mode {
                    PathMode::Repository => ManagementAction::BrowseRepository { repository: value.trim().to_owned() },
                    PathMode::Install => ManagementAction::Install { path: PathBuf::from(value) },
                    PathMode::Development => ManagementAction::LoadDevelopment { path: PathBuf::from(value) },
                    PathMode::Update { extension_id, digest } => ManagementAction::Update { extension_id: extension_id.clone(), digest: digest.clone(), path: PathBuf::from(value) },
                };
                if let ManagementAction::BrowseRepository { repository } = &action {
                    self.repository = repository.clone();
                    self.page = ManagementPage::Catalog;
                    self.surface.filter.value.clear();
                }
                // Retain the path draft until the host reports success or the user backs out.
                ManagementResult::Action(action)
            },
        }
    }

    pub fn saved(&mut self) {
        self.path = None;
        self.page = self.root_entry.as_ref().map_or(ManagementPage::List, |id| ManagementPage::Detail(id.clone()));
        self.refresh();
    }

    fn open_path(&mut self, mode: PathMode) {
        let title = match mode { PathMode::Install => "Install extension", PathMode::Development => "Load development package", PathMode::Repository => "Browse GitHub repository", PathMode::Update { .. } => "Update extension" };
        let mut form = if matches!(mode, PathMode::Repository) {
            let mut form = Form::new(title, vec![Field::text("GitHub owner/repo or HTTPS URL", &self.repository)]);
            form.description = "Discover packages from this repository's GitHub Release catalog. Third-party publishers are unverified. Browsing does not download a package, enable an extension or grant permissions.".into();
            form.submit = "Browse releases".into();
            form
        } else {
            // A package page offers its remembered development source for review again.
            let remembered = match (&mode, &self.page) {
                (PathMode::Development, ManagementPage::Detail(id)) => self.entries.iter().find(|entry| &entry.manifest.id == id)
                    .and_then(|entry| entry.development_path.as_deref()).map(|path| path.to_string_lossy()),
                _ => None,
            };
            let mut form = Form::new(title, vec![Field::text("Package path (.vyxext)", remembered.unwrap_or_default())]);
            form.description = "Choose a local immutable package snapshot. Vyx will inspect its identity, version, digest and permissions before installation. This does not run code or approve permissions.".into();
            form.submit = "Inspect package".into();
            form
        };
        form.cancel = "Back".into();
        self.path = Some((mode, form));
        self.path_hits.clear();
    }

    fn handle(&mut self, intent: SurfaceAction) -> ManagementResult {
        match intent {
            SurfaceAction::Close => {
                if self.surface.busy || matches!(self.page, ManagementPage::List)
                    || matches!(&self.page, ManagementPage::Detail(id) if self.root_entry.as_ref() == Some(id)) {
                    return ManagementResult::Back;
                }
                self.page = match &self.page {
                    ManagementPage::CatalogDetail(_) => ManagementPage::Catalog,
                    // Cancelling a confirmation returns to the same package.
                    ManagementPage::Confirm { entry, .. } => ManagementPage::Detail(entry.manifest.id.clone()),
                    _ => self.root_entry.as_ref().map_or(ManagementPage::List, |id| ManagementPage::Detail(id.clone())),
                };
                self.surface.filter.value.clear();
                self.refresh();
            },
            SurfaceAction::Event(Event::Action { action_id, item_id }) => {
                match action_id.as_str() {
                    "browse" => {
                        self.repository = OFFICIAL_REPOSITORY.into();
                        self.page = ManagementPage::Catalog;
                        return ManagementResult::Action(ManagementAction::BrowseRepository { repository: self.repository.clone() });
                    },
                    "repository" => { self.open_path(PathMode::Repository); return ManagementResult::None; },
                    "refresh-catalog" => return ManagementResult::Action(ManagementAction::BrowseRepository { repository: self.repository.clone() }),
                    "runtime" => return ManagementResult::Action(ManagementAction::DownloadRuntime),
                    "installed" => {
                        self.page = ManagementPage::List;
                        self.surface.filter.value.clear();
                        self.refresh();
                        return ManagementResult::None;
                    },
                    "catalog-detail" => {
                        if let Some(index) = item_id.as_deref().and_then(|id| id.parse::<usize>().ok()).filter(|index| *index < self.catalog.len()) {
                            self.page = ManagementPage::CatalogDetail(index);
                            self.refresh();
                        }
                        return ManagementResult::None;
                    },
                    "download" => {
                        if let ManagementPage::CatalogDetail(index) = self.page
                            && let Some(entry) = self.catalog.get(index) {
                            return ManagementResult::Action(ManagementAction::Download { entry: entry.clone() });
                        }
                        return ManagementResult::None;
                    },
                    _ => {},
                }
                if action_id == "install" { self.open_path(PathMode::Install); return ManagementResult::None; }
                if action_id == "development" { self.open_path(PathMode::Development); return ManagementResult::None; }
                if action_id == "manage" && let Some(id) = item_id { self.page = ManagementPage::Detail(id); self.refresh(); return ManagementResult::None; }
                if action_id == "approve" {
                    if let ManagementPage::Confirm { entry, operation } = &self.page {
                        let extension_id = entry.manifest.id.clone();
                        let action = match *operation {
                            "enable" => ManagementAction::Enable { extension_id, digest: entry.digest.clone(), grants: entry.manifest.permissions.clone() },
                            "remove" => ManagementAction::Remove { extension_id },
                            "disable" => ManagementAction::Disable { extension_id },
                            "trust" => ManagementAction::TrustRebuilds { extension_id, digest: entry.digest.clone(), trusted: !entry.trust_rebuilds },
                            _ => return ManagementResult::None,
                        };
                        return ManagementResult::Action(action);
                    }
                }
                let ManagementPage::Detail(id) = &self.page else { return ManagementResult::None; };
                let Some(entry) = self.entries.iter().find(|entry| &entry.manifest.id == id).cloned() else { return ManagementResult::None; };
                let extension_id = entry.manifest.id.clone();
                let emitted = match action_id.as_str() {
                    // Opening native settings runs no package code and starts no worker.
                    "ai-settings" if entry.native => return ManagementResult::OpenAi,
                    "retry" => Some(ManagementAction::Retry { extension_id }),
                    "reload" if entry.development && entry.reload_available => Some(ManagementAction::Reload { extension_id }),
                    "browse-updates" => {
                        if let Some(repository) = entry.repository {
                            self.repository = repository.clone();
                            self.page = ManagementPage::Catalog;
                            return ManagementResult::Action(ManagementAction::BrowseRepository { repository });
                        }
                        None
                    },
                    "update" => { self.open_path(PathMode::Update { extension_id, digest: entry.digest }); None },
                    "enable" | "remove" | "disable" | "trust" => {
                        if action_id == "trust" && !entry.development { return ManagementResult::None; }
                        let operation = match action_id.as_str() { "enable" => "enable", "remove" => "remove", "disable" => "disable", _ => "trust" };
                        let mut fields = entry_fields(&entry);
                        fields.push(detail("Review", match operation {
                            "enable" => "Approve all requested permissions for this exact digest. Declaring permissions alone grants nothing.",
                            "remove" => "Remove this local package and grants. Saved servers and already approved SSH sessions remain.",
                            "disable" => "Disabling stops this extension and clears its granted permissions. Enabling it again requires a new permission review. Saved servers and SSH sessions stay intact.",
                            _ => "Session-only trust for rebuilds from this entry's development path and extension ID, limited to the reviewed permission ceiling. ID or permission growth always requires review.",
                        }));
                        self.surface = ExtensionSurface::new(None, View::Detail { title: format!("Review {operation}"), fields, actions: vec![action("approve", match operation { "enable" => "Approve and enable", "remove" => "Remove package", "disable" => "Disable extension", _ if entry.trust_rebuilds => "Stop trusting rebuilds", _ => "Trust these rebuilds" })] });
                        if matches!(operation, "remove" | "disable") { self.surface.danger = Some("approve"); }
                        self.page = ManagementPage::Confirm { entry, operation };
                        None
                    },
                    "diagnostics" => {
                        let fields = entry.diagnostics.iter().enumerate().flat_map(|(index, line)| {
                            // Ring lines may contain long stacks; preserve all displayable data in scrollable fields.
                            line.split('\n').map(move |line| detail(&format!("Log {}", index + 1), &sanitize_display(line)))
                        }).collect();
                        self.surface = ExtensionSurface::new(None, View::Detail { title: format!("Diagnostics · {}", sanitize_display(&entry.manifest.id)), fields, actions: vec![action("retry", "Retry"), action("back", "Package details")] });
                        None
                    },
                    "back" => { self.refresh(); None },
                    _ => None,
                };
                if let Some(action) = emitted { return ManagementResult::Action(action); }
            },
            _ => {},
        }
        ManagementResult::None
    }
}

fn detail(label: &str, value: &str) -> DetailField { DetailField { label: label.into(), value: sanitize_display(value) } }

fn entry_fields(entry: &ExtensionEntry) -> Vec<DetailField> {
    let mut fields = vec![
        detail("ID", &entry.manifest.id), detail("Version", &entry.manifest.version),
        detail("SHA-256", &entry.digest), detail("Publisher / source", source(entry)),
        detail("Description", &entry.manifest.description),
        detail("Enabled", if entry.enabled { "Yes" } else { "No" }), detail("Status", &entry.status),
    ];
    if let Some(repository) = &entry.repository { fields.push(detail("Repository", repository)); }
    for requested in &entry.manifest.permissions {
        fields.push(detail(if entry.grants.contains(requested) { "Granted" } else { "Requested, not granted" }, permission(*requested)));
    }
    if entry.manifest.permissions.is_empty() { fields.push(detail("Permissions", "No host capabilities requested")); }
    if entry.development { fields.push(detail("Trust rebuilds", if entry.trust_rebuilds { "Trusted for this session, path, identity and permission ceiling" } else { "Every replacement requires review" })); }
    if let Some(path) = &entry.development_path {
        fields.push(detail("Development path", &path.to_string_lossy()));
        // Remembered approval covers only the reviewed bytes at this path.
        if !entry.development { fields.push(detail("Development review", "Needed: the remembered package changed or is unavailable. Load development package to review it again.")); }
    }
    if entry.native { fields.push(detail("Host integration", "Commands open native Vyx AI chat and settings. They never start the sandbox worker, and the package receives no credentials, history, terminal contents, or network access.")); }
    fields
}

fn management_list(entries: &[ExtensionEntry]) -> View {
    View::List { title: "Settings / Extensions".into(), searchable: true,
        items: entries.iter().map(|entry| ListItem {
            id: entry.manifest.id.clone(), title: sanitize_display(&entry.manifest.name),
            subtitle: Some(format!("{} · {} · {}", sanitize_display(&entry.manifest.version), if entry.enabled { "Enabled" } else { "Disabled" }, source(entry))),
            metadata: entry_fields(entry), actions: vec!["manage".into()],
        }).collect(),
        actions: {
            let mut actions = Vec::new();
            if !entries.is_empty() { actions.push(action("manage", "Package details")); }
            actions.extend([action("browse", "Browse official catalog"), action("repository", "Browse GitHub repository"), action("install", "Install local package"), action("development", "Load development package"), action("runtime", "Install / repair sandbox worker")]);
            actions
        },
    }
}

fn management_detail(entry: &ExtensionEntry) -> View {
    let mut actions = Vec::new();
    // Native settings stay usable while the package is disabled; inference remains gated by the App.
    if entry.native { actions.push(action("ai-settings", "Open Vyx AI settings")); }
    // Local installation is not a development activation; expose the distinct
    // reviewed load here rather than making users find it on the parent page.
    if entry.repository.is_none() && !entry.development {
        actions.push(action("development", "Load development package"));
    }
    actions.push(if entry.enabled { action("disable", "Disable") } else { action("enable", "Review and enable") });
    if entry.repository.is_some() { actions.push(action("browse-updates", "Browse repository updates")); }
    actions.extend([action("update", "Update from local package"), action("diagnostics", "Diagnostics"), action("retry", "Retry")]);
    actions.push(action("remove", "Remove"));
    if entry.development {
        actions.push(action("trust", if entry.trust_rebuilds { "Stop trusting rebuilds" } else { "Trust rebuilds" }));
        if entry.reload_available { actions.push(action("reload", "Reload replacement")); }
    }
    View::Detail { title: format!("Extension · {}", sanitize_display(&entry.manifest.name)), fields: entry_fields(entry), actions }
}

fn same_entry(before: &ExtensionEntry, after: &ExtensionEntry) -> bool {
    before.manifest.id == after.manifest.id
        && before.digest == after.digest
        && before.enabled == after.enabled
        && before.grants == after.grants
        && before.official == after.official
        && before.repository == after.repository
        && before.development == after.development
        && before.development_path == after.development_path
        && before.status == after.status
        && before.diagnostics == after.diagnostics
        && before.trust_rebuilds == after.trust_rebuilds
        && before.reload_available == after.reload_available
        && before.native == after.native
}

fn catalog_fields(entry: &CatalogEntry, installed: &[ExtensionEntry]) -> Vec<DetailField> {
    let mut fields = vec![
        detail("ID", &entry.manifest.id),
        detail("Description", &entry.manifest.description),
        detail("Version", &entry.manifest.version),
        detail("Publisher / source", if entry.source.is_official() { "Vyx release" } else { "Unverified publisher" }),
        detail("Repository", &entry.source.repository),
        detail("Release", &entry.source.tag),
        detail("Asset", &entry.source.asset),
        detail("Download size", &format!("{} bytes", entry.bytes)),
        detail("SHA-256", &entry.digest),
    ];
    if let Some(current) = installed.iter().find(|current| current.manifest.id == entry.manifest.id) {
        fields.push(detail("Installed version", &current.manifest.version));
        fields.push(detail("Installed SHA-256", &current.digest));
    }
    for requested in &entry.manifest.permissions {
        fields.push(detail("Requested, not granted", permission(*requested)));
    }
    if entry.manifest.permissions.is_empty() { fields.push(detail("Permissions", "No host capabilities requested")); }
    fields.push(detail("Review", "Download retrieves an immutable package for host-owned review. Installation does not enable it or approve permissions. Repository metadata and third-party publisher names are unverified."));
    fields
}

fn catalog_list(repository: &str, catalog: &[CatalogEntry], installed: &[ExtensionEntry]) -> View {
    let mut actions = Vec::new();
    if !catalog.is_empty() { actions.push(action("catalog-detail", "Package details")); }
    actions.extend([action("refresh-catalog", "Refresh catalog"), action("repository", "Browse GitHub repository"), action("browse", "Browse official catalog"), action("installed", "Installed packages")]);
    View::List {
        title: format!("Available extensions · {}", sanitize_display(repository)),
        searchable: true,
        items: catalog.iter().enumerate().map(|(index, entry)| ListItem {
            id: index.to_string(),
            title: sanitize_display(&entry.manifest.name),
            subtitle: Some(format!("{} · {} · {}", sanitize_display(&entry.manifest.version), if entry.source.is_official() { "Vyx release" } else { "Unverified publisher" }, if installed.iter().any(|current| current.manifest.id == entry.manifest.id) { "Installed" } else { "Available" })),
            metadata: catalog_fields(entry, installed),
            actions: vec!["catalog-detail".into()],
        }).collect(),
        actions,
    }
}

fn catalog_detail(entry: &CatalogEntry, installed: &[ExtensionEntry]) -> View {
    let current = installed.iter().find(|current| current.manifest.id == entry.manifest.id);
    let label = match current {
        Some(current) if current.digest == entry.digest => "Download again for review",
        Some(_) => "Download update for review",
        None => "Download for review",
    };
    View::Detail {
        title: format!("Available extension · {}", sanitize_display(&entry.manifest.name)),
        fields: catalog_fields(entry, installed),
        actions: vec![action("download", label), action("installed", "Installed packages")],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyModifiers};
    use ratatui::{Terminal, backend::TestBackend};
    use crate::theme::default_theme;

    #[test]
    fn action_buttons_invoke_view_actions_when_item_actions_are_unavailable() {
        let item = ListItem { id: "alpha".into(), title: "Alpha".into(), subtitle: None, metadata: Vec::new(), actions: vec!["open".into()] };
        let mut surface = ExtensionSurface::new(None, View::List { title: "Items".into(), searchable: true, items: vec![item],
            actions: vec![action("open", "Open item"), action("refresh", "Refresh")] });
        // A filter without matches leaves only the second, global action available.
        surface.paste("zzz");
        let bindings = Bindings::default();
        let mut terminal = Terminal::new(TestBackend::new(80, 12)).unwrap();
        terminal.draw(|frame| surface.draw(frame, frame.area(), &bindings, &default_theme().palette, true)).unwrap();
        let buffer = terminal.backend().buffer();
        let width = usize::from(buffer.area.width);
        let position = (0..buffer.content.len()).find(|&start| buffer.content[start..(start / width + 1) * width].iter()
            .map(|cell| cell.symbol()).collect::<String>().starts_with("[Refresh]")).expect("global action button");
        let click = MouseEvent { kind: MouseEventKind::Down(MouseButton::Left), column: (position % width) as u16,
            row: (position / width) as u16, modifiers: KeyModifiers::NONE };
        let SurfaceAction::Event(Event::Action { action_id, item_id }) = surface.mouse(click, &bindings) else { panic!("click invoked nothing") };
        assert_eq!((action_id.as_str(), item_id), ("refresh", None));
        surface.key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE), &bindings);
        let SurfaceAction::Event(Event::Action { action_id, .. }) = surface.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE), &bindings)
            else { panic!("keyboard invoked nothing") };
        assert_eq!(action_id, "refresh");
    }
}
