use crossterm::event::{KeyEvent, MouseButton, MouseEvent, MouseEventKind};
use ratatui::{
    Frame,
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
};

use crate::{
    screen::safe_text,
    shortcuts::{Bindings, Shortcut},
    theme::{Appearance, Palette, Theme, THEMES},
    ui::{
        form::{Field, breadcrumb},
        render::contains,
        theming::clear,
        widgets::{Button, ButtonKind, Notice, draw_buttons, draw_scrollbar, keyed_captions},
    },
};

pub enum ThemeAction {
    None,
    Back,
    Apply(&'static Theme),
}

#[derive(Clone, Copy)]
enum Target {
    Group(usize),
    Row(usize),
    Search,
    Previous,
    Next,
    PageUp,
    PageDown,
    Scrollbar,
    Apply,
    Back,
    Keep,
    Undo,
    Clear,
}

struct Hit {
    area: Rect,
    target: Target,
}

struct SearchSnapshot {
    text: String,
    selected: usize,
    scroll: usize,
}

pub struct ThemeMenu {
    group: Option<Appearance>,
    selected_group: usize,
    counts: [usize; 2],
    query: Field,
    filter: String,
    search: Option<SearchSnapshot>,
    matches: Vec<&'static Theme>,
    selected: usize,
    scroll: usize,
    visible_rows: usize,
    area: Rect,
    scrollbar: Rect,
    dragging_scrollbar: bool,
    hits: Vec<Hit>,
    notice: Option<Notice>,
}

impl ThemeMenu {
    pub fn new(current: &Theme) -> Self {
        let mut counts = [0; 2];
        for theme in THEMES {
            counts[usize::from(theme.appearance == Appearance::Light)] += 1;
        }
        Self {
            group: None,
            selected_group: usize::from(current.appearance == Appearance::Light),
            counts,
            query: Field::text("Search", ""),
            filter: String::new(),
            search: None,
            matches: Vec::with_capacity(counts[0].max(counts[1])),
            selected: 0,
            scroll: 0,
            visible_rows: 1,
            area: Rect::default(),
            scrollbar: Rect::default(),
            dragging_scrollbar: false,
            hits: Vec::new(),
            notice: None,
        }
    }

    fn open_group(&mut self, index: usize, current: &Theme) {
        self.selected_group = index.min(1);
        self.group = Some(if self.selected_group == 0 { Appearance::Dark } else { Appearance::Light });
        self.notice = None;
        self.refilter(Some(current.id));
    }

    fn refilter(&mut self, preferred: Option<&str>) {
        self.matches.clear();
        if let Some(group) = self.group {
            self.matches.extend(THEMES.iter().filter(|theme| {
                theme.appearance == group && theme.search.contains(self.filter.as_str())
            }));
        }
        self.selected = preferred.and_then(|id| self.matches.iter().position(|theme| theme.id == id)).unwrap_or(0);
        self.scroll = 0;
        self.keep_visible();
    }

    fn query_changed(&mut self) {
        if self.query.value.chars().flat_map(char::to_lowercase).eq(self.filter.chars()) {
            return;
        }
        let preferred = self.matches.get(self.selected).map(|theme| theme.id);
        self.filter.clear();
        self.filter.extend(self.query.value.chars().flat_map(char::to_lowercase));
        self.notice = None;
        self.refilter(preferred);
    }

    fn begin_search(&mut self) {
        if self.group.is_some() && self.search.is_none() {
            self.search = Some(SearchSnapshot {
                text: self.query.value.to_string(),
                selected: self.selected,
                scroll: self.scroll,
            });
        }
    }

    fn finish_search(&mut self, cancel: bool) {
        if let Some(snapshot) = self.search.take() {
            if cancel {
                self.query.set_value(&snapshot.text);
                self.query_changed();
                self.selected = snapshot.selected;
                self.scroll = snapshot.scroll;
                self.keep_visible();
            }
        }
    }

    fn keep_visible(&mut self) {
        self.selected = self.selected.min(self.matches.len().saturating_sub(1));
        let visible = self.visible_rows.max(1);
        self.scroll = self.scroll.min(self.matches.len().saturating_sub(visible));
        if self.selected < self.scroll {
            self.scroll = self.selected;
        } else if self.selected >= self.scroll + visible {
            self.scroll = self.selected + 1 - visible;
        }
    }

    fn move_selection(&mut self, delta: isize) {
        if self.group.is_none() {
            self.selected_group = self.selected_group.saturating_add_signed(delta).min(1);
        } else {
            self.selected = self.selected.saturating_add_signed(delta).min(self.matches.len().saturating_sub(1));
            self.keep_visible();
        }
    }

    fn apply(&mut self) -> ThemeAction {
        self.finish_search(false);
        self.matches.get(self.selected).copied().map_or(ThemeAction::None, ThemeAction::Apply)
    }

    fn back(&mut self) -> ThemeAction {
        self.finish_search(false);
        self.notice = None;
        if self.group.take().is_some() { ThemeAction::None } else { ThemeAction::Back }
    }

    pub fn key(&mut self, key: KeyEvent, bindings: &Bindings, current: &'static Theme) -> ThemeAction {
        if self.search.is_some() {
            if bindings.matches(Shortcut::SearchKeep, key) {
                self.finish_search(false);
            } else if bindings.matches(Shortcut::SearchCancel, key) {
                self.finish_search(true);
            } else if bindings.matches(Shortcut::SearchPrevious, key) {
                self.move_selection(-1);
            } else if bindings.matches(Shortcut::SearchNext, key) {
                self.move_selection(1);
            } else {
                self.query.key(key, bindings);
                self.query_changed();
            }
            return ThemeAction::None;
        }
        if bindings.matches(Shortcut::MenuPrevious, key) {
            self.move_selection(-1);
        } else if bindings.matches(Shortcut::MenuNext, key) {
            self.move_selection(1);
        } else if bindings.matches(Shortcut::MenuPageUp, key) {
            self.move_selection(-(self.visible_rows as isize));
        } else if bindings.matches(Shortcut::MenuPageDown, key) {
            self.move_selection(self.visible_rows as isize);
        } else if bindings.matches(Shortcut::MenuFirst, key) {
            self.selected_group = 0;
            self.selected = 0;
            self.keep_visible();
        } else if bindings.matches(Shortcut::MenuLast, key) {
            self.selected_group = 1;
            self.selected = self.matches.len().saturating_sub(1);
            self.keep_visible();
        } else if bindings.matches(Shortcut::SettingsEdit, key) {
            if self.group.is_some() {
                return self.apply();
            }
            self.open_group(self.selected_group, current);
        } else if bindings.matches(Shortcut::SettingsClose, key) {
            return self.back();
        } else if bindings.matches(Shortcut::NextField, key) || bindings.matches(Shortcut::PreviousField, key) {
            self.begin_search();
        }
        ThemeAction::None
    }

    pub fn paste(&mut self, text: &str) {
        if self.group.is_some() {
            self.begin_search();
            self.query.paste(text);
            self.query_changed();
        }
    }

    pub fn mouse(&mut self, mouse: MouseEvent, current: &'static Theme) -> ThemeAction {
        if mouse.kind == MouseEventKind::Up(MouseButton::Left) {
            self.dragging_scrollbar = false;
            return ThemeAction::None;
        }
        if self.dragging_scrollbar && mouse.kind == MouseEventKind::Drag(MouseButton::Left) {
            self.scroll_to(mouse.row);
            return ThemeAction::None;
        }
        if !contains(self.area, mouse.column, mouse.row) {
            return ThemeAction::None;
        }
        match mouse.kind {
            MouseEventKind::ScrollUp => self.move_selection(-3),
            MouseEventKind::ScrollDown => self.move_selection(3),
            MouseEventKind::Down(MouseButton::Left) => {
                self.dragging_scrollbar = false;
                let target = self.hits.iter().rev()
                    .find(|hit| contains(hit.area, mouse.column, mouse.row)).map(|hit| hit.target);
                match target {
                    Some(Target::Group(index)) => self.open_group(index, current),
                    Some(Target::Row(index)) => {
                        self.finish_search(false);
                        self.selected = index;
                        self.keep_visible();
                    }
                    Some(Target::Search) => self.begin_search(),
                    Some(Target::Previous) => self.move_selection(-1),
                    Some(Target::Next) => self.move_selection(1),
                    Some(Target::PageUp) => self.move_selection(-(self.visible_rows as isize)),
                    Some(Target::PageDown) => self.move_selection(self.visible_rows as isize),
                    Some(Target::Scrollbar) => {
                        self.dragging_scrollbar = true;
                        self.scroll_to(mouse.row);
                    }
                    Some(Target::Apply) if self.group.is_none() => self.open_group(self.selected_group, current),
                    Some(Target::Apply) => return self.apply(),
                    Some(Target::Back) => return self.back(),
                    Some(Target::Keep) => self.finish_search(false),
                    Some(Target::Undo) => self.finish_search(true),
                    Some(Target::Clear) => {
                        self.query.set_value("");
                        self.query_changed();
                    }
                    None => {}
                }
            }
            _ => {}
        }
        ThemeAction::None
    }

    fn scroll_to(&mut self, row: u16) {
        let position = usize::from(row.saturating_sub(self.scrollbar.y).min(self.scrollbar.height.saturating_sub(1)));
        let maximum = self.matches.len().saturating_sub(self.visible_rows);
        self.scroll = position * maximum / usize::from(self.scrollbar.height.saturating_sub(1).max(1));
        self.selected = self.selected.clamp(self.scroll, (self.scroll + self.visible_rows - 1).min(self.matches.len().saturating_sub(1)));
    }

    pub fn saved(&mut self, warning: Option<String>) {
        self.notice = Some(warning.map_or_else(|| Notice::success("Theme saved locally."), |message| Notice::warning(safe_text(&message))));
    }

    pub fn set_error(&mut self, error: String) {
        self.notice = Some(Notice::error(safe_text(&error)));
    }

    /// `active` is false while Settings navigation owns the keyboard beside this page; the page
    /// then draws no focus marker or search cursor.
    pub fn draw(&mut self, frame: &mut Frame, area: Rect, bindings: &Bindings, current: &'static Theme, active: bool) {
        self.area = area;
        self.hits.clear();
        self.scrollbar = Rect::default();
        let palette = &current.palette;
        clear(frame, area, palette);
        if area.width < 3 || area.height < 3 {
            return;
        }
        let title = match self.group {
            Some(group) => format!("Settings / Themes / {} · {}/{}", group.label(), if self.matches.is_empty() { 0 } else { self.selected + 1 }, self.matches.len()),
            None => "Settings / Themes".to_owned(),
        };
        let title = format!(" {} ", breadcrumb(&title, area.width.saturating_sub(4)));
        let block = Block::default().title(title).borders(Borders::ALL).border_style(Style::default().fg(palette.accent));
        let inner = block.inner(area);
        frame.render_widget(block, area);
        if self.group.is_none() {
            self.draw_groups(frame, inner, bindings, current, active);
            return;
        }

        let controls_height = if inner.width >= 78 { 1 } else { 2 }.min(inner.height);
        let available = inner.height.saturating_sub(controls_height);
        let search_height = available.min(1);
        let notice_height = u16::from(self.notice.is_some() && available > search_height + 1);
        let preview_height = if available >= search_height + notice_height + 8 { 4 } else { 0 };
        let list_height = available.saturating_sub(search_height + notice_height + preview_height);
        let search = Rect::new(inner.x, inner.y, inner.width, search_height);
        let list = Rect::new(inner.x, search.bottom(), inner.width, list_height);
        let preview = Rect::new(inner.x, list.bottom(), inner.width, preview_height);
        let notice = Rect::new(inner.x, preview.bottom(), inner.width, notice_height);
        let controls = Rect::new(inner.x, notice.bottom(), inner.width, controls_height);
        if search.height > 0 {
            let caption_width = search.width.min(8);
            frame.render_widget(Span::styled("Search: ", Style::default().fg(palette.accent)), Rect { width: caption_width, ..search });
            self.query.draw_input(frame, Rect::new(search.x + caption_width, search.y, search.width - caption_width, 1), active && self.search.is_some(), palette);
            self.hits.push(Hit { area: search, target: Target::Search });
        }
        self.visible_rows = usize::from(list.height).max(1);
        self.keep_visible();
        let has_scrollbar = self.matches.len() > self.visible_rows && list.width >= 2 && list.height > 0;
        let row_width = list.width.saturating_sub(u16::from(has_scrollbar));
        if self.matches.is_empty() {
            frame.render_widget(Paragraph::new("No themes match this search.").style(Style::default().fg(palette.muted)), list);
        } else {
            for (slot, theme) in self.matches.iter().skip(self.scroll).take(usize::from(list.height)).enumerate() {
                let index = self.scroll + slot;
                let row = Rect::new(list.x, list.y + slot as u16, row_width, 1);
                let selected = active && index == self.selected;
                let style = if selected {
                    Style::default().fg(palette.selection_fg).bg(palette.selection_bg).add_modifier(Modifier::BOLD)
                } else {
                    palette.style()
                };
                let text = format!("{}{} {} [{}]", if selected { ">" } else { " " }, if theme.id == current.id { "*" } else { " " }, theme.name, theme.system);
                frame.render_widget(Paragraph::new(text).style(style), row);
                self.hits.push(Hit { area: row, target: Target::Row(index) });
            }
        }
        if has_scrollbar {
            self.scrollbar = Rect::new(list.right() - 1, list.y, 1, list.height);
            draw_scrollbar(frame, list, self.scroll, self.matches.len(), palette);
            self.hits.push(Hit { area: self.scrollbar, target: Target::Scrollbar });
        }
        self.draw_preview(frame, preview);
        if notice.height > 0 && let Some(notice_text) = &self.notice {
            notice_text.draw(frame, notice, palette);
        }
        self.draw_controls(frame, controls, bindings, palette);
    }

    fn draw_groups(&mut self, frame: &mut Frame, area: Rect, bindings: &Bindings, current: &Theme, active: bool) {
        let palette = &current.palette;
        if area.height == 0 { return; }
        frame.render_widget(Paragraph::new(format!("Tinted collection · {} themes · offline", THEMES.len())).style(Style::default().fg(palette.muted)), Rect { height: 1, ..area });
        for (index, group) in [Appearance::Dark, Appearance::Light].into_iter().enumerate() {
            let y = area.y + 1 + index as u16;
            if y >= area.bottom().saturating_sub(1) { break; }
            let row = Rect::new(area.x, y, area.width, 1);
            let selected = active && self.selected_group == index;
            let style = if selected {
                Style::default().fg(palette.selection_fg).bg(palette.selection_bg).add_modifier(Modifier::BOLD)
            } else { palette.style() };
            frame.render_widget(Paragraph::new(format!("{} {} · {} themes", if selected { ">" } else { " " }, group.label(), self.counts[index])).style(style), row);
            self.hits.push(Hit { area: row, target: Target::Group(index) });
        }
        if area.height > 4 {
            let detail = Rect::new(area.x, area.y + 3, area.width, area.height - 4);
            frame.render_widget(Paragraph::new(vec![
                Line::from(format!("Current: {} [{}]", current.name, current.system)),
                Line::from("Base16, Base24 and Tinted8. Search by name or ID."),
                Line::from("Preview a palette, then Apply. Browsing does not change the active theme."),
                Line::from("Changes stay local and do not reconnect SSH sessions."),
            ]), detail);
        }
        let footer = Rect::new(area.x, area.bottom() - 1, area.width, 1);
        let captions = keyed_captions(&[("Open", bindings.primary(Shortcut::SettingsEdit)), ("Back", bindings.primary(Shortcut::SettingsClose))], footer.width, 1);
        let targets = [Target::Apply, Target::Back];
        let hits = &mut self.hits;
        draw_buttons(frame, footer, &[Button::primary(&captions[0]), Button::secondary(&captions[1])], None, palette,
            |index, area| hits.push(Hit { area, target: targets[index] }));
    }

    fn draw_preview(&self, frame: &mut Frame, area: Rect) {
        if area.height < 4 || area.width == 0 { return; }
        let Some(theme) = self.matches.get(self.selected) else { return; };
        let palette = &theme.palette;
        clear(frame, area, palette);
        frame.render_widget(Paragraph::new(format!("Preview: {}", theme.id)).style(Style::default().fg(palette.accent)), Rect { height: 1, ..area });
        frame.render_widget(Paragraph::new(Line::from(vec![
            Span::raw(" Sample text "),
            Span::styled(" success ", Style::default().fg(palette.success)),
            Span::styled(" warning ", Style::default().fg(palette.warning)),
            Span::styled(" error ", Style::default().fg(palette.error)),
        ])), Rect::new(area.x, area.y + 1, area.width, 1));
        let width = (area.width / 16).clamp(1, 4);
        for (index, color) in palette.ansi.into_iter().enumerate() {
            let x = area.x + index as u16 * width;
            if x >= area.right() { break; }
            frame.render_widget(Block::default().style(Style::default().bg(color)), Rect::new(x, area.y + 2, width.min(area.right() - x), 1));
        }
        frame.render_widget(Paragraph::new(theme.author).style(Style::default().fg(palette.muted)), Rect::new(area.x, area.y + 3, area.width, 1));
    }

    fn draw_controls(&mut self, frame: &mut Frame, area: Rect, bindings: &Bindings, palette: &Palette) {
        if area.height == 0 { return; }
        let searching = self.search.is_some();
        let page_up = if searching { "" } else { bindings.primary(Shortcut::MenuPageUp) };
        let page_down = if searching { "" } else { bindings.primary(Shortcut::MenuPageDown) };
        let navigation = [
            ("Prev", bindings.primary(if searching { Shortcut::SearchPrevious } else { Shortcut::MenuPrevious }), Target::Previous),
            ("Next", bindings.primary(if searching { Shortcut::SearchNext } else { Shortcut::MenuNext }), Target::Next),
            ("PgUp", page_up, Target::PageUp),
            ("PgDn", page_down, Target::PageDown),
        ];
        let search_conflict = bindings.primary_event(Shortcut::NextField).is_some_and(|search_key| {
            [Shortcut::MenuPrevious, Shortcut::MenuNext, Shortcut::MenuPageUp, Shortcut::MenuPageDown, Shortcut::MenuFirst, Shortcut::MenuLast, Shortcut::SettingsEdit, Shortcut::SettingsClose]
                .into_iter().any(|action| bindings.matches(action, search_key))
        });
        let controls = if searching {
            [
                navigation[0], navigation[1], navigation[2], navigation[3],
                ("Keep", bindings.primary(Shortcut::SearchKeep), Target::Keep),
                ("Undo", bindings.primary(Shortcut::SearchCancel), Target::Undo),
                ("Clear", bindings.primary(Shortcut::ClearField), Target::Clear),
            ]
        } else {
            [
                navigation[0], navigation[1], navigation[2], navigation[3],
                ("Apply", bindings.primary(Shortcut::SettingsEdit), Target::Apply),
                ("Search", if search_conflict { "" } else { bindings.primary(Shortcut::NextField) }, Target::Search),
                ("Back", bindings.primary(Shortcut::SettingsClose), Target::Back),
            ]
        };
        let labels = controls.map(|(caption, key, _)| (caption, key));
        let captions = keyed_captions(&labels, area.width, area.height);
        let can_apply = !self.matches.is_empty();
        let buttons: Vec<Button<'_>> = captions.iter().zip(&controls).map(|(caption, (_, _, target))| {
            let kind = if matches!(target, Target::Apply | Target::Keep) { ButtonKind::Primary } else { ButtonKind::Secondary };
            Button::new(caption, kind).enabled(!matches!(target, Target::Apply) || can_apply)
        }).collect();
        let hits = &mut self.hits;
        draw_buttons(frame, area, &buttons, None, palette, |index, area| hits.push(Hit { area, target: controls[index].2 }));
    }
}
