use std::borrow::Cow;
use std::ops::Range;
use std::time::Duration;

use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Paragraph, Wrap},
};
use uuid::Uuid;

use crate::{
    input::{Focus, PREFIX_COMMANDS, PrefixAction, PrefixContext, SidebarAction, prefix_action},
    screen::safe_text,
    settings::{MAX_SIDEBAR_WIDTH, MIN_SIDEBAR_WIDTH, TerminalLayout, TerminalSizes, WorkspaceSettings},
    shortcuts::{Bindings, Shortcut},
    theme::{Palette, Theme},
    ssh::{Session, SessionPhase},
    ui::{
        actions::{Dialog, auth_label, category_path, host_details},
        ai::AiRender,
        animation::paint_unlock_edge,
        catalog::{Catalog, CatalogRow, RowKey, Section},
        form::{Field, FormHitRegion},
        extensions::ExtensionSurface,
        icons::Icon,
        menu::WorkspaceMenu,
        terminal_layout::{PaneDivider, PaneLayout, PaneResize},
        theming,
        widgets::{self, Button, ButtonKind, Notice},
    },
    vault::{Auth, LocalState},
};

#[derive(Clone, Debug)]
pub enum HitTarget {
    Sidebar(RowKey),
    SidebarBackground,
    SidebarToggle,
    SidebarResize,
    PaneResize(PaneDivider),
    Search,
    /// Clears the kept sidebar filter.
    ClearFilter,
    SidebarAction { key: RowKey, action: SidebarAction },
    Tab(Uuid),
    RenameTab(Uuid),
    CloseTab(Uuid),
    /// Layout control at the end of the tab strip; cycles the terminal arrangement.
    CycleLayout,
    /// Hidden-tab count beside the strip, bound to the nearest hidden session.
    TabOverflow(Uuid),
    /// Reconnect control of an ended pane, bound to that session.
    Reconnect(Uuid),
    Pane(Uuid),
    Terminal(Uuid),
    PrefixToggle,
    PrefixCommand(PrefixAction),
    PrefixPage(isize),
    PrefixPanel,
    /// The open Vyx AI panel; the App routes these events to `ai::Panel::mouse`.
    Ai,
    /// The split AI panel's left border; dragging it resizes the panel.
    AiResize,
}

#[derive(Clone, Debug)]
pub struct HitRegion {
    pub area: Rect,
    pub target: HitTarget,
}

#[derive(Clone, Copy, Debug)]
pub struct TerminalPane {
    pub session_id: Uuid,
    pub inner: Rect,
}

#[derive(Default)]
pub struct RenderOutput {
    pub terminal_area: Option<Rect>,
    pub pane_layout: PaneLayout,
    pub terminals: Vec<TerminalPane>,
    pub sidebar: Option<Rect>,
    pub sidebar_divider: Option<Rect>,
    pub hits: Vec<HitRegion>,
    pub form_hits: Vec<FormHitRegion>,
    pub columns: u16,
    pub narrow: bool,
    /// The frame is below the minimum size and shows only size guidance and the footer.
    pub too_small: bool,
    pub prefix_pages: usize,
    /// Whole Vyx AI panel rectangle when drawn.
    pub ai: Option<Rect>,
    /// The split panel's draggable left border.
    pub ai_divider: Option<Rect>,
    /// The area the AI panel splits with terminals; resize widths derive from its right edge.
    pub ai_bounds: Option<Rect>,
}

pub struct RenderRequest<'a> {
    pub catalog: &'a mut Catalog,
    pub state: &'a LocalState,
    pub sessions: &'a [Session],
    pub active_session: Option<usize>,
    pub focus: Focus,
    pub prefix: bool,
    pub prefix_page: usize,
    /// Which prefix commands apply; the command bar dims the rest.
    pub commands: PrefixContext,
    pub workspace: WorkspaceSettings,
    pub terminal_sizes: &'a TerminalSizes,
    pub pane_resize: Option<PaneResize>,
    pub sidebar_width: u16,
    pub sidebar_overlay: bool,
    pub sync_label: &'a str,
    pub sync_detail: &'a str,
    pub notice: Option<&'a Notice>,
    /// Recovery guidance outranks ordinary notices until it is resolved.
    pub guidance: Option<&'a str>,
    pub update_notice: Option<&'a str>,
    pub uncertain: bool,
    pub dialog: Option<&'a mut Dialog>,
    pub search: Option<&'a Field>,
    pub bindings: &'a Bindings,
    pub theme: &'static Theme,
    pub menu: Option<&'a mut WorkspaceMenu>,
    pub extension_surface: Option<&'a mut ExtensionSurface>,
    pub unlock_reveal: Option<Duration>,
    /// Present whenever Vyx AI is installed; the panel is drawn only while open.
    pub ai: Option<AiRender<'a>>,
    /// Live width while the AI divider is dragged; the saved width otherwise.
    pub ai_width: Option<u16>,
}

const COMPACT_SIDEBAR_WIDTH: u16 = 6;
/// Terminals keep at least this many columns beside a split AI panel.
const MIN_TERMINAL_COLUMNS: u16 = 30;
/// Smallest frame that shows the workspace; anything smaller shows only size guidance.
pub const MIN_COLUMNS: u16 = 40;
pub const MIN_ROWS: u16 = 10;
/// Frames narrower than this show the expanded sidebar over the workspace.
pub const NARROW_COLUMNS: u16 = 70;
/// Narrowest tab that still shows its status icon, some title, and its close control.
const MIN_TAB_WIDTH: u16 = 12;

pub fn too_small(columns: u16, rows: u16) -> bool {
    columns < MIN_COLUMNS || rows < MIN_ROWS
}

pub fn sidebar_width(columns: u16, preferred: u16, narrow: bool) -> u16 {
    let reserved = if narrow { 2 } else { 24 };
    preferred
        .clamp(MIN_SIDEBAR_WIDTH, MAX_SIDEBAR_WIDTH)
        .min(columns.saturating_sub(reserved))
}

/// Split AI panel width: the preference clamped to the panel limits, leaving terminals at
/// least [`MIN_TERMINAL_COLUMNS`]. Callers split only when `main_width` fits both minimums.
pub fn ai_width(main_width: u16, preferred: u16) -> u16 {
    preferred
        .clamp(crate::ai::MIN_PANEL_WIDTH, crate::ai::MAX_PANEL_WIDTH)
        .min(main_width.saturating_sub(MIN_TERMINAL_COLUMNS))
}

pub fn draw(
    frame: &mut Frame,
    mut request: RenderRequest<'_>,
    output: &mut RenderOutput,
) {
    let bounds = frame.area();
    let palette = &request.theme.palette;
    theming::clear(frame, bounds, palette);
    output.terminal_area = None;
    output.terminals.clear();
    output.sidebar = None;
    output.sidebar_divider = None;
    output.hits.clear();
    output.form_hits.clear();
    output.narrow = bounds.width < NARROW_COLUMNS;
    output.columns = bounds.width;
    output.prefix_pages = 1;
    output.ai = None;
    output.ai_divider = None;
    output.ai_bounds = None;
    output.too_small = too_small(bounds.width, bounds.height);
    request.commands.too_small = output.too_small;
    if output.too_small {
        // Workspace, dialogs, and menus cannot fit; only size guidance and the footer remain.
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(1), Constraint::Length(1)])
            .split(bounds);
        draw_too_small(frame, chunks[0], &request);
        draw_footer(frame, chunks[1], &request, output);
        return;
    }

    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(1)])
        .split(bounds);
    let workspace = vertical[0];
    let footer = vertical[1];
    let expanded = request.search.is_some()
        || if output.narrow {
            request.sidebar_overlay
        } else {
            !request.workspace.sidebar_collapsed
        };
    let overlay = output.narrow && expanded;
    let rail_width = COMPACT_SIDEBAR_WIDTH.min(workspace.width.saturating_sub(1));
    let (sidebar, main) = if overlay {
        (None, workspace)
    } else {
        let width = if expanded {
            sidebar_width(workspace.width, request.sidebar_width, false)
        } else {
            rail_width
        };
        let horizontal = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Length(width), Constraint::Min(1)])
            .split(workspace);
        (Some((horizontal[0], expanded)), horizontal[1])
    };

    // Split before terminals are arranged: moving focus never resizes SSH panes.
    let (terminals, panel) = ai_layout(main, workspace, output.narrow, request.ai.as_ref(), request.ai_width);
    draw_main(frame, terminals, &request, output);

    if let Some((area, true)) = sidebar {
        draw_sidebar(frame, area, &mut request, output, false);
    } else if let Some((area, false)) = sidebar {
        draw_compact_sidebar(frame, area, &mut request, output);
    } else {
        let width = sidebar_width(workspace.width, request.sidebar_width, true);
        let area = Rect::new(workspace.x, workspace.y, width, workspace.height);
        theming::clear(frame, area, palette);
        draw_sidebar(frame, area, &mut request, output, true);
    }

    if let Some((area, full)) = panel
        && let Some(ai) = request.ai.as_mut()
    {
        // One elevated palette for clearing and the whole panel, so no strip stays untinted.
        let elevated = theming::elevated(*palette);
        theming::clear(frame, area, &elevated);
        ai.panel.draw(frame, area, &ai.view, request.bindings, &elevated);
        output.ai = Some(area);
        output.hits.push(HitRegion { area, target: HitTarget::Ai });
        if !full {
            let divider = Rect::new(area.x, area.y, 1, area.height);
            if area.height > 2 {
                frame.buffer_mut().set_string(
                    area.x,
                    area.y + area.height / 2,
                    "↔",
                    Style::default().fg(elevated.accent).bg(elevated.background),
                );
            }
            output.ai_divider = Some(divider);
            output.ai_bounds = Some(main);
            // Hit-testing searches in reverse, so the divider wins over the panel beneath it.
            output.hits.push(HitRegion { area: divider, target: HitTarget::AiResize });
        }
    }
    if let Some(surface) = request.extension_surface.as_deref_mut() {
        surface.draw(frame, workspace, request.bindings, palette, true);
    }
    if request.menu.is_none() {
        if let Some(dialog) = request.dialog.as_deref_mut() {
            dialog.draw(frame, bounds, &request.state.vault, request.bindings, &mut output.form_hits, palette);
        }
    }
    if let Some(menu) = request.menu.as_deref_mut() {
        menu.draw(
            frame,
            bounds,
            request.bindings,
            request.workspace,
            request.state,
            request.theme,
        );
    }
    draw_footer(frame, footer, &request, output);
}

/// Current and required size, then how to detach or quit, or the pending quit question.
fn draw_too_small(frame: &mut Frame, area: Rect, request: &RenderRequest<'_>) {
    let palette = &request.theme.palette;
    let bindings = request.bindings;
    let bounds = frame.area();
    let controls = if request.commands.quit_confirming {
        format!("Quit vyx? {} quits · {} keeps working.", bindings.primary(Shortcut::Submit), bindings.primary(Shortcut::Cancel))
    } else {
        format!("{} detaches · {} quits.", bindings.sequence(Shortcut::PrefixDetach), bindings.sequence(Shortcut::PrefixQuit))
    };
    let text = Paragraph::new(vec![
        Line::from(Span::styled(
            "Terminal is too small",
            Style::default().fg(palette.warning).add_modifier(Modifier::BOLD),
        )),
        Line::from(format!("Now {}×{}; needs at least {MIN_COLUMNS}×{MIN_ROWS}.", bounds.width, bounds.height)),
        Line::from(controls),
    ])
    .style(palette.style())
    .alignment(Alignment::Center)
    .wrap(Wrap { trim: true });
    let height = text.line_count(area.width).min(usize::from(area.height)) as u16;
    frame.render_widget(text, Rect { y: area.y + (area.height - height) / 2, height, ..area });
}

fn draw_main(
    frame: &mut Frame,
    area: Rect,
    request: &RenderRequest<'_>,
    output: &mut RenderOutput,
) {
    let palette = &request.theme.palette;
    let split = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(1)])
        .split(area);
    let tabs = split[0];
    let terminal_area = split[1];
    output.terminal_area = Some(terminal_area);
    output.pane_layout.arrange(
        terminal_area,
        request.workspace.terminal_layout,
        request.sessions.len(),
        request.active_session.unwrap_or(0),
        request.terminal_sizes,
        request.pane_resize,
    );

    if request.sessions.is_empty() {
        draw_details(frame, area, request, output);
        return;
    }
    draw_tabs(frame, tabs, request, output);

    let Some(active) = request.active_session else {
        draw_details(frame, terminal_area, request, output);
        return;
    };
    let active = active.min(request.sessions.len() - 1);
    let bindings = request.bindings;
    for (index, pane) in output.pane_layout.panes() {
        let session = &request.sessions[index];
        output.hits.push(HitRegion {
            area: pane,
            target: HitTarget::Pane(session.id),
        });

        let view = session.view.lock();
        let is_active = index == active;
        let border = pane_border(
            palette,
            is_active,
            request.focus == Focus::Terminal,
            matches!(view.phase, SessionPhase::Error(_)),
        );
        let (terminal_outer, phase) = if let SessionPhase::Error(message) = &view.phase {
            let error_height = (pane.height / 3)
                .clamp(5, 10)
                .min(pane.height.saturating_sub(3));
            let areas = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(3), Constraint::Length(error_height)])
                .split(pane);
            frame.render_widget(
                Paragraph::new(safe_text(message))
                    .wrap(Wrap { trim: false })
                    .block(
                        Block::default()
                            .title(" Connection error ")
                            .borders(Borders::ALL)
                            .style(palette.style())
                            .border_style(border),
                    )
                    .style(Style::default().fg(palette.error).bg(palette.background)),
                areas[1],
            );
            (areas[0], "Error".to_owned())
        } else {
            (pane, view.phase.label())
        };
        // Ended panes offer Reconnect and Close at the right of the pane's top border; resize
        // dividers run along bottom and right borders, so they never cover these controls.
        let ended = !view.phase.is_live();
        let controls_row = Rect::new(pane.x.saturating_add(1), pane.y, pane.width.saturating_sub(2), 1);
        let captions = if ended {
            // Durability uncertainty gives the Reconnect key to Retry save.
            let reconnect = if request.uncertain { "" } else { bindings.primary(Shortcut::Reconnect) };
            widgets::keyed_captions(
                &[("Reconnect", reconnect), ("Close", bindings.sequence(Shortcut::PrefixCloseSession))],
                controls_row.width,
                1,
            )
        } else {
            Vec::new()
        };
        let controls_width = captions
            .iter()
            .map(|caption| widgets::width(caption) + 3)
            .sum::<usize>()
            .saturating_sub(1)
            .min(usize::from(controls_row.width)) as u16;
        let controls = Rect {
            x: controls_row.right() - controls_width,
            width: controls_width,
            ..controls_row
        };
        let title = format!(" {} — {} ", safe_text(&session.label), safe_text(&phase));
        let title_room = controls_row.width.saturating_sub(if controls_width > 0 { controls_width + 1 } else { 0 });
        let mut block = Block::default()
            .title(widgets::fit(&title, title_room).into_owned())
            .borders(Borders::ALL)
            .style(palette.style())
            .border_style(border);
        let scrollback = view.terminal.screen().scrollback();
        if scrollback > 0 {
            // Typing returns to the live screen only where it is forwarded.
            let marker = if matches!(view.phase, SessionPhase::Connected) {
                format!(" Scrollback +{scrollback} · type to return ")
            } else {
                format!(" Scrollback +{scrollback} ")
            };
            let room = terminal_outer.width.saturating_sub(2);
            block = block.title_bottom(Line::from(Span::styled(
                widgets::fit(&marker, room).into_owned(),
                Style::default().fg(palette.warning).add_modifier(Modifier::BOLD),
            )));
        }
        let inner = block.inner(terminal_outer);
        let show_cursor = is_active
            && request.focus == Focus::Terminal
            && !request.prefix
            && request.dialog.is_none()
            && request.menu.is_none()
            && matches!(&view.phase, SessionPhase::Connected);
        frame.render_widget(block, terminal_outer);
        theming::terminal(
            frame,
            inner,
            view.terminal.screen(),
            show_cursor,
            palette,
        );
        if inner.width > 0 && inner.height > 0 {
            output.terminals.push(TerminalPane {
                session_id: session.id,
                inner,
            });
            output.hits.push(HitRegion {
                area: inner,
                target: HitTarget::Terminal(session.id),
            });
        }
        if controls_width > 0 {
            let id = session.id;
            let buttons = [Button::primary(&captions[0]), Button::secondary(&captions[1])];
            widgets::draw_buttons(frame, controls, &buttons, None, palette, |button, area| {
                output.hits.push(HitRegion {
                    area,
                    target: if button == 0 { HitTarget::Reconnect(id) } else { HitTarget::CloseTab(id) },
                });
            });
        }
    }
    for divider in output.pane_layout.dividers() {
        let grip = Rect::new(
            divider.area.x + divider.area.width / 2,
            divider.area.y + divider.area.height / 2,
            1,
            1,
        );
        frame.render_widget(
            Span::styled(
                if divider.vertical { "↔" } else { "↕" },
                Style::default().fg(palette.accent).add_modifier(Modifier::BOLD),
            ),
            grip,
        );
        output.hits.push(HitRegion { area: divider.area, target: HitTarget::PaneResize(divider) });
    }
}

/// Border of a terminal pane. The active pane is bold while it receives typing and dimmed
/// while the sidebar or AI panel owns input; inactive panes are plain. Error panes keep the
/// error colour with the same emphasis.
fn pane_border(palette: &Palette, active: bool, typing: bool, error: bool) -> Style {
    let color = if error {
        palette.error
    } else if active {
        palette.accent
    } else {
        palette.border
    };
    match (active, typing) {
        (true, true) => Style::default().fg(color).add_modifier(Modifier::BOLD),
        (true, false) => Style::default().fg(theming::blend(color, palette.background, 0.45)),
        (false, _) => Style::default().fg(color),
    }
}

fn session_icon(phase: &SessionPhase, active: bool) -> Icon {
    match phase {
        SessionPhase::Connected if active => Icon::Active,
        SessionPhase::Connected => Icon::Connected,
        SessionPhase::Connecting | SessionPhase::Authenticating => Icon::Pending,
        SessionPhase::Error(_) => Icon::Error,
        SessionPhase::Closed { .. } => Icon::Closed,
    }
}

/// Tabs shown for `total` sessions: the arranged pane `page` widened to `capacity` tabs, or,
/// when fewer tabs fit than the page holds, shifted within it only far enough to show `active`.
fn tab_window(total: usize, page: Range<usize>, active: usize, capacity: usize) -> Range<usize> {
    let capacity = capacity.clamp(1, total.max(1));
    let start = if capacity >= page.len() {
        page.start
    } else {
        page.start.max((active + 1).saturating_sub(capacity))
    };
    let start = start.min(total.saturating_sub(capacity));
    start..start + capacity
}

fn draw_tabs(
    frame: &mut Frame,
    area: Rect,
    request: &RenderRequest<'_>,
    output: &mut RenderOutput,
) {
    let palette = &request.theme.palette;
    if area.width == 0 || request.sessions.is_empty() {
        return;
    }
    let total = request.sessions.len();
    let active = request.active_session.unwrap_or(0).min(total - 1);
    // An always visible layout control, shortened when its full label would crowd the tabs.
    let full = format!("Layout: {}", request.workspace.terminal_layout.label());
    let caption = if widgets::width(&full) + 3 + 2 * usize::from(MIN_TAB_WIDTH) <= usize::from(area.width) {
        full.as_str()
    } else {
        "Layout"
    };
    let layout_width = (widgets::width(caption) as u16 + 2).min(area.width);
    let layout = Rect::new(area.right() - layout_width, area.y, layout_width, 1);
    widgets::draw_buttons(frame, layout, &[Button::secondary(caption)], None, palette, |_, area| {
        output.hits.push(HitRegion { area, target: HitTarget::CycleLayout });
    });
    let mut strip = Rect { width: area.width.saturating_sub(layout_width + 1), ..area };
    if strip.width == 0 {
        return;
    }

    // Tabs follow the arranged pane page, shifted only to keep the active tab in view.
    let page = {
        let mut panes = output.pane_layout.panes().map(|(index, _)| index);
        match panes.next() {
            Some(first) => first..panes.last().unwrap_or(first) + 1,
            None => active..active + 1,
        }
    };
    let mut capacity = usize::from(strip.width / MIN_TAB_WIDTH).max(1);
    if total > capacity {
        // Hidden tabs are counted in a cell on each side.
        let counter = total.to_string().len() as u16 + 2;
        capacity = usize::from(strip.width.saturating_sub(2 * counter) / MIN_TAB_WIDTH).max(1);
    }
    let window = tab_window(total, page, active, capacity);
    let counter_style = Style::default().fg(palette.accent).bg(palette.surface).add_modifier(Modifier::BOLD);
    if window.start > 0 {
        let label = format!("‹{}", window.start);
        let cell = Rect { width: (widgets::width(&label) as u16).min(strip.width), ..strip };
        frame.render_widget(Paragraph::new(label).style(counter_style), cell);
        output.hits.push(HitRegion { area: cell, target: HitTarget::TabOverflow(request.sessions[window.start - 1].id) });
        let used = (cell.width + 1).min(strip.width);
        strip.x += used;
        strip.width -= used;
    }
    if window.end < total {
        let label = format!("{}›", total - window.end);
        let width = (widgets::width(&label) as u16).min(strip.width);
        let cell = Rect::new(strip.right() - width, strip.y, width, 1);
        frame.render_widget(Paragraph::new(label).style(counter_style), cell);
        output.hits.push(HitRegion { area: cell, target: HitTarget::TabOverflow(request.sessions[window.end].id) });
        strip.width -= (width + 1).min(strip.width);
    }
    let count = window.len();
    let base = (strip.width / count as u16).max(1);
    let mut x = strip.x;
    for (slot, index) in window.enumerate() {
        let remaining = strip.right().saturating_sub(x);
        if remaining == 0 {
            break;
        }
        let width = if slot + 1 == count { remaining } else { base.min(remaining) };
        draw_tab(frame, Rect::new(x, strip.y, width, 1), request, index, index == active, output);
        x = x.saturating_add(width);
    }
}

/// One tab: status icon and ellipsized title, then Rename on a wide active tab and close.
/// Every hit stays inside the tab.
fn draw_tab(
    frame: &mut Frame,
    tab: Rect,
    request: &RenderRequest<'_>,
    index: usize,
    is_active: bool,
    output: &mut RenderOutput,
) {
    let palette = &request.theme.palette;
    let session = &request.sessions[index];
    let icon = session_icon(&session.view.lock().phase, is_active);
    let style = if is_active {
        Style::default()
            .fg(palette.selection_fg)
            .bg(palette.selection_bg)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(palette.muted).bg(palette.surface)
    };
    let close_width = if tab.width >= 7 { 3 } else { 0 };
    let rename_width = if is_active && tab.width >= 24 { 8 } else { 0 };
    let close = Rect::new(tab.right() - close_width, tab.y, close_width, 1);
    let rename = Rect::new(close.x - rename_width, tab.y, rename_width, 1);
    let label_area = Rect { width: tab.width - close_width - rename_width, ..tab };
    let glyph = icon.glyph(request.workspace.icon_mode);
    // A space, the icon, a space, the title, and a trailing space.
    let room = label_area.width.saturating_sub(widgets::width(glyph) as u16 + 3);
    let title = safe_text(&session.label);
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::raw(" "),
            Span::styled(glyph, Style::default().fg(icon.color(palette))),
            Span::raw(" "),
            Span::raw(widgets::fit(&title, room)),
        ]))
        .style(style),
        label_area,
    );
    if label_area.width > 0 {
        output.hits.push(HitRegion { area: label_area, target: HitTarget::Tab(session.id) });
    }
    if rename_width > 0 {
        frame.render_widget(Paragraph::new("[Rename]").style(style), rename);
        output.hits.push(HitRegion { area: rename, target: HitTarget::RenameTab(session.id) });
    }
    if close_width > 0 {
        frame.render_widget(Paragraph::new("[x]").style(style), close);
        output.hits.push(HitRegion { area: close, target: HitTarget::CloseTab(session.id) });
    }
}

fn draw_compact_sidebar(
    frame: &mut Frame,
    area: Rect,
    request: &mut RenderRequest<'_>,
    output: &mut RenderOutput,
) {
    let palette = &request.theme.palette;
    if area.width == 0 || area.height == 0 {
        return;
    }
    let block = Block::default()
        .borders(Borders::ALL)
        .style(palette.style())
        .border_style(if request.focus == Focus::Sidebar {
            Style::default().fg(palette.accent)
        } else {
            Style::default().fg(palette.border)
        });
    let inner = block.inner(area);
    frame.render_widget(block, area);
    output.hits.push(HitRegion {
        area,
        target: HitTarget::SidebarBackground,
    });

    if inner.width > 0 && inner.height > 0 {
        output.sidebar = Some(inner);
        let range = request.catalog.visible_range(usize::from(inner.height));
        let viewport = range.start;
        for (line, index) in range.enumerate() {
            let row = &request.catalog.rows()[index];
            let row_area = Rect::new(inner.x, inner.y + line as u16, inner.width, 1);
            let selected = request.catalog.selected_index() == index;
            let icon = row_icon(&row.key);
            let (marker, marker_color) = row_status(&row.key, request)
                .unwrap_or_else(|| (icon.glyph(request.workspace.icon_mode), icon.color(palette)));
            let chevron = if row.expandable {
                if row.expanded { Icon::Expanded } else { Icon::Collapsed }.glyph(request.workspace.icon_mode)
            } else {
                " "
            };
            let foreground = if selected {
                palette.selection_fg
            } else {
                palette.foreground
            };
            let mut style = palette.style();
            if selected {
                style = style.bg(palette.selection_bg).add_modifier(Modifier::BOLD);
            } else if matches!(row.key, RowKey::Section(_)) {
                style = style.add_modifier(Modifier::BOLD);
            }
            let label = Line::from(vec![
                Span::styled(marker, Style::default().fg(marker_color)),
                Span::styled(rail_label(row, request), Style::default().fg(foreground)),
                Span::styled(chevron, Style::default().fg(palette.muted)),
            ]);
            frame.render_widget(Paragraph::new(label).style(style), row_area);
            output.hits.push(HitRegion {
                area: row_area,
                target: HitTarget::Sidebar(row.key.clone()),
            });
        }
        // The scrollbar takes the right border beside the rows, so every content column stays.
        let track = Rect { width: inner.width + 1, ..inner };
        widgets::draw_scrollbar(frame, track, viewport, request.catalog.rows().len(), palette);
    }
    draw_sidebar_chrome(frame, area, output, true, false, palette);
    if let Some(elapsed) = request.unlock_reveal { paint_unlock_edge(frame, area, palette, elapsed); }
}

/// Two-cell rail label: fixed abbreviations for sections, otherwise the first characters
/// of the sanitized label that fit in two cells.
fn rail_label(row: &CatalogRow, request: &RenderRequest<'_>) -> Cow<'static, str> {
    let text = match &row.key {
        RowKey::Section(section) => {
            return Cow::Borrowed(match section {
                Section::Sessions => "Se",
                Section::Servers => "Sv",
                Section::Credentials => "Cr",
                Section::Tools => "To",
                Section::Sync => "Sy",
            });
        }
        RowKey::Sync => request.sync_label,
        _ => row.label.as_str(),
    };
    let mut label = String::with_capacity(8);
    let mut cells = 0;
    for character in safe_text(text).chars() {
        let width = widgets::width(character.encode_utf8(&mut [0; 4]));
        if cells + width > 2 {
            break;
        }
        cells += width;
        label.push(character);
    }
    for _ in cells..2 {
        label.push(' ');
    }
    Cow::Owned(label)
}

fn row_status(
    key: &RowKey,
    request: &RenderRequest<'_>,
) -> Option<(&'static str, Color)> {
    let palette = &request.theme.palette;
    match key {
        RowKey::Session(id) => {
            let Some(session) = request.sessions.iter().find(|session| session.id == *id) else {
                return Some(("?", palette.error));
            };
            let active = request
                .active_session
                .and_then(|index| request.sessions.get(index))
                .is_some_and(|active| active.id == *id);
            let view = session.view.lock();
            let icon = session_icon(&view.phase, active);
            Some((icon.glyph(request.workspace.icon_mode), icon.color(palette)))
        }
        RowKey::Host(id) => {
            let active_host = request
                .active_session
                .and_then(|index| request.sessions.get(index))
                .is_some_and(|session| session.host_id == Some(*id) && session.is_live());
            if active_host {
                Some((Icon::Active.glyph(request.workspace.icon_mode), Icon::Active.color(palette)))
            } else if request
                .sessions
                .iter()
                .any(|session| session.host_id == Some(*id) && session.is_live())
            {
                Some((Icon::Connected.glyph(request.workspace.icon_mode), Icon::Connected.color(palette)))
            } else {
                None
            }
        }
        _ => None,
    }
}

fn row_icon(key: &RowKey) -> Icon {
    match key {
        RowKey::Section(Section::Sessions) | RowKey::Session(_) => Icon::Terminal,
        RowKey::Section(Section::Servers) | RowKey::Host(_) => Icon::Server,
        RowKey::Section(Section::Credentials) | RowKey::Credential(_) => Icon::Key,
        RowKey::Section(Section::Tools) => Icon::Tools,
        RowKey::Section(Section::Sync) | RowKey::Sync => Icon::Sync,
        RowKey::Category(_) | RowKey::Ungrouped => Icon::Folder,
        RowKey::Snippet(_) | RowKey::Snippets => Icon::Snippet,
    }
}

fn draw_sidebar_chrome(
    frame: &mut Frame,
    area: Rect,
    output: &mut RenderOutput,
    collapsed: bool,
    resizable: bool,
    palette: &Palette,
) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    if resizable {
        let divider = Rect::new(area.right() - 1, area.y, 1, area.height);
        output.sidebar_divider = Some(divider);
        output.hits.push(HitRegion {
            area: divider,
            target: HitTarget::SidebarResize,
        });
        if divider.height > 2 {
            let grip = Rect::new(divider.x, divider.y + divider.height / 2, 1, 1);
            frame.render_widget(
                Span::styled("↔", Style::default().fg(palette.accent).add_modifier(Modifier::BOLD)),
                grip,
            );
        }
    }
    let interior_width = area.width.saturating_sub(2);
    let width = interior_width.min(3);
    if width == 0 {
        return;
    }
    let toggle = Rect::new(area.x + 1 + interior_width - width, area.y, width, 1);
    let label = if collapsed { "[>]" } else { "[<]" };
    frame.render_widget(
        Paragraph::new(label).style(
            Style::default()
                .fg(palette.accent)
                .bg(palette.surface),
        ),
        toggle,
    );
    output.hits.push(HitRegion {
        area: toggle,
        target: HitTarget::SidebarToggle,
    });
}

fn draw_sidebar(
    frame: &mut Frame,
    area: Rect,
    request: &mut RenderRequest<'_>,
    output: &mut RenderOutput,
    overlay: bool,
) {
    let palette = &request.theme.palette;
    let title = if overlay {
        " Workspace (overlay) "
    } else {
        " Workspace "
    };
    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .style(palette.style())
        .border_style(if request.focus == Focus::Sidebar {
            Style::default().fg(palette.accent)
        } else {
            Style::default().fg(palette.border)
        });
    let inner = block.inner(area);
    frame.render_widget(block, area);
    output.hits.push(HitRegion {
        area,
        target: HitTarget::SidebarBackground,
    });
    if inner.height == 0 || inner.width == 0 {
        draw_sidebar_chrome(frame, area, output, false, true, palette);
        if let Some(elapsed) = request.unlock_reveal { paint_unlock_edge(frame, area, palette, elapsed); }
        return;
    }
    let search_height = inner.height.min(if request.search.is_some() { 2 } else { 1 });
    let search_area = Rect::new(inner.x, inner.y, inner.width, search_height);
    output.hits.push(HitRegion { area: search_area, target: HitTarget::Search });
    let no_matches = request.catalog.no_matches();
    if let Some(search) = request.search {
        frame.render_widget(
            Paragraph::new("> ").style(Style::default().fg(palette.warning)),
            Rect::new(search_area.x, search_area.y, search_area.width.min(2), 1),
        );
        search.draw_input(frame, Rect::new(search_area.x + 2, search_area.y, search_area.width.saturating_sub(2), 1), request.menu.is_none(), palette);
        if search_height > 1 {
            let undo = request.bindings.primary(Shortcut::SearchCancel);
            let hint = if no_matches {
                format!("No matches · {undo} undo")
            } else {
                format!("{} keep · {undo} undo", request.bindings.primary(Shortcut::SearchKeep))
            };
            frame.render_widget(
                Paragraph::new(widgets::fit(&hint, search_area.width)).style(Style::default().fg(palette.warning)),
                Rect::new(search_area.x, search_area.y + 1, search_area.width, 1),
            );
        }
    } else {
        // The single Search control; a kept filter stays visible here, with a Clear control
        // that works even when the Clear filter key yielded to a custom binding.
        let key = request.bindings.primary(Shortcut::SidebarSearch);
        let filter = request.catalog.filter();
        let mut label_area = search_area;
        let label = if filter.is_empty() {
            if key.is_empty() { "[Search]".to_owned() } else { format!("[{key} Search]") }
        } else {
            let captions = widgets::keyed_captions(
                &[("Clear", request.bindings.primary(Shortcut::SidebarClearFilter))],
                search_area.width / 2,
                1,
            );
            let clear_width = (widgets::width(&captions[0]) as u16 + 2).min(search_area.width / 2);
            let clear = Rect::new(search_area.right() - clear_width, search_area.y, clear_width, 1);
            widgets::draw_buttons(frame, clear, &[Button::secondary(&captions[0])], None, palette, |_, area| {
                output.hits.push(HitRegion { area, target: HitTarget::ClearFilter });
            });
            label_area.width = search_area.width.saturating_sub(clear_width + 1);
            let mut label = if key.is_empty() {
                format!("[Search] {}", safe_text(filter))
            } else {
                format!("[{key}] {}", safe_text(filter))
            };
            if no_matches {
                label.push_str(" · No matches");
            }
            label
        };
        let color = if no_matches { palette.warning } else { palette.accent };
        frame.render_widget(Paragraph::new(widgets::fit(&label, label_area.width)).style(Style::default().fg(color)), label_area);
    }
    let inner = Rect::new(inner.x, inner.y + search_height, inner.width, inner.height.saturating_sub(search_height));
    // Up to three rows of wrapping action buttons; the list keeps at least two rows.
    let actions = request.catalog.selected().map_or_else(Vec::new, |row| {
        sidebar_buttons(row, request.state.sync.is_some(), request.uncertain, !request.catalog.filter().is_empty())
    });
    let labels: Vec<_> = actions.iter().map(|button| (button.caption, request.bindings.primary(button.shortcut))).collect();
    let max_rows = inner.height.saturating_sub(3).min(3);
    let captions = widgets::keyed_captions(&labels, inner.width, max_rows);
    let buttons: Vec<_> = captions.iter().zip(&actions).map(|(caption, button)| Button::new(caption, button.kind)).collect();
    let button_rows = widgets::button_rows(inner.width, &buttons).min(max_rows);
    let controls_height = if button_rows == 0 { 0 } else { button_rows + 1 };
    let list = Rect { height: inner.height - controls_height, ..inner };
    let controls = Rect::new(inner.x, list.bottom(), inner.width, controls_height);
    let total = request.catalog.rows().len();
    // Rows give their last column to the scrollbar only while the list overflows.
    let overflow = total > usize::from(list.height);
    let rows_area = Rect { width: list.width.saturating_sub(u16::from(overflow)), ..list };
    output.sidebar = Some(rows_area);
    let range = request.catalog.visible_range(usize::from(list.height));
    let viewport = range.start;
    for (line, index) in range.enumerate() {
        let row = &request.catalog.rows()[index];
        let row_area = Rect::new(rows_area.x, rows_area.y + line as u16, rows_area.width, 1);
        let selected = request.catalog.selected_index() == index;
        let section = matches!(row.key, RowKey::Section(_));
        let mode = request.workspace.icon_mode;
        let (disclosure, disclosure_color) = if row.expandable {
            let icon = if row.expanded { Icon::Expanded } else { Icon::Collapsed };
            (icon.glyph(mode), icon.color(palette))
        } else {
            row_status(&row.key, request).unwrap_or((" ", palette.muted))
        };
        let indent = usize::from(row.indent) * 2;
        let marker = if selected { ">" } else { " " };
        let icon = row_icon(&row.key);
        let text = if matches!(row.key, RowKey::Sync) { request.sync_label } else { &row.label };
        // One marker cell, two per depth, then disclosure, a gap, icon, and a text gap.
        let used = 1 + indent + widgets::width(disclosure) + 1 + widgets::width(icon.glyph(mode)) + 1;
        let text = widgets::fit(text, row_area.width.saturating_sub(u16::try_from(used).unwrap_or(u16::MAX)));
        let label = Line::from(vec![
            Span::raw(format!("{marker}{:indent$}", "")),
            Span::styled(disclosure, Style::default().fg(disclosure_color)),
            Span::raw(" "),
            Span::styled(icon.glyph(mode), Style::default().fg(icon.color(palette))),
            Span::raw(" "),
            Span::raw(text),
        ]);
        let mut style = palette.style();
        if selected {
            style = style.fg(palette.selection_fg).bg(palette.selection_bg);
        }
        if section || selected {
            style = style.add_modifier(Modifier::BOLD);
        }
        frame.render_widget(Paragraph::new(label).style(style), row_area);
        output.hits.push(HitRegion {
            area: row_area,
            target: HitTarget::Sidebar(row.key.clone()),
        });
    }
    if overflow {
        widgets::draw_scrollbar(frame, list, viewport, total, palette);
    }
    draw_sidebar_actions(frame, controls, &buttons, &actions, request, output);
    draw_sidebar_chrome(frame, area, output, false, true, palette);
    if let Some(elapsed) = request.unlock_reveal { paint_unlock_edge(frame, area, palette, elapsed); }
}

/// One contextual sidebar action: caption, emphasis, the action it dispatches, and the
/// shortcut shown as its key.
#[derive(Clone, Copy)]
struct SidebarButton {
    caption: &'static str,
    kind: ButtonKind,
    action: SidebarAction,
    shortcut: Shortcut,
}

impl SidebarButton {
    const fn new(caption: &'static str, kind: ButtonKind, action: SidebarAction, shortcut: Shortcut) -> Self {
        Self { caption, kind, action, shortcut }
    }
}

/// Actions for the selected row. Search stays the single control above the list; while a
/// filter forces groups open, expanding or collapsing them would change nothing visible, and
/// while save durability is uncertain Retry save replaces every action that writes.
fn sidebar_buttons(row: &CatalogRow, sync_configured: bool, uncertain: bool, filtering: bool) -> Vec<SidebarButton> {
    use ButtonKind::{Danger, Primary, Secondary};
    let edit = SidebarButton::new("Edit", Secondary, SidebarAction::Edit, Shortcut::SidebarEdit);
    let delete = SidebarButton::new("Delete", Danger, SidebarAction::Delete, Shortcut::SidebarDelete);
    let info = SidebarButton::new("Info", Secondary, SidebarAction::Inspect, Shortcut::SidebarInspect);
    let add = SidebarButton::new("Add", Secondary, SidebarAction::Add, Shortcut::SidebarAdd);
    let activate = |caption| SidebarButton::new(caption, Primary, SidebarAction::Activate, Shortcut::SidebarActivate);
    let sync = || if sync_configured {
        vec![
            SidebarButton::new("Configure", Secondary, SidebarAction::Edit, Shortcut::SidebarEdit),
            SidebarButton::new("Sync now", Primary, SidebarAction::Sync, Shortcut::SidebarSync),
            SidebarButton::new("Disable", Danger, SidebarAction::Delete, Shortcut::SidebarDelete),
        ]
    } else {
        vec![SidebarButton::new("Setup", Primary, SidebarAction::Edit, Shortcut::SidebarEdit)]
    };
    let mut buttons = match &row.key {
        RowKey::Host(_) => vec![activate("Connect"), edit, delete, info],
        RowKey::Session(_) => vec![
            activate("Open"),
            SidebarButton::new("Rename", Secondary, SidebarAction::Edit, Shortcut::SidebarEdit),
            SidebarButton::new("Close", Danger, SidebarAction::CloseSession, Shortcut::SidebarCloseSession),
            info,
        ],
        RowKey::Snippet(_) => vec![activate("Insert"), edit, delete, info],
        RowKey::Credential(_) => vec![edit, delete, info],
        RowKey::Category(_) => vec![add, edit, delete, info],
        RowKey::Section(Section::Sessions) => vec![info],
        RowKey::Section(Section::Servers | Section::Credentials | Section::Tools)
        | RowKey::Ungrouped
        | RowKey::Snippets => vec![add, info],
        RowKey::Section(Section::Sync) | RowKey::Sync => sync(),
    };
    if row.expandable && !filtering {
        let toggle = if row.expanded {
            SidebarButton::new("Collapse", Secondary, SidebarAction::Collapse, Shortcut::SidebarCollapse)
        } else {
            SidebarButton::new("Expand", Secondary, SidebarAction::Expand, Shortcut::SidebarExpand)
        };
        buttons.insert(0, toggle);
    }
    if uncertain {
        buttons.retain(|button| !button.action.changes_saved_state(&row.key));
        buttons.push(SidebarButton::new("Retry save", Primary, SidebarAction::RetrySave, Shortcut::RetrySave));
    }
    buttons
}

fn draw_sidebar_actions(
    frame: &mut Frame,
    area: Rect,
    buttons: &[Button<'_>],
    actions: &[SidebarButton],
    request: &RenderRequest<'_>,
    output: &mut RenderOutput,
) {
    if area.height == 0 {
        return;
    }
    let palette = &request.theme.palette;
    let block = Block::default()
        .title(" Actions ")
        .borders(Borders::TOP)
        .style(palette.style())
        .border_style(Style::default().fg(palette.border));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let Some(key) = request.catalog.selected_key() else {
        return;
    };
    widgets::draw_buttons(frame, inner, buttons, None, palette, |index, area| {
        output.hits.push(HitRegion {
            area,
            target: HitTarget::SidebarAction { key: key.clone(), action: actions[index].action },
        });
    });
}

fn draw_details(frame: &mut Frame, area: Rect, request: &RenderRequest<'_>, output: &mut RenderOutput) {
    let palette = &request.theme.palette;
    let block = Block::default()
        .title(" Details ")
        .borders(Borders::ALL)
        .style(palette.style())
        .border_style(Style::default().fg(palette.border));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let vault = &request.state.vault;
    let bindings = request.bindings;
    // Empty workspaces get a direct Add server control below the text.
    let mut add_server = false;
    let lines = match request.catalog.selected_key() {
        Some(RowKey::Host(id)) => {
            let mut lines = host_details(vault, id, palette);
            lines.push(Line::from(""));
            lines.push(Line::from(format!("{}: connect   {}: preview   {}: edit   {}: delete",
                bindings.primary(Shortcut::SidebarActivate), bindings.primary(Shortcut::SidebarInspect),
                bindings.primary(Shortcut::SidebarEdit), bindings.primary(Shortcut::SidebarDelete))));
            if vault.hosts.iter().any(|host| host.id == id && !matches!(host.auth, crate::vault::HostAuth::Tailscale { .. })) {
                lines.push(Line::from(format!("{}: forget key", bindings.primary(Shortcut::SidebarForgetHostKey))));
            }
            lines
        }
        Some(RowKey::Category(id)) => vault.categories.iter().find(|entry| entry.id == id).map_or_else(
            || vec![Line::from("The selected category no longer exists.")],
            |category| {
                let children = vault.categories.iter().filter(|entry| entry.parent_id == Some(id)).count();
                let hosts = vault.hosts.iter().filter(|entry| entry.category_id == Some(id)).count();
                vec![
                    heading(&category.label, palette),
                    Line::from(format!("Path: {}", category_path(vault, id))),
                    Line::from(format!("{children} child categories · {hosts} direct servers")),
                    Line::from(""),
                    Line::from("Deleting reparents immediate children and servers; it never deletes servers."),
                    Line::from(format!("{}: add child/server   {}: edit/reparent   {}: delete",
                        bindings.primary(Shortcut::SidebarAdd), bindings.primary(Shortcut::SidebarEdit),
                        bindings.primary(Shortcut::SidebarDelete))),
                ]
            },
        ),
        Some(RowKey::Credential(id)) => vault.credentials.iter().find(|entry| entry.id == id).map_or_else(
            || vec![Line::from("The selected credential no longer exists.")],
            |credential| {
                let note = match &credential.auth {
                    Auth::Password { .. } => "Encrypted in the local vault",
                    Auth::PrivateKey { passphrase, .. } => {
                        if passphrase.is_some() { "Key contents and passphrase are encrypted in the vault" } else { "Key contents are stored; passphrase is requested when connecting" }
                    }
                    Auth::Agent => "Local agent required on this device",
                    Auth::KeyboardInteractive => "Challenge answers are never saved",
                };
                let referenced: Vec<_> = vault.hosts.iter().filter(|host| host.auth.credential_id() == Some(id)).map(|host| host.label.as_str()).collect();
                vec![
                    heading(&credential.label, palette),
                    Line::from(format!("Username: {}", credential.username)),
                    Line::from(format!("Authentication: {}", auth_label(&credential.auth))),
                    Line::from(note),
                    Line::from(format!("Used by: {}", if referenced.is_empty() { "no servers".to_owned() } else { referenced.join(", ") })),
                    Line::from(""),
                    Line::from(format!("{}: edit   {}: delete (refused while referenced)",
                        bindings.primary(Shortcut::SidebarEdit), bindings.primary(Shortcut::SidebarDelete))),
                ]
            },
        ),
        Some(RowKey::Snippet(id)) => vault.snippets.iter().find(|entry| entry.id == id).map_or_else(
            || vec![Line::from("The selected snippet no longer exists.")],
            |snippet| vec![
                heading(&snippet.label, palette),
                Line::from("Exact command:"),
                Line::from(Span::styled(snippet.command.as_str(), Style::default().fg(palette.warning))),
                Line::from(""),
                Line::from(format!("{}: preview target and insert without Enter   {}: edit   {}: delete",
                    bindings.primary(Shortcut::SidebarActivate), bindings.primary(Shortcut::SidebarEdit),
                    bindings.primary(Shortcut::SidebarDelete))),
            ],
        ),
        Some(RowKey::Sync) | Some(RowKey::Section(Section::Sync)) => {
            let setting = request.state.sync.as_ref();
            let actions = if setting.is_some() {
                format!("{}/{}: configure   {}: synchronize now   {}: disable",
                    bindings.primary(Shortcut::SidebarActivate), bindings.primary(Shortcut::SidebarEdit),
                    bindings.primary(Shortcut::SidebarSync), bindings.primary(Shortcut::SidebarDelete))
            } else {
                format!("{}/{}: set up synchronization",
                    bindings.primary(Shortcut::SidebarActivate), bindings.primary(Shortcut::SidebarEdit))
            };
            vec![
                heading("Synchronization", palette),
                Line::from(format!("Status: {}", request.sync_label)),
                Line::from(safe_text(request.sync_detail)),
                Line::from(format!("Server: {}", setting.map(|sync| sync.url.as_str()).unwrap_or("not configured"))),
                Line::from(format!("Access token: {}", if setting.is_some() { "•••••••• (masked)" } else { "not configured" })),
                Line::from(""),
                Line::from(actions),
                Line::from("Network errors never disable local edits or live SSH sessions."),
            ]
        }
        Some(RowKey::Session(id)) => request.sessions.iter().find(|session| session.id == id).map_or_else(
            || vec![Line::from("The selected session has ended.")],
            |session| {
                let view = session.view.lock();
                vec![
                    heading(&session.label, palette),
                    Line::from(format!("State: {}", safe_text(&view.phase.label()))),
                    Line::from(format!("{}: activate tab   {}: close/dismiss",
                        bindings.primary(Shortcut::SidebarActivate), bindings.sequence(Shortcut::PrefixCloseSession))),
                    Line::from(format!("{}: rename   or right-click the tab or sidebar session",
                        bindings.primary(Shortcut::SidebarEdit))),
                ]
            },
        ),
        Some(RowKey::Ungrouped) => vec![
            heading("Ungrouped servers", palette),
            Line::from("Servers without a category appear here."),
            Line::from(format!("{}: add a server or root category", bindings.primary(Shortcut::SidebarAdd))),
        ],
        Some(RowKey::Snippets) | Some(RowKey::Section(Section::Tools)) => vec![
            heading("Snippets", palette),
            Line::from("Reusable single-line commands are inserted into a live session without Enter."),
            Line::from(format!("{}: add snippet", bindings.primary(Shortcut::SidebarAdd))),
        ],
        Some(RowKey::Section(Section::Servers)) => {
            let mut lines = vec![heading("Servers", palette)];
            if vault.hosts.is_empty() {
                lines.push(Line::from("No saved servers yet. Add one with its own password or a reusable credential."));
                add_server = true;
            } else {
                lines.push(Line::from(format!("{} saved servers · {} categories", vault.hosts.len(), vault.categories.len())));
                lines.push(Line::from(format!("Select a server and choose Connect ({}).", bindings.primary(Shortcut::SidebarActivate))));
            }
            lines.push(Line::from(format!("{}: add a server or category", bindings.primary(Shortcut::SidebarAdd))));
            lines
        }
        Some(RowKey::Section(Section::Credentials)) => vec![heading("Credentials", palette), Line::from(format!("{}: add a reusable credential", bindings.primary(Shortcut::SidebarAdd)))],
        Some(RowKey::Section(Section::Sessions)) => {
            let mut lines = vec![heading("Sessions", palette)];
            if vault.hosts.is_empty() {
                lines.push(Line::from("No saved servers yet. Add a server, then connect to it to open an embedded SSH terminal."));
                add_server = true;
            } else if request.sessions.is_empty() {
                lines.push(Line::from(format!(
                    "No open sessions. Select one of {} saved servers under Servers and choose Connect ({}).",
                    vault.hosts.len(),
                    bindings.primary(Shortcut::SidebarActivate),
                )));
            } else {
                lines.push(Line::from(format!(
                    "{} open sessions. Select one and choose Open ({}).",
                    request.sessions.len(),
                    bindings.primary(Shortcut::SidebarActivate),
                )));
            }
            lines
        }
        None => Vec::new(),
    };
    let paragraph = Paragraph::new(lines)
        .style(palette.style())
        .wrap(Wrap { trim: false });
    let text_rows = paragraph.line_count(inner.width).min(usize::from(u16::MAX)) as u16;
    frame.render_widget(paragraph, inner);
    let servers = RowKey::Section(Section::Servers);
    if add_server && !request.uncertain && request.catalog.rows().iter().any(|row| row.key == servers) {
        let row = inner.y.saturating_add(text_rows).saturating_add(1);
        if row < inner.bottom() {
            let captions = widgets::keyed_captions(&[("Add server", bindings.primary(Shortcut::SidebarAdd))], inner.width, 1);
            widgets::draw_buttons(frame, Rect::new(inner.x, row, inner.width, 1), &[Button::primary(&captions[0])], None, palette, |_, area| {
                output.hits.push(HitRegion {
                    area,
                    target: HitTarget::SidebarAction { key: servers.clone(), action: SidebarAction::Add },
                });
            });
        }
    }
}

fn heading<'a>(text: &'a str, palette: &Palette) -> Line<'a> {
    Line::from(Span::styled(
        safe_text(text),
        Style::default()
            .fg(palette.accent)
            .add_modifier(Modifier::BOLD),
    ))
}

fn draw_footer(
    frame: &mut Frame,
    area: Rect,
    request: &RenderRequest<'_>,
    output: &mut RenderOutput,
) {
    let palette = &request.theme.palette;
    if area.width == 0 || area.height == 0 {
        return;
    }
    let bounds = frame.area();
    let bindings = request.bindings;
    let context = &request.commands;
    let buttons = [
        (bindings.primary(Shortcut::Prefix), "Commands", HitTarget::PrefixToggle),
        (bindings.primary(Shortcut::PrefixSettings), Icon::Settings.glyph(request.workspace.icon_mode), HitTarget::PrefixCommand(PrefixAction::Settings)),
        (bindings.primary(Shortcut::PrefixShortcuts), Icon::Shortcuts.glyph(request.workspace.icon_mode), HitTarget::PrefixCommand(PrefixAction::Shortcuts)),
    ].map(|(key, label, target)| (key, Span::raw(key).width(), label, target));
    let widths = buttons.each_ref().map(|(_, key_width, label, _)| {
        let label_width = if label.is_empty() { 0 } else { Span::raw(*label).width() + 1 };
        (key_width + label_width + 2).min(usize::from(bounds.width)) as u16
    });
    let (mut cells, rows) = wrap_bar_buttons(bounds.width, widths, 1);
    let footer = Rect::new(
        bounds.x, bounds.bottom() - rows.min(bounds.height), bounds.width, rows.min(bounds.height),
    );
    let mut row_widths = [0; 3];
    for cell in &cells {
        row_widths[usize::from(cell.y)] = cell.right();
    }
    let status_width = bounds.width - row_widths[0];
    for cell in &mut cells {
        cell.x += bounds.x + bounds.width - row_widths[usize::from(cell.y)];
        cell.y += footer.y;
    }
    theming::clear(frame, footer, palette);
    output.hits.push(HitRegion { area: footer, target: HitTarget::PrefixPanel });
    let background = Style::default().fg(palette.foreground).bg(palette.surface);

    if request.prefix && bounds.width >= 8 && footer.y > bounds.y {
        // Give status and paging their own row when the pinned controls leave too little room.
        let status_row = if status_width < 32 && footer.y > bounds.y + 1 {
            Rect::new(bounds.x, footer.y - 1, bounds.width, 1)
        } else {
            Rect::new(bounds.x, footer.y, status_width, 1)
        };
        let bottom = status_row.y.min(footer.y);
        let available_rows = usize::from(bottom - bounds.y);
        let commands: [_; PREFIX_COMMANDS.len()] = std::array::from_fn(|index| {
            let (shortcut, action) = PREFIX_COMMANDS[index];
            let key = bindings.primary(shortcut);
            let key_width = Span::raw(key).width();
            let full_label = command_label(action, request.workspace.terminal_layout, false);
            let label = if key_width + full_label.len() + 3 <= usize::from(bounds.width) {
                full_label
            } else {
                command_label(action, request.workspace.terminal_layout, true)
            };
            (action, key, key_width, label)
        });
        let widths = commands.each_ref().map(|(action, _, key_width, label)| {
            // Pinned footer commands, and AI commands before Vyx AI is installed, take no bar cell.
            if matches!(action, PrefixAction::Settings | PrefixAction::Shortcuts)
                || (matches!(action, PrefixAction::AiChat | PrefixAction::AiFocus) && request.ai.is_none())
            {
                0
            } else {
                (key_width + label.len() + 3).min(usize::from(bounds.width)) as u16
            }
        });
        let (command_cells, rows) = wrap_bar_buttons(bounds.width, widths, 0);
        let pages = usize::from(rows).div_ceil(available_rows);
        let page = request.prefix_page.min(pages - 1);
        let first_row = page * available_rows;
        let visible_rows = (usize::from(rows) - first_row).min(available_rows) as u16;
        let top = bottom - visible_rows;
        let bar = Rect::new(bounds.x, top, bounds.width, bounds.bottom() - top);
        output.prefix_pages = pages;
        theming::clear(frame, bar, palette);
        frame.render_widget(Block::default().style(background), bar);
        output.hits.push(HitRegion { area: bar, target: HitTarget::PrefixPanel });
        let editing = request.menu.is_some() || request.dialog.is_some() || request.search.is_some() || request.extension_surface.is_some();
        for ((action, key, key_width, label), mut cell) in commands.into_iter().zip(command_cells) {
            if cell.width == 0 || !(first_row..first_row + usize::from(visible_rows)).contains(&usize::from(cell.y)) {
                continue;
            }
            cell.x += bounds.x;
            cell.y = top + (usize::from(cell.y) - first_row) as u16;
            let enabled = action.applicable(context);
            draw_bar_command(frame, cell, key, key_width, label, enabled, palette);
            output.hits.push(HitRegion { area: cell, target: HitTarget::PrefixCommand(action) });
        }

        let (status, status_color) = footer_status(request, editing);
        let show_pages = pages > 1 && status_row.width >= 6;
        let status_width = if show_pages { status_row.width - 6 } else { status_row.width };
        let text = if pages > 1 {
            let page_keys_available = [Shortcut::MenuPageUp, Shortcut::MenuPageDown].into_iter()
                .all(|shortcut| bindings.primary_event(shortcut).is_some_and(|event| prefix_action(event, bindings) == PrefixAction::Consume));
            if page_keys_available {
                format!("{}/{} {}/{} · {status}", page + 1, pages,
                    bindings.primary(Shortcut::MenuPageUp), bindings.primary(Shortcut::MenuPageDown))
            } else {
                format!("{}/{} · {status}", page + 1, pages)
            }
        } else {
            status.into_owned()
        };
        frame.render_widget(
            Paragraph::new(widgets::fit(&text, status_width)).style(
                Style::default()
                    .fg(status_color)
                    .bg(palette.surface),
            ),
            Rect { width: status_width, ..status_row },
        );
        if show_pages {
            for (index, (label, delta)) in [("[<]", -1), ("[>]", 1)].into_iter().enumerate() {
                let button = Rect::new(status_row.x + status_width + index as u16 * 3, status_row.y, 3, 1);
                frame.render_widget(Span::styled(label, Style::default().fg(palette.accent)), button);
                output.hits.push(HitRegion { area: button, target: HitTarget::PrefixPage(delta) });
            }
        }
    }
    if !request.prefix {
        let (status, color) = footer_status(request, false);
        frame.render_widget(
            Paragraph::new(widgets::fit(&status, status_width)).style(background.fg(color)),
            Rect::new(bounds.x, footer.y, status_width, 1),
        );
    }

    let accent = if request.uncertain { palette.warning } else { palette.accent };
    for ((key, key_width, label, target), cell) in buttons.into_iter().zip(cells) {
        if cell.y >= bounds.bottom() {
            continue;
        }
        frame.render_widget(Block::default().style(background), cell);
        if matches!(target, HitTarget::PrefixToggle) {
            let style = if request.prefix {
                Style::default()
                    .fg(if request.uncertain { palette.background } else { palette.selection_fg })
                    .bg(if request.uncertain { palette.warning } else { palette.selection_bg })
            } else {
                background.fg(accent)
            }.add_modifier(Modifier::BOLD);
            let text = if key.is_empty() { Cow::Borrowed(label) } else { Cow::Owned(format!("{key} {label}")) };
            frame.render_widget(
                Paragraph::new(widgets::fit(&text, cell.width)).alignment(Alignment::Center).style(style), cell,
            );
        } else {
            let enabled = match target {
                HitTarget::PrefixCommand(action) => action.applicable(context),
                _ => true,
            };
            draw_bar_command(frame, cell, key, key_width, label, enabled, palette);
        }
        output.hits.push(HitRegion { area: cell, target });
    }
}

/// Footer status by priority: unresolved durability or recovery guidance, the current notice,
/// then (in the command bar) the overlay hint, an available update, and finally sync state.
fn footer_status<'r>(request: &'r RenderRequest<'_>, editing: bool) -> (Cow<'r, str>, Color) {
    let palette = &request.theme.palette;
    if request.uncertain {
        let key = request.bindings.primary(Shortcut::RetrySave);
        return (Cow::Owned(format!("Save durability uncertain; {key} retries save")), palette.warning);
    }
    if let Some(guidance) = request.guidance {
        return (Cow::Borrowed(guidance), palette.warning);
    }
    if let Some(notice) = request.notice {
        return (Cow::Borrowed(notice.text.as_str()), notice.kind.color(palette));
    }
    if editing {
        return (Cow::Borrowed("Close menus/forms for dimmed commands"), palette.muted);
    }
    if let Some(update) = request.update_notice {
        return (Cow::Borrowed(update.trim()), palette.info);
    }
    (Cow::Owned(format!("Sync: {}", request.sync_label)), palette.muted)
}

fn wrap_bar_buttons<const N: usize>(width: u16, widths: [u16; N], gap: u16) -> ([Rect; N], u16) {
    let mut cells = [Rect::default(); N];
    let mut column = 0usize;
    let mut row = 0;
    let mut height = 0;
    for (cell, button_width) in cells.iter_mut().zip(widths) {
        let button_width = button_width.min(width);
        if button_width == 0 {
            continue;
        }
        if column > 0 && column + usize::from(button_width) > usize::from(width) {
            column = 0;
            row += 1;
        }
        *cell = Rect::new(column as u16, row, button_width, 1);
        column += usize::from(button_width) + usize::from(gap);
        height = row + 1;
    }
    (cells, height)
}

fn draw_bar_command(
    frame: &mut Frame,
    cell: Rect,
    key: &str,
    key_width: usize,
    label: &str,
    enabled: bool,
    palette: &Palette,
) {
    let inner_width = cell.width.saturating_sub(2);
    let label_width = Span::raw(label).width().min(usize::from(inner_width)) as u16;
    let key_width = key_width.min(usize::from(inner_width.saturating_sub(label_width + 1))) as u16;
    if key_width > 0 {
        frame.render_widget(
            Span::styled(key, Style::default().fg(if enabled { palette.warning } else { palette.muted })),
            Rect::new(cell.x + 1, cell.y, key_width, 1),
        );
    }
    if label_width > 0 {
        frame.render_widget(
            Span::styled(label, Style::default().fg(if enabled { palette.foreground } else { palette.muted })),
            Rect::new(cell.x + 1 + key_width + u16::from(key_width > 0), cell.y, label_width, 1),
        );
    }
}

fn command_label(action: PrefixAction, layout: TerminalLayout, compact: bool) -> &'static str {
    match action {
        PrefixAction::ToggleSidebar => "Sidebar",
        PrefixAction::CycleLayout => match (layout, compact) {
            (TerminalLayout::Single, false) => "Layout: Single",
            (TerminalLayout::Single, true) => "Layout: One",
            (TerminalLayout::SideBySide, false) => "Layout: Side by side",
            (TerminalLayout::SideBySide, true) => "Layout: Cols",
            (TerminalLayout::Stacked, false) => "Layout: Stacked",
            (TerminalLayout::Stacked, true) => "Layout: Rows",
            (TerminalLayout::Grid, _) => "Layout: Grid",
        },
        PrefixAction::NextSession => "Next session",
        PrefixAction::PreviousSession => "Prev session",
        PrefixAction::CloseSession => "Close session",
        PrefixAction::Sync => "Sync",
        PrefixAction::Detach => "Detach",
        PrefixAction::Quit => "Quit",
        PrefixAction::Shortcuts => "Shortcuts",
        PrefixAction::Settings => "Settings",
        PrefixAction::Extensions => "Extensions",
        PrefixAction::AiChat => "AI chat",
        PrefixAction::AiFocus => "AI focus",
        PrefixAction::LiteralPrefix => "Send prefix",
        PrefixAction::Cancel | PrefixAction::Consume => "Cancel",
    }
}

/// Terminal rectangle beside the AI panel, and the panel rectangle with whether it
/// covers the workspace. Terminals are sized the same whether or not the panel is
/// focused, so focus changes never resize SSH sessions.
fn ai_layout(
    main: Rect,
    workspace: Rect,
    narrow: bool,
    ai: Option<&AiRender<'_>>,
    dragged: Option<u16>,
) -> (Rect, Option<(Rect, bool)>) {
    let Some(ai) = ai.filter(|ai| ai.panel.is_open()) else {
        return (main, None);
    };
    let focused = ai.view.focused;
    if narrow || main.width < crate::ui::ai::MIN_WIDTH + MIN_TERMINAL_COLUMNS {
        // Too narrow to share: the panel covers the workspace only while it owns the
        // keyboard, so an unfocused panel never hides the terminal receiving input.
        return (main, focused.then_some((if narrow { workspace } else { main }, true)));
    }
    let width = ai_width(main.width, dragged.unwrap_or(ai.view.data.config.panel_width));
    let terminals = Rect { width: main.width - width, ..main };
    if focused && ai.panel.expanded() {
        return (terminals, Some((main, true)));
    }
    (terminals, Some((Rect::new(terminals.right(), main.y, width, main.height), false)))
}

pub fn contains(area: Rect, column: u16, row: u16) -> bool {
    column >= area.x && column < area.right() && row >= area.y && row < area.bottom()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{Terminal, backend::TestBackend};

    use crate::{settings::IconMode, theme::default_theme, vault::Vault};

    fn render_catalog(
        catalog: &mut Catalog,
        width: u16,
        height: u16,
        collapsed: bool,
        mode: IconMode,
    ) -> (Terminal<TestBackend>, RenderOutput) {
        let state = LocalState::new(Vault::new(), None);
        let bindings = Bindings::default();
        let terminal_sizes = TerminalSizes::default();
        let workspace = WorkspaceSettings {
            sidebar_collapsed: collapsed,
            icon_mode: mode,
            ..WorkspaceSettings::default()
        };
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        let mut output = RenderOutput::default();
        terminal.draw(|frame| {
            draw(frame, RenderRequest {
                catalog,
                state: &state,
                sessions: &[],
                active_session: None,
                focus: Focus::Sidebar,
                prefix: false,
                prefix_page: 0,
                commands: PrefixContext::default(),
                workspace,
                terminal_sizes: &terminal_sizes,
                pane_resize: None,
                sidebar_width: workspace.sidebar_width,
                sidebar_overlay: !collapsed,
                sync_label: "Disabled",
                sync_detail: "",
                notice: None,
                guidance: None,
                update_notice: None,
                uncertain: false,
                dialog: None,
                search: None,
                bindings: &bindings,
                theme: default_theme(),
                menu: None,
                extension_surface: None,
                unlock_reveal: None,
                ai: None,
                ai_width: None,
            }, &mut output);
        }).unwrap();
        (terminal, output)
    }

    #[test]
    fn sidebar_hits_follow_catalog_rows_across_resize_and_selection() {
        let mut catalog = Catalog::default();
        catalog.rebuild(&Vault::new(), std::iter::empty());
        let first = catalog.rows().first().unwrap().key.clone();
        let last = catalog.rows().last().unwrap().key.clone();
        for collapsed in [false, true] {
            for width in [40, 100] {
                for selected in [&last, &first] {
                    assert!(catalog.select(selected));
                    for height in [10, 16, 30, 10] {
                        let (_, output) = render_catalog(
                            &mut catalog, width, height, collapsed, IconMode::Plain,
                        );
                        let sidebar = output.sidebar.unwrap();
                        let hits: Vec<_> = output.hits.iter().filter_map(|hit| {
                            match &hit.target {
                                HitTarget::Sidebar(key) => Some((hit.area, key)),
                                _ => None,
                            }
                        }).collect();
                        let first_index = catalog.rows().iter()
                            .position(|row| &row.key == hits[0].1).unwrap();
                        let visible = &catalog.rows()[first_index..];
                        assert_eq!(hits.len(), visible.len().min(usize::from(sidebar.height)));
                        assert!(hits.iter().any(|(_, key)| *key == selected));
                        for (line, ((area, key), row)) in hits.iter().zip(visible).enumerate() {
                            assert_eq!(*area, Rect::new(
                                sidebar.x, sidebar.y + line as u16, sidebar.width, 1,
                            ));
                            assert_eq!(*key, &row.key);
                            assert!(area.bottom() <= sidebar.bottom());
                        }
                        if !collapsed {
                            let search = output.hits.iter()
                                .find(|hit| matches!(hit.target, HitTarget::Search)).unwrap();
                            assert_eq!(sidebar.y, search.area.bottom());
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn sidebar_selection_keeps_icon_color_and_full_row_highlight() {
        let palette = &default_theme().palette;
        let mut catalog = Catalog::default();
        catalog.rebuild(&Vault::new(), std::iter::empty());
        for mode in [IconMode::Plain, IconMode::NerdFont] {
            for collapsed in [false, true] {
                for selected in [
                    RowKey::Section(Section::Servers),
                    RowKey::Ungrouped,
                    RowKey::Sync,
                ] {
                    assert!(catalog.select(&selected));
                    let (terminal, output) = render_catalog(&mut catalog, 100, 30, collapsed, mode);
                    let buffer = terminal.backend().buffer();
                    for hit in &output.hits {
                        let HitTarget::Sidebar(key) = &hit.target else { continue };
                        let row = catalog.rows().iter().find(|row| &row.key == key).unwrap();
                        let is_selected = key == &selected;
                        let icon_x = (hit.area.x..hit.area.right())
                            .find(|&x| buffer[(x, hit.area.y)].symbol() == row_icon(key).glyph(mode))
                            .unwrap();
                        if !collapsed {
                            let disclosure_x = hit.area.x + 1 + row.indent * 2;
                            assert!(icon_x >= disclosure_x + 2, "disclosure must not touch the icon");
                            assert!((disclosure_x + 1..icon_x)
                                .all(|x| buffer[(x, hit.area.y)].symbol() == " "));
                        }
                        let icon_cell = &buffer[(icon_x, hit.area.y)];
                        assert_eq!(icon_cell.fg, row_icon(key).color(palette));
                        let label_x = if collapsed { hit.area.x + 1 } else { icon_x + 2 };
                        assert_eq!(buffer[(label_x, hit.area.y)].fg,
                            if is_selected { palette.selection_fg } else { palette.foreground });
                        if is_selected {
                            for x in hit.area.x..hit.area.right() {
                                assert_eq!(buffer[(x, hit.area.y)].bg, palette.selection_bg);
                            }
                            if !collapsed {
                                assert_eq!(buffer[(hit.area.x, hit.area.y)].symbol(), ">");
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn tab_window_follows_the_pane_page_and_always_shows_the_active_tab() {
        for total in 1..=9 {
            for page_size in 1..=4 {
                for capacity in 1..=10 {
                    for active in 0..total {
                        let start = active / page_size * page_size;
                        let page = start..(start + page_size).min(total);
                        let window = tab_window(total, page.clone(), active, capacity);
                        assert!(window.contains(&active));
                        assert_eq!(window.len(), capacity.min(total));
                        assert!(window.end <= total);
                        if capacity >= page.len() {
                            assert!(window.start <= page.start && page.end <= window.end, "the whole page stays visible");
                        } else {
                            assert!(page.start <= window.start && window.end <= page.end, "tabs shift only within the page");
                        }
                    }
                }
            }
        }
    }
}
