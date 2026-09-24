use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
};
use tui_term::widget::{Cursor, PseudoTerminal};
use uuid::Uuid;

use crate::{
    input::{Focus, SidebarAction},
    screen::safe_text,
    ssh::{Session, SessionPhase},
    ui::{
        actions::{Dialog, category_path},
        catalog::{Catalog, RowKey, Section},
    },
    vault::{Auth, LocalState},
};

#[derive(Clone, Debug)]
pub enum HitTarget {
    Sidebar(RowKey),
    SidebarBackground,
    SidebarAction { key: RowKey, action: SidebarAction },
    Tab(Uuid),
    CloseTab(Uuid),
    Detach,
    Quit,
    Terminal,
}

#[derive(Clone, Debug)]
pub struct HitRegion {
    pub area: Rect,
    pub target: HitTarget,
}

#[derive(Default)]
pub struct RenderOutput {
    pub terminal_inner: Option<Rect>,
    pub sidebar: Option<Rect>,
    pub hits: Vec<HitRegion>,
    pub narrow: bool,
}

pub struct RenderRequest<'a> {
    pub catalog: &'a mut Catalog,
    pub state: &'a LocalState,
    pub sessions: &'a [Session],
    pub active_session: Option<usize>,
    pub focus: Focus,
    pub prefix: bool,
    pub sidebar_visible: bool,
    pub sidebar_overlay: bool,
    pub sync_label: &'a str,
    pub sync_detail: &'a str,
    pub notice: &'a str,
    pub update_notice: Option<&'a str>,
    pub uncertain: bool,
    pub dialog: Option<&'a Dialog>,
}

pub fn draw(frame: &mut Frame, mut request: RenderRequest<'_>) -> RenderOutput {
    let bounds = frame.area();
    let mut output = RenderOutput {
        narrow: bounds.width < 70,
        ..RenderOutput::default()
    };
    if bounds.width < 40 || bounds.height < 10 {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(1), Constraint::Length(1)])
            .split(bounds);
        frame.render_widget(
            Paragraph::new(vec![
                Line::from(Span::styled(
                    "Terminal is too small",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                )),
                Line::from("Resize to at least 40 columns × 10 rows."),
                Line::from("Ctrl+B d detaches; Ctrl+B q quits."),
            ])
            .alignment(ratatui::layout::Alignment::Center)
            .block(Block::default().borders(Borders::ALL)),
            chunks[0],
        );
        draw_footer(frame, chunks[1], &request, &mut output);
        if let Some(dialog) = request.dialog {
            dialog.draw(frame, bounds);
        }
        return output;
    }

    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(1)])
        .split(bounds);
    let workspace = vertical[0];
    let footer = vertical[1];
    let docked_sidebar = request.sidebar_visible && bounds.width >= 70;
    let overlay_sidebar = request.sidebar_overlay && bounds.width < 70;
    let (sidebar, main) = if docked_sidebar {
        let sidebar_width = (bounds.width / 4)
            .clamp(22, 32)
            .min(workspace.width.saturating_sub(8));
        let horizontal = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Length(sidebar_width), Constraint::Min(1)])
            .split(workspace);
        (Some(horizontal[0]), horizontal[1])
    } else {
        (None, workspace)
    };

    draw_main(frame, main, &request, &mut output);

    if let Some(area) = sidebar {
        draw_sidebar(frame, area, &mut request, &mut output, false);
    } else if overlay_sidebar {
        let width = workspace.width.saturating_sub(2).min(32).max(1);
        let area = Rect::new(workspace.x, workspace.y, width, workspace.height);
        frame.render_widget(Clear, area);
        draw_sidebar(frame, area, &mut request, &mut output, true);
    }

    draw_footer(frame, footer, &request, &mut output);
    if let Some(dialog) = request.dialog {
        dialog.draw(frame, bounds);
    }
    output
}

fn draw_main(
    frame: &mut Frame,
    area: Rect,
    request: &RenderRequest<'_>,
    output: &mut RenderOutput,
) {
    let (tabs, pane) = if request.sessions.is_empty() {
        (None, area)
    } else {
        let split = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(1), Constraint::Min(1)])
            .split(area);
        (Some(split[0]), split[1])
    };
    if let Some(tabs) = tabs {
        draw_tabs(frame, tabs, request, output);
    }

    let Some(index) = request
        .active_session
        .filter(|index| *index < request.sessions.len())
    else {
        output.terminal_inner = Some(draw_details(frame, pane, request));
        return;
    };
    let session = &request.sessions[index];
    let view = session.view.lock();
    let (pane, phase) = if let SessionPhase::Error(message) = &view.phase {
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
                        .borders(Borders::ALL),
                )
                .style(Style::default().fg(Color::LightRed)),
            areas[1],
        );
        (areas[0], "Error".to_owned())
    } else {
        (pane, view.phase.label())
    };
    let title = format!(" {} — {} ", safe_text(&session.label), safe_text(&phase));
    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(if request.focus == Focus::Terminal {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default().fg(Color::DarkGray)
        });
    let inner = block.inner(pane);
    let show_cursor = request.focus == Focus::Terminal
        && !request.prefix
        && request.dialog.is_none()
        && matches!(&view.phase, SessionPhase::Connected);
    let terminal = PseudoTerminal::new(view.terminal.screen())
        .block(block)
        .cursor(Cursor::default().visibility(show_cursor));
    frame.render_widget(terminal, pane);
    if inner.width > 0 && inner.height > 0 {
        output.terminal_inner = Some(inner);
        output.hits.push(HitRegion {
            area: inner,
            target: HitTarget::Terminal,
        });
    }
}

fn draw_tabs(
    frame: &mut Frame,
    area: Rect,
    request: &RenderRequest<'_>,
    output: &mut RenderOutput,
) {
    if area.width == 0 || request.sessions.is_empty() {
        return;
    }
    let capacity = usize::from((area.width / 12).max(1));
    let count = request.sessions.len().min(capacity);
    let active = request
        .active_session
        .unwrap_or(0)
        .min(request.sessions.len() - 1);
    let start = active
        .saturating_sub(count - 1)
        .min(request.sessions.len() - count);
    let base = (usize::from(area.width) / count).max(1);
    let mut x = area.x;
    for (slot, (index, session)) in request
        .sessions
        .iter()
        .enumerate()
        .skip(start)
        .take(count)
        .enumerate()
    {
        let remaining = area.right().saturating_sub(x);
        if remaining == 0 {
            break;
        }
        let width = if slot + 1 == count {
            remaining
        } else {
            (base as u16).min(remaining)
        };
        let tab = Rect::new(x, area.y, width, 1);
        let view = session.view.lock();
        let marker = if view.phase.is_live() { "●" } else { "○" };
        let label = format!(" {marker} {} ", safe_text(&session.label));
        drop(view);
        let active = request.active_session == Some(index);
        let style = if active {
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Gray).bg(Color::Rgb(30, 30, 30))
        };
        let close = Rect::new(tab.right().saturating_sub(3), tab.y, 3, 1);
        let label_area = Rect {
            width: tab.width.saturating_sub(3),
            ..tab
        };
        frame.render_widget(Paragraph::new(label).style(style), label_area);
        frame.render_widget(Paragraph::new("[x]").style(style), close);
        output.hits.push(HitRegion {
            area: label_area,
            target: HitTarget::Tab(session.id),
        });
        output.hits.push(HitRegion {
            area: close,
            target: HitTarget::CloseTab(session.id),
        });
        x = x.saturating_add(width);
    }
}

fn draw_sidebar(
    frame: &mut Frame,
    area: Rect,
    request: &mut RenderRequest<'_>,
    output: &mut RenderOutput,
    overlay: bool,
) {
    let title = if overlay {
        " Workspace (overlay) "
    } else {
        " Workspace "
    };
    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(if request.focus == Focus::Sidebar {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default().fg(Color::DarkGray)
        });
    let inner = block.inner(area);
    frame.render_widget(block, area);
    output.hits.push(HitRegion {
        area,
        target: HitTarget::SidebarBackground,
    });
    if inner.height == 0 || inner.width == 0 {
        return;
    }
    let controls_height = inner.height.min(3);
    let controls = Rect::new(
        inner.x,
        inner.bottom() - controls_height,
        inner.width,
        controls_height,
    );
    let inner = Rect {
        height: inner.height - controls_height,
        ..inner
    };
    output.sidebar = Some(inner);
    let range = request.catalog.visible_range(usize::from(inner.height));
    let active_session = request
        .active_session
        .and_then(|index| request.sessions.get(index))
        .map(|session| session.id);
    for (line, index) in range.enumerate() {
        let row = &request.catalog.rows()[index];
        let row_area = Rect::new(inner.x, inner.y + line as u16, inner.width, 1);
        let selected = request.catalog.selected_index() == index;
        let active = match row.key {
            RowKey::Session(id) => active_session == Some(id),
            RowKey::Host(id) => request
                .sessions
                .iter()
                .any(|session| session.host_id == id && session.is_live()),
            _ => false,
        };
        let section = matches!(row.key, RowKey::Section(_));
        let glyph = if row.expandable {
            if row.expanded { "▾" } else { "▸" }
        } else if active {
            "●"
        } else {
            " "
        };
        let indent = "  ".repeat(row.indent as usize);
        let mut label = format!("{indent}{glyph} {}", row.label);
        if row.key == RowKey::Sync {
            label.push_str(" · ");
            label.push_str(request.sync_label);
        }
        let mut style = if section {
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD)
        } else if active {
            Style::default().fg(Color::Green)
        } else {
            Style::default().fg(Color::White)
        };
        if selected {
            style = style.bg(if request.focus == Focus::Sidebar {
                Color::Blue
            } else {
                Color::DarkGray
            });
        }
        frame.render_widget(Paragraph::new(label).style(style), row_area);
        output.hits.push(HitRegion {
            area: row_area,
            target: HitTarget::Sidebar(row.key.clone()),
        });
    }
    draw_sidebar_actions(frame, controls, request, output);
}

fn draw_sidebar_actions(
    frame: &mut Frame,
    area: Rect,
    request: &RenderRequest<'_>,
    output: &mut RenderOutput,
) {
    let block = Block::default()
        .title(" Actions ")
        .borders(Borders::TOP)
        .border_style(Style::default().fg(Color::DarkGray));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let Some(key) = request.catalog.selected_key() else {
        return;
    };
    let rows: [&[(&str, SidebarAction)]; 2] = match &key {
        RowKey::Host(_) | RowKey::Credential(_) | RowKey::Category(_) | RowKey::Snippet(_) => [
            &[
                ("[a Add]", SidebarAction::Add),
                ("[e Edit]", SidebarAction::Edit),
            ],
            &[
                ("[d Delete]", SidebarAction::Delete),
                ("[/ Find]", SidebarAction::Filter),
            ],
        ],
        RowKey::Session(_) => [
            &[("[x Close]", SidebarAction::CloseSession)],
            &[("[/ Find]", SidebarAction::Filter)],
        ],
        RowKey::Sync | RowKey::Section(Section::Sync) => [
            &[
                ("[e Setup]", SidebarAction::Edit),
                ("[s Sync]", SidebarAction::Sync),
            ],
            &[
                ("[d Disable]", SidebarAction::Delete),
                ("[/ Find]", SidebarAction::Filter),
            ],
        ],
        RowKey::Section(Section::Sessions) => [&[], &[("[/ Find]", SidebarAction::Filter)]],
        _ => [
            &[("[a Add]", SidebarAction::Add)],
            &[("[/ Find]", SidebarAction::Filter)],
        ],
    };
    for (line, actions) in rows.into_iter().enumerate().take(usize::from(inner.height)) {
        let actions = if line == 1 && request.uncertain {
            &[("[r Retry save]", SidebarAction::RetrySave)][..]
        } else {
            actions
        };
        let mut x = inner.x;
        for &(label, action) in actions {
            let width = label.len() as u16;
            if x.saturating_add(width) > inner.right() {
                break;
            }
            let button = Rect::new(x, inner.y + line as u16, width, 1);
            frame.render_widget(
                Paragraph::new(label)
                    .style(Style::default().fg(Color::Cyan).bg(Color::Rgb(30, 30, 30))),
                button,
            );
            output.hits.push(HitRegion {
                area: button,
                target: HitTarget::SidebarAction {
                    key: key.clone(),
                    action,
                },
            });
            x += width + 1;
        }
    }
}

fn draw_details(frame: &mut Frame, area: Rect, request: &RenderRequest<'_>) -> Rect {
    let block = Block::default().title(" Details ").borders(Borders::ALL);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let vault = &request.state.vault;
    let lines = match request.catalog.selected_key() {
        Some(RowKey::Host(id)) => vault.hosts.iter().find(|entry| entry.id == id).map_or_else(
            || vec![Line::from("The selected server no longer exists.")],
            |host| {
                let credential = vault.credentials.iter().find(|entry| entry.id == host.credential_id);
                let category = host.category_id.map(|id| category_path(vault, id)).unwrap_or_else(|| "Ungrouped".to_owned());
                let trusted = vault.known_hosts.iter().any(|known| known.hostname.eq_ignore_ascii_case(&host.hostname) && known.port == host.port);
                vec![
                    heading(&host.label),
                    Line::from(format!("{}:{}", host.hostname, host.port)),
                    Line::from(format!("Category: {category}")),
                    Line::from(format!("Credential: {}", credential.map(|entry| entry.label.as_str()).unwrap_or("missing"))),
                    Line::from(format!("Trusted key: {}", if trusted { "saved" } else { "not yet accepted" })),
                    Line::from(""),
                    Line::from("Enter: connect   e: edit   d: delete   f: forget trusted key"),
                ]
            },
        ),
        Some(RowKey::Category(id)) => vault.categories.iter().find(|entry| entry.id == id).map_or_else(
            || vec![Line::from("The selected category no longer exists.")],
            |category| {
                let children = vault.categories.iter().filter(|entry| entry.parent_id == Some(id)).count();
                let hosts = vault.hosts.iter().filter(|entry| entry.category_id == Some(id)).count();
                vec![
                    heading(&category.label),
                    Line::from(format!("Path: {}", category_path(vault, id))),
                    Line::from(format!("{children} child categories · {hosts} direct servers")),
                    Line::from(""),
                    Line::from("Deleting reparents immediate children and servers; it never deletes servers."),
                    Line::from("a: add child/server   e: edit/reparent   d: delete"),
                ]
            },
        ),
        Some(RowKey::Credential(id)) => vault.credentials.iter().find(|entry| entry.id == id).map_or_else(
            || vec![Line::from("The selected credential no longer exists.")],
            |credential| {
                let (kind, note) = match &credential.auth {
                    Auth::Password { .. } => ("Password", "Encrypted in the local vault"),
                    Auth::PrivateKey { passphrase, .. } => (
                        "Imported private key",
                        if passphrase.is_some() { "Key contents and passphrase are encrypted in the vault" } else { "Key contents are stored; passphrase is requested when connecting" },
                    ),
                    Auth::Agent => ("Local SSH agent", "Local agent required on this device"),
                    Auth::KeyboardInteractive => ("Keyboard-interactive", "Challenge answers are never saved"),
                };
                let referenced: Vec<_> = vault.hosts.iter().filter(|host| host.credential_id == id).map(|host| host.label.as_str()).collect();
                vec![
                    heading(&credential.label),
                    Line::from(format!("Username: {}", credential.username)),
                    Line::from(format!("Authentication: {kind}")),
                    Line::from(note),
                    Line::from(format!("Used by: {}", if referenced.is_empty() { "no servers".to_owned() } else { referenced.join(", ") })),
                    Line::from(""),
                    Line::from("e: edit   d: delete (refused while referenced)"),
                ]
            },
        ),
        Some(RowKey::Snippet(id)) => vault.snippets.iter().find(|entry| entry.id == id).map_or_else(
            || vec![Line::from("The selected snippet no longer exists.")],
            |snippet| vec![
                heading(&snippet.label),
                Line::from("Exact command:"),
                Line::from(Span::styled(snippet.command.as_str(), Style::default().fg(Color::Yellow))),
                Line::from(""),
                Line::from("Enter: preview target and insert without Enter   e: edit   d: delete"),
            ],
        ),
        Some(RowKey::Sync) | Some(RowKey::Section(Section::Sync)) => {
            let setting = request.state.sync.as_ref();
            vec![
                heading("Synchronization"),
                Line::from(format!("Status: {}", request.sync_label)),
                Line::from(safe_text(request.sync_detail)),
                Line::from(format!("Server: {}", setting.map(|sync| sync.url.as_str()).unwrap_or("not configured"))),
                Line::from(format!("Access token: {}", if setting.is_some() { "•••••••• (masked)" } else { "not configured" })),
                Line::from(""),
                Line::from("Enter/e: configure   s: synchronize now   d: disable"),
                Line::from("Network errors never disable local edits or live SSH sessions."),
            ]
        }
        Some(RowKey::Session(id)) => request.sessions.iter().find(|session| session.id == id).map_or_else(
            || vec![Line::from("The selected session has ended.")],
            |session| {
                let view = session.view.lock();
                vec![
                    heading(&session.label),
                    Line::from(format!("State: {}", safe_text(&view.phase.label()))),
                    Line::from("Enter: activate tab   Ctrl+B x: close/dismiss"),
                ]
            },
        ),
        Some(RowKey::Ungrouped) => vec![
            heading("Ungrouped servers"),
            Line::from("Servers without a category appear here."),
            Line::from("a: add a server or root category"),
        ],
        Some(RowKey::Snippets) | Some(RowKey::Section(Section::Tools)) => vec![
            heading("Snippets"),
            Line::from("Reusable single-line commands are inserted into a live session without Enter."),
            Line::from("a: add snippet"),
        ],
        Some(RowKey::Section(Section::Servers)) => vec![heading("Servers"), Line::from("a: add a server or category")],
        Some(RowKey::Section(Section::Credentials)) => vec![heading("Credentials"), Line::from("a: add a reusable credential")],
        Some(RowKey::Section(Section::Sessions)) => vec![
            heading("Sessions"),
            Line::from("Open a saved server to create an embedded SSH terminal."),
        ],
        None => vec![
            heading("Welcome to vyx"),
            Line::from("Add a credential, then a server. Ctrl+B d detaches; Ctrl+B ? opens help."),
        ],
    };
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
    inner
}

fn heading(text: &str) -> Line<'_> {
    Line::from(Span::styled(
        safe_text(text),
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    ))
}

fn draw_footer(
    frame: &mut Frame,
    area: Rect,
    request: &RenderRequest<'_>,
    output: &mut RenderOutput,
) {
    let focus = if request.prefix {
        "Prefix"
    } else if request.dialog.is_some() {
        "Modal"
    } else {
        match request.focus {
            Focus::Sidebar => "Sidebar",
            Focus::Terminal => "Terminal",
        }
    };
    let message = if request.uncertain {
        "Save durability uncertain — r Retry save"
    } else {
        request.notice
    };
    let filter = if request.catalog.filter().is_empty() {
        String::new()
    } else {
        format!(" · Filter: {}", safe_text(request.catalog.filter()))
    };
    let text = format!(
        " {focus} · Sync: {}{filter} · {}",
        request.sync_label,
        safe_text(message)
    );
    let (detach_label, quit_label) = if request.dialog.is_some() {
        ("", "")
    } else {
        let full = if request.prefix {
            ("[d Detach]", "[q Quit]")
        } else if request.focus == Focus::Sidebar {
            ("[Ctrl+B d Detach]", "[q Quit]")
        } else {
            ("[Ctrl+B d Detach]", "[Ctrl+B q Quit]")
        };
        if (full.0.len() + full.1.len()) as u16 <= area.width {
            full
        } else if area.width >= 14 {
            ("[Detach]", "[Quit]")
        } else if area.width >= 6 {
            ("[D]", "[Q]")
        } else if area.width >= 2 {
            ("D", "Q")
        } else {
            ("D", "")
        }
    };
    let detach_width = (detach_label.len() as u16).min(area.width);
    let quit_width = (quit_label.len() as u16).min(area.width.saturating_sub(detach_width));
    let controls_left = area.right().saturating_sub(detach_width + quit_width);
    let available_width = controls_left.saturating_sub(area.x);
    let update = request
        .update_notice
        .filter(|_| !request.uncertain && request.dialog.is_none())
        .map(|full| {
            if full.chars().count() + 24 <= usize::from(available_width) {
                full
            } else if available_width >= 43 {
                " Update: vyx update "
            } else {
                ""
            }
        })
        .unwrap_or("");
    let update_width = update.chars().count() as u16;
    let status = Rect {
        width: available_width.saturating_sub(update_width),
        ..area
    };
    frame.render_widget(
        Paragraph::new(text).style(Style::default().fg(Color::Black).bg(if request.uncertain {
            Color::Yellow
        } else {
            Color::Cyan
        })),
        status,
    );
    if update_width > 0 {
        frame.render_widget(
            Paragraph::new(update)
                .style(Style::default().fg(Color::Gray).bg(Color::Rgb(30, 30, 30))),
            Rect::new(status.right(), area.y, update_width, area.height),
        );
    }
    let button_style = Style::default().fg(Color::Cyan).bg(Color::Rgb(30, 30, 30));
    if detach_width > 0 {
        let button = Rect::new(controls_left, area.y, detach_width, area.height);
        frame.render_widget(Paragraph::new(detach_label).style(button_style), button);
        output.hits.push(HitRegion {
            area: button,
            target: HitTarget::Detach,
        });
    }
    if quit_width > 0 {
        let button = Rect::new(
            controls_left.saturating_add(detach_width),
            area.y,
            quit_width,
            area.height,
        );
        frame.render_widget(Paragraph::new(quit_label).style(button_style), button);
        output.hits.push(HitRegion {
            area: button,
            target: HitTarget::Quit,
        });
    }
}

pub fn contains(area: Rect, column: u16, row: u16) -> bool {
    column >= area.x && column < area.right() && row >= area.y && row < area.bottom()
}
