use std::{path::PathBuf, time::Instant};

use anyhow::{Result, ensure};
use crossterm::event::{Event, KeyEvent, MouseEventKind};
use ratatui::{layout::Rect, style::Style, widgets::{Paragraph, Wrap}};

use crate::{
    input::is_key_input,
    screen::{Screen, ScreenEvent, safe_text},
    settings::Motion,
    shortcuts::{Bindings, Shortcut},
    theme::Palette,
    ui::{animation::{BrandAnimation, auth_regions}, form::{Action, Field, Form, FormHitRegion}, theming::clear},
    vault::Secret,
};

pub enum UnlockRequest {
    Passphrase(Secret),
    Recovery { file: PathBuf, new: Secret },
}

pub struct UnlockOutcome<T> {
    pub value: T,
    pub recovered: bool,
}

pub struct UnlockOptions<'a> {
    pub title: &'a str,
    pub description: &'a str,
    pub live_sessions: usize,
    pub confirm_quit: bool,
    pub allow_recovery: bool,
    pub motion: Motion,
}

pub(crate) fn meaningful_input(event: &Event) -> bool {
    match event {
        Event::Key(key) => is_key_input(*key),
        Event::Paste(_) => true,
        Event::Mouse(mouse) => matches!(mouse.kind,
            MouseEventKind::Down(_) | MouseEventKind::Drag(_) | MouseEventKind::ScrollUp |
            MouseEventKind::ScrollDown | MouseEventKind::ScrollLeft | MouseEventKind::ScrollRight),
        _ => false,
    }
}

pub(crate) async fn visual_tick(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline.into()).await,
        None => std::future::pending().await,
    }
}

fn clear_secrets(form: &mut Form) {
    for field in &mut form.fields {
        if field.secret { field.set_value(""); }
    }
}

fn select_method(form: &mut Form, options: &UnlockOptions<'_>) {
    clear_secrets(form);
    let recovery = options.allow_recovery && form.fields[0].choice == 1;
    form.fields[0].visible = options.allow_recovery;
    form.fields[1].visible = !recovery;
    for field in &mut form.fields[2..] { field.visible = recovery; }
    form.focus = if recovery { 2 } else { 1 };
    form.submit = if recovery { "Reset passphrase" } else { "Unlock" }.into();
    form.description = if recovery {
        format!("{} For local-only vaults. Select a matching recovery file saved before the password was lost. Resetting the passphrase invalidates earlier recovery files for the current vault.", options.description)
    } else { options.description.into() };
    form.error.clear();
}

fn request(form: &Form, recovery: bool) -> Result<UnlockRequest> {
    if !recovery { return Ok(UnlockRequest::Passphrase(Secret::new(form.value(1)))); }
    let file = PathBuf::from(form.value(2));
    ensure!(file.is_absolute(), "Choose an absolute recovery file path; ~ is not expanded.");
    ensure!(form.value(3).chars().count() >= 16, "Use at least 16 characters for the new passphrase.");
    ensure!(form.value(3) == form.value(4), "Passphrases do not match.");
    Ok(UnlockRequest::Recovery { file, new: Secret::new(form.value(3)) })
}

/// The only input consumer while locked. Workspace controls and SSH never receive these events.
///
/// Success fences keyboard, paste and mouse events admitted before the handoff,
/// including senders waiting for queue capacity. Resize, focus, lifecycle and
/// connection requests remain available to the unlocked workspace.
pub async fn unlock<T, F, Work>(
    screen: &mut Screen,
    bindings: &Bindings,
    palette: &Palette,
    options: UnlockOptions<'_>,
    verify: F,
) -> Result<Option<UnlockOutcome<T>>>
where
    F: Fn(UnlockRequest) -> Work,
    Work: Future<Output = Result<T>>,
{
    let mut animation = BrandAnimation::new(options.motion, palette, Instant::now(), screen.attachment_generation());
    let mut form = Form::new(options.title, vec![
        Field::inline("Unlock with", vec!["Passphrase".into(), "Recovery file".into()], 0),
        Field::secret("Vault passphrase", ""),
        Field::text("Absolute recovery file path", "").with_hint("~ is not expanded."),
        Field::secret("New passphrase", "").with_hint("At least 16 characters."),
        Field::secret("Repeat new passphrase", ""),
    ]);
    select_method(&mut form, &options);
    form.cancel = if options.confirm_quit { "Quit" } else { "Cancel" }.into();
    let mut quit = Form::new("Quit vyx", Vec::new());
    quit.description = if options.live_sessions == 0 { "Stop this workspace?".into() } else {
        format!("Disconnect {} live SSH session(s) and stop this workspace? Remote programs may stop unless they run in a remote multiplexer.", options.live_sessions)
    };
    quit.submit = "Quit".into();
    quit.cancel = "Stay locked".into();
    let mut confirming_quit = false;
    let mut prefix = false;
    let mut hits = Vec::new();
    // Startup already shows its description above the form; only the in-app lock adds a hint.
    let locked_help = if options.confirm_quit {
        format!("Locked · {} quits", bindings.sequence(Shortcut::PrefixQuit))
    } else { String::new() };
    let prefix_help = format!("{} Quit · {} Cancel prefix",
        bindings.primary(Shortcut::PrefixQuit), bindings.primary(Shortcut::PrefixCancel));
    loop {
        let request = loop {
            animation.observe_attachment(screen.is_attached(), screen.attachment_generation());
            let active = if confirming_quit { &mut quit } else { &mut form };
            let visible = draw(screen, active, &mut hits, bindings, palette,
                if prefix { &prefix_help } else { &locked_help }, None, &mut animation).await?;
            let deadline = animation.deadline(screen.is_attached(), visible);
            let event = tokio::select! {
                biased;
                event = screen.next_event() => event?,
                _ = visual_tick(deadline) => continue,
            };
            let Some(event) = event else { return Ok(None); };
            if let ScreenEvent::Input(input) = &event {
                if meaningful_input(input) { animation.settle(); }
            }
            let old_method = active.fields.first().map(|field| field.choice);
            let action = match event {
                ScreenEvent::Input(Event::Key(key)) if is_key_input(key) => {
                    if !options.confirm_quit && bindings.matches(Shortcut::AbortStartup, key) { return Ok(None); }
                    let route = if options.confirm_quit { route_key(key, bindings, &mut prefix) } else { KeyRoute::Form };
                    match route {
                        KeyRoute::Quit => { clear_secrets(&mut form); confirming_quit = true; continue; }
                        KeyRoute::Consumed => continue,
                        KeyRoute::Form => active.key(key, bindings),
                    }
                }
                ScreenEvent::Input(Event::Paste(text)) => { active.paste(&text); Action::Continue }
                ScreenEvent::Input(Event::Mouse(mouse)) => active.mouse(mouse, &hits),
                _ => Action::Continue,
            };
            if confirming_quit {
                match action {
                    Action::Submit => return Ok(None),
                    Action::Cancel => confirming_quit = false,
                    Action::Continue => {}
                }
            } else {
                if old_method != form.fields.first().map(|field| field.choice) { select_method(&mut form, &options); }
                match action {
                    Action::Submit => {
                        let recovery = options.allow_recovery && form.fields[0].choice == 1;
                        match request(&form, recovery) {
                            Ok(request) => { clear_secrets(&mut form); break (request, recovery); }
                            Err(error) => { clear_secrets(&mut form); form.error = safe_text(&error.to_string()); }
                        }
                    }
                    Action::Cancel => {
                        clear_secrets(&mut form);
                        if !options.confirm_quit { return Ok(None); }
                        confirming_quit = true;
                    }
                    Action::Continue => {}
                }
            }
        };
        let (request, recovered) = request;
        let work = verify(request);
        form.error.clear();
        animation.begin_work(Instant::now());
        tokio::pin!(work);
        let progress = if recovered {
            "Resetting vault passphrase… Please wait for the result before closing vyx.".into()
        } else { format!("Unlocking vault… {} cancels.", bindings.primary(Shortcut::Cancel)) };
        loop {
            animation.observe_attachment(screen.is_attached(), screen.attachment_generation());
            let visible = draw(screen, &form, &mut hits, bindings, palette,
                if recovered { "" } else if prefix { &prefix_help } else { &locked_help }, Some(&progress), &mut animation).await?;
            let deadline = animation.deadline(screen.is_attached(), visible);
            tokio::select! {
                biased;
                result = &mut work => {
                    animation.settle();
                    match result {
                        Ok(value) => {
                            screen.fence_authentication_input();
                            return Ok(Some(UnlockOutcome { value, recovered }));
                        }
                        Err(error) => form.error = safe_text(&format!("Cannot unlock: {error:#}")),
                    }
                    break;
                }
                event = screen.next_event() => match event? {
                    None if recovered => {
                        // Submission authorizes the write. Await its outcome rather than imply rollback.
                        let _value = (&mut work).await?;
                        animation.settle();
                        // The shutdown event was consumed here; do not start a workspace
                        // that would wait forever for that same lifecycle event again.
                        return Ok(None);
                    }
                    None => return Ok(None),
                    Some(ScreenEvent::Input(Event::Key(key))) if !recovered && is_key_input(key) => {
                        let route = if options.confirm_quit { route_key(key, bindings, &mut prefix) }
                            else if bindings.matches(Shortcut::AbortStartup, key) { return Ok(None); }
                            else { KeyRoute::Form };
                        match route {
                            KeyRoute::Quit => { confirming_quit = true; animation.settle(); break; }
                            KeyRoute::Form if bindings.matches(Shortcut::Cancel, key) => {
                                animation.settle();
                                if !options.confirm_quit { return Ok(None); }
                                break;
                            }
                            _ => {}
                        }
                    }
                    _ => {}
                },
                _ = visual_tick(deadline) => {}
            }
        }
    }
}

enum KeyRoute { Quit, Consumed, Form }

fn route_key(key: KeyEvent, bindings: &Bindings, prefix: &mut bool) -> KeyRoute {
    if *prefix {
        *prefix = false;
        return if bindings.matches(Shortcut::PrefixQuit, key) { KeyRoute::Quit } else { KeyRoute::Consumed };
    }
    if bindings.matches_prefix(key, true) {
        *prefix = true;
        KeyRoute::Consumed
    } else if bindings.matches(Shortcut::AbortStartup, key) {
        KeyRoute::Quit
    } else {
        KeyRoute::Form
    }
}

async fn draw(
    screen: &mut Screen,
    form: &Form,
    hits: &mut Vec<FormHitRegion>,
    bindings: &Bindings,
    palette: &Palette,
    help: &str,
    progress: Option<&str>,
    animation: &mut BrandAnimation,
) -> Result<bool> {
    if !screen.is_attached() { hits.clear(); return Ok(false); }
    let sampled_at = Instant::now();
    let mut visible = false;
    screen.draw(|frame| {
        let bounds = frame.area();
        clear(frame, bounds, palette);
        hits.clear();
        let (brand, body) = auth_regions(bounds, form.preferred_dialog_height(bounds.width), animation.motion());
        visible = !brand.is_empty();
        animation.draw(frame, bounds, brand, sampled_at);
        if let Some(progress) = progress {
            frame.render_widget(Paragraph::new(progress).style(palette.style()).wrap(Wrap { trim: false }), body);
        } else if body.height < form.preferred_dialog_height(body.width).saturating_add(2) {
            form.draw_panel(frame, body, bindings, hits, palette);
        } else {
            form.draw(frame, body, bindings, hits, palette);
        }
        if bounds.height > 0 {
            frame.render_widget(Paragraph::new(help).style(Style::default().fg(palette.muted)),
                Rect::new(bounds.x, bounds.bottom() - 1, bounds.width, 1));
        }
    }).await?;
    animation.frame_drawn(sampled_at, Instant::now());
    Ok(visible)
}
