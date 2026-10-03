use std::{
    future::Future,
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
    time::Instant,
};

use anyhow::{Result, bail, ensure};
use crossterm::event::{Event, KeyEventKind};
use ratatui::widgets::{Paragraph, Wrap};

use crate::{
    remote::{Remote, RemoteRead, canonical_origin},
    screen::{Screen, ScreenEvent},
    settings::Motion,
    shortcuts::{Bindings, Shortcut},
    theme::Palette,
    ui::{animation::{BrandAnimation, auth_regions}, form::{Action, Field, Form},
        lock::{self, UnlockOptions, UnlockRequest, meaningful_input, visual_tick},
        setup::storage_mode_form, theming},
    vault::{Directory, MAX_ENVELOPE, Secret, Store, SyncState},
};

pub async fn ask(
    screen: &mut Screen,
    form: &mut Form,
    bindings: &Bindings,
    palette: &Palette,
    animation: &mut BrandAnimation,
) -> Result<bool> {
    let mut hits = Vec::new();
    loop {
        animation.observe_attachment(screen.is_attached(), screen.attachment_generation());
        let sampled_at = Instant::now();
        let mut visible = false;
        if screen.is_attached() {
            screen.draw(|frame| {
                let area = frame.area();
                theming::clear(frame, area, palette);
                let (brand, body) = auth_regions(area, form.preferred_dialog_height(area.width), animation.motion());
                visible = !brand.is_empty();
                animation.draw(frame, area, brand, sampled_at);
                hits.clear();
                if body.height < form.preferred_dialog_height(body.width).saturating_add(2) {
                    form.draw_panel(frame, body, bindings, &mut hits, palette);
                } else {
                    form.draw(frame, body, bindings, &mut hits, palette);
                }
            }).await?;
            animation.frame_drawn(sampled_at, Instant::now());
        }
        let deadline = animation.deadline(screen.is_attached(), visible);
        let event = tokio::select! {
            biased;
            event = screen.next_event() => event?,
            _ = visual_tick(deadline) => continue,
        };
        if let Some(ScreenEvent::Input(input)) = &event {
            if meaningful_input(input) { animation.settle(); }
        }
        match event {
            None => return Ok(false),
            Some(ScreenEvent::Input(Event::Key(key))) if key.kind != KeyEventKind::Release => {
                if bindings.matches(Shortcut::AbortStartup, key) { return Ok(false); }
                match form.key(key, bindings) {
                    Action::Submit => return Ok(true),
                    Action::Cancel => return Ok(false),
                    Action::Continue => (),
                }
            }
            Some(ScreenEvent::Input(Event::Paste(text))) => form.paste(&text),
            Some(ScreenEvent::Input(Event::Mouse(mouse))) => match form.mouse(mouse, &hits) {
                Action::Submit => return Ok(true),
                Action::Cancel => return Ok(false),
                Action::Continue => (),
            },
            _ => (),
        }
    }
}

pub async fn busy<T>(
    screen: &mut Screen,
    message: &str,
    work: impl Future<Output = Result<T>>,
    bindings: &Bindings,
    palette: &Palette,
    animation: &mut BrandAnimation,
) -> Result<Option<T>> {
    let message = format!("{message}  {} / {}: cancel",
        bindings.primary(Shortcut::Cancel), bindings.primary(Shortcut::AbortStartup));
    animation.begin_work(Instant::now());
    tokio::pin!(work);
    let result = async {
        loop {
            animation.observe_attachment(screen.is_attached(), screen.attachment_generation());
            let sampled_at = Instant::now();
            let mut visible = false;
            if screen.is_attached() {
                screen.draw(|frame| {
                    let area = frame.area();
                    theming::clear(frame, area, palette);
                    let (brand, body) = auth_regions(area, 5, animation.motion());
                    visible = !brand.is_empty();
                    animation.draw(frame, area, brand, sampled_at);
                    frame.render_widget(Paragraph::new(message.as_str()).style(palette.style())
                        .wrap(Wrap { trim: false }), body);
                }).await?;
                animation.frame_drawn(sampled_at, Instant::now());
            }
            let deadline = animation.deadline(screen.is_attached(), visible);
            tokio::select! {
                biased;
                result = &mut work => return result.map(Some),
                event = screen.next_event() => match event? {
                    None => return Ok(None),
                    Some(ScreenEvent::Input(Event::Key(key)))
                        if key.kind != KeyEventKind::Release
                            && (bindings.matches(Shortcut::Cancel, key)
                                || bindings.matches(Shortcut::AbortStartup, key)) => return Ok(None),
                    _ => (),
                },
                _ = visual_tick(deadline) => {}
            }
        }
    }.await;
    animation.settle();
    result
}

async fn read_file(path: PathBuf) -> Result<Vec<u8>> {
    tokio::task::spawn_blocking(move || {
        let file = std::fs::File::open(path)?;
        ensure!(
            file.metadata()?.len() <= MAX_ENVELOPE as u64,
            "Encrypted file exceeds 16 MiB"
        );
        let mut bytes = Vec::new();
        file.take(MAX_ENVELOPE as u64 + 1).read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= MAX_ENVELOPE, "Encrypted file exceeds 16 MiB");
        Ok(bytes)
    })
    .await?
}

async fn restore_file(
    screen: &mut Screen,
    directory: &Arc<Directory>,
    path: Option<&Path>,
    bindings: &Bindings,
    palette: &Palette,
    animation: &mut BrandAnimation,
) -> Result<Option<Store>> {
    let mut form = Form::new(
        "Restore encrypted file",
        vec![
            Field::text(
                "Encrypted snapshot path",
                path.map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_default(),
            ),
            Field::secret("Vault passphrase", ""),
        ],
    );
    form.description =
        "Restores a standalone encrypted vault; never overwrites existing data.".into();
    form.submit = "Restore".into();
    while ask(screen, &mut form, bindings, palette, animation).await? {
        let file = PathBuf::from(form.value(0));
        let passphrase = Secret::new(form.value(1));
        let operation = async {
            let envelope = read_file(file).await?;
            directory.restore(envelope, passphrase, None).await
        };
        match busy(
            screen,
            "Decrypting and validating snapshot…",
            operation,
            bindings,
            palette,
            animation,
        )
        .await
        {
            Ok(store) => return Ok(store),
            Err(error) => form.error = crate::screen::safe_text(&error.to_string()),
        }
    }
    Ok(None)
}

async fn restore_server(
    screen: &mut Screen,
    directory: &Arc<Directory>,
    bindings: &Bindings,
    palette: &Palette,
    animation: &mut BrandAnimation,
) -> Result<Option<Store>> {
    let mut form = Form::new(
        "Restore from server",
        vec![
            Field::text("Server origin", "https://"),
            Field::secret("Access token", ""),
        ],
    );
    form.description =
        "The server holds only ciphertext. Your passphrase is needed after download.".into();
    form.submit = "Download".into();
    while ask(screen, &mut form, bindings, palette, animation).await? {
        let prepare = (|| {
            Ok::<_, anyhow::Error>((canonical_origin(form.value(0))?, Secret::new(form.value(1))))
        })();
        let (origin, token) = match prepare {
            Ok(value) => value,
            Err(error) => {
                form.error = error.to_string();
                continue;
            }
        };
        let remote = match Remote::new(&origin, &token) {
            Ok(remote) => remote,
            Err(error) => {
                form.error = error.to_string();
                continue;
            }
        };
        let download = match busy(
            screen,
            "Downloading encrypted vault…",
            remote.get(None),
            bindings,
            palette,
            animation,
        )
        .await
        {
            Ok(Some(RemoteRead::Found(download))) => download,
            Ok(Some(_)) => {
                form.error = "The server has no vault to restore".into();
                continue;
            }
            Ok(None) => return Ok(None),
            Err(error) => {
                form.error = crate::screen::safe_text(&error.to_string());
                continue;
            }
        };
        let mut unlock = Form::new(
            "Decrypt downloaded vault",
            vec![Field::secret("Vault passphrase", "")],
        );
        unlock.submit = "Restore".into();
        unlock.description =
            "Decryption happens on this device; the passphrase is never sent.".into();
        while ask(screen, &mut unlock, bindings, palette, animation).await? {
            let settings = SyncState {
                url: origin.clone(),
                token: token.clone(),
                base_etag: Some(download.etag.clone()),
                base_snapshot_id: None,
                base_content_sha256: None,
                pending_upload: None,
            };
            match busy(
                screen,
                "Decrypting and validating snapshot…",
                directory.restore(
                    download.envelope.clone(),
                    Secret::new(unlock.value(0)),
                    Some(settings),
                ),
                bindings,
                palette,
                animation,
            )
            .await
            {
                Ok(store) => return Ok(store),
                Err(error) => unlock.error = crate::screen::safe_text(&error.to_string()),
            }
        }
    }
    Ok(None)
}

pub struct StartupOutcome {
    pub store: Store,
    pub recovered: bool,
    pub setup_created: bool,
}

pub async fn acquire(
    screen: &mut Screen,
    directory: Arc<Directory>,
    restore: Option<PathBuf>,
    bindings: &Bindings,
    palette: &Palette,
    motion: Motion,
) -> Result<Option<StartupOutcome>> {
    if directory.exists() {
        ensure!(
            restore.is_none(),
            "Restore refuses to overwrite an existing state.vyx"
        );
        return lock::unlock(screen, bindings, palette, UnlockOptions {
            title: "Unlock vault",
            description: "Hosts and credentials remain encrypted until unlocked.",
            live_sessions: 0, confirm_quit: false, allow_recovery: true, motion,
        }, |request| async {
            match request {
                UnlockRequest::Passphrase(passphrase) => directory.unlock(passphrase).await,
                UnlockRequest::Recovery { file, new } => directory.recover(file, new).await,
            }
        }).await.map(|outcome| outcome.map(|outcome| StartupOutcome {
            store: outcome.value, recovered: outcome.recovered, setup_created: false,
        }));
    }
    let mut animation = BrandAnimation::new(motion, palette, Instant::now(), screen.attachment_generation());
    if let Some(path) = restore {
        let store = restore_file(screen, &directory, Some(&path), bindings, palette, &mut animation).await?;
        if store.is_some() { screen.fence_authentication_input(); }
        return Ok(store.map(|store| StartupOutcome { store, recovered: false, setup_created: false }));
    }
    let mut choice = Form::new(
        "Welcome to vyx",
        vec![Field::inline(
            "Start",
            vec![
                "Set up Vyx".into(),
                "Restore from server".into(),
                "Restore encrypted file".into(),
            ],
            0,
        )],
    );
    choice.description = "Set up a local encrypted SSH workspace, or restore an existing vault from a server or encrypted file. Detach keeps the unlocked workspace running on this device; Quit stops it.".into();
    choice.submit = "Continue".into();
    while ask(screen, &mut choice, bindings, palette, &mut animation).await? {
        let store = match choice.fields[0].choice {
            0 => {
                let mut storage = storage_mode_form("Setup / 1 of 4: Storage");
                'storage: loop {
                    if !ask(screen, &mut storage, bindings, palette, &mut animation).await? {
                        break None;
                    }
                    let mut create = Form::new(
                        "Setup / 2 of 4: Vault",
                        vec![
                            Field::secret("New passphrase", "").with_hint("At least 16 characters."),
                            Field::secret("Repeat new passphrase", ""),
                        ],
                    );
                    create.description = "Keep this passphrase safe. The next step offers recovery protection: a forgotten passphrase cannot be reset without a matching recovery file.".into();
                    create.submit = "Create".into();
                    create.cancel = "Back".into();
                    while ask(screen, &mut create, bindings, palette, &mut animation).await? {
                        if create.value(0).chars().count() < 16 {
                            create.error = "Use at least 16 characters for the new passphrase.".into();
                            continue;
                        }
                        if create.value(0) != create.value(1) {
                            create.error = "Passphrases do not match.".into();
                            continue;
                        }
                        match busy(
                            screen,
                            "Creating encrypted vault…",
                            directory.create(Secret::new(create.value(0))),
                            bindings,
                            palette,
                            &mut animation,
                        ).await {
                            // Even a canceled accepted write must pass the outer existence guard.
                            Ok(value) => break 'storage value,
                            Err(error) => create.error = crate::screen::safe_text(&error.to_string()),
                        }
                    }
                }
            }
            1 => restore_server(screen, &directory, bindings, palette, &mut animation).await?,
            2 => restore_file(screen, &directory, None, bindings, palette, &mut animation).await?,
            _ => bail!("Invalid onboarding choice"),
        };
        if store.is_some() {
            screen.fence_authentication_input();
            return Ok(store.map(|store| StartupOutcome {
                store, recovered: false, setup_created: choice.fields[0].choice == 0,
            }));
        }
        // A canceled accepted write can finish off-loop. Never overwrite it.
        if directory.exists() {
            bail!("Vault creation finished; restart vyx to unlock it");
        }
    }
    Ok(None)
}
