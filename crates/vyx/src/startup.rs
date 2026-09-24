use std::{
    future::Future,
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Result, bail, ensure};
use crossterm::event::{Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::{
    style::{Color, Style},
    widgets::{Block, Borders, Paragraph},
};

use crate::{
    remote::{Remote, RemoteRead, canonical_origin},
    screen::Screen,
    ui::form::{Action, Field, Form},
    vault::{Directory, Secret, Store, SyncState, crypto::MAX_ENVELOPE},
};

pub async fn ask(screen: &mut Screen, form: &mut Form) -> Result<bool> {
    loop {
        screen
            .draw(|frame| {
                let area = frame.area();
                frame.render_widget(
                    Paragraph::new("vyx · encrypted SSH workspace")
                        .style(Style::default().fg(Color::Cyan)),
                    area,
                );
                form.draw(frame, area);
            })
            .await?;
        match screen.next_event().await? {
            None => return Ok(false),
            Some(Event::Key(key)) if key.kind != KeyEventKind::Release => {
                if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
                    return Ok(false);
                }
                match form.key(key) {
                    Action::Submit => return Ok(true),
                    Action::Cancel => return Ok(false),
                    Action::Continue => (),
                }
            }
            Some(Event::Paste(text)) => form.paste(&text),
            _ => (),
        }
    }
}

pub async fn busy<T>(
    screen: &mut Screen,
    message: &str,
    work: impl Future<Output = Result<T>>,
) -> Result<Option<T>> {
    tokio::pin!(work);
    loop {
        screen
            .draw(|frame| {
                let area = frame.area();
                frame.render_widget(
                    Paragraph::new(message)
                        .block(Block::default().title(" vyx ").borders(Borders::ALL)),
                    area,
                );
            })
            .await?;
        tokio::select! {
            result = &mut work => return result.map(Some),
            event = screen.next_event() => match event? {
                None => return Ok(None),
                Some(Event::Key(key)) if key.code == KeyCode::Esc || (key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL)) => return Ok(None),
                Some(Event::Resize(_, _)) => (),
                _ => continue,
            }
        }
    }
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
    while ask(screen, &mut form).await? {
        let file = PathBuf::from(form.value(0));
        let passphrase = Secret::new(form.value(1));
        let operation = async {
            let envelope = read_file(file).await?;
            directory.restore(envelope, passphrase, None).await
        };
        match busy(
            screen,
            "Decrypting and validating snapshot…  Esc: cancel",
            operation,
        )
        .await
        {
            Ok(store) => return Ok(store),
            Err(error) => form.error = crate::screen::safe_text(&error.to_string()),
        }
    }
    Ok(None)
}

async fn restore_server(screen: &mut Screen, directory: &Arc<Directory>) -> Result<Option<Store>> {
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
    while ask(screen, &mut form).await? {
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
            "Downloading encrypted vault…  Esc: cancel",
            remote.get(None),
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
        while ask(screen, &mut unlock).await? {
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
                "Decrypting and validating snapshot…  Esc: cancel",
                directory.restore(
                    download.envelope.clone(),
                    Secret::new(unlock.value(0)),
                    Some(settings),
                ),
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

pub async fn acquire(
    screen: &mut Screen,
    directory: Arc<Directory>,
    restore: Option<PathBuf>,
) -> Result<Option<Store>> {
    if directory.exists() {
        ensure!(
            restore.is_none(),
            "Restore refuses to overwrite an existing state.vyx"
        );
        let mut form = Form::new("Unlock vault", vec![Field::secret("Vault passphrase", "")]);
        form.description = "Hosts and credentials remain encrypted until unlocked.".into();
        form.submit = "Unlock".into();
        while ask(screen, &mut form).await? {
            match busy(
                screen,
                "Unlocking vault…  Esc: cancel",
                directory.unlock(Secret::new(form.value(0))),
            )
            .await
            {
                Ok(store) => return Ok(store),
                Err(error) => form.error = crate::screen::safe_text(&error.to_string()),
            }
        }
        return Ok(None);
    }
    if let Some(path) = restore {
        return restore_file(screen, &directory, Some(&path)).await;
    }
    let mut choice = Form::new(
        "Welcome to vyx",
        vec![Field::select(
            "Start",
            vec![
                "Create vault".into(),
                "Restore from server".into(),
                "Restore encrypted file".into(),
            ],
            0,
        )],
    );
    choice.description = "A local encrypted SSH workspace. Detach keeps the unlocked workspace running on this device; Quit stops it. Optional encrypted sync.".into();
    choice.submit = "Continue".into();
    while ask(screen, &mut choice).await? {
        let store = match choice.fields[0].choice {
            0 => {
                let mut create = Form::new(
                    "Create vault",
                    vec![
                        Field::secret("Passphrase (at least 16 characters)", ""),
                        Field::secret("Repeat passphrase", ""),
                    ],
                );
                create.description =
                    "Keep this passphrase safe: neither vyx nor your server can recover it.".into();
                create.submit = "Create".into();
                let mut created = None;
                while ask(screen, &mut create).await? {
                    if create.value(0).chars().count() < 16 {
                        create.error = "Use at least 16 characters".into();
                        continue;
                    }
                    if create.value(0) != create.value(1) {
                        create.error = "Passphrases do not match".into();
                        continue;
                    }
                    match busy(
                        screen,
                        "Creating encrypted vault…  Esc: cancel",
                        directory.create(Secret::new(create.value(0))),
                    )
                    .await
                    {
                        Ok(value) => {
                            created = value;
                            break;
                        }
                        Err(error) => create.error = crate::screen::safe_text(&error.to_string()),
                    }
                }
                created
            }
            1 => restore_server(screen, &directory).await?,
            2 => restore_file(screen, &directory, None).await?,
            _ => bail!("Invalid onboarding choice"),
        };
        if store.is_some() {
            return Ok(store);
        }
        // A canceled accepted write can finish off-loop. Never overwrite it.
        if directory.exists() {
            bail!("Vault creation finished; restart vyx to unlock it");
        }
    }
    Ok(None)
}
