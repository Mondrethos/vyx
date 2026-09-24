use std::collections::HashSet;

use anyhow::{Context, Result, bail, ensure};
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    Frame,
    layout::{Alignment, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
};
use tokio::io::AsyncReadExt;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    screen::safe_text,
    ssh::{PromptKind, PromptRequest},
    sync::{QuestionKind, SyncChoice, SyncQuestion},
    ui::form::{Action as FormAction, Field, Form},
    vault::{
        Auth, Category, Credential, Host, LocalState, Secret, Snippet, Vault, canonical_hostname,
    },
};

const MAX_PRIVATE_KEY: u64 = 64 * 1024;

pub enum Mutation {
    PutCategory {
        category: Category,
        create: bool,
    },
    DeleteCategory {
        id: Uuid,
    },
    PutCredential {
        credential: Credential,
        create: bool,
    },
    DeleteCredential {
        id: Uuid,
    },
    PutHost {
        host: Host,
        create: bool,
    },
    DeleteHost {
        id: Uuid,
    },
    PutSnippet {
        snippet: Snippet,
        create: bool,
    },
    DeleteSnippet {
        id: Uuid,
    },
    ForgetHostKey {
        hostname: String,
        port: u16,
    },
}

impl Mutation {
    pub fn apply(self, state: &mut LocalState) -> Result<()> {
        match self {
            Self::PutCategory { category, create } => {
                put_record(&mut state.vault.categories, category, create, |entry| {
                    entry.id
                })?;
            }
            Self::DeleteCategory { id } => {
                let index = state
                    .vault
                    .categories
                    .iter()
                    .position(|category| category.id == id)
                    .context("The category no longer exists")?;
                let parent = state.vault.categories[index].parent_id;
                state.vault.categories.remove(index);
                for category in &mut state.vault.categories {
                    if category.parent_id == Some(id) {
                        category.parent_id = parent;
                    }
                }
                for host in &mut state.vault.hosts {
                    if host.category_id == Some(id) {
                        host.category_id = parent;
                    }
                }
            }
            Self::PutCredential { credential, create } => {
                put_record(&mut state.vault.credentials, credential, create, |entry| {
                    entry.id
                })?;
            }
            Self::DeleteCredential { id } => {
                let credential = state
                    .vault
                    .credentials
                    .iter()
                    .find(|credential| credential.id == id)
                    .context("The credential no longer exists")?;
                let referenced: Vec<_> = state
                    .vault
                    .hosts
                    .iter()
                    .filter(|host| host.credential_id == id)
                    .map(|host| host.label.as_str())
                    .collect();
                ensure!(
                    referenced.is_empty(),
                    "Credential '{}' is used by: {}",
                    credential.label,
                    referenced.join(", ")
                );
                state
                    .vault
                    .credentials
                    .retain(|credential| credential.id != id);
            }
            Self::PutHost { host, create } => {
                put_record(&mut state.vault.hosts, host, create, |entry| entry.id)?;
            }
            Self::DeleteHost { id } => {
                let before = state.vault.hosts.len();
                state.vault.hosts.retain(|host| host.id != id);
                ensure!(
                    state.vault.hosts.len() != before,
                    "The server no longer exists"
                );
            }
            Self::PutSnippet { snippet, create } => {
                put_record(&mut state.vault.snippets, snippet, create, |entry| entry.id)?;
            }
            Self::DeleteSnippet { id } => {
                let before = state.vault.snippets.len();
                state.vault.snippets.retain(|snippet| snippet.id != id);
                ensure!(
                    state.vault.snippets.len() != before,
                    "The snippet no longer exists"
                );
            }
            Self::ForgetHostKey { hostname, port } => {
                let hostname = canonical_hostname(&hostname)?;
                let before = state.vault.known_hosts.len();
                state.vault.known_hosts.retain(|known| {
                    !(known.port == port && known.hostname.eq_ignore_ascii_case(&hostname))
                });
                ensure!(
                    state.vault.known_hosts.len() != before,
                    "No trusted key is saved for this server"
                );
            }
        }
        Ok(())
    }
}

fn put_record<T, F>(records: &mut Vec<T>, record: T, create: bool, id: F) -> Result<()>
where
    F: Fn(&T) -> Uuid,
{
    let record_id = id(&record);
    if create {
        ensure!(
            records.iter().all(|entry| id(entry) != record_id),
            "The record already exists"
        );
        records.push(record);
    } else {
        let target = records
            .iter_mut()
            .find(|entry| id(entry) == record_id)
            .context("The record no longer exists")?;
        *target = record;
    }
    Ok(())
}

pub enum EditorTarget {
    Category {
        id: Uuid,
        create: bool,
        parents: Vec<Option<Uuid>>,
    },
    Credential {
        id: Uuid,
        create: bool,
    },
    Host {
        id: Uuid,
        create: bool,
        categories: Vec<Option<Uuid>>,
        credentials: Vec<Uuid>,
    },
    Snippet {
        id: Uuid,
        create: bool,
    },
}

pub struct Editor {
    pub form: Form,
    pub target: EditorTarget,
}

impl Editor {
    pub fn category(vault: &Vault, id: Option<Uuid>, default_parent: Option<Uuid>) -> Result<Self> {
        let existing = id.and_then(|id| vault.categories.iter().find(|entry| entry.id == id));
        if id.is_some() && existing.is_none() {
            bail!("The category no longer exists");
        }
        let record_id = id.unwrap_or_else(Uuid::new_v4);
        let excluded = category_descendants(vault, record_id);
        let mut choices = vec![("Root".to_owned(), None)];
        let mut categories: Vec<_> = vault
            .categories
            .iter()
            .filter(|entry| entry.id != record_id && !excluded.contains(&entry.id))
            .collect();
        categories.sort_unstable_by(|left, right| {
            left.label
                .to_lowercase()
                .cmp(&right.label.to_lowercase())
                .then_with(|| left.id.cmp(&right.id))
        });
        choices.extend(categories.into_iter().map(|entry| {
            (
                format!(
                    "{} · {}",
                    category_path(vault, entry.id),
                    short_id(entry.id)
                ),
                Some(entry.id),
            )
        }));
        let parent = existing
            .map(|entry| entry.parent_id)
            .unwrap_or(default_parent);
        let choice = choices
            .iter()
            .position(|(_, id)| *id == parent)
            .unwrap_or(0);
        let mut form = Form::new(
            if existing.is_some() {
                "Edit category"
            } else {
                "Add category"
            },
            vec![
                Field::text(
                    "Label",
                    existing.map(|entry| entry.label.as_str()).unwrap_or(""),
                ),
                Field::select(
                    "Parent",
                    choices.iter().map(|(label, _)| label.clone()).collect(),
                    choice,
                ),
            ],
        );
        form.description =
            "Categories organize servers. Reparenting cannot create a cycle.".to_owned();
        Ok(Self {
            form,
            target: EditorTarget::Category {
                id: record_id,
                create: existing.is_none(),
                parents: choices.into_iter().map(|(_, id)| id).collect(),
            },
        })
    }

    pub fn credential(vault: &Vault, id: Option<Uuid>) -> Result<Self> {
        let existing = id.and_then(|id| vault.credentials.iter().find(|entry| entry.id == id));
        if id.is_some() && existing.is_none() {
            bail!("The credential no longer exists");
        }
        let auth_choice = existing
            .map(|entry| match &entry.auth {
                Auth::Password { .. } => 0,
                Auth::PrivateKey { .. } => 1,
                Auth::Agent => 2,
                Auth::KeyboardInteractive => 3,
            })
            .unwrap_or(0);
        let password = existing
            .and_then(|entry| match &entry.auth {
                Auth::Password { password } => Some(password.expose()),
                _ => None,
            })
            .unwrap_or("");
        let key_passphrase = existing
            .and_then(|entry| match &entry.auth {
                Auth::PrivateKey { passphrase, .. } => passphrase.as_ref().map(Secret::expose),
                _ => None,
            })
            .unwrap_or("");
        let mut form = Form::new(
            if existing.is_some() {
                "Edit credential"
            } else {
                "Add credential"
            },
            vec![
                Field::text(
                    "Label",
                    existing.map(|entry| entry.label.as_str()).unwrap_or(""),
                ),
                Field::text(
                    "Username",
                    existing.map(|entry| entry.username.as_str()).unwrap_or(""),
                ),
                Field::select(
                    "Authentication",
                    vec![
                        "Password".to_owned(),
                        "Imported private key".to_owned(),
                        "Local SSH agent".to_owned(),
                        "Keyboard-interactive".to_owned(),
                    ],
                    auth_choice,
                ),
                Field::secret("Password (password authentication only)", password),
                Field::text("Private key file (blank keeps imported key)", ""),
                Field::secret(
                    "Key passphrase (blank prompts when connecting)",
                    key_passphrase,
                ),
            ],
        );
        form.description = "Only fields for the chosen authentication method are used. Imported key contents are saved; the path is not. Agent profiles require a local agent on every device.".to_owned();
        Ok(Self {
            form,
            target: EditorTarget::Credential {
                id: id.unwrap_or_else(Uuid::new_v4),
                create: existing.is_none(),
            },
        })
    }

    pub fn host(vault: &Vault, id: Option<Uuid>, default_category: Option<Uuid>) -> Result<Self> {
        ensure!(
            !vault.credentials.is_empty(),
            "Add a credential before adding a server"
        );
        let existing = id.and_then(|id| vault.hosts.iter().find(|entry| entry.id == id));
        if id.is_some() && existing.is_none() {
            bail!("The server no longer exists");
        }
        let mut category_choices = vec![("Ungrouped".to_owned(), None)];
        let mut categories: Vec<_> = vault.categories.iter().collect();
        categories.sort_unstable_by(|left, right| {
            category_path(vault, left.id)
                .to_lowercase()
                .cmp(&category_path(vault, right.id).to_lowercase())
                .then_with(|| left.id.cmp(&right.id))
        });
        category_choices.extend(categories.into_iter().map(|entry| {
            (
                format!(
                    "{} · {}",
                    category_path(vault, entry.id),
                    short_id(entry.id)
                ),
                Some(entry.id),
            )
        }));
        let selected_category = existing
            .map(|entry| entry.category_id)
            .unwrap_or(default_category);
        let category_choice = category_choices
            .iter()
            .position(|(_, id)| *id == selected_category)
            .unwrap_or(0);

        let mut credentials: Vec<_> = vault.credentials.iter().collect();
        credentials.sort_unstable_by(|left, right| {
            left.label
                .to_lowercase()
                .cmp(&right.label.to_lowercase())
                .then_with(|| left.id.cmp(&right.id))
        });
        let credential_choice = existing
            .and_then(|host| {
                credentials
                    .iter()
                    .position(|credential| credential.id == host.credential_id)
            })
            .unwrap_or(0);
        let mut form = Form::new(
            if existing.is_some() {
                "Edit server"
            } else {
                "Add server"
            },
            vec![
                Field::text(
                    "Label",
                    existing.map(|entry| entry.label.as_str()).unwrap_or(""),
                ),
                Field::text(
                    "Hostname or IP",
                    existing.map(|entry| entry.hostname.as_str()).unwrap_or(""),
                ),
                Field::text(
                    "Port",
                    existing
                        .map(|entry| entry.port.to_string())
                        .unwrap_or_else(|| "22".to_owned()),
                ),
                Field::select(
                    "Category",
                    category_choices
                        .iter()
                        .map(|(label, _)| label.clone())
                        .collect(),
                    category_choice,
                ),
                Field::select(
                    "Credential",
                    credentials
                        .iter()
                        .map(|entry| {
                            format!(
                                "{} ({}) · {}",
                                entry.label,
                                entry.username,
                                short_id(entry.id)
                            )
                        })
                        .collect(),
                    credential_choice,
                ),
            ],
        );
        form.description =
            "Connection details are validated when saved; network access is not attempted."
                .to_owned();
        Ok(Self {
            form,
            target: EditorTarget::Host {
                id: id.unwrap_or_else(Uuid::new_v4),
                create: existing.is_none(),
                categories: category_choices.into_iter().map(|(_, id)| id).collect(),
                credentials: credentials.into_iter().map(|entry| entry.id).collect(),
            },
        })
    }

    pub fn snippet(vault: &Vault, id: Option<Uuid>) -> Result<Self> {
        let existing = id.and_then(|id| vault.snippets.iter().find(|entry| entry.id == id));
        if id.is_some() && existing.is_none() {
            bail!("The snippet no longer exists");
        }
        let mut form = Form::new(
            if existing.is_some() {
                "Edit snippet"
            } else {
                "Add snippet"
            },
            vec![
                Field::text(
                    "Label",
                    existing.map(|entry| entry.label.as_str()).unwrap_or(""),
                ),
                Field::text(
                    "Command (single line)",
                    existing.map(|entry| entry.command.as_str()).unwrap_or(""),
                ),
            ],
        );
        form.description =
            "Insertion never sends Enter. Review the exact command and execute it yourself."
                .to_owned();
        Ok(Self {
            form,
            target: EditorTarget::Snippet {
                id: id.unwrap_or_else(Uuid::new_v4),
                create: existing.is_none(),
            },
        })
    }

    pub async fn mutation(&self, vault: &Vault) -> Result<Mutation> {
        match &self.target {
            EditorTarget::Category {
                id,
                create,
                parents,
            } => {
                let parent_id = parents
                    .get(self.form.fields[1].choice)
                    .copied()
                    .context("Choose a category parent")?;
                Ok(Mutation::PutCategory {
                    category: Category {
                        id: *id,
                        label: required_trimmed(self.form.value(0), "Category label")?,
                        parent_id,
                    },
                    create: *create,
                })
            }
            EditorTarget::Credential { id, create } => {
                let auth = match self.form.fields[2].choice {
                    0 => {
                        let value = self.form.value(3);
                        ensure!(!value.is_empty(), "Password cannot be blank");
                        Auth::Password {
                            password: Secret::new(value),
                        }
                    }
                    1 => {
                        let path = self.form.value(4).trim();
                        let pem = if path.is_empty() {
                            match vault
                                .credentials
                                .iter()
                                .find(|credential| credential.id == *id)
                                .map(|credential| &credential.auth)
                            {
                                Some(Auth::PrivateKey { pem, .. }) => pem.clone(),
                                _ => bail!("Choose a private key file"),
                            }
                        } else {
                            read_private_key(path).await?
                        };
                        let passphrase = (!self.form.value(5).is_empty())
                            .then(|| Secret::new(self.form.value(5)));
                        let (pem, passphrase) = validate_private_key(pem, passphrase).await?;
                        Auth::PrivateKey { pem, passphrase }
                    }
                    2 => Auth::Agent,
                    3 => Auth::KeyboardInteractive,
                    _ => bail!("Choose an authentication method"),
                };
                Ok(Mutation::PutCredential {
                    credential: Credential {
                        id: *id,
                        label: required_trimmed(self.form.value(0), "Credential label")?,
                        username: required_trimmed(self.form.value(1), "Username")?,
                        auth,
                    },
                    create: *create,
                })
            }
            EditorTarget::Host {
                id,
                create,
                categories,
                credentials,
            } => {
                let port = self
                    .form
                    .value(2)
                    .trim()
                    .parse::<u16>()
                    .context("Port must be a number from 1 to 65535")?;
                ensure!(port != 0, "Port must be from 1 to 65535");
                let category_id = categories
                    .get(self.form.fields[3].choice)
                    .copied()
                    .context("Choose a category")?;
                let credential_id = credentials
                    .get(self.form.fields[4].choice)
                    .copied()
                    .context("Choose a credential")?;
                Ok(Mutation::PutHost {
                    host: Host {
                        id: *id,
                        label: required_trimmed(self.form.value(0), "Server label")?,
                        hostname: canonical_hostname(self.form.value(1).trim())?,
                        port,
                        category_id,
                        credential_id,
                    },
                    create: *create,
                })
            }
            EditorTarget::Snippet { id, create } => Ok(Mutation::PutSnippet {
                snippet: Snippet {
                    id: *id,
                    label: required_trimmed(self.form.value(0), "Snippet label")?,
                    command: self.form.value(1).to_owned(),
                },
                create: *create,
            }),
        }
    }
}

fn required_trimmed(value: &str, field: &str) -> Result<String> {
    let value = value.trim();
    ensure!(!value.is_empty(), "{field} cannot be blank");
    Ok(value.to_owned())
}

async fn read_private_key(path: &str) -> Result<Secret> {
    let file = tokio::fs::File::open(path)
        .await
        .with_context(|| format!("Cannot open private key file {path}"))?;
    let metadata = file
        .metadata()
        .await
        .context("Cannot inspect private key file")?;
    ensure!(metadata.is_file(), "Private key path is not a regular file");
    ensure!(
        metadata.len() <= MAX_PRIVATE_KEY,
        "Private key exceeds 64 KiB"
    );
    let mut pem = Zeroizing::new(String::with_capacity(metadata.len() as usize));
    file.take(MAX_PRIVATE_KEY + 1)
        .read_to_string(&mut pem)
        .await
        .context("Cannot read UTF-8 private key file")?;
    ensure!(
        pem.len() as u64 <= MAX_PRIVATE_KEY,
        "Private key exceeds 64 KiB"
    );
    Ok(Secret::new(std::mem::take(&mut *pem)))
}

async fn validate_private_key(
    pem: Secret,
    passphrase: Option<Secret>,
) -> Result<(Secret, Option<Secret>)> {
    tokio::task::spawn_blocking(move || {
        validate_private_key_blocking(pem.expose(), passphrase.as_ref().map(Secret::expose))?;
        Ok((pem, passphrase))
    })
    .await
    .context("Private key validation worker stopped")?
}

fn validate_private_key_blocking(pem: &str, passphrase: Option<&str>) -> Result<()> {
    match russh::keys::decode_secret_key(pem, passphrase) {
        Ok(key) => ensure_supported_algorithm(key.algorithm()),
        Err(russh::keys::Error::KeyIsEncrypted) if passphrase.is_none() => {
            let key = russh::keys::PrivateKey::from_openssh(pem)
                .context("Encrypted private key format is invalid")?;
            ensure!(key.is_encrypted(), "Private key could not be validated");
            ensure_supported_algorithm(key.algorithm())
        }
        Err(error) => Err(error).context("Private key or passphrase is invalid"),
    }
}

fn ensure_supported_algorithm(algorithm: russh::keys::Algorithm) -> Result<()> {
    ensure!(
        algorithm == russh::keys::Algorithm::Ed25519
            || matches!(&algorithm, russh::keys::Algorithm::Ecdsa { .. })
            || algorithm.is_rsa(),
        "Only Ed25519, ECDSA, and RSA private keys are supported"
    );
    Ok(())
}

fn category_descendants(vault: &Vault, root: Uuid) -> HashSet<Uuid> {
    let mut descendants = HashSet::new();
    let mut frontier = vec![root];
    while let Some(parent) = frontier.pop() {
        for category in &vault.categories {
            if category.parent_id == Some(parent) && descendants.insert(category.id) {
                frontier.push(category.id);
            }
        }
    }
    descendants
}

pub fn category_path(vault: &Vault, id: Uuid) -> String {
    let mut labels = Vec::new();
    let mut current = Some(id);
    while let Some(id) = current {
        let Some(category) = vault.categories.iter().find(|entry| entry.id == id) else {
            break;
        };
        labels.push(category.label.as_str());
        current = category.parent_id;
    }
    labels.reverse();
    labels.join(" / ")
}

fn short_id(id: Uuid) -> String {
    id.simple().to_string()[..8].to_owned()
}

pub enum ConfirmAction {
    DeleteCategory(Uuid),
    DeleteCredential(Uuid),
    DeleteHost(Uuid),
    DeleteSnippet(Uuid),
    ForgetHostKey { hostname: String, port: u16 },
    CloseSession(Uuid),
    DisableSync,
    Quit,
}

pub struct ConfirmDialog {
    pub form: Form,
    pub action: ConfirmAction,
}

impl ConfirmDialog {
    pub fn new(
        title: impl Into<String>,
        description: impl Into<String>,
        submit: impl Into<String>,
        action: ConfirmAction,
    ) -> Self {
        let mut form = Form::new(title, Vec::new());
        form.description = description.into();
        form.submit = submit.into();
        Self { form, action }
    }
}

pub struct AddMenu {
    pub form: Form,
    pub parent: Option<Uuid>,
}

impl AddMenu {
    pub fn new(parent: Option<Uuid>) -> Self {
        let mut form = Form::new(
            "Add to servers",
            vec![Field::select(
                "Record type",
                vec!["Server".to_owned(), "Category".to_owned()],
                0,
            )],
        );
        form.description =
            "Choose what to add. New records use the selected category as their initial parent."
                .to_owned();
        form.submit = "Continue".to_owned();
        Self { form, parent }
    }
}

pub struct FilterDialog {
    pub form: Form,
}

impl FilterDialog {
    pub fn new(current: &str) -> Self {
        let mut form = Form::new("Filter catalog", vec![Field::text("Search", current)]);
        form.description = "Matches labels, hostnames, usernames, category paths, and snippet commands. Secret values are never searched.".to_owned();
        form.submit = "Apply".to_owned();
        Self { form }
    }
}

pub struct PromptDialog {
    pub session_id: Uuid,
    pub form: Form,
    pub response: Option<tokio::sync::oneshot::Sender<Option<Vec<Secret>>>>,
    pub cancelled: tokio::sync::watch::Receiver<bool>,
}

impl PromptDialog {
    pub fn new(request: PromptRequest) -> Self {
        let fields = request
            .fields
            .into_iter()
            .map(|field| {
                if field.secret {
                    Field::secret(safe_text(&field.label), "")
                } else {
                    Field::text(safe_text(&field.label), "")
                }
            })
            .collect();
        let mut form = Form::new(safe_text(&request.title), fields);
        form.description = safe_text(&request.description);
        form.submit = match request.kind {
            PromptKind::Trust => "Trust and connect".to_owned(),
            PromptKind::Authentication => "Respond".to_owned(),
        };
        Self {
            session_id: request.session_id,
            form,
            response: Some(request.response),
            cancelled: request.cancelled,
        }
    }

    pub fn respond(&mut self, accepted: bool) {
        let response = accepted.then(|| {
            self.form
                .fields
                .iter()
                .map(|field| Secret::new(field.value.as_str()))
                .collect()
        });
        if let Some(sender) = self.response.take() {
            let _ = sender.send(response);
        }
    }
}

pub struct SnippetDialog {
    pub command: String,
    pub target: Option<Uuid>,
    pub target_label: String,
}

pub struct SyncSetupDialog {
    pub form: Form,
}

impl SyncSetupDialog {
    pub fn new(url: &str, token: &str) -> Self {
        let mut form = Form::new(
            "Sync settings",
            vec![
                Field::text("Server origin", url),
                Field::secret("Access token", token),
            ],
        );
        form.description = "HTTPS is required, except literal loopback HTTP for a local tunnel. The token is stored only inside this encrypted vault.".to_owned();
        form.submit = "Save settings".to_owned();
        Self { form }
    }
}

pub struct SyncQuestionDialog {
    pub form: Form,
    pub kind: QuestionKind,
}

impl SyncQuestionDialog {
    pub fn new(question: SyncQuestion) -> Self {
        let SyncQuestion { summary, kind } = question;
        let choices = match &kind {
            QuestionKind::Conflict => vec![
                "Keep this device".to_owned(),
                "Use server".to_owned(),
                "Cancel".to_owned(),
            ],
            QuestionKind::Upload => vec!["Upload this vault".to_owned(), "Cancel".to_owned()],
            QuestionKind::Recreate => vec!["Recreate server vault".to_owned(), "Cancel".to_owned()],
        };
        let mut form = Form::new(
            "Synchronization decision",
            vec![Field::select("Choice", choices, 0)],
        );
        form.description = safe_text(&summary);
        form.submit = "Confirm".to_owned();
        Self { form, kind }
    }

    pub fn choice(&self) -> SyncChoice {
        match &self.kind {
            QuestionKind::Conflict => match self.form.fields[0].choice {
                0 => SyncChoice::KeepLocal,
                1 => SyncChoice::UseServer,
                _ => SyncChoice::Cancel,
            },
            QuestionKind::Upload | QuestionKind::Recreate => {
                if self.form.fields[0].choice == 0 {
                    SyncChoice::KeepLocal
                } else {
                    SyncChoice::Cancel
                }
            }
        }
    }
}

pub enum Dialog {
    Editor(Editor),
    AddMenu(AddMenu),
    Filter(FilterDialog),
    Confirm(ConfirmDialog),
    Prompt(PromptDialog),
    Snippet(SnippetDialog),
    SyncSetup(SyncSetupDialog),
    SyncQuestion(SyncQuestionDialog),
    Help,
    Message { title: String, body: String },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DialogInput {
    Continue,
    Submit,
    Cancel,
}

impl Dialog {
    pub fn input(&mut self, key: KeyEvent) -> DialogInput {
        match self {
            Self::Editor(dialog) => form_input(&mut dialog.form, key),
            Self::AddMenu(dialog) => form_input(&mut dialog.form, key),
            Self::Filter(dialog) => form_input(&mut dialog.form, key),
            Self::Confirm(dialog) => form_input(&mut dialog.form, key),
            Self::Prompt(dialog) => form_input(&mut dialog.form, key),
            Self::SyncSetup(dialog) => form_input(&mut dialog.form, key),
            Self::SyncQuestion(dialog) => form_input(&mut dialog.form, key),
            Self::Snippet(_) => match key.code {
                KeyCode::Enter => DialogInput::Submit,
                KeyCode::Esc => DialogInput::Cancel,
                _ => DialogInput::Continue,
            },
            Self::Help | Self::Message { .. } => match key.code {
                KeyCode::Enter | KeyCode::Esc => DialogInput::Cancel,
                _ => DialogInput::Continue,
            },
        }
    }

    pub fn paste(&mut self, text: &str) {
        match self {
            Self::Editor(dialog) => dialog.form.paste(text),
            Self::AddMenu(dialog) => dialog.form.paste(text),
            Self::Filter(dialog) => dialog.form.paste(text),
            Self::Confirm(dialog) => dialog.form.paste(text),
            Self::Prompt(dialog) => dialog.form.paste(text),
            Self::SyncSetup(dialog) => dialog.form.paste(text),
            Self::SyncQuestion(dialog) => dialog.form.paste(text),
            Self::Snippet(_) | Self::Help | Self::Message { .. } => {}
        }
    }

    pub fn set_error(&mut self, error: impl Into<String>) {
        let error = safe_text(&error.into());
        match self {
            Self::Editor(dialog) => dialog.form.error = error,
            Self::AddMenu(dialog) => dialog.form.error = error,
            Self::Filter(dialog) => dialog.form.error = error,
            Self::Confirm(dialog) => dialog.form.error = error,
            Self::Prompt(dialog) => dialog.form.error = error,
            Self::SyncSetup(dialog) => dialog.form.error = error,
            Self::SyncQuestion(dialog) => dialog.form.error = error,
            Self::Snippet(_) | Self::Help | Self::Message { .. } => {}
        }
    }

    pub fn prompt_session(&self) -> Option<Uuid> {
        match self {
            Self::Prompt(dialog) => Some(dialog.session_id),
            _ => None,
        }
    }

    pub fn cancel_prompt(&mut self) {
        if let Self::Prompt(dialog) = self {
            dialog.respond(false);
        }
    }

    pub fn draw(&self, frame: &mut Frame, bounds: Rect) {
        match self {
            Self::Editor(dialog) => dialog.form.draw(frame, bounds),
            Self::AddMenu(dialog) => dialog.form.draw(frame, bounds),
            Self::Filter(dialog) => dialog.form.draw(frame, bounds),
            Self::Confirm(dialog) => dialog.form.draw(frame, bounds),
            Self::Prompt(dialog) => dialog.form.draw(frame, bounds),
            Self::SyncSetup(dialog) => dialog.form.draw(frame, bounds),
            Self::SyncQuestion(dialog) => dialog.form.draw(frame, bounds),
            Self::Snippet(dialog) => draw_text_dialog(
                frame,
                bounds,
                "Insert snippet",
                vec![
                    Line::from(vec![
                        Span::styled("Target: ", Style::default().fg(Color::Gray)),
                        Span::raw(if dialog.target.is_some() {
                            dialog.target_label.as_str()
                        } else {
                            "No live session"
                        }),
                    ]),
                    Line::from(""),
                    Line::from(Span::styled(
                        dialog.command.as_str(),
                        Style::default().fg(Color::White),
                    )),
                    Line::from(""),
                    Line::from(if dialog.target.is_some() {
                        "Enter: Insert without Enter   Esc: Cancel"
                    } else {
                        "Insert is disabled because there is no live target. Esc: Close"
                    }),
                ],
            ),
            Self::Help => draw_text_dialog(frame, bounds, "Help", help_lines()),
            Self::Message { title, body } => draw_text_dialog(
                frame,
                bounds,
                title,
                vec![
                    Line::from(body.as_str()),
                    Line::from(""),
                    Line::from("Enter/Esc: Close"),
                ],
            ),
        }
    }
}

fn form_input(form: &mut Form, key: KeyEvent) -> DialogInput {
    match form.key(key) {
        FormAction::Continue => DialogInput::Continue,
        FormAction::Submit => DialogInput::Submit,
        FormAction::Cancel => DialogInput::Cancel,
    }
}

fn draw_text_dialog(frame: &mut Frame, bounds: Rect, title: &str, lines: Vec<Line<'_>>) {
    let width = bounds.width.saturating_sub(4).min(86).max(1);
    let height = bounds.height.saturating_sub(2).min(24).max(1);
    let area = Rect::new(
        bounds.x + bounds.width.saturating_sub(width) / 2,
        bounds.y + bounds.height.saturating_sub(height) / 2,
        width,
        height,
    );
    frame.render_widget(Clear, area);
    let block = Block::default()
        .title(format!(" {} ", safe_text(title)))
        .title_alignment(Alignment::Center)
        .borders(Borders::ALL)
        .border_style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        );
    let inner = block.inner(area);
    frame.render_widget(block, area);
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
}

fn help_lines() -> Vec<Line<'static>> {
    vec![
        Line::from(Span::styled(
            "Global prefix",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(
            "Ctrl+B: b sidebar · n/p sessions · x close · s sync · d detach · q quit · ? help",
        ),
        Line::from("Ctrl+B twice sends a literal Ctrl+B; Escape cancels."),
        Line::from(""),
        Line::from(Span::styled(
            "Detach and quit",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(
            "Detach closes only this UI; the unlocked worker and SSH sessions keep running.",
        ),
        Line::from("Reattach on this device with vyx or vyx attach."),
        Line::from(
            "Quit disconnects sessions and ends the worker. Detached workers do not survive reboot.",
        ),
        Line::from(""),
        Line::from(Span::styled(
            "Sidebar",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from("↑/↓ or j/k select · ←/→ fold · Enter open/connect · q quit"),
        Line::from("a/e/d add/edit/delete · x close session · / filter · f forget key"),
        Line::from(
            "Actions manages records; [x] closes a tab; footer Detach and Quit are separate.",
        ),
        Line::from(""),
        Line::from(Span::styled(
            "Terminal",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from("Escape, Ctrl+C/D/Z, and other ordinary keys go to SSH."),
        Line::from("Shift+PageUp/Down scrolls history; paste honors bracketed-paste mode."),
        Line::from("r reconnects a closed/error tab when its host still exists."),
        Line::from(""),
        Line::from("Snippets insert without Enter. Sync never migrates live sessions."),
        Line::from("Enter/Esc: Close help"),
    ]
}
