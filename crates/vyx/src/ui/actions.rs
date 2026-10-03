use std::{borrow::Cow, collections::HashSet};

use anyhow::{Context, Result, bail, ensure};
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use ratatui::{
    Frame,
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Paragraph, Wrap},
};
use tokio::io::AsyncReadExt;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    screen::safe_text,
    shortcuts::{Bindings, Shortcut},
    ssh::{PromptKind, PromptRequest},
    sync::{QuestionKind, SyncChoice, SyncQuestion},
    theme::Palette,
    ui::{
        form::{Action as FormAction, Field, Form, FormHitRegion},
        render::contains,
        theming,
        widgets::{self, Button, ButtonKind},
    },
    vault::{
        Auth, Category, Credential, Host, HostAuth, HostTransport, TailscaleIdentity, LocalState, Secret, Snippet, Vault,
        canonical_hostname,
    },
};

const MAX_PRIVATE_KEY: u64 = 64 * 1024;

const HOST_AUTH_FIELD: usize = 4;
const HOST_CREDENTIAL_FIELD: usize = 5;
const HOST_USERNAME_FIELD: usize = 6;
const HOST_PASSWORD_FIELD: usize = 7;
const HOST_TRANSPORT_FIELD: usize = 8;

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
                    .filter(|host| host.auth.credential_id() == Some(id))
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
        credentials: Vec<(Uuid, String)>,
        tailscale: Option<TailscaleIdentity>,
        identity_hostname: Option<String>,
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
        let form = Form::new(
            if existing.is_some() {
                "Edit credential"
            } else {
                "Add credential"
            },
            vec![
                Field::text(
                    "Label *",
                    existing.map(|entry| entry.label.as_str()).unwrap_or(""),
                ).with_hint("A reusable name, for example: Production admin"),
                Field::text(
                    "Username *",
                    existing.map(|entry| entry.username.as_str()).unwrap_or(""),
                ).with_hint("The remote account, for example: deploy"),
                Field::inline(
                    "Authentication",
                    vec![
                        "Password".to_owned(),
                        "Imported private key".to_owned(),
                        "Local SSH agent".to_owned(),
                        "Keyboard-interactive".to_owned(),
                    ],
                    auth_choice,
                ),
                Field::secret("Password *", password),
                Field::text("Private key file", "")
                    .with_hint("Path to the key file; ~/ means your home folder. Blank keeps an existing imported key."),
                Field::secret("Key passphrase", key_passphrase)
                    .with_hint("Leave blank to prompt when connecting."),
            ],
        );
        let mut editor = Self {
            form,
            target: EditorTarget::Credential {
                id: id.unwrap_or_else(Uuid::new_v4),
                create: existing.is_none(),
            },
        };
        editor.configure_credential_auth_fields();
        Ok(editor)
    }

    pub fn host(vault: &Vault, id: Option<Uuid>, default_category: Option<Uuid>) -> Result<Self> {
        let existing = id.and_then(|id| vault.hosts.iter().find(|entry| entry.id == id));
        if id.is_some() && existing.is_none() {
            bail!("The server no longer exists");
        }
        Self::host_form(vault, existing, default_category, existing.is_none())
    }

    pub fn host_draft(vault: &Vault, draft: &Host) -> Result<Self> {
        Self::host_form(vault, Some(draft), draft.category_id, true)
    }

    fn host_form(vault: &Vault, existing: Option<&Host>, default_category: Option<Uuid>, create: bool) -> Result<Self> {
        let id = existing.map(|host| host.id);
        let tailscale = existing.and_then(|host| match &host.auth {
            HostAuth::Tailscale { tailscale, .. } => Some(tailscale.clone()),
            _ => None,
        });
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
            .and_then(|host| host.auth.credential_id())
            .and_then(|credential_id| {
                credentials
                    .iter()
                    .position(|credential| credential.id == credential_id)
            })
            .unwrap_or(0);
        let auth_choice = existing.map_or(usize::from(credentials.is_empty()), |host| {
            match &host.auth { HostAuth::Credential { .. } => 0, HostAuth::Password { .. } => 1, HostAuth::Tailscale { .. } => 2 }
        });
        let username = existing
            .and_then(|host| match &host.auth {
                HostAuth::Password { username, .. } | HostAuth::Tailscale { username, .. } => Some(username.as_str()),
                HostAuth::Credential { .. } => None,
            })
            .unwrap_or("");
        let password = existing
            .and_then(|host| match &host.auth {
                HostAuth::Password { password, .. } => Some(password.expose()),
                HostAuth::Credential { .. } | HostAuth::Tailscale { .. } => None,
            })
            .unwrap_or("");
        let form = Form::new(
            if !create {
                "Edit server"
            } else {
                "Add server"
            },
            vec![
                Field::text(
                    "Label",
                    existing.map(|entry| entry.label.as_str()).unwrap_or(""),
                ).with_hint("Shown in the sidebar and tabs, for example: Production web"),
                Field::text(
                    "Hostname or IP",
                    existing.map(|entry| entry.hostname.as_str()).unwrap_or(""),
                ).with_hint("Host name or address only, for example: web.example.com or 192.0.2.10"),
                Field::text(
                    "Port",
                    existing
                        .map(|entry| entry.port.to_string())
                        .unwrap_or_else(|| "22".to_owned()),
                ).with_hint("1–65535; SSH normally uses 22."),
                Field::select(
                    "Category",
                    category_choices
                        .iter()
                        .map(|(label, _)| label.clone())
                        .collect(),
                    category_choice,
                ),
                Field::inline(
                    "Authentication",
                    if tailscale.is_some() { vec!["Saved credential".into(), "Password".into(), "Tailscale SSH (keyless)".into()] } else { vec!["Saved credential".into(), "Password".into()] },
                    auth_choice,
                ),
                Field::select(
                    "Credential",
                    if credentials.is_empty() {
                        vec!["No saved credentials".to_owned()]
                    } else {
                        credentials.iter().map(|entry| {
                            format!(
                                "{} ({}) · {}",
                                entry.label,
                                entry.username,
                                short_id(entry.id)
                            )
                        }).collect()
                    },
                    credential_choice,
                )
                .with_hint(if credentials.is_empty() {
                    "No saved credentials are available. Choose Password instead."
                } else if credentials.len() == 1 {
                    "Only one saved credential. Choose Authentication: Password for a server-only login."
                } else {
                    "Choose a reusable entry managed under Credentials."
                }),
                Field::text("Username *", username)
                    .with_hint("Used only by this server; saved credentials are not changed."),
                Field::secret("Password *", password)
                    .with_hint("Encrypted in the vault and used only by this server."),
                Field::inline("Routing", vec!["Direct".into(), "Tailscale".into()],
                    usize::from(existing.is_some_and(|host| host.transport == HostTransport::Tailscale)))
                    .with_hint("Tailscale routing re-resolves the saved endpoint through the local Tailscale client."),
                Field::read_only("Tailnet identity", tailscale.as_ref().map(|identity| identity.tailnet_id.clone()).unwrap_or_default()),
                Field::read_only("Node identity", tailscale.as_ref().map(|identity| identity.node_id.clone()).unwrap_or_default()),
                Field::read_only("Identity-bound destination", existing.map(|host| host.hostname.clone()).unwrap_or_default()),
            ],
        );
        let mut editor = Self {
            form,
            target: EditorTarget::Host {
                id: id.unwrap_or_else(Uuid::new_v4),
                create,
                categories: category_choices.into_iter().map(|(_, id)| id).collect(),
                credentials: credentials
                    .into_iter()
                    .map(|entry| (entry.id, entry.username.clone()))
                    .collect(),
                identity_hostname: tailscale.as_ref().and_then(|_| existing.map(|host| host.hostname.clone())),
                tailscale,
            },
        };
        editor.configure_host_auth_fields();
        Ok(editor)
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

    fn input(&mut self, key: KeyEvent, bindings: &Bindings) -> DialogInput {
        let credential_auth = matches!(self.target, EditorTarget::Credential { .. })
            .then(|| self.form.fields[2].choice);
        let host_auth = matches!(self.target, EditorTarget::Host { .. })
            .then(|| self.form.fields[HOST_AUTH_FIELD].choice);
        let route = matches!(self.target, EditorTarget::Host { .. }).then(|| self.form.fields[HOST_TRANSPORT_FIELD].choice);
        let result = form_input(&mut self.form, key, bindings);
        if credential_auth.is_some_and(|previous| previous != self.form.fields[2].choice) {
            self.configure_credential_auth_fields();
        }
        if host_auth
            .is_some_and(|previous| previous != self.form.fields[HOST_AUTH_FIELD].choice) || route.is_some_and(|previous| previous != self.form.fields[HOST_TRANSPORT_FIELD].choice)
        {
            self.configure_host_auth_fields();
        }
        result
    }

    fn mouse(&mut self, mouse: MouseEvent, hits: &[FormHitRegion]) -> DialogInput {
        let credential_auth = matches!(self.target, EditorTarget::Credential { .. })
            .then(|| self.form.fields[2].choice);
        let host_auth = matches!(self.target, EditorTarget::Host { .. })
            .then(|| self.form.fields[HOST_AUTH_FIELD].choice);
        let route = matches!(self.target, EditorTarget::Host { .. }).then(|| self.form.fields[HOST_TRANSPORT_FIELD].choice);
        let result = self.form.mouse(mouse, hits);
        if credential_auth.is_some_and(|previous| previous != self.form.fields[2].choice) {
            self.configure_credential_auth_fields();
        }
        if host_auth
            .is_some_and(|previous| previous != self.form.fields[HOST_AUTH_FIELD].choice) || route.is_some_and(|previous| previous != self.form.fields[HOST_TRANSPORT_FIELD].choice)
        {
            self.configure_host_auth_fields();
        }
        dialog_input(result)
    }

    fn configure_credential_auth_fields(&mut self) {
        let choice = self.form.fields[2].choice;
        self.form.fields[3].visible = choice == 0;
        self.form.fields[4].visible = choice == 1;
        self.form.fields[5].visible = choice == 1;
        self.form.description = match choice {
            0 => "Password authentication. Fields marked * are required; the password is encrypted in your vault.",
            1 => "Private-key authentication. Key contents are encrypted in the vault; the source file is not needed afterward.",
            2 => "Agent authentication requires a running local SSH agent on each device. No password or private key is stored.",
            _ => "The SSH server will prompt when connecting, including any verification code. No authentication responses are saved.",
        }.to_owned();
    }

    fn configure_host_auth_fields(&mut self) {
        let choice = self.form.fields[HOST_AUTH_FIELD].choice;
        let password = choice == 1;
        let keyless = choice == 2;
        self.form.fields[HOST_CREDENTIAL_FIELD].visible = choice == 0;
        self.form.fields[HOST_USERNAME_FIELD].visible = password || keyless;
        self.form.fields[HOST_PASSWORD_FIELD].visible = password;
        self.form.fields[1].visible = !keyless;
        self.form.fields[2].visible = !keyless;
        for field in &mut self.form.fields[9..12] { field.visible = keyless; }
        if keyless {
            self.form.fields[HOST_TRANSPORT_FIELD].choice = 1;
            self.form.fields[2].set_value("22");
        } else if let EditorTarget::Host { tailscale, identity_hostname, .. } = &mut self.target {
            *tailscale = None;
            *identity_hostname = None;
            self.form.fields[HOST_AUTH_FIELD].choices.truncate(2);
        }
        if password && self.form.value(HOST_USERNAME_FIELD).is_empty()
            && let EditorTarget::Host { credentials, .. } = &self.target
            && let Some((_, username)) =
                credentials.get(self.form.fields[HOST_CREDENTIAL_FIELD].choice)
        {
            self.form.fields[HOST_USERNAME_FIELD].set_value(username);
        }
        self.form.description = if keyless {
            "Keyless Tailscale SSH uses port 22, the stable node identity and Tailscale-distributed host keys. No local credential is sent. Changing the node requires the reviewed device picker. Convert authentication explicitly before selecting Direct routing."
        } else if password {
            "This server uses its own username and password. The password is encrypted in the vault; saved credentials are not changed."
        } else {
            "This server uses a reusable saved credential. Connection details are validated when saved; network access is not attempted."
        }
        .to_owned();
    }

    /// Validates the draft in displayed field order. On failure, focus moves to the first
    /// invalid field and every draft value is kept.
    pub async fn mutation(&mut self, vault: &Vault) -> Result<Mutation> {
        let result = self.validate(vault).await;
        result.map_err(|Invalid(field, error)| {
            if self.form.fields.get(field).is_some_and(Field::editable) {
                self.form.focus = field;
            }
            error
        })
    }

    async fn validate(&self, vault: &Vault) -> Result<Mutation, Invalid> {
        match &self.target {
            EditorTarget::Category {
                id,
                create,
                parents,
            } => {
                let label = required_trimmed(self.form.value(0), "Category label").at(0)?;
                let parent_id = parents
                    .get(self.form.fields[1].choice)
                    .copied()
                    .context("Choose a category parent")
                    .at(1)?;
                Ok(Mutation::PutCategory {
                    category: Category {
                        id: *id,
                        label,
                        parent_id,
                    },
                    create: *create,
                })
            }
            EditorTarget::Credential { id, create } => {
                let label = required_trimmed(self.form.value(0), "Credential label").at(0)?;
                let username = required_trimmed(self.form.value(1), "Username").at(1)?;
                let auth = match self.form.fields[2].choice {
                    0 => {
                        let value = self.form.value(3);
                        check(!value.is_empty(), 3, "Password cannot be blank")?;
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
                                _ => return Err(Invalid::new(4, "Choose a private key file")),
                            }
                        } else {
                            read_private_key(path).await.at(4)?
                        };
                        let passphrase = (!self.form.value(5).is_empty())
                            .then(|| Secret::new(self.form.value(5)));
                        // A kept key was valid when saved, so a failure points at the passphrase.
                        let (pem, passphrase) = validate_private_key(pem, passphrase)
                            .await
                            .at(if path.is_empty() { 5 } else { 4 })?;
                        Auth::PrivateKey { pem, passphrase }
                    }
                    2 => Auth::Agent,
                    3 => Auth::KeyboardInteractive,
                    _ => return Err(Invalid::new(2, "Choose an authentication method")),
                };
                Ok(Mutation::PutCredential {
                    credential: Credential {
                        id: *id,
                        label,
                        username,
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
                tailscale,
                identity_hostname,
            } => {
                let label = required_trimmed(self.form.value(0), "Server label").at(0)?;
                let hostname = canonical_hostname(identity_hostname.as_deref().unwrap_or(self.form.value(1)).trim()).at(1)?;
                let port = self
                    .form
                    .value(2)
                    .trim()
                    .parse::<u16>()
                    .ok()
                    .filter(|port| *port != 0)
                    .context("Port must be a number from 1 to 65535")
                    .at(2)?;
                let category_id = categories
                    .get(self.form.fields[3].choice)
                    .copied()
                    .context("Choose a category")
                    .at(3)?;
                let transport = match self.form.fields[HOST_TRANSPORT_FIELD].choice {
                    0 => HostTransport::Direct,
                    1 => HostTransport::Tailscale,
                    _ => return Err(Invalid::new(HOST_TRANSPORT_FIELD, "Choose a routing mode")),
                };
                let auth = match self.form.fields[HOST_AUTH_FIELD].choice {
                    0 => {
                        let credential_id = credentials
                            .get(self.form.fields[HOST_CREDENTIAL_FIELD].choice)
                            .map(|(id, _)| *id)
                            .context("Choose a credential")
                            .at(HOST_CREDENTIAL_FIELD)?;
                        HostAuth::Credential { credential_id }
                    }
                    1 => {
                        let username = required_trimmed(self.form.value(HOST_USERNAME_FIELD), "Username")
                            .at(HOST_USERNAME_FIELD)?;
                        let password = self.form.value(HOST_PASSWORD_FIELD);
                        check(!password.is_empty(), HOST_PASSWORD_FIELD, "Password cannot be blank")?;
                        HostAuth::Password {
                            username,
                            password: Secret::new(password),
                        }
                    }
                    2 => {
                        let username = required_trimmed(self.form.value(HOST_USERNAME_FIELD), "Username")
                            .at(HOST_USERNAME_FIELD)?;
                        let tailscale = tailscale
                            .clone()
                            .context("Choose a Tailscale node through the reviewed device picker")
                            .at(HOST_AUTH_FIELD)?;
                        check(transport == HostTransport::Tailscale && port == 22, HOST_TRANSPORT_FIELD,
                            "Keyless Tailscale SSH requires Tailscale routing and port 22")?;
                        HostAuth::Tailscale { username, tailscale }
                    }
                    _ => return Err(Invalid::new(HOST_AUTH_FIELD, "Choose an authentication method")),
                };
                Ok(Mutation::PutHost {
                    host: Host {
                        id: *id,
                        label,
                        hostname,
                        port,
                        transport,
                        category_id,
                        auth,
                    },
                    create: *create,
                })
            }
            EditorTarget::Snippet { id, create } => {
                let label = required_trimmed(self.form.value(0), "Snippet label").at(0)?;
                let command = self.form.value(1);
                check(!command.trim().is_empty(), 1, "Command cannot be blank")?;
                Ok(Mutation::PutSnippet {
                    snippet: Snippet {
                        id: *id,
                        label,
                        command: command.to_owned(),
                    },
                    create: *create,
                })
            }
        }
    }
}

/// A failed editor check and the index of the field to focus for it.
struct Invalid(usize, anyhow::Error);

impl Invalid {
    fn new(field: usize, message: &'static str) -> Self {
        Self(field, anyhow::Error::msg(message))
    }
}

trait AtField<T> {
    /// Attributes an error to the editor field at `index`.
    fn at(self, index: usize) -> Result<T, Invalid>;
}

impl<T> AtField<T> for Result<T> {
    fn at(self, index: usize) -> Result<T, Invalid> {
        self.map_err(|error| Invalid(index, error))
    }
}

fn check(valid: bool, field: usize, message: &'static str) -> Result<(), Invalid> {
    if valid { Ok(()) } else { Err(Invalid::new(field, message)) }
}

fn required_trimmed(value: &str, field: &str) -> Result<String> {
    let value = value.trim();
    ensure!(!value.is_empty(), "{field} cannot be blank");
    Ok(value.to_owned())
}

async fn read_private_key(path: &str) -> Result<Secret> {
    let path = private_key_path(path)?;
    let file = tokio::fs::File::open(&path)
        .await
        .with_context(|| format!("Cannot open private key file {}", path.display()))?;
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

/// Expands only a bare `~` or a leading `~/` to the home directory. Every other character,
/// including `~user` and environment variables, stays literal.
fn private_key_path(path: &str) -> Result<std::path::PathBuf> {
    let rest = match path.strip_prefix('~') {
        Some(rest) if rest.is_empty() || rest.starts_with('/') => rest,
        _ => return Ok(path.into()),
    };
    let home = directories::BaseDirs::new()
        .context("Cannot expand ~ because your home directory is unknown; enter the full path")?;
    let mut expanded = home.home_dir().as_os_str().to_owned();
    expanded.push(rest);
    Ok(expanded.into())
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
        // Every confirmation guards a destructive or disconnecting action.
        form.submit_kind = ButtonKind::Danger;
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
            vec![Field::inline(
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
        if request.kind == PromptKind::Trust {
            // Appended after the identity so clipping at small sizes removes this advice first.
            form.description.push_str("\nVerify this fingerprint with your server administrator before accepting.");
        }
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

/// Previews a snippet for the session that was active when it opened. The target never
/// changes; Insert is disabled while that session is not connected.
pub struct SnippetDialog {
    pub command: String,
    pub target: Option<Uuid>,
    pub target_label: String,
    /// Whether `target` is still connected; the application refreshes it.
    pub available: bool,
    pub state: TextDialogState,
}

impl SnippetDialog {
    /// `target` is the connected session and its label, if any.
    pub fn new(command: String, target: Option<(Uuid, String)>) -> Self {
        let available = target.is_some();
        let (target, target_label) = target.map_or((None, String::new()), |(id, label)| (Some(id), label));
        Self { command, target, target_label, available, state: TextDialogState::default() }
    }

    fn draw(&mut self, frame: &mut Frame, bounds: Rect, bindings: &Bindings, palette: &Palette) {
        let Self { command, target, target_label, available, state } = self;
        let target: Cow<'_, str> = match (target, *available) {
            (Some(_), true) => Cow::Borrowed(target_label.as_str()),
            (Some(_), false) => Cow::Owned(format!("{target_label} (not connected)")),
            (None, _) => Cow::Borrowed("No live session"),
        };
        let content = vec![
            Line::from(vec![Span::styled("Target: ", Style::default().fg(palette.muted)), Span::raw(target)]),
            Line::from(""),
            Line::from(if *available {
                "Inserts the exact text above without Enter."
            } else {
                "No connected target; insertion is disabled."
            }),
        ];
        let buttons = [Button::primary("Insert").enabled(*available), Button::secondary("Cancel")];
        draw_text_dialog(frame, bounds, TextDialog {
            title: "Insert snippet",
            payload: Some(command.as_str()),
            content: Text::from(content),
            error: "",
            buttons: &buttons,
            selected: None,
            submit: available.then_some("insert"),
            cancel: Some("cancel"),
        }, bindings, state, palette);
    }
}

pub struct SyncSetupDialog {
    pub form: Form,
}

impl SyncSetupDialog {
    pub fn new(url: &str, token: &str) -> Self {
        let mut form = Form::new(
            "Settings / Vault synchronization",
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

/// A synchronization decision answered with one button per choice.
pub struct SyncQuestionDialog {
    pub summary: String,
    pub kind: QuestionKind,
    /// Highlighted button; Enter submits it.
    selected: usize,
    pub state: TextDialogState,
}

impl SyncQuestionDialog {
    pub fn new(question: SyncQuestion) -> Self {
        let SyncQuestion { summary, kind } = question;
        Self { summary: safe_text(&summary), kind, selected: 0, state: TextDialogState::default() }
    }

    /// Buttons in display order, with the answer each submits.
    fn choices(&self) -> (&'static [Button<'static>], &'static [SyncChoice]) {
        const CONFLICT: [Button<'static>; 3] =
            [Button::secondary("Keep this device"), Button::secondary("Use server"), Button::secondary("Cancel")];
        const UPLOAD: [Button<'static>; 2] = [Button::secondary("Upload this vault"), Button::secondary("Cancel")];
        const RECREATE: [Button<'static>; 2] = [Button::secondary("Recreate server vault"), Button::secondary("Cancel")];
        match self.kind {
            QuestionKind::Conflict => (&CONFLICT, &[SyncChoice::KeepLocal, SyncChoice::UseServer, SyncChoice::Cancel]),
            QuestionKind::Upload => (&UPLOAD, &[SyncChoice::KeepLocal, SyncChoice::Cancel]),
            QuestionKind::Recreate => (&RECREATE, &[SyncChoice::KeepLocal, SyncChoice::Cancel]),
        }
    }

    /// The answer of the highlighted button.
    pub fn choice(&self) -> SyncChoice {
        self.choices().1.get(self.selected).copied().unwrap_or(SyncChoice::Cancel)
    }

    fn input(&mut self, key: KeyEvent, bindings: &Bindings) -> DialogInput {
        let count = self.choices().1.len();
        match self.state.route(key, bindings, true) {
            Some(TextKey::Submit) => DialogInput::Submit,
            Some(TextKey::Cancel) => DialogInput::Cancel,
            Some(TextKey::Previous) => {
                self.selected = (self.selected + count - 1) % count;
                DialogInput::Continue
            }
            Some(TextKey::Next) => {
                self.selected = (self.selected + 1) % count;
                DialogInput::Continue
            }
            Some(TextKey::Scroll(_)) | None => DialogInput::Continue,
        }
    }

    /// A click submits the clicked choice.
    fn mouse(&mut self, mouse: MouseEvent) -> DialogInput {
        match self.state.mouse(mouse) {
            Some(index) => {
                self.selected = index;
                DialogInput::Submit
            }
            None => DialogInput::Continue,
        }
    }

    fn draw(&mut self, frame: &mut Frame, bounds: Rect, bindings: &Bindings, palette: &Palette) {
        let buttons = self.choices().0;
        draw_text_dialog(frame, bounds, TextDialog {
            title: "Synchronization decision",
            payload: None,
            content: Text::from(self.summary.as_str()),
            error: "",
            buttons,
            selected: Some(self.selected),
            submit: Some("confirm"),
            cancel: Some("cancel"),
        }, bindings, &mut self.state, palette);
    }
}

/// Host-owned review. The scrollable text and final action are never guest UI.
pub struct ExtensionReview {
    /// Identity of this review instance; continuations match it, never its text.
    pub id: Uuid,
    /// Title, submit/cancel captions and styling, and any error. An empty cancel caption
    /// hides the Cancel button; the Cancel key still cancels.
    pub form: Form,
    pub content: String,
    /// Exact text or keys being approved, shown verbatim before the explanation.
    pub payload: Option<String>,
    pub state: TextDialogState,
}

impl ExtensionReview {
    pub fn new(title: &str, content: String, submit: &str) -> Self {
        let mut form = Form::new(title, Vec::new());
        form.submit = submit.into();
        Self { id: Uuid::new_v4(), form, content, payload: None, state: TextDialogState::default() }
    }

    pub fn with_payload(mut self, payload: impl Into<String>) -> Self {
        self.payload = Some(payload.into());
        self
    }

    fn input(&mut self, key: KeyEvent, bindings: &Bindings) -> DialogInput {
        match self.state.route(key, bindings, false) {
            Some(TextKey::Submit) => DialogInput::Submit,
            Some(TextKey::Cancel) => DialogInput::Cancel,
            _ => DialogInput::Continue,
        }
    }

    fn mouse(&mut self, mouse: MouseEvent) -> DialogInput {
        match self.state.mouse(mouse) {
            Some(0) => DialogInput::Submit,
            Some(_) => DialogInput::Cancel,
            None => DialogInput::Continue,
        }
    }

    fn draw(&mut self, frame: &mut Frame, bounds: Rect, bindings: &Bindings, palette: &Palette) {
        let Self { form, content, payload, state, .. } = self;
        let buttons = [Button::new(&form.submit, form.submit_kind), Button::secondary(&form.cancel)];
        let shown = if form.cancel.is_empty() { 1 } else { 2 };
        let submit = hint_verb(&form.submit);
        let cancel = hint_verb(&form.cancel);
        draw_text_dialog(frame, bounds, TextDialog {
            title: &form.title,
            payload: payload.as_deref(),
            content: Text::from(content.as_str()),
            error: &form.error,
            buttons: &buttons[..shown],
            selected: None,
            submit: Some(&submit),
            cancel: (!cancel.is_empty()).then_some(cancel.as_str()),
        }, bindings, state, palette);
    }
}

/// A button caption as a hint verb: "Insert without Enter" becomes "insert without Enter".
fn hint_verb(caption: &str) -> String {
    let mut characters = caption.chars();
    characters.next().map(|first| first.to_lowercase().chain(characters).collect()).unwrap_or_default()
}

pub enum Dialog {
    Editor(Editor),
    ConnectionDraft(Editor),
    AddMenu(AddMenu),
    Confirm(ConfirmDialog),
    Prompt(PromptDialog),
    ExtensionReview(ExtensionReview),
    ExtensionDownload(ExtensionReview),
    AuthenticationNotice { session_id: Uuid, review: ExtensionReview, content_start: usize },
    Snippet(SnippetDialog),
    SyncQuestion(SyncQuestionDialog),
    /// Read-only details of a saved server, generated from the current vault when drawn.
    Preview { host: Uuid, state: TextDialogState },
    RenameSession { session_id: Uuid, form: Form },
    Message { title: String, body: String, state: TextDialogState },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DialogInput {
    Continue,
    Submit,
    Cancel,
}

impl Dialog {
    pub fn message(title: impl Into<String>, body: impl Into<String>) -> Self {
        Self::Message { title: title.into(), body: body.into(), state: TextDialogState::default() }
    }

    /// Read-only details of a saved server, generated from the current vault when drawn.
    pub fn preview(host: Uuid) -> Self {
        Self::Preview { host, state: TextDialogState::default() }
    }

    pub fn rename_session(session_id: Uuid, label: &str) -> Self {
        let mut form = Form::new("Rename session", vec![Field::text("Session name", label)]);
        form.description = "Change this session's tab and sidebar name without reconnecting. The saved server is unchanged. This name lasts until the session is closed.".into();
        form.submit = "Rename".into();
        Self::RenameSession { session_id, form }
    }

    pub fn input(&mut self, key: KeyEvent, bindings: &Bindings) -> DialogInput {
        match self {
            Self::Editor(dialog) | Self::ConnectionDraft(dialog) => dialog.input(key, bindings),
            Self::AddMenu(dialog) => form_input(&mut dialog.form, key, bindings),
            Self::Confirm(dialog) => form_input(&mut dialog.form, key, bindings),
            Self::Prompt(dialog) => form_input(&mut dialog.form, key, bindings),
            Self::ExtensionReview(dialog) | Self::ExtensionDownload(dialog) | Self::AuthenticationNotice { review: dialog, .. } => dialog.input(key, bindings),
            Self::SyncQuestion(dialog) => dialog.input(key, bindings),
            Self::RenameSession { form, .. } => form_input(form, key, bindings),
            Self::Snippet(dialog) => match dialog.state.route(key, bindings, false) {
                Some(TextKey::Submit) if dialog.available => DialogInput::Submit,
                Some(TextKey::Cancel) => DialogInput::Cancel,
                _ => DialogInput::Continue,
            },
            // Submit and Cancel both close a read-only dialog.
            Self::Preview { state, .. } | Self::Message { state, .. } => match state.route(key, bindings, false) {
                Some(TextKey::Submit | TextKey::Cancel) => DialogInput::Cancel,
                _ => DialogInput::Continue,
            },
        }
    }

    pub fn mouse(&mut self, mouse: MouseEvent, hits: &[FormHitRegion]) -> DialogInput {
        match self {
            Self::Editor(dialog) | Self::ConnectionDraft(dialog) => dialog.mouse(mouse, hits),
            Self::AddMenu(dialog) => dialog_input(dialog.form.mouse(mouse, hits)),
            Self::Confirm(dialog) => dialog_input(dialog.form.mouse(mouse, hits)),
            Self::Prompt(dialog) => dialog_input(dialog.form.mouse(mouse, hits)),
            Self::ExtensionReview(dialog) | Self::ExtensionDownload(dialog) | Self::AuthenticationNotice { review: dialog, .. } => dialog.mouse(mouse),
            Self::SyncQuestion(dialog) => dialog.mouse(mouse),
            Self::RenameSession { form, .. } => dialog_input(form.mouse(mouse, hits)),
            // Clicks outside the buttons never dismiss these dialogs.
            Self::Snippet(dialog) => match dialog.state.mouse(mouse) {
                Some(0) if dialog.available => DialogInput::Submit,
                Some(0) | None => DialogInput::Continue,
                Some(_) => DialogInput::Cancel,
            },
            Self::Preview { state, .. } | Self::Message { state, .. } => match state.mouse(mouse) {
                Some(_) => DialogInput::Cancel,
                None => DialogInput::Continue,
            },
        }
    }

    pub fn paste(&mut self, text: &str) {
        match self {
            Self::Editor(dialog) | Self::ConnectionDraft(dialog) => dialog.form.paste(text),
            Self::AddMenu(dialog) => dialog.form.paste(text),
            Self::Confirm(dialog) => dialog.form.paste(text),
            Self::Prompt(dialog) => dialog.form.paste(text),
            Self::ExtensionReview(dialog) | Self::ExtensionDownload(dialog) | Self::AuthenticationNotice { review: dialog, .. } => dialog.form.paste(text),
            Self::RenameSession { form, .. } => form.paste(text),
            Self::SyncQuestion(_) | Self::Snippet(_) | Self::Preview { .. } | Self::Message { .. } => {}
        }
    }

    pub fn set_error(&mut self, error: impl Into<String>) {
        let error = safe_text(&error.into());
        match self {
            Self::Editor(dialog) | Self::ConnectionDraft(dialog) => dialog.form.error = error,
            Self::AddMenu(dialog) => dialog.form.error = error,
            Self::Confirm(dialog) => dialog.form.error = error,
            Self::Prompt(dialog) => dialog.form.error = error,
            Self::ExtensionReview(dialog) | Self::ExtensionDownload(dialog) | Self::AuthenticationNotice { review: dialog, .. } => dialog.form.error = error,
            Self::RenameSession { form, .. } => form.error = error,
            Self::SyncQuestion(_) | Self::Snippet(_) | Self::Preview { .. } | Self::Message { .. } => {}
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

    pub fn draw(
        &mut self,
        frame: &mut Frame,
        bounds: Rect,
        vault: &Vault,
        bindings: &Bindings,
        hits: &mut Vec<FormHitRegion>,
        palette: &Palette,
    ) {
        match self {
            Self::Editor(dialog) | Self::ConnectionDraft(dialog) => dialog.form.draw(frame, bounds, bindings, hits, palette),
            Self::AddMenu(dialog) => dialog.form.draw(frame, bounds, bindings, hits, palette),
            Self::Confirm(dialog) => dialog.form.draw(frame, bounds, bindings, hits, palette),
            Self::Prompt(dialog) => dialog.form.draw(frame, bounds, bindings, hits, palette),
            Self::ExtensionReview(dialog) | Self::ExtensionDownload(dialog) | Self::AuthenticationNotice { review: dialog, .. } => dialog.draw(frame, bounds, bindings, palette),
            Self::SyncQuestion(dialog) => dialog.draw(frame, bounds, bindings, palette),
            Self::RenameSession { form, .. } => {
                if bounds.height < form.preferred_dialog_height(bounds.width).saturating_add(2) {
                    form.draw_panel(frame, bounds, bindings, hits, palette);
                } else {
                    form.draw(frame, bounds, bindings, hits, palette);
                }
            }
            Self::Snippet(dialog) => dialog.draw(frame, bounds, bindings, palette),
            Self::Preview { host, state } => {
                let mut lines = host_details(vault, *host, palette);
                lines.push(Line::from(""));
                lines.push(Line::from("Read-only preview; existing sessions keep running."));
                draw_text_dialog(frame, bounds, TextDialog::read_only("Destination preview", Text::from(lines)), bindings, state, palette);
            }
            Self::Message { title, body, state } => {
                draw_text_dialog(frame, bounds, TextDialog::read_only(title, Text::from(body.as_str())), bindings, state, palette);
            }
        }
    }
}

/// User-facing name of a credential's authentication method; never any secret material.
pub fn auth_label(auth: &Auth) -> &'static str {
    match auth {
        Auth::Password { .. } => "Password",
        Auth::PrivateKey { .. } => "Imported private key",
        Auth::Agent => "Local SSH agent",
        Auth::KeyboardInteractive => "Keyboard-interactive",
    }
}

/// User-facing name of how a server is reached.
pub fn routing_label(transport: HostTransport) -> &'static str {
    match transport {
        HostTransport::Direct => "Direct",
        HostTransport::Tailscale => "Tailscale",
    }
}

pub fn host_details<'a>(vault: &'a Vault, id: Uuid, palette: &Palette) -> Vec<Line<'a>> {
    let Some(host) = vault.hosts.iter().find(|entry| entry.id == id) else {
        return vec![Line::from("The saved server no longer exists.")];
    };
    let credential = host
        .auth
        .credential_id()
        .and_then(|id| vault.credentials.iter().find(|entry| entry.id == id));
    let category = host.category_id.map(|id| category_path(vault, id))
        .unwrap_or_else(|| "Ungrouped".to_owned());
    let trusted = vault.known_hosts.iter().any(|known| {
        known.hostname.eq_ignore_ascii_case(&host.hostname) && known.port == host.port
    });
    let (username, credential_label, authentication) = match &host.auth {
        HostAuth::Credential { .. } => (
            credential.map_or("missing", |entry| entry.username.as_str()),
            credential.map_or("missing", |entry| entry.label.as_str()),
            credential.map_or("Missing credential", |credential| match &credential.auth {
                Auth::Password { .. } => "Password",
                Auth::PrivateKey { .. } => "Imported private key",
                Auth::Agent => "Local SSH agent (required on this device)",
                Auth::KeyboardInteractive => "Keyboard-interactive",
            }),
        ),
        HostAuth::Password { username, .. } => (
            username.as_str(),
            "Server-specific",
            "Password (server-specific)",
        ),
        HostAuth::Tailscale { username, .. } => (username.as_str(), "None", "Keyless Tailscale SSH; distributed host keys"),
    };
    vec![
        Line::from(Span::styled(safe_text(&host.label), Style::default().fg(palette.accent).add_modifier(Modifier::BOLD))),
        Line::from(format!("Hostname: {}", safe_text(&host.hostname))),
        Line::from(format!("Port: {}", host.port)),
        Line::from(format!("Username: {}", safe_text(username))),
        Line::from(format!("Credential: {}", safe_text(credential_label))),
        Line::from(format!("Authentication: {authentication}")),
        Line::from(format!("Routing: {}", routing_label(host.transport))),
        Line::from(format!("Category: {}", safe_text(&category))),
        Line::from(format!("Trusted key: {}", if matches!(host.auth, HostAuth::Tailscale { .. }) { "Tailscale-distributed; ordinary Forget key does not apply" } else if trusted { "saved; checked when connecting" } else { "not yet accepted" })),
    ]
}

fn form_input(form: &mut Form, key: KeyEvent, bindings: &Bindings) -> DialogInput {
    dialog_input(form.key(key, bindings))
}

fn dialog_input(action: FormAction) -> DialogInput {
    match action {
        FormAction::Continue => DialogInput::Continue,
        FormAction::Submit => DialogInput::Submit,
        FormAction::Cancel => DialogInput::Cancel,
    }
}

/// Widest review or text dialog, including its border.
const TEXT_DIALOG_MAX_WIDTH: u16 = 100;
/// Short content still gets a dialog this wide when the terminal allows it.
const TEXT_DIALOG_MIN_WIDTH: u16 = 40;
/// Longer errors wrap to this many rows above the buttons.
const TEXT_ERROR_ROWS: u16 = 3;
/// Rows one mouse-wheel step scrolls.
const WHEEL_ROWS: i32 = 3;

/// Scroll position and last drawn geometry of a review or text dialog. Drawing records the
/// scroll limit, the body, and the enabled buttons; input clamps to the recorded limit.
#[derive(Debug, Default)]
pub struct TextDialogState {
    pub scroll: u16,
    pub max_scroll: u16,
    /// Scrollable body; the mouse wheel scrolls only over it.
    pub body: Rect,
    /// Index and rectangle of each enabled button.
    pub hits: Vec<(usize, Rect)>,
}

impl TextDialogState {
    /// Applies a scroll key; returns any other dialog key.
    fn route(&mut self, key: KeyEvent, bindings: &Bindings, choices: bool) -> Option<TextKey> {
        let action = text_key(key, bindings, choices)?;
        let TextKey::Scroll(scroll) = action else {
            return Some(action);
        };
        let page = i32::from(self.body.height.saturating_sub(1).max(1));
        match scroll {
            Scroll::Up => self.scroll_by(-1),
            Scroll::Down => self.scroll_by(1),
            Scroll::PageUp => self.scroll_by(-page),
            Scroll::PageDown => self.scroll_by(page),
            Scroll::Start => self.scroll = 0,
            Scroll::End => self.scroll = self.max_scroll,
        }
        None
    }

    fn scroll_by(&mut self, rows: i32) {
        self.scroll = (i32::from(self.scroll) + rows).clamp(0, i32::from(self.max_scroll)) as u16;
    }

    /// Scrolls for the wheel over the body; returns the enabled button under a left click.
    fn mouse(&mut self, mouse: MouseEvent) -> Option<usize> {
        match mouse.kind {
            MouseEventKind::Down(MouseButton::Left) => self.hits.iter()
                .find(|(_, area)| contains(*area, mouse.column, mouse.row))
                .map(|&(index, _)| index),
            MouseEventKind::ScrollUp | MouseEventKind::ScrollDown if contains(self.body, mouse.column, mouse.row) => {
                self.scroll_by(if mouse.kind == MouseEventKind::ScrollUp { -WHEEL_ROWS } else { WHEEL_ROWS });
                None
            }
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Scroll {
    Up,
    Down,
    PageUp,
    PageDown,
    Start,
    End,
}

/// What a key does in a review or text dialog.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TextKey {
    Submit,
    Cancel,
    /// Highlights the previous or next button of a dialog that chooses between its buttons.
    Previous,
    Next,
    Scroll(Scroll),
}

/// Configured keys in priority order: Submit and Cancel, button choice, then the menu
/// navigation bindings. Menu navigation stays outside the dialog shortcut context, so stored
/// Submit/Cancel customizations remain valid.
const TEXT_BINDINGS: [(Shortcut, TextKey); 10] = [
    (Shortcut::Submit, TextKey::Submit),
    (Shortcut::Cancel, TextKey::Cancel),
    (Shortcut::PreviousChoice, TextKey::Previous),
    (Shortcut::NextChoice, TextKey::Next),
    (Shortcut::MenuPrevious, TextKey::Scroll(Scroll::Up)),
    (Shortcut::MenuNext, TextKey::Scroll(Scroll::Down)),
    (Shortcut::MenuPageUp, TextKey::Scroll(Scroll::PageUp)),
    (Shortcut::MenuPageDown, TextKey::Scroll(Scroll::PageDown)),
    (Shortcut::MenuFirst, TextKey::Scroll(Scroll::Start)),
    (Shortcut::MenuLast, TextKey::Scroll(Scroll::End)),
];

/// Unmodified keys that keep working when the configured actions use other keys, labelled as
/// shortcut settings label them.
const TEXT_FALLBACKS: [(KeyCode, &str, TextKey); 10] = [
    (KeyCode::Left, "Left", TextKey::Previous),
    (KeyCode::Right, "Right", TextKey::Next),
    (KeyCode::Tab, "Tab", TextKey::Next),
    (KeyCode::BackTab, "Shift+Tab", TextKey::Previous),
    (KeyCode::Up, "Up", TextKey::Scroll(Scroll::Up)),
    (KeyCode::Down, "Down", TextKey::Scroll(Scroll::Down)),
    (KeyCode::PageUp, "PageUp", TextKey::Scroll(Scroll::PageUp)),
    (KeyCode::PageDown, "PageDown", TextKey::Scroll(Scroll::PageDown)),
    (KeyCode::Home, "Home", TextKey::Scroll(Scroll::Start)),
    (KeyCode::End, "End", TextKey::Scroll(Scroll::End)),
];

/// Routes a key: configured bindings first, then unmodified fallbacks. Button choice applies
/// only to dialogs with `choices`.
fn text_key(key: KeyEvent, bindings: &Bindings, choices: bool) -> Option<TextKey> {
    let applies = |action: TextKey| choices || !matches!(action, TextKey::Previous | TextKey::Next);
    if let Some(&(_, action)) = TEXT_BINDINGS.iter()
        .find(|&&(shortcut, action)| applies(action) && bindings.matches(shortcut, key))
    {
        return Some(action);
    }
    // Terminals usually report Shift+Tab as BackTab that still carries Shift.
    let modifiers = if key.code == KeyCode::BackTab { key.modifiers.difference(KeyModifiers::SHIFT) } else { key.modifiers };
    if key.kind == KeyEventKind::Release || !modifiers.is_empty() {
        return None;
    }
    TEXT_FALLBACKS.iter()
        .find(|&&(code, _, action)| code == key.code && applies(action))
        .map(|&(_, _, action)| action)
}

/// Label of a key that reaches `action`: its configured primary key unless a higher-priority
/// binding claims that key, otherwise an unmodified fallback that does.
fn reaching_key(bindings: &Bindings, action: TextKey, choices: bool) -> Option<&str> {
    TEXT_BINDINGS.iter()
        .filter(|&&(_, target)| target == action)
        .find_map(|&(shortcut, _)| {
            let key = bindings.primary_event(shortcut)?;
            (text_key(key, bindings, choices) == Some(action)).then(|| bindings.primary(shortcut))
        })
        .or_else(|| TEXT_FALLBACKS.iter()
            .filter(|&&(_, _, target)| target == action)
            .find_map(|&(code, label, _)| {
                let modifiers = if code == KeyCode::BackTab { KeyModifiers::SHIFT } else { KeyModifiers::NONE };
                (text_key(KeyEvent::new(code, modifiers), bindings, choices) == Some(action)).then_some(label)
            }))
}

/// Key hints in priority order, naming only keys that reach their action. Scroll keys are
/// listed only while the body overflows.
fn text_hints(bindings: &Bindings, submit: Option<&str>, cancel: Option<&str>, choices: bool, scrollable: bool) -> Vec<String> {
    let reach = |action| reaching_key(bindings, action, choices);
    let mut hints = Vec::new();
    for (verb, action) in [(submit, TextKey::Submit), (cancel, TextKey::Cancel)] {
        if let Some(verb) = verb && let Some(key) = reach(action) {
            hints.push(format!("{key} {verb}"));
        }
    }
    // Verbs for both keys, the first alone, and the second alone.
    let mut pair = |first, second, [both, first_verb, second_verb]: [&str; 3]| {
        hints.extend(match (reach(first), reach(second)) {
            (Some(first), Some(second)) => Some(format!("{first}/{second} {both}")),
            (Some(key), None) => Some(format!("{key} {first_verb}")),
            (None, Some(key)) => Some(format!("{key} {second_verb}")),
            (None, None) => None,
        });
    };
    if choices {
        pair(TextKey::Previous, TextKey::Next, ["choose", "previous", "next"]);
    }
    if scrollable {
        pair(TextKey::Scroll(Scroll::Up), TextKey::Scroll(Scroll::Down), ["scroll", "scroll up", "scroll down"]);
        pair(TextKey::Scroll(Scroll::PageUp), TextKey::Scroll(Scroll::PageDown), ["page", "page up", "page down"]);
        pair(TextKey::Scroll(Scroll::Start), TextKey::Scroll(Scroll::End), ["top/bottom", "top", "bottom"]);
    }
    hints
}

/// `hints` packed into at most `rows` lines of `width` cells, highest priority first; a hint
/// that does not fit is omitted rather than clipped.
fn pack_hints(hints: Vec<String>, width: u16, rows: u16) -> Vec<String> {
    let width = usize::from(width);
    let mut lines: Vec<String> = Vec::new();
    for hint in hints {
        let hint_width = widgets::width(&hint);
        if hint_width > width {
            continue;
        }
        if let Some(line) = lines.last_mut()
            && widgets::width(line) + 3 + hint_width <= width
        {
            line.push_str(" · ");
            line.push_str(&hint);
        } else if lines.len() < usize::from(rows) {
            lines.push(hint);
        }
    }
    lines
}

/// What a review or text dialog shows.
struct TextDialog<'a> {
    title: &'a str,
    /// Exact text being approved, boxed verbatim before the explanation.
    payload: Option<&'a str>,
    content: Text<'a>,
    error: &'a str,
    buttons: &'a [Button<'a>],
    /// Highlighted button of a dialog that chooses between its buttons.
    selected: Option<usize>,
    /// Hint verbs for the Submit key, and for the Cancel key while its button is shown.
    submit: Option<&'a str>,
    cancel: Option<&'a str>,
}

impl<'a> TextDialog<'a> {
    /// A dialog whose Close button, Submit, and Cancel all close it.
    fn read_only(title: &'a str, content: Text<'a>) -> Self {
        const CLOSE: &[Button<'static>] = &[Button::primary("Close")];
        Self { title, payload: None, content, error: "", buttons: CLOSE, selected: None, submit: Some("close"), cancel: None }
    }
}

/// Body rows at one text width, with the hint lines that leave room for it.
struct TextLayout {
    /// Text columns; a scrolling body gives its last column to the scrollbar.
    width: u16,
    /// The boxed payload, including its border.
    payload_rows: u16,
    /// Payload and content rows together.
    rows: u16,
    hints: Vec<String>,
    hint_rows: u16,
    /// Visible body rows.
    body_rows: u16,
}

fn row_count(lines: usize) -> u16 {
    u16::try_from(lines).unwrap_or(u16::MAX)
}

/// Draws a content-sized dialog centred above the status row: the title, then one scrollable
/// body holding the optional boxed payload and the content, any error, and the buttons with
/// key hints at the bottom. Records the body, scroll limit, and button hits in `state` and
/// clamps its scroll to the new limit.
fn draw_text_dialog(
    frame: &mut Frame,
    bounds: Rect,
    dialog: TextDialog<'_>,
    bindings: &Bindings,
    state: &mut TextDialogState,
    palette: &Palette,
) {
    let TextDialog { title, payload, content, error, buttons, selected, submit, cancel } = dialog;
    state.hits.clear();
    let available = Rect { height: bounds.height.saturating_sub(1), ..bounds };
    let max_width = available.width.saturating_sub(2).min(TEXT_DIALOG_MAX_WIDTH);
    let natural = [
        content.width(),
        payload.map_or(0, |payload| payload.lines().map(widgets::width).max().unwrap_or(0) + 2),
        widgets::width(title) + 2,
        buttons.iter().map(|button| widgets::width(button.caption) + 3).sum::<usize>().saturating_sub(1),
    ].into_iter().max().unwrap_or(0).saturating_add(2);
    let width = row_count(natural).max(TEXT_DIALOG_MIN_WIDTH).min(max_width);
    let inner_width = width.saturating_sub(2);
    let inner_limit = available.height.saturating_sub(2);
    // Buttons stay visible first, then at least one body row, then the error and hints.
    let button_rows = widgets::button_rows(inner_width, buttons).max(1).min(inner_limit);
    let error_rows = if error.is_empty() {
        0
    } else {
        row_count(Paragraph::new(error).wrap(Wrap { trim: false }).line_count(inner_width)).clamp(1, TEXT_ERROR_ROWS)
    }.min(inner_limit.saturating_sub(button_rows + 1));
    let free = inner_limit.saturating_sub(button_rows + error_rows);
    let payload = payload.map(|payload| {
        Paragraph::new(Text::styled(payload, Style::default().fg(palette.foreground).add_modifier(Modifier::BOLD)))
            .wrap(Wrap { trim: false })
    });
    let content = Paragraph::new(content).wrap(Wrap { trim: false });
    let hint_limit = if inner_width >= 60 { 1 } else { 2 };
    let measure = |scrollable: bool| {
        let width = inner_width.saturating_sub(u16::from(scrollable));
        let payload_rows = payload.as_ref()
            .map_or(0, |payload| row_count(payload.line_count(width.saturating_sub(2))).saturating_add(2));
        let rows = payload_rows.saturating_add(row_count(content.line_count(width)));
        let hints = pack_hints(text_hints(bindings, submit, cancel, selected.is_some(), scrollable), inner_width, hint_limit);
        let hint_rows = row_count(hints.len()).min(free.saturating_sub(1));
        TextLayout { width, payload_rows, rows, hints, hint_rows, body_rows: rows.min(free - hint_rows) }
    };
    let fitted = measure(false);
    // Overflow costs a scrollbar column and adds scroll hints, so the body only grows taller.
    let layout = if fitted.rows > fitted.body_rows { measure(true) } else { fitted };

    let height = layout.body_rows + error_rows + button_rows + layout.hint_rows + 2;
    let area = Rect::new(
        available.x + (available.width - width) / 2,
        available.y + available.height.saturating_sub(height) / 2,
        width,
        height.min(available.height),
    );
    theming::clear(frame, area, palette);
    let block = Block::default()
        .borders(Borders::ALL)
        .style(palette.style())
        .border_style(Style::default().fg(palette.accent))
        .title(format!(" {} ", widgets::fit(title, inner_width.saturating_sub(2))));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let body = Rect { height: layout.body_rows.min(inner.height), ..inner };
    state.body = body;
    state.max_scroll = layout.rows.saturating_sub(body.height);
    state.scroll = state.scroll.min(state.max_scroll);
    let (top, bottom) = (state.scroll, state.scroll.saturating_add(body.height));
    if let Some(payload) = payload {
        let end = layout.payload_rows.min(bottom);
        if top < end {
            let mut borders = Borders::LEFT | Borders::RIGHT;
            if top == 0 {
                borders |= Borders::TOP;
            }
            if end == layout.payload_rows {
                borders |= Borders::BOTTOM;
            }
            let block = Block::default().borders(borders).border_style(Style::default().fg(palette.border));
            // Payload text starts below the box's top border.
            frame.render_widget(
                payload.block(block).scroll((top.saturating_sub(1), 0)),
                Rect::new(body.x, body.y, layout.width, end - top),
            );
        }
    }
    let start = layout.payload_rows.max(top);
    let end = layout.rows.min(bottom);
    if start < end {
        frame.render_widget(
            content.scroll((start - layout.payload_rows, 0)),
            Rect::new(body.x, body.y + (start - top), layout.width, end - start),
        );
    }
    if state.max_scroll > 0 {
        widgets::draw_scrollbar(frame, body, usize::from(state.scroll), usize::from(layout.rows), palette);
    }

    let mut y = body.bottom();
    if error_rows > 0 {
        frame.render_widget(
            Paragraph::new(error).wrap(Wrap { trim: false }).style(Style::default().fg(palette.error)),
            Rect::new(inner.x, y, inner.width, error_rows),
        );
        y += error_rows;
    }
    let hits = &mut state.hits;
    widgets::draw_buttons(frame, Rect::new(inner.x, y, inner.width, button_rows), buttons, selected, palette, |index, area| {
        hits.push((index, area));
    });
    frame.render_widget(
        Paragraph::new(layout.hints.into_iter().map(Line::from).collect::<Vec<_>>()).style(Style::default().fg(palette.muted)),
        Rect::new(inner.x, y + button_rows, inner.width, layout.hint_rows),
    );
}

