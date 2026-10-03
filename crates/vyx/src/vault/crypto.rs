use std::io::{self, Read, Write};
use std::iter;

use age::secrecy::{ExposeSecret, SecretString};
use anyhow::{Context, Result, anyhow, bail, ensure};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::model::{LocalDocument, LocalState, Secret, Vault, VaultDocument};

pub const MAX_ENVELOPE: usize = 16 * 1024 * 1024;
pub const MAX_VAULT_PLAINTEXT: usize = 8 * 1024 * 1024;
pub const MAX_RECOVERY_FILE: usize = 4096;

const MAGIC: [u8; 4] = [0x56, 0x59, 0x58, 0x01];
const HEADER_LEN: usize = MAGIC.len() + std::mem::size_of::<u32>();
const MAX_WRAPPED_IDENTITY: usize = 16 * 1024;
const MAX_IDENTITY_PLAINTEXT: usize = 1024;
const SCRYPT_WORK_FACTOR: u8 = 17;

pub struct Crypto {
    identity: age::x25519::Identity,
    wrapped_identity: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryFile<'a> {
    kind: &'a str,
    version: u8,
    vault_id: Uuid,
    identity: &'a str,
}

impl Crypto {
    /// Exports the active random identity, never the passphrase or vault contents.
    ///
    /// Store the resulting `vyx-<vault-id>.recovery` separately from the encrypted
    /// vault. Possession of both grants access; this file is not a data backup.
    /// Ordinary saves keep it valid. Identity rotation invalidates it for current
    /// state, but cannot revoke access to copied historical ciphertext.
    pub fn export_recovery(&self, vault_id: Uuid) -> Result<Zeroizing<Vec<u8>>> {
        ensure!(!vault_id.is_nil(), "Invalid recovery file");
        let identity = self.identity.to_string();
        let file = RecoveryFile {
            kind: "vyx_recovery",
            version: 1,
            vault_id,
            identity: identity.expose_secret(),
        };
        let mut output = Zeroizing::new(Vec::with_capacity(MAX_RECOVERY_FILE));
        serde_json::to_writer(&mut *output, &file)
            .map_err(|_| anyhow!("Could not encode recovery file"))?;
        output.push(b'\n');
        ensure!(output.len() <= MAX_RECOVERY_FILE, "Invalid recovery file");
        Ok(output)
    }

    /// Authenticates a local envelope with a previously exported recovery identity.
    ///
    /// This does not disclose the old passphrase or write anything. Store recovery
    /// APIs enforce the local-only boundary and rotate credentials atomically.
    pub fn recover_local(envelope: &[u8], recovery: &[u8]) -> Result<(Self, LocalState)> {
        ensure!(recovery.len() <= MAX_RECOVERY_FILE, "Invalid recovery file");
        let input = Zeroizing::new(recovery.to_vec());
        let file: RecoveryFile<'_> = serde_json::from_slice(&input)
            .map_err(|_| anyhow!("Invalid recovery file"))?;
        ensure!(
            file.kind == "vyx_recovery" && file.version == 1 && !file.vault_id.is_nil(),
            "Invalid recovery file"
        );
        let identity = file.identity.parse::<age::x25519::Identity>()
            .map_err(|_| anyhow!("Invalid recovery file"))?;
        let recover = || -> Result<(Self, LocalState)> {
            let parts = parse_envelope(envelope)?;
            let crypto = Self {
                identity,
                wrapped_identity: parts.wrapped_identity.to_vec(),
            };
            let state = crypto.decrypt_local(envelope)?;
            ensure!(state.vault.id == file.vault_id, "vault ID mismatch");
            Ok((crypto, state))
        };
        recover().map_err(|_| anyhow!("Recovery file does not unlock this vault"))
    }

    pub(crate) fn same_identity(&self, other: &Self) -> bool {
        self.identity.to_public() == other.identity.to_public()
    }

    pub fn create(passphrase: &Secret) -> Result<Self> {
        let identity = age::x25519::Identity::generate();
        let serialized_identity = identity.to_string();
        let mut recipient = age::scrypt::Recipient::new(age_passphrase(passphrase));
        recipient.set_work_factor(SCRYPT_WORK_FACTOR);
        let wrapped_identity = encrypt_age(
            &recipient,
            serialized_identity.expose_secret().as_bytes(),
            MAX_WRAPPED_IDENTITY,
        )
        .context("could not wrap the vault identity")?;
        ensure!(
            !wrapped_identity.is_empty() && wrapped_identity.len() <= MAX_WRAPPED_IDENTITY,
            "wrapped vault identity exceeds the size limit"
        );

        Ok(Self {
            identity,
            wrapped_identity,
        })
    }

    pub fn unlock(envelope: &[u8], passphrase: &Secret) -> Result<Self> {
        let parts = parse_envelope(envelope)?;
        let identity = decrypt_wrapped_identity(parts.wrapped_identity, passphrase)?;

        Ok(Self {
            identity,
            wrapped_identity: parts.wrapped_identity.to_vec(),
        })
    }

    pub fn wrapped_identity(&self) -> &[u8] {
        &self.wrapped_identity
    }

    pub(crate) fn verify_passphrase(
        &self,
        envelope: &[u8],
        passphrase: &Secret,
    ) -> Result<()> {
        let parts = parse_envelope(envelope)?;
        let _candidate = decrypt_wrapped_identity(parts.wrapped_identity, passphrase)?;
        ensure!(
            parts.wrapped_identity == self.wrapped_identity,
            "passphrase does not unlock the active vault identity"
        );
        Ok(())
    }

    pub fn encrypt_local(&self, state: &LocalState) -> Result<Vec<u8>> {
        let mut state = state.clone();
        state.normalize();
        state.validate()?;
        ensure_vault_document_size(&state.vault)?;

        let plaintext = Zeroizing::new(
            serde_json::to_vec(&LocalDocument::Local { state })
                .context("could not serialize local vault document")?,
        );
        ensure!(
            plaintext.len() <= MAX_ENVELOPE,
            "local vault document exceeds the size limit"
        );
        self.encrypt_document(plaintext.as_slice())
    }

    pub fn decrypt_local(&self, envelope: &[u8]) -> Result<LocalState> {
        let plaintext = self.decrypt_document(envelope, MAX_ENVELOPE)?;
        let document: LocalDocument = serde_json::from_slice(plaintext.as_slice())
            .context("decrypted data is not a valid local vault document")?;
        let LocalDocument::Local { mut state } = document;
        // AI settings and history must never keep the vault from unlocking: repair, don't reject.
        state.ai.repair();
        state.normalize();
        state.validate()?;
        ensure_vault_document_size(&state.vault)?;
        Ok(state)
    }

    pub fn encrypt_vault(&self, vault: &Vault) -> Result<Vec<u8>> {
        let plaintext = canonical_vault_plaintext(vault)?;
        self.encrypt_document(plaintext.as_slice())
    }

    pub fn decrypt_vault(&self, envelope: &[u8]) -> Result<Vault> {
        let plaintext = self.decrypt_document(envelope, MAX_VAULT_PLAINTEXT)?;
        let document: VaultDocument = serde_json::from_slice(plaintext.as_slice())
            .context("decrypted data is not a valid synced vault document")?;
        let VaultDocument::Vault { mut vault } = document;
        vault.normalize();
        vault.validate()?;
        Ok(vault)
    }

    fn encrypt_document(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let prefix_len = HEADER_LEN
            .checked_add(self.wrapped_identity.len())
            .context("vault envelope length overflow")?;
        let mut envelope = Vec::with_capacity(
            prefix_len
                .checked_add(plaintext.len())
                .context("vault envelope length overflow")?,
        );
        envelope.extend_from_slice(&MAGIC);
        let wrapped_len = u32::try_from(self.wrapped_identity.len())
            .context("wrapped vault identity length overflow")?;
        envelope.extend_from_slice(&wrapped_len.to_be_bytes());
        envelope.extend_from_slice(&self.wrapped_identity);

        let recipient = self.identity.to_public();
        let encryptor = age::Encryptor::with_recipients(iter::once(&recipient as _))
            .context("could not initialize vault encryption")?;
        let mut writer = encryptor
            .wrap_output(&mut envelope)
            .context("could not begin vault encryption")?;
        writer
            .write_all(plaintext)
            .context("could not encrypt vault document")?;
        writer
            .finish()
            .context("could not finish vault encryption")?;

        ensure!(
            envelope.len() <= MAX_ENVELOPE,
            "encrypted vault envelope exceeds the size limit"
        );
        Ok(envelope)
    }

    fn decrypt_document(
        &self,
        envelope: &[u8],
        plaintext_limit: usize,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let parts = parse_envelope(envelope)?;
        ensure!(
            parts.wrapped_identity == self.wrapped_identity,
            "vault envelope uses a different wrapped identity"
        );
        let decryptor = age::Decryptor::new_buffered(parts.document)
            .context("vault document is not a valid age file")?;
        ensure!(
            !decryptor.is_scrypt(),
            "vault document is encrypted with an unsupported recipient"
        );
        decrypt_with(
            decryptor,
            &self.identity,
            plaintext_limit,
            "could not decrypt vault document",
        )
    }
}

fn decrypt_wrapped_identity(
    wrapped_identity: &[u8],
    passphrase: &Secret,
) -> Result<age::x25519::Identity> {
    let decryptor = age::Decryptor::new_buffered(wrapped_identity)
        .context("wrapped vault identity is not a valid age file")?;
    ensure!(
        decryptor.is_scrypt(),
        "wrapped vault identity is not passphrase-encrypted"
    );

    let mut passphrase_identity = age::scrypt::Identity::new(age_passphrase(passphrase));
    passphrase_identity.set_max_work_factor(SCRYPT_WORK_FACTOR);
    let serialized_identity = decrypt_with(
        decryptor,
        &passphrase_identity,
        MAX_IDENTITY_PLAINTEXT,
        "could not decrypt the wrapped vault identity",
    )?;
    let serialized_identity = std::str::from_utf8(serialized_identity.as_slice())
        .context("decrypted vault identity is not UTF-8")?;
    serialized_identity
        .parse::<age::x25519::Identity>()
        .map_err(|error| anyhow!("decrypted vault identity is invalid: {error}"))
}

struct EnvelopeParts<'a> {
    wrapped_identity: &'a [u8],
    document: &'a [u8],
}

fn parse_envelope(envelope: &[u8]) -> Result<EnvelopeParts<'_>> {
    ensure!(
        envelope.len() <= MAX_ENVELOPE,
        "encrypted vault envelope exceeds the size limit"
    );
    ensure!(
        envelope.len() >= HEADER_LEN,
        "encrypted vault envelope is truncated"
    );
    ensure!(
        envelope[..MAGIC.len()] == MAGIC,
        "unsupported vault envelope format"
    );

    let wrapped_len = u32::from_be_bytes(
        envelope[MAGIC.len()..HEADER_LEN]
            .try_into()
            .expect("the envelope length field is four bytes"),
    ) as usize;
    ensure!(wrapped_len != 0, "wrapped vault identity is empty");
    ensure!(
        wrapped_len <= MAX_WRAPPED_IDENTITY,
        "wrapped vault identity exceeds the size limit"
    );
    let document_offset = HEADER_LEN
        .checked_add(wrapped_len)
        .context("vault envelope length overflow")?;
    ensure!(
        document_offset < envelope.len(),
        "encrypted vault envelope is truncated"
    );

    Ok(EnvelopeParts {
        wrapped_identity: &envelope[HEADER_LEN..document_offset],
        document: &envelope[document_offset..],
    })
}

fn decrypt_with<R: io::BufRead>(
    decryptor: age::Decryptor<R>,
    identity: &dyn age::Identity,
    plaintext_limit: usize,
    error_context: &'static str,
) -> Result<Zeroizing<Vec<u8>>> {
    let reader = decryptor
        .decrypt(iter::once(identity))
        .with_context(|| error_context)?;
    let read_limit = u64::try_from(plaintext_limit)
        .context("plaintext limit does not fit in u64")?
        .checked_add(1)
        .context("plaintext limit overflow")?;
    let mut plaintext = Zeroizing::new(Vec::with_capacity(plaintext_limit.min(64 * 1024)));
    reader
        .take(read_limit)
        .read_to_end(plaintext.as_mut())
        .with_context(|| error_context)?;
    ensure!(
        plaintext.len() <= plaintext_limit,
        "decrypted vault document exceeds the size limit"
    );
    Ok(plaintext)
}

fn encrypt_age(
    recipient: &impl age::Recipient,
    plaintext: &[u8],
    ciphertext_limit: usize,
) -> Result<Vec<u8>> {
    let encryptor = age::Encryptor::with_recipients(iter::once(recipient as _))
        .context("could not initialize age encryption")?;
    let mut ciphertext = Vec::with_capacity(plaintext.len());
    let mut writer = encryptor
        .wrap_output(&mut ciphertext)
        .context("could not begin age encryption")?;
    writer
        .write_all(plaintext)
        .context("could not encrypt age plaintext")?;
    writer.finish().context("could not finish age encryption")?;
    ensure!(
        ciphertext.len() <= ciphertext_limit,
        "age ciphertext exceeds the size limit"
    );
    Ok(ciphertext)
}

fn canonical_vault_plaintext(vault: &Vault) -> Result<Zeroizing<Vec<u8>>> {
    let mut vault = vault.clone();
    vault.normalize();
    vault.validate()?;
    let plaintext = Zeroizing::new(
        serde_json::to_vec(&VaultDocument::Vault { vault })
            .context("could not serialize synced vault document")?,
    );
    ensure!(
        plaintext.len() <= MAX_VAULT_PLAINTEXT,
        "synced vault document exceeds the size limit"
    );
    Ok(plaintext)
}

#[derive(Serialize)]
#[serde(tag = "kind", rename = "vault")]
struct BorrowedVaultDocument<'a> {
    vault: &'a Vault,
}

fn ensure_vault_document_size(vault: &Vault) -> Result<()> {
    let mut writer = BoundedCounter::new(MAX_VAULT_PLAINTEXT);
    let result = serde_json::to_writer(&mut writer, &BorrowedVaultDocument { vault });
    match result {
        Ok(()) => Ok(()),
        Err(_) if writer.exceeded => bail!("synced vault document exceeds the size limit"),
        Err(error) => Err(error).context("could not measure synced vault document"),
    }
}

struct BoundedCounter {
    written: usize,
    limit: usize,
    exceeded: bool,
}

impl BoundedCounter {
    fn new(limit: usize) -> Self {
        Self {
            written: 0,
            limit,
            exceeded: false,
        }
    }
}

impl Write for BoundedCounter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let Some(new_len) = self.written.checked_add(bytes.len()) else {
            self.exceeded = true;
            return Err(io::Error::other("serialized document length overflow"));
        };
        if new_len > self.limit {
            self.exceeded = true;
            return Err(io::Error::other("serialized document exceeds limit"));
        }
        self.written = new_len;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn age_passphrase(passphrase: &Secret) -> SecretString {
    SecretString::from(passphrase.expose().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::model::{
        Auth, Credential, Host, HostAuth, HostTransport, LocalState, SCHEMA_VERSION, Snippet,
        SyncState, TailscaleIdentity,
    };
    use crate::ai::{AiData, Conversation, Feature, Message, Profile, ProviderKind, Role, Usage};
    use uuid::Uuid;

    fn sample_vault() -> Vault {
        let mut vault = Vault::new();
        vault.snippets.push(Snippet {
            id: Uuid::new_v4(),
            label: "Check".to_owned(),
            command: "printf ok".to_owned(),
        });
        vault
    }

    #[test]
    fn recovery_file_requires_matching_identity_and_vault() {
        let crypto = Crypto::create(&Secret::new("recovery test passphrase")).unwrap();
        let mut state = LocalState::new(sample_vault(), None);
        let file = crypto.export_recovery(state.vault.id).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&file).unwrap();
        assert_eq!(json.as_object().unwrap().keys().map(String::as_str).collect::<Vec<_>>(),
            ["identity", "kind", "vault_id", "version"]);
        assert!(file.ends_with(b"\n"));
        let envelope = crypto.encrypt_local(&state).unwrap();
        let (candidate, recovered) = Crypto::recover_local(&envelope, &file).unwrap();
        assert!(crypto.same_identity(&candidate));
        assert_eq!(recovered, state);
        state.vault.snippets[0].command = "changed after export".into();
        assert_eq!(Crypto::recover_local(&crypto.encrypt_local(&state).unwrap(), &file).unwrap().1, state);
        let other = Crypto::create(&Secret::new("different random identity")).unwrap();
        assert!(Crypto::recover_local(&envelope, &other.export_recovery(state.vault.id).unwrap()).is_err());
        assert!(Crypto::recover_local(&envelope, &crypto.export_recovery(Uuid::new_v4()).unwrap()).is_err());
        for suffix in [
            r#","recognizable-secret-material":true}"#,
            r#","version":1}"#,
        ] {
            let mut malformed = file[..file.len()-2].to_vec();
            malformed.extend_from_slice(suffix.as_bytes());
            let error = Crypto::recover_local(&envelope, &malformed).err().unwrap();
            assert!(!format!("{error:#}").contains("recognizable-secret-material"));
            assert!(!error.to_string().contains("recognizable-secret-material"));
        }
        for (field, value) in [
            ("version", serde_json::json!(2)),
            ("kind", serde_json::json!("other")),
            ("vault_id", serde_json::json!(Uuid::nil())),
            ("identity", serde_json::json!("not-an-X25519-secret")),
        ] {
            let mut malformed = json.clone();
            malformed[field] = value;
            assert!(Crypto::recover_local(&envelope, &serde_json::to_vec(&malformed).unwrap()).is_err());
        }
        for malformed in [b"{".to_vec(), vec![b' '; MAX_RECOVERY_FILE + 1], [file.as_slice(), b"false"].concat()] {
            assert!(Crypto::recover_local(&envelope, &malformed).is_err());
        }
        let mut corrupt = envelope.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(Crypto::recover_local(&corrupt, &file).is_err());
        assert!(Crypto::recover_local(&envelope[..envelope.len()-1], &file).is_err());
        assert!(Crypto::recover_local(&crypto.encrypt_vault(&state.vault).unwrap(), &file).is_err());
    }

    #[test]
    fn authenticated_envelopes_reject_wrong_password_tampering_and_wrong_kind() {
        let passphrase = Secret::new("correct horse battery staple");
        let wrong_passphrase = Secret::new("not the correct vault passphrase");
        let crypto = Crypto::create(&passphrase).unwrap();
        let vault = sample_vault();
        let envelope = crypto.encrypt_vault(&vault).unwrap();

        let unlocked = Crypto::unlock(&envelope, &passphrase).unwrap();
        assert_eq!(unlocked.decrypt_vault(&envelope).unwrap(), vault);
        assert!(Crypto::unlock(&envelope, &wrong_passphrase).is_err());

        let mut tampered = envelope.clone();
        *tampered.last_mut().unwrap() ^= 0x01;
        assert!(crypto.decrypt_vault(&tampered).is_err());

        let mut truncated = envelope.clone();
        truncated.pop();
        assert!(crypto.decrypt_vault(&truncated).is_err());

        let local = crypto
            .encrypt_local(&LocalState::new(vault.clone(), None))
            .unwrap();
        assert!(crypto.decrypt_vault(&local).is_err());

        let mut different_wrapped_identity = envelope.clone();
        different_wrapped_identity[HEADER_LEN] ^= 0x01;
        assert!(crypto.decrypt_vault(&different_wrapped_identity).is_err());

        let mut unsupported_schema = sample_vault();
        unsupported_schema.schema_version = SCHEMA_VERSION + 1;
        let plaintext = Zeroizing::new(
            serde_json::to_vec(&VaultDocument::Vault {
                vault: unsupported_schema,
            })
            .unwrap(),
        );
        let malformed = crypto.encrypt_document(plaintext.as_slice()).unwrap();
        assert!(crypto.decrypt_vault(&malformed).is_err());

        let vault_plaintext = canonical_vault_plaintext(&sample_vault()).unwrap();
        let mut unknown_field = Zeroizing::new(vault_plaintext.to_vec());
        unknown_field.pop();
        unknown_field.extend_from_slice(br#","unexpected":true}"#);
        let malformed = crypto.encrypt_document(unknown_field.as_slice()).unwrap();
        assert!(crypto.decrypt_vault(&malformed).is_err());

        let mut unsupported_format = envelope;
        unsupported_format[3] = 0x02;
        assert!(crypto.decrypt_vault(&unsupported_format).is_err());
    }

    #[test]
    fn schema_one_saved_host_roundtrips_without_changing_content_or_checkpoint() {
        let passphrase = Secret::new("vault passphrase");
        let crypto = Crypto::create(&passphrase).unwrap();
        let credential_id = Uuid::new_v4();
        let mut vault = Vault::new();
        vault.schema_version = 1;
        vault.credentials.push(Credential {
            id: credential_id,
            label: "Shared login".to_owned(),
            username: "shared-user".to_owned(),
            auth: Auth::Password {
                password: Secret::new("shared-secret"),
            },
        });
        vault.hosts.push(Host {
            id: Uuid::new_v4(),
            label: "Server".to_owned(),
            hostname: "example.test".to_owned(),
            port: 22,
            category_id: None,
            transport: HostTransport::Direct,
            auth: HostAuth::Credential { credential_id },
        });
        let content_sha256 = vault.content_sha256().unwrap();
        let canonical = canonical_vault_plaintext(&vault).unwrap();
        let state = LocalState::new(
            vault.clone(),
            Some(SyncState {
                url: "https://sync.example.test/vault".to_owned(),
                token: Secret::new("sync-token"),
                base_etag: Some(format!("\"{}\"", "a".repeat(64))),
                base_snapshot_id: Some(vault.snapshot_id),
                base_content_sha256: Some(content_sha256.clone()),
                pending_upload: None,
            }),
        );

        let local_envelope = crypto.encrypt_local(&state).unwrap();
        let loaded_state = crypto.decrypt_local(&local_envelope).unwrap();
        assert_eq!(loaded_state, state);
        assert_eq!(loaded_state.vault.schema_version, 1);
        assert_eq!(
            loaded_state
                .sync
                .as_ref()
                .unwrap()
                .base_content_sha256
                .as_deref(),
            Some(content_sha256.as_str())
        );

        let sync_envelope = crypto.encrypt_vault(&vault).unwrap();
        let loaded_vault = crypto.decrypt_vault(&sync_envelope).unwrap();
        assert_eq!(loaded_vault, vault);
        assert_eq!(loaded_vault.content_sha256().unwrap(), content_sha256);
        assert_eq!(
            canonical_vault_plaintext(&loaded_vault).unwrap().as_slice(),
            canonical.as_slice()
        );
    }

    #[test]
    fn direct_password_host_roundtrips_exact_secret_as_schema_two() {
        let passphrase = Secret::new("vault passphrase");
        let crypto = Crypto::create(&passphrase).unwrap();
        let mut vault = Vault::new();
        vault.schema_version = 1;
        vault.hosts.push(Host {
            id: Uuid::new_v4(),
            label: "Server".to_owned(),
            hostname: "example.test".to_owned(),
            port: 22,
            category_id: None,
            transport: HostTransport::Direct,
            auth: HostAuth::Password {
                username: "direct-user".to_owned(),
                password: Secret::new("  exact password\n"),
            },
        });
        assert!(vault.validate().is_err());

        let envelope = crypto.encrypt_vault(&vault).unwrap();
        let loaded = crypto.decrypt_vault(&envelope).unwrap();
        assert_eq!(loaded.schema_version, 2);
        assert_eq!(
            loaded.hosts[0].auth,
            HostAuth::Password {
                username: "direct-user".to_owned(),
                password: Secret::new("  exact password\n"),
            }
        );
        loaded.validate().unwrap();
    }

    #[test]
    fn tailscale_modes_survive_local_and_sync_encryption_with_schema_three() {
        let crypto = Crypto::create(&Secret::new("vault passphrase")).unwrap();
        let mut vault = Vault::new();
        vault.schema_version = 2;
        let keyless = Host {
            id: Uuid::from_u128(3),
            label: "Keyless".to_owned(),
            hostname: "server.example.ts.net".to_owned(),
            port: 22,
            category_id: None,
            transport: HostTransport::Tailscale,
            auth: HostAuth::Tailscale {
                username: "alice".to_owned(),
                tailscale: TailscaleIdentity {
                    tailnet_id: "tailnet-stable".to_owned(),
                    node_id: "node-stable".to_owned(),
                },
            },
        };
        vault.hosts.push(keyless.clone());
        vault.hosts.push(Host {
            id: Uuid::from_u128(4),
            label: "Standard SSH".to_owned(),
            port: 2222,
            auth: HostAuth::Password {
                username: "bob".to_owned(),
                password: Secret::new("  retained secret\n"),
            },
            ..keyless
        });
        let envelope = crypto.encrypt_vault(&vault).unwrap();
        let loaded = crypto.decrypt_vault(&envelope).unwrap();
        assert_eq!(vault.schema_version, 2);
        vault.normalize();
        assert_eq!(loaded.schema_version, 3);
        assert_eq!(loaded, vault);
        assert_eq!(loaded.content_sha256().unwrap(), vault.content_sha256().unwrap());
        let state = LocalState::new(vault, None);
        let envelope = crypto.encrypt_local(&state).unwrap();
        assert_eq!(crypto.decrypt_local(&envelope).unwrap(), state);
    }

    #[test]
    fn vault_plaintext_size_boundary_is_exact() {
        let mut at_limit = sample_vault();
        at_limit.snippets[0].command.clear();
        let base_len = serde_json::to_vec(&VaultDocument::Vault {
            vault: at_limit.clone(),
        })
        .unwrap()
        .len();
        at_limit.snippets[0].command = "x".repeat(MAX_VAULT_PLAINTEXT - base_len);
        assert_eq!(
            canonical_vault_plaintext(&at_limit).unwrap().len(),
            MAX_VAULT_PLAINTEXT
        );

        let crypto = Crypto {
            identity: age::x25519::Identity::generate(),
            wrapped_identity: vec![0x42],
        };
        let envelope = crypto.encrypt_vault(&at_limit).unwrap();
        assert!(envelope.len() <= MAX_ENVELOPE);
        assert_eq!(
            crypto.decrypt_vault(&envelope).unwrap().snippets[0]
                .command
                .len(),
            at_limit.snippets[0].command.len()
        );

        let mut over_limit = at_limit;
        over_limit.snippets[0].command.push('x');
        assert!(canonical_vault_plaintext(&over_limit).is_err());
        let plaintext = Zeroizing::new(
            serde_json::to_vec(&VaultDocument::Vault { vault: over_limit }).unwrap(),
        );
        let envelope = crypto.encrypt_document(plaintext.as_slice()).unwrap();
        assert!(crypto.decrypt_vault(&envelope).is_err());
    }

    #[test]
    fn legacy_local_documents_unlock_without_ai_and_unused_ai_stays_backward_compatible() {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct LegacyState {
            vault: Vault,
            sync: Option<SyncState>,
        }

        let crypto = Crypto {
            identity: age::x25519::Identity::generate(),
            wrapped_identity: vec![0x42],
        };
        for schema in 1..=SCHEMA_VERSION {
            let mut vault = sample_vault();
            vault.schema_version = schema;
            let old_document = serde_json::json!({
                "kind": "local",
                "state": { "vault": vault, "sync": null },
            });
            let envelope = crypto.encrypt_document(&serde_json::to_vec(&old_document).unwrap()).unwrap();
            let loaded = crypto.decrypt_local(&envelope).unwrap();
            assert_eq!(loaded.vault, vault);
            assert!(loaded.ai.is_default());
            let legacy: LegacyState = serde_json::from_value(serde_json::to_value(&loaded).unwrap()).unwrap();
            assert_eq!(legacy.vault, vault);
            assert!(legacy.sync.is_none());
        }
    }

    #[test]
    fn ai_roundtrips_locally_without_changing_sync_content_or_serializing_temporary_chats() {
        let crypto = Crypto {
            identity: age::x25519::Identity::generate(),
            wrapped_identity: vec![0x42],
        };
        let mut state = LocalState::new(sample_vault(), None);
        let hash = state.vault.content_sha256().unwrap();
        let mut profile = Profile::new(ProviderKind::OpenAi);
        profile.credential = Some(Secret::new("ai-secret-not-for-sync"));
        profile.temperature = Some(f64::from_bits(0x3feb0e7009b61ce0));
        let mut conversation = Conversation::new(Some(&profile), false);
        let mut message = Message::new(Role::Assistant, "private-ai-message-not-for-sync");
        message.usage = Some(Usage {
            input_tokens: 7,
            output_tokens: 9,
            cost_usd: Some(f64::from_bits(0x3f847ae147ae147b)),
        });
        conversation.push(message).unwrap();
        state.ai.put_profile(profile).unwrap();
        let mut subscription = Profile::new(ProviderKind::Codex);
        subscription.codex_auth = Some(Secret::new(serde_json::json!({
            "auth_mode": "chatgpt",
            "tokens": {"id_token": "codex-id-not-for-sync", "access_token": "codex-access-not-for-sync",
                "refresh_token": "codex-refresh-not-for-sync", "account_id": "fixture-account"}
        }).to_string()));
        state.ai.put_profile(subscription).unwrap();
        state.ai.conversations.push(conversation);
        let retained = state.clone();
        let mut temporary = Conversation::new(None, true);
        temporary.push(Message::new(Role::User, "temporary-ai-content")).unwrap();
        state.ai.conversations.push(temporary);
        assert!(serde_json::to_vec(&state).is_err());
        let envelope = crypto.encrypt_local(&state).unwrap();
        let diagnostics = format!("{state:?}");
        for secret in ["ai-secret-not-for-sync", "private-ai-message-not-for-sync", "temporary-ai-content", "codex-id-not-for-sync", "codex-access-not-for-sync", "codex-refresh-not-for-sync"] {
            assert!(!envelope.windows(secret.len()).any(|bytes| bytes == secret.as_bytes()));
            assert!(!diagnostics.contains(secret));
        }
        assert_eq!(crypto.decrypt_local(&envelope).unwrap(), retained);
        assert_eq!(state.vault.content_sha256().unwrap(), hash);
        let exported = crypto.encrypt_vault(&state.vault).unwrap();
        let exported_plaintext = crypto.decrypt_document(&exported, MAX_VAULT_PLAINTEXT).unwrap();
        let text = std::str::from_utf8(&exported_plaintext).unwrap();
        assert!(!text.contains("ai-secret-not-for-sync"));
        assert!(!text.contains("private-ai-message-not-for-sync"));
        assert!(!text.contains("temporary-ai-content"));
        assert!(!text.contains("codex_auth"));
        assert!(!text.contains("codex-access-not-for-sync"));
        assert!(!text.contains("codex-refresh-not-for-sync"));
        assert_eq!(crypto.decrypt_vault(&exported).unwrap(), retained.vault);
        assert!(crypto.decrypt_local(&exported).is_err());
    }

    #[test]
    fn ai_validation_repairs_saved_limits_without_relaxing_vault_validation() {
        let crypto = Crypto {
            identity: age::x25519::Identity::generate(),
            wrapped_identity: vec![0x42],
        };
        let vault = sample_vault();
        let profile = Profile::new(ProviderKind::Anthropic);
        let mut ai = AiData::default();
        ai.put_profile(profile).unwrap();
        let mut document = serde_json::json!({
            "kind": "local",
            "state": { "vault": vault, "sync": null, "ai": ai },
        });
        document["state"]["ai"]["config"]["context_chars"] = serde_json::json!(0);
        document["state"]["ai"]["config"]["panel_width"] = serde_json::json!(u16::MAX);
        document["state"]["ai"]["config"]["features"] = serde_json::json!(["chat", "future_capability"]);
        document["state"]["ai"]["profiles"][0]["temperature"] = serde_json::json!("NaN");
        document["state"]["ai"]["profiles"][0]["max_output_tokens"] = serde_json::json!(0);
        let envelope = crypto.encrypt_document(&serde_json::to_vec(&document).unwrap()).unwrap();
        let loaded = crypto.decrypt_local(&envelope).unwrap();
        assert_eq!(loaded.vault, vault);
        assert_eq!(loaded.ai.config.context_chars, crate::ai::MIN_CONTEXT_CHARS);
        assert_eq!(loaded.ai.config.panel_width, crate::ai::MAX_PANEL_WIDTH);
        assert_eq!(loaded.ai.config.features, [Feature::Chat].into_iter().collect());
        assert_eq!(loaded.ai.profiles[0].temperature, None);
        assert_eq!(loaded.ai.profiles[0].max_output_tokens, 1);
        document["state"]["vault"]["schema_version"] = serde_json::json!(SCHEMA_VERSION + 1);
        let envelope = crypto.encrypt_document(&serde_json::to_vec(&document).unwrap()).unwrap();
        assert!(crypto.decrypt_local(&envelope).is_err());
    }
}

