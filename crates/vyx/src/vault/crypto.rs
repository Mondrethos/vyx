use std::io::{self, Read, Write};
use std::iter;

use age::secrecy::{ExposeSecret, SecretString};
use anyhow::{Context, Result, anyhow, bail, ensure};
use serde::Serialize;
use zeroize::Zeroizing;

use super::model::{LocalDocument, LocalState, Secret, Vault, VaultDocument};

pub const MAX_ENVELOPE: usize = 16 * 1024 * 1024;
pub const MAX_VAULT_PLAINTEXT: usize = 8 * 1024 * 1024;

const MAGIC: [u8; 4] = [0x56, 0x59, 0x58, 0x01];
const HEADER_LEN: usize = MAGIC.len() + std::mem::size_of::<u32>();
const MAX_WRAPPED_IDENTITY: usize = 16 * 1024;
const MAX_IDENTITY_PLAINTEXT: usize = 1024;
const SCRYPT_WORK_FACTOR: u8 = 17;

pub struct Crypto {
    identity: age::x25519::Identity,
    wrapped_identity: Vec<u8>,
}

impl Crypto {
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
        let decryptor = age::Decryptor::new_buffered(parts.wrapped_identity)
            .context("wrapped vault identity is not a valid age file")?;
        ensure!(
            decryptor.is_scrypt(),
            "wrapped vault identity is not passphrase-encrypted"
        );

        let mut identity = age::scrypt::Identity::new(age_passphrase(passphrase));
        identity.set_max_work_factor(SCRYPT_WORK_FACTOR);
        let serialized_identity = decrypt_with(
            decryptor,
            &identity,
            MAX_IDENTITY_PLAINTEXT,
            "could not decrypt the wrapped vault identity",
        )?;
        let serialized_identity = std::str::from_utf8(serialized_identity.as_slice())
            .context("decrypted vault identity is not UTF-8")?;
        let identity = serialized_identity
            .parse::<age::x25519::Identity>()
            .map_err(|error| anyhow!("decrypted vault identity is invalid: {error}"))?;

        Ok(Self {
            identity,
            wrapped_identity: parts.wrapped_identity.to_vec(),
        })
    }

    pub fn wrapped_identity(&self) -> &[u8] {
        &self.wrapped_identity
    }

    pub fn encrypt_local(&self, state: &LocalState) -> Result<Vec<u8>> {
        let mut state = state.clone();
        state.vault.normalize();
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
        state.vault.normalize();
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
    use crate::vault::model::{LocalState, SCHEMA_VERSION, Snippet};
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
            .encrypt_local(&LocalState {
                vault: vault.clone(),
                sync: None,
            })
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
}
