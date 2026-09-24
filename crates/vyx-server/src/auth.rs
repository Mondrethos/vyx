use std::{
    fs::{self, File},
    io::{self, Read, Write},
    os::unix::fs::PermissionsExt,
    path::Path,
};

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tempfile::Builder;

use crate::store::{LockedDirectory, sync_directory};

const AUTH_FILE: &str = "auth.sha256";
const TOKEN_BYTES: usize = 32;
const TOKEN_HEX_BYTES: usize = TOKEN_BYTES * 2;

pub(crate) fn initialize(data_dir: &Path) -> Result<String> {
    let directory = LockedDirectory::acquire(data_dir)?;
    let destination = directory.path().join(AUTH_FILE);
    if destination
        .try_exists()
        .context("checking authentication state")?
    {
        bail!("authentication state already exists");
    }

    let token = generate_token()?;
    let digest = digest(token.as_bytes());
    install_digest(directory.path(), &destination, &digest, true)?;
    Ok(token)
}

pub(crate) fn rotate(data_dir: &Path) -> Result<String> {
    let directory = LockedDirectory::acquire(data_dir)?;
    let destination = directory.path().join(AUTH_FILE);
    load_digest(directory.path()).context("authentication state is not initialized")?;

    let token = generate_token()?;
    let digest = digest(token.as_bytes());
    install_digest(directory.path(), &destination, &digest, false)?;
    Ok(token)
}

pub(crate) fn load_digest(data_dir: &Path) -> Result<[u8; 32]> {
    let path = data_dir.join(AUTH_FILE);
    let mut file = File::open(&path).context("opening authentication state")?;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .context("setting authentication state permissions")?;
    let metadata = file.metadata().context("reading authentication metadata")?;
    if !metadata.is_file() || metadata.len() != 32 {
        bail!("authentication state must contain exactly 32 bytes");
    }

    let mut value = [0_u8; 32];
    file.read_exact(&mut value)
        .context("reading authentication state")?;
    let mut trailing = [0_u8; 1];
    if file
        .read(&mut trailing)
        .context("validating authentication state")?
        != 0
    {
        bail!("authentication state has trailing data");
    }
    Ok(value)
}

pub(crate) fn authenticate(header: Option<&[u8]>, expected: &[u8; 32]) -> bool {
    let Some(header) = header else {
        return false;
    };
    if header.len() != 7 + TOKEN_HEX_BYTES || !header[..7].eq_ignore_ascii_case(b"bearer ") {
        return false;
    }

    let token = &header[7..];
    if !token
        .iter()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return false;
    }

    bool::from(digest(token).ct_eq(expected))
}

pub(crate) fn digest(value: &[u8]) -> [u8; 32] {
    Sha256::digest(value).into()
}

fn generate_token() -> Result<String> {
    let mut random = [0_u8; TOKEN_BYTES];
    getrandom::fill(&mut random)
        .map_err(|error| anyhow::anyhow!("generating access token: {error}"))?;

    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(TOKEN_HEX_BYTES);
    for byte in random {
        encoded.push(HEX[usize::from(byte >> 4)] as char);
        encoded.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    Ok(encoded)
}

fn install_digest(
    data_dir: &Path,
    destination: &Path,
    digest: &[u8; 32],
    no_clobber: bool,
) -> Result<()> {
    let mut temporary = Builder::new()
        .prefix(".vyx-auth-")
        .tempfile_in(data_dir)
        .context("creating authentication staging file")?;
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))
        .context("setting authentication staging permissions")?;
    temporary
        .write_all(digest)
        .context("writing authentication state")?;
    temporary
        .as_file()
        .sync_all()
        .context("synchronizing authentication state")?;

    if no_clobber {
        temporary
            .persist_noclobber(destination)
            .map_err(|error| error.error)
            .context("installing authentication state")?;
    } else {
        temporary
            .persist(destination)
            .map_err(|error| error.error)
            .context("replacing authentication state")?;
    }

    sync_directory(data_dir)
        .context("authentication state was installed, but directory durability is uncertain")?;
    Ok(())
}

pub(crate) fn sync_auth_file(data_dir: &Path) -> io::Result<()> {
    File::open(data_dir.join(AUTH_FILE))?.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    #[test]
    fn initialization_and_rotation_install_only_raw_digests() {
        let temporary = tempfile::tempdir().unwrap();
        let token = initialize(temporary.path()).unwrap();
        assert_eq!(token.len(), 64);
        assert!(
            token
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
        assert_eq!(
            fs::read(temporary.path().join(AUTH_FILE)).unwrap(),
            digest(token.as_bytes())
        );
        assert_eq!(
            fs::metadata(temporary.path().join(AUTH_FILE))
                .unwrap()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(temporary.path()).unwrap().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(temporary.path().join(".lock")).unwrap().mode() & 0o777,
            0o600
        );
        assert!(initialize(temporary.path()).is_err());

        let vault_path = temporary.path().join("vault.vyx");
        fs::write(&vault_path, b"opaque snapshot").unwrap();
        let replacement = rotate(temporary.path()).unwrap();
        assert_ne!(replacement, token);
        assert_eq!(
            fs::read(temporary.path().join(AUTH_FILE)).unwrap(),
            digest(replacement.as_bytes())
        );
        assert_eq!(fs::read(vault_path).unwrap(), b"opaque snapshot");
        assert!(!authenticate(
            Some(format!("Bearer {token}").as_bytes()),
            &digest(replacement.as_bytes())
        ));
        assert!(authenticate(
            Some(format!("Bearer {replacement}").as_bytes()),
            &digest(replacement.as_bytes())
        ));
    }
}
