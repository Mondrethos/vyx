//! Immutable package parsing. This module never parses or compiles WebAssembly.
use std::collections::BTreeSet;

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::contract::{Permission, parse_json, validate_display_text};

pub const MAGIC: &[u8; 8] = b"VYXEXT1\n";
pub const MAX_MANIFEST_BYTES: usize = 64 * 1024;
pub const MAX_WASM_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_PACKAGE_BYTES: usize = 16 + MAX_MANIFEST_BYTES + MAX_WASM_BYTES;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Manifest {
    pub schema_version: u32,
    pub api_version: u32,
    pub id: String,
    pub name: String,
    pub description: String,
    pub version: String,
    pub permissions: Vec<Permission>,
    pub commands: Vec<Command>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Command {
    pub id: String,
    pub title: String,
    pub description: String,
}

impl Manifest {
    pub fn validate(&self) -> Result<()> {
        ensure!(self.schema_version == 1, "unsupported manifest schema version");
        ensure!(self.api_version == 1, "unsupported extension API version");
        ensure!(valid_extension_id(&self.id), "invalid extension ID");
        validate_display_text(&self.name, 256)?;
        ensure!(!self.name.trim().is_empty(), "extension name is blank");
        validate_display_text(&self.description, 8192)?;
        ensure!(self.version.len() <= 128, "version is too long");
        semver::Version::parse(&self.version)?;
        let permissions: BTreeSet<_> = self.permissions.iter().collect();
        ensure!(permissions.len() == self.permissions.len(), "duplicate permission");
        ensure!(!self.commands.is_empty() && self.commands.len() <= 32, "expected 1 to 32 commands");
        let mut ids = BTreeSet::new();
        for command in &self.commands {
            ensure!(valid_command_id(&command.id), "invalid command ID");
            ensure!(ids.insert(&command.id), "duplicate command ID");
            validate_display_text(&command.title, 256)?;
            ensure!(!command.title.trim().is_empty(), "command title is blank");
            validate_display_text(&command.description, 8192)?;
        }
        Ok(())
    }

    pub fn declares_command(&self, id: &str) -> bool {
        self.commands.iter().any(|command| command.id == id)
    }
}

pub fn valid_extension_id(id: &str) -> bool {
    if id.len() > 128 || !id.contains('.') {
        return false;
    }
    id.split('.').all(|segment| {
        !segment.is_empty()
            && segment.as_bytes()[0].is_ascii_lowercase()
            && segment.as_bytes().last().is_some_and(u8::is_ascii_alphanumeric)
            && segment.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    })
}

pub fn valid_command_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

#[derive(Debug)]
pub struct Package<'a> {
    pub manifest: Manifest,
    pub digest: String,
    pub wasm: &'a [u8],
}

impl<'a> Package<'a> {
    /// Validate immutable package structure; installation provenance is checked
    /// separately by the registry, never inferred from author-controlled bytes.
    pub fn parse(bytes: &'a [u8]) -> Result<Self> {
        ensure!(bytes.len() >= 16 && bytes.len() <= MAX_PACKAGE_BYTES, "invalid package length");
        ensure!(&bytes[..8] == MAGIC, "invalid package magic");
        let manifest_len = u32::from_le_bytes(bytes[8..12].try_into()?) as usize;
        let wasm_len = u32::from_le_bytes(bytes[12..16].try_into()?) as usize;
        ensure!(manifest_len > 0 && manifest_len <= MAX_MANIFEST_BYTES, "invalid manifest length");
        ensure!(wasm_len > 0 && wasm_len <= MAX_WASM_BYTES, "invalid Wasm length");
        ensure!(bytes.len() == 16 + manifest_len + wasm_len, "truncated package or trailing bytes");
        let mut manifest: Manifest = parse_json(&bytes[16..16 + manifest_len])?;
        manifest.validate()?;
        super::contract::sanitize_display_in_place(&mut manifest.name);
        super::contract::sanitize_display_in_place(&mut manifest.description);
        for command in &mut manifest.commands {
            super::contract::sanitize_display_in_place(&mut command.title);
            super::contract::sanitize_display_in_place(&mut command.description);
        }
        ensure!(!manifest.name.trim().is_empty(), "extension name is blank after sanitization");
        ensure!(manifest.commands.iter().all(|command| !command.title.trim().is_empty()), "command title is blank after sanitization");
        let digest = format!("{:x}", Sha256::digest(bytes));
        Ok(Self { manifest, digest, wasm: &bytes[16 + manifest_len..] })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn package(id: &str) -> Vec<u8> {
        let manifest = serde_json::to_vec(&json!({
            "schemaVersion":1,"apiVersion":1,"id":id,"name":"Example",
            "description":"Example","version":"1.0.0","permissions":["hosts.read"],
            "commands":[{"id":"browse","title":"Browse","description":"Browse hosts"}]
        })).unwrap();
        let mut bytes = MAGIC.to_vec();
        bytes.extend((manifest.len() as u32).to_le_bytes());
        bytes.extend(8u32.to_le_bytes());
        bytes.extend(manifest);
        bytes.extend(b"\0asm\x01\0\0\0");
        bytes
    }

    #[test]
    fn exact_container_rejects_truncation_and_trailing_bytes() {
        let bytes = package("com.vyx.example");
        let parsed = Package::parse(&bytes).unwrap();
        assert_eq!(parsed.digest, format!("{:x}", Sha256::digest(&bytes)));
        let mut extra = package("org.example.plugin");
        extra.push(0);
        assert!(Package::parse(&extra).is_err());
        assert!(Package::parse(&bytes[..bytes.len() - 1]).is_err());
    }

    #[test]
    fn manifest_rejects_unknown_permissions_duplicate_commands_and_bad_versions() {
        let bytes = package("org.example.plugin");
        let mut manifest = Package::parse(&bytes).unwrap().manifest;
        manifest.commands.push(manifest.commands[0].clone());
        assert!(manifest.validate().is_err());
        manifest.commands.pop();
        manifest.version = "latest".into();
        assert!(manifest.validate().is_err());
        assert!(parse_json::<Permission>(br#""vault.read""#).is_err());
        assert!(!valid_extension_id("org..bad"));
        assert!(!valid_extension_id("org.Example.bad"));
    }
}
