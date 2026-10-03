use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use tempfile::Builder as TempFileBuilder;

use crate::{shortcuts::Bindings, theme::{self, Theme}};

const SETTINGS_FILE: &str = "settings.json";
const MAX_SETTINGS_BYTES: u64 = 256 * 1024;

pub const MIN_SIDEBAR_WIDTH: u16 = 20;
pub const MAX_SIDEBAR_WIDTH: u16 = 80;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalLayout {
    #[default]
    Single,
    SideBySide,
    Stacked,
    Grid,
}

impl TerminalLayout {
    pub const ALL: [Self; 4] = [
        Self::Single,
        Self::SideBySide,
        Self::Stacked,
        Self::Grid,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::Single => "Single",
            Self::SideBySide => "Side by side",
            Self::Stacked => "Stacked",
            Self::Grid => "Grid",
        }
    }
}

/// Codicons require an externally installed icon fallback or compatible Nerd Font.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IconMode {
    #[default]
    Plain,
    NerdFont,
}

impl IconMode {
    pub const ALL: [Self; 2] = [Self::Plain, Self::NerdFont];

    pub fn label(self) -> &'static str {
        match self {
            Self::Plain => "Plain",
            Self::NerdFont => "Codicons",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Motion {
    #[default]
    Full,
    Reduced,
    Off,
}

impl Motion {
    pub const ALL: [Self; 3] = [Self::Full, Self::Reduced, Self::Off];

    pub fn label(self) -> &'static str {
        match self {
            Self::Full => "Full",
            Self::Reduced => "Reduced motion",
            Self::Off => "Off",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceSettings {
    pub sidebar_width: u16,
    pub sidebar_collapsed: bool,
    #[serde(default)]
    pub terminal_layout: TerminalLayout,
    #[serde(default)]
    pub icon_mode: IconMode,
    #[serde(default)]
    pub motion: Motion,
}

impl Default for WorkspaceSettings {
    fn default() -> Self {
        Self {
            sidebar_width: 28,
            sidebar_collapsed: false,
            terminal_layout: TerminalLayout::default(),
            icon_mode: IconMode::default(),
            motion: Motion::default(),
        }
    }
}

impl WorkspaceSettings {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (MIN_SIDEBAR_WIDTH..=MAX_SIDEBAR_WIDTH).contains(&self.sidebar_width),
            "sidebar width must be between {MIN_SIDEBAR_WIDTH} and {MAX_SIDEBAR_WIDTH} columns"
        );
        Ok(())
    }
}

/// Normalized divider positions in (0, u16::MAX), relative to the full axis.
/// A saved axis applies only when its divider count matches the visible layout.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TerminalSizes {
    pub side_by_side: Vec<u16>,
    pub stacked: Vec<u16>,
    pub grid_columns: Vec<u16>,
    pub grid_rows: Vec<u16>,
}

impl TerminalSizes {
    fn validate(&self) -> Result<()> {
        for splits in [&self.side_by_side, &self.stacked, &self.grid_columns, &self.grid_rows] {
            ensure!(
                splits.first().is_none_or(|position| *position > 0)
                    && splits.last().is_none_or(|position| *position < u16::MAX)
                    && splits.windows(2).all(|pair| pair[0] < pair[1]),
                "terminal split positions must be increasing and between 0 and 65535"
            );
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LockSessions {
    #[default]
    Disconnect,
    KeepRunning,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SecuritySettings {
    pub idle_timeout_seconds: u32,
    pub lock_sessions: LockSessions,
}

impl Default for SecuritySettings {
    fn default() -> Self {
        Self { idle_timeout_seconds: 600, lock_sessions: LockSessions::Disconnect }
    }
}

impl SecuritySettings {
    pub fn validate(&self) -> Result<()> {
        ensure!(self.idle_timeout_seconds <= 86400, "Auto-lock timeout cannot exceed 24 hours");
        Ok(())
    }

    pub fn timeout_text(self) -> String {
        match self.idle_timeout_seconds {
            0 => "0".to_owned(),
            seconds if seconds % 3600 == 0 => format!("{}h", seconds / 3600),
            seconds if seconds % 60 == 0 => format!("{}m", seconds / 60),
            seconds => format!("{seconds}s"),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredSettings {
    #[serde(default)]
    bindings: Bindings,
    #[serde(default)]
    workspace: WorkspaceSettings,
    #[serde(default)]
    terminal_sizes: TerminalSizes,
    #[serde(default)]
    theme: Option<String>,
    #[serde(default)]
    security: SecuritySettings,
    #[serde(default)]
    tailscale_cli_path: Option<PathBuf>,
}

#[derive(Serialize)]
struct BorrowedSettings<'a> {
    bindings: &'a Bindings,
    workspace: &'a WorkspaceSettings,
    terminal_sizes: &'a TerminalSizes,
    theme: &'a str,
    security: &'a SecuritySettings,
    #[serde(skip_serializing_if = "Option::is_none")]
    tailscale_cli_path: Option<&'a Path>,
}

#[derive(Debug)]
pub struct Settings {
    pub bindings: Bindings,
    pub workspace: WorkspaceSettings,
    pub terminal_sizes: TerminalSizes,
    pub theme: &'static Theme,
    pub security: SecuritySettings,
    pub tailscale_cli_path: Option<PathBuf>,
    data_directory: PathBuf,
}

impl Settings {
    pub fn load(data_directory: &Path) -> Result<Self> {
        let path = data_directory.join(SETTINGS_FILE);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(Self {
                    bindings: Bindings::default(),
                    workspace: WorkspaceSettings::default(),
                    terminal_sizes: TerminalSizes::default(),
                    theme: theme::default_theme(),
                    security: SecuritySettings::default(),
                    tailscale_cli_path: None,
                    data_directory: data_directory.to_owned(),
                });
            }
            Err(error) => {
                return Err(error).with_context(|| format!("inspect settings {}", path.display()));
            }
        };
        ensure!(
            metadata.file_type().is_file(),
            "settings path is not a regular file: {}",
            path.display()
        );
        ensure!(
            metadata.len() <= MAX_SETTINGS_BYTES,
            "settings file {} exceeds the {MAX_SETTINGS_BYTES}-byte limit",
            path.display()
        );

        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
            .with_context(|| format!("open settings {}", path.display()))?;
        let opened = file
            .metadata()
            .with_context(|| format!("inspect open settings {}", path.display()))?;
        ensure!(
            opened.file_type().is_file(),
            "settings path is not a regular file: {}",
            path.display()
        );
        ensure!(
            opened.len() <= MAX_SETTINGS_BYTES,
            "settings file {} exceeds the {MAX_SETTINGS_BYTES}-byte limit",
            path.display()
        );

        let mut bytes = Vec::with_capacity(opened.len() as usize);
        (&mut file)
            .take(MAX_SETTINGS_BYTES + 1)
            .read_to_end(&mut bytes)
            .with_context(|| format!("read settings {}", path.display()))?;
        ensure!(
            bytes.len() as u64 <= MAX_SETTINGS_BYTES,
            "settings file {} exceeds the {MAX_SETTINGS_BYTES}-byte limit",
            path.display()
        );
        let stored: StoredSettings = serde_json::from_slice(&bytes)
            .with_context(|| format!("parse settings {}", path.display()))?;
        stored
            .workspace
            .validate()
            .with_context(|| format!("validate settings {}", path.display()))?;
        stored.terminal_sizes.validate()
            .with_context(|| format!("validate settings {}", path.display()))?;
        stored.security.validate()
            .with_context(|| format!("validate settings {}", path.display()))?;
        if let Some(path) = &stored.tailscale_cli_path {
            ensure!(path.is_absolute(), "Tailscale CLI override must be an absolute path");
        }
        let theme = match stored.theme.as_deref() {
            Some(id) => theme::find(id)
                .with_context(|| format!("Unknown theme {id:?} in settings {}", path.display()))?,
            None => theme::default_theme(),
        };
        Ok(Self {
            bindings: stored.bindings,
            workspace: stored.workspace,
            terminal_sizes: stored.terminal_sizes,
            theme,
            security: stored.security,
            tailscale_cli_path: stored.tailscale_cli_path,
            data_directory: data_directory.to_owned(),
        })
    }

    pub fn save_bindings(&mut self, bindings: Bindings) -> Result<Option<String>> {
        let warning = self.persist(&bindings, &self.workspace, &self.terminal_sizes, self.theme, &self.security, self.tailscale_cli_path.as_deref())?;
        self.bindings = bindings;
        Ok(warning)
    }

    pub fn save_workspace(&mut self, workspace: WorkspaceSettings) -> Result<Option<String>> {
        workspace.validate()?;
        let warning = self.persist(&self.bindings, &workspace, &self.terminal_sizes, self.theme, &self.security, self.tailscale_cli_path.as_deref())?;
        self.workspace = workspace;
        Ok(warning)
    }

    pub fn save_terminal_sizes(&mut self, terminal_sizes: TerminalSizes) -> Result<Option<String>> {
        terminal_sizes.validate()?;
        let warning = self.persist(&self.bindings, &self.workspace, &terminal_sizes, self.theme, &self.security, self.tailscale_cli_path.as_deref())?;
        self.terminal_sizes = terminal_sizes;
        Ok(warning)
    }

    pub fn save_theme(&mut self, theme: &'static Theme) -> Result<Option<String>> {
        let warning = self.persist(&self.bindings, &self.workspace, &self.terminal_sizes, theme, &self.security, self.tailscale_cli_path.as_deref())?;
        self.theme = theme;
        Ok(warning)
    }

    pub fn save_security(&mut self, security: SecuritySettings) -> Result<Option<String>> {
        security.validate()?;
        let warning = self.persist(&self.bindings, &self.workspace, &self.terminal_sizes, self.theme, &security, self.tailscale_cli_path.as_deref())?;
        self.security = security;
        Ok(warning)
    }

    pub fn save_tailscale_cli_path(&mut self, path: Option<PathBuf>) -> Result<Option<String>> {
        if let Some(path) = &path {
            crate::tailscale::Adapter::discover(Some(path))?;
        }
        let warning = self.persist(&self.bindings, &self.workspace, &self.terminal_sizes, self.theme, &self.security, path.as_deref())?;
        self.tailscale_cli_path = path;
        Ok(warning)
    }

    fn persist(
        &self,
        bindings: &Bindings,
        workspace: &WorkspaceSettings,
        terminal_sizes: &TerminalSizes,
        theme: &Theme,
        security: &SecuritySettings,
        tailscale_cli_path: Option<&Path>,
    ) -> Result<Option<String>> {
        let path = self.data_directory.join(SETTINGS_FILE);
        let mut bytes = serde_json::to_vec_pretty(&BorrowedSettings {
            bindings,
            workspace,
            terminal_sizes,
            theme: theme.id,
            security,
            tailscale_cli_path,
        })
        .context("encode settings")?;
        bytes.push(b'\n');
        ensure!(
            bytes.len() as u64 <= MAX_SETTINGS_BYTES,
            "settings file {} would exceed the {MAX_SETTINGS_BYTES}-byte limit",
            path.display()
        );

        let mut staged = TempFileBuilder::new()
            .prefix(".settings.json.tmp-")
            .tempfile_in(&self.data_directory)
            .with_context(|| {
                format!(
                    "create staged settings in {}",
                    self.data_directory.display()
                )
            })?;
        staged
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))
            .with_context(|| format!("secure staged settings for {}", path.display()))?;
        staged
            .write_all(&bytes)
            .with_context(|| format!("write staged settings for {}", path.display()))?;
        staged
            .as_file()
            .sync_all()
            .with_context(|| format!("synchronize staged settings for {}", path.display()))?;

        match staged.persist(&path) {
            Ok(file) => drop(file),
            Err(error) => {
                return Err(error.error)
                    .with_context(|| format!("replace settings {}", path.display()));
            }
        }

        let warning = match File::open(&self.data_directory).and_then(|directory| directory.sync_all()) {
            Ok(()) => None,
            Err(error) => Some(format!(
                "Settings were saved, but synchronizing {} failed; durability after a crash is uncertain: {error}",
                self.data_directory.display()
            )),
        };
        Ok(warning)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shortcuts::Shortcut;
    use std::os::unix::fs::{MetadataExt, symlink};

    fn settings(data_directory: &Path) -> Settings {
        Settings {
            bindings: Bindings::default(),
            workspace: WorkspaceSettings::default(),
            terminal_sizes: TerminalSizes::default(),
            theme: theme::default_theme(),
            security: SecuritySettings::default(),
            tailscale_cli_path: None,
            data_directory: data_directory.to_owned(),
        }
    }

    #[test]
    fn tailscale_override_survives_other_saves_and_clearing_removes_new_field() {
        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("tailscale-fixture");
        fs::write(&executable, "#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        let mut settings = settings(directory.path());
        settings.save_tailscale_cli_path(Some(executable.clone())).unwrap();
        settings.save_security(SecuritySettings::default()).unwrap();
        assert_eq!(Settings::load(directory.path()).unwrap().tailscale_cli_path, Some(executable));
        settings.save_tailscale_cli_path(None).unwrap();
        assert_eq!(Settings::load(directory.path()).unwrap().tailscale_cli_path, None);
        let stored: serde_json::Value = serde_json::from_slice(&fs::read(directory.path().join(SETTINGS_FILE)).unwrap()).unwrap();
        assert!(stored.get("tailscale_cli_path").is_none());
    }

    #[test]
    fn invalid_tailscale_override_does_not_replace_saved_settings() {
        let directory = tempfile::tempdir().unwrap();
        let mut settings = settings(directory.path());
        settings.save_security(SecuritySettings::default()).unwrap();
        let before = fs::read(directory.path().join(SETTINGS_FILE)).unwrap();
        assert!(settings.save_tailscale_cli_path(Some(PathBuf::from("relative/tailscale"))).is_err());
        assert_eq!(fs::read(directory.path().join(SETTINGS_FILE)).unwrap(), before);
        assert!(settings.tailscale_cli_path.is_none());
        fs::write(directory.path().join(SETTINGS_FILE), br#"{"tailscale_cli_path":"relative/tailscale"}"#).unwrap();
        assert!(Settings::load(directory.path()).is_err());
    }

    #[test]
    fn legacy_bindings_only_settings_load_with_workspace_defaults() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(
            directory.path().join(SETTINGS_FILE),
            br#"{"bindings":{"sidebar_add":"Ctrl+G"}}"#,
        )
        .unwrap();

        let loaded = Settings::load(directory.path()).unwrap();
        assert_eq!(loaded.bindings.edit_text(Shortcut::SidebarAdd), "Ctrl+G");
        assert_eq!(loaded.workspace, WorkspaceSettings::default());
        assert_eq!(loaded.terminal_sizes, TerminalSizes::default());
        assert_eq!(loaded.security, SecuritySettings::default());
    }

    #[test]
    fn legacy_workspace_without_terminal_layout_loads_as_single() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(
            directory.path().join(SETTINGS_FILE),
            br#"{"bindings":{},"workspace":{"sidebar_width":42,"sidebar_collapsed":true}}"#,
        )
        .unwrap();

        let loaded = Settings::load(directory.path()).unwrap();
        assert_eq!(
            loaded.workspace,
            WorkspaceSettings {
                sidebar_width: 42,
                sidebar_collapsed: true,
                terminal_layout: TerminalLayout::Single,
                icon_mode: IconMode::Plain,
                motion: Motion::Full,
            }
        );
    }

    #[test]
    fn saving_each_section_preserves_bindings_and_workspace_layout() {
        let directory = tempfile::tempdir().unwrap();
        let mut settings = settings(directory.path());
        let chosen_theme = theme::find("tinted8-catppuccin-latte").unwrap();
        settings.save_theme(chosen_theme).unwrap();
        let security = SecuritySettings { idle_timeout_seconds: 75, lock_sessions: LockSessions::KeepRunning };
        settings.save_security(security).unwrap();
        let bindings = settings
            .bindings
            .with_binding(Shortcut::SidebarAdd, "Ctrl+G")
            .unwrap();
        settings.save_bindings(bindings).unwrap();
        let terminal_sizes = TerminalSizes {
            side_by_side: vec![20000, 50000],
            grid_rows: vec![40000],
            ..TerminalSizes::default()
        };
        settings.save_terminal_sizes(terminal_sizes.clone()).unwrap();

        let workspace = WorkspaceSettings {
            sidebar_width: 47,
            sidebar_collapsed: true,
            terminal_layout: TerminalLayout::Grid,
            icon_mode: IconMode::NerdFont,
            motion: Motion::Reduced,
        };
        settings.save_workspace(workspace).unwrap();
        let loaded = Settings::load(directory.path()).unwrap();
        assert_eq!(loaded.bindings.edit_text(Shortcut::SidebarAdd), "Ctrl+G");
        assert_eq!(loaded.workspace, workspace);
        assert_eq!(loaded.terminal_sizes, terminal_sizes);
        assert_eq!(loaded.theme.id, chosen_theme.id);
        assert_eq!(loaded.security, security);

        let bindings = settings
            .bindings
            .with_binding(Shortcut::SidebarAdd, "F12")
            .unwrap();
        settings.save_bindings(bindings).unwrap();
        let loaded = Settings::load(directory.path()).unwrap();
        assert_eq!(loaded.bindings.edit_text(Shortcut::SidebarAdd), "F12");
        assert_eq!(loaded.workspace, workspace);
        assert_eq!(loaded.terminal_sizes, terminal_sizes);
        assert_eq!(loaded.theme.id, chosen_theme.id);
        assert_eq!(loaded.security, security);

        settings.save_theme(theme::default_theme()).unwrap();
        let loaded = Settings::load(directory.path()).unwrap();
        assert_eq!(loaded.theme.id, theme::default_theme().id);
        assert_eq!(loaded.bindings.edit_text(Shortcut::SidebarAdd), "F12");
        assert_eq!(loaded.workspace, workspace);
        assert_eq!(loaded.terminal_sizes, terminal_sizes);
        assert_eq!(loaded.security, security);

        let security = SecuritySettings { idle_timeout_seconds: 120, lock_sessions: LockSessions::Disconnect };
        settings.save_security(security).unwrap();
        let terminal_sizes = TerminalSizes {
            stacked: vec![30000],
            ..terminal_sizes
        };
        settings.save_terminal_sizes(terminal_sizes.clone()).unwrap();
        let loaded = Settings::load(directory.path()).unwrap();
        assert_eq!(loaded.workspace, workspace);
        assert_eq!(loaded.security, security);
        assert_eq!(loaded.terminal_sizes, terminal_sizes);

        let workspace = WorkspaceSettings {
            sidebar_width: 51,
            sidebar_collapsed: false,
            terminal_layout: TerminalLayout::Stacked,
            ..workspace
        };
        settings.save_workspace(workspace).unwrap();
        assert_eq!(Settings::load(directory.path()).unwrap().workspace, workspace);

        let workspace = WorkspaceSettings { motion: Motion::Off, ..workspace };
        settings.save_workspace(workspace).unwrap();
        assert_eq!(Settings::load(directory.path()).unwrap().workspace, workspace);
    }

    #[test]
    fn invalid_workspace_does_not_overwrite_file_or_active_state() {
        let directory = tempfile::tempdir().unwrap();
        let mut settings = settings(directory.path());
        let active = WorkspaceSettings {
            sidebar_width: 45,
            sidebar_collapsed: true,
            terminal_layout: TerminalLayout::SideBySide,
            icon_mode: IconMode::NerdFont,
            motion: Motion::Off,
        };
        settings.save_workspace(active).unwrap();
        let path = directory.path().join(SETTINGS_FILE);
        let persisted = fs::read(&path).unwrap();

        let invalid = WorkspaceSettings {
            sidebar_width: MIN_SIDEBAR_WIDTH - 1,
            sidebar_collapsed: false,
            terminal_layout: TerminalLayout::Stacked,
            icon_mode: IconMode::Plain,
            motion: Motion::Full,
        };
        assert!(settings.save_workspace(invalid).is_err());
        assert_eq!(settings.workspace, active);
        assert_eq!(fs::read(path).unwrap(), persisted);
    }

    #[test]
    fn saved_settings_atomically_replace_and_survive_reload() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(SETTINGS_FILE);
        fs::write(&path, b"{\"bindings\":{}}\nold trailing bytes").unwrap();
        let mut settings = settings(directory.path());
        let changed = settings
            .bindings
            .with_binding(Shortcut::SidebarAdd, "Ctrl+G, F12")
            .unwrap();
        assert_eq!(settings.save_bindings(changed).unwrap(), None);
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        assert!(!fs::read(&path)
            .unwrap()
            .windows(b"old trailing bytes".len())
            .any(|window| window == b"old trailing bytes"));

        let loaded = Settings::load(directory.path()).unwrap();
        assert_eq!(loaded.bindings.edit_text(Shortcut::SidebarAdd), "Ctrl+G, F12");
        assert!(loaded.bindings.is_custom(Shortcut::SidebarAdd));
        assert_eq!(loaded.workspace, WorkspaceSettings::default());
        assert!(fs::read_dir(directory.path()).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".settings.json.tmp-")
        }));
    }

    #[test]
    fn failed_replace_keeps_in_memory_settings() {
        let directory = tempfile::tempdir().unwrap();
        fs::create_dir(directory.path().join(SETTINGS_FILE)).unwrap();
        let mut settings = settings(directory.path());
        let changed = settings
            .bindings
            .with_binding(Shortcut::SidebarAdd, "Ctrl+G")
            .unwrap();
        assert!(settings.save_bindings(changed).is_err());
        assert_eq!(settings.bindings.edit_text(Shortcut::SidebarAdd), "a");
        assert_eq!(settings.workspace, WorkspaceSettings::default());
        let old_theme = settings.theme.id;
        assert!(settings.save_theme(theme::find("tinted8-catppuccin-latte").unwrap()).is_err());
        assert_eq!(settings.theme.id, old_theme);
    }

    #[test]
    fn invalid_persisted_workspace_is_reported_and_preserved() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(SETTINGS_FILE);
        let invalid = br#"{"bindings":{},"workspace":{"sidebar_width":19,"sidebar_collapsed":false}}"#;
        fs::write(&path, invalid).unwrap();
        let error = Settings::load(directory.path()).unwrap_err();
        assert!(error.to_string().contains(path.to_string_lossy().as_ref()));
        assert_eq!(fs::read(&path).unwrap(), invalid);
    }

    #[test]
    fn malformed_terminal_layout_is_reported_and_preserved() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(SETTINGS_FILE);
        let invalid = br#"{"bindings":{},"workspace":{"sidebar_width":28,"sidebar_collapsed":false,"terminal_layout":"columns"}}"#;
        fs::write(&path, invalid).unwrap();

        let error = Settings::load(directory.path()).unwrap_err();
        assert!(error.to_string().contains(path.to_string_lossy().as_ref()));
        assert_eq!(fs::read(&path).unwrap(), invalid);
    }

    #[test]
    fn invalid_terminal_sizes_preserve_the_file_and_active_sizes() {
        let directory = tempfile::tempdir().unwrap();
        let mut settings = settings(directory.path());
        let active = TerminalSizes { grid_columns: vec![30000], ..TerminalSizes::default() };
        settings.save_terminal_sizes(active.clone()).unwrap();
        let path = directory.path().join(SETTINGS_FILE);
        let persisted = fs::read(&path).unwrap();
        for splits in [vec![0], vec![u16::MAX], vec![40000, 20000], vec![20000, 20000]] {
            let invalid = TerminalSizes { grid_columns: splits, ..TerminalSizes::default() };
            assert!(settings.save_terminal_sizes(invalid.clone()).is_err());
            assert_eq!(settings.terminal_sizes, active);
            assert_eq!(fs::read(&path).unwrap(), persisted);
            let stored = serde_json::to_vec(&BorrowedSettings {
                bindings: &settings.bindings,
                workspace: &settings.workspace,
                terminal_sizes: &invalid,
                theme: settings.theme.id,
                security: &settings.security,
                tailscale_cli_path: settings.tailscale_cli_path.as_deref(),
            }).unwrap();
            fs::write(&path, &stored).unwrap();
            assert!(Settings::load(directory.path()).is_err());
            assert_eq!(fs::read(&path).unwrap(), stored);
            fs::write(&path, &persisted).unwrap();
        }
    }

    #[test]
    fn invalid_bindings_are_reported_and_preserved() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(SETTINGS_FILE);
        let invalid = b"{\"bindings\":{\"sidebar_add\":\"q\"}}";
        fs::write(&path, invalid).unwrap();
        let error = Settings::load(directory.path()).unwrap_err();
        assert!(error.to_string().contains(path.to_string_lossy().as_ref()));
        assert_eq!(fs::read(&path).unwrap(), invalid);
    }

    #[test]
    fn invalid_security_preserves_file_and_active_policy() {
        let directory = tempfile::tempdir().unwrap();
        let mut settings = settings(directory.path());
        let security = SecuritySettings { idle_timeout_seconds: 0, lock_sessions: LockSessions::KeepRunning };
        settings.save_security(security).unwrap();
        let path = directory.path().join(SETTINGS_FILE);
        let bytes = fs::read(&path).unwrap();
        assert!(settings.save_security(SecuritySettings { idle_timeout_seconds: 86401, ..security }).is_err());
        assert_eq!(settings.security, security);
        assert_eq!(fs::read(&path).unwrap(), bytes);
        fs::write(&path, br#"{"security":{"idle_timeout_seconds":86401}}"#).unwrap();
        assert!(Settings::load(directory.path()).is_err());
    }

    #[test]
    fn unknown_theme_is_reported_without_overwriting_preferences() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(SETTINGS_FILE);
        let invalid = br#"{"theme":"base16-no-such-theme"}"#;
        fs::write(&path, invalid).unwrap();
        let error = Settings::load(directory.path()).unwrap_err();
        assert!(error.to_string().contains(path.to_string_lossy().as_ref()));
        assert_eq!(fs::read(path).unwrap(), invalid);
    }

    #[test]
    fn settings_symlinks_are_rejected_without_touching_target() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target.json");
        let contents = b"{\"bindings\":{}}";
        fs::write(&target, contents).unwrap();
        symlink(&target, directory.path().join(SETTINGS_FILE)).unwrap();
        assert!(Settings::load(directory.path()).is_err());
        assert_eq!(fs::read(target).unwrap(), contents);
    }
}
