use ratatui::style::Color;

use crate::{settings::IconMode, theme::Palette};

/// Codicons from an external icon fallback or compatible Nerd Font; no bundled fonts.
/// Mapping: https://github.com/ryanoasis/nerd-fonts/blob/master/glyphnames.json
/// Artwork: Microsoft vscode-codicons (CC BY 4.0); code: MIT.
#[derive(Clone, Copy)]
pub enum Icon {
    Terminal,
    Server,
    Key,
    Tools,
    Sync,
    Workspace,
    Theme,
    Security,
    Shortcuts,
    Folder,
    Snippet,
    Expanded,
    Collapsed,
    Active,
    Connected,
    Pending,
    Error,
    Closed,
    Settings,
}

impl Icon {
    pub fn color(self, palette: &Palette) -> Color {
        match self {
            Self::Terminal | Self::Active | Self::Connected => palette.success,
            Self::Server | Self::Workspace => palette.info,
            Self::Key | Self::Folder | Self::Security | Self::Pending => palette.warning,
            Self::Tools | Self::Snippet | Self::Theme => palette.ansi[5],
            Self::Sync | Self::Shortcuts => palette.ansi[6],
            Self::Settings => palette.accent,
            Self::Expanded | Self::Collapsed | Self::Closed => palette.muted,
            Self::Error => palette.error,
        }
    }

    pub fn glyph(self, mode: IconMode) -> &'static str {
        let (plain, nerd) = match self {
            Self::Terminal => ("T", "\u{ea85}"),
            Self::Server => ("S", "\u{eb50}"),
            Self::Key => ("K", "\u{eb11}"),
            Self::Tools => ("+", "\u{eb6d}"),
            Self::Sync => ("=", "\u{ea77}"),
            Self::Workspace => ("W", "\u{ebeb}"),
            Self::Theme => ("C", "\u{eb5c}"),
            Self::Security => ("L", "\u{eb53}"),
            Self::Shortcuts => ("?", "\u{eac4}"),
            Self::Folder => ("D", "\u{ea83}"),
            Self::Snippet => ("$", "\u{eac4}"),
            Self::Expanded => ("v", "\u{eab4}"),
            Self::Collapsed => (">", "\u{eab6}"),
            Self::Active => ("*", "\u{ea71}"),
            Self::Connected => ("+", "\u{eb8a}"),
            Self::Pending => ("~", "\u{eb19}"),
            Self::Error => ("!", "\u{ea87}"),
            Self::Closed => ("o", "\u{eabc}"),
            Self::Settings => ("S", "\u{eb51}"),
        };
        match mode {
            IconMode::Plain => plain,
            IconMode::NerdFont => nerd,
        }
    }
}
