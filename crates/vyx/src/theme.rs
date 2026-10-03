use ratatui::style::{Color, Style};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Appearance {
    Dark,
    Light,
}

impl Appearance {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Dark => "Dark",
            Self::Light => "Light",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Palette {
    pub background: Color,
    pub foreground: Color,
    pub surface: Color,
    pub muted: Color,
    pub border: Color,
    pub accent: Color,
    pub selection_bg: Color,
    pub selection_fg: Color,
    pub success: Color,
    pub warning: Color,
    pub error: Color,
    pub info: Color,
    pub ansi: [Color; 16],
}

impl Palette {
    pub fn style(&self) -> Style {
        Style::default().fg(self.foreground).bg(self.background)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Theme {
    pub id: &'static str,
    pub name: &'static str,
    pub author: &'static str,
    pub system: &'static str,
    pub search: &'static str,
    pub appearance: Appearance,
    pub palette: Palette,
}

const fn rgb(value: u32) -> Color {
    Color::Rgb(
        ((value >> 16) & 0xff) as u8,
        ((value >> 8) & 0xff) as u8,
        (value & 0xff) as u8,
    )
}

// Base16's first sixteen colors define both application roles and the terminal
// palette. Base24 keeps the same roles and supplies distinct bright ANSI colors.
const fn base16_palette(c: [u32; 16]) -> Palette {
    Palette {
        background: rgb(c[0x00]),
        foreground: rgb(c[0x05]),
        surface: rgb(c[0x01]),
        muted: rgb(c[0x04]),
        border: rgb(c[0x03]),
        accent: rgb(c[0x0d]),
        selection_bg: rgb(c[0x02]),
        selection_fg: rgb(c[0x05]),
        success: rgb(c[0x0b]),
        warning: rgb(c[0x0a]),
        error: rgb(c[0x08]),
        info: rgb(c[0x0d]),
        ansi: [
            rgb(c[0x00]),
            rgb(c[0x08]),
            rgb(c[0x0b]),
            rgb(c[0x0a]),
            rgb(c[0x0d]),
            rgb(c[0x0e]),
            rgb(c[0x0c]),
            rgb(c[0x05]),
            rgb(c[0x03]),
            rgb(c[0x08]),
            rgb(c[0x0b]),
            rgb(c[0x0a]),
            rgb(c[0x0d]),
            rgb(c[0x0e]),
            rgb(c[0x0c]),
            rgb(c[0x07]),
        ],
    }
}

const fn base24_palette(c: [u32; 24]) -> Palette {
    Palette {
        background: rgb(c[0x00]),
        foreground: rgb(c[0x05]),
        surface: rgb(c[0x01]),
        muted: rgb(c[0x04]),
        border: rgb(c[0x03]),
        accent: rgb(c[0x0d]),
        selection_bg: rgb(c[0x02]),
        selection_fg: rgb(c[0x05]),
        success: rgb(c[0x0b]),
        warning: rgb(c[0x0a]),
        error: rgb(c[0x08]),
        info: rgb(c[0x0d]),
        ansi: [
            rgb(c[0x00]),
            rgb(c[0x08]),
            rgb(c[0x0b]),
            rgb(c[0x0a]),
            rgb(c[0x0d]),
            rgb(c[0x0e]),
            rgb(c[0x0c]),
            rgb(c[0x05]),
            rgb(c[0x03]),
            rgb(c[0x12]),
            rgb(c[0x14]),
            rgb(c[0x13]),
            rgb(c[0x16]),
            rgb(c[0x17]),
            rgb(c[0x15]),
            rgb(c[0x07]),
        ],
    }
}

// Tinted8 UI roles are already fully resolved in the gallery payload. Keeping
// those separate from the ANSI palette preserves authored UI overrides.
const fn tinted8_palette(semantic: [u32; 12], ansi: [u32; 16]) -> Palette {
    Palette {
        background: rgb(semantic[0]),
        foreground: rgb(semantic[1]),
        surface: rgb(semantic[2]),
        muted: rgb(semantic[3]),
        border: rgb(semantic[4]),
        accent: rgb(semantic[5]),
        selection_bg: rgb(semantic[6]),
        selection_fg: rgb(semantic[7]),
        success: rgb(semantic[8]),
        warning: rgb(semantic[9]),
        error: rgb(semantic[10]),
        info: rgb(semantic[11]),
        ansi: [
            rgb(ansi[0]),
            rgb(ansi[1]),
            rgb(ansi[2]),
            rgb(ansi[3]),
            rgb(ansi[4]),
            rgb(ansi[5]),
            rgb(ansi[6]),
            rgb(ansi[7]),
            rgb(ansi[8]),
            rgb(ansi[9]),
            rgb(ansi[10]),
            rgb(ansi[11]),
            rgb(ansi[12]),
            rgb(ansi[13]),
            rgb(ansi[14]),
            rgb(ansi[15]),
        ],
    }
}

mod catalog;

pub use catalog::THEMES;

pub fn find(id: &str) -> Option<&'static Theme> {
    THEMES.iter().find(|theme| theme.id == id)
}

pub fn default_theme() -> &'static Theme {
    &THEMES[catalog::DEFAULT_THEME_INDEX]
}
