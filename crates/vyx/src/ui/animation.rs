//! Authentication branding shares a 1.2-second, input-interruptible introduction.
//! Full motion adds terminal-wide prismatic bands behind the opaque form and an
//! outward finishing sweep. Spacious terminals use a doubled wordmark; smaller
//! layouts reserve form space first and fall back to compact branding.
//! Reduced motion keeps the mark static; Off uses plain text. Neither schedules
//! animation frames. Authentication work and input never wait for the scene.
//!
use std::time::{Duration, Instant};

use ratatui::{Frame, layout::Rect, style::{Color, Style}};

use crate::{settings::Motion, theme::Palette, ui::theming::{blend, unit}};

const INTRO: Duration = Duration::from_millis(1200);
const FRAME_SPACING: Duration = Duration::from_millis(34);
const V: [&str; 5] = ["##   ##", "##   ##", " ## ## ", " ## ## ", "  ###  "];
const Y: [&str; 5] = ["##   ##", " ## ## ", "  ###  ", "  ###  ", "  ###  "];
const X: [&str; 5] = ["##   ##", " ## ## ", "  ###  ", " ## ## ", "##   ##"];
const PARTICLES: [(u16, u16); 8] = [(2, 0), (37, 0), (4, 2), (36, 2), (1, 4), (39, 4), (6, 5), (34, 5)];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BrandPhase {
    Intro,
    Working,
    Rest,
}

/// Prepared once per authentication surface, including for non-RGB themes.
pub struct BrandPalette {
    ramp: [Color; 256],
    stops: [Color; 3],
    pub background: Color,
    pub foreground: Color,
    pub muted: Color,
    pub accent: Color,
    pub success: Color,
}

impl BrandPalette {
    pub fn new(palette: &Palette) -> Self {
        let stops = [palette.ansi[6], palette.accent, palette.ansi[5]];
        let mut ramp = [stops[0]; 256];
        for (index, color) in ramp.iter_mut().enumerate() {
            let position = index as f64 / 255.0 * 2.0;
            let segment = usize::from(position > 1.0);
            *color = blend(stops[segment], stops[segment + 1], position - segment as f64);
        }
        Self {
            ramp,
            stops,
            background: palette.background,
            foreground: palette.foreground,
            muted: palette.muted,
            accent: palette.accent,
            success: palette.success,
        }
    }

    fn gradient(&self, position: f64) -> Color {
        self.ramp[(unit(position) * 255.0).round() as usize]
    }
}

fn smoothstep(value: f64) -> f64 {
    let value = unit(value);
    value * value * (3.0 - 2.0 * value)
}

fn ease_out_cubic(value: f64) -> f64 {
    1.0 - (1.0 - unit(value)).powi(3)
}

/// Returns branding and form bounds, excluding the existing bottom help row.
/// The form budget includes its existing two-row outer margin.
pub fn auth_regions(bounds: Rect, preferred_form_height: u16, motion: Motion) -> (Rect, Rect) {
    let width = bounds.width.min(u16::MAX - bounds.x);
    let height = bounds.height.min(u16::MAX - bounds.y).saturating_sub(1);
    let available = Rect::new(bounds.x, bounds.y, width, height);
    let form_budget = u32::from(preferred_form_height) + 2;
    let brand_height = if width == 0 {
        0
    } else if motion != Motion::Off && width >= 86 && u32::from(height) >= form_budget + 14 {
        14
    } else if motion != Motion::Off && width >= 45 && u32::from(height) >= form_budget + 7 {
        7
    } else if u32::from(height) > form_budget {
        1
    } else {
        0
    };
    (
        Rect::new(available.x, available.y, width, brand_height),
        Rect::new(available.x, available.y + brand_height, width, height - brand_height),
    )
}

/// Paints only within `area`; no form or help-row cells are touched.
pub fn draw_brand(
    frame: &mut Frame<'_>,
    area: Rect,
    colors: &BrandPalette,
    motion: Motion,
    phase: BrandPhase,
    elapsed: Duration,
) {
    let area = area.intersection(frame.area());
    if area.is_empty() {
        return;
    }
    let style = Style::default().fg(colors.foreground).bg(colors.background);
    for y in area.y..area.bottom() {
        for x in area.x..area.right() {
            let cell = &mut frame.buffer_mut()[(x, y)];
            cell.reset();
            cell.set_symbol(" ").set_style(style);
        }
    }
    if motion == Motion::Off {
        centered_text(frame, area, area.y, "vyx · encrypted SSH workspace", colors.foreground);
        return;
    }
    // Slow publication must not leave a nearly settled frame as the resting image.
    let phase = if motion == Motion::Reduced || (phase == BrandPhase::Intro && elapsed >= INTRO) {
        BrandPhase::Rest
    } else {
        phase
    };
    let milliseconds = elapsed.as_secs_f64() * 1000.0;
    let parallax = if phase == BrandPhase::Intro {
        0.12 * (1.0 - ease_out_cubic(milliseconds / 1200.0))
    } else {
        0.0
    };
    if area.width < 41 || area.height < 7 {
        let width = area.width.min(5);
        let left = area.x + (area.width - width) / 2;
        for (x, glyph) in ['V', ' ', 'Y', ' ', 'X'].into_iter().take(usize::from(width)).enumerate() {
            if glyph == ' ' {
                continue;
            }
            let base = colors.gradient(x as f64 / 4.0 + parallax);
            let color = highlight(base, colors.foreground, phase, milliseconds, x as f64, 4.0);
            frame.buffer_mut()[(left + x as u16, area.y)].set_char(glyph).set_fg(color);
        }
        return;
    }
    let scale = if area.width >= 82 && area.height >= 14 { 2 } else { 1 };
    let left = area.x + (area.width - 41 * scale) / 2;
    let top = area.y + scale - 1;
    for (letter, mask) in [V, Y, X].iter().enumerate() {
        for (y, row) in mask.iter().enumerate() {
            for (column, occupied) in row.bytes().enumerate() {
                if occupied != b'#' {
                    continue;
                }
                let x = letter * 9 + column;
                let base = colors.gradient((x as f64 / 24.0 + y as f64 / 4.0) / 2.0 + parallax);
                let (glyph, base) = if phase == BrandPhase::Intro {
                    let strength = smoothstep((milliseconds - (6 * x + 12 * y) as f64) / 48.0);
                    let glyph = if strength < 1.0 / 3.0 { "░" } else if strength < 2.0 / 3.0 { "▒" } else { "█" };
                    (glyph, blend(colors.background, base, 0.2 + 0.8 * strength))
                } else {
                    ("█", base)
                };
                for dy in 0..scale {
                    for dx in 0..scale {
                        let cell_x = x as u16 * scale + dx;
                        let cell_y = y as u16 * scale + dy;
                        // Work sweeps retain actual cell-space velocity at either size.
                        let q = if phase == BrandPhase::Working {
                            f64::from(cell_x) + 0.5 * f64::from(cell_y)
                        } else {
                            x as f64 + 0.5 * y as f64
                        };
                        let color = highlight(base, colors.foreground, phase, milliseconds, q, 27.0 * f64::from(scale));
                        frame.buffer_mut()[(left + 8 * scale + cell_x, top + cell_y)]
                            .set_symbol(glyph).set_fg(color);
                    }
                }
            }
        }
    }
    if phase == BrandPhase::Intro {
        for (index, &(x, y)) in PARTICLES.iter().enumerate() {
            let progress = unit((milliseconds - 45.0 * index as f64) / 700.0);
            if progress == 0.0 || progress == 1.0 {
                continue;
            }
            let strength = 0.3 * (std::f64::consts::PI * progress).sin();
            let position = (f64::from(x) / 40.0 + f64::from(y) / 6.0) / 2.0;
            let stop = colors.stops[(unit(position) * 2.0).round() as usize];
            frame.buffer_mut()[(left + x * scale, top + y * scale)]
                .set_symbol("·").set_fg(blend(colors.background, stop, strength));
        }
    }
    centered_text(frame, area, area.y + 7 * scale - 1, "encrypted SSH workspace", colors.muted);
}

/// Paints an authentication scene before its opaque form/status surface.
/// Full-screen light remains behind the form and never enters the bottom help row.
pub fn draw_auth_scene(
    frame: &mut Frame<'_>,
    bounds: Rect,
    brand: Rect,
    colors: &BrandPalette,
    motion: Motion,
    phase: BrandPhase,
    elapsed: Duration,
) {
    let bounds = bounds.intersection(frame.area());
    let scene = Rect { height: bounds.height.saturating_sub(1), ..bounds };
    let brand = brand.intersection(scene);
    draw_brand(frame, brand, colors, motion, phase, elapsed);
    if motion != Motion::Full || phase != BrandPhase::Intro || elapsed >= INTRO || brand.height < 7 {
        return;
    }

    let milliseconds = elapsed.as_secs_f64() * 1000.0;
    let fade = smoothstep(milliseconds / 150.0) * (1.0 - smoothstep((milliseconds - 880.0) / 320.0));
    if fade == 0.0 || scene.is_empty() {
        return;
    }
    let opening = 0.05 + 1.65 * ease_out_cubic((milliseconds - 40.0) / 900.0);
    let finish = -0.2 + 2.5 * ease_out_cubic((milliseconds - 520.0) / 680.0);
    let finish_strength = smoothstep((milliseconds - 520.0) / 140.0);
    let inverse_width = 1.0 / f64::from(scene.width.saturating_sub(1).max(1));
    let inverse_height = 1.0 / f64::from(scene.height.saturating_sub(1).max(1));
    for y in scene.y..scene.bottom() {
        let ny = f64::from(y - scene.y) * inverse_height;
        let vertical = (2.0 * ny - 1.0).abs();
        for x in scene.x..scene.right() {
            // Keep the logo/subtitle glyphs untouched; the form is drawn afterward
            // with its normal opaque palette, so no light reaches secret fields.
            if frame.buffer_mut()[(x, y)].symbol() != " " {
                continue;
            }
            let nx = f64::from(x - scene.x) * inverse_width;
            let distance = (2.0 * nx - 1.0).abs() + vertical;
            let broad = unit(1.0 - (distance - opening).abs() / 0.24);
            let sweep = unit(1.0 - (distance - finish).abs() / 0.10) * finish_strength;
            let strength = (0.16 * broad * broad).max(0.22 * sweep * sweep) * fade;
            if strength < 0.002 {
                continue;
            }
            let color = colors.gradient((nx + ny) / 2.0);
            let cell = &mut frame.buffer_mut()[(x, y)];
            cell.set_bg(blend(colors.background, color, strength));
            if broad > 0.90 || sweep > 0.70 {
                cell.set_symbol(if (nx < 0.5) == (ny < 0.5) { "╱" } else { "╲" })
                    .set_fg(blend(colors.background, color, 0.38 * broad.max(sweep) * fade));
            }
        }
    }
}

fn centered_text(frame: &mut Frame<'_>, area: Rect, y: u16, text: &str, color: Color) {
    let width = text.chars().count().min(usize::from(area.width)) as u16;
    let left = area.x + (area.width - width) / 2;
    for (x, glyph) in text.chars().take(usize::from(width)).enumerate() {
        frame.buffer_mut()[(left + x as u16, y)].set_char(glyph).set_fg(color);
    }
}

fn highlight(base: Color, foreground: Color, phase: BrandPhase, milliseconds: f64, q: f64, span: f64) -> Color {
    let (head, strength) = match phase {
        BrandPhase::Intro if milliseconds >= 180.0 => (
            -4.0 + 30.0 * (milliseconds - 180.0) / 1000.0,
            0.6 * (1.0 - smoothstep((milliseconds - 800.0) / 400.0)),
        ),
        BrandPhase::Working => (((milliseconds / 1000.0 * 18.0) % (span + 10.0)) - 5.0, 0.25),
        _ => return base,
    };
    let intensity = unit(1.0 - (q - head).abs() / 4.0).powi(2);
    blend(base, foreground, strength * intensity)
}

/// Color-only success resolution. Call after drawing the original outer chrome.
pub fn paint_unlock_edge(frame: &mut Frame<'_>, sidebar: Rect, palette: &Palette, elapsed: Duration) {
    let sidebar = Rect::new(
        sidebar.x,
        sidebar.y,
        sidebar.width.min(u16::MAX - sidebar.x),
        sidebar.height.min(u16::MAX - sidebar.y),
    );
    if sidebar.is_empty() || elapsed >= Duration::from_millis(420) {
        return;
    }
    let bounds = frame.area();
    let progress = unit(elapsed.as_secs_f64() / 0.420);
    let head = -3.0 + progress * (f64::from(sidebar.height) + 6.0);
    let envelope = (std::f64::consts::PI * progress).sin();
    let mut paint = |x: u16, y: u16| {
        if !bounds.contains((x, y).into()) {
            return;
        }
        let cell = &mut frame.buffer_mut()[(x, y)];
        if matches!(cell.symbol(), "│" | "─" | "┌" | "┐" | "└" | "┘" | "╭" | "╮" | "╰" | "╯") {
            let intensity = unit(1.0 - (f64::from(y - sidebar.y) - head).abs() / 3.0) * envelope;
            cell.set_fg(blend(cell.fg, palette.success, intensity));
        }
    };
    let right = sidebar.right() - 1;
    let bottom = sidebar.bottom() - 1;
    for x in sidebar.x..sidebar.right() {
        paint(x, sidebar.y);
        if bottom != sidebar.y {
            paint(x, bottom);
        }
    }
    for y in sidebar.y.saturating_add(1)..bottom {
        paint(sidebar.x, y);
        if right != sidebar.x {
            paint(right, y);
        }
    }
}

/// Elapsed-time driver. The input loop owns both event routing and publication.
pub struct BrandAnimation {
    colors: BrandPalette,
    motion: Motion,
    phase: BrandPhase,
    started: Instant,
    next_frame: Option<Instant>,
    attached: bool,
    generation: u64,
}

impl BrandAnimation {
    pub fn new(motion: Motion, palette: &Palette, now: Instant, generation: u64) -> Self {
        Self {
            colors: BrandPalette::new(palette),
            motion,
            phase: if motion == Motion::Full { BrandPhase::Intro } else { BrandPhase::Rest },
            started: now,
            next_frame: (motion == Motion::Full).then_some(now),
            attached: true,
            generation,
        }
    }

    pub fn begin_work(&mut self, now: Instant) {
        self.phase = BrandPhase::Working;
        self.started = now;
        self.next_frame = (self.motion == Motion::Full && self.attached).then_some(now);
    }

    pub fn settle(&mut self) {
        self.phase = BrandPhase::Rest;
        self.next_frame = None;
    }

    pub fn observe_attachment(&mut self, attached: bool, generation: u64) {
        if !attached || generation != self.generation || attached != self.attached {
            if self.phase == BrandPhase::Intro {
                self.settle();
            }
            // A resumed work frame samples current elapsed time, never a stale frame.
            self.next_frame = (attached && self.phase == BrandPhase::Working && self.motion == Motion::Full)
                .then_some(self.started);
        }
        self.attached = attached;
        self.generation = generation;
    }

    pub fn deadline(&self, attached: bool, visible: bool) -> Option<Instant> {
        if attached && self.attached && visible && self.motion == Motion::Full && self.phase != BrandPhase::Rest {
            self.next_frame
        } else {
            None
        }
    }

    pub fn frame_drawn(&mut self, sampled_at: Instant, completed_at: Instant) {
        if sampled_at < self.started {
            return;
        }
        if self.phase == BrandPhase::Intro && sampled_at.duration_since(self.started) >= INTRO {
            self.settle();
        } else {
            self.next_frame = (self.attached && self.motion == Motion::Full && self.phase != BrandPhase::Rest)
                .then(|| completed_at + FRAME_SPACING);
        }
    }

    pub fn motion(&self) -> Motion {
        self.motion
    }

    pub fn draw(&self, frame: &mut Frame<'_>, bounds: Rect, brand: Rect, sampled_at: Instant) {
        draw_auth_scene(frame, bounds, brand, &self.colors, self.motion, self.phase,
            sampled_at.saturating_duration_since(self.started));
    }
}
