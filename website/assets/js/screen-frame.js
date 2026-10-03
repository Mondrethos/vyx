// Draws a captured Vyx screen cell by cell. Box-drawing and block glyphs become crisp vector
// shapes that meet exactly, Codicons glyphs are filled from their outlines, and every other glyph
// is set in its own cell, so columns never drift.
import { ICONS, SCENES } from "./scenes-data.js";

// Box-drawing arms: up, right, down, left.
const ARMS = {
  "─": [0, 1, 0, 1], "│": [1, 0, 1, 0],
  "┌": [0, 1, 1, 0], "┐": [0, 0, 1, 1], "└": [1, 1, 0, 0], "┘": [1, 0, 0, 1],
  "├": [1, 1, 1, 0], "┤": [1, 0, 1, 1], "┬": [0, 1, 1, 1], "┴": [1, 1, 0, 1], "┼": [1, 1, 1, 1],
};
// Rounded corners: the two arms each joins.
const ROUND = { "╭": [1, 2], "╮": [2, 3], "╰": [0, 1], "╯": [0, 3] };
const SHADE = { "░": 0.25, "▒": 0.5, "▓": 0.75 };
// Like icon-aware terminals, an icon followed by a blank cell grows into it: 1.5 cells wide,
// which leaves half a cell before the next label.
const WIDE_ICON = 1.5;

let paths = null;
const icons = () => (paths ??= new Map(Object.entries(ICONS).map(([glyph, path]) => [glyph, new Path2D(path)])));

// Each cell of one captured row, as [glyph, fg, bg, bold].
function cells(runs) {
  const out = [];
  for (const [text, fg, bg, bold] of runs) {
    for (const glyph of text) out.push([glyph, fg, bg, bold]);
  }
  return out;
}

// "column,row,width,height" in cells, or the whole screen.
function region(crop, scene) {
  const values = String(crop || "").split(",").map(Number);
  return values.length === 4 && values.every(Number.isFinite)
    ? { x: values[0], y: values[1], cols: values[2], rows: values[3] }
    : { x: 0, y: 0, cols: scene.cols, rows: scene.rows };
}

// The most common background color, which the frame adopts around the canvas.
function background(scene) {
  const counts = new Map();
  for (const runs of scene.lines) {
    for (const [text, , bg] of runs) counts.set(bg, (counts.get(bg) || 0) + text.length);
  }
  return [...counts].reduce((best, entry) => (entry[1] > best[1] ? entry : best))[0];
}

function render(canvas, cursor, scene, view, colors) {
  const width = canvas.clientWidth;
  if (!width) return;
  const cw = width / view.cols;
  const ch = cw * 2;
  const ratio = Math.min(2, window.devicePixelRatio || 1);
  canvas.width = Math.round(width * ratio);
  canvas.height = Math.round(ch * view.rows * ratio);
  const context = canvas.getContext("2d");
  context.setTransform(ratio, 0, 0, ratio, 0, 0);
  const snap = (value) => Math.round(value * ratio) / ratio;
  const mono = getComputedStyle(canvas).getPropertyValue("--mono");
  const size = ch / 1.2;
  const thin = Math.max(1, Math.round(cw * 0.11 * ratio)) / ratio;
  const glyphs = icons();
  let font = "";

  const lines = [];
  for (let row = 0; row < view.rows; row += 1) lines.push(cells(scene.lines[view.y + row] || []));

  // Backgrounds first, so glyphs that reach into a neighbouring cell stay visible.
  lines.forEach((line, row) => {
    const top = snap(row * ch);
    const bottom = snap((row + 1) * ch);
    for (let column = 0; column < view.cols; column += 1) {
      const cell = line[view.x + column];
      if (!cell) continue;
      const x0 = snap(column * cw);
      context.fillStyle = colors[cell[2]];
      context.fillRect(x0, top, snap((column + 1) * cw) - x0, bottom - top);
    }
  });

  lines.forEach((line, row) => {
    const top = snap(row * ch);
    const bottom = snap((row + 1) * ch);
    for (let column = 0; column < view.cols; column += 1) {
      const cell = line[view.x + column];
      if (!cell || cell[0] === " ") continue;
      const [glyph, fg, , bold] = cell;
      const x0 = snap(column * cw);
      const x1 = snap((column + 1) * cw);
      const cx = snap((column + 0.5) * cw);
      const cy = snap((row + 0.5) * ch);
      context.fillStyle = colors[fg];
      context.strokeStyle = colors[fg];
      const weight = bold ? thin * 1.8 : thin;
      const arms = ARMS[glyph];
      const icon = glyphs.get(glyph);
      if (arms) {
        if (arms[0]) context.fillRect(cx - weight / 2, top, weight, cy - top + weight / 2);
        if (arms[2]) context.fillRect(cx - weight / 2, cy - weight / 2, weight, bottom - cy + weight / 2);
        if (arms[3]) context.fillRect(x0, cy - weight / 2, cx - x0 + weight / 2, weight);
        if (arms[1]) context.fillRect(cx - weight / 2, cy - weight / 2, x1 - cx + weight / 2, weight);
      } else if (ROUND[glyph]) {
        const [from, to] = ROUND[glyph];
        const ends = [[cx, top], [x1, cy], [cx, bottom], [x0, cy]];
        context.lineWidth = weight;
        context.beginPath();
        context.moveTo(...ends[from]);
        context.arcTo(cx, cy, ...ends[to], Math.min(cw, ch) / 2);
        context.lineTo(...ends[to]);
        context.stroke();
      } else if (icon) {
        const next = line[view.x + column + 1];
        const wide = next && next[0] === " ";
        const em = Math.min(wide ? WIDE_ICON * cw : cw, ch);
        const centre = (column + (wide ? WIDE_ICON / 2 : 0.5)) * cw;
        context.save();
        context.translate(centre - em / 2, (row + 0.5) * ch - em / 2);
        context.scale(em / 1000, em / 1000);
        context.fill(icon);
        context.restore();
      } else if (glyph === "█") {
        context.fillRect(x0, top, x1 - x0, bottom - top);
      } else if (glyph === "▀" || glyph === "▄") {
        context.fillRect(x0, glyph === "▀" ? top : cy, x1 - x0, glyph === "▀" ? cy - top : bottom - cy);
      } else if (SHADE[glyph]) {
        context.globalAlpha = SHADE[glyph];
        context.fillRect(x0, top, x1 - x0, bottom - top);
        context.globalAlpha = 1;
      } else {
        const wanted = `${bold ? 700 : 400} ${size}px ${mono}`;
        if (wanted !== font) {
          context.font = wanted;
          context.textAlign = "center";
          context.textBaseline = "middle";
          font = wanted;
        }
        context.fillText(glyph, (column + 0.5) * cw, (row + 0.55) * ch);
      }
    }
  });

  if (cursor) {
    const [x, y] = scene.cursor;
    Object.assign(cursor.style, {
      left: `${canvas.offsetLeft + (x - view.x) * cw}px`,
      top: `${canvas.offsetTop + (y - view.y) * ch}px`,
      width: `${cw}px`,
      height: `${ch}px`,
      background: colors[cells(scene.lines[y])[x][1]],
    });
  }
}

/**
 * Renders the scene named by `figure.dataset.scene`, optionally cropped by `data-crop`, into the
 * figure's `.v-frame-canvas`, and keeps it sharp as the figure resizes. A blinking cursor marks
 * the captured cursor position when it falls inside the crop.
 * @param {HTMLElement} figure
 */
export function mountScreenFrame(figure) {
  const scene = SCENES[figure.dataset.scene];
  const view = region(figure.dataset.crop, scene);
  const colors = scene.colors.map((hex) => `#${hex}`);
  const screen = figure.querySelector(".v-frame-screen");
  const canvas = figure.querySelector(".v-frame-canvas");
  figure.style.setProperty("--cols", view.cols);
  figure.style.setProperty("--rows", view.rows);
  screen.style.setProperty("--scene-bg", colors[background(scene)]);

  let cursor = null;
  const [x, y] = scene.cursor || [-1, -1];
  if (x >= view.x && x < view.x + view.cols && y >= view.y && y < view.y + view.rows) {
    cursor = document.createElement("span");
    cursor.className = "v-frame-cursor";
    cursor.setAttribute("aria-hidden", "true");
    screen.append(cursor);
  }

  let frame = 0;
  const draw = () => {
    cancelAnimationFrame(frame);
    frame = requestAnimationFrame(() => render(canvas, cursor, scene, view, colors));
  };
  new ResizeObserver(draw).observe(canvas);
  if (document.fonts && document.fonts.ready) document.fonts.ready.then(draw);
}
