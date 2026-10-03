// VYX in large block cells over a slowly drifting halftone field. The letter masks are the app's
// own logo (crates/vyx/src/ui/animation.rs). Cells are 1:2 like a terminal, and each logo cell
// covers 2×2 field cells. The pointer lifts nearby field cells toward yellow and ripples the
// letters; a yellow band sweeps the letters every few seconds.
const V = ["##   ##", "##   ##", " ## ## ", " ## ## ", "  ###  "];
const Y = ["##   ##", " ## ## ", "  ###  ", "  ###  ", "  ###  "];
const X = ["##   ##", " ## ## ", "  ###  ", " ## ## ", "##   ##"];
const LOGO_COLS = 25;
const INTRO = 1400;
const SWEEP_EVERY = 7000;
const FRAME_MS = 33;

const clamp01 = (value) => Math.min(1, Math.max(0, value));
const smooth = (value) => {
  const t = clamp01(value);
  return t * t * (3 - 2 * t);
};

function hash(x, y) {
  let h = (Math.imul(x, 374761393) + Math.imul(y, 668265263)) | 0;
  h = Math.imul(h ^ (h >>> 13), 1274126177);
  return ((h ^ (h >>> 16)) >>> 0) / 4294967296;
}

// 2D value noise in [0, 1).
function noise(x, y) {
  const xi = Math.floor(x);
  const yi = Math.floor(y);
  const u = smooth(x - xi);
  const v = smooth(y - yi);
  const a = hash(xi, yi);
  const b = hash(xi + 1, yi);
  const c = hash(xi, yi + 1);
  const d = hash(xi + 1, yi + 1);
  return a + (b - a) * u + (c - a) * v + (a - b - c + d) * u * v;
}

const parse = (hex) => {
  const value = hex.trim().replace("#", "");
  return [0, 2, 4].map((offset) => parseInt(value.slice(offset, offset + 2), 16));
};
const mix = (a, b, t) => a.map((channel, index) => Math.round(channel + (b[index] - channel) * clamp01(t)));
const rgb = (color) => `rgb(${color[0]},${color[1]},${color[2]})`;

// [column, row] of every filled logo cell; letters start nine columns apart.
const LOGO_CELLS = [];
[V, Y, X].forEach((mask, letter) =>
  mask.forEach((row, y) =>
    [...row].forEach((cell, column) => {
      if (cell === "#") LOGO_CELLS.push([letter * 9 + column, y]);
    }),
  ),
);

/**
 * Draws the art into `canvas`, which fills `root`, and reserves `slot` (10 logo-cell heights
 * tall) for the letters. Returns a function that stops the animation.
 * @param {HTMLElement} root
 * @param {HTMLCanvasElement} canvas
 * @param {HTMLElement} slot
 */
export function createArt(root, canvas, slot) {
  const context = canvas.getContext("2d");
  const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const css = getComputedStyle(root);
  const read = (name, fallback) => parse(css.getPropertyValue(name) || fallback);
  const palette = {
    bg: read("--bg", "#282828"),
    line: read("--line", "#3c3836"),
    strong: read("--line-strong", "#504945"),
    hover: read("--line-hover", "#665c54"),
    text: read("--text-strong", "#fbf1c7"),
    yellow: read("--yellow", "#fabd2f"),
  };
  // L is the logo cell width; field cells are L/2 × L.
  let L, bw, bh, cols, rows, ox, oy, width, height;
  const pointer = { x: -9999, y: -9999 };
  let start = performance.now();
  let frame = 0;
  let last = 0;
  let visible = true;
  let alive = true;
  let logoMask = new Set();

  function measure() {
    width = root.clientWidth;
    L = Math.max(8, Math.min(40, Math.floor(Math.min(width * 0.72, 980) / LOGO_COLS)));
    bw = L / 2;
    bh = L;
    slot.style.height = `${5 * 2 * L}px`;
    height = root.clientHeight;
    const ratio = Math.min(2, window.devicePixelRatio || 1);
    canvas.width = Math.round(width * ratio);
    canvas.height = Math.round(height * ratio);
    context.setTransform(ratio, 0, 0, ratio, 0, 0);
    cols = Math.ceil(width / bw) + 1;
    rows = Math.ceil(height / bh) + 1;
    const box = root.getBoundingClientRect();
    const reserved = slot.getBoundingClientRect();
    ox = Math.round((reserved.left - box.left + reserved.width / 2 - (LOGO_COLS * L) / 2) / bw);
    oy = Math.round((reserved.top - box.top) / bh);
    logoMask = new Set();
    for (const [x, y] of LOGO_CELLS) {
      for (let dy = 0; dy < 2; dy += 1) {
        for (let dx = 0; dx < 2; dx += 1) logoMask.add((oy + y * 2 + dy) * 100000 + ox + x * 2 + dx);
      }
    }
  }

  function draw(now) {
    const ms = reduced ? INTRO + 1 + (now - start) : now - start;
    const t = (reduced ? 0.4 : 1) * (ms / 1000);
    context.fillStyle = rgb(palette.bg);
    context.fillRect(0, 0, width, height);

    const fieldIn = reduced ? 1 : smooth(ms / 900);
    for (let cy = 0; cy < rows; cy += 1) {
      for (let cx = 0; cx < cols; cx += 1) {
        if (logoMask.has(cy * 100000 + cx)) continue;
        let v = noise(cx * 0.055 + t * 0.05, cy * 0.11 - t * 0.03) * 0.72 + noise(cx * 0.16 - t * 0.09, cy * 0.3 + 40) * 0.28;
        const px = (cx + 0.5) * bw;
        const py = (cy + 0.5) * bh;
        const d = Math.hypot(px - pointer.x, py - pointer.y);
        const lift = d < 200 ? (1 - d / 200) ** 2 : 0;
        v = v * fieldIn + lift * 0.45;
        if (v < 0.46) continue;
        const k = clamp01((v - 0.46) / 0.44);
        const side = Math.max(1.5, bw * (0.16 + 0.42 * k));
        context.fillStyle = rgb(
          lift > 0.05 ? mix(mix(palette.strong, palette.hover, k), palette.yellow, lift * 0.6) : mix(palette.line, palette.hover, k),
        );
        context.fillRect(px - side / 2, py - side / 2, side, side);
      }
    }

    // Letter cells near the pointer warm toward yellow, shrink, and ripple outward.
    const tracking = pointer.x > -9000;
    const gap = Math.max(1, Math.round(L * 0.06));
    const phase = (ms % SWEEP_EVERY) / 1400;
    const head = -6 + phase * (LOGO_COLS + 18);
    for (const [x, y] of LOGO_CELLS) {
      const grow = reduced ? 1 : smooth((ms - (x * 28 + y * 60)) / 380);
      if (grow <= 0) continue;
      const band = !reduced && phase <= 1 ? clamp01(1 - Math.abs(x + y * 0.6 - head) / 3.5) ** 2 : 0;
      const intro = ms < INTRO ? clamp01(1 - Math.abs(x + y * 0.6 - (-4 + (ms / INTRO) * 34)) / 4) * 0.8 : 0;
      const cx = (ox + x * 2) * bw;
      const cy = (oy + y * 2) * bh;
      const fw = 2 * bw - gap;
      const fh = 2 * bh - gap;
      let hover = 0;
      let dx = 0;
      let dy = 0;
      if (tracking) {
        const mx = cx + fw / 2 - pointer.x;
        const my = cy + fh / 2 - pointer.y;
        const d = Math.hypot(mx, my);
        const R = L * 5;
        if (d < R) {
          const k = (1 - d / R) ** 2;
          const wave = 0.5 + 0.5 * Math.sin(t * 7 - d / (L * 0.9));
          hover = k * (0.55 + 0.45 * wave);
          const push = k * L * 0.28 * wave;
          dx = d ? (mx / d) * push : 0;
          dy = d ? (my / d) * push : 0;
        }
      }
      context.fillStyle = rgb(mix(palette.text, palette.yellow, Math.max(band, intro, hover)));
      const scale = (0.2 + 0.8 * grow) * (1 - hover * 0.22);
      const sw = fw * scale;
      const sh = fh * scale;
      context.fillRect(cx + (fw - sw) / 2 + dx, cy + (fh - sh) / 2 + dy, sw, sh);
    }
  }

  // About 30 frames a second, only while the art is on screen and the tab is visible.
  function loop(now) {
    if (!alive) return;
    frame = requestAnimationFrame(loop);
    if (!visible || document.hidden || now - last < FRAME_MS) return;
    last = now;
    draw(now);
  }

  const onMove = (event) => {
    const box = canvas.getBoundingClientRect();
    pointer.x = event.clientX - box.left;
    pointer.y = event.clientY - box.top;
  };
  const onLeave = () => {
    pointer.x = -9999;
    pointer.y = -9999;
  };
  const resize = new ResizeObserver(() => {
    measure();
    draw(performance.now());
  });
  const intersection = new IntersectionObserver((entries) => {
    visible = entries.some((entry) => entry.isIntersecting);
  });
  resize.observe(root);
  intersection.observe(root);
  measure();

  const go = () => {
    if (!alive) return;
    measure();
    start = performance.now();
    addEventListener("pointermove", onMove, { passive: true });
    document.addEventListener("pointerleave", onLeave);
    frame = requestAnimationFrame(loop);
  };
  if (document.fonts && document.fonts.ready) document.fonts.ready.then(go);
  else go();

  return () => {
    alive = false;
    cancelAnimationFrame(frame);
    resize.disconnect();
    intersection.disconnect();
    removeEventListener("pointermove", onMove);
    document.removeEventListener("pointerleave", onLeave);
  };
}
