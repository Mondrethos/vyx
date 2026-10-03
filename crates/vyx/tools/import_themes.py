#!/usr/bin/env python3
"""Generate the bundled Rust theme catalog from the canonical Tinted Gallery."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import urllib.request
import unicodedata
from collections import Counter
from pathlib import Path
from typing import Any

GALLERY_COMMIT = "3a7eb3b22a4cff4e0861124fed7eaa25c41f462c"
SOURCE_URL = (
    "https://raw.githubusercontent.com/tinted-theming/tinted-gallery/"
    f"{GALLERY_COMMIT}/assets/gallery.js"
)
SOURCE_SHA256 = "ccf7607b865937c524884abc66ed5989f9fbaefe4d96e5aaf3ed4c791790144f"
SCHEMES_SHA256 = "af946ae61764906f40def3429094eaef9a447de338c35fbe9b4e85461180a8a5"
EXPECTED_COUNTS = {
    ("base16", "dark"): 250,
    ("base16", "light"): 102,
    ("base24", "dark"): 175,
    ("base24", "light"): 34,
    ("tinted8", "dark"): 3,
    ("tinted8", "light"): 1,
}

BASE16_KEYS = tuple(f"base{i:02X}" for i in range(16))
BASE24_KEYS = tuple(f"base{i:02X}" for i in range(24))
TINTED8_COLORS = (
    "black",
    "red",
    "green",
    "yellow",
    "blue",
    "magenta",
    "cyan",
    "white",
    "gray",
    "orange",
    "brown",
)
TINTED8_KEYS = tuple(
    f"{color}-{variant}"
    for color in TINTED8_COLORS
    for variant in ("normal", "bright", "dim")
)
TINTED8_SEMANTIC_UI = (
    "global.background.normal",
    "global.foreground.normal",
    "chrome.background.normal",
    "global.foreground.dark",
    "border.normal",
    "accent.normal",
    "selection.background",
    "selection.foreground",
    "status.success",
    "status.warning",
    "status.error",
    "status.info",
)
TINTED8_ANSI = tuple(
    [f"{color}-normal" for color in TINTED8_COLORS[:8]]
    + [f"{color}-bright" for color in TINTED8_COLORS[:8]]
)
HEX_COLOR = re.compile(r"#[0-9a-fA-F]{6}\Z")


def fail(message: str) -> None:
    raise ValueError(message)


def load_source(source: str | None) -> tuple[bytes, bool]:
    if source is None:
        with urllib.request.urlopen(SOURCE_URL, timeout=30) as response:
            return response.read(), True
    if source == "-":
        return sys.stdin.buffer.read(), False
    if source.startswith(("https://", "http://")):
        with urllib.request.urlopen(source, timeout=30) as response:
            return response.read(), source == SOURCE_URL
    return Path(source).read_bytes(), False


def extract_schemes(raw: bytes) -> list[dict[str, Any]]:
    text = raw.decode("utf-8")
    stripped = text.lstrip()
    if stripped.startswith("["):
        value = json.loads(stripped)
    else:
        match = re.search(r"(?:const|let|var)\s+SCHEMES\s*=\s*", text)
        if match is None:
            fail("input is neither a JSON array nor a gallery asset containing SCHEMES")
        value, _ = json.JSONDecoder().raw_decode(text, match.end())
    if not isinstance(value, list):
        fail("SCHEMES must be a JSON array")
    return value


def canonical_digest(schemes: list[dict[str, Any]]) -> str:
    payload = json.dumps(
        schemes, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def require_string(scheme: dict[str, Any], key: str) -> str:
    value = scheme.get(key)
    if not isinstance(value, str) or not value:
        fail(f"{scheme.get('id', '<unknown>')}: {key} must be a non-empty string")
    return value


def validate_color(owner: str, key: str, value: Any) -> int:
    if not isinstance(value, dict):
        fail(f"{owner}: {key} must be a resolved color object")
    hex_string = value.get("hex_str")
    if not isinstance(hex_string, str) or HEX_COLOR.fullmatch(hex_string) is None:
        fail(f"{owner}: {key}.hex_str must be #RRGGBB")
    number = int(hex_string[1:], 16)
    expected_rgb = [(number >> 16) & 0xFF, (number >> 8) & 0xFF, number & 0xFF]
    if value.get("rgb") != expected_rgb:
        fail(f"{owner}: {key}.rgb disagrees with hex_str")
    return number


def validate_palette(
    scheme_id: str, palette: Any, required_keys: tuple[str, ...]
) -> dict[str, Any]:
    if not isinstance(palette, dict):
        fail(f"{scheme_id}: palette must be an object")
    actual = set(palette)
    required = set(required_keys)
    if actual != required:
        missing = sorted(required - actual)
        unexpected = sorted(actual - required)
        fail(
            f"{scheme_id}: incomplete/malformed palette; "
            f"missing={missing}, unexpected={unexpected}"
        )
    for key, value in palette.items():
        validate_color(scheme_id, f"palette.{key}", value)
    return palette


def validate(schemes: list[dict[str, Any]]) -> None:
    if len(schemes) != sum(EXPECTED_COUNTS.values()):
        fail(f"expected 565 schemes, found {len(schemes)}")

    ids: set[str] = set()
    counts: Counter[tuple[str, str]] = Counter()
    for item in schemes:
        if not isinstance(item, dict):
            fail("every SCHEMES entry must be an object")
        scheme_id = require_string(item, "id")
        if any(unicodedata.category(char) == "Cc" for char in scheme_id):
            fail("entry contains a control character in id")
        name = require_string(item, "name")
        author = item.get("author")
        if not isinstance(author, str):
            fail(f"{scheme_id}: author must be a string")
        system = require_string(item, "system")
        variant = require_string(item, "variant")
        slug = require_string(item, "slug")
        for key, value in (
            ("name", name),
            ("author", author),
            ("system", system),
            ("variant", variant),
            ("slug", slug),
        ):
            if any(unicodedata.category(char) == "Cc" for char in value):
                fail(f"{scheme_id}: control character in {key}")

        if scheme_id in ids:
            fail(f"duplicate scheme id: {scheme_id}")
        ids.add(scheme_id)
        if system not in ("base16", "base24", "tinted8"):
            fail(f"{scheme_id}: unsupported system {system!r}")
        if not scheme_id.startswith(f"{system}-"):
            fail(f"{scheme_id}: id does not preserve its system prefix")
        if variant not in ("dark", "light"):
            fail(f"{scheme_id}: unsupported variant {variant!r}")
        counts[(system, variant)] += 1

        lightness = item.get("lightness")
        if not isinstance(lightness, dict) or not isinstance(
            lightness.get("background"), (int, float)
        ):
            fail(f"{scheme_id}: missing resolved background lightness")
        measured_variant = "light" if lightness["background"] >= 50 else "dark"
        if measured_variant != variant:
            fail(
                f"{scheme_id}: variant {variant!r} disagrees with resolved lightness"
            )

        if system == "base16":
            validate_palette(scheme_id, item.get("palette"), BASE16_KEYS)
        elif system == "base24":
            validate_palette(scheme_id, item.get("palette"), BASE24_KEYS)
        else:
            validate_palette(scheme_id, item.get("palette"), TINTED8_KEYS)
            ui = item.get("ui")
            if not isinstance(ui, dict):
                fail(f"{scheme_id}: missing resolved Tinted8 ui variables")
            for key in TINTED8_SEMANTIC_UI:
                if key not in ui:
                    fail(f"{scheme_id}: missing resolved ui.{key}")
            for key, value in ui.items():
                validate_color(scheme_id, f"ui.{key}", value)


    if dict(counts) != EXPECTED_COUNTS:
        fail(f"unexpected system/appearance counts: {dict(counts)}")
    if "base16-default-dark" not in ids:
        fail("required default base16-default-dark is absent")


def color(palette: dict[str, Any], key: str) -> int:
    return int(palette[key]["hex_str"][1:], 16)


def rust_string(value: str) -> str:
    escaped: list[str] = ['"']
    for char in value:
        code = ord(char)
        if char == "\\":
            escaped.append("\\\\")
        elif char == '"':
            escaped.append('\\"')
        elif char == "\n":
            escaped.append("\\n")
        elif char == "\r":
            escaped.append("\\r")
        elif char == "\t":
            escaped.append("\\t")
        elif code < 0x20 or code == 0x7F:
            escaped.append(f"\\u{{{code:x}}}")
        else:
            escaped.append(char)
    escaped.append('"')
    return "".join(escaped)


def rust_colors(values: list[int], indent: str = "            ") -> list[str]:
    lines: list[str] = []
    for start in range(0, len(values), 8):
        chunk = values[start : start + 8]
        lines.append(indent + " ".join(f"0x{value:06x}," for value in chunk))
    return lines


def generate(schemes: list[dict[str, Any]]) -> str:
    ordered = sorted(
        schemes,
        key=lambda scheme: (
            scheme["name"].casefold(),
            scheme["system"],
            scheme["id"],
        ),
    )
    default_index = next(
        index
        for index, scheme in enumerate(ordered)
        if scheme["id"] == "base16-default-dark"
    )
    lines = [
        "// @generated by tools/import_themes.py; do not edit by hand.",
        f"// Source SCHEMES SHA-256: {SCHEMES_SHA256}",
        "// License and mapping provenance: theme-data/.",
        "",
        "use super::{",
        "    Appearance, Theme, base16_palette, base24_palette, tinted8_palette,",
        "};",
        "",
        "pub static THEMES: &[Theme] = &[",
    ]

    for scheme in ordered:
        system = scheme["system"]
        palette = scheme["palette"]
        lines.extend(
            [
                "    Theme {",
                f"        id: {rust_string(scheme['id'])},",
                f"        name: {rust_string(scheme['name'])},",
                f"        author: {rust_string(scheme['author'])},",
                f"        system: {rust_string(system)},",
                f"        search: {rust_string((scheme['name'] + ' ' + scheme['id']).lower())},",
                f"        appearance: Appearance::{scheme['variant'].title()},",
            ]
        )
        if system == "base16":
            values = [color(palette, key) for key in BASE16_KEYS]
            lines.append("        palette: base16_palette([")
            lines.extend(rust_colors(values))
            lines.append("        ]),")
        elif system == "base24":
            values = [color(palette, key) for key in BASE24_KEYS]
            lines.append("        palette: base24_palette([")
            lines.extend(rust_colors(values))
            lines.append("        ]),")
        else:
            ui = scheme["ui"]
            semantic = [color(ui, key) for key in TINTED8_SEMANTIC_UI]
            ansi = [color(palette, key) for key in TINTED8_ANSI]
            lines.append("        palette: tinted8_palette(")
            lines.append("            [")
            lines.extend(rust_colors(semantic, "                "))
            lines.append("            ],")
            lines.append("            [")
            lines.extend(rust_colors(ansi, "                "))
            lines.append("            ],")
            lines.append("        ),")
        lines.extend(["    },"])

    lines.extend(
        [
            "];",
            "",
            f"pub(super) const DEFAULT_THEME_INDEX: usize = {default_index};",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "source",
        nargs="?",
        help="gallery.js or extracted SCHEMES JSON path/URL; defaults to the pinned asset",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "src/theme/catalog.rs",
        help="generated Rust destination",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify the destination is current instead of writing it",
    )
    args = parser.parse_args()

    raw, pinned_download = load_source(args.source)
    if pinned_download:
        digest = hashlib.sha256(raw).hexdigest()
        if digest != SOURCE_SHA256:
            fail(f"pinned gallery asset SHA-256 changed: {digest}")
    schemes = extract_schemes(raw)
    digest = canonical_digest(schemes)
    if digest != SCHEMES_SHA256:
        fail(f"SCHEMES SHA-256 mismatch: {digest}")
    validate(schemes)
    generated = generate(schemes)

    if args.check:
        if not args.output.exists() or args.output.read_text(encoding="utf-8") != generated:
            print(f"out of date: {args.output}", file=sys.stderr)
            return 1
        print(
            f"verified {len(schemes)} themes "
            f"({sum(v for (s, a), v in EXPECTED_COUNTS.items() if a == 'dark')} dark, "
            f"{sum(v for (s, a), v in EXPECTED_COUNTS.items() if a == 'light')} light)"
        )
        return 0

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(generated, encoding="utf-8")
    print(f"wrote {len(schemes)} themes to {args.output}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(2)
