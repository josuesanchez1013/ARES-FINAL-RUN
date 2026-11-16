#!/usr/bin/env python3
"""Contrast check for the ARES theme tokens (WCAG 2.x relative luminance).

Reads the light and dark token blocks from frontend/src/styles.css and checks
every text/background pairing the UI uses. Text must reach 4.5:1; non-text
marks (focus ring, primary button edge) must reach 3:1.

    python3 scripts/check_contrast.py
"""
import re
import sys
from pathlib import Path

CSS = Path(__file__).resolve().parent.parent / "frontend" / "src" / "styles.css"
TEXT_PAIRS = [
    ("ink", "canvas"), ("ink", "panel"), ("ink", "sunken"),
    ("muted", "canvas"), ("muted", "panel"), ("muted", "sunken"),
    ("accent-ink", "accent"), ("accent-ink", "accent-hover"),
    ("info-ink", "accent-wash"), ("info-ink", "panel"), ("info-ink", "info-wash"),
    ("critical-ink", "critical-wash"), ("critical-ink", "panel"), ("critical-ink", "sunken"),
    ("good-ink", "good-wash"), ("good-ink", "sunken"),
    ("warning-ink", "warning-wash"), ("warning-ink", "sunken"),
    ("neutral-ink", "neutral-wash"),
]
MARK_PAIRS = [("focus", "panel"), ("focus", "canvas"), ("accent", "panel"), ("critical", "panel")]


def tokens(block: str) -> dict:
    return {k: v.lower() for k, v in re.findall(r"--([a-z-]+):\s*(#[0-9a-fA-F]{6})", block)}


def luminance(hex_colour: str) -> float:
    channels = [int(hex_colour[i:i + 2], 16) / 255 for i in (1, 3, 5)]
    lin = [c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4 for c in channels]
    return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2]


def ratio(a: str, b: str) -> float:
    la, lb = sorted((luminance(a), luminance(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


def main() -> int:
    css = CSS.read_text()
    light = tokens(css[css.index(":root {"):css.index("@media (prefers-color-scheme: dark)")])
    dark_block = css[css.index(':root[data-theme="dark"]'):]
    dark = {**light, **tokens(dark_block[:dark_block.index("}")])}
    failures = 0
    for name, theme in (("light", light), ("dark", dark)):
        for pairs, floor in ((TEXT_PAIRS, 4.5), (MARK_PAIRS, 3.0)):
            for fg, bg in pairs:
                value = ratio(theme[fg], theme[bg])
                ok = value >= floor
                failures += not ok
                print(f"{'PASS' if ok else 'FAIL'}  {name:5}  {fg:>13} on {bg:<14} {value:5.2f}  (min {floor})")
    print(f"\n{failures} failing pair(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
