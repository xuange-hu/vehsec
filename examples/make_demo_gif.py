#!/usr/bin/env python3
"""Offline renderer for the README demo GIF and the GitHub social preview image.

No screen recording, no asciinema, no terminal emulator: it runs the *real*
``vehsec`` commands, captures their output, and renders it into an animated
terminal GIF with Pillow. Deterministic and reproducible in CI.

    python examples/make_demo_gif.py              # writes docs/demo.gif + social-preview.png
    python examples/make_demo_gif.py --gif-only
    python examples/make_demo_gif.py --social-only
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
FONT_PATHS = [
    "C:/Windows/Fonts/CascadiaMono.ttf",
    "C:/Windows/Fonts/consola.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
]

# --- palette (GitHub dark) -------------------------------------------------- #
BG = (13, 17, 23)
BAR = (22, 27, 34)
FG = (201, 209, 217)
PROMPT = (126, 231, 135)     # green
CMD = (230, 237, 243)        # white
ACCENT = (121, 192, 255)     # blue  (hex values / results)
DIM = (110, 118, 129)
DOTS = [(255, 95, 86), (255, 189, 46), (39, 201, 63)]

W, H = 920, 520
BAR_H = 44
PAD = 18
FONT_SIZE = 15
LINE_H = 21
MAX_CHARS = 94

# The scenes: real commands, real output.
SCENES = [
    ["can", "analyze", "--file", "examples/sample_candump.log"],
    ["seedkey", "solve", "--vendor", "training_rotate", "--seed", "0102"],
    ["uds", "read", "--did", "0xF190"],
    ["j1939", "decode", "--id", "0x18F00400", "--data", "FFFFFFFF0010FFFF"],
    ["icsim", "demo", "--kmh", "250"],
]


def load_font(size: int) -> ImageFont.FreeTypeFont:
    for p in FONT_PATHS:
        if os.path.exists(p):
            return ImageFont.truetype(p, size)
    return ImageFont.load_default()


def _has_cjk(line: str) -> bool:
    """Cascadia Mono cannot render CJK; such lines would draw as tofu boxes."""
    return any(0x2E80 <= ord(c) <= 0x9FFF or 0xFF00 <= ord(c) <= 0xFFEF for c in line)


def run_scene(argv: list[str]) -> list[str]:
    """Run a vehsec command and return its captured output lines."""
    env = dict(os.environ, COLUMNS="88", TERM="dumb", NO_COLOR="1")
    proc = subprocess.run(
        [sys.executable, "-m", "vehsec.cli", *argv],
        cwd=ROOT, capture_output=True, text=True, env=env, timeout=60,
    )
    text = (proc.stdout or "") + (proc.stderr or "")
    lines = []
    for raw in text.splitlines():
        line = raw.rstrip()
        if _has_cjk(line):
            continue
        lines.append(line[:MAX_CHARS] if len(line) > MAX_CHARS else line)
    return lines or ["(no output)"]


def color_for(line: str) -> tuple[int, int, int]:
    if line.startswith("$ "):
        return PROMPT
    if line.startswith("->") or " OK " in line or line.strip().startswith("OK"):
        return ACCENT
    if line.startswith("#") or not line.strip():
        return DIM
    return FG


MAX_LINES = (H - BAR_H - 2 * PAD) // LINE_H  # visible rows; older lines scroll off


def render_frame(lines: list[tuple[str, tuple[int, int, int]]], font) -> Image.Image:
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, W, BAR_H], fill=BAR)
    for i, c in enumerate(DOTS):
        x = 18 + i * 20
        d.ellipse([x, BAR_H // 2 - 5, x + 10, BAR_H // 2 + 5], fill=c)
    title = "vehsec — bash"
    d.text((W // 2 - d.textlength(title, font=font) / 2, BAR_H // 2 - 8),
           title, font=font, fill=DIM)

    y = BAR_H + PAD
    for text, color in lines[-MAX_LINES:]:
        d.text((PAD, y), text, font=font, fill=color)
        y += LINE_H
    return img


def make_gif(out: Path) -> int:
    font = load_font(FONT_SIZE)
    frames: list[Image.Image] = []
    durations: list[int] = []
    screen: list[tuple[str, tuple[int, int, int]]] = []

    for argv in SCENES:
        cmd = "vehsec " + " ".join(argv)
        try:
            out_lines = run_scene(argv)
        except Exception as e:  # noqa: BLE001
            out_lines = [f"(demo capture failed: {e})"]

        # typing animation
        for i in range(3, len(cmd) + 3, 3):
            frames.append(render_frame(screen + [("$ " + cmd[:i], CMD)], font))
            durations.append(45)
        screen.append(("$ " + cmd, PROMPT))
        frames.append(render_frame(screen, font))
        durations.append(220)

        # output reveal
        for line in out_lines[:12]:
            screen.append((line, color_for(line)))
            frames.append(render_frame(screen, font))
            durations.append(90)
        frames.append(render_frame(screen, font))
        durations.append(900)
        screen.append(("", DIM))

    # hold the final frame a little longer
    for _ in range(3):
        frames.append(render_frame(screen, font))
        durations.append(1200)

    out.parent.mkdir(parents=True, exist_ok=True)
    first = frames[0].convert("P", palette=Image.ADAPTIVE, colors=64)
    rest = [f.convert("P", palette=Image.ADAPTIVE, colors=64) for f in frames[1:]]
    # disposal=2 (restore to background) keeps every frame self-contained, so the
    # animation composites correctly in browsers and in frame-by-frame extraction.
    first.save(out, save_all=True, append_images=rest, duration=durations,
               loop=0, optimize=True, disposal=2)
    return len(frames)


def make_social(out: Path) -> None:
    font_big = load_font(64)
    font_mid = load_font(28)
    font_small = load_font(22)
    img = Image.new("RGB", (1280, 640), BG)
    d = ImageDraw.Draw(img)

    # accent bar
    d.rectangle([0, 0, 1280, 8], fill=(63, 185, 80))
    # subtle grid of "CAN" boxes on the right
    for i in range(6):
        x = 860 + (i % 3) * 120
        y = 380 + (i // 3) * 90
        d.rectangle([x, y, x + 100, y + 70], outline=(48, 54, 61), width=2)

    d.text((80, 180), "vehsec", font=font_big, fill=CMD)
    d.text((80, 270), "Vehicle Security Toolkit", font=font_mid, fill=ACCENT)
    d.text((80, 320), "CAN  ·  UDS  ·  Seed-Key  ·  V2X  ·  ICSim  ·  DoIP  ·  DBC  ·  J1939  ·  ISO-TP",
           font=font_small, fill=FG)
    d.text((80, 380), "One core library, three surfaces: CLI · TUI · MCP server.",
           font=font_small, fill=FG)
    d.text((80, 420), "Runs on a virtual CAN bus — no car required.",
           font=font_small, fill=PROMPT)
    d.text((80, 540), "github.com/xuange-hu/vehsec", font=font_small, fill=DIM)

    out.parent.mkdir(parents=True, exist_ok=True)
    img.save(out)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--gif-only", action="store_true")
    ap.add_argument("--social-only", action="store_true")
    ap.add_argument("--gif-out", default=str(ROOT / "docs" / "demo.gif"))
    ap.add_argument("--social-out", default=str(ROOT / "docs" / "social-preview.png"))
    args = ap.parse_args()

    if not args.social_only:
        n = make_gif(Path(args.gif_out))
        print(f"[+] wrote {args.gif_out} ({n} frames)")
    if not args.gif_only:
        make_social(Path(args.social_out))
        print(f"[+] wrote {args.social_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
