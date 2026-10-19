#!/usr/bin/env python3
"""Render the GRUB theme of the installation medium from the logo.

  render_theme.py --logo LOGO.png --template grub-theme.txt.in --out DIR

DIR becomes /boot/grub/happymining on the medium:
  theme.txt        the template with the logo's display size filled in
  logo.png         the logo, byte for byte
  select_*.png     nine 8x8 solid tiles used as the highlight of the selected
                   menu entry (GRUB's "pixmap style" needs one tile per edge
                   and corner; here they are all the same colour)

The logo must be a PNG (checked by its signature and IHDR chunk, nothing else
is parsed). It is shown at its natural size, scaled down proportionally when
it is wider than MAX_W or taller than MAX_H, so the menu below it keeps its
place at every screen resolution.

Exit codes: 0 rendered, 1 bad input, 2 usage or I/O error.
"""

from __future__ import annotations

import argparse
import os
import struct
import sys
import zlib

MAX_W = 440
MAX_H = 140
TITLE_GAP = 18

# Colours of the menu. Change them here; the template only carries markers.
COLOURS = {
    "BG": "#0b1220",       # page background (dark navy)
    "FG": "#ffffff",       # titles and the selected entry
    "MUTED": "#9aa4b2",    # other entries and hints
    "ACCENT": "#f5a623",   # timeout bar and the selection tile
    "BAR_BG": "#1f2937",
}
SELECT_TILE_RGB = (0x2b, 0x3a, 0x55)  # dark blue tile behind the selected entry
SELECT_SLICES = ("nw", "n", "ne", "w", "c", "e", "sw", "s", "se")

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


class ThemeError(Exception):
    pass


def png_size(path: str) -> tuple[int, int]:
    with open(path, "rb") as fh:
        head = fh.read(33)
    if len(head) < 33 or head[:8] != PNG_SIGNATURE or head[12:16] != b"IHDR":
        raise ThemeError(f"{path}: not a PNG file (the logo must be a PNG)")
    width, height = struct.unpack(">II", head[16:24])
    if width == 0 or height == 0:
        raise ThemeError(f"{path}: empty image")
    return width, height


def display_size(width: int, height: int) -> tuple[int, int]:
    scale = min(1.0, MAX_W / width, MAX_H / height)
    return max(1, round(width * scale)), max(1, round(height * scale))


def solid_png(width: int, height: int, rgb: tuple[int, int, int]) -> bytes:
    def chunk(kind: bytes, data: bytes) -> bytes:
        crc = struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
        return struct.pack(">I", len(data)) + kind + data + crc

    row = b"\x00" + bytes(rgb) * width
    raw = row * height
    return (PNG_SIGNATURE
            + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 9))
            + chunk(b"IEND", b""))


def render(template: str, width: int, height: int) -> str:
    values = dict(COLOURS)
    values["LOGO_W"] = str(width)
    values["LOGO_H"] = str(height)
    values["LOGO_HALF_W"] = str(width // 2)
    values["TITLE_OFFSET"] = str(height + TITLE_GAP)
    out = template
    for key, value in values.items():
        out = out.replace(f"@@{key}@@", value)
    if "@@" in out:
        raise ThemeError("unresolved marker in the theme template")
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--logo", required=True)
    parser.add_argument("--template", required=True)
    parser.add_argument("--out", required=True, help="output directory (created; must be empty)")
    args = parser.parse_args(argv)
    try:
        width, height = png_size(args.logo)
        shown_w, shown_h = display_size(width, height)
        with open(args.template, encoding="utf-8") as fh:
            theme = render(fh.read(), shown_w, shown_h)
        if os.path.isdir(args.out) and os.listdir(args.out):
            raise ThemeError(f"{args.out} is not empty")
        os.makedirs(args.out, exist_ok=True)
        with open(os.path.join(args.out, "theme.txt"), "w", encoding="utf-8") as fh:
            fh.write(theme)
        with open(args.logo, "rb") as src, open(os.path.join(args.out, "logo.png"), "wb") as dst:
            dst.write(src.read())
        tile = solid_png(8, 8, SELECT_TILE_RGB)
        for slice_name in SELECT_SLICES:
            with open(os.path.join(args.out, f"select_{slice_name}.png"), "wb") as fh:
                fh.write(tile)
        print(f"render_theme.py: logo {width}x{height} shown at {shown_w}x{shown_h}; "
              f"theme written to {args.out}")
    except ThemeError as exc:
        print(f"render_theme.py: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"render_theme.py: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
