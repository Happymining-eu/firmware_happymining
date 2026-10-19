"""render_theme.py: the GRUB theme of the medium, rendered from the logo."""

from __future__ import annotations

import struct
import sys
import zlib

from hm_os_testlib import IMAGE_DIR, run

RENDER = IMAGE_DIR / "render_theme.py"
TEMPLATE = IMAGE_DIR / "branding/grub-theme.txt.in"
sys.dont_write_bytecode = True   # os/ must stay free of __pycache__ (test_shell_lint)
sys.path.insert(0, str(IMAGE_DIR))
import render_theme  # noqa: E402


def write_png(path, width, height):
    path.write_bytes(render_theme.solid_png(width, height, (255, 255, 255)))


def test_small_logo_is_shown_at_its_natural_size(tmp_path):
    logo = tmp_path / "logo.png"
    write_png(logo, 300, 90)
    out = run(["python3", RENDER, "--logo", logo, "--template", TEMPLATE, "--out", tmp_path / "theme"])
    assert out.returncode == 0, out.stderr
    theme = (tmp_path / "theme/theme.txt").read_text()
    assert "width = 300\n" in theme and "height = 90\n" in theme
    assert "left = 50%-150\n" in theme
    assert "top = 9%+108\n" in theme           # logo height + gap
    assert "@@" not in theme
    assert (tmp_path / "theme/logo.png").read_bytes() == logo.read_bytes()
    slices = sorted(p.name for p in (tmp_path / "theme").glob("select_*.png"))
    assert slices == sorted(f"select_{s}.png" for s in ("nw", "n", "ne", "w", "c", "e", "sw", "s", "se"))
    assert "logo 300x90 shown at 300x90" in out.stdout


def test_large_logo_is_scaled_down_proportionally(tmp_path):
    logo = tmp_path / "logo.png"
    write_png(logo, 1600, 400)
    out = run(["python3", RENDER, "--logo", logo, "--template", TEMPLATE, "--out", tmp_path / "theme"])
    assert out.returncode == 0, out.stderr
    theme = (tmp_path / "theme/theme.txt").read_text()
    assert "width = 440\n" in theme and "height = 110\n" in theme
    assert "logo 1600x400 shown at 440x110" in out.stdout


def test_generated_tiles_are_valid_png(tmp_path):
    data = render_theme.solid_png(8, 8, (1, 2, 3))
    assert data[:8] == b"\x89PNG\r\n\x1a\n"
    assert struct.unpack(">II", data[16:24]) == (8, 8)
    idat = data[data.index(b"IDAT") + 4:]
    length = struct.unpack(">I", data[data.index(b"IDAT") - 4:data.index(b"IDAT")])[0]
    assert zlib.decompress(idat[:length]) == (b"\x00" + b"\x01\x02\x03" * 8) * 8


def test_non_png_logo_is_refused(tmp_path):
    logo = tmp_path / "logo.png"
    logo.write_bytes(b"GIF89a not a png at all" + b"\x00" * 40)
    out = run(["python3", RENDER, "--logo", logo, "--template", TEMPLATE, "--out", tmp_path / "theme"])
    assert out.returncode == 1 and "must be a PNG" in out.stderr
    assert not (tmp_path / "theme").exists()


def test_non_empty_output_directory_is_refused(tmp_path):
    logo = tmp_path / "logo.png"
    write_png(logo, 10, 10)
    (tmp_path / "theme").mkdir()
    (tmp_path / "theme/stray").write_text("x")
    out = run(["python3", RENDER, "--logo", logo, "--template", TEMPLATE, "--out", tmp_path / "theme"])
    assert out.returncode == 1 and "not empty" in out.stderr
