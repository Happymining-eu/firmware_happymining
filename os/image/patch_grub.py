#!/usr/bin/env python3
"""Add the HappyMining OS menu entries to the GRUB configuration of an Ubuntu
Server live ISO, and keep md5sum.txt consistent.

  patch_grub.py grub --in ORIGINAL_grub.cfg --entries grub-entries.cfg.in --out NEW_grub.cfg
  patch_grub.py md5  --in ORIGINAL_md5sum.txt --root STAGED_TREE --out NEW_md5sum.txt PATH...

"grub": the kernel and initrd paths are taken from the first menu entry of the
ORIGINAL configuration that boots the live system (a "linux" line with a
/casper/ kernel), so the HappyMining entries always use the same files as
Ubuntu's own entry. The new entries are inserted before the first original
menu entry and therefore become the default. Every original entry is kept.
The result is refused if any kernel command line (original or new) contains
the "autoinstall" keyword: that keyword removes the installer's confirmation
prompt and must never be baked into the distributed image.

"md5": md5sum.txt in the ISO root lists "<md5>  ./path" for the files of the
medium and is used by the live system's integrity self-check. For each PATH
(relative to the ISO root, present under --root) the entry is replaced or
added, so the self-check does not report the files we changed or added.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import sys

AUTOCONFIRM_KEYWORD = "autoinstall"
LINUX_RE = re.compile(r"^\s*(linux|linuxefi)\s+(\S+)(.*)$")
INITRD_RE = re.compile(r"^\s*(initrd|initrdefi)\s+(\S+)")
MENUENTRY_RE = re.compile(r"^\s*menuentry\s")


class PatchError(Exception):
    pass


def kernel_lines_with_autoconfirm(text: str) -> list[int]:
    """Line numbers of 'linux' lines that pass the bare keyword to the kernel."""
    hits = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if line.lstrip().startswith("#") or not LINUX_RE.match(line):
            continue
        if any(token.strip("\"'\\;") == AUTOCONFIRM_KEYWORD for token in line.split()[1:]):
            hits.append(lineno)
    return hits


def find_live_entry(lines: list[str]) -> tuple[int, str, str]:
    """Return (index of the first menuentry line, kernel path, initrd path)."""
    first_menu = None
    in_entry = False
    depth = 0
    kernel = initrd = None
    for index, line in enumerate(lines):
        if MENUENTRY_RE.match(line):
            if first_menu is None:
                first_menu = index
            in_entry = True
            depth = 0
            kernel = initrd = None
        if in_entry:
            m = LINUX_RE.match(line)
            if m and m.group(2).startswith("/casper/"):
                kernel = m.group(2)
            m = INITRD_RE.match(line)
            if m and m.group(2).startswith("/casper/"):
                initrd = m.group(2)
            depth += line.count("{") - line.count("}")
            if depth <= 0 and "}" in line:
                if kernel and initrd:
                    assert first_menu is not None
                    return first_menu, kernel, initrd
                in_entry = False
    raise PatchError(
        "no menu entry that boots /casper/<kernel> with a /casper/<initrd> was found; "
        "the layout of this ISO's grub.cfg is not the one this tool knows — refusing to guess"
    )


def patch_grub(original: str, entries_template: str) -> str:
    if "HappyMining OS entries" in original:
        raise PatchError("this grub.cfg already contains HappyMining OS entries")
    hits = kernel_lines_with_autoconfirm(original)
    if hits:
        raise PatchError(
            f"the original grub.cfg already has 'autoinstall' on a kernel line (line {hits[0]}); "
            "this is not an unmodified Ubuntu ISO"
        )
    lines = original.splitlines()
    first_menu, kernel, initrd = find_live_entry(lines)
    if not re.fullmatch(r"/casper/[A-Za-z0-9._-]+", kernel) or not re.fullmatch(r"/casper/[A-Za-z0-9._-]+", initrd):
        raise PatchError(f"unexpected kernel or initrd path: {kernel} {initrd}")
    entries = entries_template.replace("@@KERNEL@@", kernel).replace("@@INITRD@@", initrd)
    if "@@" in entries:
        raise PatchError("unresolved marker in the entries template")
    new_lines = lines[:first_menu] + entries.rstrip("\n").splitlines() + lines[first_menu:]
    result = "\n".join(new_lines) + "\n"
    hits = kernel_lines_with_autoconfirm(result)
    if hits:
        raise PatchError(
            f"result line {hits[0]}: a kernel command line contains 'autoinstall'. The distributed image must "
            "keep the installer's confirmation prompt"
        )
    if "ds=nocloud\\;s=file:///cdrom/happymining/seed/" not in result:
        raise PatchError("the generic entry does not point at the seed on the medium")
    return result


def md5_of(path: str) -> str:
    digest = hashlib.md5()  # noqa: S324 - format of Ubuntu's md5sum.txt, not a security control
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def patch_md5(original: str, root: str, paths: list[str]) -> str:
    wanted: dict[str, str] = {}
    for rel in paths:
        rel = rel.lstrip("/")
        if rel.startswith("../") or "/../" in rel:
            raise PatchError(f"bad path: {rel}")
        full = os.path.join(root, rel)
        if not os.path.isfile(full):
            raise PatchError(f"{full} does not exist")
        wanted["./" + rel] = md5_of(full)
    out = []
    seen: set[str] = set()
    for line in original.splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2 and parts[1] in wanted:
            out.append(f"{wanted[parts[1]]}  {parts[1]}")
            seen.add(parts[1])
        else:
            out.append(line)
    for name in sorted(wanted):
        if name not in seen:
            out.append(f"{wanted[name]}  {name}")
    return "\n".join(out) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    g = sub.add_parser("grub")
    g.add_argument("--in", dest="src", required=True)
    g.add_argument("--entries", required=True)
    g.add_argument("--out", required=True)
    m = sub.add_parser("md5")
    m.add_argument("--in", dest="src", required=True)
    m.add_argument("--root", required=True)
    m.add_argument("--out", required=True)
    m.add_argument("paths", nargs="+")
    args = parser.parse_args(argv)
    try:
        with open(args.src, encoding="utf-8") as fh:
            original = fh.read()
        if args.command == "grub":
            with open(args.entries, encoding="utf-8") as fh:
                result = patch_grub(original, fh.read())
        else:
            result = patch_md5(original, args.root, args.paths)
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(result)
    except (OSError, PatchError, UnicodeDecodeError) as exc:
        print(f"patch_grub.py: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
