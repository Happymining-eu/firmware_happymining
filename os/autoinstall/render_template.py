#!/usr/bin/env python3
"""Tiny, strict template renderer for the per-machine unattended seed.

Used by render-seed.sh and by validate.py (which renders the template with
dummy values before validating it). No third-party modules.

Template syntax (os/autoinstall/user-data.unattended.yaml.tmpl):

  @@NAME@@            replaced by the value as a double-quoted YAML scalar
                      (JSON string quoting, which is valid YAML), so a value
                      can never change the structure of the document.
  @@LIST:NAME@@       must be alone on its line; replaced by one "- "value""
                      line per item, at the indentation of the placeholder.
  @@BLOCK:NAME@@      must be alone on its line; replaced by the lines of the
                      given text, each at the indentation of the placeholder
                      (used to embed disk-guard.sh inside a YAML literal block).
  #@@IF FLAG / #@@ENDIF
                      the lines in between are kept only when FLAG is enabled.
                      No nesting.

Rendering fails (ValueError) on: an unknown or unused name, a placeholder left
in the output, an unterminated #@@IF, or a control character in a value.
"""

from __future__ import annotations

import argparse
import json
import re
import sys

PLACEHOLDER_RE = re.compile(r"@@([A-Z][A-Z0-9_]*)@@")
LINE_DIRECTIVE_RE = re.compile(r"^(?P<indent>[ ]*)@@(?P<kind>LIST|BLOCK):(?P<name>[A-Z][A-Z0-9_]*)@@[ ]*$")
IF_RE = re.compile(r"^#@@IF ([A-Z][A-Z0-9_]*)\s*$")
ENDIF_RE = re.compile(r"^#@@ENDIF\s*$")
ANY_MARKER_RE = re.compile(r"@@")


def _check_scalar(name: str, value: str) -> None:
    if not isinstance(value, str):
        raise ValueError(f"value for {name} must be a string")
    for ch in value:
        if ord(ch) < 0x20 or ord(ch) == 0x7F:
            raise ValueError(f"value for {name} contains a control character")


def yaml_quote(value: str) -> str:
    """Double-quoted YAML scalar. JSON string syntax is a subset of YAML's."""
    return json.dumps(value, ensure_ascii=True)


def render(
    template: str,
    values: dict[str, str],
    lists: dict[str, list[str]] | None = None,
    blocks: dict[str, str] | None = None,
    flags: set[str] | None = None,
) -> str:
    lists = lists or {}
    blocks = blocks or {}
    flags = flags or set()
    for name, value in values.items():
        _check_scalar(name, value)
    for name, items in lists.items():
        if not items:
            raise ValueError(f"list {name} is empty")
        for item in items:
            _check_scalar(name, item)

    used: set[str] = set()
    out: list[str] = []
    skipping = False
    in_if: str | None = None

    for lineno, line in enumerate(template.splitlines(), start=1):
        m_if = IF_RE.match(line)
        if m_if:
            if in_if is not None:
                raise ValueError(f"line {lineno}: nested #@@IF is not supported")
            in_if = m_if.group(1)
            used.add("FLAG:" + in_if)
            skipping = in_if not in flags
            continue
        if ENDIF_RE.match(line):
            if in_if is None:
                raise ValueError(f"line {lineno}: #@@ENDIF without #@@IF")
            in_if = None
            skipping = False
            continue
        if skipping:
            continue

        m_dir = LINE_DIRECTIVE_RE.match(line)
        if m_dir:
            indent, kind, name = m_dir.group("indent"), m_dir.group("kind"), m_dir.group("name")
            if kind == "LIST":
                if name not in lists:
                    raise ValueError(f"line {lineno}: no list given for {name}")
                used.add("LIST:" + name)
                out.extend(f"{indent}- {yaml_quote(item)}" for item in lists[name])
            else:
                if name not in blocks:
                    raise ValueError(f"line {lineno}: no block given for {name}")
                used.add("BLOCK:" + name)
                for block_line in blocks[name].splitlines():
                    if "\t" in block_line:
                        raise ValueError(f"block {name} contains a tab character")
                    out.append((indent + block_line) if block_line.strip() else "")
            continue

        def substitute(match: re.Match[str]) -> str:
            name = match.group(1)
            if name not in values:
                raise ValueError(f"line {lineno}: no value given for {name}")
            used.add(name)
            return yaml_quote(values[name])

        rendered = PLACEHOLDER_RE.sub(substitute, line)
        out.append(rendered)

    if in_if is not None:
        raise ValueError(f"#@@IF {in_if} is never closed")

    for name in values:
        if name not in used:
            raise ValueError(f"value {name} is not used by the template")
    for name in lists:
        if "LIST:" + name not in used:
            raise ValueError(f"list {name} is not used by the template")
    for name in blocks:
        if "BLOCK:" + name not in used:
            raise ValueError(f"block {name} is not used by the template")
    for flag in flags:
        if "FLAG:" + flag not in used:
            raise ValueError(f"flag {flag} is not used by the template")

    text = "\n".join(out) + "\n"
    # Nothing that looks like template syntax may survive, except inside an
    # embedded block (the embedded script is copied verbatim and contains none).
    for lineno, line in enumerate(text.splitlines(), start=1):
        if PLACEHOLDER_RE.search(line) or line.startswith("#@@"):
            raise ValueError(f"output line {lineno}: unresolved template marker")
    return text


def _parse_pairs(items: list[str], what: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for item in items:
        if "=" not in item:
            raise ValueError(f"{what} must be NAME=VALUE: {item!r}")
        name, value = item.split("=", 1)
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", name):
            raise ValueError(f"bad {what} name: {name!r}")
        if name in result:
            raise ValueError(f"{what} {name} given twice")
        result[name] = value
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--template", required=True)
    parser.add_argument("--set", action="append", default=[], metavar="NAME=VALUE")
    parser.add_argument("--list-item", action="append", default=[], metavar="NAME=VALUE",
                        help="append VALUE to list NAME (repeat)")
    parser.add_argument("--block-file", action="append", default=[], metavar="NAME=PATH")
    parser.add_argument("--enable", action="append", default=[], metavar="FLAG")
    args = parser.parse_args(argv)

    try:
        values = _parse_pairs(args.set, "--set")
        lists: dict[str, list[str]] = {}
        for item in args.list_item:
            if "=" not in item:
                raise ValueError(f"--list-item must be NAME=VALUE: {item!r}")
            name, value = item.split("=", 1)
            lists.setdefault(name, []).append(value)
        blocks: dict[str, str] = {}
        for name, path in _parse_pairs(args.block_file, "--block-file").items():
            with open(path, encoding="utf-8") as fh:
                blocks[name] = fh.read()
        with open(args.template, encoding="utf-8") as fh:
            template = fh.read()
        sys.stdout.write(render(template, values, lists, blocks, set(args.enable)))
    except (OSError, ValueError) as exc:
        print(f"render_template.py: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
