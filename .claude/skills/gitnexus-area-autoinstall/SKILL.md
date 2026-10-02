---
name: gitnexus-area-autoinstall
description: "Skill for the Autoinstall area of firmware_happymining. 21 symbols across 2 files."
---

# Autoinstall

21 symbols | 2 files | Cohesion: 84%

## When to Use

- Working with code in `os/`
- Understanding how main, render, substitute work
- Modifying autoinstall-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `os/autoinstall/validate.py` | _is_set, common_checks, generic_checks, schema_check, validate_text (+10) |
| `os/autoinstall/render_template.py` | _check_scalar, _parse_pairs, main, render, substitute (+1) |

## Entry Points

Start here when exploring this area:

- **`main`** (Function) — `os/autoinstall/render_template.py:159`
- **`render`** (Function) — `os/autoinstall/render_template.py:51`
- **`substitute`** (Function) — `os/autoinstall/render_template.py:110`
- **`yaml_quote`** (Function) — `os/autoinstall/render_template.py:46`
- **`common_checks`** (Function) — `os/autoinstall/validate.py:141`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `main` | Function | `os/autoinstall/render_template.py` | 159 |
| `render` | Function | `os/autoinstall/render_template.py` | 51 |
| `substitute` | Function | `os/autoinstall/render_template.py` | 110 |
| `yaml_quote` | Function | `os/autoinstall/render_template.py` | 46 |
| `common_checks` | Function | `os/autoinstall/validate.py` | 141 |
| `generic_checks` | Function | `os/autoinstall/validate.py` | 207 |
| `schema_check` | Function | `os/autoinstall/validate.py` | 180 |
| `validate_text` | Function | `os/autoinstall/validate.py` | 416 |
| `walk` | Function | `os/autoinstall/validate.py` | 123 |
| `grub_checks` | Function | `os/autoinstall/validate.py` | 407 |
| `kernel_line_has_autoconfirm` | Function | `os/autoinstall/validate.py` | 396 |
| `main` | Function | `os/autoinstall/validate.py` | 482 |
| `render_dummy` | Function | `os/autoinstall/validate.py` | 439 |
| `report` | Function | `os/autoinstall/validate.py` | 471 |
| `unattended_checks` | Function | `os/autoinstall/validate.py` | 281 |
| `_check_scalar` | Function | `os/autoinstall/render_template.py` | 38 |
| `_parse_pairs` | Function | `os/autoinstall/render_template.py` | 145 |
| `_is_set` | Function | `os/autoinstall/validate.py` | 137 |
| `_check_match` | Function | `os/autoinstall/validate.py` | 381 |
| `_exact_serial` | Function | `os/autoinstall/validate.py` | 242 |

## How to Explore

1. `context({name: "main"})` — see callers and callees
2. `query({search_query: "autoinstall"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
