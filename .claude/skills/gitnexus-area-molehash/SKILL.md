---
name: gitnexus-area-molehash
description: "Skill for the Molehash area of firmware_happymining. 18 symbols across 1 files."
---

# Molehash

18 symbols | 1 files | Cohesion: 81%

## When to Use

- Working with code in `integrations/`
- Understanding how to_device_record, cancel_operation, earnings_summary work
- Modifying molehash-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `integrations/molehash/happymining_client.py` | _segment, _call, _error, cancel_operation, earnings_summary (+13) |

## Entry Points

Start here when exploring this area:

- **`to_device_record`** (Function) — `integrations/molehash/happymining_client.py:280`
- **`cancel_operation`** (Method) — `integrations/molehash/happymining_client.py:270`
- **`earnings_summary`** (Method) — `integrations/molehash/happymining_client.py:237`
- **`machine`** (Method) — `integrations/molehash/happymining_client.py:195`
- **`operation`** (Method) — `integrations/molehash/happymining_client.py:220`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `to_device_record` | Function | `integrations/molehash/happymining_client.py` | 280 |
| `cancel_operation` | Method | `integrations/molehash/happymining_client.py` | 270 |
| `earnings_summary` | Method | `integrations/molehash/happymining_client.py` | 237 |
| `machine` | Method | `integrations/molehash/happymining_client.py` | 195 |
| `operation` | Method | `integrations/molehash/happymining_client.py` | 220 |
| `operation_types` | Method | `integrations/molehash/happymining_client.py` | 212 |
| `request_operation` | Method | `integrations/molehash/happymining_client.py` | 242 |
| `telemetry` | Method | `integrations/molehash/happymining_client.py` | 198 |
| `describe` | Method | `integrations/molehash/happymining_client.py` | 184 |
| `fleet_summary` | Method | `integrations/molehash/happymining_client.py` | 188 |
| `earnings_daily` | Method | `integrations/molehash/happymining_client.py` | 223 |
| `machines` | Method | `integrations/molehash/happymining_client.py` | 191 |
| `operations` | Method | `integrations/molehash/happymining_client.py` | 215 |
| `_segment` | Function | `integrations/molehash/happymining_client.py` | 41 |
| `_main` | Function | `integrations/molehash/happymining_client.py` | 314 |
| `_call` | Method | `integrations/molehash/happymining_client.py` | 101 |
| `_error` | Method | `integrations/molehash/happymining_client.py` | 158 |
| `_pages` | Method | `integrations/molehash/happymining_client.py` | 171 |

## How to Explore

1. `context({name: "to_device_record"})` — see callers and callees
2. `query({search_query: "molehash"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
