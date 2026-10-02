---
name: gitnexus-area-providers
description: "Skill for the Providers area of firmware_happymining. 39 symbols across 6 files."
---

# Providers

39 symbols | 6 files | Cohesion: 79%

## When to Use

- Working with code in `api/`
- Understanding how dumps, epoch_day, from_epoch_day work
- Modifying providers-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `api/happymining/providers/base.py` | ProviderAuthError, ProviderAuthorizationUnverified, ProviderError, ProviderFeatureDisabled, ProviderFeatureUnverified (+6) |
| `api/happymining/providers/fake.py` | earnings_body, fetch_earnings, _check, _machine, _rental (+5) |
| `api/happymining/providers/vast_wire.py` | _money, dumps, epoch_day, from_epoch_day, loads (+3) |
| `api/happymining/providers/vast.py` | fetch_earnings, _get, _raise_for, _ready, check_health (+2) |
| `tests/api/test_provider_vast.py` | test_unverified_commercial_authorization_blocks_every_call, test_missing_key_fails_explicitly_without_calling_vast |
| `tests/api/test_security_regressions.py` | Unauthorised |

## Entry Points

Start here when exploring this area:

- **`dumps`** (Function) — `api/happymining/providers/vast_wire.py:70`
- **`epoch_day`** (Function) — `api/happymining/providers/vast_wire.py:44`
- **`from_epoch_day`** (Function) — `api/happymining/providers/vast_wire.py:48`
- **`loads`** (Function) — `api/happymining/providers/vast_wire.py:52`
- **`parse_earnings`** (Function) — `api/happymining/providers/vast_wire.py:128`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `ProviderAuthError` | Class | `api/happymining/providers/base.py` | 40 |
| `ProviderAuthorizationUnverified` | Class | `api/happymining/providers/base.py` | 34 |
| `ProviderError` | Class | `api/happymining/providers/base.py` | 18 |
| `ProviderFeatureDisabled` | Class | `api/happymining/providers/base.py` | 63 |
| `ProviderFeatureUnverified` | Class | `api/happymining/providers/base.py` | 69 |
| `ProviderMalformedResponse` | Class | `api/happymining/providers/base.py` | 59 |
| `ProviderNotConfigured` | Class | `api/happymining/providers/base.py` | 30 |
| `ProviderOutcomeUncertain` | Class | `api/happymining/providers/base.py` | 75 |
| `ProviderRateLimited` | Class | `api/happymining/providers/base.py` | 44 |
| `ProviderTimeout` | Class | `api/happymining/providers/base.py` | 49 |
| `ProviderUnavailable` | Class | `api/happymining/providers/base.py` | 54 |
| `FakeProvider` | Class | `api/happymining/providers/fake.py` | 38 |
| `Unauthorised` | Class | `tests/api/test_security_regressions.py` | 726 |
| `dumps` | Function | `api/happymining/providers/vast_wire.py` | 70 |
| `epoch_day` | Function | `api/happymining/providers/vast_wire.py` | 44 |
| `from_epoch_day` | Function | `api/happymining/providers/vast_wire.py` | 48 |
| `loads` | Function | `api/happymining/providers/vast_wire.py` | 52 |
| `parse_earnings` | Function | `api/happymining/providers/vast_wire.py` | 128 |
| `test_unverified_commercial_authorization_blocks_every_call` | Function | `tests/api/test_provider_vast.py` | 343 |
| `parse_machines` | Function | `api/happymining/providers/vast_wire.py` | 97 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Fetch_earnings → _money` | intra_community | 3 |
| `Fetch_earnings → From_epoch_day` | intra_community | 3 |
| `Fetch_earnings → Loads` | intra_community | 3 |
| `Fetch_earnings → Dumps` | intra_community | 3 |
| `Fetch_earnings → Epoch_day` | intra_community | 3 |
| `List_machines → Scrub` | cross_community | 3 |
| `Fetch_earnings → _raise_for` | cross_community | 3 |
| `Fetch_earnings → _ready` | cross_community | 3 |
| `Fetch_earnings → _money` | intra_community | 3 |
| `Fetch_earnings → From_epoch_day` | intra_community | 3 |

## How to Explore

1. `context({name: "dumps"})` — see callers and callees
2. `query({search_query: "providers"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
