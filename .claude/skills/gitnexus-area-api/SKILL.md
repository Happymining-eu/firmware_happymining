---
name: gitnexus-area-api
description: "Skill for the Api area of firmware_happymining. 408 symbols across 16 files."
---

# Api

408 symbols | 16 files | Cohesion: 85%

## When to Use

- Working with code in `tests/`
- Understanding how heartbeat, make_settings, sample work
- Modifying api-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `tests/api/test_security_regressions.py` | ack, age_sample, app_client, audit_rows, bearer (+109) |
| `tests/api/test_ledger_regressions.py` | allocate, approved_then_revised, assert_reconciliation_sound, balances, books (+69) |
| `tests/api/test_earnings_ledger.py` | _report, count, open_exceptions, run_import, setup_fleet (+28) |
| `tests/api/test_provider_vast.py` | test_registry_never_mixes_modes, provider_for, test_429_is_retried_with_backoff_then_succeeds, test_5xx_outage, test_a_write_with_unknown_outcome_is_never_retried (+28) |
| `tests/api/test_payouts.py` | test_reported_but_unreceived_earnings_cannot_be_paid, Settings_default_payouts_enabled, funded, prepare, test_approval_fails_if_funds_went_away_after_the_draft (+22) |
| `tests/api/test_access_control.py` | test_demo_session_dies_when_demo_login_is_switched_off, test_device_cannot_touch_another_devices_operation, test_login_is_rate_limited, test_owner_cannot_read_another_owners_data, test_audit_chain_detects_tampering (+21) |
| `tests/api/test_operations_maintenance.py` | fleet, request, test_acknowledgement_replay_is_refused, test_agent_hint_is_evidence_only_never_a_binding, test_allowed_only_when_unlisted_idle_and_enabled_then_rechecked_at_delivery (+18) |
| `tests/api/test_pairing_devices.py` | test_device_writes_only_to_its_own_machine, test_duplicate_telemetry_is_stored_once, test_heartbeat_updates_last_seen_and_inventory, test_malformed_telemetry_is_refused, test_real_telemetry_is_refused_for_a_synthetic_machine (+14) |
| `tests/api/helpers.py` | heartbeat, make_settings, sample, owner, paired_machine (+13) |
| `tests/api/fake_vast_server.py` | _earnings, _handle, _json, _send, do_DELETE (+9) |

## Entry Points

Start here when exploring this area:

- **`heartbeat`** (Function) — `tests/api/helpers.py:260`
- **`make_settings`** (Function) — `tests/api/helpers.py:23`
- **`sample`** (Function) — `tests/api/helpers.py:231`
- **`test_demo_session_dies_when_demo_login_is_switched_off`** (Function) — `tests/api/test_access_control.py:467`
- **`test_device_cannot_touch_another_devices_operation`** (Function) — `tests/api/test_access_control.py:253`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `Handler` | Class | `tests/api/fake_vast_server.py` | 69 |
| `LogLines` | Class | `tests/api/test_security_regressions.py` | 1758 |
| `heartbeat` | Function | `tests/api/helpers.py` | 260 |
| `make_settings` | Function | `tests/api/helpers.py` | 23 |
| `sample` | Function | `tests/api/helpers.py` | 231 |
| `test_demo_session_dies_when_demo_login_is_switched_off` | Function | `tests/api/test_access_control.py` | 467 |
| `test_device_cannot_touch_another_devices_operation` | Function | `tests/api/test_access_control.py` | 253 |
| `test_login_is_rate_limited` | Function | `tests/api/test_access_control.py` | 474 |
| `test_owner_cannot_read_another_owners_data` | Function | `tests/api/test_access_control.py` | 178 |
| `fleet` | Function | `tests/api/test_operations_maintenance.py` | 69 |
| `request` | Function | `tests/api/test_operations_maintenance.py` | 83 |
| `test_acknowledgement_replay_is_refused` | Function | `tests/api/test_operations_maintenance.py` | 185 |
| `test_agent_hint_is_evidence_only_never_a_binding` | Function | `tests/api/test_operations_maintenance.py` | 417 |
| `test_allowed_only_when_unlisted_idle_and_enabled_then_rechecked_at_delivery` | Function | `tests/api/test_operations_maintenance.py` | 299 |
| `test_blocked_request_is_an_error_over_http_not_a_quiet_success` | Function | `tests/api/test_operations_maintenance.py` | 332 |
| `test_disruptive_operation_is_denied_unless_provably_idle` | Function | `tests/api/test_operations_maintenance.py` | 260 |
| `test_disruptive_operations_are_disabled_by_default` | Function | `tests/api/test_operations_maintenance.py` | 249 |
| `test_expired_operation_is_not_delivered_and_cannot_be_acknowledged` | Function | `tests/api/test_operations_maintenance.py` | 213 |
| `test_monitoring_operation_lifecycle` | Function | `tests/api/test_operations_maintenance.py` | 153 |
| `test_operation_that_was_never_delivered_cannot_be_acknowledged` | Function | `tests/api/test_operations_maintenance.py` | 228 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Cmd_create_admin → _database_url_problems` | cross_community | 4 |
| `Cmd_create_admin → _vast_url_problems` | cross_community | 4 |
| `Cmd_create_admin → _weak_secret_problems` | cross_community | 4 |
| `Cmd_seed_demo → _database_url_problems` | cross_community | 4 |
| `Cmd_seed_demo → _vast_url_problems` | cross_community | 4 |
| `Cmd_seed_demo → _weak_secret_problems` | cross_community | 4 |
| `Main → _database_url_problems` | cross_community | 4 |
| `Main → _vast_url_problems` | cross_community | 4 |
| `Main → _weak_secret_problems` | cross_community | 4 |

## How to Explore

1. `context({name: "heartbeat"})` — see callers and callees
2. `query({search_query: "api"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
