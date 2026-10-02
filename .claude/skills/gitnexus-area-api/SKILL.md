---
name: gitnexus-area-api
description: "Skill for the Api area of firmware_happymining. 470 symbols across 17 files."
---

# Api

470 symbols | 17 files | Cohesion: 76%

## When to Use

- Working with code in `tests/`
- Understanding how count, open_exceptions, run_import work
- Modifying api-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `tests/api/test_security_regressions.py` | envelope, fleet, test_blocked_disruptive_operation_is_a_409_and_nothing_is_queued, test_dashboard_reports_a_blocked_operation_as_an_error, test_delivered_operation_keeps_the_check_that_let_it_out (+109) |
| `tests/api/test_ledger_regressions.py` | allocate, approved_then_revised, assert_reconciliation_sound, balances, books (+69) |
| `tests/api/test_integration_api.py` | audit_rows, bearer, burst, envelope, issue (+56) |
| `tests/api/test_earnings_ledger.py` | _report, count, open_exceptions, run_import, setup_fleet (+28) |
| `tests/api/test_provider_vast.py` | test_registry_never_mixes_modes, provider_for, test_429_is_retried_with_backoff_then_succeeds, test_5xx_outage, test_a_write_with_unknown_outcome_is_never_retried (+28) |
| `tests/api/test_payouts.py` | test_reported_but_unreceived_earnings_cannot_be_paid, Settings_default_payouts_enabled, funded, prepare, test_approval_fails_if_funds_went_away_after_the_draft (+22) |
| `tests/api/test_access_control.py` | test_device_cannot_touch_another_devices_operation, test_owner_cannot_read_another_owners_data, test_audit_chain_detects_tampering, test_money_must_be_a_decimal_string, test_settlement_api_end_to_end_with_idempotency_header (+22) |
| `tests/api/test_operations_maintenance.py` | test_agent_hint_is_evidence_only_never_a_binding, fleet, request, test_acknowledgement_replay_is_refused, test_allowed_only_when_unlisted_idle_and_enabled_then_rechecked_at_delivery (+18) |
| `tests/api/test_pairing_devices.py` | test_device_writes_only_to_its_own_machine, test_duplicate_telemetry_is_stored_once, test_heartbeat_updates_last_seen_and_inventory, test_malformed_telemetry_is_refused, test_real_telemetry_is_refused_for_a_synthetic_machine (+14) |
| `tests/api/helpers.py` | heartbeat, sample, owner, make_settings, live_settings (+13) |

## Entry Points

Start here when exploring this area:

- **`count`** (Function) — `tests/api/test_earnings_ledger.py:60`
- **`open_exceptions`** (Function) — `tests/api/test_earnings_ledger.py:64`
- **`run_import`** (Function) — `tests/api/test_earnings_ledger.py:51`
- **`setup_fleet`** (Function) — `tests/api/test_earnings_ledger.py:37`
- **`test_allocation_cannot_exceed_reported_or_receipt`** (Function) — `tests/api/test_earnings_ledger.py:529`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `Handler` | Class | `tests/api/fake_vast_server.py` | 69 |
| `LogLines` | Class | `tests/api/test_security_regressions.py` | 1758 |
| `count` | Function | `tests/api/test_earnings_ledger.py` | 60 |
| `open_exceptions` | Function | `tests/api/test_earnings_ledger.py` | 64 |
| `run_import` | Function | `tests/api/test_earnings_ledger.py` | 51 |
| `setup_fleet` | Function | `tests/api/test_earnings_ledger.py` | 37 |
| `test_allocation_cannot_exceed_reported_or_receipt` | Function | `tests/api/test_earnings_ledger.py` | 529 |
| `test_balance_cache_cannot_be_written_directly` | Function | `tests/api/test_earnings_ledger.py` | 610 |
| `test_bucket_with_unexplained_adjustment_cannot_be_reconciled` | Function | `tests/api/test_earnings_ledger.py` | 565 |
| `test_correction_posts_only_the_delta_and_is_traceable` | Function | `tests/api/test_earnings_ledger.py` | 150 |
| `test_demo_example_100_fee_10_owner_90` | Function | `tests/api/test_earnings_ledger.py` | 74 |
| `test_downward_revision_after_receipt_is_flagged_over_received` | Function | `tests/api/test_earnings_ledger.py` | 193 |
| `test_fee_version_boundary_and_history_is_not_rewritten` | Function | `tests/api/test_earnings_ledger.py` | 265 |
| `test_fractional_amounts_keep_sub_cent_precision` | Function | `tests/api/test_earnings_ledger.py` | 221 |
| `test_journal_is_append_only` | Function | `tests/api/test_earnings_ledger.py` | 593 |
| `test_mismatched_totals_post_nothing` | Function | `tests/api/test_earnings_ledger.py` | 413 |
| `test_negative_adjustment_reduces_accrual` | Function | `tests/api/test_earnings_ledger.py` | 174 |
| `test_only_closed_utc_days_can_be_imported` | Function | `tests/api/test_earnings_ledger.py` | 446 |
| `test_overlapping_imports_count_each_day_once` | Function | `tests/api/test_earnings_ledger.py` | 136 |
| `test_owner_specific_fee_takes_precedence` | Function | `tests/api/test_earnings_ledger.py` | 309 |

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

1. `context({name: "count"})` — see callers and callees
2. `query({search_query: "api"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
