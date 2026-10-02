---
name: gitnexus-area-services
description: "Skill for the Services area of firmware_happymining. 144 symbols across 23 files."
---

# Services

144 symbols | 23 files | Cohesion: 72%

## When to Use

- Working with code in `api/`
- Understanding how audit, lock_row, metrics work
- Modifying services-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `api/happymining/security.py` | _fernet, _random_crockford, _subkey, constant_time_equal, decrypt_json (+20) |
| `api/happymining/services/payouts.py` | _evidence, _items, _lock_batch, _lock_cash, _lock_item (+17) |
| `api/happymining/services/accounts.py` | _load_user, _new_session, activate_mfa, create_user, deactivate_user (+8) |
| `api/happymining/services/ledger.py` | balance_of, credit, debit, get_account, lock_owner (+6) |
| `api/happymining/services/earnings.py` | _post_revision, bound_machine_on, has_open_adjustment, remap_bucket, resolve_mapping (+4) |
| `api/happymining/services/operations.py` | _expire_if_due, acknowledge, cancel, expire_stale, pending_for_device (+4) |
| `api/happymining/services/provider_sync.py` | _attribution_blockers, bind_machine, unbind_machine, _fail, _ok (+4) |
| `api/happymining/services/receipts.py` | _live_receipt, _previous_request, _sync_remainder_exception, _within, allocate (+4) |
| `api/happymining/services/devices.py` | authenticate_device, revoke_device, rotate_credential, _hardware_summary, _jsonable (+3) |
| `api/happymining/services/api_clients.py` | authenticate_client, is_usable, revoke_client, ensure_still_active |

## Entry Points

Start here when exploring this area:

- **`audit`** (Function) — `api/happymining/audit.py:49`
- **`lock_row`** (Function) — `api/happymining/db.py:74`
- **`metrics`** (Function) — `api/happymining/main.py:308`
- **`utcnow`** (Function) — `api/happymining/models.py:41`
- **`constant_time_equal`** (Function) — `api/happymining/security.py:47`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `audit` | Function | `api/happymining/audit.py` | 49 |
| `lock_row` | Function | `api/happymining/db.py` | 74 |
| `metrics` | Function | `api/happymining/main.py` | 308 |
| `utcnow` | Function | `api/happymining/models.py` | 41 |
| `constant_time_equal` | Function | `api/happymining/security.py` | 47 |
| `decrypt_json` | Function | `api/happymining/security.py` | 128 |
| `decrypt_text` | Function | `api/happymining/security.py` | 117 |
| `device_secret_hash` | Function | `api/happymining/security.py` | 210 |
| `encrypt_json` | Function | `api/happymining/security.py` | 124 |
| `encrypt_text` | Function | `api/happymining/security.py` | 113 |
| `format_device_token` | Function | `api/happymining/security.py` | 199 |
| `hash_password` | Function | `api/happymining/security.py` | 54 |
| `keyed_hash` | Function | `api/happymining/security.py` | 43 |
| `match_totp_step` | Function | `api/happymining/security.py` | 83 |
| `new_csrf_token` | Function | `api/happymining/security.py` | 141 |
| `new_device_secret` | Function | `api/happymining/security.py` | 195 |
| `new_pairing_code` | Function | `api/happymining/security.py` | 168 |
| `new_session_token` | Function | `api/happymining/security.py` | 137 |
| `pairing_secret_hash` | Function | `api/happymining/security.py` | 185 |
| `parse_client_token` | Function | `api/happymining/security.py` | 232 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Audit_page → _subkey` | cross_community | 6 |
| `Login_submit → _is_sensitive_key` | cross_community | 6 |
| `Login_submit → Redact_text` | cross_community | 6 |
| `Import_confirmations → Lock_row` | cross_community | 6 |
| `Job_provider → Utcnow` | cross_community | 6 |
| `Batch_prepare → _subkey` | cross_community | 6 |
| `Login → _is_sensitive_key` | cross_community | 6 |
| `Login → Redact_text` | cross_community | 6 |
| `Beneficiary_set → _subkey` | cross_community | 6 |
| `Bucket_attribute → _subkey` | cross_community | 6 |

## How to Explore

1. `context({name: "audit"})` — see callers and callees
2. `query({search_query: "services"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
