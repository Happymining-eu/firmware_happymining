---
name: gitnexus-area-routers
description: "Skill for the Routers area of firmware_happymining. 182 symbols across 25 files."
---

# Routers

182 symbols | 25 files | Cohesion: 90%

## When to Use

- Working with code in `api/`
- Understanding how action, audit_page, back work
- Modifying routers-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `api/happymining/dashboard.py` | _form_uuid, _owner_summary, _period, _provider_action, _run_message (+36) |
| `api/happymining/routers/money.py` | _allocations_view, allocate_receipt, allocate_receipt_period, approve_batch, attribute_bucket (+34) |
| `api/happymining/routers/fleet.py` | cancel_enrollment, cancel_operation, create_enrollment, create_owner, create_user (+17) |
| `api/happymining/routers/provider.py` | _raise_if_failed, accounts, bind, check, health (+7) |
| `api/happymining/routers/views.py` | batch_view, bucket_view, exception_view, iso, item_view (+7) |
| `api/happymining/deps.py` | _bearer, _same_origin, client_ip, get_device, get_heartbeat_device (+6) |
| `api/happymining/routers/auth.py` | demo_login, login, logout, me, mfa_activate (+3) |
| `api/happymining/routers/device.py` | _provider_or_none, acknowledge, device_operations, device_self, enroll (+2) |
| `api/happymining/services/accounts.py` | demo_login, login_rate_limit, logout, resolve_session, actor |
| `api/happymining/services/ledger.py` | floor_cents, money_str, owner_balances, to_decimal, as_dict |

## Entry Points

Start here when exploring this area:

- **`action`** (Function) — `api/happymining/dashboard.py:149`
- **`audit_page`** (Function) — `api/happymining/dashboard.py:1035`
- **`back`** (Function) — `api/happymining/dashboard.py:144`
- **`batch_prepare`** (Function) — `api/happymining/dashboard.py:881`
- **`batch_step`** (Function) — `api/happymining/dashboard.py:911`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `AllocationRequest` | Class | `api/happymining/services/receipts.py` | 218 |
| `action` | Function | `api/happymining/dashboard.py` | 149 |
| `audit_page` | Function | `api/happymining/dashboard.py` | 1035 |
| `back` | Function | `api/happymining/dashboard.py` | 144 |
| `batch_prepare` | Function | `api/happymining/dashboard.py` | 881 |
| `batch_step` | Function | `api/happymining/dashboard.py` | 911 |
| `beneficiary_set` | Function | `api/happymining/dashboard.py` | 852 |
| `bucket_attribute` | Function | `api/happymining/dashboard.py` | 636 |
| `check_csrf` | Function | `api/happymining/dashboard.py` | 105 |
| `dashboard` | Function | `api/happymining/dashboard.py` | 277 |
| `demo_login_submit` | Function | `api/happymining/dashboard.py` | 213 |
| `earnings_page` | Function | `api/happymining/dashboard.py` | 369 |
| `exception_resolve` | Function | `api/happymining/dashboard.py` | 614 |
| `exceptions_page` | Function | `api/happymining/dashboard.py` | 579 |
| `fees_create` | Function | `api/happymining/dashboard.py` | 685 |
| `create` | Function | `api/happymining/dashboard.py` | 699 |
| `fees_page` | Function | `api/happymining/dashboard.py` | 657 |
| `item_outcome` | Function | `api/happymining/dashboard.py` | 964 |
| `login_page` | Function | `api/happymining/dashboard.py` | 169 |
| `login_submit` | Function | `api/happymining/dashboard.py` | 181 |

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

1. `context({name: "action"})` — see callers and callees
2. `query({search_query: "routers"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
