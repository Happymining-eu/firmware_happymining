---
name: gitnexus-area-routers
description: "Skill for the Routers area of firmware_happymining. 221 symbols across 27 files."
---

# Routers

221 symbols | 27 files | Cohesion: 87%

## When to Use

- Working with code in `api/`
- Understanding how action, audit_page, back work
- Modifying routers-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `api/happymining/dashboard.py` | _form_uuid, _integrations_page, _owner_summary, _period, _provider_action (+41) |
| `api/happymining/routers/money.py` | _allocations_view, allocate_receipt, allocate_receipt_period, approve_batch, attribute_bucket (+34) |
| `api/happymining/routers/integration.py` | _bucket_scope, _load_operation, _machine_query, _number, _operation_query (+24) |
| `api/happymining/routers/fleet.py` | cancel_enrollment, cancel_operation, create_enrollment, create_owner, create_user (+17) |
| `api/happymining/deps.py` | _bearer, _same_origin, client_ip, get_api_client, get_device (+10) |
| `api/happymining/routers/provider.py` | _raise_if_failed, accounts, bind, check, health (+7) |
| `api/happymining/routers/views.py` | batch_view, bucket_view, exception_view, iso, item_view (+7) |
| `api/happymining/routers/auth.py` | demo_login, login, logout, me, mfa_activate (+3) |
| `api/happymining/routers/device.py` | acknowledge, device_self, enroll, rotate, _provider_or_none (+2) |
| `api/happymining/services/ledger.py` | floor_cents, money_str, owner_balances, to_decimal, as_dict |

## Entry Points

Start here when exploring this area:

- **`action`** (Function) — `api/happymining/dashboard.py:161`
- **`audit_page`** (Function) — `api/happymining/dashboard.py:1037`
- **`back`** (Function) — `api/happymining/dashboard.py:156`
- **`batch_prepare`** (Function) — `api/happymining/dashboard.py:883`
- **`batch_step`** (Function) — `api/happymining/dashboard.py:913`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `AllocationRequest` | Class | `api/happymining/services/receipts.py` | 218 |
| `action` | Function | `api/happymining/dashboard.py` | 161 |
| `audit_page` | Function | `api/happymining/dashboard.py` | 1037 |
| `back` | Function | `api/happymining/dashboard.py` | 156 |
| `batch_prepare` | Function | `api/happymining/dashboard.py` | 883 |
| `batch_step` | Function | `api/happymining/dashboard.py` | 913 |
| `beneficiary_set` | Function | `api/happymining/dashboard.py` | 854 |
| `bucket_attribute` | Function | `api/happymining/dashboard.py` | 638 |
| `check_csrf` | Function | `api/happymining/dashboard.py` | 117 |
| `dashboard` | Function | `api/happymining/dashboard.py` | 289 |
| `demo_login_submit` | Function | `api/happymining/dashboard.py` | 225 |
| `earnings_page` | Function | `api/happymining/dashboard.py` | 371 |
| `exception_resolve` | Function | `api/happymining/dashboard.py` | 616 |
| `exceptions_page` | Function | `api/happymining/dashboard.py` | 581 |
| `fees_create` | Function | `api/happymining/dashboard.py` | 687 |
| `create` | Function | `api/happymining/dashboard.py` | 701 |
| `fees_page` | Function | `api/happymining/dashboard.py` | 659 |
| `integrations_create` | Function | `api/happymining/dashboard.py` | 1087 |
| `integrations_page` | Function | `api/happymining/dashboard.py` | 1076 |
| `integrations_revoke` | Function | `api/happymining/dashboard.py` | 1144 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Heartbeat → Get_settings` | cross_community | 7 |
| `Audit_page → _subkey` | cross_community | 6 |
| `Login_submit → _is_sensitive_key` | cross_community | 6 |
| `Login_submit → Redact_text` | cross_community | 6 |
| `Import_confirmations → Lock_row` | cross_community | 6 |
| `Job_provider → Utcnow` | cross_community | 6 |
| `Batch_prepare → _subkey` | cross_community | 6 |
| `Login → _is_sensitive_key` | cross_community | 6 |
| `Login → Redact_text` | cross_community | 6 |
| `Beneficiary_set → _subkey` | cross_community | 6 |

## How to Explore

1. `context({name: "action"})` — see callers and callees
2. `query({search_query: "routers"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
