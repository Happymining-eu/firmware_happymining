---
name: gitnexus-area-happymining
description: "Skill for the Happymining area of firmware_happymining. 161 symbols across 21 files."
---

# Happymining

161 symbols | 21 files | Cohesion: 91%

## When to Use

- Working with code in `api/`
- Understanding how fk, in_list, pk work
- Modifying happymining-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `api/happymining/models.py` | ApiClient, AuditLog, Base, Device, DeviceCredential (+34) |
| `api/happymining/schemas.py` | AckIn, AllocateIn, AllocatePeriodIn, AllocationIn, ApiClientIn (+32) |
| `api/happymining/errors.py` | AppError, ClientUnauthorized, Conflict, DeviceUnauthorized, FeatureDisabled (+14) |
| `api/happymining/main.py` | app_factory, create_app, readyz, lifespan, guarded_send (+10) |
| `api/happymining/cli.py` | _password, _user, cmd_check_config, cmd_create_admin, cmd_deactivate_user (+6) |
| `api/happymining/security.py` | new_totp_secret, totp_uri, _is_sensitive_key, redact, redact_text (+3) |
| `api/happymining/worker.py` | main, run_once, job_expire, _due, _with_lock (+2) |
| `api/happymining/migrate.py` | expected_revision, alembic_config, migrations_dir, upgrade |
| `api/happymining/audit.py` | _digest, verify_chain, system |
| `api/happymining/db.py` | get_engine, session_factory, session_scope |

## Entry Points

Start here when exploring this area:

- **`fk`** (Function) — `api/happymining/models.py:62`
- **`in_list`** (Function) — `api/happymining/models.py:49`
- **`pk`** (Function) — `api/happymining/models.py:58`
- **`ts`** (Function) — `api/happymining/models.py:68`
- **`verify_chain`** (Function) — `api/happymining/audit.py:93`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `ApiClient` | Class | `api/happymining/models.py` | 359 |
| `AuditLog` | Class | `api/happymining/models.py` | 940 |
| `Base` | Class | `api/happymining/models.py` | 54 |
| `Device` | Class | `api/happymining/models.py` | 225 |
| `DeviceCredential` | Class | `api/happymining/models.py` | 248 |
| `EarningBucket` | Class | `api/happymining/models.py` | 657 |
| `EarningRevision` | Class | `api/happymining/models.py` | 695 |
| `EarningsImport` | Class | `api/happymining/models.py` | 635 |
| `EnrollmentRequest` | Class | `api/happymining/models.py` | 195 |
| `ExceptionItem` | Class | `api/happymining/models.py` | 916 |
| `FeeSchedule` | Class | `api/happymining/models.py` | 508 |
| `JournalEntry` | Class | `api/happymining/models.py` | 592 |
| `JournalLine` | Class | `api/happymining/models.py` | 614 |
| `LedgerAccount` | Class | `api/happymining/models.py` | 556 |
| `LedgerBalance` | Class | `api/happymining/models.py` | 575 |
| `Machine` | Class | `api/happymining/models.py` | 147 |
| `MachineOwnership` | Class | `api/happymining/models.py` | 169 |
| `Operation` | Class | `api/happymining/models.py` | 305 |
| `Owner` | Class | `api/happymining/models.py` | 81 |
| `OwnerBeneficiary` | Class | `api/happymining/models.py` | 795 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Heartbeat → Get_settings` | cross_community | 7 |
| `Login_submit → _is_sensitive_key` | cross_community | 6 |
| `Login_submit → Redact_text` | cross_community | 6 |
| `Job_provider → Utcnow` | cross_community | 6 |
| `Cmd_deactivate_user → Get_settings` | intra_community | 6 |
| `Login → _is_sensitive_key` | cross_community | 6 |
| `Login → Redact_text` | cross_community | 6 |
| `Cmd_seed_demo → Get_settings` | intra_community | 6 |
| `Cmd_set_password → Get_settings` | intra_community | 6 |
| `Cmd_verify → Get_settings` | intra_community | 6 |

## How to Explore

1. `context({name: "fk"})` — see callers and callees
2. `query({search_query: "happymining"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
