---
name: gitnexus-area-happymining
description: "Skill for the Happymining area of firmware_happymining. 156 symbols across 19 files."
---

# Happymining

156 symbols | 19 files | Cohesion: 91%

## When to Use

- Working with code in `api/`
- Understanding how fk, in_list, pk work
- Modifying happymining-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `api/happymining/models.py` | AuditLog, Base, Device, DeviceCredential, EarningBucket (+33) |
| `api/happymining/schemas.py` | AckIn, AllocateIn, AllocatePeriodIn, AllocationIn, BatchIn (+31) |
| `api/happymining/errors.py` | AppError, Conflict, DeviceUnauthorized, FeatureDisabled, Forbidden (+13) |
| `api/happymining/main.py` | app_factory, create_app, lifespan, guarded_send, _route_label (+10) |
| `api/happymining/cli.py` | _password, _user, cmd_check_config, cmd_create_admin, cmd_deactivate_user (+6) |
| `api/happymining/worker.py` | main, run_once, job_expire, _due, _with_lock (+2) |
| `api/happymining/security.py` | hash_password, new_totp_secret, totp_uri, new_csrf_token, new_session_token (+1) |
| `api/happymining/services/accounts.py` | begin_mfa_enrollment, create_owner, create_user, normalise_email, set_password (+1) |
| `api/happymining/migrate.py` | alembic_config, expected_revision, migrations_dir, upgrade |
| `api/happymining/audit.py` | _digest, verify_chain, system |

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
| `AuditLog` | Class | `api/happymining/models.py` | 883 |
| `Base` | Class | `api/happymining/models.py` | 54 |
| `Device` | Class | `api/happymining/models.py` | 225 |
| `DeviceCredential` | Class | `api/happymining/models.py` | 248 |
| `EarningBucket` | Class | `api/happymining/models.py` | 600 |
| `EarningRevision` | Class | `api/happymining/models.py` | 638 |
| `EarningsImport` | Class | `api/happymining/models.py` | 578 |
| `EnrollmentRequest` | Class | `api/happymining/models.py` | 195 |
| `ExceptionItem` | Class | `api/happymining/models.py` | 859 |
| `FeeSchedule` | Class | `api/happymining/models.py` | 451 |
| `JournalEntry` | Class | `api/happymining/models.py` | 535 |
| `JournalLine` | Class | `api/happymining/models.py` | 557 |
| `LedgerAccount` | Class | `api/happymining/models.py` | 499 |
| `LedgerBalance` | Class | `api/happymining/models.py` | 518 |
| `Machine` | Class | `api/happymining/models.py` | 147 |
| `MachineOwnership` | Class | `api/happymining/models.py` | 169 |
| `Operation` | Class | `api/happymining/models.py` | 305 |
| `Owner` | Class | `api/happymining/models.py` | 81 |
| `OwnerBeneficiary` | Class | `api/happymining/models.py` | 738 |
| `PayoutBatch` | Class | `api/happymining/models.py` | 765 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Cmd_deactivate_user → Get_settings` | intra_community | 6 |
| `Audit_page → _subkey` | cross_community | 6 |
| `Job_provider → Utcnow` | cross_community | 6 |
| `Cmd_seed_demo → Get_settings` | intra_community | 6 |
| `Batch_prepare → _subkey` | cross_community | 6 |
| `Cmd_set_password → Get_settings` | intra_community | 6 |
| `Beneficiary_set → _subkey` | cross_community | 6 |
| `Cmd_verify → Get_settings` | intra_community | 6 |
| `Bucket_attribute → _subkey` | cross_community | 6 |
| `Audit_page → Get_settings` | cross_community | 6 |

## How to Explore

1. `context({name: "fk"})` — see callers and callees
2. `query({search_query: "happymining"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
