# Architecture

HappyMining OS is a managed-host platform: customers own GPU servers,
HappyMining operates them as a supplier fleet on Vast.ai, and settles each
owner's share of the earnings after a disclosed management fee. It is not a
renter marketplace and it does not sit in the path of any workload.

```
                         ┌────────────────────────── HappyMining control plane ─────────────────────────┐
 owner / admin browser ─►│  Caddy (TLS) ─► API + dashboard (FastAPI) ─► PostgreSQL ◄─ worker            │
                         └──────────▲───────────────────────────────────────────────────┬──────────────┘
                                    │ HTTPS, device credential                           │ HTTPS, account key
                                    │ telemetry in, typed operations out                 │ read-only by default
              ┌─────────────────────┴─────────┐                                          ▼
              │ GPU server (owner's hardware) │                                   Vast host API
              │  HappyMining agent (Go)       │
              │  official Vast host daemon ◄──┼──────────────────────────────►  Vast platform
              │  renter containers ◄──────────┼──────────────────────────────►  Vast renters (direct)
              └───────────────────────────────┘

 Vast pays HappyMining ─► receipt recorded with evidence ─► ledger ─► owner settlement
```

What is deliberately absent: GPU BIOS flashing, a replacement for Vast's host
daemon, any proxying of renter traffic, any diversion of GPU time.

## Components

| Directory | What | Notes |
|---|---|---|
| `api/` | FastAPI application, provider adapters, ledger, worker, CLI | Python 3.13, SQLAlchemy 2, PostgreSQL 16. One process type for API and dashboard, one for the worker. |
| `dashboard/` | Jinja templates and CSS for the owner/admin pages | Server-rendered, no JavaScript, served by the API process. |
| `migrations/` | Alembic migrations | The integrity rules (triggers, exclusion constraint) are hand-written there. |
| `agent/` | Go agent, CLI, privileged helper, simulator, `.deb` packaging | Standard library only. |
| `os/` | Install scripts, autoinstall seeds, ISO build, QEMU smoke test, release signing | Bash and Python. |
| `deploy/` | Docker Compose and Caddy configuration | Single host, pilot scale. |
| `tests/` | `tests/api` (API, ledger, security, end to end), `tests/os` (installer) | Go tests live next to the Go code. |
| `docs/` | This file, evidence, protocol, ledger, operations, threat model, limitations | |

No Kubernetes and no microservices: one API, one worker, one database.

## Two modes, never mixed

| | DEMO | LIVE |
|---|---|---|
| Provider | `FakeProvider`: synthetic fixtures, no network | `VastProvider`: real API, read-only by default |
| Data | Every row flagged synthetic; banner on every page | Synthetic telemetry is refused |
| Login | Passwordless demo accounts (if enabled) | Password + TOTP; admins must have MFA |
| Payouts | `mock` provider | `manual_export` only |

`HM_MODE` has no default. The start-up guard (`config.py`) refuses to start
LIVE with default secrets, the demo login, the fake provider, the mock payout
provider, an insecure cookie, a plain-HTTP base URL, wildcard hosts or a
development database password; and refuses to start DEMO with the real
provider. A LIVE process that lacks its provider configuration reports an
explicit error for each provider call. It never substitutes demo data.

## Main flows

**Pairing.** An admin creates an enrollment request for one owner and one
machine; the API returns a single-use code once. The operator types it on the
machine (`happyminingctl pair`). The API issues a device credential. Only keyed
hashes of the code and the credential are stored. Details:
`docs/agent-protocol.md`.

**Telemetry.** The agent collects GPU, CPU, memory, disk and service state,
spools it to disk, and sends batches. The API de-duplicates on
`(device, seq)`, so resending is safe. Nothing in telemetry affects money or
maintenance decisions.

**Operations.** An admin requests one of a fixed set of typed operations. It
travels in the response to the next heartbeat. Disruptive types pass the
rental-protection gate at request time and again at delivery
(`services/maintenance.py`).

**Provider sync.** The worker refreshes the provider's machine inventory and
imports earnings for recent closed days. An admin binds a provider machine to a
HappyMining machine; a device cannot.

**Money.** Earnings import → accrual; receipt recorded and allocated →
available; settlement → reserved → in transit → paid. See `docs/ledger.md`.

## Data model (main tables)

- People: `owners`, `users`, `user_sessions`.
- Fleet: `machines`, `machine_ownership` (day-granular history),
  `enrollment_requests`, `devices`, `device_credentials`, `telemetry_samples`,
  `operations`.
- Provider: `provider_accounts`, `provider_machines`,
  `provider_binding_events`, `sync_runs`, `source_snapshots`.
- Money: `fee_schedules`, `ledger_accounts`, `journal_entries`,
  `journal_lines`, `ledger_balances`, `earnings_imports`, `earning_buckets`,
  `earning_revisions`, `provider_receipts`, `receipt_allocations`,
  `owner_beneficiaries`, `payout_batches`, `payout_items`, `payout_evidence`.
- Control: `exception_items`, `audit_log`, `rate_limit_counters`.

## Authorization

Three human roles and one machine identity.

| | admin | auditor | owner | device |
|---|---|---|---|---|
| Read all tenants | yes | yes | own only | no |
| Fleet, provider, fee, receipt, payout mutations | yes | no | no | no |
| Own telemetry and operation acknowledgements | – | – | – | yes |
| Any financial data | yes | read | own, read | **no** |

Enforced per route by dependencies in `deps.py`, and checked by tests that
enumerate every route of the application.

## Failure behaviour

- **HappyMining API down:** agents keep collecting and buffer to disk; no
  operation can reach a machine; Vast hosting is unaffected, because the agent
  is not in the rental path. Tested with the real agent binary.
- **Provider down or misconfigured:** a failed or blocked sync run, an error
  response, a stale flag on the dashboard. Maintenance is blocked.
- **Uncertain write to the provider:** never retried; reported as "outcome
  unknown" for an operator to reconcile.
- **Uncertain payout:** funds stay in transit until evidence.

## Rental protection, and what it means today

Vast's documented API does not expose whether a machine has running or stopped
instances or stored customer data (`docs/integration-evidence.md`, B6). The
real adapter therefore reports the rental state as "unknown", and the gate
blocks every disruptive action in LIVE. That is intended. Until Vast provides
that state through a supported interface, disruptive maintenance is an
operator procedure (`docs/os-maintenance.md`), not a button.
