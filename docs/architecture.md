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

**The appliance** (built, not committed, never run on a real machine;
contract: `docs/appliance.md`). A machine can also be used by its owner:
in mode `private_ai` or `vectorize` (never in `vast`) the root helper runs
plugins from a catalog shipped with the package, mounts the owner's NAS
shares, indexes them, makes encrypted backups and installs signed firmware
releases. The cloud names what should run; the machine holds every
definition and validates everything again.

```
 people on the owner's network ──► plugins (Compose projects hm-<id>, network hm-appliance) ◄── NAS shares (CIFS/NFS)
                                         ▲ plugins started and stopped, shares mounted on the host, by
 GPU server:  agent ──unix socket──► hm-helper (root, quick actions) ──systemctl start──► apply, job and update units (root)
                │                      every step behind a switch in helper.conf (all off by default)
                └──HTTPS──► API: desired-state document and sealed secrets in heartbeat responses; release offers and packages
```

AI traffic between people and plugins stays on the owner's network; the
control plane only configures and shows state.

## Components

| Directory | What | Notes |
|---|---|---|
| `api/` | FastAPI application, provider adapters, ledger, worker, CLI | Python 3.13, SQLAlchemy 2, PostgreSQL 16. One process type for API and dashboard, one for the worker. |
| `dashboard/` | Jinja templates and CSS for the owner/admin pages | Server-rendered, served by the API process. One script, `static/seal.js`, loaded only on the appliance page for people who may enter secrets: it seals them in the browser (WebCrypto). |
| `migrations/` | Alembic migrations | The integrity rules (triggers, exclusion constraint) are hand-written there. `0003_appliance` adds the appliance tables. |
| `agent/` | Go agent, CLI, privileged helper, simulator, `.deb` packaging | Standard library only. The helper's appliance engine is `internal/applier`; libraries in `internal/appliance`, `seal`, `release`, `schedule`, `backup`. |
| `appliance/` | Plugin catalog (`catalog/`), the vectorizer (`vectorizer/`, Python, runs in a container on the machine), shared test fixtures (`testdata/`) | The catalog is read by the control plane and shipped in the package. |
| `os/` | Install scripts, autoinstall seeds, ISO build, QEMU smoke test, release signing | Bash and Python. |
| `deploy/` | Docker Compose: a stand-alone host with Caddy, and `deploy/hostinger/` for a host that already runs Traefik | Single host, pilot scale. |
| `tests/` | `tests/api` (API, ledger, security, end to end; needs PostgreSQL), `tests/os` (installer), `tests/appliance` (catalog rules, vectorizer, `seal.js`; no database) | Go tests live next to the Go code. |
| `docs/` | This file, evidence, protocol, ledger, operations, threat model, limitations, the appliance contract | |

No Kubernetes and no microservices: one API, one worker, one database.

## Two modes, never mixed

| | DEMO | LIVE |
|---|---|---|
| Provider | `FakeProvider`: synthetic fixtures, no network | `VastProvider`: real API, read-only by default |
| Data | Every row flagged synthetic; banner on every page | Synthetic telemetry is refused |
| Login | Passwordless demo accounts (if enabled) | Password + TOTP; admins must have MFA |
| Payouts | `mock` provider | `manual_export` only |

`HM_MODE` has no default. The start-up guard (`config.py`) refuses to start
LIVE with default, placeholder or low-variety secrets, the demo login, the
fake provider, the mock payout provider, an insecure cookie, a plain-HTTP base
URL, wildcard hosts, a weak or development database password, or a Vast URL
that is not Vast's console over TLS; and refuses to start DEMO with the real
provider or with a Vast key present. A LIVE process that lacks its provider
configuration reports an explicit error for each provider call. It never
substitutes demo data.

The guard checks the configuration. A second check covers the *database*: the
first process to use a database records its mode in `system_info`, and the
API, the worker and every operator command refuse to run against a database
that belongs to the other mode (`services/system.py`). A demo and a pilot are
therefore two deployments with two databases, never one switched back and
forth.

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
HappyMining machine; a device cannot. Bindings and ownership are kept as
day-granular history, and changes take effect the next UTC day, so a day's
earnings always go to whoever had the machine that day.

**Integration.** Another system calls `/api/v1/integration/...` with an API
client token an admin created with chosen scopes. It reads the fleet,
telemetry, operations and earnings, and requests typed operations, which take
the same path as an admin's (same list, same gate, same audit trail), with an
idempotency key so that a retry never queues a second one.

**Money.** Earnings import → accrual; receipt recorded and allocated →
available; settlement → reserved → in transit → paid. See `docs/ledger.md`.

**Appliance configuration.** A person allowed to (section "Authorization")
changes one part of a machine's desired-state document on the dashboard or
through `/api/v1/machines/{id}/appliance/...`; each accepted change raises
the revision and is audited. Secrets arrive sealed for that machine's public
key and are stored as they are. Leaving `vast` mode on a machine bound to a
provider machine passes the rental-protection gate first (in LIVE it always
blocks). The next heartbeat response carries the document; the agent hands
it to the root helper, which validates it again, stores it and starts the
apply unit. The machine reports what it did in the following heartbeats.

**Firmware releases.** A release engineer signs a manifest with
`scripts/release-sign.py` on a machine outside the repository; staff upload
manifest, signature and package (`/api/v1/releases`); the API checks the
signature against `HM_RELEASE_PUBLIC_KEYS` and the package against the
manifest, and stores both in PostgreSQL. A release on a channel is offered
to the machines of that channel; the agent downloads it, the root helper
verifies it again with the keys installed on the machine, installs it, and
rolls it back if the new agent does not come back within 10 minutes.

## Data model (main tables)

- People and callers: `owners`, `users`, `user_sessions`, `api_clients`.
- Fleet: `machines`, `machine_ownership` (day-granular history),
  `enrollment_requests`, `devices`, `device_credentials`, `telemetry_samples`,
  `operations`.
- Provider: `provider_accounts`, `provider_machines`,
  `provider_binding_events`, `sync_runs`, `source_snapshots`.
- Money: `fee_schedules`, `ledger_accounts`, `journal_entries`,
  `journal_lines`, `ledger_balances`, `earnings_imports`, `earning_buckets`,
  `earning_revisions`, `provider_receipts`, `receipt_allocations`,
  `owner_beneficiaries`, `payout_batches`, `payout_items`, `payout_evidence`.
- Control: `exception_items`, `audit_log`, `rate_limit_counters`,
  `system_info`.
- Appliance (`0003_appliance`): `machine_appliances` (document, revision,
  sealed secrets, the last report, the machine's sealing public key),
  `remote_access_grants`, `releases` (manifest, signature, channels, the
  package bytes); `users.org_role` (existing owner users became
  `org_admin`) and `machines.management` (`company` by default).

Two database roles: the owner role (`happymining`) creates the schema and is
used by the migration job only; the API and the worker connect as
`happymining_app`, which can read and insert but cannot update or delete
journal or audit rows, and cannot disable triggers.

## Authorization

Three human roles, the device identity, and API clients (other software, such
as Mole Hash; `docs/integration-api.md`).

| | admin | auditor | owner | device | API client |
|---|---|---|---|---|---|
| Read all tenants | yes | yes | own only | no | fleet-wide or one owner, as created |
| Fleet, provider, fee, receipt, payout mutations | yes | no | no | no | no |
| Request typed operations | yes | no | no | no | with the scope, through the same gate |
| Own telemetry and operation acknowledgements | – | – | – | yes | – |
| Any financial data | yes | read | own, read | **no** | earnings, read only, with the scope |

The three kinds of credential (session, device credential, API client token)
open three disjoint sets of routes: none of them is accepted on another kind's
routes. Enforced per route by dependencies in `deps.py`, and checked by tests
that enumerate every route of the application.

With the appliance (`docs/appliance.md`, section 3; `services/access.py`):

| | admin | auditor | owner's `org_admin` | `org_operator` | `org_viewer` | fleet-wide API client |
|---|---|---|---|---|---|---|
| Appliance state of a `company` machine | yes | read | own | own | own | with `appliance:read` |
| Appliance state of a `customer` machine | with a grant | with a grant | own | own | own | with a grant and `appliance:read` |
| Change mode, NAS, backup, updates, secrets | `company`, or `manage` grant | no | own | no | no | no |
| Change plugins and schedules, run jobs | `company`, or `manage` grant | no | own | own | no | no |
| Request or cancel typed operations | `company`, or `manage` grant | no | no¹ | no¹ | no | with the scope; on `customer` only with a `manage` grant |
| Grant or revoke remote access | revoke (give up) only | no | own | no | no | no |
| Earnings and settlements | yes | read | own | no | no | with `earnings:read` |

¹ The owner's people request the two appliance operations
(`appliance_run_job`, `install_update`) through the appliance routes only;
nobody requests those through the general operation routes.

An owner-scoped API client acts for its owner and is not subject to grants.
The check reads only the machine's `management`, its owner and its grants:
nothing a device reports.

## Failure behaviour

- **HappyMining API down:** agents keep collecting and buffer to disk; no
  operation can reach a machine; Vast hosting is unaffected, because the agent
  is not in the rental path. Tested with the real agent binary.
- **Provider down or misconfigured:** a failed or blocked sync run, an error
  response, a stale flag on the dashboard. Maintenance is blocked.
- **Uncertain write to the provider:** never retried; reported as "outcome
  unknown" for an operator to reconcile.
- **Uncertain payout:** funds stay in transit until evidence.
- **Appliance, API down:** plugins, mounts, the index, schedules and backups
  keep running on the machine; no new document or release arrives.
- **Root helper unreachable:** the agent keeps sending telemetry and reports
  the appliance as `control: unknown` with the reason; nothing is applied.
  (The control plane currently records that as `cloud`:
  `docs/appliance.md`, section 14.)
- **A new release whose agent does not come back:** the update guard
  reinstalls the previous package after 10 minutes, when one was kept.

## Rental protection, and what it means today

Vast's documented API does not expose whether a machine has running or stopped
instances or stored customer data (`docs/integration-evidence.md`, B6). The
real adapter therefore reports the rental state as "unknown", and the gate
blocks every disruptive action in LIVE. That is intended. Until Vast provides
that state through a supported interface, disruptive maintenance is an
operator procedure (`docs/os-maintenance.md`), not a button.

Taking a machine out of `vast` mode while it is bound to a provider machine
is gated the same way (`leave_vast_mode`) and is therefore always blocked in
LIVE: the operator confirms in Vast's console that the machine is unlisted
and empty, removes the binding, and only then changes the mode
(`docs/operations.md`).
