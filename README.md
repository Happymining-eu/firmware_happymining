# HappyMining OS

A management layer for customer-owned GPU servers that HappyMining operates as
a supplier fleet on Vast.ai. Vast pays HappyMining; HappyMining allocates each
owner's share of the earnings after a disclosed management fee.

It is an Ubuntu Server based host appliance with a small agent, a central API
with a PostgreSQL ledger, and an owner/admin dashboard. It is not a renter
marketplace, it does not replace Vast's host daemon, it does not proxy AI
workloads, and it does not flash GPU firmware.

**Status: a working DEMO, not a production system.** Everything runs end to
end with synthetic data. The LIVE path exists and is guarded, and has never
been run against Vast, a real GPU machine or a bank. Read
[`IMPLEMENTATION_STATUS.md`](IMPLEMENTATION_STATUS.md) and
[`docs/limitations.md`](docs/limitations.md) before relying on anything.

## Layout

| Directory | What |
|---|---|
| `api/` | FastAPI control plane: pairing, telemetry, typed operations, provider adapters, ledger, settlements, worker, operator CLI |
| `dashboard/` | Server-rendered owner and admin pages (served by the API) |
| `migrations/` | Alembic schema, including the database-enforced ledger rules |
| `agent/` | Go agent, `happyminingctl`, privileged helper, simulator, `.deb` packaging |
| `os/` | Installer scripts, Ubuntu autoinstall seeds, ISO build, QEMU smoke test, release signing |
| `deploy/` | Docker Compose: stand-alone (Caddy) and for a host with Traefik (`deploy/hostinger/`) |
| `tests/` | `tests/api` against real PostgreSQL, `tests/os` for the installer tooling; Go tests sit next to the Go code |
| `docs/` | Architecture, integration evidence, agent protocol, ledger, operations, threat model, trust chain, limitations |

## Two modes

- **DEMO**: fake machines, synthetic provider fixtures, simulated receipts and
  a mock payout provider. No real money, no hardware actions, never calls Vast.
- **LIVE**: the real Vast adapter and real credentials, read-only by default.
  Payouts, provider writes and disruptive operations are off until switched on.

`HM_MODE` has no default and there is no fallback from LIVE to DEMO. A LIVE
process refuses to start with demo logins, default secrets or mock adapters,
and a database belongs to the mode that first used it.

## Run it

Requirements: Python 3.12+ with [uv](https://docs.astral.sh/uv/), Go 1.24+,
and PostgreSQL (Docker, or local binaries; `scripts/dev-postgres.sh` finds
either).

```sh
make setup            # pinned Python dependencies into api/.venv
make build-agent      # agent binaries and the .deb into dist/
make demo             # the seven-step acceptance demo, end to end, synthetic data
make dev              # API + dashboard with demo data on http://127.0.0.1:8000/login
make test             # Go, API (real PostgreSQL) and installer test suites
make lint             # ruff, gofmt, go vet, shellcheck, compose files
make build-installer  # installer bundles; the ISO too where xorriso and a verified base ISO exist
make smoke-test       # boots the ISO in QEMU (exit 77 where QEMU or the ISO is missing)
make help             # everything else
```

`make demo` pairs two simulated machines, takes their telemetry, binds them to
synthetic provider machines, imports provider earnings twice (the second
import posts nothing), records and allocates a receipt, prepares, approves,
exports, submits and confirms a settlement, repeats each step to show nothing
is duplicated, and verifies the ledger and the audit chain.

## Deploy

`deploy/README.md`. In short: a stand-alone host uses
`deploy/docker-compose.yml` with Caddy; the Hostinger VPS, which already runs
Traefik and other projects, uses `deploy/hostinger/docker-compose.yml`, built
from this repository at a pinned commit.

## Documents

| | |
|---|---|
| [`docs/architecture.md`](docs/architecture.md) | Components, flows, roles, failure behaviour |
| [`docs/integration-evidence.md`](docs/integration-evidence.md) | What is confirmed about Vast's API and terms, from primary sources, and what is not |
| [`docs/agent-protocol.md`](docs/agent-protocol.md) | The contract between the agent and the API |
| [`docs/ledger.md`](docs/ledger.md) | Accounts, entries, imports, reconciliation, settlement |
| [`docs/operations.md`](docs/operations.md) | Running it: health, backups, incidents, secrets |
| [`docs/threat-model.md`](docs/threat-model.md) | Renters, agents, owners, central compromise, supply chain |
| [`docs/trust-chain.md`](docs/trust-chain.md), [`docs/os-maintenance.md`](docs/os-maintenance.md) | Release signing; patching and driver maintenance on hosts |
| [`docs/limitations.md`](docs/limitations.md) | What is not built, not run, not verified |

## Things this project will not do

- Kill customer workloads, delete their storage, or treat an idle GPU as
  permission to do maintenance.
- Let a device choose its owner or claim a Vast machine.
- Put the Vast account key, a password or a pairing code on a machine or in an
  image.
- Offer a remote shell. Operations are a fixed list of typed actions.
- Treat a provider report, or a provider invoice marked "Paid", as cash.
- Treat a timeout as proof a payment failed.

## Code index (GitNexus)

The repository is set up for [GitNexus](https://github.com/abhigyanpatwari/GitNexus):
`CLAUDE.md` / `AGENTS.md` and `.claude/skills/gitnexus-*` tell coding agents
how to use the graph, and `.mcp.json` starts its MCP server. The index itself
(`.gitnexus/`) is local and not committed. Build or refresh it with:

```sh
npx gitnexus@1.6.12 analyze --skills
```
