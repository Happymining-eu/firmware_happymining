# Implementation status

Last updated 2026-10-02. Branch `happymining-os`.

**In one line:** the product builds, and the whole flow runs end to end with
synthetic data and passes its tests. It has not been deployed, it has never
talked to Vast, no real machine has run it, and the installation image has not
been built.

## State by area

| Area | State | Notes |
|---|---|---|
| Vast integration evidence | Done | `docs/integration-evidence.md`: primary sources, each claim marked confirmed or unresolved. 24 points unresolved. |
| API, schema, migrations | Done, tested | FastAPI, PostgreSQL 16, one Alembic revision with database-enforced ledger rules. |
| Ledger and settlements | Done, tested, reviewed once | Double entry, immutable, idempotent, evidence-based. Independent review findings fixed with regression tests. |
| Vast adapter | Written, **never run against Vast** | Tested against a fake server built from the documentation. Read-only by default. |
| Rental protection gate | Done, tested | In LIVE it always blocks disruptive actions, because Vast does not expose rental state. Intended. |
| Go agent, CLI, helper, simulator, `.deb` | Built, tested | Real binaries run against the real API in tests. Not run on a GPU machine, not under systemd, `.deb` not installed with `dpkg -i`. |
| Installer and image tooling | Scripts and seeds tested; **ISO not built, smoke test not run** | No `xorriso`, no base ISO, no QEMU in the build environment. |
| Dashboard | Done | Server-rendered owner and admin pages. |
| Deployment files | Written, validated offline; **not deployed** | See "Deployment" below. |
| Documentation | Done | `README.md`, `docs/`, `deploy/README.md`. |
| Integration API (Mole Hash) | Done, tested, reviewed once | API clients with scoped tokens; fleet, telemetry, operations and earnings for other software; operations through the same gate. `docs/integration-api.md`, client in `integrations/molehash/`. **The Mole Hash side is not wired**: its source was not accessible. |
| GitNexus code index | Set up | `CLAUDE.md`, `AGENTS.md`, `.claude/skills/gitnexus-*`, `.mcp.json`. Full-text search index not built (see below). |

## What was run, and the result

All on 2026-10-02, in the build sandbox (Linux, Python 3.13.15, Go 1.24.7,
PostgreSQL 16 from local binaries), at the state of this commit.

| Command | Result |
|---|---|
| `make build-agent` | exit 0. Four binaries and `dist/happymining-agent_0.1.0_amd64.deb`. |
| `make test` | exit 0. |
| - `test-agent` (`go vet`, `go test ./... -race`) | 19 packages ok, 193 tests passed. |
| - `test-api` (pytest, real PostgreSQL, fake Vast server, real agent binaries) | **595 passed**. |
| - `test-os` (installer and image tooling) | **340 passed, 2 skipped** (the two need tools that are not installed). |
| `make demo` | exit 0. The seven acceptance steps plus the idempotency checks: **41 checks passed**. |
| `make lint` | exit 0. ruff, ruff format, gofmt, `go vet`, shellcheck, three compose files. |
| Migration `0002` | upgrade, `alembic check` (models match), downgrade to `0001`, upgrade again: all pass. |
| `HM_ALLOW_PARTIAL=1 make build-installer` | exit 0. Seed and install-script bundles produced. **ISO not produced** (no `xorriso`, no base ISO). |
| `make smoke-test` | **exit 77: not run** (no QEMU, no ISO, no `ssh`). |
| `make checksums` | exit 0. `dist/SHA256SUMS` signed with a **development key**. |
| `gitnexus analyze --skills` | 4,867 symbols, 15,943 relationships, 421 flows indexed. The full-text extension could not be downloaded here, so keyword search is off until `npx gitnexus analyze --repair-fts` is run with network access. |

Not run anywhere: a Docker image build, `docker compose up`, the ISO build, a
boot of the image, the agent on real hardware, any call to Vast, any payment.

## Acceptance demo (`make demo`)

What the run above did, over HTTP against the real API and PostgreSQL, with
the simulator binary:

1. Created two synthetic owners, one single-use pairing code per machine, and
   a 10% fee marked as a DEMO assumption.
2. Paired two simulated agents. Each machine belongs to the owner the admin
   chose; a used code cannot be replayed.
3. Stored their telemetry: 24 samples each, once each, despite a simulated
   outage and resends; every sample marked synthetic.
4. Imported synthetic provider earnings: 17 machine-days. The earnings of a
   third machine nobody is bound to went to the exception queue.
5. Applied the fee: USD 100.00 reported = 10.00 fee + 90.00 owner share, and
   nothing payable yet, because a report is not cash.
6. Recorded a simulated receipt and allocated it: USD 90.00 payable. An
   unexplained USD 1.25 stayed in suspense as an open exception.
7. Prepared a settlement; the preparer could not approve it; a second admin
   did; the export was produced.

Then every request was repeated: the second import posted nothing, the same
settlement request returned the same batch, a second approval reserved nothing
more, the export was identical, a different settlement request found no money
to pay twice, and the journal had no new entries. Finally the batch was
submitted (mock provider, no money moved) and confirmed with simulated
evidence; the ledger (38 balanced entries) and the audit chain (33 entries)
verified.

## Artifacts (in `dist/`, not committed)

| File | SHA-256 |
|---|---|
| `happymining-agent_0.1.0_amd64.deb` | `1cb280b495e29e4157b4e48b26ff082880ed5ac58330f8ff52ef1593fb58df59` |
| `bin/happymining-agent` | `fbffff07a80efa97c98eba64095a65deccb4995a138ed1c8e3b851ab8316b2c8` |
| `bin/happyminingctl` | `26572a27f9ff7e9f6c94823782118d2bdb64489215e73976a8f1f5a6a9008f43` |
| `bin/hm-helper` | `f4bd8d4f1f61b224ce42d7d5667a617cb3f5b79d2d5659d9abd192864c9d2c31` |
| `bin/hm-simulator` | `2afc80e6e0d60b6db8515065d54ef1938484eb5b8fb413dba570f59ceaf9ab05` |
| `happymining-install-scripts-0.1.0.tar.gz` | `5170d1646b5ba62d31f15422a81b56863b5b1e2b6af8a91f9d4701f1089fcd7c` |
| `happymining-seed-generic.tar.gz` | `462b51702b03356ba5935b49d88bd463d4491ef97e02a5987c8e4f28e70850be` |
| `SHA256SUMS`, `SHA256SUMS.gpg` | signed with a development key, **not for production** |

Not produced: `happymining-os-0.1.0-ubuntu-24.04.5-amd64.iso`.

## Reviews

Two independent reviews of the first complete version (ledger; security) found
defects that were fixed, each with a regression test
(`tests/api/test_ledger_regressions.py`, `tests/api/test_security_regressions.py`):

- Ledger: double allocation under concurrency; over-received funds payable;
  cancel after export; allocation replay; clawback netting; gaps in database
  immutability; the application running as database superuser; blind spots in
  `verify`; missing machines not imported; attribution by day for unbind and
  ownership transfer; vanished days; lenient money parsing; provider errors
  treated as failure; missing earnings components read as zero.
- Security: DEMO and LIVE sharing a database; weak start-up guard; login rate
  limiting; TOTP replay; a sync status that could read "ok" while a job was
  failing; CSV formula injection; no way to contain an account; telemetry
  flood and retention; redaction gaps; and smaller items.

Writing those tests found nine more defects (among them: closing an
over-received exception by hand made the money payable; a streamed request
body past the size limit was processed in part; two admins could deactivate
each other at the same moment). They are fixed and tested as well. There has
been no review of the fixes by a second party, no review of the Go agent or
the installer beyond their own tests, and no penetration test.

The integration API had its own independent security review after it was
written. No critical finding; one high (a burst of requests from one client
could exhaust the database connection pool and stall the whole API for 30
seconds, also reachable by a device), three medium (a provider-machine hint
in telemetry; a request authenticated just before revocation still queued; the
Python client could print the token in an error) and six low. All are fixed,
each with a test; the burst test was checked to fail without its fix.

## Deployment

**Not deployed.**

- The Hostinger VPS was inspected read-only through the Hostinger API: it
  already runs Traefik on 80/443 and about fifteen other projects.
  `deploy/hostinger/docker-compose.yml` is written for that host (no published
  ports, Traefik labels, staging gate, image built from Git at a pinned
  commit).
- The Hostinger API can create a Compose project but cannot copy files to the
  server, so the server has to build from GitHub. **The push to GitHub is
  refused**: the Claude GitHub App is not installed on the `Happymining-eu`
  organization. Until the branch is on GitHub nothing can be deployed.
- `happymining.fr` DNS is not in the Hostinger account. `cloud.happymining.fr`
  and `api.happymining.fr` need A records at the DNS host before they can be
  used.

Once the branch is pushed, the first deployment is one call
(`deploy/README.md`, "Deploy or redeploy"), as a DEMO instance behind basic
authentication. That will also be the first time the Docker image is built.

## Production blockers

1. Written agreement with Vast for operating third-party machines and for API
   use. Without it the LIVE adapter does not call Vast.
2. Earnings semantics unverified (net or gross of Vast's fee, day boundaries,
   currency). LIVE earnings are held, not posted.
3. Rental state not available from Vast. Disruptive maintenance stays blocked
   in LIVE.
4. The image has never been built or booted; the agent has never run on a GPU
   machine or under systemd.
5. Release signing uses a development key. Production key custody
   (`docs/trust-chain.md`) is not in place.
6. No bank format, no automatic transfers, no fee withdrawal, no tax logic.
   Accounting review of the ledger is pending.
7. Contract terms with owners (fee, what happens on clawback, who may remove
   the agent) are outside the software and not written.
8. Backups not scheduled anywhere; no alerting; no CI; no dependency scanning.
9. A dedicated host for LIVE. The VPS is shared with workloads that hold the
   Docker socket.
10. The 10% fee is a DEMO assumption, not an approved rate.

Full list: `docs/limitations.md`.

## Next steps, in order

1. Install the Claude GitHub App on the organization (or push the branch by
   hand), then deploy the DEMO instance to the VPS and check it from outside.
2. On a build host with `xorriso`, QEMU and the Ubuntu ISO:
   `make build-installer && make smoke-test`.
3. Install the `.deb` on one real GPU machine with Vast's host software and
   go through `agent/README.md`, "Not verified here".
4. Get the Vast agreement and a scoped key; resolve the points listed at the
   end of `docs/integration-evidence.md` against real data.
5. Only then: a LIVE pilot on a dedicated host, payouts still off.
