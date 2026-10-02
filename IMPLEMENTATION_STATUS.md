# Implementation status

Last updated 2026-10-02. Branch `happymining-os`.

**In one line:** the product builds, and at commit `c1c9c6d` the whole flow
ran end to end with synthetic data and passed its tests. The DEMO is deployed
on the Hostinger VPS (commit `d0f84f9`). It has never talked to Vast, no real
machine has run it, and the installation image has not been built. The
**appliance** (local AI plugins, NAS indexing, encrypted backups, signed
firmware updates, organisation roles, remote-access grants) is built on top,
**on branch `appliance-wip`, not merged and not deployed**; its machine side was tested with fakes
only, and the API tests that need the database **have not run against the
final code**.

## State by area

| Area | State | Notes |
|---|---|---|
| Vast integration evidence | Done | `docs/integration-evidence.md`: primary sources, each claim marked confirmed or unresolved. 24 points unresolved. |
| API, schema, migrations | Done, tested (up to `0002`) | FastAPI, PostgreSQL 16, database-enforced ledger rules. Migration `0003_appliance` checked before the test database was lost (see below). |
| Ledger and settlements | Done, tested, reviewed once | Double entry, immutable, idempotent, evidence-based. Independent review findings fixed with regression tests. |
| Vast adapter | Written, **never run against Vast** | Tested against a fake server built from the documentation. Read-only by default. |
| Rental protection gate | Done, tested | In LIVE it always blocks disruptive actions, because Vast does not expose rental state. Intended. Leaving `vast` mode now passes it too (`leave_vast_mode`); its tests need the database and have not run against the final code. |
| Go agent, CLI, helper, simulator, `.deb` | Built, tested | Real binaries ran against the real API in tests at `c1c9c6d`. Not run on a GPU machine, not under systemd, `.deb` not installed with `dpkg -i`. |
| Installer and image tooling | Scripts and seeds tested; **ISO not built, smoke test not run** | No `xorriso`, no base ISO, no QEMU in the build environment. No appliance installer profile yet. |
| Dashboard | Done | Server-rendered owner and admin pages. |
| Deployment files | Written; DEMO **deployed** | See "Deployment" below. |
| Documentation | Done | `README.md`, `docs/`, `deploy/README.md`; `docs/appliance.md` for the appliance. |
| Integration API (Mole Hash) | Done, tested, reviewed once | API clients with scoped tokens; fleet, telemetry, operations and earnings for other software; operations through the same gate. `docs/integration-api.md`, client in `integrations/molehash/`. **The Mole Hash side is not wired**: its source was not accessible. The appliance additions (`appliance:read`, `mode`, `remote_access_required`) are not run (database). |
| GitNexus code index | Set up | `CLAUDE.md`, `AGENTS.md`, `.claude/skills/gitnexus-*`, `.mcp.json`. |
| **Appliance** (branch `appliance-wip`) | | Contract: `docs/appliance.md`. Limits: `docs/limitations.md`, "The appliance". |
| - Contract | Written, revised to what was built | Decisions taken while building are marked in it; open questions in its section 14. |
| - Control plane: appliance documents, catalog, sealing, releases, organisation roles, remote access | Written; **database tests not run against the final code** | Migration `0003_appliance`; `services/appliance.py`, `catalog.py`, `releases.py`, `org.py`, `remote_access.py`, `access.py`; `routers/appliance.py`, `releases.py`, `org.py`; device routes `/device/update` and `/device/update/artifact/{version}`; `scripts/release-sign.py`. |
| - Dashboard: appliance page, organisation page, releases page | Written; template and route tests with fakes pass; database tests not run | Secrets sealed in the browser by `dashboard/static/seal.js`, which never ran in a browser. |
| - Machine side: helper actions, apply / job / update units, backups, sealing, release verification, schedules | Built, tested with injected fakes | Never on a real machine, under systemd, with Docker, a NAS or `dpkg`. |
| - Agent: appliance report, document hand-off, schedules, update download, two operation types, CLI | Built, tested with fakes | Version still `0.1.0`. |
| - Plugin catalog | Six entries, digests pinned | Ollama, Qdrant, the vectorizer, Open WebUI, OpenClaw, Hermes Agent. Images never pulled; digests read from Docker Hub's API. |
| - Vectorizer | Built, tested | Image never built; PDF and OCR not run. |

## What was run, and the result

### Appliance work (branch `appliance-wip`), 2026-10-02

The PostgreSQL test database became unavailable during this work. A test
experiment run as root with a safety check removed renamed over and deleted
the sandbox's real `/etc/passwd` (a relative system call given an absolute
name ignores its directory). Since then PostgreSQL cannot start here; the
file has not been restored. Two fixes came out of it: a guard in
`agent/internal/backup/sys.go` that refuses an absolute name on every
relative system call (with tests), and `scripts/dev-postgres.sh` no longer
deletes a running server's data when `pg_isready` fails, which had also
destroyed the test database (`tests/os/test_dev_postgres.py`).

Run by the documentation pass, at the state of the tree at the time:

| Command | Result |
|---|---|
| `cd agent && go test ./... -count=1` | exit 0. 26 packages ok; 495 top-level tests passed (784 with subtests), 1 skipped (`TestWriteArchiveReportsUnreadableSources`). |
| `api/.venv/bin/python -m pytest tests/appliance tests/os -q -p no:cacheprovider` | exit 0. **1300 passed, 5 skipped**: real Docling (not installed in that environment), real Qdrant (two, no server), the ISO build (no `xorriso`), the QEMU smoke test. |

Reported by the engineers who built it (not repeated here):

| What | Result |
|---|---|
| `go test ./... -race` | 25 packages ok (at the time of that report; the run above found 26). |
| `make build-agent`, `dpkg-deb -c/-I` | ok; package content inspected. |
| Catalog checker (`tests/appliance/catalog`) | 425 passed, including `docker compose config` on every Compose file. |
| `tests/appliance/seal_js` | 159 passed (`seal.js` under Node, its output opened in Python; templates; dashboard routes with fakes). |
| Vectorizer suite | 359 passed under Python 3.13; 367 passed in a Python 3.12 environment built from the lock file, with the real Docling parsing DOCX, PPTX, XLSX, HTML and CSV. |
| Env-file encoding | 35 hostile values round-tripped through the real `docker compose config` (v5.5.1). |
| Removed-check experiments | 17, each caught by a failing test. |
| Migration `0003_appliance` | upgrade, `alembic check`, downgrade to `0002`, upgrade: pass, **before** the database was lost, with the models as they were then (changed since by a line wrap only). |
| `tests/api` (four appliance files) | 444 of 444 passed before the database was lost, on earlier code. |
| `pytest tests/api --noconftest` (no database) | 509 tests that need no fixture passed; about 610 could not run; 19 failed because they need the database or conftest's environment. |
| After the review fixes (lead) | `go test ./... -race` and the database-free Python suites, recorded at the end of this file's update; the document fixtures (now 17 valid, 143 invalid) pass in Go and in Python. |

**Not run against the final code:** every test in `tests/api` that needs
PostgreSQL (among them `test_appliance.py`, `test_appliance_device.py`,
`test_releases.py`, `test_sealing.py`, `test_dashboard_appliance.py`,
`test_org_roles.py`, `test_remote_access.py`, `test_integration_api.py`,
`test_access_control.py`, `test_security_regressions.py` and
`test_end_to_end_binaries.py`), `make test`, `make demo` (the simulator now
creates appliance rows), `make lint` (not recorded), any Docker build or
container, any mount, `dpkg -i`, systemd, real hardware.

### Before the appliance (commit `c1c9c6d`)

All on 2026-10-02, in the build sandbox (Linux, Python 3.13.15, Go 1.24.7,
PostgreSQL 16 from local binaries).

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

Not run anywhere: a Docker image build, the ISO build, a boot of the image,
the agent on real hardware, any call to Vast, any payment.

## Acceptance demo (`make demo`)

What the run at `c1c9c6d` did, over HTTP against the real API and
PostgreSQL, with the simulator binary (the appliance did not exist then):

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

The hashes below are those of the build at `c1c9c6d`. `dist/` now holds a
rebuild from the `appliance-wip` tree (still named `0.1.0`);
its hashes are not recorded here because that tree is not final.

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

The appliance had one independent security review (static reading, Go tests
and database-free Python tests; scratch-copy demonstrations), after it was
built. Findings, all fixed with a test that fails without the fix:

- **Critical:** the package's `postinst` ran `chown`/`chmod` as root on
  entries inside `/var/lib/happymining`, which the agent's account owns: a
  planted symbolic link would have given that account any file on the
  system at the next package configuration (each firmware update).
  `postinst` no longer touches anything inside that directory.
- **High:** a comma in a NAS `subpath` became a CIFS mount option
  (`mount.cifs` passes the path after the share to the kernel unescaped).
  Commas and backslashes are refused by both validators and by the helper.
- **Medium:** the dashboard let an `org_operator` remove a plugin's stored
  secret with a padded form value; the permission check now reads the form
  with the same code that performs the change.
- **Low:** with `ALLOW_PLUGINS` switched off at the same time as the mode
  became `vast`, plugins HappyMining had started kept running and were
  reported stopped. Stopping HappyMining's own plugins no longer needs the
  switch.

Also fixed after the documentation pass, from its list of contract
questions: a stored secret is no longer carried over to a new destination
(the documentation had found that a sealed value is bound to its name only);
the control plane queues `install_update` only for the release the machine
is offered; `control: unknown` is stored as such and the document is sent
only under `cloud`; machines installed from the image get a rollback package
(the installer's copy); Caddy lets the release upload through. The control
plane parts of these fixes have tests that need the database: **not run**.
The vectorizer's configuration was made readable by its container user
(0750/0640 root:10001; it was root-only, so the container could not have
started) and the vectorizer is restarted when it changes.

## Deployment

- **The DEMO is deployed** on the Hostinger VPS at commit `d0f84f9`, behind
  basic authentication, at `https://srv734584.hstgr.cloud`. Whether it is
  reachable from outside has **not been verified**.
- The VPS already runs Traefik on 80/443 and about fifteen other projects
  (inspected read-only through the Hostinger API).
  `deploy/hostinger/docker-compose.yml` is written for it: stock images, no
  published ports, Traefik labels, a staging gate, and a bootstrap step that
  fetches exactly one commit and its hash-pinned dependencies.
- **The appliance is not deployed**: it is only on branch `appliance-wip`, so no deployed
  commit contains it.
- `happymining.fr` DNS is not in the Hostinger account. `cloud.happymining.fr`
  and `api.happymining.fr` need A records at the DNS host before they can be
  used.
- Caddy (`deploy/Caddyfile*`) lets the firmware upload
  (`PUT /api/v1/releases/{version}/artifact`) through with 512 MB and keeps
  1 MB for everything else (not validated by Caddy here). The Hostinger
  instance's Traefik still limits every body to 1 MB, so releases cannot be
  uploaded there.

## Production blockers

1. Written agreement with Vast for operating third-party machines and for API
   use. Without it the LIVE adapter does not call Vast.
2. Earnings semantics unverified (net or gross of Vast's fee, day boundaries,
   currency). LIVE earnings are held, not posted.
3. Rental state not available from Vast. Disruptive maintenance, and taking
   a bound machine out of `vast` mode, stay blocked in LIVE.
4. The image has never been built or booted; the agent has never run on a GPU
   machine or under systemd.
5. Release signing uses a development key. Production key custody
   (`docs/trust-chain.md`) is not in place, and for firmware updates no
   signing key exists at all: who holds it, where, and how it is rotated is
   undecided.
6. No bank format, no automatic transfers, no fee withdrawal, no tax logic.
   Accounting review of the ledger is pending.
7. Contract terms with owners (fee, what happens on clawback, who may remove
   the agent, what HappyMining may do on a machine its owner manages) are
   outside the software and not written.
8. Backups not scheduled anywhere; no alerting; no CI; no dependency scanning.
9. A dedicated host for LIVE. The VPS is shared with workloads that hold the
   Docker socket.
10. The 10% fee is a DEMO assumption, not an approved rate.
11. The appliance's API tests have not run against the final code: the test
    database has to be restored first and the whole `make test` and
    `make demo` run.
12. The root helper's appliance actions have never run on real hardware:
    the five new units under systemd, Docker and Compose, the NVIDIA
    container runtime, CIFS and NFS mounts (and the mount propagation into
    the vectorizer), `dpkg -i`, the update guard and the rollback have never
    been exercised.
13. The appliance needs installer support that does not exist: the
    "appliance" and "Vast host" switch profiles, a rollback package after a
    manual installation (image installs are covered), and a version number
    for the build (it still says `0.1.0`).
14. The seal binds a secret to its name; only the control plane binds it to
    its destination. A compromised control plane can still point a stored
    secret at another host (`docs/appliance.md`, section 5).
15. One independent review of the appliance, by a reader who had not seen it
    built; its fixes have not been reviewed again, and nothing replaces a
    test on real hardware.

Full list: `docs/limitations.md`.

## Next steps, in order

1. Restore the build sandbox's system account file (or use another host),
   then run `make test`, `make demo` and `make lint` on the appliance tree
   and fix what fails; then commit it.
2. Check from outside that the DEMO at `https://srv734584.hstgr.cloud`
   answers behind its basic authentication.
3. On a build host with `xorriso`, QEMU and the Ubuntu ISO:
   `make build-installer && make smoke-test`.
4. Install the `.deb` on one real GPU machine with Vast's host software and
   go through `agent/README.md`, "Not verified here"; then, on a machine that
   is not rented, the appliance: Docker, one plugin, a NAS, a backup and an
   update with rollback.
5. Decide the firmware signing key's custody; generate it; build a package
   with it and a new version number.
6. Get the Vast agreement and a scoped key; resolve the points listed at the
   end of `docs/integration-evidence.md` against real data.
7. Only then: a LIVE pilot on a dedicated host, payouts still off.
