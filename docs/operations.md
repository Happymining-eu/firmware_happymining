# Operations

How to run the control plane day to day. Deployment itself is in
`deploy/README.md`; what is not built or not verified is in
`docs/limitations.md`.

Commands below use `hm` for "the operator CLI inside the API image":

```sh
# stand-alone stack
alias hm='docker compose -f deploy/docker-compose.yml --env-file deploy/.env run --rm api python -m happymining.cli'
# from a checkout, with the variables of deploy/.env exported
alias hm='PYTHONPATH=api api/.venv/bin/python -m happymining.cli'
```

| Command | What it does |
|---|---|
| `hm check-config` | Validates the configuration for the selected mode and lists every problem. |
| `hm migrate` | Applies database migrations (run as the owner role). |
| `hm setup-runtime-role` | Creates or updates the unprivileged role the API and worker connect as. Password from `HM_DB_APP_PASSWORD`. |
| `hm create-admin <email>` | Creates an admin and starts MFA enrollment. |
| `hm enroll-mfa <email>` | Activates TOTP for a user. |
| `hm set-password <email>` | Replaces a password and ends that user's sessions. |
| `hm deactivate-user <email>` | Disables an account and ends its sessions. |
| `hm verify` | Recomputes the ledger and the audit hash chain. Exit code 1 on any problem. |
| `hm seed-demo` | Synthetic demo data. DEMO only. |

Every command except `check-config`, `migrate` and `setup-runtime-role`
refuses to run against a database that belongs to the other mode.

## First start (LIVE)

1. Fill in the environment. `hm check-config` must print no problem.
2. Start the stack. The migration job creates the schema and the runtime role.
3. `hm create-admin you@example.com`, set the password, scan the TOTP secret,
   confirm with a code. Create a second admin the same way: payouts need a
   preparer and a different approver, and the last active admin cannot be
   deactivated.
4. Sign in at `/login`. The provider page shows what the integration is
   missing (key, commercial authorization reference, verified earnings
   semantics).

## Health

| Check | Meaning |
|---|---|
| `GET /healthz` | The process is up. Answers any `Host`. Used by the container health check. |
| `GET /readyz` | The database is reachable and at the expected schema revision. |
| `GET /metrics` | Prometheus metrics. Needs `Authorization: Bearer $HM_METRICS_TOKEN`; without a configured token it answers nobody. |
| Admin → Provider | Last run of each sync job, which one is failing, whether the data is stale. |
| Admin → Exceptions | Everything a person must decide before money moves. |
| `hm verify` / `GET /api/v1/ledger/verify`, `/api/v1/audit-log/verify` | Ledger and audit chain integrity. Run daily and after every restore. |

The worker runs: expiry of overdue pairing codes and operations; purge of old
rate-limit counters; telemetry retention (default 30 days); provider machine
sync (every 10 minutes); earnings import for the last 14 closed days (every 6
hours). Jobs take advisory locks, so a second worker does no harm.

## Backups and restore

```sh
# stand-alone stack: writes a dump and its SHA-256 to deploy/backups/
docker compose -f deploy/docker-compose.yml --env-file deploy/.env --profile ops run --rm backup

# anywhere pg_dump can reach the database (password from PGPASSWORD or ~/.pgpass)
scripts/backup.sh --host HOST --user happymining --database happymining --out-dir /backups

# the tested restore procedure: restores into a scratch database, checks the
# schema revision, recomputes the ledger and the audit chain, prints row counts
scripts/restore-verify.sh --dump /backups/<file>.dump --host HOST --user happymining --scratch-db hm_restore_check
```

- Schedule the backup (cron on the host) and copy the dumps off the server.
- A dump contains owner names, earnings, the audit trail, and beneficiary
  details and TOTP secrets in encrypted form. Protect it like the database.
- `HM_FIELD_ENCRYPTION_KEY` and `HM_SECRET_KEY` are **not** in the dump. Back
  them up separately. Without the first, beneficiary details and TOTP secrets
  cannot be read. Without the second, every device has to be paired again.
- A backup that was never restored is not a backup. Run `restore-verify.sh`
  on a schedule, not only after an incident.

### Disaster recovery

1. Restore the latest dump into a new, empty database (as the owner role).
2. `hm setup-runtime-role`, then point `HM_DATABASE_URL` at the new database
   with the same two keys as before.
3. `hm verify`. Do not prepare or submit a payout until it is clean.
4. Compare the last journal entry and the last payout batch with the bank
   statement: anything paid after the dump was taken is missing from the
   ledger and must be re-entered with its evidence, not paid again.

## Incidents

| Situation | Action |
|---|---|
| An account is or may be compromised | Admin → Users → deactivate (or `hm deactivate-user`). Its sessions end at once. To keep the account: revoke sessions, then `hm set-password`. |
| A machine's credential is or may be stolen | Revoke the device (Admin → machine page, or `POST /api/v1/devices/{id}/revoke`). Its queued operations are cancelled. Pair again with a new code. |
| An API client token (Mole Hash) is or may be leaked | Dashboard → Integrations → Rotate (new token, old one dead at once) or Revoke. Revoking also cancels the operations that client had queued and no machine has received. Check the audit trail for `operation.request` rows with that client as the actor. |
| The Vast key is or may be leaked | Revoke it at Vast, issue a new scoped key, restart the stack. The key is only in the environment. |
| `hm verify` reports a problem | Stop payouts (`HM_PAYOUTS_ENABLED=false`, restart). Keep the database as it is. Restore the latest good dump into a scratch database and compare. |
| A payout's outcome is unknown | Leave it `uncertain`. The money stays in transit and cannot be paid again. Settle it with bank evidence: confirm, or fail. |
| The provider revised a day that was already received or paid | `docs/ledger.md`, "When the provider revises a paid day". |
| Receipt entered by mistake | De-allocate what was allocated from it, then void it with a reason. |
| The API is down | Agents buffer and retry. Hosting on Vast is not affected. No operation reaches any machine. Appliance plugins, mounts, schedules and backups keep running on the machines. |
| The firmware signing key is or may be leaked | Remove its public key from `HM_RELEASE_PUBLIC_KEYS` and restart: nothing signed with it is offered or served any more. Withdraw the releases signed with it. Machines keep trusting the key until they install a package whose `release-keys` directory no longer holds it. Check the audit trail for `release.*` rows. |
| A machine reports a new sealing key and was not reinstalled | Audit rows `appliance.seal_key`. Treat it as a stolen device credential (row above): revoke the device, pair again, and have the owner enter the secrets again. |
| A machine reports `control: unknown` (the panel shows `cloud` with `apply_status: disabled` and the reason) | The agent cannot reach the root helper. On the machine: `systemctl status happymining-helper.socket`, `journalctl -u 'happymining-helper@*'`. Nothing is applied meanwhile; telemetry continues. |

## Rotating secrets

| Secret | How | Effect |
|---|---|---|
| `HM_DB_APP_PASSWORD` | New value, `hm setup-runtime-role` (the migration job does it), restart API and worker. | None for users. |
| `POSTGRES_PASSWORD` | `ALTER ROLE happymining PASSWORD ...` in the database, then the new value in the environment. | None for users. |
| `HM_VAST_API_KEY` | New key at Vast, new value, restart. | None. |
| `HM_SECRET_KEY` | New value, restart. | **Every session ends, every device credential and pending pairing code stops working.** All machines must be paired again. Do this only after a compromise. |
| `HM_FIELD_ENCRYPTION_KEY` | Not supported in place. | Stored beneficiary details and TOTP secrets would become unreadable. A re-encryption command does not exist yet (`docs/limitations.md`). |

## Switches that are off by default

| Variable | Turns on | Before turning it on |
|---|---|---|
| `HM_PAYOUTS_ENABLED` | Settlement batches | Backups rehearsed, two admins with MFA, the earnings semantics verified. |
| `HM_PROVIDER_MUTATIONS_ENABLED` | Unlisting a machine at Vast | A key with `machine_write`. Unlisting does not end running rentals and is not permission to. |
| `HM_DISRUPTIVE_OPERATIONS_ENABLED` | Restart of the Vast daemon, reboot | Nothing changes in LIVE today: the rental check cannot be answered from Vast's documented API, so the gate blocks these anyway. The machine's local administrator must also enable them. |
| `HM_VAST_EARNINGS_BASIS=net_of_provider_fee` and `HM_VAST_EARNINGS_BUCKETS_VERIFIED=true` | Posting LIVE earnings to the ledger | Both points verified against real data (`docs/integration-evidence.md`, C8 and C11). |
| `HM_RELEASE_PUBLIC_KEYS` | Publishing firmware releases (comma-separated base64 Ed25519 public keys) | The signing key exists, offline, with its custody decided (below). LIVE refuses the published test key. |

## Appliance

Built and **not run on any real machine**, with API tests that have not run
against the final code (`docs/limitations.md`). The procedures below follow
the code; none has been rehearsed. Contract: `docs/appliance.md`.

Server settings: `HM_CATALOG_DIR` (plugin catalog; empty: the one next to
the code), `HM_RELEASE_PUBLIC_KEYS`, `HM_RELEASE_MAX_BYTES` (largest
package, default 128 MiB), `HM_REMOTE_ACCESS_MAX_HOURS` (longest grant with
an expiry, default 2160). On each machine the root-owned
`/etc/happymining/helper.conf` decides what the helper may do; every switch
is off as packaged.

API calls below use an admin session (with a cookie, also the
`X-CSRF-Token` header).

### Taking a machine out of Vast mode (LIVE)

In LIVE the rental-protection gate always blocks leaving `vast` while the
machine is bound to a provider machine, because Vast does not expose the
rental state. Do not try to get around it: the binding is removed only once
a person has confirmed the machine is empty.

1. In Vast's console (or CLI), unlist the machine. Unlisting does not end
   running rentals and is not permission to. Wait until Vast's console shows
   no active rental, no stopped instance and no stored customer data on it.
   HappyMining cannot check this for you; zero GPU utilisation proves
   nothing.
2. Remove the provider binding:
   `POST /api/v1/provider/machines/{provider_machine_id}/unbind` (the
   dashboard has no button for it). Earnings of today and earlier stay
   attributed through the binding; it ends from the next UTC day.
3. Change the mode on the machine's appliance page, or
   `PUT /api/v1/machines/{id}/appliance/mode` `{"mode": "private_ai"}`.
   On a machine managed by its owner, staff need a `manage` grant; the
   owner's `org_admin` can do it directly. With the machine still bound the
   answer is `409 maintenance_blocked`, and the attempt is audited.
4. On the appliance page, check that the machine reports the new mode and
   `apply_status` `applied`. A GPU plugin reported `blocked` means a
   container HappyMining did not start is still running: find out what it
   is before doing anything else.

Back to Vast: set the mode to `vast` (always accepted), wait until every
plugin reports `stopped`, bind the machine again, then list it in Vast's
console.

### Publishing a firmware release

Machines verify a release with the keys installed by their **current**
package. A package built without a key refuses every update, so the first
package that carries a key is installed by hand.

1. Once, on the release engineer's machine, outside any repository:
   `api/.venv/bin/python scripts/release-sign.py keygen --out <directory>`.
   It writes `happymining-release-<key id>.key` (private, 0600, unencrypted
   PEM: keep it offline) and `.pub`, and prints the line for
   `HM_RELEASE_PUBLIC_KEYS`. The tool refuses a directory inside a working
   tree.
2. Build the package with a new version and the public key(s) machines
   should trust from then on:
   `HM_VERSION=<X.Y.Z> HM_RELEASE_KEYS_DIR=<directory with *.pub> make build-agent`.
   The build refuses the published test key and warns when no key is
   packaged. Bump the vectorizer's image tag in the catalog if
   `appliance/vectorizer` changed.
3. Sign:
   `release-sign.py manifest --deb dist/happymining-agent_<X.Y.Z>_amd64.deb --version <X.Y.Z> --key <private key> --out <directory> [--min-upgrade-from <A.B.C>] [--notes "…"]`,
   then check:
   `release-sign.py verify --manifest <dir>/manifest.json --signature <dir>/manifest.sig --pub <key>.pub --deb <package>`.
4. Make sure the server lists the public key in `HM_RELEASE_PUBLIC_KEYS`.
5. Publish: dashboard Admin → Releases (manifest and signature), or
   `POST /api/v1/releases` `{"manifest_b64": "<base64 of manifest.json>", "signature_b64": "<content of manifest.sig>"}`.
6. Upload the package: `PUT /api/v1/releases/<X.Y.Z>/artifact` with the
   file as the raw body, `Content-Type: application/octet-stream`. The
   dashboard cannot upload it. Behind Caddy (`deploy/Caddyfile*`) this one
   route accepts up to 512 MB; **the Hostinger staging instance's Traefik
   limits every body to 1 MB** and refuses it with `413`.
7. Offer it: `POST /api/v1/releases/<X.Y.Z>/channels` `{"channels": ["beta"]}`;
   after machines on `beta` report it `installed` and keep heartbeating,
   `{"channels": ["beta", "stable"]}`.
8. To stop a release: `POST /api/v1/releases/<X.Y.Z>/withdraw`
   `{"reason": "…"}`. Queued `install_update` operations that no machine has
   received are cancelled; machines that installed it keep it.

### Giving and revoking remote access

On a machine managed by its owner (`customer`), HappyMining sees monitoring
data only. To work on its appliance, staff need a grant from the owner's
organisation.

- The owner's `org_admin`, on the machine page, section "Remote access":
  level `view` (read the appliance state) or `manage` (change it, request
  operations), an expiry (1 hour to 90 days, or none) and a reason. API:
  `POST /api/v1/machines/{id}/remote-access/grants`
  `{"level": "manage", "expires_in_hours": 24, "reason": "…"}`
  (`expires_in_hours: null` for no expiry, which has to be said
  explicitly).
- Revoking: the `org_admin`, or staff to give a grant up, with the revoke
  button on the same page or
  `POST /api/v1/machines/{id}/remote-access/grants/{grant_id}/revoke`. It
  takes effect at once: operations staff or fleet-wide API clients had
  queued and the machine has not received are cancelled. What the machine
  already received is not recalled.
- Who manages the machine: `PUT /api/v1/machines/{id}/management`
  `{"management": "customer"}` (staff or `org_admin`); back to `company`
  only by the `org_admin`.
- `GET /api/v1/machines/{id}/remote-access` shows the current and past
  grants. Issuing, each change made under a grant and revoking are in the
  audit trail.

### A machine reports `rolled_back`

It means: the release was installed, the new agent did not complete a
heartbeat with the new version within 10 minutes, and the helper installed
the previous package again. That version is never installed again on that
machine.

1. Check that the machine heartbeats again with the previous version.
2. If other machines might install it, take it off the channels or withdraw
   it.
3. With the owner's consent (and a grant on a `customer` machine), have the
   machine's administrator collect
   `journalctl -u happymining-update-install.service -u happymining-update-guard.service -u happymining-agent.service`
   from around the installation. A slow or broken network after the
   installation can roll back a good release: the guard only sees whether a
   heartbeat happened.
4. Publish the fix under a new, higher version.

`error` with "no previous package to roll back to" means nothing was rolled
back and the new agent may not be running: the machine needs hands-on
repair (install the previous package by hand). A machine without
`/var/lib/happymining-helper/packages/current.deb` refuses `install_update`
unless `ALLOW_UPDATE_WITHOUT_ROLLBACK=1` is set there. On a machine installed
from the image the helper takes the installer's copy of the package from
`/var/cache/happymining` (`docs/appliance.md`, section 9); after a manual
installation the first update has no automatic rollback.
