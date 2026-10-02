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
| The API is down | Agents buffer and retry. Hosting on Vast is not affected. No operation reaches any machine. |

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
