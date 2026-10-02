# Threat model

Scope: the HappyMining control plane (API, dashboard, worker, database), the
HappyMining agent on owners' machines, and the installer. Vast's platform and
host daemon are outside our control; they appear here only where they shape
ours.

One thing first, because no control changes it:

> **An owner with root on their machine can remove the agent, block it, or
> feed it false readings.** Software cannot enforce a commission against the
> person who controls the hardware. What protects HappyMining's fee is that the
> Vast account, and therefore the payout, is HappyMining's, plus the contract
> with the owner. The agent is a monitoring tool, not an enforcement tool.

## Assets

1. Owner money: ledger balances, beneficiary details, payout batches.
2. The Vast account API key (account-wide).
3. Renter workloads and data on the machines.
4. Device credentials and pairing codes.
5. Human sessions, especially admin.
6. Release artifacts: the agent package and the installation image.
7. API client tokens held by other systems (Mole Hash).

## Trust boundaries

```
renter ──(Vast)──► machine: Vast daemon + renter containers
                   machine: HappyMining agent (unprivileged)  ──TLS──►  API ◄── admin / owner browsers
                                                                         │
                                                              worker ──TLS──► Vast host API (read-only)
```

- The agent is **not** trusted by the API: it can only write its own telemetry
  and acknowledge its own operations.
- The API is **not** trusted by the agent beyond a fixed list of typed
  operations, and the disruptive ones are off unless the machine's local
  administrator enables them.
- Renters are trusted by nobody.

## 1. Malicious renters

A renter controls a container (possibly a VM) on the machine.

| Threat | Position |
|---|---|
| Read the agent's credential or config | Files are `0600`/`0750`, owned by the `happymining` user, outside any path Vast exposes to containers. A container escape defeats this; that is a host-compromise scenario and Vast's isolation is the control. |
| Reach the agent or helper | The agent listens on nothing. The helper socket is a root-owned Unix socket not mounted into containers. |
| Get their workload data collected by HappyMining | The agent collects no process lists, container names, command lines, environment or files. The API additionally drops any field it does not know before storing. Tested on both sides. |
| Use the Docker socket through the agent | The agent has no access to the Docker socket; a packaging test fails if it ever appears. |
| Poison telemetry (fake GPU load) | Possible to a degree. Telemetry is informational only: it never feeds earnings, and never decides whether maintenance is safe. |
| Be interrupted by HappyMining | The rental-protection gate blocks every disruptive action unless the provider confirms the machine is unlisted and has no active contract, stopped instance or stored data. In LIVE that state is not available from Vast's documented API, so the gate always blocks. |

## 2. Compromised agent (or a stolen device credential)

| Threat | Control |
|---|---|
| Write telemetry for another machine | The machine comes from the credential, never from the payload. |
| Read or change another tenant's data, or any financial data | Device credentials are refused on every human route (tested by enumerating all routes). There is no device route that touches money. |
| Claim a Vast machine or an owner | The device never chooses either. Binding is an admin action against the provider's own machine list; the agent's hint is labelled untrusted evidence. |
| Replay or forge operation acknowledgements | Per-operation nonce, write-once final state, expiry, device scoping. |
| Flood the API | Body limit 256 KiB (a body past the limit is never handed to the application as if complete), at most 100 samples per request, bounded field sizes, idempotent on `(device, seq)`. Every authenticated device request counts against a per-device limit before its body is validated; heartbeats and credential rotations have their own, lower limits. Telemetry older than the retention period is purged. |
| Leak secrets through an acknowledgement | `detail` and `result` are redacted before storage and capped at 64 KiB. Redaction is pattern matching: a net, not a guarantee. |
| Keep using a stolen credential | Revocation is immediate. Rotation supersedes the old credential; first use of the new one revokes it. |
| Lift the Vast account key | It is not on the machine and is never sent to agents. |

A compromised agent on a machine can still lie about that machine's telemetry
and can execute the operations the local administrator enabled. It cannot
escalate through the helper beyond the two fixed, switch-gated actions.

## 3. Owner tampering

| Threat | Position |
|---|---|
| Remove or block the agent | Cannot be prevented. Detected as a stale machine. Hosting and earnings continue; they do not depend on the agent. |
| Send false telemetry | Cannot be prevented. Earnings come from the provider, not from telemetry. |
| See or alter another owner's data | Tenant scoping on every route and page; object ids of other tenants answer "not found". |
| Raise their own balance, change their fee, approve their own payout | All mutating money routes are admin only. The owner role is refused on every one (tested by enumeration). |
| Re-pair a machine to themselves | Pairing codes are created by an admin for a fixed owner and machine. |
| Take the machine off Vast and host on their own account | A commercial matter. The system shows the machine as missing from the provider inventory. |
| Extract Vast's host key from their own machine | It is on their disk and root can read it. It is Vast's host-local credential, scoped by Vast to that machine. HappyMining's agent never reads it. |

## 4. Central account compromise

The most damaging scenario: an admin session, the database, or the Vast key.

| Threat | Control | Residual risk |
|---|---|---|
| Stolen admin password | MFA (TOTP) is mandatory for admins in LIVE; demo login is refused at start-up. A TOTP code is accepted once. Login attempts are limited per address, per account-and-address, and per account. Sessions are server-side, `HttpOnly`, `Secure`, `SameSite=Strict`, with CSRF tokens. An admin (or the operator CLI) can deactivate an account or revoke its sessions at once; replacing a password ends its sessions. | Phishing of a live TOTP code. Hardware keys or an MFA-enforcing IdP would be stronger. |
| Demo and real data in one database | A database records the mode that first used it; a process configured for the other mode refuses to start against it. Synthetic owners are never paid in LIVE. | An operator pointing a LIVE process at a fresh, empty database by mistake creates a second LIVE database, not a mixed one. |
| One admin pays themselves | Preparer and approver must differ by default. Payouts are off by default. No automatic transfer exists: money moves only when a human pays the exported file at the bank. Every step is audited. | Two colluding admins. An admin with database access. |
| Malicious remote commands to the fleet | No shell endpoint. Fixed typed operations; disruptive ones need the server flag, the gate, the agent's local allowlist and the root-owned helper switch. | An admin could still enable and misuse a restart on a machine whose local admin opted in. |
| Database theft | Beneficiary details and TOTP secrets are encrypted with a key that is not in the database. Device, session and pairing secrets are stored as keyed hashes. | Owner names, earnings, emails and the audit trail are readable. The provider snapshots are scrubbed of personal data and keys. |
| Tampering with the ledger or audit trail | Append-only triggers; hash-chained audit trail; `verify` recomputes both and cross-checks the reconciliation tables against the journal. The API and the worker connect as a role with no `UPDATE`/`DELETE` on the journal or the audit trail and no right to disable triggers, so a compromised application process cannot rewrite history. | **The database owner role, a superuser, or anyone with the host can disable triggers and rewrite the whole chain.** The audit trail is tamper-evident for the application, not tamper-proof. Ship the chain head to a separate system to close this. Running totals outside the journal (a bucket's reported amount, for example) are writable by the application role; `verify` detects a change, it does not prevent one. |
| Stolen Vast API key | Stays in the backend environment. Use a scoped key (`machine_read`, `billing_read`, `user_read`). Never logged; scrubbed from stored responses. Writes are off by default. | If writes are enabled later the key must be `machine_write` and its theft could unlist or relist machines. |
| Server compromise | The API, worker and migration containers run as a non-root user with a read-only filesystem and no capabilities; the database is not exposed; only the reverse proxy publishes ports. (The PostgreSQL and proxy containers are the stock images and are not hardened beyond `no-new-privileges`.) | Full host compromise yields the encryption key and the Vast key from the environment. Keep them in a secret manager when one is available. On a shared host, every other workload with access to the Docker socket is equivalent to root: the Hostinger VPS runs such workloads (see `deploy/README.md`). |

### API clients (Mole Hash and other integrations)

A token for the integration API is a long-lived secret held by another system.

| Threat | Control | Residual risk |
|---|---|---|
| The token leaks (from the other system, its backups, its logs) | Scopes chosen per client; optional restriction to one owner; optional expiry; revocation and rotation take effect at once; only a keyed hash is stored here; the token is refused on every route outside the integration API; per-client rate limit; redacted from logs and audit details. | Until it is noticed, the holder has what the scopes give: with read scopes, the fleet, telemetry and earnings of every owner in scope. |
| The other system is compromised and asks for harmful actions | Only the fixed typed operations exist. Disruptive ones need a separate scope, the server switch, the rental-protection gate and the machine's local allowlist. Every request is audited with the client as the actor and carries an idempotency key. A client can cancel only its own requests, and can hold at most 8 open operations per machine, so it cannot withdraw an admin's request or fill a machine's queue. A token is re-checked inside the transaction that queues an operation; requests of a revoked or expired client that are still pending are not delivered. | A client with `operations:write` can still queue non-disruptive operations on every machine in scope (diagnostics, inventory, credential rotation). |
| Money moved through an integration | There is no scope and no route for it. The only write routes are "request an operation" and "cancel a pending operation" (checked by a test that enumerates them). | None through this API. |
| A browser page uses the token | The API is server-to-server: bearer token only, no cookies. | A front end that embeds the token gives it to every user of that front end. Do not. If `HM_CORS_ALLOWED_ORIGINS` lists an origin for another reason, a page on that origin could call this API with a token it holds; leave the setting empty unless a separate front end needs it. |
| A burst of requests stalls the API | A request never holds one database connection while waiting for another (this used to exhaust the pool; found in review, fixed, tested with more simultaneous requests than the pool has connections). Per-client rate limit; refused tokens are throttled per address. | An attacker with many addresses and no token can still load the API; that is the reverse proxy's job. |
| One owner's history reaches another | A client limited to an owner (and an owner signed in) sees a machine's telemetry and operations only from the day the machine became theirs. | Staff and fleet-wide clients see the whole history, by design. |

## 5. Supply chain

| Threat | Control | Residual risk |
|---|---|---|
| Malicious Go dependency in the agent | The agent uses only the Go standard library. | The Go toolchain itself. |
| Malicious Python dependency | Versions and hashes pinned in `api/uv.lock`; the image installs with `--frozen`. | A compromised release that was already pinned. No automated vulnerability scan is wired up yet. |
| Tampered agent package or image | Signed `SHA256SUMS`; `install.sh` refuses unsigned packages by default and verifies against a keyring the operator supplies. The Ubuntu base ISO is verified against Canonical's signed checksums. | The signing key in this repository's workflow is a **development key**. Production key custody is specified in `docs/trust-chain.md` and not yet in place. There is no signed APT repository; upgrades are manual. |
| Secrets baked into an image | The image holds no password, key, pairing code or credential; a scanner fails the build if one appears. Identity and SSH host keys are generated on first boot. | A cloned disk copies identity: `sanitize-clone.sh` must be run. |
| Vast's installer or daemon | Outside our control. It runs as root with passwordless sudo and auto-updates. | Complete. The operator runs Vast's command themselves; HappyMining does not download, embed or automate it. |
| Base images (`python`, `postgres`, `caddy`) | Tags are pinned. | Not pinned by digest yet. |

## Not addressed

- Denial of service against the API beyond the login, pairing and per-device
  rate limits. Unauthenticated floods are the reverse proxy's problem.
- Secrets that do not look like secrets: redaction of logs, audit details and
  device acknowledgements recognises known formats and key names only.
- Physical attacks on machines.
- Side channels between renter workloads.
- Insider abuse at Vast.
