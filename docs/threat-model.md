# Threat model

Scope: the HappyMining control plane (API, dashboard, worker, database), the
HappyMining agent on owners' machines, and the installer. Vast's platform and
host daemon are outside our control; they appear here only where they shape
ours. Section 6 covers the appliance (plugins, NAS, index, backups, firmware
updates; `docs/appliance.md`), which is built but has never run on a real
machine.

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
8. With the appliance: the owner's files on NAS shares and the index built
   from them; the owner's secrets (NAS passwords, AI provider keys, S3
   keys), stored sealed; the machine's sealing key and backup key; the
   vectorizer token.
9. The firmware release signing key (Ed25519), which every machine with
   `ALLOW_UPDATE` trusts.

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

With the appliance, on the machine:

```
 API ──document, sealed secrets, release offer──► agent (unprivileged)
                                                    │ unix socket, peer uid checked
                                                    ▼
                         hm-helper (root): validates again against the installed catalog,
                         gated by root-owned helper.conf switches (all off by default)
                                                    │ fixed argv only
                     ┌──────────────────────────────┼──────────────────────────────┐
                     ▼                              ▼                              ▼
          Docker: plugin containers         mount: NAS shares (CIFS/NFS)     dpkg: signed package
          (third-party images,              read-only, nosuid,nodev,noexec   (verified with keys
           network hm-appliance)            except backup destinations       shipped in the package)
```

- The helper trusts nothing from the agent: every document, job and release
  is validated again, against definitions installed on the machine.
- Plugins (third-party software in containers) are trusted by nobody: they
  never see the helper, the Docker socket or another plugin's secrets.
- The owner's people reach plugins on their own network; the control plane
  is not in that path.

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
| Share the machine with the appliance's plugins | In `vast` mode no plugin runs. Leaving `vast` on a bound machine passes the same gate (always blocked in LIVE). On the machine, GPU plugins do not start while a container HappyMining did not start is running. Nothing in the appliance stops Vast's daemon, a container without HappyMining's label, or deletes storage it did not create. Residual: the gate is in the control plane; the helper applies any well-formed document it is handed, so a compromised agent or control plane could start the **non-GPU** plugins next to a renter (CPU, memory, disk, ports) on a machine whose `ALLOW_PLUGINS` is on. A Vast host should keep the appliance switches off. The GPU guard is a guard, not a proof: a container can carry any label. |
| Reach a plugin | Only possible when a machine outside `vast` mode is rented anyway (listing is an operator action at Vast that HappyMining does not undo). Plugins publish their ports on the host (`127.0.0.1` or all addresses, per plugin), so a renter container that can reach the host's addresses can reach a plugin published on all addresses. Each plugin's own authentication (Open WebUI login, OpenClaw pairing, Hermes basic authentication, the vectorizer's token) is what stands; Qdrant and Ollama have none and default to `127.0.0.1`. |

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
and can execute the operations the local administrator enabled. With every
appliance switch off it cannot escalate through the helper beyond the two
fixed, switch-gated actions.

With the appliance switches on the helper does more (section 6). A compromised
agent can then also, within the switches that are on: hand the helper any
document that validates against the installed catalog (start catalog
plugins, mount NAS hosts of its choosing, change the mode without the
control plane's gate), start the appliance jobs, and hand it a release that
is properly signed and newer than the installed one. It cannot make the
helper run anything outside the fixed command lines, install an unsigned or
older package, read the backup key or the sealing key, or open a secret
(the agent never has the sealing key; secrets travel through it sealed). It
can report a false appliance state, including a new sealing public key to
receive future secrets: the control plane audits every key change.

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
| Malicious appliance configuration | Documents name catalog plugins with typed settings; no image, Compose file, command or path travels. Staff need a remote-access grant on customer-managed machines; every change is audited with what changed. On the machine: the switches, the GPU guard, `control: local`. | An admin (on `company` machines, or with a `manage` grant) or a compromised control plane can start any catalog plugin, point NAS entries, the answer provider and the S3 endpoint at hosts of their choosing — through the API or the panel only by sending the secret again (the control plane does not carry a stored secret over to a new destination), but a compromised control plane can hand the machine such a document directly, because the seal binds only the name (section 6) — switch a machine out of `vast` (an admin only where the gate allows it, a compromised control plane at will), and set the update policy to `auto`. |
| Malicious firmware | A package installs only if its manifest is signed by a key installed with the current package; the API also refuses unsigned manifests, so a staff session alone cannot publish firmware. Never a downgrade; automatic rollback when the new agent does not come back. | Whoever holds the signing key **and** can publish (an admin account, or the API itself) can run code as root on every machine with `ALLOW_UPDATE` on that channel; with `policy: auto` it installs unattended in the window. Custody of that key is not in place (section 6). |
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
| Tampered agent package or image | Signed `SHA256SUMS`; `install.sh` refuses unsigned packages by default and verifies against a keyring the operator supplies. The Ubuntu base ISO is verified against Canonical's signed checksums. | The signing key in this repository's workflow is a **development key**. Production key custody is specified in `docs/trust-chain.md` and not yet in place. There is no signed APT repository. Upgrades through the API (signed manifests, section 6) are built but have never run; the first installation is manual. |
| Secrets baked into an image | The image holds no password, key, pairing code or credential; a scanner fails the build if one appears. Identity and SSH host keys are generated on first boot. | A cloned disk copies identity: `sanitize-clone.sh` must be run. |
| Vast's installer or daemon | Outside our control. It runs as root with passwordless sudo and auto-updates. | Complete. The operator runs Vast's command themselves; HappyMining does not download, embed or automate it. |
| Base images (`python`, `postgres`, `caddy`) | Tags are pinned. | Not pinned by digest yet. |
| Plugin images (Ollama, Qdrant, Open WebUI, OpenClaw, Hermes Agent) | Pinned by tag and digest in the catalog; a plugin with an unverified digest does not start unless `ALLOW_UNPINNED_IMAGES`. Compose rules forbid privileged mode, host networking, host PID/IPC, the Docker socket and host paths outside HappyMining's directories (repository tests). Upstream telemetry off where documented. | Their code was not audited. Digests were read from Docker Hub's API, not pulled, and should be checked again (`docker buildx imagetools inspect`) before a release. A plugin has whatever its upstream does with the network and with the API keys it is given. |
| The vectorizer image, built on each machine | Base image pinned by digest; Python dependencies installed with `--require-hashes` from a lock file; the running container is offline and runs as uid 10001. | The build downloads `torch` and `torchvision` from PyTorch's CPU index **by version only** (not hash-pinned) and Docling's models from Hugging Face and modelscope.cn **unpinned**, on each machine, at the time of the build. Two machines can end up with different bytes. Never built anywhere yet. |
| Firmware release keys on the machine | Only keys from `HM_RELEASE_KEYS_DIR` at build time enter the package; the build refuses the published test key; the control plane refuses it in LIVE. | No production key exists. A new key reaches machines only inside a package signed with a key they already trust. |

## 6. The appliance

Built, tested with fakes, never run on a real machine (`docs/limitations.md`).
The positions below are what the code does, not what was observed in use.

### Plugins and their images

| Threat | Control | Residual risk |
|---|---|---|
| A plugin escapes into the host | Containers only, no privileged mode, no host network, PID or IPC, no Docker socket, bind mounts only under `/srv/happymining` and the plugin's own data directory (checked by the repository's catalog tests on every Compose file). | Container isolation is the control. A kernel or runtime escape is host compromise. GPU plugins get the NVIDIA runtime's device access. |
| A plugin reads another plugin's data or secrets | Each plugin's secrets are only in its own root-only env file; volumes are per plugin. | All plugins share the network `hm-appliance` and reach each other by service name. Qdrant has no API key while the vectorizer is used, so any plugin can read and change the whole index there. Ollama has no authentication. |
| A plugin acts on the internet with the owner's keys (OpenClaw, Hermes Agent and Open WebUI can call AI providers and tools) | The owner enables each plugin and gives it its keys. | Agents with tools act on what they read, including injected instructions. HappyMining does not restrict a plugin's outbound network. |
| The catalog is changed remotely | It cannot be: the catalog is installed with the package, and only a signed release changes it. | Whoever can sign a release can change it (below). |

### The root helper's new powers

The helper now drives Docker (equivalent to root), mounts network file
systems as root and installs packages with `dpkg`.

| Threat | Control | Residual risk |
|---|---|---|
| Arbitrary command or path from the network | Every command is a fixed argv with an absolute path; the only variable parts are validated ids, paths built from them, image references from the installed catalog and catalog argv. No shell. Mount options come from fixed forms. In 17 experiments that each removed one check, a test failed every time (as reported by the engineers who built it). | Tested with an injected command runner only; never against real Docker, mount or dpkg. |
| The socket helper becomes a long-running root process | Quick actions only, in the unchanged sandbox; long work runs in separate oneshot units with their own (wider) sandboxes, each relaxation commented. | `happymining-appliance-apply.service` has no file-system namespace (mounts must reach the host) and a capability set for mount helpers; the update units have no `ProtectSystem` (dpkg writes the system). None was ever started. |
| Something HappyMining did not start is stopped or deleted | Only Compose projects `hm-<id>` are acted on, by name; `down` never with `-v`; volumes are deleted only by `appliance-purge` on the machine, after confirmation; mounts not made by HappyMining are never unmounted. | A container labelled `eu.happymining.plugin` by someone else counts as HappyMining's for the GPU guard. |
| A secret leaks through the helper | Secrets are opened only to write the file that needs them, never put in an argv (visible in `/proc`), a log, the audit, `state.json`, a result or an error; buffers are wiped (tested with commands that echo every argument). | Go strings (the S3 key during a backup run) cannot be wiped. A plugin's env file holds plaintext, root-only, for as long as the plugin is configured. |

### Sealed secrets and their limits

| Threat | Control | Residual risk |
|---|---|---|
| Database, logs or backups of the control plane leak | Secrets are stored sealed (ECDH P-256, HKDF, AES-GCM) for one machine's key; the control plane has no key to open them. | — |
| Staff read a customer's secret | They see names only. | See the next two rows. |
| The control plane serves a modified sealing page | None: **the page that seals is served by the control plane**. A modified page can send the plaintext elsewhere. | Complete against a compromised or malicious control plane. |
| A stored secret is used against another host | The name is authenticated, so a value sealed as `nas.docs.password` opens only as that. The control plane does not carry a stored secret over to a new destination: changing a NAS entry's server, share, user or domain, the answer provider or its `base_url`, or the S3 endpoint or access key id needs the secret again, sealed (`docs/appliance.md`, section 5). | The seal itself binds the name, not the destination: a **compromised control plane** can still hand the machine a document that sends a stored answer key to another URL or authenticates to another SMB host with the stored password. |
| A false sealing key is reported (stolen device credential, compromised agent) | Every change of a machine's public key is audited (`appliance.seal_key`). | Secrets entered after the change are sealed for the false key. Nothing blocks the change itself. |

### Remote-access grants

| Threat | Control | Residual risk |
|---|---|---|
| HappyMining reads or changes a customer-managed machine without consent | On `customer` machines staff and fleet-wide clients need a grant from an `org_admin` (`view` or `manage`, expiry up to `HM_REMOTE_ACCESS_MAX_HOURS`, revocable); staff cannot issue one to themselves; issuing, each change under it and revoking are audited; pending operations are cancelled when it ends; a transfer closes the previous owner's grants. | `company` is the default for machines staff create. Staff keep monitoring data (telemetry, operation history) without a grant. A database administrator can insert a grant. |
| An owner's operator does more than allowed | Organisation roles per route (`org_operator` cannot change mode, NAS, backup, secrets, updates, users, grants, or see money); an organisation keeps at least one `org_admin`. | — |

### Release signing key custody

| Threat | Control | Residual risk |
|---|---|---|
| The signing key leaks | `scripts/release-sign.py keygen` refuses to write into a repository and creates the private key with mode 0600. Removing its public key from `HM_RELEASE_PUBLIC_KEYS` stops the API from offering anything signed with it. | **No production key exists and its custody is not organised.** The key is an unencrypted PEM file. Machines keep trusting a key until a package signed by a trusted key replaces their key directory. With the key and the ability to publish, code runs as root on every machine with `ALLOW_UPDATE`. |
| A downgrade to a vulnerable version | Never through the helper: the version must be newer and `min_upgrade_from` satisfied; a rolled-back version is refused afterwards. | Root on the machine can install anything; that is the owner. |
| A bad release bricks the fleet | Automatic rollback when the new agent has not completed a heartbeat within 10 minutes. | Only where `packages/current.deb` exists: on machines installed from the image (the helper adopts the installer's copy) and after each update the helper installed; not on a first update after a manual installation. A release that heartbeats but breaks something else stays. |

### The index

| Threat | Control | Residual risk |
|---|---|---|
| Someone on the owner's network searches the index | Every API call except `/healthz` needs the bearer token, compared in constant time; 10 wrong tokens per minute per address give `429`. The token is created on the machine and shown only to root. | **One token, one access level**: whoever has it can search everything that was indexed, whatever the NAS's own permissions. Qdrant, which holds the vectors and the passages, has no API key while the vectorizer is used: anyone reaching its port (published on `127.0.0.1` by default) or the plugin network reads the whole index without the token. |
| Instructions hidden in indexed documents (prompt injection) | Passages are delimited and marked as untrusted data in the prompt; answers come with their sources. | Mitigated, not prevented. The model may follow injected text. |
| A cloud answer provider sees the documents | Only when the owner chooses a cloud provider; the panel says so; the key is the customer's own. | Every question and the passages retrieved for it go to that provider. |
| Documents leave through a write-access share | Shares used as sources are mounted read-only. | The vectorizer container sees every mounted share read-only, also backup destinations. |

### Backups

| Threat | Control | Residual risk |
|---|---|---|
| HappyMining or the storage provider reads a backup | Encrypted on the machine (HKDF, AES-256-GCM, authenticated chunks, truncation detected) with a key generated there and never sent; only its `key_id` is reported. | Losing the recovery key loses every archive. |
| A hostile archive damages the machine on restore | Restored into a new directory; absolute names, `..`, links and special files refused; nothing overwritten; setuid bits dropped. | Putting restored data back into place is manual. |

## Not addressed

- Denial of service against the API beyond the login, pairing and per-device
  rate limits. Unauthenticated floods are the reverse proxy's problem.
- Secrets that do not look like secrets: redaction of logs, audit details and
  device acknowledgements recognises known formats and key names only.
- Physical attacks on machines.
- Side channels between renter workloads.
- Insider abuse at Vast.
- What third-party plugins do with the owner's data and keys once they run.
- The security of the owner's NAS, of their AI providers and of their S3
  storage.
- Per-user access to the index.
