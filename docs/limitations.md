# Limitations

What is not built, not run, or not verified. Nothing here is a detail: each
item is a reason the system is not ready for real machines or real money
without further work. Component-level lists are in `os/README.md`
("Unverified", "Known limitations") and `agent/README.md` ("Not verified
here").

## Never exercised against the real world

| What | State |
|---|---|
| The Vast adapter | Tested against a fake server written from Vast's documentation and CLI source. **It has never called Vast.** No key and no authorization were available. |
| A real GPU machine | The agent was tested with fixtures and a simulator. `nvidia-smi` on real drivers, the sandboxed systemd units, the helper socket, and the `.deb` installed with `dpkg -i` are untested. |
| The installation image | **The ISO has not been built** (no `xorriso` here, and the Ubuntu ISO could not be downloaded). The seed, the validation and the build script are tested in pieces. |
| The QEMU smoke test | **Not run** (`make smoke-test` exits 77: no QEMU, no ISO). No machine has booted this image. |
| The Docker images | **Not built in the development sandbox** (registries unreachable). The compose files are validated offline. The Hostinger deployment does not build one: it runs stock images with a bootstrap step that fetches one commit; the DEMO runs that way at commit `d0f84f9`, which has no appliance code. The stand-alone image (`deploy/docker-compose.yml`) has never been built. |
| The agent against a deployed API | The real agent binary was run against the real API on the same host only. |
| Bank or payout-provider files | The settlement export and the confirmation import use a CSV layout of our own. No bank format is implemented. |
| The appliance on a machine | Never. See "The appliance" below. |

## The appliance (built, not committed)

`docs/appliance.md` is the contract; its section 14 lists where code and
contract do not fully agree.

### Not run against the final code

- **The control-plane tests that need PostgreSQL.** The test database became
  unavailable during the work (a system account file of the build sandbox
  was lost; see `IMPLEMENTATION_STATUS.md`). None of `tests/api` that needs
  the database has run against the final code: the appliance, device,
  release, sealing, dashboard (18 tests), organisation-role and
  remote-access suites, the changed access-control, integration-API and
  security-regression suites, and `test_end_to_end_binaries.py` (real agent
  binaries against the real API). Earlier versions of four of them passed
  before the database was lost; that says nothing about the final code.
- **Migration `0003_appliance`** was checked (upgrade, `alembic check`,
  downgrade, upgrade) before the database was lost, against the models as
  they were then.
- **`make demo`.** Not run. The simulator now reports an appliance by
  default, so the demo also creates appliance rows; that path is untested.
- **`seal.js`** never ran in a browser. It ran only under Node in the test
  suite, and its output was opened in Python with the test key.

### Never exercised on a machine

| What | State |
|---|---|
| The root helper under systemd | The socket helper and the five new units (`happymining-appliance-apply`, `happymining-appliance-job@`, `happymining-update-install`, `happymining-update-guard` service and timer) were checked with `systemd-analyze verify` only. Whether the apply unit's capability set is enough for `mount.cifs` and `mount.nfs`, whether mounts made by it reach the host's namespace, and whether `systemctl start --no-block` works from the socket helper's sandbox: unverified. |
| Docker | Every Docker command was asserted on as an argv against a fake. No plugin was ever started, no image pulled, no network created. The catalog files and the env-file encoding were checked with the real `docker compose config` (v5.5.1), which reads files and starts nothing. |
| The vectorizer image | Never built: PyTorch's CPU index and Hugging Face were not reachable from the build sandbox. The build downloads `torch`/`torchvision` by version only and Docling's models unpinned, on each machine. |
| Plugin images | Never pulled. Their digests were read from Docker Hub's API on 2026-10-02 and should be checked again before a release. Their upstream code was not audited. |
| CIFS and NFS | Never mounted. The bind propagation `rslave` that should make later mounts visible inside the vectorizer was never observed. |
| `dpkg` | The update installation, the rollback and the guard were tested with a fake `dpkg`. The package itself was never installed with `dpkg -i`; the new maintainer scripts never ran on a real system. |
| The NVIDIA container runtime | Not present here. Whether `ollama` gets the GPUs as its Compose file asks is unverified. |
| Real services | No real Ollama, Qdrant, OpenAI-compatible or Anthropic endpoint, NAS or S3 provider was used. S3 was tested against an in-test server that verifies SigV4 signatures again. |
| Docling | DOCX, PPTX, XLSX, HTML and CSV parsed with the real Docling 2.132.0 in a separate environment. **PDF and OCR not run** (their models could not be downloaded). |
| The firmware update path end to end | Never: no release was signed with a real key, uploaded, offered, downloaded and installed. |
| The integration API additions | `appliance:read`, `GET /machines/{id}/appliance`, `mode` and `remote_access_required` are tested only by database tests that have not run. |

### Not built

- **Installer profiles.** The contract's "appliance" profile (first four
  switches on) and "Vast host" profile do not exist in `os/`; the packaged
  `helper.conf` has every switch off. The seed does not place a local
  profile either.
- **`current.deb` on a first installation by hand.** On a machine installed
  from the image the helper adopts the installer's copy of the package
  (`/var/cache/happymining`) as its rollback package. A package installed by
  hand (`dpkg -i`, `os/install/install.sh`) leaves no copy: such a machine
  refuses updates until `ALLOW_UPDATE_WITHOUT_ROLLBACK=1`
  (`docs/appliance.md`, section 9).
- **A version number for this build.** The agent still reports `0.1.0`.
- **Production release signing for firmware updates.** No production
  Ed25519 key exists; a package built without `HM_RELEASE_KEYS_DIR` refuses
  every update.
- **Package upload behind the Hostinger staging proxy.** Caddy
  (`deploy/Caddyfile*`) lets `PUT /api/v1/releases/{version}/artifact`
  through with 512 MB and keeps 1 MB for everything else (not validated by
  Caddy itself here). The Traefik labels of `deploy/hostinger/` still limit
  every request to 1 MB, so releases cannot be uploaded to that instance.
- **Putting a restored backup back into place.** `backup restore` extracts
  into a new directory; copying back is manual and has no written procedure.
- **Binding a secret to its destination on the machine.** The control plane
  no longer carries a stored secret over to a new host, but the seal itself
  binds only the name: a compromised control plane can still hand the
  machine a document that points a stored secret elsewhere
  (`docs/appliance.md`, section 5).
- **Per-user access to the index**, and an API key between the vectorizer
  and Qdrant.
- **Showing "helper unreachable" in the panel.** The machine reports
  `control: unknown`; the control plane records it as `cloud`.
- **The Mole Hash client** (`integrations/molehash/`) has no method for the
  appliance endpoint.

### Limits of what is built

- `install_update` installs only the newest release offered to the machine;
  a request for an older one fails on the machine.
- A slow download outlasts the operation (default 10 minutes): the operation
  ends `expired` while the machine may still install.
- Under `control: local` the update channel and policy still come from the
  cloud.
- Reported plugin states lag about one heartbeat (refreshed by a job when
  older than 45 seconds).
- A schedule's `ok` means the job was started. The job's own result
  (`skipped`, `failed`) is kept on the machine and not reported; only the
  vectorizer, backup and update states show outcomes.
- The GPU guard trusts a label any container can carry. It is a guard, not a
  proof that no rental is affected.
- The gate on leaving `vast` is in the control plane; the helper applies any
  valid document it is handed.
- The vectorizer container sees every mounted share, read-only, including
  backup destinations.
- Prompt injection from indexed documents is mitigated, not prevented. A
  cloud answer provider receives each question and the passages retrieved
  for it.
- The release package is stored in PostgreSQL and held in memory while it is
  uploaded and served.

## Blocked on Vast (see `docs/integration-evidence.md`)

- **Commercial authorization.** Vast's terms forbid automated use and use of
  an account for others without written agreement. Recorded as an unverified
  external prerequisite. The adapter refuses to call Vast until a reference to
  that agreement is configured. Whether Vast will agree is not known.
- **Rental state is not exposed** by any documented endpoint (running or
  stopped instances, stored customer data). The LIVE adapter reports it as
  unknown, so every disruptive action is blocked in LIVE. Restart of the Vast
  daemon, reboot, driver changes and anything else that can interrupt a renter
  are an operator procedure (`docs/os-maintenance.md`), not a button.
- **Earnings semantics.** Whether reported host earnings are net of Vast's
  fee, the unit and boundaries of the day parameters, and the currency are not
  documented. LIVE earnings are fetched and kept as evidence but **not posted**
  until an operator verifies them against real data and sets two switches. A
  gross basis is not supported at all.
- **No per-day-per-machine endpoint.** One call per machine; the adapter
  refuses a response that does not match the machine it asked for.
- **Maintenance windows** (`dnotify`): the documentation and the CLI disagree
  on a parameter. Not implemented; the call fails explicitly.
- **No webhooks, no enrollment API, no payout splitting.** None exist in what
  Vast documents. None are invented here: machines are bound by an admin,
  earnings are polled, payouts to owners are HappyMining's own.
- **Payout status.** A Vast invoice marked "Paid" means submitted. The ledger
  only accepts HappyMining's own bank or payout-provider statement as evidence
  of cash.

## Not built

- **The Mole Hash side of the integration.** The integration API and a Python
  client exist and are tested. Nothing was changed in Mole Hash: its manager's
  source was not accessible. Until someone wires the client into it, the AI
  servers do not appear there. The API is polling only: no webhooks.

- `run_benchmark` and `apply_hardware_profile` operations (benchmarks, power
  limits, fan or clock profiles). Typed in the protocol, refused by the server
  with `501`. No GPU BIOS flashing, ever.
- Automatic money transfers. `manual_export` is the only LIVE path: a person
  pays the exported file at the bank.
- A flow to take the management fee out (`fee_earned` accumulates in the cash
  account), VAT or tax logic, currency conversion (USD only), a holdback
  reserve percentage, negative owner balances or automatic clawback.
- Automatic matching of provider payouts to earnings days. Allocation is an
  operator decision.
- Re-encryption after rotating `HM_FIELD_ENCRYPTION_KEY`.
- Password reset by email, self-service owner sign-up, an owner-facing way to
  enter beneficiary details (an admin enters them).
- A signed APT repository. Firmware updates of the agent package through
  the API (signed manifests, automatic rollback) are built but have never
  run (see "The appliance"); the first installation is still a signed file
  installed by hand.
- Production release signing. Everything signed so far is signed with a
  **development key** generated locally and kept out of the repository; for
  firmware updates no key exists at all.
- Alerting. Health, metrics and the exception queue exist; nothing pages
  anyone.
- Scheduled backups in the Traefik deployment variant, and shipping the audit
  chain head to a separate system.
- Dependency vulnerability scanning and image pinning by digest.
- CI. The checks are `make` targets run by hand.

## Security limits worth knowing

- An owner with root on their machine can remove or block the agent, or feed
  it false readings. Software cannot enforce a commission against the person
  who controls the hardware. What protects the fee is that the Vast account,
  and therefore the payout, is HappyMining's, plus the contract.
- The audit trail and the journal are tamper-evident for the application, not
  tamper-proof against the database owner, a superuser or the host.
- Running totals outside the journal can be changed by the application's
  database role; `verify` detects that, it does not prevent it.
- TOTP is the only second factor. No hardware keys, no single sign-on.
- Redaction of logs and stored device output is pattern matching.
- Rate limiting covers logins, pairing and authenticated devices.
  Unauthenticated floods are left to the reverse proxy.
- On a shared host, any workload with the Docker socket is root on that host.
- The appliance's sealed secrets are only as safe as the control plane that
  serves the sealing page; the seal binds a secret to its name, and only the
  control plane's rule binds it to its destination (`docs/threat-model.md`,
  section 6).
- The vectorizer token is one access level for the whole index; Qdrant has
  no key while the vectorizer uses it.

## Scale

Sized for a pilot: one API process, one worker, one PostgreSQL, tens of
machines. Rate limits and counters are in PostgreSQL. Telemetry is one row per
sample with a 30-day retention. Nothing was load tested.
