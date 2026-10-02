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
| The Docker images | **Not built in the development sandbox** (registries unreachable). The compose files are validated offline. The first real build is the first deployment. |
| The agent against a deployed API | The real agent binary was run against the real API on the same host only. |
| Bank or payout-provider files | The settlement export and the confirmation import use a CSV layout of our own. No bank format is implemented. |

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
- A signed APT repository and automatic agent upgrades. The package is a
  signed file installed by hand.
- Production release signing. Everything signed so far is signed with a
  **development key** generated locally and kept out of the repository.
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

## Scale

Sized for a pilot: one API process, one worker, one PostgreSQL, tens of
machines. Rate limits and counters are in PostgreSQL. Telemetry is one row per
sample with a 30-day retention. Nothing was load tested.
