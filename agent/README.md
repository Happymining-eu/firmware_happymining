# HappyMining agent

On-machine software of HappyMining OS: a Go monitoring agent for GPU servers
(Ubuntu Server, NVIDIA GPUs) that HappyMining operates as hosts on Vast.ai.

The agent **observes and reports** to HappyMining's own API
(`docs/agent-protocol.md`). It is not in the rental data path:

- it never talks to Vast's API and never holds a Vast account key;
- it never reads renter containers, files, processes or command lines, and it
  does not use the Docker socket;
- it never installs, changes or removes Docker, NVIDIA drivers or the Vast host
  software;
- if the HappyMining API is unreachable it buffers on disk and retries. Vast
  hosting is not affected.

The package also carries the **appliance** (`docs/appliance.md`): a catalog
of local AI plugins, a vectorizer that indexes NAS shares, encrypted
backups and signed firmware updates. The unprivileged agent only relays: it
reports the appliance state in its heartbeat, hands the desired-state
document to the privileged helper, runs the schedules and downloads
releases. Everything that needs root (Docker Compose for HappyMining's own
plugins, NAS mounts, backups, `dpkg`) is done by the helper, each part only
when its switch in `/etc/happymining/helper.conf` is on; every switch is off
as packaged. No plugin runs while the machine is in `vast` mode. The
appliance has **never run on a real machine** ("Not verified here").

Version: `0.1.0` (single source of truth: `internal/version/version.go`).
The tree with the appliance has not changed it yet; a release must (build
with `HM_VERSION`, see "Build, test, package").
Only the Go standard library is used; there is no third-party module.

## Binaries

| Binary | Installed at | Runs as | What it does |
|---|---|---|---|
| `happymining-agent` | `/usr/bin` | user `happymining` (systemd, sandboxed) | Collects a sample every interval, spools it on disk, sends spooled samples oldest first (at most 100 per request and 256 KiB), deletes what the API acknowledged, handles typed operations. |
| `happyminingctl` | `/usr/bin` | the operator (`sudo` for `pair`, `unpair` and the appliance's local actions) | `identity init`, `pair`, `status`, `unpair`, `preflight`, `vast-enroll-help`, `version`, `appliance status\|secret set\|purge\|token`, `backup init\|restore`. |
| `hm-helper` | `/usr/lib/happymining/hm-helper` | root: socket-activated, one process per request, and as the program of the appliance's oneshot units | The only privileged code. Restart of the Vast daemon and delayed reboot (both disabled by default), and the appliance actions (each behind its own switch, all off by default). |
| `hm-simulator` | not packaged (`dist/bin`) | anyone | Simulates machines without NVIDIA hardware. Every sample is marked `"synthetic": true`. |

## Pairing procedure

1. A HappyMining administrator creates an enrollment request for one owner and
   one machine record. The API shows a pairing code once. It is valid for a
   short time and usable once.
2. On the machine, at a terminal:

   ```
   sudo happyminingctl preflight      # optional, read-only
   sudo happyminingctl pair
   ```

   `pair` prompts for the code with echo switched off, then shows the code
   with its secret part masked so the locator can be checked. Case, hyphens
   and spaces do not matter; `O` is read as `0`, `I` and `L` as `1`.
3. `pair` creates the install identity if it is missing, calls the enrollment
   endpoint once and writes `/var/lib/happymining/credential.json` (mode 0600,
   owner `happymining`, atomic write). It prints the device, machine and
   credential ids, never the token.
4. The running agent picks the credential up within about ten seconds.
   Check with `happyminingctl status`.

Rules that are enforced in code:

- The pairing code is never written to disk and never logged. It is not read
  from an environment variable. `--code` exists for automated tests only: a
  command line is visible to other users of the machine.
- `pair` refuses to run when a credential exists. Run `sudo happyminingctl
  unpair` first. `unpair` deletes only the local credential; ask HappyMining to
  revoke it on the server as well.
- A failed pairing is never retried automatically. The API answers the same
  generic error for a wrong, expired, used or locked code.
- The device chooses neither its owner nor its machine record: both come from
  the enrollment request on the server.

Installing the official Vast host software is a separate, manual step:
`happyminingctl vast-enroll-help` prints the procedure. The operator obtains
the install command from the Vast console and runs it by hand. No HappyMining
tool downloads, embeds, stores or automates that command or any Vast key.

## Configuration

### `/etc/happymining/agent.env`

`KEY=VALUE` per line, `#` comment lines. The parser is strict: unknown keys,
duplicate keys, malformed lines and out-of-range values are errors, and the
agent exits with status 78 without restarting in a loop. The file is root-owned
and must not contain secrets.

| Key | Default | Meaning |
|---|---|---|
| `HM_API_URL` | (packaged: `https://api.happymining.fr`) | API base URL. HTTPS only, certificate always verified. |
| `HM_HEARTBEAT_INTERVAL_S` | `60` | Seconds between samples, 15 to 3600. The API's `next_interval_s` may change it at run time within the same bounds. |
| `HM_STATE_DIR` | `/var/lib/happymining` | Identity, credential, sequence counter, operation journal, status file. If you change it, change `StateDirectory=`/`ReadWritePaths=` in a unit drop-in too. |
| `HM_SPOOL_DIR` | `<state dir>/spool` | Telemetry buffer. |
| `HM_SPOOL_QUOTA_MIB` | `64` | Buffer quota, 1 to 4096. When full, the oldest samples are dropped first and counted in the log and in `status`. |
| `HM_MAX_SAMPLE_AGE_H` | `168` | Buffered samples older than this are dropped instead of sent (the API rejects samples older than 7 days). |
| `HM_CA_FILE` | empty | Extra CA bundle (PEM) trusted in addition to the system roots. |
| `HM_ALLOW_INSECURE_LOOPBACK` | `0` | `1` allows plain HTTP, only to `127.0.0.1`, `::1` or `localhost`. For development and tests. |
| `HM_OPS_ENABLED` | empty | Comma list of opt-in operation types: `restart_vast_daemon`, `reboot` (`run_benchmark` and `apply_hardware_profile` are accepted by the parser but not implemented in 0.1.0). |
| `HM_EXTRA_MOUNTS` | empty | Extra mount points to report, comma-separated absolute paths (at most 14). |
| `HM_VAST_MACHINE_ID_FILE` | `/var/lib/vastai_kaalia/machine_num_id` | File holding the **numeric** Vast machine id (the number shown in the Vast console). Only the SHA-256 of that number is sent, as an untrusted hint, and only if the unprivileged agent can read the file and it contains a plain number; otherwise `null`. The default path comes from reading Vast's installer and is **not confirmed by Vast documentation**. `vastai_kaalia/machine_id` is rejected: despite its name that file is Vast's host API key (a secret), and the agent never reads it. |
| `HM_HELPER_SOCKET` | `/run/happymining-helper.sock` | Socket of the privileged helper. |
| `HM_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error`. |

There is no option to skip TLS verification. TLS 1.2 is the minimum. Redirects
are never followed, so the bearer token only ever goes to the configured URL.

### `/etc/happymining/helper.conf`

Switches of the privileged helper, each `0` or `1`. Default and missing file:
everything disabled. The helper refuses the file (and therefore every
action) if it is a symbolic link, not a regular file owned by root, writable
by group or others, or has an unknown key.

| Key | Allows |
|---|---|
| `ALLOW_RESTART_VAST_DAEMON` | `systemctl restart vastai.service` on request (also needs `HM_OPS_ENABLED`) |
| `ALLOW_REBOOT` | a delayed reboot on request (also needs `HM_OPS_ENABLED`) |
| `ALLOW_PLUGINS` | starting and stopping the catalog plugins (Compose projects `hm-<id>`); `vectorize_sync` and `plugin_restart` jobs |
| `ALLOW_NAS` | mounting the document's NAS entries under `/srv/happymining/nas/<id>` |
| `ALLOW_BACKUP` | running backups |
| `ALLOW_UPDATE` | installing signed releases of this package |
| `ALLOW_UNPINNED_IMAGES` | starting a plugin whose image is not pinned to a verified digest |
| `ALLOW_FOREIGN_CONTAINERS` | starting GPU plugins while containers HappyMining did not start are running |
| `ALLOW_UPDATE_WITHOUT_ROLLBACK` | installing a release when no copy of the installed package is kept (`/var/lib/happymining-helper/packages/current.deb` missing) |

With `ALLOW_PLUGINS` and `ALLOW_NAS` both off, desired-state documents are
validated and stored but nothing is applied, except that a plugin HappyMining
started earlier is stopped when the document no longer runs it (vast mode
above all): stopping HappyMining's own plugins needs no switch, starting
does. A Vast host should leave the appliance switches off. The packaged file
explains each switch.

### State directory

| File | Mode | Content |
|---|---|---|
| `identity` | 0600 | 32 random bytes (hex), created on first boot. Only its SHA-256 is sent, at enrollment. Not derived from hardware serial numbers. |
| `credential.json` | 0600 | Device credential. The agent refuses to load it if group or others can access it. |
| `seq` | 0600 | Sequence counter, persisted before each number is used. |
| `spool/` | 0750 | One file per unsent sample. |
| `ops.journal` | 0600 | Append-only, fsynced journal of operation ids (replay protection). |
| `agent-state.json` | 0600 | Status for `happyminingctl status`. No secret. Also `machine_id` (backup archive names) and the last successful heartbeat with the agent version that made it (the update guard reads both; the helper never reads `credential.json`). |
| `schedules.json` | 0600 | Last run and outcome of each appliance schedule. |
| `updates/` | 0700 | Download of a firmware release (`.<file>.part` while it is written), handed to the helper. |

The helper's own state is root-only, in `/var/lib/happymining-helper`
(0700): `docs/appliance.md`, section 8.4.

## What the agent sends

Exactly the sample object of the protocol and nothing else; a unit test fails
if a serialised sample contains any other key. Unknown numbers are `null`,
never `0` (`[N/A]`, `[Not Supported]`, `N/A`, empty and out-of-range values
from `nvidia-smi` all become `null`). Unknown strings are sent as `""`.

Sources: `/proc` (uptime, cpuinfo, loadavg, stat, meminfo, mounts), `statfs`
for `/`, `/var/lib/docker` and `HM_EXTRA_MOUNTS`, `nvidia-smi` with one fixed
`--query-gpu` line, `systemctl is-active` (plus a `LoadState` query to tell
"not installed" from "inactive") for `docker`, `vastai` and
`nvidia-persistenced`. External programs are run by absolute path, without a
shell, with a timeout and bounded output.

Not collected, by design: process lists, container names, images or
environment, paths inside container storage, command lines.

Next to the samples, each heartbeat carries the `appliance` object
(`docs/appliance.md`, section 6.1): the state the helper reports (states of
HappyMining's own plugins, NAS mounts, secrets by name, index counters,
backup and update state) plus the agent's schedule history, redacted,
bounded to 64 KiB. It never holds a secret, a file name from a NAS or a
renter's container. When the helper does not answer within 10 seconds, the
object says `control: "unknown"` with the reason.

## Failure behaviour

| Situation | Behaviour |
|---|---|
| Network error, timeout, 5xx, malformed or oversized (over 1 MiB) response | Samples stay in the spool. Retry with exponential backoff and full jitter, base 5 s, cap 15 min. |
| 429 | Wait `Retry-After` seconds (bounded to 1 h) plus jitter. |
| 401 `device_unauthorized` | Stop sending. Keep collecting and buffering within the quota. State `revoked` in `happyminingctl status`. Sending resumes only with a new credential (`unpair`, then `pair`). |
| 400/422 `invalid_request` | The batch is dropped and counted, never resent; then one backoff period before the next batch. |
| 413 | The batch is halved and retried; a single sample that is still too large is dropped. |
| 403/404/409/410 on a heartbeat | Samples are kept; backoff. |
| Any 4xx **without** the protocol's error envelope | Treated as a transient error (a proxy answered, not the API): nothing is dropped and the device is not marked revoked. |
| Process killed or machine reset | Spool, sequence counter and journal are on disk; a resend is safe because the API de-duplicates on `(device, seq)`. |
| Local state lost | The counter jumps to the API's `highest_seq` after the first acknowledged heartbeat. |
| SIGTERM | The request in flight is cancelled, the status file is written, the process exits. Unsent samples stay in the spool. |

## Typed operations

There is no remote shell. The agent accepts only the ten operation types of
the protocol and enforces its own rules in this order: valid UUID id, replay
check against the journal, valid nonce, known type, implemented type, strict
parameters (unknown fields rejected), valid timestamps and not expired, enabled
locally. The id is written to the journal and fsynced before anything runs.

| Type | 0.1.0 | Needs |
|---|---|---|
| `refresh_inventory`, `collect_diagnostics`, `run_preflight`, `rotate_credential` | implemented, enabled | nothing |
| `restart_vast_daemon`, `reboot` | implemented, **disabled** | `HM_OPS_ENABLED` in `agent.env` **and** the switch in `helper.conf` |
| `run_benchmark`, `apply_hardware_profile` | always `rejected`: "not implemented in this agent version" | not available |
| `appliance_run_job` | implemented, enabled | the helper switch of the job (`ALLOW_PLUGINS` or `ALLOW_BACKUP`); `update_check` runs in the agent and needs the update capability (`ALLOW_UPDATE`) |
| `install_update` | implemented, enabled; runs in the background (`accepted`, then the final acknowledgement) | `ALLOW_UPDATE` in `helper.conf` |

The two appliance types are enabled in the agent because they touch only
HappyMining's own containers and package; the root-owned switches, all off
as packaged, are their real gate. A final `succeeded` means started
(`appliance_run_job`) or verified, staged and handed to the installation
unit (`install_update`); the outcome is in the reported appliance state.

`detail` and `result` are redacted and bounded (2000 characters, 64 KiB) before
they are sent. Journal entries are pruned after 30 days, but never before the
operation they describe has expired; the journal holds at most 10 000 ids and
rejects new operations when full.

Zero GPU utilisation is not proof that a restart or reboot is safe. The agent
cannot know about rentals; deciding that is the server's job and enabling the
two switches is a deliberate act of the machine's administrator.

Credential rotation: the agent calls the rotate endpoint, writes the new
credential atomically and only then switches to it. If the write fails it
keeps using the old credential and acknowledges `failed`.

## Security model

### What runs as root, and why

| Component | Root? | Why |
|---|---|---|
| `happymining-agent` | no | User `happymining`, no login shell, no home, empty capability set. |
| `happymining-firstboot.service` | no | Runs `happyminingctl identity init` as `happymining`, once. |
| `hm-helper` (via `happymining-helper@.service`) | **yes** | Restarting a system service and scheduling a reboot need root, and so do the appliance's quick actions (reading root-only state, starting units). This is the only privileged HappyMining code. |
| `hm-helper apply-stored` (`happymining-appliance-apply.service`) | **yes** | Mounting network shares and driving Docker Compose. |
| `hm-helper run-job` (`happymining-appliance-job@.service`) | **yes** | Index runs, plugin restarts and backups (reading plugin volumes under `/var/lib/docker/volumes`). |
| `hm-helper install-staged`, `update-guard` (`happymining-update-install.service`, `happymining-update-guard.service` and `.timer`) | **yes** | `dpkg -i` of a verified release, and the rollback. |
| `happyminingctl pair` / `unpair` | run with `sudo` by a local operator | To write into `/var/lib/happymining`. New files are chowned to the owner of the state directory. |
| `happyminingctl appliance secret set`, `purge`, `token`, `backup init`, `restore` | run with `sudo` by a local operator | They execute `hm-helper` with a fixed argument list and the terminal attached. |
| maintainer scripts | yes (dpkg) | Create the system user and the state directories (agent, helper, plugin data, NAS mount points), enable units. Nothing else. |

Neither the agent nor the helper listens on a network port. The appliance's
plugins do, inside their containers, published on `127.0.0.1` or on every
address according to each plugin's `bind` setting.

### Privileged helper: a root socket instead of sudo

The agent reaches `hm-helper` through `happymining-helper.socket`
(`/run/happymining-helper.sock`, `root:happymining`, mode 0660, `Accept=yes`),
not through sudo. systemd starts one `hm-helper serve` process per connection.

Why this choice:

- `sudo` is setuid, so it cannot work under `NoNewPrivileges=yes`. Using sudo
  would mean giving up `NoNewPrivileges`, the empty capability bounding set and
  `RestrictSUIDSGID` for the whole agent, i.e. for the code that parses
  responses from the network.
- With the socket, the agent keeps the full sandbox and the privileged side is
  a separate process with its own unit, its own audit trail in the journal and
  no environment or file descriptors inherited from the agent.

The cost: one more unit pair to maintain, behaviour that depends on systemd
socket activation (not testable in this repository's CI, see "Not verified
here"), and a local attack surface in the form of a unix socket instead of a
sudoers rule. Because of that choice **the package ships no
`/etc/sudoers.d` file**.

What bounds the helper:

- the socket is reachable only by root and the `happymining` group, and the
  helper checks the peer uid with `SO_PEERCRED` (root or the `happymining`
  user);
- one request per connection, strict JSON (unknown fields and fields that do
  not belong to the action rejected), 5 s read deadline; at most 256 bytes,
  except `appliance-apply` (96 KiB) and `update-install` (32 KiB); the
  response at most 256 KiB;
- two actions with fixed validation: `restart-vast-daemon` (no argument) and
  `reboot` with `delay_s` between 60 and 3600;
- four appliance actions, quick by design (they read and write files under
  `/var/lib/happymining-helper` and start a unit; they never run Docker,
  mount, a backup or dpkg themselves): `appliance-status`,
  `appliance-apply`, `appliance-run-job`, `update-install`. Their switches,
  limits and results: `docs/appliance.md`, section 8.2;
- fixed command lines, absolute paths, argv arrays, no shell:
  `/usr/bin/systemctl restart vastai.service` and
  `/usr/sbin/shutdown -r +M <fixed message>` (M is the delay rounded **up** to
  whole minutes; cancel with `shutdown -c`);
- each action refused unless its switch is set in the root-owned
  `helper.conf` (`appliance-status`, which only reads, needs none); the
  paths of that file and of the commands are compiled in;
- every request, refusal and result is logged to the journal (stderr of the
  unit) or to syslog facility `authpriv` when run by hand.

Root can also run `hm-helper restart-vast-daemon` or
`hm-helper reboot --delay-s N` directly; the same switches apply.

The appliance's heavy work runs in separate oneshot units without an
`[Install]` section, started only by the helper with
`/usr/bin/systemctl start --no-block <unit>`:

| Unit | Runs | Notes |
|---|---|---|
| `happymining-appliance-apply.service` | `hm-helper apply-stored` | No file-system namespace on purpose (the NAS mounts must reach the host); `NoNewPrivileges`, a capability bounding set for the mount helpers, `@system-service @mount`, 3 h limit. |
| `happymining-appliance-job@.service` | `hm-helper run-job %i` (`vectorize_sync`, `backup_run`, `status_refresh`, `plugin_restart-<id>`) | `ProtectSystem=strict`, writable only the helper state and the NAS mount points; lowest I/O priority; 13 h limit. |
| `happymining-update-install.service` | `hm-helper install-staged` | Wide (dpkg writes the system), `KillMode=process` so that a running dpkg is never killed. |
| `happymining-update-guard.timer` / `.service` | `hm-helper update-guard`, 10 minutes after an installation | Same sandbox as the install unit. |

Root-only command-line actions, never reachable over the socket:
`apply-stored`, `run-job <instance>`, `install-staged`, `update-guard` (for
the units), `appliance-status`, `secret-set <name>`, `backup-init`,
`backup-restore --from <file> [--to <dir>]`, `appliance-purge <plugin id>`,
`vectorizer-token`. Every command the helper runs is a fixed argv with an
absolute path (`docs/appliance.md`, section 8.5).

### `happyminingctl appliance` and `backup`

| Command | Does |
|---|---|
| `happyminingctl appliance status [--json]` | asks the helper socket for the appliance state (root or the agent's account) and adds the agent's schedule history |
| `sudo happyminingctl appliance secret set <name>` | reads a secret on standard input and stores it sealed for this machine; only names the local profile refers to |
| `sudo happyminingctl appliance purge <plugin id>` | deletes a removed, stopped plugin's data after the id is typed again |
| `sudo happyminingctl appliance token [vectorizer]` | creates the vectorizer's bearer token if missing and prints it |
| `sudo happyminingctl backup init` | creates the backup key and prints the recovery key once; refuses if a key exists |
| `sudo happyminingctl backup restore --from <archive> [--to <directory>]` | asks for the recovery key and restores into a new directory |

Without root, these say that `sudo` is needed. No secret passes through
`happyminingctl`'s own memory or arguments.

### Sandbox of the agent unit

`NoNewPrivileges=yes`, `CapabilityBoundingSet=` (empty), `ProtectSystem=strict`,
`ProtectHome=yes`, `PrivateTmp=yes`, `ProtectKernelTunables=yes`,
`ProtectKernelModules=yes`, `ProtectKernelLogs=yes`, `ProtectControlGroups=yes`,
`ProtectHostname=yes`, `ProtectProc=invisible`,
`RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`, `RestrictNamespaces=yes`,
`RestrictRealtime=yes`, `RestrictSUIDSGID=yes`, `LockPersonality=yes`,
`MemoryDenyWriteExecute=yes`, `SystemCallFilter=@system-service`,
`SystemCallArchitectures=native`, `ReadWritePaths=/var/lib/happymining`,
`MemoryMax=256M`, `TasksMax=64`, `Restart=on-failure` with `RestartSec=10`,
`StartLimitIntervalSec=300` and `StartLimitBurst=5`.

`ProtectProc=invisible` hides other users' processes in `/proc`, so the agent
could not read renter process lists even by mistake.

### Device access

`nvidia-smi` opens `/dev/nvidiactl` and `/dev/nvidia*`. `PrivateDevices=yes`
would hide them, so it is **not** set, and no device allow-list is active by
default. A stricter drop-in (`DevicePolicy=closed`, `DeviceAllow=char-nvidia*
rw`) is shipped as
`/usr/share/doc/happymining-agent/examples/device-policy.conf`. It is not the
default because a device allow-list is resolved when the unit starts: if the
NVIDIA module loads later, GPU telemetry would stay empty until the agent is
restarted, and this could not be tested on real hardware here.

Under `NoNewPrivileges=yes` the setuid `nvidia-modprobe` cannot create missing
device nodes for the agent. They exist once the driver was used by anything
else (for example `nvidia-persistenced`, which the unit is ordered after).

### Secrets and redaction

- Logs are JSON on stdout (journald). Every record passes through a redaction
  layer that removes `Bearer ...` values, anything starting like a device
  credential (`hmd_...`), pairing codes in any typed form, and the exact
  current token and its secret part. The same layer is applied to `detail` and
  `result` of every acknowledgement, where values of keys named like
  `token`, `secret`, `password`, `authorization`, `pairing_code` are removed
  as well.
- The token is sent only in the `Authorization` header, only to the configured
  base URL, and only if it has the protocol's format.
- The package contains no credential, pairing code or key. A test scans the
  built `.deb` for them.

### Credentials installed by Vast itself

The official Vast host software installs its own host-local files and
credentials when the operator enrolls the machine. Those are Vast's: HappyMining
does not create, manage, rotate or protect them, and cannot. **Anyone with root
access on the machine can read them.** The agent does not read them, with one
exception that is off unless file permissions allow it: the SHA-256 of the Vast
machine identifier file (`vast.machine_id_hint`), which the API treats as
untrusted evidence for an operator, never as proof of identity.

### What this does not protect against

- The owner of a machine has root. Root can stop, modify or remove the agent,
  read its credential and send fabricated telemetry. Software on the machine
  cannot prevent that; the API must treat everything from a device as
  untrusted.
- A compromised HappyMining API can send typed operations. By default that
  yields only read-only results; restart and reboot need the two local
  switches. With the appliance switches on it can also send desired-state
  documents (any catalog plugin, NAS hosts of its choosing, stored secrets
  pointed at other hosts: `docs/threat-model.md`, section 6).
- A compromised agent process can talk to the helper socket. With the
  appliance switches off the helper still only does two things, both
  disabled by default. With them on, it can also hand the helper any
  document that validates against the installed catalog (including a mode
  change that the control plane's rental-protection gate would have
  refused), start the appliance jobs, and offer a release that is properly
  signed and newer. It cannot make the helper run anything else, install an
  unsigned or older package, or open a secret.

## Preflight

`happyminingctl preflight [--json] [--offline] [--requirements FILE]` and the
`run_preflight` operation run the same read-only checks and report
`PASS`, `WARN`, `FAIL` or `SKIP` per check with a remediation text and the
source of the requirement. Exit status: 0 if no check failed (`WARN` included),
1 if at least one check failed, 2 if preflight could not run (usage,
configuration or requirements file error).

**Passing preflight does not guarantee that Vast verifies the machine.** Every
report says so and quotes Vast's own statement.

Thresholds come from `internal/preflight/requirements.json`, embedded in the
binaries. Each threshold has a `source` URL and a `verified` flag. A check whose
threshold is not verified reports `WARN: requirement not verified against Vast
documentation` instead of `PASS` or `FAIL`.

| Threshold | Value | Verified | Source |
|---|---|---|---|
| OS releases | Ubuntu 22.04, 24.04 | yes | https://docs.vast.ai/host/verification-stages |
| CPU architecture | amd64, arm64 (arm64 gives WARN: this package is amd64 only) | yes | same |
| CPU flags | `avx` | yes | same |
| Physical cores per GPU | 2 | yes | same |
| System RAM / total VRAM | 0.95 | yes | same |
| VRAM per GPU | more than 7168 MiB ("More than 7 GB", read as 7 GiB) | yes | same |
| Identical GPU models | required | yes | same |
| Secure Boot | disabled | yes | same |
| Docker storage size | 200 GB | yes | same |
| Docker storage on a dedicated drive | required (checked as "not on the root filesystem") | yes | same |
| Root filesystem free space | 20 GB | yes | same |
| NVIDIA driver minimum | 520.61.05 (derived: Vast asks for CUDA 11.8 or newer; NVIDIA lists this driver for CUDA 11.8 GA) | yes | https://docs.nvidia.com/cuda/archive/12.8.0/cuda-toolkit-release-notes/index.html |
| NVIDIA driver upper bound | none | **no** | not found |
| Docker storage filesystem | xfs | **no** | https://cloud.vast.ai/host/setup/ could not be read |
| Expected Docker package | docker-ce | **no** | same |
| Vast detection paths | `vastai.service`, `/var/lib/vastai_kaalia` | **no** | not stated on the pages read |

Documented requirements that preflight cannot check are listed in one `SKIP`
entry (network speed, forwarded ports, public IPv4, PCIe bandwidth, kernel
patch level, SSH configuration, SSD, reliability, GPU generation).

HappyMining policy checks (not Vast requirements): a snap-packaged Docker and
two coexisting Docker installations are `FAIL`. Preflight reports them and
changes nothing.

Network checks: the HappyMining API (one unauthenticated request; any HTTP
answer over a verified connection counts) and generic outbound HTTPS to the
URLs in `outbound_https_probes` (default: an Ubuntu host). Preflight contacts
no Vast host.

## Protocol interpretation notes

Where `docs/agent-protocol.md` leaves room, the agent does the following. The
API side should check these against its own reading.

1. **Replayed operation id.** The id is never executed again. If the journal
   holds a final outcome, the agent acknowledges again with that recorded
   status (detail prefixed "replayed operation id"), so that an
   acknowledgement lost in transit does not turn a succeeded operation into a
   rejected one. If only the start was recorded (crash or reboot in between),
   it acknowledges `rejected`. A second final acknowledgement is answered with
   409 by the API, which the agent treats as final.
2. **Rejected operations are journaled too**, so an id that was rejected once
   is never executed later.
3. **`completed_at` is sent with every acknowledgement**, including
   `accepted`. `accepted` is only sent before `restart_vast_daemon` and
   `reboot`; the read-only operations send one final acknowledgement.
4. **403 and 404 on a heartbeat** keep the samples and back off instead of
   dropping them ("do not retry" is applied to acknowledgements).
5. **Unknown strings** (CPU model, GPU uuid, name, driver version, filesystem
   type) are sent as `""`; only numbers and `machine_id_hint` become `null`.
6. **Service states** other than the six of the protocol (`reloading`,
   `deactivating`, `maintenance`) are sent as `unknown`.
7. **`cpu.cores`** is the number of logical CPUs. **`util_pct`, `temp_c`,
   `fan_pct`** of a GPU are integers, `power_w` is a float.
8. **`vast.machine_id_hint`** is `sha256:` + SHA-256 of the file content with
   leading and trailing whitespace removed.
9. **`next_interval_s`** is honoured within 15 to 3600 seconds; 0 or a
   negative value keeps the current interval. `heartbeat_interval_s` of the
   enrollment response is not used.
10. **`highest_seq`** is used only to move the local counter forward after
    local state loss. Values above 2^63 are ignored.
11. **`Retry-After`** is read as whole seconds and bounded to one hour.
12. **`GET /api/v1/device/operations`** is implemented in the client but the
    agent loop does not call it: operations arrive in heartbeat responses.
13. At most 32 operations of one response are handled; the rest stays pending.
14. An operation whose `id` is not a UUID cannot be acknowledged (the id is
    part of the URL) and is ignored with a log line. An invalid `nonce` is
    acknowledged `rejected` with an empty nonce.

## Build, test, package

Requirements: Go 1.24, `dpkg-deb`. No network access is needed.

```
cd agent
gofmt -l .                      # must print nothing
go vet ./...
go test ./... -race             # or: make check

scripts/build.sh                # dist/bin/{happymining-agent,happyminingctl,hm-helper,hm-simulator}
scripts/build-deb.sh            # dist/happymining-agent_0.1.0_amd64.deb + .sha256, then scans the package
```

`make check`, `make build` and `make deb` wrap the same commands. `build-deb.sh`
checks the unit files with `systemd-analyze verify` when it is installed and
ends with the package scan (`go test ./packaging/ -run TestDeb`).

Builds are static (`CGO_ENABLED=0`, linux/amd64) and reproducible: `-trimpath`,
`-buildvcs=false`, `-ldflags "-s -w -buildid= -X ...Version=<v>"`,
`SOURCE_DATE_EPOCH` (default 2026-01-01T00:00:00Z), fixed file times and a
single compressor thread in the `.deb`.

`HM_DEB_MAINTAINER` sets the package's Maintainer field. The default is an
explicit placeholder with an `.invalid` address: set it before a release.
`HM_VERSION` overrides the version (default: `internal/version/version.go`).
`HM_RELEASE_KEYS_DIR` is a directory whose `*.pub` files (base64 Ed25519
public keys) are installed as the keys the machine trusts for firmware
updates; without it no key is packaged, the build says so, and machines
with that package refuse every update. The published test key of
`appliance/testdata` is refused. `build-deb.sh` now fails, and removes the
package, when the package scan fails (it used to report success).

The package is not signed. Signing and the repository trust chain are outside
this directory. Firmware releases are signed with `scripts/release-sign.py`
(`docs/operations.md`, "Publishing a firmware release").

### Package content

`/usr/bin/happymining-agent`, `/usr/bin/happyminingctl`,
`/usr/lib/happymining/hm-helper`, every unit of `packaging/systemd/` in
`/lib/systemd/system` (`happymining-agent.service`,
`happymining-firstboot.service`, `happymining-helper.socket`,
`happymining-helper@.service`, `happymining-appliance-apply.service`,
`happymining-appliance-job@.service`, `happymining-update-install.service`,
`happymining-update-guard.service`, `happymining-update-guard.timer`), the
conffiles `/etc/happymining/agent.env`, `/etc/happymining/helper.conf`,
`/etc/update-motd.d/60-happymining`, `/etc/issue.d/happymining.issue`, the
plugin catalog in `/usr/share/happymining/catalog/` (`plugin.json` and
`compose.yaml` of each plugin), the vectorizer's build context in
`/usr/share/happymining/vectorizer/` (sources, `Dockerfile`,
`requirements.lock`, `.dockerignore`, `README.md`), the release keys in
`/usr/share/happymining/release-keys/` (only from `HM_RELEASE_KEYS_DIR`),
and this README plus the device-policy example in
`/usr/share/doc/happymining-agent`.

Maintainer scripts:

- `postinst`: creates the system user and group `happymining` (no login shell,
  no home), creates `/var/lib/happymining` and `spool` with mode 0750 and
  `updates` with 0700, the helper's `/var/lib/happymining-helper` (0700
  root), `/var/lib/happymining-plugins` and `/srv/happymining/nas` (0755
  root), enables the units and, when systemd is running, starts them. It
  does not fail when systemd is absent (chroot, image build). It never starts
  pairing, never touches disks or partitions, never mounts anything and never
  installs or removes a package. It creates `/var/lib/happymining` but never
  touches anything inside it (the agent's account owns it and could have
  planted a symbolic link there that a root `chown` would follow); the agent
  creates `spool` and `updates` itself. It cannot place
  `/var/lib/happymining-helper/packages/current.deb` (dpkg does not say which
  file it installs): on a machine installed from the image the helper adopts
  the installer's copy from `/var/cache/happymining`; after a manual
  installation the first update needs `ALLOW_UPDATE_WITHOUT_ROLLBACK=1`
  (`docs/appliance.md`, section 9).
- `prerm`: stops the agent; on removal also disables the units and stops the
  update guard timer (which would otherwise reinstall the previous package).
  On upgrade the guard stays armed. Docker, the Vast host software, renter
  workloads, the plugins and the NAS mounts are not touched.
- `postrm`: on `purge` removes `/var/lib/happymining`. `remove` keeps it. The
  system user is left in place. Even `purge` keeps the helper's state (with
  the backup key), the plugins' data and `/srv/happymining`.
- Upgrades keep the credential, the spool, the journal, the helper's keys
  and the plugins' data.

Depends: `adduser` only. No dependency on Docker, NVIDIA or Vast packages.
The appliance needs Docker with the Compose plugin (and the NVIDIA container
runtime for GPU plugins) and the CIFS and NFS mount helpers; the package
does not depend on them and does not install them.

Image builders: the package does not create the install identity at install
time. Make sure `/var/lib/happymining/identity` and `credential.json` do not
exist in an image; `happymining-firstboot.service` creates the identity on the
first boot of each machine.

## Simulator

```
dist/bin/hm-simulator --api-url https://api.example.test \
    --machines 3 --codes-file codes.txt --state-dir ./sim-state \
    --gpu-model rtx4090 --gpus 2 --interval 5s --samples 100 --seed 7 \
    --outage-after 10 --outage-for 20 --duplicate-every 5
```

- One pairing code per machine that is not paired yet (`--codes a,b,c` or
  `--codes-file`); state is kept per machine, so a second run needs no code.
- The simulator runs the real agent loop (same client, spool, sequence, backoff
  and operation code) with a synthetic collector. `"synthetic": true` is set by
  the runtime on every sample and cannot be switched off. The API refuses
  synthetic samples in LIVE mode.
- `--outage-after/--outage-for`: requests fail without reaching the server for
  that many samples; the agent buffers, then flushes.
- `--duplicate-every N`: the response of every Nth heartbeat is lost after the
  server processed it, so the agent resends samples the server already has.
- `--seed` makes the telemetry reproducible. GPU figures in the simulator are
  plausible values, not measurements or vendor specifications.
- From Go tests: `sim.Run(ctx, sim.Options{...})`.

Appliance (on by default): `--appliance=false` makes the simulated agents
send no appliance object, as an agent without the feature.
`--appliance-capabilities` (default `plugins,nas,backup,update,docker`)
sets what the synthetic helper reports; `--appliance-catalog` points at a
catalog directory (default: the repository's `appliance/catalog` next to
`dist/`, else the installed one). Each
simulated machine has its own sealing key, validates the documents it
receives with the real validator and reports the plugins running as the
plan says. Nothing is started, mounted or installed, every detail says so,
and it never claims to have installed a firmware release.

`internal/testapi` is an in-memory fake of the device API used by the tests;
`go run ./internal/testapi/cmd/hm-fakeapi` serves it on a loopback port for
local end-to-end runs. It is not the real API and is not packaged.

A passing simulator run proves the software paths. It proves nothing about
real hardware.

## Not verified here

This code was built and tested in a sandbox without NVIDIA hardware, without a
running systemd and without a Docker daemon. On 2026-10-02, at the
uncommitted state with the appliance, `go test ./... -count=1` exited 0: 26
packages ok, 495 top-level tests passed (784 with subtests), 1 skipped; the
engineers also ran the suite with `-race`. The following has **not** been run and must
be validated on a real machine before a pilot:

- **Real NVIDIA hardware**: `nvidia-smi` output of real drivers and GPU models
  (parsing is tested against written fixtures only), access to `/dev/nvidia*`
  from the sandboxed unit, behaviour of `nvidia-smi` under
  `MemoryDenyWriteExecute=yes`, `SystemCallFilter=@system-service`,
  `ProtectProc=invisible` and `NoNewPrivileges=yes`.
- **Real systemd behaviour**: the units were checked with
  `systemd-analyze verify` only (see the build output); they were never
  started. Socket activation of the helper, `SO_PEERCRED` on the
  systemd-passed socket, `StateDirectory=` ownership, the restart limits,
  `systemctl restart` and `shutdown -r +M` issued from the helper's sandbox,
  and the optional device-policy drop-in are unverified.
- **Package installation**: the `.deb` was built and inspected
  (`dpkg-deb --info/--contents`) and its maintainer scripts were run against a
  temporary root with stubbed `adduser`/`systemctl`. It was not installed with
  `dpkg -i`. `lintian` was not run (not installed).
- **Real Vast daemon paths and names**: the unit name `vastai.service`, the
  directory `/var/lib/vastai_kaalia` and the machine identifier file are
  assumptions. If the unit name differs, `restart_vast_daemon` fails with the
  error from `systemctl`, the `vastai` service state reads `not-installed`, and
  `vast.daemon_installed` may be wrong.
- **The real HappyMining API**: the Go client tests run against
  `internal/testapi`, a fake written from the same protocol document. The
  built binaries are additionally run against the real API, on real
  PostgreSQL, by `tests/api/test_end_to_end_binaries.py` (pairing, heartbeats,
  an API outage with buffering and recovery, revocation). **That test has
  not run against the binaries with the appliance** (the test database was
  unavailable). No test runs the agent against a deployed API over the
  internet.
- **The appliance, all of it**: the helper's appliance actions and the five
  new units never ran under systemd; the apply unit's capability set was
  never tried with `mount.cifs` or `mount.nfs`; no Docker command, mount,
  `umount` or `dpkg` was ever executed (each was asserted on as an argv
  against an injected fake); no plugin image was pulled and the vectorizer
  image was never built; the NVIDIA container runtime, a NAS, an S3 provider
  and a real release were never used; the update guard and the rollback
  never ran against a real `dpkg`. The new maintainer scripts never ran on a
  real system.
- **Preflight values**: read through a web-fetch tool on 2026-10-02 (see the
  table above); the Vast host setup guide itself could not be read.
- Terminal handling of `happyminingctl pair` (echo off, Ctrl-C restore) was not
  exercised on a real TTY.
