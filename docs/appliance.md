# Appliance: modes, plugins, NAS, backup, updates

What turns a HappyMining machine from "a GPU host rented on Vast" into an AI
server its owner can also use: run local AI software, index the company's
files, keep an encrypted copy elsewhere, and receive firmware updates.

This document is the contract between the three parts that implement it:

- the control plane (`api/happymining/…`): stores what each machine should
  do, decides who may change it, publishes releases;
- the agent and its privileged helper (`agent/…`): make the machine match;
- the vectorizer and the plugin catalog (`appliance/…`).

Anything not written here is not part of the contract.

**Status (2026-10-02).** All three parts are built and not committed. The
machine side was tested with injected fakes for every command (Docker,
mount, dpkg, systemctl): it has never run on a real machine, under systemd,
with Docker, a NAS or `dpkg -i`. The control-plane tests that need
PostgreSQL have **not run against the final code** (the test database was
unavailable). What was run, and the results: `IMPLEMENTATION_STATUS.md`.
What is not verified: `docs/limitations.md`.

Points the first version of this contract left open were settled while it
was implemented. They are marked **Decision (implementation)** below. Open
questions are listed in section 14.

## 1. Principles

1. **The cloud names things; the machine holds the definitions.** A plugin is
   an entry in the catalog installed on the machine with the firmware
   (`/usr/share/happymining/catalog/`). The cloud can ask for plugin `ollama`
   with typed settings. It cannot send a Compose file, an image name, a
   command or a path to execute. A new plugin arrives with a firmware update.
2. **Secrets are sealed for one machine.** A NAS password or an API key is
   encrypted in the browser with the machine's public key. The control plane
   stores and forwards the sealed value and has no key to open it.
3. **Nothing here may hurt a renter.** In `vast` mode no plugin runs. Leaving
   `vast` mode goes through the rental-protection gate. Zero GPU utilisation
   proves nothing; unlisting is not permission to end rentals; nothing in this
   feature stops Vast's daemon, kills a container it did not start, or deletes
   a renter's storage.
4. **The machine keeps working without the cloud.** Plugins, the index, the
   schedules and backups run locally. An API outage changes nothing on the
   machine.
5. **The owner decides whether HappyMining may manage the machine.** See
   "Who may do what". And since the owner has root, the real switch is on the
   machine: `control: local` (section 6) and the helper switches (section 8).
6. **AI traffic does not go through the control plane.** Plugins are reached
   on the owner's network. The cloud panel configures and shows state.
7. **Backups are readable by the customer only.** The backup key is generated
   on the machine, shown once there, and never sent anywhere.

## 2. Modes

| Mode | Meaning on the machine |
|---|---|
| `vast` | The machine is reserved for Vast hosting. **No plugin runs.** Vast's own software is not touched. This is the default and what existed before. |
| `private_ai` | The owner uses the machine. Every enabled plugin runs. |
| `vectorize` | The machine only indexes the NAS. Only plugins whose catalog entry lists `vectorize` in `modes` run (the vector database, the embedding runtime, the vectorizer). Answers come from a cloud AI with the customer's own key, or from search alone. |

Changing mode is a change to the desired-state document (section 4).

- **To `vast`**: always accepted. Plugins stop. HappyMining does not list the
  machine on Vast: listing and pricing stay an operator action in Vast's
  console or CLI.
- **From `vast`** to another mode, when the machine is bound to a provider
  machine: the rental-protection gate (`services/maintenance.py`) is
  evaluated with the action `leave_vast_mode`. Unknown state blocks. In LIVE
  today the gate always blocks, because Vast does not expose the rental state:
  the operator first confirms in Vast's console that the machine is unlisted
  and empty, then removes the provider binding, and only then can the mode
  change. A blocked attempt answers `409 maintenance_blocked` and is audited.
- **From `vast`** when the machine has no provider binding: accepted.
- **On the machine**, independently of the cloud: the helper refuses to start
  a plugin whose catalog entry says `gpu: true` while any container that
  HappyMining did not start is running (`ALLOW_FOREIGN_CONTAINERS=false`, the
  default). Reported as plugin state `blocked`. The absence of foreign
  containers is not treated as proof of anything else. A running container
  counts as HappyMining's when it carries the label `eu.happymining.plugin`;
  a container can carry any label its creator chose. When `docker ps` cannot
  be read, GPU plugins are blocked too. A plugin blocked by this guard is
  started by a later status refresh once no foreign container runs.
- The gate for leaving `vast` is evaluated by the control plane only. The
  helper applies any well-formed document it is handed; on the machine, the
  switches (section 8) and the GPU guard above are what protect a renter.
- **Decision (implementation):** in `vast` mode the NAS entries of the
  document are still mounted (with `ALLOW_NAS`), after every plugin has been
  stopped, so that a backup can still reach its destination. No plugin runs.

Mode changes are never scheduled (section 4.6): a timer cannot evaluate the
gate.

## 3. Who may do what

People sign in to the cloud panel. Three kinds of people matter here.

**HappyMining staff** (`admin`; `auditor` reads). **The owner's
organisation**: users with role `owner`, each with an organisation role:

| Organisation role | May |
|---|---|
| `org_admin` | Everything for the organisation's machines: mode, plugins, NAS, vectorization, backup, schedules, updates, secrets, run jobs; manage the organisation's users; grant and revoke remote access; see earnings and settlements. |
| `org_operator` | Enable, disable and configure plugins, run jobs, edit schedules, see state. Not: mode, NAS, backup destination, secrets, update policy, users, remote access, money. |
| `org_viewer` | See machines and appliance state. Change nothing. No money. |

Existing owner users become `org_admin`. An organisation always keeps at
least one active `org_admin`.

**Remote management by HappyMining.** Each machine has
`management`: `company` or `customer`.

- `company`: HappyMining operates the machine (the Vast fleet). Staff may
  read and change the appliance configuration and request operations.
- `customer`: staff keep what they need to monitor the fleet (connection
  state, hardware, telemetry, agent version, operation history). They cannot
  read the appliance configuration, change it, or request operations,
  **unless** an `org_admin` has issued a remote-access grant for that machine:
  - level `view` (read the appliance state) or `manage` (read and change,
    request operations);
  - optional expiry (1 hour to 90 days; the upper bound is
    `HM_REMOTE_ACCESS_MAX_HOURS`, default 2160) or open-ended;
  - revocable at any time by an `org_admin`; staff may also give a grant up;
  - issuing, using (each change) and revoking are audited.
- `management` is chosen by staff when the machine is created. Afterwards:
  `company` → `customer` by staff or an `org_admin`; `customer` → `company`
  only by an `org_admin`. Staff cannot give themselves access.

An integration API client (Mole Hash) follows the same rule as staff when it
is fleet-wide, and the rule of its owner when it is owner-scoped; it gets a
read-only scope `appliance:read` and nothing that changes the appliance.

What else follows from these rules in the code (`services/access.py`,
`services/remote_access.py`):

- On a `customer` machine without a grant, staff and fleet-wide clients get
  `403 remote_access_required` on the appliance routes, when they request or
  cancel an operation (any type), and when they create a new pairing code for
  a machine that was paired before or transfer its ownership. Monitoring
  (connection state, telemetry, operation history) stays visible.
- Losing access takes effect at delivery: an operation requested by staff or
  a fleet-wide client that the machine has not received yet is cancelled
  when the grant expires or is revoked, when the machine goes to `customer`,
  or when a `customer` machine changes owner (an ownership transfer closes
  the previous owner's grants). Requests by the owner's own people are
  cancelled the same way when the machine changes owner or the person loses
  the role.
- A grant counts only for the owner that issued it.
- Earnings, settlements and beneficiary details are visible to `org_admin`
  only, within the organisation.
- **Decision (implementation):** `appliance_run_job` and `install_update`
  (section 6.5) can be requested only through the appliance routes of
  section 12, which check what the general operation routes do not (that the
  plugin is configured, that the release can be installed). The general
  operation routes, their dashboard form and the integration API refuse them.

A device still cannot choose its owner, its mode or its permissions: what it
reports is displayed, never used for authorisation.

## 4. The desired-state document

One JSON document per machine, with a revision that increases by one at every
accepted change. At most 64 KiB serialised.

```json
{
  "schema": 1,
  "revision": 12,
  "mode": "private_ai",
  "plugins": [
    {"id": "ollama", "enabled": true, "settings": {"models": ["hermes3:8b"]}},
    {"id": "qdrant", "enabled": true, "settings": {}},
    {"id": "vectorizer", "enabled": true, "settings": {}}
  ],
  "nas": [
    {"id": "docs", "kind": "smb", "host": "nas.lan", "share": "documents", "subpath": "",
     "username": "indexer", "domain": "", "secret": "nas.docs.password", "access": "read"},
    {"id": "bk", "kind": "nfs", "host": "192.168.1.20", "export": "/volume1/backup", "access": "write"}
  ],
  "vectorizer": {
    "sources": ["docs"],
    "extensions": ["pdf", "docx", "pptx", "xlsx", "html", "md", "txt"],
    "exclude": ["#recycle", "private/hr"],
    "max_file_mib": 64,
    "embedding_model": "bge-m3",
    "ocr": false,
    "answer": {"provider": "openai_compatible", "base_url": "https://api.openai.com/v1",
               "model": "gpt-4.1-mini", "secret": "ai.answer.api_key"}
  },
  "backup": {
    "enabled": true,
    "destination": {"kind": "nas", "nas_id": "bk", "subpath": "happymining"},
    "include_models": false,
    "keep": 7
  },
  "schedules": [
    {"id": "nightly-sync", "job": "vectorize_sync", "every": "daily", "hour": 2, "minute": 30, "enabled": true},
    {"id": "weekly-backup", "job": "backup_run", "every": "weekly", "weekday": 6, "hour": 3, "minute": 0, "enabled": true}
  ],
  "update": {"channel": "stable", "policy": "auto", "window": {"start_hour": 2, "end_hour": 5}},
  "secrets": {"nas.docs.password": "hmseal1.…", "ai.answer.api_key": "hmseal1.…"}
}
```

Unknown keys anywhere in the document are an error, on the server and on the
machine. The machine validates everything again and trusts none of it.

Both validators (Python in the control plane, Go in the helper) must accept
every file in `appliance/testdata/documents/valid/` and refuse every file in
`appliance/testdata/documents/invalid/`, against the fixture catalog in
`appliance/testdata/catalog/`. Each file is `{"why": "…", "document": {…}}`.

Required and optional keys:

- top level: `schema` (1), `revision` (integer ≥ 1) and `mode` are required;
  `plugins`, `nas` and `schedules` default to empty lists, `secrets` to an
  empty object; `vectorizer`, `backup` and `update` may be absent;
- plugin entry: `id`, `enabled`; `settings` defaults to `{}`;
- `smb` entry: `id`, `kind`, `host`, `share`, `username`, `access`; `subpath`
  and `domain` default to `""`; `secret` exactly when `username` is not empty;
- `nfs` entry: `id`, `kind`, `host`, `export`, `access`; `subpath` optional;
- `vectorizer`: all of `sources`, `extensions`, `exclude`, `max_file_mib`,
  `embedding_model`, `ocr`, `answer`;
- `backup`: all of `enabled`, `destination`, `include_models`, `keep`;
- schedule: `id`, `job`, `every`, `minute`, `enabled`, plus what `every` and
  `job` require;
- `update`: `channel` and `policy`; `window` is required with `auto` and
  optional with `manual`.

Integers are JSON integers: `"12"`, `12.5` and `true` are not.

### 4.1 Common rules

- Ids (plugin, NAS, schedule): `^[a-z][a-z0-9-]{0,30}$`. Unique in their list.
- `mode`: `vast`, `private_ai` or `vectorize`.
- No string contains a control character (U+0000–U+001F, U+007F).

### 4.2 `plugins` (at most 32)

- `id` must exist in the catalog. `enabled` is a boolean.
- `settings`: an object validated against the catalog entry's `settings`
  schema (section 7). A missing setting takes its default. An unknown setting
  is an error.
- A plugin listed in another enabled plugin's `requires` must be enabled.
- A plugin absent from the list is not installed. Removing a plugin from the
  list stops it and leaves its data on the machine; data is deleted only
  locally (`happyminingctl appliance purge <id>`), never remotely.
- Whether an enabled plugin actually runs depends on the mode (section 2).

### 4.3 `nas` (at most 8)

| Field | Rule |
|---|---|
| `kind` | `smb` or `nfs` |
| `host` | host name or IPv4 address: `^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$` |
| `share` (smb) | `^[A-Za-z0-9][A-Za-z0-9 ._$-]{0,79}$`, not ending with a space |
| `export` (nfs) | absolute path, `^/[A-Za-z0-9._/-]{0,254}$`, no `..` segment |
| `subpath` | optional relative path inside the share: at most 512 characters, segments separated by `/`, no empty, `.` or `..` segment, no leading or trailing `/`, **no `,` and no `\`**. `""` means the root. The subpath becomes part of the mount source, and `mount.cifs` hands it to the kernel as `prefixpath=` without escaping: a comma would add mount options (found by the independent review; refused by both validators and again by the helper before it mounts). A backslash is an SMB path separator |
| `username` (smb) | 0 to 64 characters, none of `,` `=` `\` `/` `:` and no white space. Empty means guest access, and then `secret` must be absent |
| `domain` (smb) | optional, `^[A-Za-z0-9._-]{0,64}$` |
| `secret` (smb) | name of the sealed password: exactly `nas.<id>.password` |
| `access` | `read`: mounted read-only, usable as a vectorizer source. `write`: mounted read-write, usable as a backup destination only |

`nfs` entries have no `username`, `domain`, `secret` or `share`; `smb` entries
have no `export`.

On the machine a NAS entry is mounted at `/srv/happymining/nas/<id>` with
fixed options: `ro` or `rw`, `nosuid`, `nodev`, `noexec`; SMB credentials in a
root-only file; nothing in the document can add a mount option. The exact
command lines are in section 8.5. The helper never unmounts anything it did
not mount: a mount point where something else is mounted is reported as
`error` and left alone. A changed entry (including a new password) is
unmounted and mounted again. An SMB password longer than 4000 bytes or
containing a line break or NUL cannot be written to a credentials file and
is refused.

### 4.4 `vectorizer` (optional object)

| Field | Rule |
|---|---|
| `sources` | 1 to 8 ids of `nas` entries with `access: read` |
| `extensions` | 1 to 40 of `^[a-z0-9]{1,8}$`; files with other extensions are skipped |
| `exclude` | 0 to 32 relative paths or directory names (same rule as `subpath` except that `,` and `\` are allowed, at most 200 characters); a file is skipped when any path segment sequence matches |
| `max_file_mib` | integer 1 to 2048 |
| `embedding_model` | Ollama model reference: `^[a-z0-9][a-z0-9._/-]{0,80}(:[A-Za-z0-9._-]{1,40})?$` |
| `ocr` | boolean: run OCR on scanned pages and images (slow) |
| `answer.provider` | `none` (search only), `local` (an Ollama model on this machine), `openai_compatible`, `anthropic` |
| `answer.model` | 1 to 100 characters of `[A-Za-z0-9._:/-]`; absent for `none` |
| `answer.base_url` | `openai_compatible`: required, `https://host[:port][/path]`, at most 200 characters, no user info, query or fragment. `anthropic`: optional, same rule, default `https://api.anthropic.com`. Others: absent |
| `answer.secret` | `openai_compatible` and `anthropic`: exactly `ai.answer.api_key`. Others: absent |

The plugin `vectorizer` may be enabled only when this object exists.

With a cloud `answer.provider`, each question and the passages retrieved for
it are sent to that provider, with the customer's key, from the customer's
machine. The panel says so next to the setting.

### 4.5 `backup` (optional object)

| Field | Rule |
|---|---|
| `enabled` | boolean |
| `destination.kind` | `nas` or `s3` |
| `nas` destination | `nas_id`: id of a `nas` entry with `access: write`; `subpath` as in 4.3, except that `,` and `\` are allowed (this subpath is a directory inside the mounted share, never part of a mount) |
| `s3` destination | `endpoint`: `https://host[:port]`; `region`: `^[a-z0-9-]{1,40}$`; `bucket`: `^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`; `prefix`: `^[A-Za-z0-9._/-]{0,200}$`, no `..`; `access_key_id`: `^[A-Za-z0-9]{4,128}$`; `secret`: exactly `backup.s3.secret_key` |
| `include_models` | boolean; model files are large and can be downloaded again |
| `keep` | integer 1 to 365: archives kept at the destination |

### 4.6 `schedules` (at most 16)

| Field | Rule |
|---|---|
| `job` | `vectorize_sync`, `backup_run`, `update_check`, `plugin_restart` |
| `plugin` | required for `plugin_restart` (an id in `plugins`), absent otherwise |
| `every` | `hourly`, `daily`, `weekly` |
| `minute` | 0–59 |
| `hour` | 0–23; required for `daily` and `weekly`, absent for `hourly` |
| `weekday` | 0 (Monday) – 6; required for `weekly`, absent otherwise |
| `enabled` | boolean |

Times are the machine's local time. A run missed while the machine was off is
not caught up. A job that is still running is not started again. A schedule
may name a job whose feature is not configured (a `vectorize_sync` without a
vectorizer): the run is recorded as `skipped`.

How the agent runs them (`agent/internal/agent/schedules.go`). **Decision
(implementation)** for each point:

- The agent learns the schedules from the helper's status (the document in
  force, cloud or local). The next run of a new or changed schedule is
  computed from that moment. A run that falls while the agent is not running
  is not caught up.
- A run that is due but that the agent reaches more than 15 minutes late
  (machine suspended, clock jump) is not started; a warning is logged and the
  next run is computed.
- `update_check` runs in the agent itself, one at a time. The other jobs are
  started through the helper (`appliance-run-job`), which starts the oneshot
  unit `happymining-appliance-job@<job>.service`; systemd does not start a
  unit again while it runs.
- `last_status` `ok` means **the job was started**, not that it succeeded:
  its outcome is in the reported state (vectorizer, backup, update). A start
  request for a job that is already running is also recorded `ok`, although
  nothing new starts. `skipped`: the helper answered `disabled` or `busy`, or
  the update capability is off. `failed`: the helper was unreachable or
  refused for another reason.
- Therefore a `vectorize_sync` or `plugin_restart` whose feature is not
  configured, with the switch on, is recorded `ok`, not `skipped` as written
  above: the helper starts the unit, and the unit records `skipped` (or a
  failure) in its own `state.json`, which no report carries (section 14).
- `last_run_at` and `last_status` survive a restart
  (`<agent state dir>/schedules.json`); `next_run_at` is computed again.

### 4.7 `update` (optional object; absent means `channel: none`)

`channel`: `stable`, `beta` or `none`. `policy`: `manual` or `auto`.
`window`: `start_hour` and `end_hour` (0–23, different; the window may cross
midnight): with `auto`, an update installs only inside it.

### 4.8 `secrets`

An object of name → sealed value (section 5). At most 32. Names are exactly
those the other sections refer to:

- `nas.<nas id>.password`
- `ai.answer.api_key`
- `backup.s3.secret_key`
- `plugin.<plugin id>.<key>` for each entry of the catalog's `secrets` list

A reference to a name that is not in `secrets` is an error, and so is a name
nothing refers to (the control plane removes a secret when its last reference
goes).

## 5. Sealed secrets

Reference implementation: `api/happymining/sealing.py`. Test vectors:
`appliance/testdata/seal-vectors.json`. The Go and JavaScript implementations
must pass them.

```
public key  = "hmk1." + base64url_nopad( uncompressed P-256 point, 65 bytes )
blob        = "hmseal1." + base64url_nopad( ephemeral_public(65) || AES-256-GCM ciphertext || tag(16) )
key         = HKDF-SHA256( ikm  = ECDH(ephemeral_private, machine_public)   (32-byte x coordinate),
                           salt = ephemeral_public(65) || machine_public(65),
                           info = "happymining-seal-v1", length = 32 )
nonce       = 12 zero bytes (each key is used once)
AAD         = the secret's name, UTF-8
plaintext   = 1 to 4096 bytes
names       = ^[a-z][a-z0-9_.-]{0,62}$
```

- The machine's key pair is generated by the root helper
  (`/var/lib/happymining-helper/seal.key`, 0600 root, created at the first
  status request if missing). The private key never leaves that file. The
  public key is reported in the heartbeat. The control plane audits every
  change of a machine's public key (`appliance.seal_key`): a new key is also
  what a stolen device credential would report to receive future secrets.
- A secret is opened only when the file that needs it is written (an env
  file, a CIFS credentials file, the S3 client of a backup run); the
  plaintext buffers are wiped afterwards. A secret never goes into an argv,
  a log line, the audit, `state.json` or an error message (tested with fake
  commands that echo every argument).
- The name is authenticated: a value sealed as `nas.docs.password` does not
  open as anything else.
- The control plane accepts a secret only in sealed form. It checks the shape
  and stores it. It cannot check the content.
- If the machine's key changes (reinstall), old sealed values no longer open;
  the machine reports them and the panel asks for them again.
- Limit of the scheme: the page that seals is served by the control plane. It
  protects against a leak of the database, logs and backups, and against
  staff reading stored values. It does not protect against a control plane
  that is actively modified to serve a different page. See
  `docs/threat-model.md`.
- Second limit: the seal binds a value to its **name**, not to the host or
  URL it is used with. **Decision (implementation, after the review):** the
  control plane therefore does not carry a stored secret over to a new
  destination. Changing what a secret is bound to — a NAS entry's `kind`,
  `host`, `share`, `username` or `domain`; the answer `provider` or
  `base_url`; an S3 `endpoint` or `access_key_id` — is refused (`400`)
  unless the request carries the secret again, sealed. Changes that keep
  the destination (another subpath of the same share, another model,
  another bucket prefix) keep it. This stops an `org_admin` or staff with
  `manage` access from sending a customer's stored password or API key to a
  host of their choice through the API or the panel. It does not stop a
  control plane that is itself compromised: such a control plane could also
  hand the machine a document directly. The machine applies what it is
  given.

## 6. Agent ⇄ API

Additions to `docs/agent-protocol.md`. An agent that does not send the
`appliance` object gets none of this back; nothing changes for agent 0.1.0.

"Agent 0.1.0" here means the agent released before this feature. The agent
built from this tree still reports version `0.1.0` (`agent/internal/version`
was not bumped); a release of it must carry a new version number, or the
update offers of section 6.6 cannot tell the two apart. The packaged agent
always has a helper client and therefore always sends the object; only a
build without a helper (tests, the simulator with `--appliance=false`) sends
none.

### 6.1 Heartbeat request: `appliance` (optional object)

```json
{
  "schema": 1,
  "control": "cloud",
  "applied_revision": 12,
  "apply_status": "applied",
  "apply_detail": "",
  "mode": "private_ai",
  "seal_public_key": "hmk1.…",
  "capabilities": {"plugins": true, "nas": true, "backup": true, "update": true, "docker": true},
  "catalog": [{"id": "ollama", "version": "1"}],
  "plugins": [{"id": "ollama", "state": "running", "detail": "", "version": "1", "ports": [11434]}],
  "nas": [{"id": "docs", "state": "mounted", "detail": ""}],
  "secrets": [{"name": "nas.docs.password", "state": "ok"}],
  "vectorizer": {"state": "idle", "last_run_at": "2026-10-02T02:30:00Z", "last_ok_at": "2026-10-02T02:41:10Z",
                 "files_indexed": 1820, "files_failed": 3, "files_skipped": 12, "chunks": 40211, "detail": ""},
  "backup": {"state": "ok", "key_present": true, "key_id": "9f2c1a7b", "last_ok_at": "…", "last_size_bytes": 123456, "detail": ""},
  "update": {"current_version": "0.2.0", "state": "idle", "target_version": "", "detail": ""},
  "schedules": [{"id": "nightly-sync", "last_run_at": "…", "last_status": "ok", "next_run_at": "…"}]
}
```

| Field | Values |
|---|---|
| `control` | `cloud`, or `local` when the machine follows its own profile file |
| `applied_revision` | the last cloud revision the machine finished processing; 0 if none |
| `apply_status` | `applied`, `partial` (something failed, see the items), `rejected` (document refused, nothing changed), `disabled` (helper switches off), `pending` |
| plugin `state` | `running`, `starting`, `stopped`, `blocked` (mode or GPU guard), `error`, `not_in_catalog` |
| nas `state` | `mounted`, `unmounted`, `error` |
| secret `state` | `ok`, `unreadable` (does not open with this machine's key), `missing` |
| vectorizer `state` | `disabled`, `idle`, `running`, `error` |
| backup `state` | `disabled`, `no_key`, `never`, `running`, `ok`, `error` |
| update `state` | `idle`, `downloading`, `installing`, `installed`, `rolled_back`, `error` |
| schedule `last_status` | `ok`, `failed`, `skipped`, `never` |

Bounds: lists at most 32 entries, strings at most 128 characters, `detail`
at most 500. Details are redacted by the agent and again by the API. The
object never contains a secret, a NAS path listing, a file name from the NAS
or any text of a document.

Where the values come from: the helper's `appliance-status` (section 8.2)
gives everything except `schedules`, which the agent adds from its own
schedule history, and `update`, which the agent overlays while it downloads
a release. The encoded object is at most 64 KiB: past that the agent drops
the plugin and NAS details first, then sends a minimal object.

**Decision (implementation): the helper does not answer.** When the helper
is unreachable, refuses, or answers something that is not the expected
object, the agent sends a minimal object: `control: "unknown"`,
`mode: "unknown"`, `apply_status: "disabled"`, the reason in
`apply_detail`, every capability false, vectorizer and backup `disabled`,
update `idle` with the agent's version. The control plane stores
`control` as `cloud`, `local` or `unknown` (anything else becomes `unknown`)
and any unlisted `mode` as `unknown` (`sanitise_report` in
`services/appliance.py`). **Decision (implementation):** the document is sent
only to a machine that reports `control: cloud`; under `unknown` it waits,
since the machine could not apply it. Only `local` refuses configuration
changes.

The control plane keeps only the keys and values listed above, bounds
every string, replaces an unlisted state by `unknown`, and uses none of it
for authorisation.

### 6.2 Heartbeat response: `appliance`

Present only when the request carried an `appliance` object and the cloud
revision is at least 1:

```json
{"appliance": {"revision": 12, "document": { … section 4 … }}}
```

`document` is included when the request's `applied_revision` differs from
`revision`, and omitted otherwise. When `control` is `local` the document is
never sent.

The agent checks only the document's size (64 KiB), that it is a JSON object
and that its `revision` is the response's. It hands a revision to the helper
only while the helper reports `control: "cloud"`, and once per agent run. A
revision the helper refused as `invalid` or `locally_controlled` is not
offered again in that run; after any other failure (helper unreachable,
`failed`) it is offered again after 1 minute, doubling up to 30 minutes.

### 6.3 Applying

The agent hands the document to the helper, which validates it against the
installed catalog, opens the secrets, mounts the NAS entries, stops what must
not run, starts what must, writes the vectorizer configuration and installs
the schedules. Applying is idempotent and is repeated at agent start. The
agent then reports `applied_revision` with the outcome. A document that fails
validation is `rejected` as a whole and changes nothing.

How it is done (**Decision (implementation)**, `agent/internal/applier`):

1. `appliance-apply` (quick, over the socket): validate against the
   installed catalog; refuse with `locally_controlled` under `control: local`
   or when the local profile exists but cannot be used; a document that does
   not validate is recorded `rejected` for its revision and changes nothing.
   The same revision already applied in the same boot, with the same
   switches, answers OK at once.
   Otherwise the document is stored in `applied.json`, the status becomes
   `pending` and `happymining-appliance-apply.service` is started. With
   `ALLOW_PLUGINS` and `ALLOW_NAS` both off the document is stored, nothing
   is applied, and the status is `disabled`.
2. `hm-helper apply-stored` (the apply unit, under the appliance lock): in
   this order, each item recording its result; a failing item does not stop
   the others (`partial`):
   1. mode `vast`: every plugin is stopped first — also with `ALLOW_PLUGINS`
      off, for plugins HappyMining started earlier: stopping needs no switch,
      starting does (**decision after the review**; an apply then runs even
      with both switches off);
   2. NAS (`ALLOW_NAS`): the vectorizer is stopped before the first mount
      change; entries are mounted, changed entries remounted, removed ones
      unmounted (only what HappyMining mounted);
   3. the Docker network `hm-appliance` is created if missing;
   4. plugins (`ALLOW_PLUGINS`) in plan order (requirements first): those
      that must not run are stopped (dependents first); for each that must,
      the guards of section 7, the env file, the vectorizer configuration,
      a build if the image is built on the machine and missing,
      `compose up -d`, a restart of the vectorizer when its configuration
      changed, and the `post_start` commands (each tried 3 times, 10 s and
      30 s apart);
   5. `applied_revision`, `apply_status` and a bounded `apply_detail` (no
      secret, no NAS path listing).
   If a newer document arrived meanwhile it is applied in turn (at most 5
   rounds).
3. "Repeated at agent start" is implemented as: each status request starts
   the apply unit again when the document in force, the helper switches or
   the boot id changed since the last apply, or when an apply has been
   `pending` for more than 10 minutes. A reboot therefore leads to a new
   apply (mounts and containers may be gone); an agent restart alone does
   not.
4. The plugin states the quick status reports come from `state.json`. When
   they are older than 45 seconds the status starts the job
   `status_refresh` (`docker compose ps` of each plugin), at most every 30
   seconds: reported plugin states lag about one heartbeat.

### 6.4 Local profile

`/etc/happymining/appliance.json`, root-owned, not writable by group or
others, at most 64 KiB, no secrets:

```json
{"schema": 1, "control": "local", "document": { … section 4 without "revision" and "secrets" … }}
```

- File absent: `control` is `cloud`.
- `control: "local"`: the file's document is what the machine runs. Cloud
  documents are ignored and the control plane refuses changes with
  `409 locally_controlled`. Secrets are entered on the machine
  (`sudo happyminingctl appliance secret set <name>`, read from standard
  input).
- `control: "cloud"` with a `document`: a start-up profile, used until the
  first cloud document (revision ≥ 1) arrives.

This file is how a machine is configured beforehand (it can be placed by the
installer seed) and how an owner takes the machine out of remote control.

- **Decision (implementation):** a profile file that exists but cannot be
  used (wrong owner or mode, too large, invalid against the installed
  catalog) counts as `control: local`: nothing is applied and cloud
  documents are refused until it is fixed or removed. It may have been
  written precisely to take the machine out of remote control.
- `secret set` accepts only names the profile's document refers to, reads at
  most 4096 bytes (one trailing line end removed), seals the value for the
  machine's own key into `/var/lib/happymining-helper/local-secrets.json`
  and starts an apply. These secrets are used only while the profile's
  document is in force.
- The installer seed does not place a profile today; the file is written by
  hand.

### 6.5 Operations

Two typed operations join the list in `docs/agent-protocol.md`:

| type | params | Notes |
|---|---|---|
| `appliance_run_job` | `{"job": "vectorize_sync" \| "backup_run" \| "update_check" \| "plugin_restart", "plugin": "<id>"}` (`plugin` only for `plugin_restart`) | Starts the job and acknowledges `succeeded` once it is started; progress is in the reported state. |
| `install_update` | `{"version": "0.2.0"}` | Downloads, verifies and installs that release (section 9). |

Neither is disruptive for renters: they touch only HappyMining's own
containers and package. Both need the matching helper switch.

As built:

- Both are enabled by default in the agent's own allowlist: the helper
  switches are the gate. `vectorize_sync` and `plugin_restart` need
  `ALLOW_PLUGINS`, `backup_run` needs `ALLOW_BACKUP`, `update_check` and
  `install_update` need `ALLOW_UPDATE` (reported as the `update`
  capability).
- Parameters are validated identically on both sides: `job` from the list,
  `plugin` (a plugin id) with `plugin_restart` and with nothing else;
  `version` `MAJOR.MINOR.PATCH` and nothing else.
- `appliance_run_job` is acknowledged once, `succeeded` when the job was
  started (or `failed` when the helper refused). `update_check` is started
  in the agent.
- `install_update` is acknowledged `accepted` at once; download, checks and
  hand-off to the helper run in the background, and the final `succeeded`
  means the helper verified and staged the package and started its
  installation unit. Whether `dpkg` then succeeded, and whether the guard
  kept the release, is in the reported `update` state, not in the operation.
- The control plane queues `install_update` only for a `ready` release that
  is newer than the agent version the machine last reported, installable
  from it (`min_upgrade_from`) and offered on the machine's channel.
  Withdrawing a release cancels its `install_update` operations that no
  machine has received yet.

### 6.6 Updates for devices

`GET /api/v1/device/update` (device credential):

```json
{"channel": "stable", "policy": "auto", "window": {"start_hour": 2, "end_hour": 5},
 "release": {"version": "0.2.0", "manifest_b64": "…", "signature_b64": "…",
             "size": 9412345, "sha256": "…", "artifact_path": "/api/v1/device/update/artifact/0.2.0"}}
```

`release` is `null` when there is nothing newer for this machine: the newest
published release of the machine's channel whose version is greater than the
agent version the device last reported and whose `min_upgrade_from` is not
greater than it. `GET /api/v1/device/update/artifact/{version}` returns the
package bytes (`application/octet-stream`).

As built: without an `update` section the answer is `channel: "none"`,
`policy: "manual"`, `window: null`, `release: null`. Only a release whose
signing key is still in `HM_RELEASE_PUBLIC_KEYS` is offered or served. The
artifact route answers `404` for any version not offered on the machine's
channel and is limited to 12 downloads an hour per device. The channel and
policy always come from the cloud document, also under `control: local`
(section 14).

## 7. Plugin catalog

`appliance/catalog/<id>/plugin.json` and `appliance/catalog/<id>/compose.yaml`
in the repository; installed to `/usr/share/happymining/catalog/` by the
package; read by the control plane from the same tree (`HM_CATALOG_DIR`).

```json
{
  "schema": 1,
  "id": "ollama",
  "version": "1",
  "name": "Ollama",
  "summary": "Runs open models on the machine's GPUs.",
  "homepage": "https://ollama.com",
  "license": "MIT",
  "gpu": true,
  "modes": ["private_ai", "vectorize"],
  "requires": [],
  "ports": [{"name": "api", "port": 11434, "protocol": "http", "ui": false}],
  "settings": {
    "models": {"type": "string_list", "label": "Models to keep installed", "env": "HM_SET_MODELS",
               "max_items": 8, "pattern": "^[a-z0-9][a-z0-9._/-]{0,80}(:[A-Za-z0-9._-]{1,40})?$", "default": []}
  },
  "secrets": [{"key": "api_key", "env": "EXAMPLE_API_KEY", "label": "…", "required": false}],
  "images": [{"ref": "docker.io/ollama/ollama:0.0.0", "digest": "sha256:…", "verified": true}],
  "volumes": [{"name": "models", "backup": "models"}, {"name": "config", "backup": "always"}],
  "post_start": [{"service": "ollama", "exec": ["ollama", "pull", "{item}"], "for_each": "models", "timeout_s": 3600}]
}
```

- `id` equals the directory name. `version` is a string that changes whenever
  the entry changes.
- `modes`: the modes in which the plugin runs. Never contains `vast`.
- `settings` types: `bool`; `int` (`min`, `max`); `enum` (`values`);
  `string` (`pattern`, `max_len` ≤ 200); `string_list` (`pattern`,
  `max_items` ≤ 32). Every setting has `label`, `default` and `env`
  (`^HM_SET_[A-Z0-9_]{1,40}$`). Patterns must not match a control character,
  a quote, `$`, `` ` `` or `\`. A list is passed as one space-separated
  variable, so list patterns must not match a space.
- `secrets`: `key` `^[a-z][a-z0-9_]{0,30}$`, `env` `^[A-Z][A-Z0-9_]{1,60}$`.
  The document's secret name is `plugin.<id>.<key>`.
- `images`: every image the Compose file uses, as `ref` (with a tag) and
  `digest`. `verified: true` only when the digest was read from the registry
  for that tag; the Compose file then pins `ref@digest`. An entry with an
  unverified image is installed but the helper refuses to start it unless
  `ALLOW_UNPINNED_IMAGES=true`.
- `volumes`: named volumes, each with `backup`: `always`, `models` (only with
  `include_models`) or `never`.
- `build` (optional): `{"context": "vectorizer", "image": "happymining/vectorizer:1"}`
  for a plugin whose image is built on the machine from a directory shipped
  with the package (`/usr/share/happymining/<context>`). Used for
  HappyMining's own vectorizer; the base image of its Dockerfile is listed in
  `images` like any other.
- `post_start`: commands run inside a service of the plugin after start, as
  argv arrays. `{item}` is replaced by each value of the `for_each` list
  setting. No shell.
- `compose.yaml`: services of this plugin only. Required in every service:
  `restart: unless-stopped`; label `eu.happymining.plugin=<id>`; no
  `privileged`, no `network_mode: host`, no `pid`/`ipc` host, no bind mount
  of the Docker socket or of a host path outside `/srv/happymining` and
  `/var/lib/happymining-plugins/<id>`; published ports only those in `ports`.
  Variables: `${HM_SET_…}` from settings, secret variables from the root-only
  env file, `${HM_BIND}` (the address ports are published on), and
  `${HM_PLUGIN_DATA}`. The repository tests enforce these rules.

Plugins talk to each other over one Docker network, `hm-appliance`, which the
helper creates. Every service joins it (declared `external: true` in each
Compose file) and is reachable there by its service name, so service names
are unique across the catalog and the main service of a plugin is named after
the plugin. Ports are published on the host only for what people or other
machines on the owner's network need, on `${HM_BIND}`.

The helper runs `docker compose -p hm-<id> --env-file <root-only file> -f
<catalog>/compose.yaml up -d` and the matching `down`. Docker and the NVIDIA
container runtime must already be on the machine; the helper does not install
them.

As built:

- `${HM_BIND}`: `0.0.0.0` for a plugin whose `bind` setting is `lan` or
  that has no `bind` setting, `127.0.0.1` for `localhost` and, to fail
  closed, for any other value. **Decision (implementation).**
- The repository checker (`tests/appliance/catalog/catalog_rules.py`) is
  stricter than this section: no YAML merge keys, `!reset` or `!override`;
  a setting may only be a single argv element; list items cannot start with
  `-`; a bind mount's propagation may only be `rslave`, `slave`, `rprivate`
  or `private`. It also runs `docker compose config` on every file.
- The catalog shipped in this tree (`appliance/catalog/README.md` lists the
  sources). Digests were read from Docker Hub's API on 2026-10-02; the
  registry itself could not be reached from the build sandbox.

| Plugin | Image | GPU | Port | `bind` default | Runs in |
|---|---|---|---|---|---|
| `ollama` | `docker.io/ollama/ollama:0.35.0`, pinned | yes | 11434 | `localhost` | `private_ai`, `vectorize` |
| `qdrant` | `docker.io/qdrant/qdrant:v1.19.1`, pinned | no | 6333 | `localhost` | `private_ai`, `vectorize` |
| `vectorizer` | built on the machine (`happymining/vectorizer:1`, base `python:3.12-slim-bookworm` pinned) | no | 8765 | `lan` | `private_ai`, `vectorize` |
| `open-webui` | `docker.io/openwebui/open-webui:0.11.4`, pinned | no | 3000 | `lan` | `private_ai` |
| `openclaw` | `docker.io/openclaw/openclaw:2026.9.7`, pinned | no | 18789 | `lan` | `private_ai` |
| `hermes` | `docker.io/nousresearch/hermes-agent:v2026.9.24`, pinned (Nous Research's Hermes Agent) | no | 9119 | `lan` | `private_ai` |

  Upstream telemetry and update checks are switched off where the upstream
  documents a switch (Open WebUI, OpenClaw). The upstream code was not
  audited.
- The helper builds `happymining/vectorizer:1` only when that image is
  missing. The tag must change whenever `appliance/vectorizer` changes, or
  machines keep running the old image.

## 8. Helper switches

`/etc/happymining/helper.conf`, root-owned. Everything is off unless the file
says otherwise, as before.

| Key | Allows |
|---|---|
| `ALLOW_PLUGINS` | Starting catalog plugins and managing those that run. Without it, a plugin HappyMining started earlier is still stopped when the document no longer runs it (vast mode, disabled, removed) |
| `ALLOW_NAS` | Mounting NAS entries |
| `ALLOW_BACKUP` | Running backups |
| `ALLOW_UPDATE` | Installing signed firmware releases |
| `ALLOW_UNPINNED_IMAGES` | Starting a plugin whose image digest is not verified |
| `ALLOW_FOREIGN_CONTAINERS` | Starting GPU plugins while containers not started by HappyMining are running |
| `ALLOW_UPDATE_WITHOUT_ROLLBACK` | Installing a release although no copy of the installed package is kept (section 9). **Decision (implementation).** |

Values are `0` or `1`. The file is refused, and every switch is then off,
when it is a symbolic link, not a regular file, not owned by root, writable
by group or others, or contains an unknown key.

The appliance installer profile turns the first four on. The Vast host
profile leaves them off. **Not built:** the installer tooling (`os/`) has no
such profiles yet; the packaged `helper.conf` has every switch off.

### 8.1 Process layout on the machine

**Decision (implementation):** the socket helper answers quick requests
only; everything that can take long runs in its own oneshot unit. None of
these units has an `[Install]` section: they are started only by the helper
with `/usr/bin/systemctl start --no-block <unit>`, a fixed argv whose unit
name comes from the fixed job set and a validated plugin id.

| Unit | User | Runs | Sandbox |
|---|---|---|---|
| `happymining-agent.service` | `happymining` | the agent: heartbeats, schedules, update check and download, asks the helper | unchanged |
| `happymining-helper@.service` (socket `/run/happymining-helper.sock`, one process per request) | root | `hm-helper serve`: the quick actions of 8.2; never Docker, mount, a backup or dpkg | unchanged: `ProtectSystem=full`, `RestrictAddressFamilies=AF_UNIX`, `MemoryMax=64M`, `RuntimeMaxSec=180` |
| `happymining-appliance-apply.service` | root | `hm-helper apply-stored` (section 6.3) | no file-system namespace (it would keep the NAS mounts inside the unit); `NoNewPrivileges`, a capability bounding set for mount helpers, `SystemCallFilter=@system-service @mount`, `TimeoutStartSec=3h` |
| `happymining-appliance-job@.service` | root | `hm-helper run-job %i`, `%i` one of `vectorize_sync`, `backup_run`, `status_refresh`, `plugin_restart-<plugin id>` | `ProtectSystem=strict`, writable only the helper state and the NAS mount points, lowest I/O priority, `Nice=10`, `TimeoutStartSec=13h` |
| `happymining-update-install.service` | root | `hm-helper install-staged` (section 9) | wide (dpkg writes the system); `KillMode=process` so that a running dpkg is not killed |
| `happymining-update-guard.timer` (`OnActiveSec=10min`) and `.service` | root | `hm-helper update-guard` (section 9) | as the install unit |

Each relaxation is commented in the unit file. None of the units was ever
started: they were checked with `systemd-analyze verify` only.

Locks: `apply-stored`, `plugin_restart` and `backup_run` take an exclusive
lock on `/var/lib/happymining-helper/appliance.lock` and wait for it, so an
apply (also one to `vast` mode) waits until a running backup has finished.
`vectorize_sync` and `status_refresh` take none, so that an index run of
several hours never holds up an apply (a change to `vast` in particular);
the vectorizer has its own lock, and an apply that stops it ends the run.
`update-install`, `install-staged` and `update-guard` share
`update.lock`; `update-install` answers `busy` when it is held.

### 8.2 Socket actions

One JSON object and a newline per connection, one response line, the peer's
uid checked with `SO_PEERCRED` (root or the `happymining` user), unknown
fields and fields that do not belong to the action refused.

| Action | Switch | Request limit | What it does |
|---|---|---|---|
| `restart-vast-daemon`, `reboot` | as before | 256 bytes | unchanged |
| `appliance-status` | none (read only) | 256 bytes | reads files only: `state.json`, the mount table (`/proc/self/mountinfo`, never `mount`), the profile, the catalog, the keys; opens each referenced secret to tell `ok` / `unreadable` / `missing`; may start the apply unit, `status_refresh` or the update guard (sections 6.3, 9) |
| `appliance-apply` | none to store a valid document; applying needs `ALLOW_PLUGINS` or `ALLOW_NAS` | 96 KiB | section 6.3, step 1 |
| `appliance-run-job` | `vectorize_sync`, `plugin_restart`: `ALLOW_PLUGINS`; `backup_run`: `ALLOW_BACKUP` | 256 bytes | starts `happymining-appliance-job@<instance>.service`; `plugin_restart` only for a plugin of the document in force |
| `update-install` | `ALLOW_UPDATE` | 32 KiB (a 16 KiB manifest in base64) | section 9 |

Responses: `{"ok", "code", "detail", "result"}`, at most 256 KiB; codes
`invalid`, `disabled`, `failed`, `unauthorized`, `locally_controlled`,
`busy`. The result of `appliance-status` is the object of section 6.1
without `schedules`, plus `applied_schedules` (the schedule objects of the
document in force), which the agent removes before sending.

### 8.3 Root command-line actions

Run as root on the machine, never over the socket (only
`appliance-status` exists in both forms); `hm-helper` refuses every action
unless its effective uid is 0.

| Command | Use |
|---|---|
| `apply-stored`, `run-job <instance>`, `install-staged`, `update-guard` | run by the units of 8.1; refused when `helper.conf` is unusable |
| `appliance-status` | prints the status as JSON |
| `secret-set <name>` | section 6.4 |
| `backup-init` | creates the backup key and prints the recovery key once; refuses if a key exists |
| `backup-restore --from <file> [--to <dir>]` | section 10; asks the recovery key on standard input |
| `appliance-purge <plugin id>` | deletes a plugin's volumes, data directory and env file, only when the plugin is in no document (in force or stored) and has no container that is not stopped, and only after the id is typed again at the terminal |
| `vectorizer-token` | creates the vectorizer token if missing and prints it |

`happyminingctl` exposes them as `appliance status [--json]`,
`appliance secret set <name>`, `appliance purge <id>`,
`appliance token [vectorizer]`, `backup init` and
`backup restore --from <file> [--to <dir>]`. As root it executes
`/usr/lib/happymining/hm-helper` with a fixed argument list and the terminal
attached; otherwise it says that `sudo` is needed. `appliance status` asks
the socket instead, like the agent.

### 8.4 Files on the machine

| Path | Mode | Content |
|---|---|---|
| `/var/lib/happymining-helper/` | 0700 root | the helper's state; created by the package's `postinst` |
| `…/applied.json` | 0600 | the cloud document waiting for or last given to `apply-stored`, with its sealed secrets and a checksum |
| `…/state.json` | 0600 | apply status, per-item results, plugin observations, backup and update state |
| `…/seal.key`, `…/backup.key` | 0600 | the machine's sealing key; the backup key |
| `…/local-secrets.json` | 0600 | secrets entered with `secret set`, sealed for this machine |
| `…/plugins/<id>.env` | 0600 | the env file of a plugin (settings, `HM_BIND`, `HM_PLUGIN_DATA`, opened secrets) |
| `…/nas/<id>.cred` | 0600 | CIFS credentials (`username=`, `password=`, `domain=`) |
| `…/updates/` | 0600 files | the staged package and `staged.json` |
| `…/packages/current.deb`, `previous.deb` | 0600 | the installed package and the one before, for rollback |
| `…/restore/` | 0700 | holds `<UTC time>/`, the default target of `backup restore` |
| `/var/lib/happymining-plugins/<id>/` | 0700 root | `HM_PLUGIN_DATA` of a plugin |
| `/var/lib/happymining-plugins/vectorizer/config/` | 0750 root:10001 | `vectorizer.json` and `token`, 0640 root:10001, so that the container (uid and gid 10001) can read them and not write them; the parent directory stays 0700 root |
| `/srv/happymining/nas/<id>` | 0755 root | NAS mount points |
| `/usr/share/happymining/catalog/`, `…/vectorizer/`, `…/release-keys/*.pub` | from the package | the catalog, the vectorizer's build context, the trusted release keys |
| `/var/lib/happymining/updates/` | 0700 `happymining` | the agent's download directory |
| `/var/lib/happymining/agent-state.json` | 0600 `happymining` | now also `machine_id` (backup archive names) and the last successful heartbeat with its agent version (update guard); the helper reads it, and never the credential file |
| `/var/lib/happymining/schedules.json` | 0600 `happymining` | schedule history |

`postinst` creates the helper, plugin and NAS directories and leaves their
content as it is on upgrade. Even `purge` keeps them: deleting the backup
key would make every archive unreadable. It creates `/var/lib/happymining`
itself but **nothing inside it**: the agent's account owns that directory
and could have replaced an entry with a symbolic link, which a root `chown`
or `chmod` would follow (found by the review). The agent creates its
`spool` and `updates` directories itself.

### 8.5 Commands the helper runs

Absolute paths, argv arrays, no shell. The only variable parts are validated
ids, paths built by the helper from those ids, image references from the
installed catalog and catalog argv.

- `/usr/bin/systemctl start --no-block <unit of 8.1>`;
  `/usr/bin/systemctl restart happymining-update-guard.timer`.
- Mounts, one of three forms (nothing from the document is in the option
  string: the access level picks `ro` or `rw`, the credentials file name is
  built from the validated id):

  ```
  /usr/bin/mount -t cifs //host/share[/subpath] /srv/happymining/nas/<id> -o ro|rw,nosuid,nodev,noexec,credentials=/var/lib/happymining-helper/nas/<id>.cred
  /usr/bin/mount -t cifs //host/share[/subpath] /srv/happymining/nas/<id> -o ro|rw,nosuid,nodev,noexec,guest
  /usr/bin/mount -t nfs  host:/export[/subpath] /srv/happymining/nas/<id> -o ro|rw,nosuid,nodev,noexec
  ```

  and `/usr/bin/umount /srv/happymining/nas/<id>` for what HappyMining
  mounted. After a mount the entry must appear in the mount table.
- Docker: `network inspect|create hm-appliance`; `ps` (the foreign-container
  guard); `image inspect`; `build -t <image> /usr/share/happymining/<context>`;
  `compose -p hm-<id> --env-file <env> -f <catalog>/compose.yaml up -d`;
  `compose -p hm-<id>` with `down` (never `-v`, never `--rmi`), `stop`,
  `start`, `restart`, `ps --all --format json`, `exec -T <service> <argv>`;
  `volume inspect`; and, in `appliance-purge` only, `volume ls` and
  `volume rm` of the plugin's own volumes. Commands on an existing project
  select it by name only (no `-f`), so Compose reads no file and acts only
  on containers labelled with that project.
- `/usr/bin/dpkg --force-confdef --force-confold -i <package>` (a changed
  `helper.conf` is kept).

Env files (**Decision (implementation)**): every value double-quoted, with
`\` → `\\`, `"` → `\"`, `$` → `$$`, newline → `\n`, carriage return → `\r`,
tab → `\t`; every other character as it is; a value with a NUL byte or
invalid UTF-8 is refused. The round trip of 35 hostile values was checked
with the real `docker compose config` (v5.5.1). An optional secret that is
not set is left out; one that is set but does not open stops the plugin from
starting.

## 9. Firmware releases

A release is the agent package (`happymining-agent_<version>_amd64.deb`),
which also carries the catalog and the vectorizer. Reference implementation
and test vector: `api/happymining/sealing.py`,
`appliance/testdata/release-vector.json`.

Manifest (the signed bytes are the file as it is, at most 16 KiB):

```json
{
  "schema": 1,
  "product": "happymining-agent",
  "version": "0.2.0",
  "created_at": "2026-10-02T12:00:00Z",
  "artifact": {"filename": "happymining-agent_0.2.0_amd64.deb", "size": 9412345, "sha256": "…"},
  "min_upgrade_from": "0.1.0",
  "notes": "…"
}
```

- Signature: Ed25519 over the manifest bytes, base64. Key id: first 16 hex
  characters of SHA-256 of the 32-byte public key.
- Versions are `MAJOR.MINOR.PATCH`, numbers only, compared numerically.
- **Publishing** (staff): upload manifest and signature, then the package.
  The API verifies the signature against `HM_RELEASE_PUBLIC_KEYS` and the
  package against the manifest's size and SHA-256. With no key configured,
  nothing can be published. Then the release is assigned to channels
  (`beta`, `stable`). A release can be withdrawn; it is then no longer
  offered.
- **Installing** (machine): the agent downloads the package into its own
  directory. The helper, as root, verifies the signature against the keys
  installed with the current package
  (`/usr/share/happymining/release-keys/*.pub`), the size, the SHA-256, that
  the version is greater than the installed one and that `min_upgrade_from`
  allows it, keeps the current package for rollback, and runs `dpkg -i`. It
  never installs a package that failed any check, never downgrades through
  this path, and takes no URL: the bytes come from the agent's download.
- **Rollback**: if the new agent has not completed a heartbeat within 10
  minutes of the installation, a root timer reinstalls the previous package.
  The update state reports `rolled_back`.
- The signing key is generated locally and stays out of the repository
  (`scripts/release-sign.py`). The key in `appliance/testdata/` is a
  published test key that no build trusts.

As built (control plane, `services/releases.py`):

- `POST /releases` takes `manifest_b64` and `signature_b64` and refuses
  them unless the signature verifies against `HM_RELEASE_PUBLIC_KEYS`
  (release status `awaiting_artifact`). A version is published once.
- `PUT /releases/{version}/artifact` takes the package as the raw request
  body (`Content-Type: application/octet-stream`). The caller and the
  expectation are checked before the first byte is read; reading stops at
  the first byte beyond the manifest's size (at most `HM_RELEASE_MAX_BYTES`,
  default 128 MiB); nothing is stored unless size and SHA-256 match (status
  `ready`). The package is stored in PostgreSQL. This route alone has a body
  limit above the general one. The dashboard cannot upload a package (its
  form limit is 1 MiB); it points to this route.
- `POST /releases/{version}/channels` puts a `ready` release on exactly the
  channels given; `POST /releases/{version}/withdraw` (reason required)
  stops offering it.
- A release is offered and served only while its key is still configured:
  removing a key from `HM_RELEASE_PUBLIC_KEYS` stops the distribution of
  everything signed with it. LIVE refuses to start with the published test
  key configured.

As built (machine, `agent/internal/agent/updates.go`,
`agent/internal/applier/update.go`). **Decision (implementation)** unless
stated:

1. The agent asks for the offer 2 minutes after it starts and then every 6
   hours while the helper reports the `update` capability, when the job
   `update_check` runs, at the start of the window when an automatic update
   waits for it, and when `install_update` arrives.
2. It installs only for an `install_update` operation naming exactly the
   offered version, or with `policy: auto` while the local time is inside
   the window, checked before and again after the download (a download that
   ends after the window waits for the next one).
3. It checks that the unsigned offer and the manifest agree (product,
   version, file name, size, SHA-256) and downloads to
   `/var/lib/happymining/updates/.<file>.part` (created `O_EXCL|O_NOFOLLOW`,
   0600, earlier files removed first, at most the stated size, hashed while
   written, abandoned after 2 minutes without data), then renames it to
   `<file>`. It never runs dpkg.
4. Helper `update-install` (quick): `ALLOW_UPDATE`; signature against
   `/usr/share/happymining/release-keys/*.pub` (root-owned; no key, no
   update); version equal to the request and newer than the installed one,
   `min_upgrade_from` satisfied; the download must be a regular file directly
   in the agent's download directory, named as the manifest says, owned by
   the agent's user, not a link, of the stated size; a version that was
   rolled back on this machine is refused from then on. Then it is copied
   into `/var/lib/happymining-helper/updates/` while size and SHA-256 are
   checked, `staged.json` is written and the install unit started.
5. Refused when `packages/current.deb` does not exist (no rollback would be
   possible), unless `ALLOW_UPDATE_WITHOUT_ROLLBACK=1`. Before refusing, the
   helper adopts the package the image's installer left in
   `/var/cache/happymining/` (named by the file `current`, with its
   `.sha256`): only if its file name carries the installed version, every
   file is a regular file owned by root and writable by nobody else, and the
   checksum matches.
6. `install-staged`: everything again from the root-owned copies;
   `current.deb` copied to `previous.deb`; `dpkg -i`. On failure,
   `previous.deb` (when there is one) is installed again and the state is
   `error`. On success the package becomes `current.deb`, the state
   `installed`, and the guard timer is armed.
7. `update-guard`: the release stays when `agent-state.json` shows a
   successful heartbeat after the installation started **and** the agent
   version is the new one. Otherwise `previous.deb` is installed again and
   the state is `rolled_back`; without `previous.deb` the state is `error`.
   The timer does not survive a reboot: the status request starts the guard
   itself once an undecided installation is older than 12 minutes.
8. **First-installation gap.** `postinst` cannot place `current.deb` (dpkg
   does not tell a maintainer script which file it installs). The helper
   records it after each update it installs, and on a machine installed
   from the image it adopts the installer's copy (item 5). A machine whose
   package was installed by hand (`dpkg -i`, or `os/install/install.sh`,
   which does not keep the package) still refuses every update until
   `ALLOW_UPDATE_WITHOUT_ROLLBACK=1` is set, and the first update installed
   that way has no automatic rollback.
9. Release keys enter the package only from `HM_RELEASE_KEYS_DIR` at build
   time; the build refuses the published test key. A package built without
   a key installs fine and refuses every update.

Limits of `install_update` (section 14): the offer carries only the newest
installable release, so the control plane accepts a request only for that
release (**decision, implementation**: `409` names the release the machine
is offered); a download can
outlast the operation's lifetime (`HM_OPERATION_TTL_S`, default 600 s), in
which case the operation ends `expired` while the reported update state
shows what really happened.

This updates HappyMining's own software. The operating system, the kernel,
the NVIDIA driver and Vast's software are not updated by this mechanism.

## 10. Backups

What is saved: the applied document (sealed secrets as they are), each
plugin's volumes according to the catalog, and the vector database. A plugin
is stopped while its volumes are copied and started again afterwards.

- The key is 32 random bytes generated on the machine by
  `sudo happyminingctl backup init`, which prints the **recovery key** once.
  The key stays in a root-only file for scheduled runs. It is never part of
  a heartbeat, an operation result or a log. The control plane learns only
  that a key exists and its `key_id` (first 8 hex characters of SHA-256 of
  the key). Without the recovery key a backup cannot be restored by anyone,
  HappyMining included.
- Recovery key text: `hmrk1-` followed by the 32 key bytes and a 2-byte
  check (first two bytes of SHA-256 of the key) in base32 without padding,
  lower case, in groups of four separated by `-`.
- Restoring is a local, root action:
  `sudo happyminingctl backup restore --from <file>`; it asks for the
  recovery key. It is never triggered remotely.

Archive format `HMBK1` (so that a restore tool can be written independently):

```
header     = "HMBK1\n" (6 bytes) || key_id (8 bytes: first 8 of SHA-256(key)) || salt (16 random bytes) || chunk_size (uint32 BE, 1048576)
stream_key = HKDF-SHA256(ikm = key, salt = salt, info = "happymining-backup-v1", length = 32)
chunk i    = uint32 BE length of ciphertext || AES-256-GCM(stream_key, nonce_i, plaintext_i, AAD = header)
nonce_i    = uint64 BE i || 0x00 0x00 0x00 || last   (last = 0x01 for the final chunk, else 0x00)
plaintext  = gzip( tar ), cut into chunk_size pieces; the final chunk may be shorter or empty
```

A stream that does not end with a final chunk is truncated and is refused.
File name: `hm-backup-<machine id>-<YYYYMMDDTHHMMSSZ>.hmbk`.

Destinations: a directory on a NAS entry with `access: write`, or an
S3-compatible bucket (SigV4, multipart upload, path-style addressing).
`keep` older archives are deleted from the destination after a successful
run.

As built (`agent/internal/applier/backupjob.go`, `agent/internal/backup`):

- Items: `applied.json` (the cloud document with its sealed secrets), the
  local profile and `local-secrets.json` when they exist, and the volumes of
  each **enabled** plugin according to the catalog (`always`; `models` only
  with `include_models`). "The vector database" is the `storage` volume of
  `qdrant` (policy `always`) and the vectorizer's `state` volume. A volume
  is located with `docker volume inspect hm-<id>_<name>` and accepted only
  as a real directory under `/var/lib/docker/volumes/`.
- Running plugins whose volumes are saved are stopped with `compose stop`
  (dependents first) and started again afterwards, also when the backup
  fails.
- A NAS destination must be mounted read-write, by HappyMining, at its
  mount point. The S3 secret key is opened for the run only.
- The machine id in the file name comes from the `machine_id` the agent
  writes into `agent-state.json`; before the first heartbeat there is none
  and the run fails with that reason. No key: state `no_key`, run `failed`.
- `backup restore` writes into a new directory,
  `/var/lib/happymining-helper/restore/<UTC time>/` unless `--to` is given,
  and never overwrites an existing file. It does **not** put anything back
  into the plugins' volumes or the helper's state: copying the restored
  files into place (with the plugins stopped) is a manual step, and no
  procedure for it is written yet.
- The archive is treated as hostile when it is extracted: absolute names
  and `..` components are refused, only regular files, directories and
  symbolic links are accepted, no link is ever followed (every component is
  opened relative to its parent with `O_NOFOLLOW`), nothing is overwritten,
  setuid and setgid bits are dropped. Every relative system call of the
  backup code refuses an absolute name (`relName` in `backup/sys.go`): an
  experiment that ran a backup test as root with the name check removed
  replaced and deleted a real system file of the build sandbox
  (`/etc/passwd`), because `unlinkat` and `renameat` ignore the directory
  for an absolute name.

## 11. Vectorizer

`appliance/vectorizer/`. Runs on the machine as the plugin `vectorizer`.

- Reads the `sources` (mounted read-only under `/srv/happymining/nas/`).
- For each file with a wanted extension and within the size limit: parses it
  with Docling (layout, tables, optional OCR; plain text and Markdown are read
  directly), cuts it into passages, embeds them with the embedding model
  served by the `ollama` plugin, and stores vectors and passages in the
  `qdrant` plugin. A file is processed again only when its size or
  modification time changed and its SHA-256 differs. Passages of files that
  disappeared are removed.
- Writes `status.json` (the counters of section 6.1; no file names).
- Inside its container: HTTP on port 8765; `/config` (read-only) holds
  `vectorizer.json` (the `vectorizer` object of the document, plus the mount
  path of each source and the addresses of `ollama` and `qdrant`) and
  `token`; `/state` (a volume) holds its database and `status.json`; the
  cloud API key arrives as the environment variable `HM_ANSWER_API_KEY`.
- Serves on the owner's network, with a bearer token generated on the machine
  (`sudo happyminingctl appliance token vectorizer`):
  - `POST /v1/search` `{"query": "…", "limit": 8}` → passages with source
    path and score;
  - `POST /v1/ask` `{"question": "…"}` → an answer with its sources, produced
    by the configured `answer.provider`; `501` when the provider is `none`;
  - `GET /healthz`.
- It does not copy the NAS's access rights: anyone holding the token can
  search everything that was indexed. Index only shares meant for everyone
  who gets the token.

As built (`appliance/vectorizer/README.md`):

- Command line, run with the image's own interpreter
  (`/opt/venv/bin/python -m hm_vectorizer …`): `serve` (the container's
  default), `sync`, `status`, `healthcheck`, `selfcheck`. `sync` exits 0
  when the run ended `idle` (files that failed are counted, they do not fail
  the run), 1 when it ended in `error`, 2 when the configuration or the state
  directory was refused (nothing indexed), 3 when another sync holds the lock
  (nothing ran).
- The job `vectorize_sync` runs
  `docker compose -p hm-vectorizer exec -T vectorizer /opt/venv/bin/python -m hm_vectorizer sync`
  with a 12-hour limit; exit 3 is recorded `skipped`, 1 and 2 `failed`. It
  is `skipped` when the vectorizer is not configured to run or not running.
- HTTP API: `GET /healthz` (no authentication, no detail), `POST /v1/search`,
  `POST /v1/ask` (`501` with provider `none`), `GET /v1/status`,
  `POST /v1/sync` (`202`, or `409` while a run is going). Everything but
  `/healthz` needs `Authorization: Bearer <token>`, compared in constant
  time; 10 wrong tokens from one address within 60 seconds give `429` for a
  while. Bodies at most 64 KiB, errors `{"error": "<code>"}` without upstream
  text.
- Container layout (`appliance/catalog/vectorizer/compose.yaml`): runs as
  uid and gid 10001; `/config` is the host's
  `/var/lib/happymining-plugins/vectorizer/config`, read-only; `/state` a
  named volume; the host's `/srv/happymining/nas` is bind-mounted read-only
  at the same path with propagation `rslave`, so that a share mounted or
  unmounted while the container runs appears or disappears inside it
  (Docker's default, `rprivate`, would freeze the view taken at start).
  **Consequence:** every NAS entry, including one with `access: write`, is
  visible read-only inside the vectorizer container; only the `sources` are
  indexed.
- `vectorizer.json` is the document's `vectorizer` object plus
  `source_paths` (each source's mount point), `ollama_url`
  (`http://ollama:11434`), `qdrant_url` (`http://qdrant:6333`) and
  `collection`. The helper restarts the vectorizer after `up -d` when this
  file changed, because it is read only at start.
- The status the helper reports comes from `status.json` in the `state`
  volume, read without following a link, bounded to 64 KiB and checked
  again.
- The vectorizer sends no API key to Qdrant. Qdrant's optional `api_key`
  secret must therefore stay unset while the vectorizer is used, and Qdrant
  then has no authentication: anything on the `hm-appliance` network, and
  anyone who reaches its published port (`127.0.0.1` by default), can read
  and change the whole index without the vectorizer's token.
- Passages taken from documents are delimited and marked as untrusted in
  the prompt sent to the answer provider. That reduces prompt injection from
  indexed documents; it does not prevent it.
- Docling 2.132.0 parses DOCX, PPTX, XLSX, HTML and CSV in tests. **PDF and
  OCR were not run** (their models could not be downloaded in the build
  sandbox); without them a file is counted as failed with
  `parser_unavailable`.
- The image is built on the machine, by the apply unit, when
  `happymining/vectorizer:1` is missing. The build needs the network: PyPI
  (dependencies installed with `--require-hashes` from `requirements.lock`),
  PyTorch's CPU index (`torch` and `torchvision` by version only) and Hugging
  Face and modelscope.cn (Docling's models, not pinned). The running
  container needs none of it. The image was never built (those hosts were
  not reachable from the build sandbox).

## 12. Control plane routes (people)

All under `/api/v1`, session authentication, the rules of section 3.

| Route | Who |
|---|---|
| `GET /appliance/catalog` | any signed-in user |
| `GET /machines/{id}/appliance` | may view |
| `PUT /machines/{id}/appliance/mode` `{mode}` | `org_admin`, staff who may manage |
| `PUT`, `DELETE /machines/{id}/appliance/plugins/{plugin_id}` `{enabled, settings, sealed_secrets}` | `org_operator` and up (secrets: `org_admin`), staff who may manage |
| `PUT`, `DELETE /machines/{id}/appliance/nas/{nas_id}` | `org_admin`, staff who may manage |
| `PUT`, `DELETE /machines/{id}/appliance/vectorizer` | `org_admin`, staff who may manage |
| `PUT`, `DELETE /machines/{id}/appliance/backup` | `org_admin`, staff who may manage |
| `PUT`, `DELETE /machines/{id}/appliance/schedules/{schedule_id}` | `org_operator` and up, staff who may manage |
| `PUT /machines/{id}/appliance/update` | `org_admin`, staff who may manage |
| `POST /machines/{id}/appliance/jobs` `{job, plugin}` | `org_operator` and up, staff who may manage |
| `POST /machines/{id}/appliance/install-update` `{version}` | `org_admin`, staff who may manage |
| `GET /machines/{id}/remote-access` | `org_admin`, staff |
| `PUT /machines/{id}/management` `{management}` | section 3 |
| `POST /machines/{id}/remote-access/grants` `{level, expires_in_hours, reason}` | `org_admin` |
| `POST /machines/{id}/remote-access/grants/{grant_id}/revoke` | `org_admin`, staff |
| `GET`, `POST /org/users`, `PATCH /org/users/{id}` | `org_admin` (staff pass `owner_id`) |
| `GET`, `POST /releases`, `PUT /releases/{version}/artifact`, `POST /releases/{version}/channels`, `POST /releases/{version}/withdraw` | staff (`auditor` reads) |

Every change takes the current revision in `If-Match` when the caller wants
to detect a concurrent change (`409 conflict` on mismatch), increases the
revision, and is audited with what changed. Sealed values are never written
to the audit trail or the logs.

A secret is sent with the object that uses it: `sealed_secret` in a NAS
entry, in `vectorizer.answer`, in an `s3` destination; `sealed_secrets`
(`{key: sealed}`) in a plugin. Omitting it keeps the stored one, except when
the object now points somewhere else (section 5, second limit): then the
secret has to be sent again.

The dashboard (`api/happymining/dashboard_appliance.py`, page
`/machines/{id}/appliance`) offers the same changes as forms. It checks the
CSRF token first, then the permission, then calls the same service functions
as these routes, with the current revision in a hidden field. Secrets are
sealed in the browser by `dashboard/static/seal.js` (WebCrypto); the password
inputs have no `name`, so the plaintext is never posted. The releases page
(`/admin/releases`) creates releases, sets channels and withdraws; it does
not upload packages (1 MiB form limit). **Deviation (implementation):**
under `control: local` the page hides the configuration forms but keeps
"run a job" and "install an update", which the machine still accepts.

## 13. What this does not do

- It does not install Vast's host software, list or unlist a machine, or set
  prices.
- It does not install Docker, the NVIDIA driver or the container runtime.
- It does not schedule mode changes.
- It does not give a per-user view of the index: one token, one index.
- It does not proxy the plugins through the cloud: they are reachable on the
  owner's network only, and making them reachable from elsewhere (VPN) is the
  owner's choice.
- It does not update the operating system.
- It does not put restored backup data back into place (section 10).
- It does not delete plugin data remotely, ever.

## 14. Contract questions left open

Places where the code and this contract, or the contract and safety, do not
fully agree. Items 1 to 3, 7 (in part) and 10 (in part) were resolved in code
after the documentation pass, as noted; the others are open.

1. **`control: "unknown"`.** *Resolved:* stored as `unknown`; the document
   is sent only under `cloud` (6.1).
2. **Secrets are bound to their name, not to their destination.**
   *Resolved in the control plane:* a stored secret is not carried over to a
   new destination (section 5, second limit). Not resolved against a
   compromised control plane.
3. **`install_update` of an older release.** *Resolved:* the control plane
   accepts only the release the machine is offered (9).
4. **Operation lifetime.** A slow download ends the `install_update`
   operation as `expired` although the machine may still install the
   release (9).
5. **Update policy under local control.** The channel, policy and window
   come from the cloud document even when the machine follows its local
   profile (6.6).
6. **Dashboard under local control** keeps "run a job" and "install an
   update" (12).
7. **Installer profiles and `current.deb`.** The "appliance" and "Vast host"
   installer profiles of section 8 do not exist. *Resolved for machines
   installed from the image:* the helper adopts the installer's copy of the
   package as `current.deb` (9, items 5 and 8); not for packages installed
   by hand.
8. **Version number.** The agent built from this tree reports `0.1.0`, like
   the agent released before it (6).
9. **Outcome of a scheduled job.** Section 4.6 says a job whose feature is
   not configured is recorded `skipped`; the agent records `ok` once the
   helper has started the unit, and the unit's own result (`skipped`,
   `failed`) stays in the helper's `state.json`, not in the report.
10. **Package upload through the reverse proxy.** *Resolved for Caddy*
    (`deploy/Caddyfile`, `Caddyfile.demo`): `PUT
    /api/v1/releases/<version>/artifact` gets 512 MB, every other request
    keeps 1 MB (checked by `tests/os/test_proxy_body_limits.py` as text; Caddy
    itself is not installed here, so the files were not validated by Caddy).
    *Open for the Hostinger staging instance:* its Traefik limit
    (`maxRequestBodyBytes` 1048576) still applies to every route; its Compose
    file is at the Hostinger API's size limit, and the Traefik version there
    is unknown.
11. **The gate on leaving `vast` exists only in the control plane**
    (principle 3, section 2). The helper applies any valid document it is
    handed, so a compromised agent or control plane can leave `vast` on a
    machine whose switches allow plugins; only the GPU guard remains there.
12. **Pinning of the vectorizer's build.** Images are pinned by digest
    (section 7), but the vectorizer's image is built on each machine and its
    build downloads `torch`/`torchvision` by version only and Docling's
    models without a pin (section 11).
