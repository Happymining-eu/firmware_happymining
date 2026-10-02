# HappyMining agent ⇄ API protocol (v1)

This is the contract between the Go agent (`agent/`) and the HappyMining API
(`api/`). These are **HappyMining's own endpoints**. None of them is a Vast.ai
endpoint, and the agent never talks to Vast.ai's API or holds a Vast account key.

- Base URL: configurable, e.g. `https://api.happymining.fr`. All paths below are
  relative to it.
- Transport: HTTPS with certificate verification against the system trust store
  (optionally an extra CA bundle file). Plain HTTP is accepted by the agent only
  for loopback addresses and only when `HM_ALLOW_INSECURE_LOOPBACK=1` (tests and
  local development).
- Encoding: JSON, UTF-8, `Content-Type: application/json`.
- Timestamps: RFC 3339 in UTC, e.g. `2026-10-02T07:45:00Z`.
- Request body limit: 256 KiB. Larger bodies get `413`, and are never processed
  in part.
- Every response produced by the application carries `X-Request-ID`, including
  errors.
- Rate limits, per device: every authenticated request counts against a
  general limit (default 240 a minute) before its body is validated;
  heartbeats have their own (default 60 a minute); credential rotations are
  limited per hour (default 6). An agent that follows this document stays far
  below all three.

## Error envelope

Every non-2xx response has this body:

```json
{"error": {"code": "pairing_failed", "message": "Pairing failed.", "request_id": "..."}}
```

`code` is stable and machine-readable; `message` is safe to show an operator and
never contains secrets.

| HTTP | code | Agent behaviour |
|---|---|---|
| 400 / 422 | `invalid_request` | Do not retry the same payload; log and drop it. |
| 401 | `pairing_failed` | Enrollment only. Generic on purpose (wrong, expired, used and locked codes are indistinguishable). Do not retry automatically. |
| 401 | `device_unauthorized` | Credential unknown, revoked or expired. Stop sending, keep buffering within quota, report `revoked` state locally. Do not hammer. |
| 403 | `forbidden` | Not allowed for this device. Do not retry. |
| 404 | `not_found` | Do not retry. |
| 409 | `conflict` | Operation acknowledgement replay or state conflict. Treat as final. |
| 410 | `expired` | Operation expired. Treat as final. |
| 413 | `payload_too_large` | Split the batch and retry. |
| 429 | `rate_limited` | Honour `Retry-After` (seconds), then retry with jitter. |
| 501 | `not_implemented` | Never sent to a device. Returned to the operator who requests an operation type this release does not implement. |
| 5xx / network error / timeout | — | Retry with exponential backoff and full jitter (base 5 s, cap 15 min). |

## 1. Enrollment (pairing)

`POST /api/v1/devices/enroll` — no authentication; rate limited.

A HappyMining admin creates an enrollment request for one owner and one machine
record. The API returns a pairing code **once**. The local operator types it on
the machine (`sudo happyminingctl pair`). The device never chooses its owner or
its machine: both come from the enrollment request on the server.

Pairing code format: `HM-LLLLLL-SSSS-SSSS-SSSS-SSSS`

- `LLLLLL`: 6-character locator (Crockford base32, upper-case). Not secret; it
  identifies the enrollment request so failed attempts can be counted against it.
- `SSSS-SSSS-SSSS-SSSS`: 16-character secret (Crockford base32, 80 bits).
- Input is case-insensitive; hyphens and spaces are ignored; `O`→`0`, `I`/`L`→`1`.
- Single use, short lived (default 15 minutes), locked after 5 failed attempts.

Request:

```json
{
  "pairing_code": "HM-7K2M9Q-4F8T-ZP3D-W6NH-R5XA",
  "hostname": "gpu-01",
  "machine_fingerprint": "sha256:<64 hex>",
  "agent_version": "0.1.0",
  "os": {"id": "ubuntu", "version_id": "24.04", "kernel": "6.8.0-45-generic", "arch": "amd64"}
}
```

`machine_fingerprint` is the SHA-256 of a random 32-byte install identity the
agent generates on first boot (`/var/lib/happymining/identity`). It is not
derived from hardware serial numbers.

Response `201`:

```json
{
  "device_id": "uuid",
  "machine_id": "uuid",
  "credential": {
    "id": "uuid",
    "token": "hmd_<credential id as 32 hex>.<43-char base64url secret>",
    "expires_at": null
  },
  "heartbeat_interval_s": 60,
  "server_time": "2026-10-02T07:45:00Z"
}
```

The token is shown once. The agent stores it at
`/var/lib/happymining/credential.json` (mode `0600`, owner `happymining`),
written atomically (temp file + `fsync` + `rename`).

## 2. Device authentication

Every other device request sends `Authorization: Bearer hmd_<id>.<secret>`.
The server stores only a hash of the secret. Credentials are unique per device,
revocable and rotatable.

## 3. Heartbeat and telemetry

`POST /api/v1/device/heartbeat`

```json
{
  "sent_at": "2026-10-02T07:45:00Z",
  "boot_id": "uuid",
  "agent_version": "0.1.0",
  "samples": [
    {
      "seq": 1234,
      "collected_at": "2026-10-02T07:44:58Z",
      "uptime_s": 86400,
      "synthetic": false,
      "cpu": {"model": "AMD EPYC 7543", "cores": 64, "load1": 0.42, "util_pct": 3.5},
      "memory": {"total_bytes": 270000000000, "available_bytes": 250000000000},
      "disks": [
        {"mount": "/", "fs": "ext4", "total_bytes": 500000000000, "avail_bytes": 400000000000},
        {"mount": "/var/lib/docker", "fs": "xfs", "total_bytes": 2000000000000, "avail_bytes": 1500000000000}
      ],
      "gpus": [
        {
          "index": 0,
          "uuid": "GPU-6f0c...",
          "name": "NVIDIA GeForce RTX 4090",
          "driver_version": "550.120",
          "vram_total_mib": 24564,
          "vram_used_mib": 12,
          "util_pct": 0,
          "power_w": 34.8,
          "temp_c": 41,
          "fan_pct": 30
        }
      ],
      "services": {
        "docker": "active",
        "vastai": "active",
        "nvidia-persistenced": "active"
      },
      "vast": {"daemon_installed": true, "machine_id_hint": "sha256:<64 hex>"}
    }
  ]
}
```

Rules:

- `samples`: 1 to 100 per request, oldest first. Backlog from an outage is sent
  in batches together with live samples.
- `seq`: unsigned 64-bit, strictly increasing per device, persisted on disk so it
  survives restarts. The server de-duplicates on `(device, seq)`; resending a
  sample is safe.
- Bounds: at most 32 GPUs, 16 disks, 16 services per sample; strings at most 128
  characters. Unknown numeric values are sent as `null`, never as `0`.
- Service states: `active`, `inactive`, `failed`, `activating`, `not-installed`,
  `unknown`.
- `vast.machine_id_hint` is the SHA-256 of the host-local Vast machine identifier
  if the official Vast host software is installed. It is **untrusted evidence**
  shown to an operator. It never binds a machine by itself.
- `synthetic` is `true` only for simulator output. The API refuses synthetic
  samples in LIVE mode.
- The agent never collects renter files, container contents, prompts, datasets,
  process command lines of renter workloads, or environment variables.
- `appliance` (optional, next to `samples`): the appliance state of the
  machine, defined in `docs/appliance.md`, section 6.1. The agent built with
  the appliance always sends it (at most 64 KiB encoded); an agent that does
  not know about it sends nothing, and then nothing below about the
  appliance applies to it. When the privileged helper does not answer, the
  object says `"control": "unknown"`, `"mode": "unknown"`,
  `"apply_status": "disabled"`, with the reason in `apply_detail`. The API
  keeps only the listed keys and values, bounds and redacts every string,
  and uses none of it for authorisation.

Response `200`:

```json
{
  "accepted": 3,
  "duplicates": 1,
  "rejected": 0,
  "highest_seq": 1234,
  "server_time": "2026-10-02T07:45:00Z",
  "next_interval_s": 60,
  "operations": []
}
```

`rejected` counts samples dropped by the server (for example a `collected_at`
more than 10 minutes in the future or older than 7 days). The agent deletes all
samples in an acknowledged batch from its spool whatever the split between
accepted, duplicate and rejected.

`operations` lists pending operations (section 4).

`appliance` is present only when the request carried an `appliance` object
and the machine has a cloud configuration (revision at least 1):

```json
{"appliance": {"revision": 12, "document": { … }}}
```

`document`, the desired-state document of `docs/appliance.md` section 4 with
its sealed secrets, is included when the request's `applied_revision` differs
from `revision`, and only when the request said `"control": "cloud"`: not
under `local` (the machine ignores it) and not under `unknown` (its helper
did not answer, so it could not apply it). The
agent checks its size (64 KiB) and that its `revision` matches, and hands it
to the root helper, which validates it again against the catalog installed
on the machine. An agent that sent no `appliance` object gets no
`appliance` key back.

## 4. Typed operations

There is no remote shell. The server can only request an operation from a fixed
allowlist, and the agent independently enforces its own local allowlist.

Operation object:

```json
{
  "id": "uuid",
  "type": "collect_diagnostics",
  "params": {"sections": ["services", "gpu", "disk"]},
  "issued_at": "2026-10-02T07:45:00Z",
  "expires_at": "2026-10-02T07:55:00Z",
  "nonce": "<22+ char base64url>"
}
```

| type | params | Agent default | Effect |
|---|---|---|---|
| `refresh_inventory` | `{}` | enabled | Re-read hardware inventory, send in next heartbeat. |
| `collect_diagnostics` | `{"sections": [...]}` from `services`, `gpu`, `disk`, `network`, `agent` | enabled | Read-only, redacted summary returned in `result`. |
| `run_preflight` | `{}` | enabled | Read-only preflight, PASS/WARN/FAIL list in `result`. |
| `rotate_credential` | `{}` | enabled | Agent calls the rotate endpoint. |
| `restart_vast_daemon` | `{}` | **disabled** | Via privileged helper. |
| `reboot` | `{"delay_s": 60..3600}` | **disabled** | Via privileged helper. The server only issues 60..300, so that the reboot happens while the rental check that allowed it is still fresh. |
| `run_benchmark` | `{"duration_s": 30..600}` | **disabled** | Reserved. Not implemented in agent 0.1.0; the server refuses to queue it (`501`). |
| `apply_hardware_profile` | `{"profile_id": "<id>"}` | **disabled** | Reserved. Not implemented in agent 0.1.0; the server refuses to queue it (`501`). |
| `appliance_run_job` | `{"job": J}` with J one of `vectorize_sync`, `backup_run`, `update_check`; or exactly `{"job": "plugin_restart", "plugin": "<plugin id>"}` (`^[a-z][a-z0-9-]{0,30}$`) | enabled | Starts one of HappyMining's own appliance jobs. `update_check` runs in the agent; the others are started by the helper, which needs `ALLOW_PLUGINS` (`vectorize_sync`, `plugin_restart`) or `ALLOW_BACKUP` (`backup_run`). One final acknowledgement: `succeeded` once the job is started. Progress is in the heartbeat's `appliance` object. |
| `install_update` | exactly `{"version": "MAJOR.MINOR.PATCH"}` | enabled | Downloads, checks and hands that release to the helper (`ALLOW_UPDATE`), which verifies and installs it (`docs/appliance.md`, section 9). Acknowledged `accepted` at once, final acknowledgement when the hand-off is done. |

The two appliance types are not disruptive for renters and are enabled by
default in the agent: the helper's root-owned switches are the gate, all off
by default. The server queues them only through the machine's appliance
routes (`docs/appliance.md`, section 12), never through the general
operation routes or the integration API. An agent that does not know them
rejects them as unknown types.

Agent rules:

1. Reject unknown types, extra or invalid params, expired operations
   (`expires_at` in the past by the local clock), and any operation `id` already
   recorded in the local journal (`/var/lib/happymining/ops.journal`) — replay
   protection.
2. Disabled types are rejected unless enabled in the root-owned local config.
   Enabling is a deliberate act by the machine's local administrator.
3. Record the operation `id` in the journal **before** executing.
4. Acknowledge with the same `nonce`.

`POST /api/v1/device/operations/{id}/ack`

```json
{
  "status": "accepted",
  "nonce": "<same nonce>",
  "detail": "short human-readable text, at most 2000 characters",
  "result": {},
  "completed_at": "2026-10-02T07:45:10Z"
}
```

`status` is one of `accepted` (starting), `rejected`, `succeeded`, `failed`.
`rejected`, `succeeded` and `failed` are final. A second final acknowledgement
returns `409 conflict`. An acknowledgement after expiry returns `410 expired`.
`result` is at most 64 KiB and is redacted by the agent before sending. The
server enforces the size and redacts `detail` and `result` again before
storing them; an agent must still never put a credential in either.

An operation that was already handed to the device is not sent a second time
if the rental check has since closed, and its record is not rewritten: the
device may have started it. Its acknowledgement is still accepted.

An operation that has not been handed to the device yet is cancelled at
delivery when whoever requested it may no longer have it carried out: staff
or a fleet-wide API client on a machine managed by its owner, once the
remote-access grant expired or was revoked or the machine changed owner; a
person of the owner's organisation, or a client limited to that owner, once
the machine changed owner; a person who was deactivated or lost the role
(`services/remote_access.py`). A device never sees such an operation.

`install_update` runs in the background so that telemetry keeps flowing: the
agent acknowledges `accepted`, then `succeeded` or `failed` when the
download and the hand-off to the helper are done. If the operation is handed
over again meanwhile, the agent answers `accepted` again and starts nothing.
A download can outlast the operation's lifetime (`HM_OPERATION_TTL_S`,
default 600 s); the final acknowledgement then gets `410 expired`, and the
reported `update` state is what tells whether the release was installed.
`succeeded` means the helper verified and staged the package and started
the installation, not that `dpkg` finished.

`GET /api/v1/device/operations` returns `{"operations": [...]}` (same objects).

## 5. Credential rotation

`POST /api/v1/device/credential/rotate` with the current credential.

Response `200`: `{"credential": {"id": "...", "token": "hmd_...", "expires_at": null}}`

The agent writes the new credential atomically, then uses it. The old credential
stays valid until the new one is first used, or for at most 24 hours, so a crash
between the response and the write cannot lock the device out.

## 6. Self

`GET /api/v1/device/self` →
`{"device_id": "uuid", "machine_id": "uuid", "status": "active", "server_time": "..."}`

Used by `happyminingctl status` to check connectivity and credential validity.

## 7. Firmware updates

Defined in `docs/appliance.md`, sections 6.6 and 9. Device credential only.

`GET /api/v1/device/update` →

```json
{"channel": "stable", "policy": "auto", "window": {"start_hour": 2, "end_hour": 5},
 "release": {"version": "0.2.0", "manifest_b64": "…", "signature_b64": "…",
             "size": 9412345, "sha256": "…", "artifact_path": "/api/v1/device/update/artifact/0.2.0"}}
```

- `channel` `stable`, `beta` or `none`; `policy` `manual` or `auto`; both
  from the machine's cloud configuration (`none` and `manual` when it has no
  `update` section; `window` is then `null`).
- `release` is the newest release on that channel that is newer than the
  `agent_version` the device last reported and whose `min_upgrade_from` is
  not newer than it, signed with a key the server still trusts; `null`
  otherwise, also when the reported version cannot be compared.
- `manifest_b64` is the signed manifest, byte for byte; the agent forwards it
  with `signature_b64` to the helper, which verifies it with the keys
  installed on the machine. The agent itself only checks that the manifest
  and the offer agree.

`GET /api/v1/device/update/artifact/{version}` → the package bytes,
`application/octet-stream`. `version` is at most 24 characters. `404
not_found` for a version that is not offered on the machine's channel (or
has no package). At most 12 downloads an hour per device (`429
rate_limited`), on top of the general per-device limit. The agent writes the
download to `/var/lib/happymining/updates/` and gives up after 2 minutes
without data.

The agent asks for the offer 2 minutes after it starts, then every 6 hours,
only while the helper reports the `update` capability, and when an
`update_check` job or an `install_update` operation asks for it. It installs
only an `install_update` operation's exact version, or with `policy: auto`
inside the window. The control plane queues `install_update` only for the
release the machine is offered (the newest installable one on its channel);
the offer carries only that release's manifest and signature.

## Outage behaviour

A HappyMining API outage must never stop Vast hosting. The agent only observes
and reports; it has no role in the rental data path. When the API is
unreachable the agent keeps collecting, buffers samples on disk within its
quota (oldest dropped first when full), and retries with jitter. It executes no
new operations while disconnected, because operations only arrive in responses.

The appliance keeps running during an outage: plugins, mounts, the index,
the schedules and backups are on the machine. The agent keeps asking the
helper for its state and keeps starting the schedules. No new document and
no update can arrive.
