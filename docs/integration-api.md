# Integration API

How other software manages the AI servers. Written for **Mole Hash**, the
fleet manager HappyMining already runs for its ASIC miners, so that the GPU
servers appear and can be managed in the same place.

Code: `api/happymining/routers/integration.py`,
`api/happymining/services/api_clients.py`. A ready-made Python client is in
`integrations/molehash/`.

```
Mole Hash backend ──HTTPS, API client token──► HappyMining OS API ──► agents on the AI servers
   (ASIC miners: its own scanners, as today)        (this document)
```

It is a server-to-server API. The machines themselves expose nothing: the
agent on an AI server listens on no port, and that does not change. Mole Hash
talks to the central API, which already knows the fleet.

## Getting a token

An admin creates an **API client** on the dashboard (Integrations) or with
`POST /api/v1/api-clients`, and chooses:

- a name (unique), an optional description and an optional expiry;
- the **scopes** (below);
- optionally one owner, which limits the client to that owner's machines and
  earnings. Without it the client sees the whole fleet.

The token (`hmc_<32 hex>.<43 characters>`) is shown **once**. Only a keyed
hash is stored. If it is lost, rotate the client: a new token is issued and
the old one stops working at once. Revoking a client is final: its token is
refused from then on, and the operations it had queued that no machine has
received yet are cancelled. The same happens to the queued operations of a
client that expires. An operation a machine has already received is not
recalled.

Keep the token in the environment of the Mole Hash **backend**. Never send it
to a browser and never commit it.

## Scopes

| Scope | Allows |
|---|---|
| `fleet:read` | List machines: connection state, hardware, provider binding, rental state. |
| `telemetry:read` | GPU, CPU, memory, disk and service telemetry. |
| `operations:read` | List operations and their results. |
| `operations:write` | Request non-disruptive typed operations, and cancel the client's own while they are still pending. |
| `operations:disruptive` | Also request operations that can interrupt a renter (Vast daemon restart, reboot). Needs `operations:write`. |
| `earnings:read` | Reported and received earnings per machine and day. |

There is no scope for moving money, recording receipts, payouts, fees, users,
pairing codes, provider bindings, beneficiary details or the audit trail. A
client cannot be given any of them.

## Calling it

- Base: `https://<host>/api/v1/integration`.
- `Authorization: Bearer <token>` on every request. Nothing else is accepted
  here: not a browser session, not a device credential. And the token opens
  nothing outside this base path.
- JSON in, JSON out. Timestamps are RFC 3339 UTC. **Money is a decimal string**
  with eight decimals; parse it as a decimal, never as a float.
- Errors use the envelope
  `{"error": {"code": "...", "message": "...", "request_id": "..."}}`.
- Rate limit: 600 requests a minute per client by default
  (`HM_INTEGRATION_RATE_LIMIT_PER_MINUTE`). Over it: `429` with `Retry-After`.
- Lists are paged with `limit` and `offset` and return `total`. Machines and
  operations: 50 by default, at most 200. Daily earnings: 200 by default, at
  most 1000.

| HTTP | code | Meaning |
|---|---|---|
| 400 / 422 | `invalid_request` | The request is wrong. Do not retry it unchanged. |
| 401 | `client_unauthorized` | Token missing, malformed, unknown, revoked or expired. All look the same. |
| 403 | `forbidden` | The client lacks the scope named in the message. |
| 404 | `not_found` | No such object, or it is outside the client's owner. |
| 409 | `maintenance_blocked` | The rental-protection gate refused a disruptive operation. See below. |
| 409 | `conflict` | State conflict, for example cancelling an operation already delivered, or an idempotency key reused for something else. |
| 409 | `too_many_open_operations` | The client already has 8 operations queued or running on that machine. Wait or cancel. |
| 429 | `rate_limited` | Wait `Retry-After` seconds. Also answered to an address that keeps presenting refused tokens. |
| 501 | `not_implemented` | The operation type exists in the protocol and is not implemented. |

## Endpoints

### `GET /` — who am I

Needs no particular scope. Use it as the connection test.

```json
{
  "api": "happymining-integration", "api_version": 1, "server_version": "0.1.0",
  "mode": "demo", "synthetic_data": true, "server_time": "2026-10-02T13:20:00+00:00",
  "client": {"id": "…", "name": "Mole Hash", "scopes": ["fleet:read", "telemetry:read"], "owner_id": null, "expires_at": null},
  "limits": {"requests_per_minute": 600}
}
```

`mode` is `demo` or `live`. In `demo` **every machine, sample and amount is
synthetic**; each object also carries `"synthetic": true`. Show that in Mole
Hash rather than mixing it with real miners.

### `GET /fleet/summary` — `fleet:read`

Machine counts by connection state. With `telemetry:read`, also the totals of
the machines reporting right now (`online_now`: GPUs, power, average
utilisation, hottest GPU).

### `GET /machines`, `GET /machines/{id}` — `fleet:read`

```json
{
  "kind": "gpu_server",
  "id": "8c1e…", "label": "rack-2-gpu-07", "hostname": "gpu-07",
  "owner_id": "5a4d…", "status": "active", "synthetic": false,
  "connection": "online", "last_seen_at": "…", "last_seen_age_s": 12, "agent_version": "0.1.0",
  "hardware": {"gpus": [{"index": 0, "name": "RTX 4090", "vram_total_mib": 24564, "driver_version": "550.120"}],
               "cpu_model": "…", "cpu_cores": 32, "memory_total_bytes": 137438953472, "vast_daemon_installed": true},
  "provider": {"provider": "vast", "external_id": "12345", "rental_state": "unknown", "listed": null,
               "state_observed_at": "…", "state_stale": false, "state_detail": "…", "missing_from_provider": false},
  "latest_telemetry": {"collected_at": "…", "synthetic": false, "gpu_count": 2,
                       "gpu_util_avg": 41.5, "gpu_power_w": 402.8, "gpu_temp_max": 59.0},
  "created_at": "…"
}
```

- `connection`: `online`, `stale` (no heartbeat for five minutes),
  `paired_never_seen`, `unpaired`, `revoked`.
- `provider` is `null` until an admin has bound the machine to a provider
  machine. `rental_state` is `unknown` in LIVE today: Vast does not expose it.
- `latest_telemetry` is present only with `telemetry:read`.
- A client limited to one owner sees a machine's telemetry and operations from
  the day the machine became that owner's, not what happened before.
- Telemetry comes from the agent on the owner's machine. It is informational:
  an owner with root can alter it. It never decides money or maintenance.

### `GET /machines/{id}/telemetry` — `telemetry:read`

Query: `since`, `until` (RFC 3339), `limit` (default 100, at most 1000).
Newest first. Each sample has the summary fields and `payload` with the
per-GPU, CPU, memory, disk and service detail, and whether Vast's host daemon
is installed. Samples are kept 30 days by default. Nothing about renters'
workloads is collected.

### `GET /operation-types`, `GET /operations`, `GET /operations/{id}` — `operations:read`

`/operations` filters on `status` and `machine_id`. An operation:

```json
{"id": "…", "machine_id": "…", "type": "refresh_inventory", "params": {}, "status": "succeeded",
 "issued_at": "…", "expires_at": "…", "delivered_at": "…", "completed_at": "…",
 "detail": "…", "result": {}, "safety": {"allowed": true, "reasons": []},
 "requested_by": "self"}
```

`requested_by` says who asked, as a kind: `self` (this client), `client`
(another one), `user` (a person on the dashboard) or `system`. Ids of people
and of other clients are not given.

Statuses: `pending` → `delivered` → `accepted` → `succeeded` | `failed` |
`rejected`; or `expired`, `cancelled`, `blocked`.

### `POST /machines/{id}/operations` — `operations:write`

```
Idempotency-Key: molehash-action-8841        (required, 8 to 128 characters)
{"type": "collect_diagnostics", "params": {"sections": ["gpu", "services"]}}
```

`201` with the operation. The machine receives it with one of its next
heartbeats (one a minute; the agent is handed its oldest open operations
first) and the result appears on `GET /operations/{id}`. An operation not
acknowledged within ten minutes becomes `expired`. A client may have at most 8
operations queued or running on one machine.

| type | params | Notes |
|---|---|---|
| `refresh_inventory` | `{}` | Re-read the hardware inventory. |
| `collect_diagnostics` | `{"sections": [...]}` of `services`, `gpu`, `disk`, `network`, `agent` | Read-only summary in `result`. |
| `run_preflight` | `{}` | Read-only checks, PASS/WARN/FAIL in `result`. |
| `rotate_credential` | `{}` | The agent replaces its own credential. |
| `restart_vast_daemon` | `{}` | **Disruptive.** |
| `reboot` | `{"delay_s": 60..300}` | **Disruptive.** |
| `run_benchmark`, `apply_hardware_profile` | | Not implemented: `501`. |

There is no free-form command. Unknown types and unknown parameters are
refused.

**Idempotency.** Send the same key when retrying after a timeout or a crash:
the first operation is returned with `200` and nothing new is queued. The same
key for a different machine, type or parameters is `409`. Use the id of the
action in Mole Hash as the key. A replay returns the operation as it is *now*,
which may be `succeeded`, `cancelled` or `expired`: read `status`. To try
again after any of those, use a new key.

**Disruptive operations** need, all at once:

1. the `operations:disruptive` scope;
2. `HM_DISRUPTIVE_OPERATIONS_ENABLED=true` on the server;
3. the rental-protection gate: the provider must confirm that the machine is
   unlisted and has no active contract, no stopped instance and no stored
   customer data. An unknown state blocks. Zero GPU utilisation proves nothing;
4. the machine's own administrator having enabled that operation locally.

When the gate refuses, the answer is `409 maintenance_blocked` with the reason,
and the refusal is on record as a `blocked` operation. The same key gives the
same answer; trying again later needs a new key. **In LIVE today the gate
always refuses**, because Vast's documented API does not expose the rental
state. Restarting or rebooting a rented machine stays an operator procedure
(`docs/os-maintenance.md`). Mole Hash should present these two actions as
unavailable for AI servers rather than as failing buttons.

### `POST /operations/{id}/cancel` — `operations:write`

Only the client's own operations (`403` otherwise), and only while `pending`.
Once delivered, the machine may already be executing it: `409`.

### `GET /earnings/daily`, `GET /earnings/summary` — `earnings:read`

Query: `start`, `end` (dates; closed UTC days only, so `end` is yesterday at
the latest; default the last 30), `machine_id` (daily only).

```json
{"day": "2026-10-01", "machine_id": "…", "owner_id": "…", "provider_machine_id": "12345",
 "attributed": true, "currency": "USD",
 "reported": "100.00000000", "received": "0.00000000",
 "fee_reported": "10.00000000", "owner_share_reported": "90.00000000",
 "fee_reconciled": "0.00000000", "owner_share_reconciled": "0.00000000",
 "revisions": 1, "synthetic": true}
```

- `reported` is what the provider says the machine earned that day. **It is
  not cash.** `received` is the part HappyMining has seen on its own bank or
  payout-provider statement and reconciled. Do not show `reported` as revenue
  collected.
- Days are attributed to the machine and owner that had the provider machine
  on that day. `attributed: false` rows (no machine, no owner) are earnings of
  provider machines nobody is bound to; only fleet-wide clients see them.
- In LIVE today reports are fetched and held, not posted, until the provider's
  earnings semantics are verified (`docs/ledger.md`). Until then this list is
  empty in LIVE.
- Read only. Nothing about money can be changed through this API.

## What is audited

Creating, rotating and revoking a client (by the admin who did it), and every
operation a client requests or cancels, with the client as the actor. Reads
are not audited: after a leak there is no record of what was read. The
client's last use (time and address, to the minute) is kept, and refused
tokens are logged with the caller's address.

## Limits of this version

- Polling only. No webhooks or event stream.
- No pairing, owner or user management, and no provider binding through this
  API. Those stay admin actions on the dashboard.
- No filter on connection state in `/machines`; filter on the caller's side.
- One token per client. Rotation has no overlap period: update the caller
  right after rotating.
