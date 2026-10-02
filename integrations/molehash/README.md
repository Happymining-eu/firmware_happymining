# Mole Hash connector

What Mole Hash needs to show and manage the AI servers next to the ASIC
miners. The API it talks to is described in `docs/integration-api.md`.

**State: the HappyMining side is built and tested. The Mole Hash side is not
wired.** The source of the Mole Hash manager (the `mine_manager` stack on the
VPS: `mining-manager-api`, its scanner and the `pickaxe-agent`) lives on the
server under `/opt/app/mine_manager/source` and is not in a repository this
work had access to. (`WumauCoding/molehash-repo` is the earlier ASIC
profitability API, not the manager.) So this directory contains the client
and the instructions, not a change to Mole Hash.

## What is here

`happymining_client.py`: one file, Python 3.8+, standard library only. Copy it
into the Mole Hash backend. It is tested against the real API
(`tests/api/test_integration_api.py`).

```python
from happymining_client import HappyMiningClient, HappyMiningError, to_device_record

hm = HappyMiningClient(os.environ["HAPPYMINING_API_URL"], os.environ["HAPPYMINING_API_TOKEN"])

info = hm.describe()                 # mode (demo / live), scopes
for machine in hm.machines():        # every AI server the token may see
    row = to_device_record(machine)  # a flat record; adapt it to Mole Hash's device model
    ...

try:
    op = hm.request_operation(machine_id, "collect_diagnostics", {"sections": ["gpu"]},
                              idempotency_key=f"molehash-action-{action.id}")
except HappyMiningError as exc:
    if exc.blocked_by_rental_protection:
        ...                          # the machine may be rented; show the reason, do not retry
```

## Wiring it into Mole Hash

1. **Create the token.** HappyMining OS dashboard → Integrations → New API
   client, name "Mole Hash". Start with `fleet:read`, `telemetry:read`,
   `operations:read`; add `operations:write` when actions are wanted, and
   `earnings:read` if Mole Hash should show earnings.
2. **Give it to the Mole Hash backend**, as environment variables of
   `mining-manager-api` (not in the compose file itself, and never in the
   front end):

   ```
   HAPPYMINING_API_URL=https://<the HappyMining OS host>
   HAPPYMINING_API_TOKEN=hmc_...
   ```

   Check from inside the container:
   `python happymining_client.py describe`.
3. **Sync.** A periodic job in the backend (every minute is plenty; telemetry
   arrives once a minute per machine) that calls `hm.machines()` and upserts
   the AI servers into Mole Hash's device table, keyed on
   `("happymining-os", machine["id"])`. Machines that disappear from the list
   are retired, not deleted.
4. **Show them** in the same fleet views, as a second device type.
5. **Actions.** Map Mole Hash's action buttons to typed operations, using the
   Mole Hash action id as the idempotency key, and poll
   `hm.operation(op["id"])` for the result.

Both stacks run on the same VPS, but go through the public host name anyway:
the API only answers the host names it is configured for, and the token should
travel over TLS.

## ASIC miners and AI servers are not the same thing

| In Mole Hash for an ASIC | For an AI server | Where it comes from |
|---|---|---|
| Online / offline | `connection` | agent heartbeat, once a minute |
| Hashrate | no equivalent; GPU utilisation is the closest reading | `latest_telemetry.gpu_util_avg` |
| Power | `latest_telemetry.gpu_power_w` (GPUs only, not the whole machine) | `nvidia-smi` |
| Temperature | `latest_telemetry.gpu_temp_max` | `nvidia-smi` |
| Pool, worker | the marketplace: `provider.provider`, `provider.external_id`, `rental_state`, `listed` | Vast, through HappyMining OS |
| Mined coins per day | `reported` earnings per day, in USD | provider report; **not cash until `received`** |
| Reboot, restart miner | `reboot`, `restart_vast_daemon` | blocked while the machine may be rented, and always blocked in LIVE today |
| Change pool, firmware, frequency | none | not offered; GPU firmware is never flashed |

Two differences matter for the UI:

- **An AI server may be running a customer's job.** A reboot button that
  always works for a miner must not exist for an AI server. Request the
  operation and show the reason when it is refused.
- **DEMO data is synthetic.** `describe()["mode"]` and the `synthetic` flag on
  every object say so. Keep it visibly apart from real devices.

## Not done

- No change inside Mole Hash: no routes, no database fields, no pages.
- No push from HappyMining OS to Mole Hash (webhooks); Mole Hash polls.
- The client has no async variant.
