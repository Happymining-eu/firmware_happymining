# Integration evidence: Vast.ai host API, host software, Ubuntu autoinstall, nvidia-smi

Access date for every source in this file: **2026-10-02**.

This file records what primary sources say about the external systems HappyMining OS
integrates with. It is evidence, not design. Nothing here is a HappyMining endpoint
(see the last section).

## How to read this

Every finding carries one of three statuses.

| Status | Meaning |
| - | - |
| **Confirmed (docs)** | Read on a documentation page published by Vast.ai, Canonical or NVIDIA. |
| **Confirmed (official CLI source)** | Read directly, on disk, in the unpacked `vastai` wheel from PyPI. These snippets are byte-exact; file hashes are in the source table. |
| **Unresolved** | Not found in any primary source that could be read. Do not code against it. |

One extra label is used only in section E: **Confirmed (official host script)**. It marks
facts taken from the two scripts Vast serves itself (the host installer and uninstaller).
They are Vast's own code, but they are neither documentation nor the CLI.

Two limits on the quotations, which apply to everything except the CLI source:

1. Web pages were read through a fetch tool that converts the page and extracts text.
   OpenAPI blocks and most long passages came back whole; some pages came back as
   extracts. A quotation here is what the tool returned. Before relying on the exact
   wording of a quotation (as opposed to the fact), re-read the page.
2. The host installer and uninstaller were read the same way, as extracts of a long
   script. No hash could be taken. Treat those code lines as indicative and re-verify
   them against the script before depending on any one of them.

Where the documentation and the CLI disagree, both are given and the row is marked
**Docs and CLI disagree**. The task rule was that the CLI source is the tie-breaker.

## Sources

### Vast.ai CLI (read on disk)

| Item | Value |
| - | - |
| Package | `vastai` (PyPI), resolved by `pip download vastai --no-deps` on 2026-10-02 |
| Version | 1.8.2 |
| File | `vastai-1.8.2-py3-none-any.whl` |
| sha256 (wheel) | `6b6a10fa011973cf625889189f7ba1120f2bf4925170d2ecb11ca99de616d885` |
| Project URLs in metadata | Homepage `https://vast.ai`, Repository `https://github.com/vast-ai/vast-cli` |

The package no longer contains a single `vast.py`. The functions that used to live there
are split between `vastai/api/*.py` (HTTP calls) and `vastai/cli/commands/*.py`
(argument parsing, help text, output). Files inspected:

| File in wheel | sha256 | Used for |
| - | - | - |
| `vastai/api/client.py` | `c7b06d5eb25cbf9e01042fc7ef4afab159b8fce80346af849d91d645f19dad91` | Base URL, `/api/v0` prefix, auth header, retries, timeout |
| `vastai/api/machines.py` | `6724080bf611369580e1328a17867383d1b3e72c2f459efcccb038e7109c2b92` | Machine endpoints |
| `vastai/api/billing.py` | `5e101f6173234458a69f706e9c2f95adb12534fa773ca4c2ec87d57361f1ca8a` | Earnings, invoices, user |
| `vastai/api/keys.py` | `1f10251cefc98f92ab2a14024983e5aa6a35c0e4892492601dd98e7b0cfde546` | API key creation |
| `vastai/cli/commands/machines.py` | `1c58876ada8c3912550396a6b2862e5de565c68b53c84554eb368e2140dc66d3` | Host command help text and semantics |
| `vastai/cli/commands/billing.py` | `92d66d4b2247f847aec3e7866c557e192109aaf03ac2746ea2cdbdb644f695f9` | `show earnings`, `show invoices-v1` |
| `vastai/cli/display.py` | `9a9772f09672d2b9be7b3228898056d536c1ca83b3e7bdef28c365e5f99d99c9` | Fields the CLI prints for machines and maintenance windows |
| `vastai/cli/main.py` | `671ac4ba83804b5fed0832651195036f81a9c99144c1d30e032c2a6bc62ceaa6` | `--retry` default, key lookup order |
| `vastai/cli/util.py` | `c1963374ddf6e7483afffbe8a607f6d1a58bafd915cd4b85a0fb778012cd83d8` | Key file path, `detect_role`, bandwidth floor |
| `vastai/cli/self_test/machine_diagnostics.py` | not hashed | Self-test requirement thresholds |
| `vastai/api/price_increase.py` | not hashed | Only place a "platform fee" field name appears |

### Web pages

| URL | Used for |
| - | - |
| https://docs.vast.ai/llms.txt | Index of the documentation; used to find every page below |
| https://docs.vast.ai/api-reference/introduction.md | Base URL |
| https://docs.vast.ai/api-reference/authentication.md | Auth header, key lifecycle |
| https://docs.vast.ai/api-reference/permissions.md | Permission categories and endpoint mapping |
| https://docs.vast.ai/cli/permissions.md | Scoped key file format, constraints |
| https://docs.vast.ai/guides/reference/api-keys.md | Key creation, default scope, reset and delete |
| https://docs.vast.ai/guides/reference/keys.md | Keys page in the console |
| https://docs.vast.ai/api-reference/rate-limits-and-errors.md | Rate limits, 429, error shape |
| https://docs.vast.ai/cli/rate-limits.md | Documented CLI retry behaviour |
| https://docs.vast.ai/cli/authentication.md | Key file location and precedence |
| https://docs.vast.ai/api-reference/machines/show-machines.md | Machine inventory endpoint |
| https://docs.vast.ai/api-reference/machines/show-reports.md | Reports endpoint |
| https://docs.vast.ai/api-reference/machines/unlist-machine.md | Unlist |
| https://docs.vast.ai/api-reference/machines/list-machine.md | List |
| https://docs.vast.ai/api-reference/machines/schedule-maint.md | Schedule maintenance |
| https://docs.vast.ai/api-reference/machines/cancel-maint.md | Cancel maintenance |
| https://docs.vast.ai/api-reference/machines/cleanup-machine.md | Cleanup |
| https://docs.vast.ai/api-reference/machines/set-min-bid.md | Minimum bid |
| https://docs.vast.ai/api-reference/machines/remove-defjob.md | Remove default job |
| https://docs.vast.ai/api-reference/billing/show-earnings.md | Earnings endpoint |
| https://docs.vast.ai/api-reference/billing/show-invoices.md | Invoices and payouts, pagination |
| https://docs.vast.ai/api-reference/billing/show-charges.md | Renter-side charges (pagination reference only) |
| https://docs.vast.ai/api-reference/accounts/show-user.md | Current user |
| https://docs.vast.ai/api-reference/accounts/create-api-key.md | Key creation endpoint |
| https://docs.vast.ai/api-reference/accounts/create-subaccount.md, `.../show-subaccounts.md` | Subaccounts |
| https://docs.vast.ai/cli/reference/show-earnings.md, https://docs.vast.ai/sdk/python/reference/show-earnings.md | CLI and SDK earnings pages |
| https://docs.vast.ai/host/cli/show-machines.md, `show-machine.md`, `list-machine.md`, `unlist-machine.md`, `schedule-maint.md`, `cancel-maint.md`, `show-maints.md`, `cleanup-machine.md` | Host CLI pages |
| https://docs.vast.ai/host/hosting-overview.md | Host duties, contracts, unlisting, maintenance |
| https://docs.vast.ai/host/verification-stages.md | Verification states and minimum requirements |
| https://docs.vast.ai/host/understanding-verification.md | Verification criteria |
| https://docs.vast.ai/host/how-to-self-test.md | Self-test |
| https://docs.vast.ai/host/set-maintenance-window.md | Maintenance window semantics |
| https://docs.vast.ai/host/upgrade-docker-and-packages.md | Rental checks, daemon, holds, Docker config |
| https://docs.vast.ai/host/upgrade-kernel.md | Kernel upkeep, 48 hour notice |
| https://docs.vast.ai/host/machine-offline.md | Service name, paths, do-not-touch rules |
| https://docs.vast.ai/host/vms.md, `disable-ssh-password-login.md`, `datacenter-status.md`, `notifications.md`, `machine-metrics.md`, `optimization-guide.md`, `guide-to-taxes.md`, `earning.md` | Supporting host pages |
| https://docs.vast.ai/host/payment.md | Payouts |
| https://docs.vast.ai/guides/reference/billing.md, `faq/billing.md`, `faq/general.md`, `faq/rental-types.md`, `faq/security.md`, https://docs.vast.ai/guides/instances/pricing.md, `choosing/instance-types.md`, `manage-instances.md`, https://docs.vast.ai/guides/pricing.md | Renter-side billing and instance lifecycle |
| https://docs.vast.ai/guides/teams/teams-overview.md | Teams |
| https://docs.vast.ai/guides/reference/notification-webhooks.md | Notification webhooks |
| https://vast.ai/terms/ | Terms of Service ("Version Date: September 1, 2026") |
| https://console.vast.ai/faq/ | Legacy FAQ (footer "© 2022 vast.ai"); only source found for a fee percentage |
| https://vast.ai/article/january-product-update | Changelog line mentioning a platform fee on the earnings PDF |
| https://console.vast.ai/install, which redirects (HTTP 302) to https://s3.amazonaws.com/public.vast.ai/kaalia/scripts/vast_host_installer.py | Host installer script |
| https://s3.amazonaws.com/vast.ai/uninstall (linked from hosting-overview) | Host uninstaller script |
| https://canonical-subiquity.readthedocs-hosted.com/en/latest/tutorial/providing-autoinstall.html | How autoinstall is provided |
| https://canonical-subiquity.readthedocs-hosted.com/en/latest/reference/autoinstall-reference.html | Autoinstall keys |
| https://canonical-subiquity.readthedocs-hosted.com/en/latest/reference/autoinstall-schema.html | Schema |
| https://canonical-subiquity.readthedocs-hosted.com/en/latest/howto/autoinstall-validation.html | Validation script |
| https://canonical-subiquity.readthedocs-hosted.com/en/latest/howto/autoinstall-quickstart.html | Kernel command line, seed volume |
| https://canonical-subiquity.readthedocs-hosted.com/en/latest/explanation/zero-touch-autoinstall.html | Confirmation prompt |
| https://canonical-subiquity.readthedocs-hosted.com/en/latest/intro-to-autoinstall.html | Supported releases |
| https://docs.nvidia.com/deploy/nvidia-smi/index.html | nvidia-smi manual |
| https://nvidia.custhelp.com/app/answers/detail/a_id/3751/~/useful-nvidia-smi-queries | NVIDIA support article with example queries (updated 09/29/2021) |

### Pages that could not be read

| URL | What happened |
| - | - |
| https://cloud.vast.ai/host/setup/ | Fetched, but it is a JavaScript console page: only the title "Vast.ai \| Console" and metadata came back. Its content is **not** in this file. hosting-overview calls it "the official documentation for setting up a machine". |
| https://cloud.vast.ai/host/agreement | Same: console shell only. The hosting agreement text was not read. |
| https://docs.vast.ai/api-reference/openapi.yaml | Truncated by the fetch tool. The per-endpoint pages were used instead. |
| https://vast.ai/faq | Redirects to https://docs.vast.ai/guides/reference/faq; the FAQ sub-pages listed above were read. |
| https://enterprise-support.nvidia.com/s/article/Useful-nvidia-smi-Queries-2 and one other article on that site | JavaScript shell only, no content. |

Several first fetches were refused by a permission prompt that timed out; all of those
succeeded on retry and are listed above.

---

## A. Vast API basics

### A1. Base URL and version path

**Confirmed (docs) and Confirmed (official CLI source).**

- Docs (api-reference/introduction): base is `https://console.vast.ai/api/v0`.
  Every per-endpoint OpenAPI block has `servers: - url: https://console.vast.ai`.
- CLI `vastai/api/client.py`:

  ```python
  server_url_default = os.getenv("VAST_URL") or "https://console.vast.ai"
  ...
          if not re.match(r"^/api/v(\d)+/", subpath):
              subpath = "/api/v0" + subpath
  ```

- One endpoint in scope uses v1: `GET /api/v1/invoices` (docs and CLI).
- The installer script talks to a different default host, `https://vast.ai` (section E).
  That is the installer's business, not the adapter's.

### A2. Authentication

**Confirmed (docs) and Confirmed (official CLI source).** Header, not query parameter.

- Docs (authentication): "Include your key as a Bearer token in the `Authorization` header".
  OpenAPI: `securitySchemes: BearerAuth: type: http, scheme: bearer`.
- CLI `client.py`:

  ```python
          result = {"User-Agent": self.user_agent}
          if self.api_key is not None:
              result["Authorization"] = "Bearer " + self.api_key
  ```

  `user_agent` is `vastai-{client_type}/{VERSION}`.
- The rate-limit page lists "`api_key` query param" as one input to the rate-limit
  identity, so a query-parameter form apparently exists server-side. The CLI does not use
  it and the authentication page does not document it. **Do not use it.**
- Redirects: the CLI keeps the `Authorization` header across redirects inside `vast.ai`
  (`VastSession.rebuild_auth`), with the comment "Our own environments redirect between
  hosts here". A client that drops the header on redirect may see spurious auth failures.
- Failure codes (docs): "If you get a `401 Unauthorized` or `403 Forbidden` response,
  double-check your API key." The invoices page documents 403 `auth_error` "This action
  requires login." when the header is missing and 404 `auth_error` "Invalid user key" when
  the key matches no user.

### A3. API key permissions

**Confirmed (docs).** Scoped keys exist.

- api-keys guide: "By default, API keys have full access to your account." and "Vast.ai
  shows the key value only at creation time."
- cli/permissions: "Keys with constraints must be created through the CLI or API. The web
  console only creates full-access keys." The keys guide, however, says the console dialog
  lets you "select specific permissions". **Docs disagree with each other** on what the
  console can do; create scoped keys through the CLI or API.
- Categories (cli/permissions table): `instance_read`, `instance_write`, `user_read`,
  `user_write`, `billing_read`, `billing_write`, `machine_read`, `machine_write`, `misc`,
  `team_read`, `team_write`.
- Endpoint mapping (api-reference/permissions, "Endpoint Reference by Category"):
  - `billing_read`: Search Invoices, Show Invoices, Show Earnings
  - `machine_read`: Show Machines, Show Reports
  - `machine_write`: Cancel Maintenance, Cleanup Machine, List Machine, Remove Default Job,
    Schedule Maintenance, Set Default Job, Set Minimum Bid, Unlist Machine, Unlist Volume
  - `user_read`: includes Show User and Show Subaccounts
- Permission file format: "The top-level key is always `"api"`". A read-only host key for
  status and earnings would therefore be:

  ```json
  { "api": { "machine_read": {}, "billing_read": {}, "user_read": {} } }
  ```

  The structure and the category names are documented. This exact combination is not shown
  on any page; it follows from the mapping above.
- Creation: `POST /api/v0/auth/apikeys/` with `name`, `permissions`, optional `key_params`
  (docs and CLI `keys.py`). CLI flag is `--permission_file`.
- Constraints: operators `eq`, `lte`, `gte`. Examples only cover instance ids.
- Lifetime: "API keys do not expire by default." Reset: "The old key stops working as soon
  as you reset; there's no overlap window." Delete: "Deletion is immediate."

**Docs disagree with each other:** the api-keys guide shows
`--permissions '{"manage_instances": true, "manage_billing": false}'`, and the create-api-key
OpenAPI example shows `read: true, write: false`. Neither matches the category model on the
permissions pages, and the CLI has no `--permissions` flag for `create api-key`. Follow the
permissions pages and the CLI.

**Unresolved:** whether `machine_read` also covers the single-machine and maintenance-list
calls the CLI makes (A/B below), which have no API reference page; whether constraints can
pin a key to specific machine ids.

### A4. Rate limits and errors

**Confirmed (docs).**

- "Vast.ai applies rate limits **per endpoint** and **per identity**. This is enforced as a
  minimum interval between requests for a given endpoint and identity."
- Identity: "bearer token + session user + `api_key` query param + client IP."
- "Some endpoints also use **method-specific** limits (GET vs POST) and/or
  **max-calls-per-period** limits for short bursts."
- 429 body: "API requests too frequent" or "API requests too frequent: endpoint threshold=...".
  In the OpenAPI blocks the 429 schema is `{ "detail": string }`.
- "The API does not currently set standard rate-limit headers (for example `Retry-After`),
  so clients should apply their own backoff strategy."
- No numeric limit is stated. The OpenAPI examples carry these threshold values, as
  examples only: machine-earnings 2.0, unlist 1.8, schedule maint 2.5, cleanup 8,
  min-bid 1.5, remove defjob 1.2, invoices 3.0, charges 1.0, create api-key 2.0,
  subaccounts 2.1.
- Error shape: `{"success": false, "error": "invalid_args", "msg": "..."}`; "Some endpoints
  omit the boolean `success`"; "Some omit `error` and return only `msg` or `message`."
  The invoices endpoint can return HTTP 200 with `success: false`.

**Confirmed (official CLI source)** for what the CLI does (`client.py`):

```python
_RETRYABLE_STATUS = {429, 502, 503, 504}
_RETRYABLE_EXC = (
    requests.exceptions.ConnectionError,
    requests.exceptions.Timeout,
)
_DEFAULT_TIMEOUT_SECONDS = 120
...
        t = 0.15
        r = None
        for i in range(0, self.retry):
            ...
            if r.status_code in _RETRYABLE_STATUS and i < self.retry - 1:
                time.sleep(t)
                t *= 1.5
                continue
            break
        return r
```

- `--retry` defaults to 3 (`main.py`). `retry` is the total number of attempts, so the
  default is 3 attempts with sleeps of 0.15 s and 0.225 s.
- The same loop wraps GET, POST, PUT and DELETE. The CLI therefore re-sends writes after a
  502/503/504 or a timeout. HappyMining must not copy that for mutating calls.

**Docs and CLI disagree:** cli/rate-limits says "Retried status codes: 429 only" and "Other
HTTP errors (4xx, 5xx) are reported immediately". Version 1.8.2 also retries 502, 503, 504,
connection errors and timeouts.

**Unresolved:** the unit of "threshold" (seconds is implied by "minimum interval", not
stated); the real per-endpoint limits for a host account.

### A5. Pagination

- Machines list, single machine, maintenance list, reports, earnings: **no pagination
  parameter in docs or CLI.** The CLI reads the whole body in one call. Whether the server
  truncates a large fleet is **Unresolved**.
- `GET /api/v1/invoices` and `GET /api/v0/charges`: **Confirmed (docs)** cursor pagination.
  `limit` (invoices default 60; charges default 100, "Server maximum 500"), `after_token`
  taken from the previous `next_token`; "When the response returns `next_token: null`,
  there are no more pages." The CLI caps `limit` at 100 and notes the type and date filters
  "MUST match previous request for pagination to work".

---

## B. Host machine inventory and status

### B6. `vastai show machines`

Method and path: **Confirmed (docs) and Confirmed (official CLI source).** `GET /api/v0/machines`.

**Docs and CLI disagree** on the parameter and the response.

- Docs: query `user_id` (string, required, "The ID of the user whose machines are being
  requested."). Response `{"machines": [{"id": string, "name": string}]}`. No other field
  is documented. Errors 401, 429.
- CLI `machines.py`:

  ```python
      r = client.get("/machines", query_args={"owner": "me"})
      r.raise_for_status()
      return r.json()["machines"]
  ```

  So the CLI sends `owner=me` and no `user_id`, and expects a top-level `machines` array.

Fields: the documentation describes none of them. The only primary evidence for field
names is the tuple the CLI uses to print the table (`display.py`, `machine_fields`):

```python
machine_fields = (
    ("id", "ID", "{}", None, True),
    ("num_gpus", "#gpus", "{}", None, True),
    ("gpu_name", "gpu_name", "{}", None, True),
    ("disk_space", "disk", "{}", None, True),
    ("hostname", "hostname", "{}", lambda x: x[:16], True),
    ("driver_version", "driver", "{}", None, True),
    ("reliability2", "reliab", "{:0.4f}", None, True),
    ("verification", "veri", "{}", None, True),
    ("public_ipaddr", "ip", "{}", None, True),
    ("geolocation", "geoloc", "{}", None, True),
    ("num_reports", "reports", "{}", None, True),
    ("listed_gpu_cost", "gpuD_$/h", "{:0.2f}", None, True),
    ("min_bid_price", "gpuI$/h", "{:0.2f}", None, True),
    ("credit_discount_max", "rdisc", "{:0.2f}", None, True),
    ("listed_inet_up_cost",   "netu_$/TB", "{:0.2f}", lambda x: x * 1024, True),
    ("listed_inet_down_cost", "netd_$/TB", "{:0.2f}", lambda x: x * 1024, True),
    ("gpu_occupancy", "occup", "{}", None, True),
)
```

The CLI reads each key with `.get(key, None)` and prints `-` when it is missing, so even
these keys are not guaranteed present.

| Concept asked for | Field | Status | Meaning |
| - | - | - | - |
| Machine id | `id` | Confirmed (official CLI source) | Printed as "ID". Docs type it as string; the CLI formats it with `{}` and uses it as an integer path parameter elsewhere. |
| Hostname | `hostname` | Confirmed (official CLI source) | Not documented. The CLI truncates it to 16 characters for display. |
| GPU name, count | `gpu_name`, `num_gpus` | Confirmed (official CLI source) | Not documented. |
| Disk | `disk_space` | Confirmed (official CLI source) | Unit not documented. |
| Driver | `driver_version` | Confirmed (official CLI source) | Not documented. |
| Reliability | `reliability2` | Confirmed (official CLI source) | Printed raw to 4 decimals. For offers the CLI multiplies `reliability` by 100, so a 0 to 1 fraction is likely; not stated. |
| Verification | `verification` | Confirmed (official CLI source) | Column "veri". Possible values are not documented. The docs name three states: Unverified, Verified, Deverified. |
| Public IP | `public_ipaddr` | Confirmed (official CLI source) | Not documented. |
| Reports | `num_reports` | Confirmed (official CLI source) | Column "reports". Not documented. Details come from the reports endpoint. |
| Prices | `listed_gpu_cost`, `min_bid_price`, `credit_discount_max`, `listed_inet_up_cost`, `listed_inet_down_cost` | Confirmed (official CLI source) | Column headers `gpuD_$/h`, `gpuI$/h`, `rdisc`, `netu_$/TB`, `netd_$/TB`. The CLI multiplies the two bandwidth fields by 1024 to show $/TB, so they are per GB. |
| Rental state | `gpu_occupancy` | Confirmed (official CLI source) for the name only | Column "occup". Format and meaning are **not documented** anywhere read. |
| Listed state | none found | **Unresolved** | No field for it appears in docs or in the CLI. |
| Listing expiry | none found | **Unresolved** | `end_date` exists as a *request* field of list machine. No response field was found. |
| Running rentals, on-demand vs interruptible, stored instances | `current_rentals_running`, `current_rentals_running_on_demand`, `current_rentals_resident`, `current_rentals_on_demand`, `clients` | **Unresolved** | None of these names appears in the documentation pages read or anywhere in CLI 1.8.2. A web search found them only in a third-party repository, which is not evidence. |
| Error text | `error_description` | **Unresolved** for machines | The name appears in the CLI only as a field of *offer* objects in the self-test (`machine_diagnostics.py`), not of machines. |

What the documentation does give for rental state is the console and the host itself
(upgrade-docker-and-packages, step 1):

- Console card: "**Occ**, **#Running** and **#Stored** must all read 0", shown as
  `#Running: D: 0, I: 0, R: 0` and `#Stored: D: 0, I: 0, R: 0`. The letters D, I, R are not
  expanded on the page. The rental types documented elsewhere are on-demand, interruptible
  and reserved; that the letters stand for those is an inference.
- Host: `docker ps -a --format '{{.Names}}\t{{.Status}}'`; "Lines starting with `C.` are
  client instances. `Exited` still counts as a rental: the client keeps the disk and can
  restart it."
- "No `C.` lines and all three at 0 means the machine is free."

The mapping from those console counters to API fields is **Unresolved**.

### B7. Single-machine status endpoint

**Confirmed (official CLI source); not in the API reference.**

```python
    r = client.get(f"/machines/{id}", query_args={"owner": "me"})
    r.raise_for_status()
    return r.json()
```

The docstring says "List of machine data dicts (API returns list even for single machine)".
The CLI prints it with the same `machine_fields`. The documentation has a CLI page for
`vastai show machine ID` but no REST page for it, and the truncated OpenAPI file showed no
such path.

Related, also CLI only: `GET /api/v0/machines/maintenances?owner=me&machine_ids=[...]`
(`show maints`). Rows are printed with `machine_id`, `start_time`, `end_time` (formatted
as UTC from epoch seconds), `duration_hours`, `maintenance_category`.

Reports: `GET /api/v0/machines/{machine_id}/reports` (docs). Response is an array of
`{problem: string, message: string, created_at: date-time string}`. The CLI calls
`/machines/{id}/reports/` and also sends a JSON body `{"machine_id": id}` on the GET.

---

## C. Earnings

### C8. Endpoint and parameters

Method and path: **Confirmed (docs) and Confirmed (official CLI source).**

- Docs: `GET /api/v0/users/{user_id}/machine-earnings`. "Retrieves the earnings history for
  a specified time range and optionally per machine."
- CLI `billing.py`:

  ```python
      Minutes = 60.0
      Hours = 60.0 * Minutes
      Days = 24.0 * Hours
      cday = time.time() / Days
      sday = cday - 1.0
      eday = cday - 1.0

      if end_date:
          eday = parse_date_arg(end_date, "end_date").timestamp() / Days
      if start_date:
          sday = parse_date_arg(start_date, "start_date").timestamp() / Days

      query_args = {
          "owner": "me",
          "sday": sday,
          "eday": eday,
          "machid": machine_id,
      }

      r = client.get("/users/me/machine-earnings", query_args=query_args)
  ```

| Parameter | Docs | CLI | Unit |
| - | - | - | - |
| `user_id` (path) | integer, required, "The ID of the user." | literal `me` | The CLI shows `me` is accepted. Docs do not mention it. |
| `sday` | integer, "Start day for the earnings report." | float | **Days since the Unix epoch** (Unix seconds divided by 86400): Confirmed (official CLI source). The docs give no unit. |
| `eday` | integer, "End day for the earnings report." | float | Same. |
| `machid` | integer, "Optional machine ID to filter earnings." | machine id, or JSON `null` | The CLI always sends the key; with no filter it is sent as `machid=null` (non-string query values are JSON-encoded). |
| `last_days` | integer, "Number of days to look back from today." | not sent | No more detail. |
| `owner` | not documented | `me` | Sent by the CLI on every host call. |

Notes on units and time zone:

- An integer day `N` is the instant `N * 86400` seconds after the epoch, which is 00:00 UTC.
  Day 20727 is 2026-10-01 UTC.
- The CLI sends fractional days. Its default is "now minus one day" for both `sday` and
  `eday`, not a whole day.
- The CLI parses user dates with `dateutil` and calls `.timestamp()` on the result. A date
  typed without a zone is taken in the local time zone of the machine running the CLI.
  That is CLI behaviour, not API behaviour.

**Unresolved:**

- Whether the server floors a fractional `sday`/`eday`, and what it does with one.
- Whether the range is inclusive or exclusive at each end. Nothing read says. The CLI
  sending `sday == eday` by default suggests a range of one day is valid when both are
  equal, but that is an inference.
- The day boundary the server uses to bucket `per_day` (UTC is implied by the epoch-day
  unit, not stated).
- How `last_days` interacts with `sday`/`eday`.

### C9. Response schema

**Confirmed (docs)** for names and types. No field has a description and the page has no
example body.

| Key | Type | Notes |
| - | - | - |
| `summary` | object | `total_gpu`, `total_stor`, `total_bwu`, `total_bwd`: number |
| `username`, `email`, `fullname`, `address1`, `address2`, `city`, `zip`, `country`, `taxinfo` | string | Account and billing identity. Personal data: keep out of logs and restrict snapshots. |
| `current` | object | `balance`, `service_fee`, `total`, `credit`: number. Meanings not documented. |
| `per_machine` | array of object | `machine_id`: integer; `gpu_earn`, `sto_earn`, `bwu_earn`, `bwd_earn`: number |
| `per_day` | array of object | `day`: integer; `gpu_earn`, `sto_earn`, `bwu_earn`, `bwd_earn`: number |

- Components: by name, GPU, storage, bandwidth up, bandwidth down. The page does not
  define them.
- Currency: **not stated in the schema.** Other pages speak in US dollars ("at least
  **$20 USD**"; invoices "Amount in dollars"). Treat an earnings currency other than USD as
  unproven rather than impossible.
- Types are JSON `number`. Parse them as decimal strings, never through binary floats.
- `day`: integer, no unit given. Consistency with `sday`/`eday` (epoch days) is likely and
  **Unresolved**.
- Errors: 400 `{success, error, msg}` "Bad Request - Invalid input syntax"; 429
  `{detail}`.
- The CLI adds nothing: `show earnings` prints the JSON as returned.

The documentation contains no example response. The body below is **synthetic**: the
structure is the documented schema, every value is invented, and the four `current` values
are zero because their meaning is unknown. It is here so a fixture has the right shape.

```json
{
  "summary": { "total_gpu": 22.0, "total_stor": 2.0, "total_bwu": 0.4, "total_bwd": 0.6 },
  "username": "synthetic-host",
  "email": "synthetic@example.invalid",
  "fullname": "Synthetic Fixture",
  "address1": "", "address2": "", "city": "", "zip": "", "country": "", "taxinfo": "",
  "current": { "balance": 0.0, "service_fee": 0.0, "total": 0.0, "credit": 0.0 },
  "per_machine": [
    { "machine_id": 101, "gpu_earn": 14.0, "sto_earn": 1.5, "bwu_earn": 0.25, "bwd_earn": 0.35 },
    { "machine_id": 102, "gpu_earn": 8.0,  "sto_earn": 0.5, "bwu_earn": 0.15, "bwd_earn": 0.25 }
  ],
  "per_day": [
    { "day": 20725, "gpu_earn": 10.0, "sto_earn": 1.0, "bwu_earn": 0.1, "bwd_earn": 0.2 },
    { "day": 20726, "gpu_earn": 12.0, "sto_earn": 1.0, "bwu_earn": 0.3, "bwd_earn": 0.4 }
  ]
}
```

That `summary` equals the sum of `per_day` and of `per_machine`, as in this fixture, is an
assumption. It is **Unresolved** and should be an import check, not a premise.

### C10. Per machine per day

**Confirmed (docs)** for the shape: the response has `per_machine` rows without a day and
`per_day` rows without a machine. There is no machine-by-day array.

Getting a machine-by-day amount therefore needs one call per machine with `machid`, and
reading `per_day` from that response. That `machid` restricts `per_day` (and not only
`per_machine`) is the natural reading of "Optional machine ID to filter earnings" and is
**Unresolved** until seen on a real account. A cross-check is available: the per-machine
calls should add up to the unfiltered call.

### C11. Gross or net of Vast's fee

**Unresolved.** No page read says whether `gpu_earn`, `sto_earn`, `bwu_earn`, `bwd_earn`
or the `summary` totals are before or after Vast's fee.

What was found, none of which settles it:

- The earnings schema has `current.service_fee` next to `current.balance` and
  `current.total`. No description.
- https://console.vast.ai/faq/, under "What is the revenue/fee structure?": "Hosts receive
  75% of the revenue earned from successful jobs, with 25% kept by Vast.ai." This page is
  stale: its footer is "© 2022 vast.ai" and it names Ubuntu 16.04 as the supported host OS.
  It is the only fee percentage found. It does not say how the API reports amounts.
- The current host pages (hosting-overview, payment) contain no occurrence of "fee",
  "commission" or "percent".
- A changelog line (January 30, 2024): "Bugfix: earnings PDF now shows correct sign for the
  platform fee". So a platform fee line exists on the earnings PDF.
- CLI `price_increase.py` documents renter-side fields `old_platform_fee` and
  `new_platform_fee`, displayed as "Platform Fee (%)". That concerns renter contracts.

Until this is closed, the ledger must record provider amounts as reported, with the
gross/net basis flagged unknown, and must not derive a Vast fee from them.

### C12. Can past days change

**Unresolved.** Nothing read says earnings for a past day are final, and nothing says they
can be adjusted. Related facts: renter refunds exist as an invoice type (`refund` is listed
among invoice `type` values), and "After spending credits, there are absolutely no refunds"
(renter billing page). Neither statement is about host earnings history. Imports must be
revision-aware.

---

## D. Listing and maintenance controls

### D13. Endpoints

All of these: **Confirmed (docs)** for method and path, and **Confirmed (official CLI
source)**. The CLI uses a trailing slash on each; the docs show one only on cleanup and
defjob.

| Command | Method and path (CLI form) | Body (CLI) | Documented response |
| - | - | - | - |
| `unlist machine` | `DELETE /api/v0/machines/{id}/asks/` | `{}` | `{success: bool, machine_id: int, user_id: int}`; 401, 404, 429 |
| `list machine` | `PUT /api/v0/machines/create_asks/` | `machine`, `price_gpu`, `price_disk`, `price_inetu`, `price_inetd`, `price_min_bid`, `min_chunk`, `end_date`, `credit_discount_max`, `duration`, `vol_size`, `vol_price` | `{success: bool, extended: int, msg: string}`; 400 `invalid_args`, 403 `not_authorized` |
| `schedule maint` | `PUT /api/v0/machines/{id}/dnotify/` | `client_id: "me"`, `sdate`, `duration`, `maintenance_category` | `{success: bool, you_sent: string}`; 400, 404, 422, 429 |
| `cancel maint` | `PUT /api/v0/machines/{id}/cancel_maint/` | `client_id: "me"`, `machine_id` | `{success, ctime: float, machine_id: int, msg}`; 404 `{success:false, msg:"No such machine id", machine_id, user_id}` |
| `cleanup machine` | `PUT /api/v0/machines/{id}/cleanup/` | `{}` ("An empty JSON object is expected.") | `{success, ctime, machine_id, user_id, num_deleted: int, msg}`; 400, 401, 403, 429 |
| `set min-bid` | `PUT /api/v0/machines/{id}/minbid/` | `client_id: "me"`, `price` | `{success, you_sent: object}`; 403, 422, 429 |
| `remove defjob` | `DELETE /api/v0/machines/{id}/defjob/` | `{}` | `{success, machine_id, user_id}`; 404, 429 |

Parameter units:

- `list machine` (CLI help): `price_gpu` "per gpu rental price in $/hour"; `price_disk`
  "storage price in $/GB/month ... default: $0.10/GB/month"; `price_inetu`/`price_inetd`
  "$/GB"; `price_min_bid` "per gpu minimum bid price floor in $/hour"; `min_chunk`
  "minimum amount of gpus (default: 1)"; `credit_discount_max` "Max long term prepay
  discount rate fraction, default: 0.4"; `end_date` "unix float timestamp or MM/DD/YYYY"
  (the CLI turns MM/DD/YYYY into UTC midnight). Docs: `end_date` "Unix timestamp for when
  the listing expires". The docs body omits `duration`, `vol_size`, `vol_price`.
- The list response field `extended` is "Number of client contracts extended to new end
  date". Listing with a later end date can extend existing contracts.
- `schedule maint`: **Docs and CLI disagree** on `sdate`. Docs: string, `format: date-time`,
  example `2023-10-30T14:00:00Z`, with `duration` integer hours. CLI: `--sdate` "maintenance
  start date in unix epoch time (UTC seconds)" as float, `--duration` "maintenance duration
  in hours" as float, example `--sdate 1677562671 --duration 0.5`. The docs also list
  `maintenance_reason` (string), which the CLI never sends. Categories: `power`, `internet`,
  `disk`, `gpu`, `software`, `other`; the CLI default is the string `not provided`.
- `set min-bid`: `price` "per gpu min bid price in $/hour" (CLI).

Other machine endpoints present in the CLI and out of scope for the adapter:
`PUT /machines/create_bids/` (set defjob), `PUT /machines/defrag_offers/`,
`POST /machines/{id}/force_delete/` ("Delete machine if the machine is not being used by
clients"). HappyMining should not call `force_delete`.

### D14. Semantics

**Confirmed (docs)** unless marked.

Unlisting:

- "Unlisting the offer will prevent new rental contracts from being created, but does not
  affect existing ones." (hosting-overview, Maintenance)
- "**Unlisting** the machine prevents new rental contracts entirely, but existing ones
  continue at their original pricing and rental end dates"
- "Once created, a rental contract's terms cannot be changed, not by modifying the offer,
  not by unlisting the machine, and not by any other host action."
- "Volume offers will be unlisted when the machine is unlisted."
- CLI help for `list machine`: "On the end date the listing will expire and your machine
  will unlist. However any existing client jobs will still remain until ended by their
  owners."

Obligations until the contract end date:

- "The latest rental end date across all active rental contracts on a machine is shown in
  the UI. You must keep the machine available until this date."
- "All rental contracts must be honored, you cannot take the machine offline until every
  active rental contract has ended."
- Host commitments: "the hardware can not be used for any other purposes"; "the client's
  data must be isolated and protected according to the data protection policy"; "the
  advertised services must be provided until each rental contract's rental end date".
- "Make sure to set an offer end date **before** listing your machine, or the offer will
  remain open indefinitely."
- "If you have raised the pricing, you cannot extend the current rental contracts."

Maintenance windows (set-maintenance-window):

- "Scheduling a window is a notification, not an action. It does not stop instances,
  unlist the machine, or block new rentals. You still take the machine down yourself when
  the window arrives."
- "everybody with a running or stopped instance on that machine is notified with the start
  time and duration"
- "The start must be in the future, and no more than a year out." The console default is
  24 hours from now.
- "Duration is recorded in whole hours, with a minimum of one. A fractional value is
  rounded down, so anything under an hour becomes one hour."
- "Upcoming and ongoing windows can be cancelled; completed ones cannot." "A window that
  Vast scheduled on your machine cannot be cancelled from this page."
- "A bulk request covers at most 100 machines." (console)
- Notice: upgrade-docker-and-packages, upgrade-kernel and disable-ssh-password-login each
  open with "schedule a maintenance window at least **48 hours** in advance" and "Work
  performed outside the scheduled maintenance window may be treated as an **operational
  failure**." The 48 hour figure is stated for those procedures. A general minimum notice
  for any maintenance is **Unresolved**.
- Proper order (hosting-overview): "The proper way to perform maintenance on your machine
  is to wait until all active rental contracts have ended or the machine has no running
  instances." "For unplanned or unscheduled maintenance, use the CLI and the schedule maint
  command. That will notify the client that you **have** to take the machine down".
- Reliability: "Restarting during an active rental does cost you reliability. Schedule a
  maintenance window first to keep the penalty smaller and recover sooner."

Stopped instances and stored data:

- "`Exited` still counts as a rental: the client keeps the disk and can restart it."
- "**If anything is rented and you still want to upgrade:** unlist the machine ..., then
  schedule maintenance so renters get a notification with your window. Do not stop or
  delete client containers."
- "Do not reboot the machine, stop customer containers, force-stop VMs, or delete instance
  data while there are active rentals, unless instructed by Vast.ai Support."
  (machine-offline)
- "Do not restart or modify NVIDIA drivers while active customer instances are running
  unless instructed by Support."
- "A kernel upgrade only takes effect after a reboot, and a reboot stops every running
  instance on the machine. Instances are not destroyed, but the workloads inside them are
  interrupted."
- Renter side: "Stopped instances: Data preserved, storage charges continue"; "Expired
  instances may be deleted 48 hours after expiration."

Cleanup (CLI help, `cleanup machine`): "Instances expire on their end date. Expired
instances still pay storage fees, but can not start. Since hosts are still paid storage
fees for expired instances, we do not auto delete them. Instead you can use this CLI/API
function to delete all expired storage instances for a machine." hosting-overview adds
that it "will automatically remove expired/deleted rental contracts from the machine".
This call deletes renter storage. It belongs behind operator approval, never in automation
that frees space.

---

## E. Host setup and requirements

### E15. Installation command and enrollment

The documented installation command lives on https://cloud.vast.ai/host/setup/, which
could not be read. Its exact documented form, where the host obtains the key, and whether
that key is temporary or single-use are therefore **Unresolved**.

What can be established:

- **Confirmed (docs):** "Once your account is created, open the host setup guide. There is
  a link in the first paragraph to the hosting agreement. Read through the agreement. Once
  you accept, your account will then be converted to a hosting account." Accepting the
  agreement is a manual act by the account holder.
- **Confirmed (docs):** "You must create a new account for hosting. If you are using
  Vast.ai as a client, do not use the same account."
- **Confirmed (official host script):** `https://console.vast.ai/install` answers with an
  HTTP 302 to `https://s3.amazonaws.com/public.vast.ai/kaalia/scripts/vast_host_installer.py`.
  That script takes one positional argument, `parser.add_argument("api_key")`, re-runs
  itself under `sudo` if not root, and sends the argument as
  `"Authorization": f"Bearer {user_api_key}"` in a `POST` to
  `server + "/api/v0/daemon/identify/"` with JSON `{"machine_api_key": machine_api_key}`.
  The response fields it reads are `machine_id`, `nonce`, `new_machine_api_key`,
  `key_adopted`. So the command does carry an account-linked key, and that key is used as
  a bearer credential for the account.
- **Confirmed (official host script):** the extract shows the same argument placed in a
  log-upload URL (`upload_url += "api_key=" + args.api_key + "&"`). Whatever key is passed
  to the installer should be treated as exposed to the host's shell history, process list
  and install log. This is one more reason never to pass a reusable account key.
- Nothing in the script extract shows expiry or single-use handling of that key. That is a
  server-side property and cannot be read from the client.

Automated enrollment API: **none documented.** The documentation index (llms.txt) has no
enrollment, registration or "identify" page. `/api/v0/daemon/identify/` and
`/api/v0/machines/report_new_key/` are internal calls of Vast's installer. They are not
part of the published API and HappyMining must not call them itself.

### E16. Requirements

Operating system. **Confirmed (docs)** (verification-stages, "Minimum Requirements for
Verification"):

| Requirement | Minimum |
| - | - |
| Operating system | "Ubuntu Server 22.04 LTS, 24.04 LTS recommended" |
| Kernel | "Latest security patch level for your Ubuntu release" |
| NVIDIA driver | "A currently supported release for your GPU" |
| SSH login | "SSH keys only, password authentication disabled" |
| SSH access keys | "A unique key pair per machine, never shared or reused" |
| Secure Boot | "Disabled" |

- "Use a server edition. Desktop editions are not supported."
- Maintenance pages: "The steps are the same on Ubuntu Server 22.04 and 24.04."
- Kernel: "Keeping the kernel patched is the host's responsibility. ... Machines running a
  kernel with a known exploited vulnerability are restricted on the marketplace and can
  lose verification." Both GA (`linux-generic`) and HWE (`linux-generic-hwe-*`) appear in
  the examples; neither is required.
- "Make sure to disable auto-updates so that your machine doesn't drop a client job to
  update a driver." (hosting-overview)
- AMD EPYC: "Make sure to read the section on IOMMU" (the section is on the unreadable
  setup page).

NVIDIA driver. **Confirmed (docs)** only as "A currently supported release for your GPU"
and "Keep drivers/CUDA on compatible, **latest** stable versions". CUDA "11.8 or newer";
on ARM64 "CUDA 12.6 or newer is required". No specific driver version is recommended or
required on any page read. The upgrade page shows `nvidia-driver-595-open` 595.84 and
595.98 in sample output on 24.04; that is an example, not guidance. The daemon holds the
installed `nvidia-driver-*` package (below). A specific recommended version or install
method is **Unresolved** (probably on the setup page).

Hardware. **Confirmed (docs)**:

| Area | Requirement | Minimum |
| - | - | - |
| GPU | GPU | NVIDIA, Maxwell or newer |
| GPU | VRAM per GPU | More than 7 GB |
| GPU | GPU models | All identical, do not mix models in one machine |
| GPU | PCIe bandwidth | More than 2.85 GiB/s per GPU |
| CPU | Architecture | x86_64 or ARM64 |
| CPU | Instruction set | AVX |
| CPU | Physical CPU cores | 2 per GPU |
| Memory | System RAM | At least 95% of total GPU VRAM ("system RAM >= 0.95 x VRAM per GPU x number of GPUs") |
| Network | Download, upload | 500 Mbps each |
| Network | Connection | Wired Ethernet, fiber recommended |
| Network | Public IP | Public IPv4 address |
| Network | Forwarded ports | 5 ports per GPU, 100 ports per GPU recommended |
| Storage | Type | SSD |
| Storage | Dedicated drive for Docker container storage | 200 GB |
| Storage | Root partition free space | 20 GB |
| Reliability | Score | Over 90% |

- "Machines behind CGNAT or a shared ISP IP cannot be used for hosting."
- "**Dedicated machines only.** Any personal workload, such as mining, gaming, running your
  own jobs, or using the machine as a desktop, will automatically fail verification."
- VMs (optional): CPU with Intel VT-d or AMD-Vi; kernel parameters `amd_iommu=on` or
  `intel_iommu=on` and `nvidia_drm.modeset=0`; display managers removed.

The self-test in CLI 1.8.2 uses slightly different gates. **Confirmed (official CLI
source)** (`machine_diagnostics.py`, `util.py`): CUDA >= 11.8; reliability > 0.90; direct
ports >= 3 per listed GPU; PCIe > 2.85; per-GPU VRAM > 7 GiB; system RAM >= 0.95 x total
VRAM, capped at 2,000,000 MiB; CPU cores >= 2 per GPU; download and upload >= a floor that
scales with total VRAM, `min(500.0, max(100.0, 500.0 * total_vram_gib / 192.0))` Mb/s; and
an advisory, "Vast instances can use at most 64 open ports each." The verification table
(5 ports per GPU, 500 Mbps) is the stricter published requirement.

Storage and filesystem.

- **Confirmed (docs):** hosts are responsible for "creating disk partitions"; a dedicated
  SSD of at least 200 GB for Docker container storage; `xfsprogs` is among the packages
  the daemon holds.
- **Confirmed (official host script):** the installer puts `/var/lib/docker` on XFS with
  project quotas. It writes an fstab line of the form
  `{device} /var/lib/docker xfs rw,auto,pquota 0 0`. Without free unpartitioned space it
  falls back to a loop file, `/var/lib/docker-loop.xfs`, and prints "Will attempt a
  loopback partition; this will have significantly worse performance." Flags:
  `--docker-partition DEVICE` ("use an existing block device ... for Docker storage",
  which fails unless `/var/lib/docker` is xfs with the project-quota mount option),
  `--no-partitioning`, `--storage-size` (loop file size in GiB). Existing Docker data is
  moved to `/var/lib/docker-temporarily-renamed/`, copied back with `rsync`, then removed.
  It also writes `/etc/containerd/config.toml` with `root = "/var/lib/docker/containerd/"`.
- The documented wording of the storage requirement (XFS, where Docker data must live) is
  on the unreadable setup page: **Unresolved** as documentation, established only from the
  script.

Container runtime.

- **Confirmed (official host script):** the installer installs Docker itself, from
  Docker's apt repository (`https://download.docker.com/linux/ubuntu`), after
  `apt-get remove docker docker-engine docker.io`. Packages: `docker-ce`, `docker-ce-cli`,
  `docker-ce-rootless-extras`, `containerd.io`, `nvidia-docker2`, plus `xfsprogs`, `dkms`,
  `build-essential`, `rsync`, and for VMs `libvirt-daemon-system`, `cloud-utils`, QEMU.
  Pins in `/etc/apt/preferences.d/vast-packages`: `docker-ce` `5:28.*`, `containerd.io`
  `1.*`, `nvidia-docker2` `2.13.*`. `--no-docker` means "assume docker is configured in
  exactly the way needed by vast.ai already".
- **Confirmed (docs):** "The Vast daemon pins Docker and containerd to their current major
  version." It "re-applies its `apt-mark` holds every hour". Sample hold list:
  `cloud-utils`, `containerd.io`, `docker-ce`, `docker-ce-cli`,
  `docker-ce-rootless-extras`, `libvirt-daemon-system`, `libvirt-dev`,
  `nvidia-container-toolkit`, `nvidia-container-toolkit-base`, `nvidia-driver-595-open`,
  `qemu-system-x86`, `xfsprogs`. The page also allows for machines running Ubuntu's
  `docker.io`.
- **Confirmed (docs):** expected `/etc/docker/daemon.json` contains registry mirrors
  (`https://registry-1.docker.io`, `https://docker1.vast.ai` to `docker5.vast.ai`) and

  ```json
  "runtimes": { "nvidia": { "path": "/var/lib/vastai_kaalia/latest/kaalia_docker_shim", "runtimeArgs": [] } }
  ```

  "Do not run `nvidia-ctk runtime configure` on a Vast machine: it replaces that path with
  NVIDIA's default runtime and client instances stop working." Also: do not add
  `"features": {"containerd-snapshotter": true}`.

  HappyMining OS must therefore not install its own Docker, must not manage
  `daemon.json`, and must not run `nvidia-ctk runtime configure`.

Networking. **Confirmed (docs):** public IPv4, forwarded port range, 5 ports per GPU
minimum and 100 recommended; "Clients require open ports to directly connect to the
machine". **Confirmed (official host script):** `--ports START END` writes
`host_port_range` as `{start_port}-{end_port}`; no default range is hard-coded. The
documented port range numbers and the testing procedure are on the unreadable setup page:
**Unresolved.**

### E17. What the host software puts on the machine

| Item | Status | Source |
| - | - | - |
| systemd unit `vastai.service`, "Vast.ai Host Daemon", at `/etc/systemd/system/vastai.service`, running `/var/lib/vastai_kaalia/latest/launch_kaalia.sh` and `/var/lib/vastai_kaalia/latest/kaalia backend=DKR ...` | Confirmed (docs) | machine-offline, upgrade-docker |
| The daemon restarts itself after a plain `systemctl stop` | Confirmed (docs) | upgrade-docker step 3 |
| Second unit `vastai_tls.service` | Confirmed (official host script) | uninstaller |
| Data directory `/var/lib/vastai_kaalia` | Confirmed (docs) | machine-offline |
| Log `/var/lib/vastai_kaalia/kaalia.log` (rotated `kaalia.log*`) | Confirmed (docs), Confirmed (official CLI source) | machine-offline; `support_bundle.py` |
| `/var/lib/vastai_kaalia/send_mach_info.py`, `enable_vms.py`, `latest/kaalia_docker_shim` | Confirmed (docs) | upgrade-docker, vms |
| State files `data/last_try_get_controller`, `data/get_controller_delay`, `controller_connection` | Confirmed (docs) | machine-offline step 3 |
| System user `vastai_kaalia`, home `/var/lib/vastai_kaalia`, primary group `docker` | Confirmed (official host script) | installer |
| `vastai_kaalia ALL=(ALL) NOPASSWD:ALL` appended to `/etc/sudoers` | Confirmed (official host script) | installer |
| `/var/lib/vastai_kaalia/machine_id`: 64 random hex characters generated locally, sent to Vast as `machine_api_key`, mode `0600`, owner `vastai_kaalia:docker`; regenerated by `--reset-machine`; rotated by the server through `new_machine_api_key` | Confirmed (official host script) | installer |
| `/var/lib/vastai_kaalia/machine_num_id`: the numeric machine id returned by Vast | Confirmed (official host script) | installer |
| `/var/lib/vastai_kaalia/host_port_range` | Confirmed (official host script) | installer |
| `/etc/cron.d/vastai_kaalia_update`, `/usr/local/bin/vastai-run-update` | Confirmed (official host script) | uninstaller |
| `/etc/apt/preferences.d/vast-packages`, `/etc/apt/sources.list.d/nvidia-docker.list`, `/etc/modprobe.d/blacklist-nouveau.conf`, edits to `/etc/fstab`, `/etc/docker/daemon.json`, `/etc/containerd/config.toml` | Confirmed (official host script) | installer |
| Daemon telemetry: "collects CPU, memory, GPU, disk, and network counters every second, plus container state every 15 seconds" | Confirmed (docs) | machine-metrics |
| Uninstall: `https://s3.amazonaws.com/vast.ai/uninstall` | Confirmed (docs) | hosting-overview |

Host-local credential and its exposure boundary: the file named `machine_id` is a secret,
not an identifier. It is the machine's API key toward Vast. Anyone who can read it as root
or as `vastai_kaalia` holds that machine's identity. Cloning a disk clones it. The numeric
id is in `machine_num_id`. HappyMining's agent must not read, transmit or back up
`machine_id`, and image sanitising must remove both files.

Whether the account key passed to the installer is stored on disk after installation is
**Unresolved**; the extract shows it used in requests and in a log-upload URL, and does
not show a file being written for it.

### E18. Verification stages

**Confirmed (docs).**

- "**States:** Unverified → Verified → (potentially) Deverified → Unverified → ..."
- "Verification is **entirely automated by proprietary algorithms**"; "There is **no
  manual intervention**".
- Unverified: "Newly added machines or machines under evaluation. ... This is not a
  judgment of quality-only that no platform guarantee exists yet."
- Verified: "The machine passed automated checks for reliability, network stability,
  operational health, and performance."
- Deverified: "When the hosting software detects an error, your machine is automatically,
  but **temporarily**, deverified." "Most error messages are cleared within 1-2 hours of
  resolution." It may need a Vast team member to clear it.
- Not guaranteed: "Meeting these minimum requirements makes your machine eligible for
  verification, but does not automatically guarantee verification." The outcome also
  depends on reliability, infrastructure, DLPerf score and "current supply and demand".
  "Top-tier AI GPUs are prioritized for verification".
- "Do not reduce hardware after creation (e.g., fewer GPUs/RAM) - this will trigger
  Deverified".
- "A drop in reliability does not by itself cost you your verification. What does is an
  active error."
- Self-test: `vastai self-test machine <machine_id>`; requires that "Your machine has been
  listed" and "There are no active clients currently renting it"; it rents the machine
  briefly through the account. A pass ends with "Test completed successfully." A pass with
  `--ignore-requirements` "does not qualify this machine for verification".

HappyMining preflight can report PASS/WARN/FAIL against the table in E16. It cannot
predict verification.

---

## F. Payment

### F19. Host payouts

**Confirmed (docs)** (host/payment).

- Methods: Wise, PayPal, Stripe. "Direct bank transfers, ACH payments, wire transfers, and
  SWIFT payments are not available."
- Minimum: "Your account must accumulate at least **$20 USD** before an invoice can be
  generated." "Balances below $20 USD will automatically roll forward".
- Schedule: "Invoices are generated weekly on **Fridays**." "Invoices generated on Friday
  are generally scheduled to be paid on the following Friday." "It typically takes up to
  **two weeks to receive your first payout**."
- Prerequisite: "You must have a valid payout method connected to your Vast.ai account."
  Hosts must be able to "receive business-to-business (B2B) payments".
- Statuses. Pending: "has been generated and is scheduled for payment during the next
  payout cycle." Paid: "An invoice is marked as Paid once Vast.ai has submitted the payout
  to your selected payout provider." "The Paid status reflects the status of the payout
  within Vast.ai's billing system only. It does not indicate whether the funds have
  completed processing within Wise, PayPal, or Stripe."

  So "Paid" means submitted by Vast, not received. This matches the project rule that a
  provider invoice marked Paid must not make owner funds withdrawable.
- Records: `Earnings → Payout History`, downloadable as CSV and PDF; invoice details under
  `Settings → Invoice Information`.
- API: `GET /api/v1/invoices` returns "Stripe top-ups, transfers, payouts, coinbase
  payments, and other billing transactions". Filter `select_filters` with `when` in "unix
  seconds (UTC)" and optional `service` (`paypal_manual`, `wise_manual`, ...). Result rows:
  `start` "Invoice creation time (unix seconds UTC)", `end` "Payment time (unix seconds
  UTC). `null` if unpaid.", `type` (`credit`, `transfer`, `payout`, `refund`, `reserved`),
  `source`, `description`, `amount` "Amount in dollars. Negative for charges, positive for
  transfers/payouts.", `metadata.invoice_id`, `metadata.service`.
- Tax: "Vast.ai does not automatically withhold taxes"; Vast "does not currently collect
  or remit VAT".

Payout splitting: **none documented.** The payment page has no occurrence of "split",
"third party" or "on behalf", and describes a single payout method per account. A
`transfer credit` endpoint exists (`billing_write`); it moves account credit between Vast
accounts, is described as irreversible, and is not a payout. Do not build on it.

**Unresolved:** which API rows correspond to the Pending and Paid statuses of a host
payout invoice (the `end` field being `null` "if unpaid" is the only documented link);
whether a payout row lists the earnings days it covers.

### F20. Operating machines for third parties

Not found in the pages read: any statement that permits or forbids a host account
operating machines owned by other parties, managed hosting, or several owners under one
account. Per the task rule, this is not a finding that it is permitted or forbidden.

The hosting agreement at https://cloud.vast.ai/host/agreement, the document most likely to
address this, **could not be read.**

Related statements that were found. **Confirmed (docs)**, Terms of Service, "Version Date:
September 1, 2026":

- "You may not use anyone else's account at any time."
- "This Agreement and your account may not be assigned by you without our express written
  consent."
- "Authorized Users" are "employees, consultants, contractors, and agents ... authorized by
  user to access and use the Services"; the account holder is "entirely responsible for
  any and all activities that occur under your account".
- "All Providers are independent contractors with respect to the Company and Users."
- Prohibited: "Using any robot, spider, crawler, scraper, script, browser automation ...
  except as expressly authorized in a separate written agreement with Company". How this
  clause sits with use of the published API is not stated. It is a second reason to get
  written authorization, and a clear reason never to automate the console.
- Authorized Data may not be used "to redistribute, resell, sublicense, publish or
  otherwise make available to any third party". What "Authorized Data" covers was not
  extracted.

Other documented structures, neither of which is described as a way to host for others:

- Subaccounts: `POST /api/v0/users/` with `parent_id: "me"` and `host_only: true`,
  "Subaccounts can be restricted to host-only functionality"; `GET /api/v0/subaccounts`.
  Whether earnings and payouts are separate per subaccount is not documented.
- Teams: "Each team shares resources such as instances, templates, machines, and certain
  settings with all team members." "Teams maintain their own separate balance/credit,
  billing information, and payment history".
- Datacenter status: "The equipment must be owned by a business", ISO/IEC 27001, a signed
  Datacenter Hosting Agreement, "at least 5 GPU servers listed". That is an ownership
  requirement for that programme, and it would sit badly with customer-owned machines.

---

## G. Ubuntu autoinstall

### G21. Providing and shaping the configuration

**Confirmed (docs)** (Canonical Subiquity documentation, "latest").

Supported releases: "This format is supported in the following installers: Ubuntu Server,
version 20.04 and later; Ubuntu Desktop, version 23.04 and later". The pages are the
"latest" documentation and are not tied to one release; version notes are given per
feature. The quick start still names 23.10 as its example ISO.

Two ways to provide it:

1. Cloud-config (recommended). User data with the `#cloud-config` header and the
   directives under a top-level `autoinstall:` key. "The NoCloud data source represents the
   most straightforward implementation". Quick start: files `user-data` and `meta-data`,
   built into a seed with `cloud-localds ~/seed.iso user-data meta-data`, attached as a
   second drive; or served over HTTP with the kernel argument
   `autoinstall ds=nocloud-net;s=http://_gateway:3003/`.
2. On the install media, as a file named `autoinstall.yaml`. In this form the top-level
   `autoinstall:` key is omitted; "Starting with 24.04 (Noble), the top-level `autoinstall:`
   keyword is permitted".

Locations searched: root of the install medium; root filesystem of the install system; a
path given on the kernel command line with `subiquity.autoinstallpath=path/to/autoinstall.yaml`.
Precedence: 1. kernel command line, 2. root of the installation system, 3. cloud-config,
4. root of the installation medium.

Confirmation prompt: "Before the Ubuntu Installer actually makes changes to the target
system, a prompt is shown." The prompt is "Continue with autoinstall? (yes|no)". "The
Ubuntu Installer contains a safeguard, intended to prevent USB Flash Drives with an
`autoinstall.yaml` file from wiping out the wrong system." "To bypass this prompt, arrange
for the argument `autoinstall` to be present on the kernel command line." Quick start: "The
installer prompts for a confirmation before modifying the disk."

For HappyMining media this prompt is wanted. Leave `autoinstall` off the kernel command
line of the destructive path so the operator must confirm.

Unanswered questions: "if there is any autoinstall configuration at all, the autoinstall
takes the default for any unanswered question (and fails if there is no default)".

`interactive-sections`: list of strings, default `[]`. "A list of configuration keys to
still show in the user interface (UI)". The example lists `network` and "stops on the
network screen and allows the user to change the defaults." The value `*` asks all the
usual questions. `storage` is marked "can be interactive: true", so
`interactive-sections: [storage]` hands disk choice to the operator at the console.

`identity`: mapping; `username`, `hostname`, `password` (crypted) and optional `realname`,
`groups`. "The password for the new user, encrypted. This is required for use with `sudo`,
even if SSH access is configured." Not needed if `user-data` is supplied.

`ssh`: `install-server` (boolean, default `false`), `authorized-keys` (list, default `[]`),
`allow-pw` (boolean, default `true` if no authorized keys, otherwise `false`).

`late-commands`: "Shell commands to run after the installation has completed successfully
and any updates and packages installed, just before the system reboots." They run in the
installer environment with the target at `/target`; use `curtin in-target --` to run inside
the target.

Other keys used by a typical image: `version` (must be `1`), `early-commands`,
`error-commands`, `user-data`, `packages`, `updates` (`security` default, or `all`),
`shutdown` (`reboot` default, or `poweroff`), `refresh-installer`.

`storage`:

- Layouts: "The three supported layouts at the time of writing are `lvm`, `direct` and
  `zfs`." (`hybrid` also exists, for TPM-backed encryption.)
- Default disk: "By default, these layouts install to the largest disk in a system, but
  you can supply a match spec ... to indicate which disk to use." A layout without `match`
  therefore picks the largest disk by itself. HappyMining must always supply a match.
- Match keys, complete list from the "Disk selection extensions" section:

  | Key | Meaning |
  | - | - |
  | `model` | udev `ID_MODEL`; globbing supported |
  | `vendor` | udev `ID_VENDOR`; globbing supported |
  | `path` | device path such as `/dev/sdc`; globbing supported |
  | `id_path` | udev `ID_PATH`; globbing supported |
  | `devpath` | udev `DEVPATH`; globbing supported |
  | `serial` | udev `ID_SERIAL`; globbing supported |
  | `ssd` | `true` or `false` |
  | `size` | `largest` or `smallest` among the matches |
  | `install-media` | the disk the installer was loaded from |

  There is no key named `id` and none for `/dev/disk/by-id`. `serial` (udev `ID_SERIAL`)
  is the documented key closest to a by-id selection.
- "As of Subiquity 24.08.1, match specs may optionally be specified in an ordered list,
  and will use the first match spec that matches one or more unused disks."
- "Using `match: {}` matches an arbitrary disk."
- "Any disk action is assigned a matching disk – chosen arbitrarily from the set of
  unassigned disks if there is more than one, and causing the installation to fail if
  there is no unassigned matching disk." A glob that matches two disks is therefore a
  silent arbitrary choice. Use an exact serial.
- `sizing-policy`: `scaled` or `all`.
- Action-based configuration is "a superset of that supported by curtin".
- Example from the page:

  ```yaml
  autoinstall:
    storage:
      layout:
        name: lvm
        match:
          serial: CT*
  ```

Schema: "The server installer validates the provided autoinstall configuration against a
JSON schema." The schema is printed on
https://canonical-subiquity.readthedocs-hosted.com/en/latest/reference/autoinstall-schema.html
and can be regenerated with `make schema` in https://github.com/canonical/subiquity. "the
actual runtime validation process is more involved than a simple JSON schema validation".
Unknown top-level keys are fatal; this "was first introduced during 24.04 (Noble)".
Validator: `./scripts/validate-autoinstall-user-data.py <path-to-config>` in the Subiquity
repository; default input is cloud-config, `--no-expect-cloudconfig` for the
`autoinstall.yaml` form. Stated limit: it cannot check "match directives", which depend on
the hardware at run time.

**Unresolved:** the file name of the schema inside the repository; whether `path` accepts
a `/dev/disk/by-id/...` symlink; the layout `mode` key (`reformat_disk`, `use_gap`), which
did not appear in the text returned for the reference page.

### G22. Is Ubuntu Server 24.04 LTS x86_64 supported by Vast

**Confirmed (docs).** verification-stages: operating system minimum "Ubuntu Server 22.04
LTS, 24.04 LTS recommended"; CPU architecture "x86_64 or ARM64". Server edition only.
Starting from 24.04 LTS on x86_64 is consistent with Vast's published requirement, and
22.04 LTS is the stated minimum. The installer script has a branch for `"24.04"` and
`"22.04"` that sets Docker's `native.cgroupdriver=cgroupfs`.

---

## H. nvidia-smi

### H23. Query interface

**Confirmed (docs)** (NVIDIA manual page):

- `--query-gpu=`: "Information about GPU. Pass comma separated list of properties you want
  to query. e.g. --query-gpu=pci.bus_id,persistence_mode." "Call --help-query-gpu for more
  info."
- `--format=`: "Comma separated list of format options: csv - comma separated values
  (MANDATORY); noheader - skip first line with column headers; nounits - don't print units
  for numerical values".
- `-i, --id=ID`: the id "may be the GPU's 0-based index in the natural enumeration returned
  by the driver, the GPU's board serial number, the GPU's UUID, or the GPU's PCI bus ID".
- `-L, --list-gpus`: "List each of the NVIDIA GPUs in the system, along with their UUIDs."
- Unsupported values: "Some devices and/or environments don't support all possible
  information. Any unsupported data is indicated by a "N/A" in the output." Also "Unknown
  Error" for some fields.
- Stability: "The output of NVSMI is not guaranteed to be backwards compatible."
- The page states no version or date.

The manual does **not** list the property identifiers. It sends the reader to
`nvidia-smi --help-query-gpu`.

| Wanted | Identifier | Status | Unit and description |
| - | - | - | - |
| Name | `name` | Confirmed (docs): NVIDIA support article and Vast's upgrade page (`--query-gpu=name,driver_version --format=csv,noheader`) | "The official product name of the GPU" |
| Driver version | `driver_version` | Confirmed (docs): same two sources | The manual marks the attribute "Deprecated; use KMD Version instead." Whether the query identifier changes is not stated. |
| GPU temperature | `temperature.gpu` | Confirmed (docs): NVIDIA support article | "All readings are in degrees C" |
| GPU utilisation | `utilization.gpu` | Confirmed (docs): NVIDIA support article | "Percent of time over the past sample period during which one or more kernels was executing on the GPU" |
| Memory utilisation | `utilization.memory` | Confirmed (docs): NVIDIA support article | Percent |
| Used memory | `memory.used` | Confirmed (docs): NVIDIA support article | "Used size of FB memory"; unit not stated on the pages read |
| Index | `index` | **Unresolved** | Not on the pages read |
| UUID | `uuid` | **Unresolved** as an identifier | Attribute: "globally unique immutable alphanumeric identifier of the GPU" |
| Total memory | `memory.total` | **Unresolved** as an identifier | "Total size of FB memory" |
| Power draw | `power.draw` | **Unresolved** as an identifier | "The last measured power draw for the entire board, in watts." |
| Fan speed | `fan.speed` | **Unresolved** as an identifier | "percent of the product's maximum noise tolerance fan speed ... This value may exceed 100% in certain cases." "Many parts do not report fan speeds" |

Other identifiers shown in the NVIDIA support article: `timestamp`, `pci.bus_id`,
`pstate`, `gpu_name`, `gpu_bus_id`, `vbios_version`. The article adds: "ensure that no
spaces are added between the queries options."

**Unresolved:** the five identifiers marked above; the literal text printed in CSV for an
unsupported value (the manual says "N/A"; whether CSV prints `[N/A]`, `[Not Supported]` or
something else was not on any page read); the memory unit (MiB is expected, not stated).
All of these are settled by one command on a host with the target driver:
`nvidia-smi --help-query-gpu`. Commit its output as a fixture with the driver version, and
have the agent's parser treat any non-numeric cell as "unavailable", not zero.

---

## Confirmed endpoint and authentication schemas

Common to all: base `https://console.vast.ai`; header `Authorization: Bearer <key>`;
JSON bodies; errors as in A4. "docs" and "CLI" tell which source supports each element.

**GET /api/v0/machines** (docs, CLI)
- Query: `owner=me` (CLI). Docs instead say `user_id` (string, required).
- 200: `{"machines": [ {...} ]}` (docs, CLI).
- Fields the CLI reads: `id`, `num_gpus`, `gpu_name`, `disk_space`, `hostname`,
  `driver_version`, `reliability2`, `verification`, `public_ipaddr`, `geolocation`,
  `num_reports`, `listed_gpu_cost`, `min_bid_price`, `credit_discount_max`,
  `listed_inet_up_cost`, `listed_inet_down_cost`, `gpu_occupancy`. Types not documented.
  Docs list only `id` (string) and `name` (string).
- Permission: `machine_read`.

**GET /api/v0/machines/{id}** (CLI only)
- Query: `owner=me`. 200: a JSON list, normally one element, same fields as above.
- Permission: not documented.

**GET /api/v0/machines/maintenances** (CLI only)
- Query: `owner=me`, `machine_ids` = JSON list of integers.
- 200: list of `{machine_id, start_time, end_time, duration_hours, maintenance_category}`;
  the CLI formats the two times as epoch seconds in UTC.

**GET /api/v0/machines/{machine_id}/reports** (docs, CLI)
- 200: array of `{problem: string, message: string, created_at: date-time string}`.
- Permission: `machine_read`.

**GET /api/v0/users/{user_id}/machine-earnings** (docs, CLI; CLI uses `me`)
- Query: `sday`, `eday` (days since the Unix epoch; docs integer, CLI float), `machid`
  (integer, optional), `last_days` (integer, docs only), `owner=me` (CLI only).
- 200: `summary{total_gpu,total_stor,total_bwu,total_bwd}`, identity strings,
  `current{balance,service_fee,total,credit}`,
  `per_machine[{machine_id,gpu_earn,sto_earn,bwu_earn,bwd_earn}]`,
  `per_day[{day,gpu_earn,sto_earn,bwu_earn,bwd_earn}]`. All amounts `number`.
- Permission: `billing_read`.

**GET /api/v0/users/current** (docs, CLI)
- 200 (docs): `id` integer, `key_id` integer, `email` string, `balance` number, `ssh_key`
  string, `sid` string. The authentication page's sample shows `credit` as well.
- The CLI additionally reads `host_agreement_accepted` (truthy for a host account) and
  strips `api_key` from the body before returning it, so the raw response can contain the
  API key. Redact it before storing a snapshot.
- Permission: `user_read`.

**GET /api/v1/invoices** (docs, CLI)
- Query: `select_filters` (JSON; `when` range in unix seconds UTC, required; optional
  `service`), `order_by`, `latest_first` (default true), `limit` (default 60),
  `after_token`.
- 200: `success`, `count`, `total`, `next_token`, `results[{start, end, type, source,
  description, amount, metadata{invoice_id, service}, items}]`.
- Permission: `billing_read`.

**DELETE /api/v0/machines/{id}/asks/**, **PUT /api/v0/machines/create_asks/**,
**PUT /api/v0/machines/{id}/dnotify/**, **PUT /api/v0/machines/{id}/cancel_maint/**,
**PUT /api/v0/machines/{id}/cleanup/**, **PUT /api/v0/machines/{id}/minbid/**,
**DELETE /api/v0/machines/{id}/defjob/**: see the table in D13. Permission:
`machine_write`. None is documented as idempotent.

**POST /api/v0/auth/apikeys/** (docs, CLI)
- Body: `name` (string, required), `permissions` (object), `key_params`.
- 200: `id` integer, `key` string, `permissions`.
- Permission: `user_write`.

Not for HappyMining use (installer internals, undocumented): `POST /api/v0/daemon/identify/`,
`PUT /api/v0/machines/report_new_key/`.

Webhooks: Vast documents notification webhooks (signed POST, headers `X-Vast-Event-Id`,
`X-Vast-Delivery-Attempt`, `X-Vast-Timestamp`, `X-Vast-Signature-256`, at most 4 per user,
at-least-once delivery, event keys discovered through the "List notification types"
endpoint). Seven host notification types are described in prose (machine offline,
verification failed, issue detected, reported by renter, disk space low, listing ending
soon, maintenance window confirmed). Their event keys were not read. There is no
documented earnings or payout webhook.

## Units, boundaries, pagination, rate limits

| Topic | Finding | Status |
| - | - | - |
| Earnings `sday`, `eday` | Days since the Unix epoch (seconds / 86400) | Confirmed (official CLI source); docs give type integer and no unit |
| Earnings range ends | Inclusive or exclusive | Unresolved |
| Earnings day boundary | 00:00 UTC implied by the unit | Unresolved |
| Earnings `per_day.day` | Integer; unit not stated | Unresolved |
| Earnings amounts | JSON number; currency not stated; gross or net not stated | Unresolved |
| Invoice times | Unix seconds, UTC | Confirmed (docs) |
| Invoice `amount` | "Amount in dollars. Negative for charges, positive for transfers/payouts." | Confirmed (docs) |
| List `end_date` | Unix timestamp, float | Confirmed (docs, CLI) |
| Maintenance `sdate` | Docs: ISO date-time string. CLI: unix epoch seconds UTC, float | Docs and CLI disagree |
| Maintenance `duration` | Hours; whole hours, minimum one, in the console | Confirmed (docs, CLI) |
| Prices | GPU $/hour per GPU; disk $/GB/month; bandwidth $/GB | Confirmed (official CLI source) |
| Pagination, host endpoints | None documented or used | Confirmed absent from docs and CLI; server behaviour for large fleets Unresolved |
| Pagination, invoices | `limit`, `after_token`, `next_token`; filters must stay identical | Confirmed (docs, CLI) |
| Rate limits | Per endpoint and per identity; minimum interval; no numbers; 429; no `Retry-After` | Confirmed (docs) |
| CLI retry | 3 attempts, 0.15 s then 0.225 s, on 429/502/503/504 and connection errors or timeouts, all methods | Confirmed (official CLI source) |
| CLI timeout | 120 s per request | Confirmed (official CLI source) |

## Supported versions

| Component | Version | Source |
| - | - | - |
| Host OS (Vast) | Ubuntu Server 22.04 LTS minimum, 24.04 LTS recommended; x86_64 or ARM64; server edition only | Confirmed (docs) |
| Kernel | Latest security patch level of the installed LTS; GA or HWE | Confirmed (docs) |
| NVIDIA driver | "A currently supported release for your GPU"; no version named | Confirmed (docs); specific version Unresolved |
| CUDA | 11.8 or newer (12.6 or newer on ARM64) | Confirmed (docs) |
| Docker (installed and pinned by Vast) | `docker-ce` `5:28.*`, `containerd.io` `1.*`, `nvidia-docker2` `2.13.*` at install; the upgrade page shows 29.x and containerd 2.x as valid upgrade targets | Confirmed (official host script); Confirmed (docs) |
| Vast CLI inspected | `vastai` 1.8.2 | Confirmed (official CLI source) |
| Vast API | `v0`, plus `v1` for invoices | Confirmed (docs, CLI) |
| Autoinstall | Ubuntu Server 20.04 and later; strict unknown-key validation and optional top-level `autoinstall:` in `autoinstall.yaml` from 24.04; ordered match lists from Subiquity 24.08.1 | Confirmed (docs) |
| Vast Terms of Service | Version Date September 1, 2026 | Confirmed (docs) |

## Unresolved points and what would resolve them

| # | Point | What would resolve it |
| - | - | - |
| 1 | Exact documented install command; where the host obtains its key; whether the key is temporary or single-use | A person signed in to a host account reads https://cloud.vast.ai/host/setup/ and saves a dated copy; or written confirmation from Vast |
| 2 | Hosting agreement text | Same: a saved copy of https://cloud.vast.ai/host/agreement |
| 3 | Whether earnings amounts are gross or net of Vast's fee; meaning of `current.service_fee`, `balance`, `total`, `credit` | Written answer from Vast support; or one real week where the API totals are compared with the payout invoice and the earnings PDF |
| 4 | Current fee percentage | Hosting agreement or Vast support. The 25% figure comes from a stale page |
| 5 | Earnings range: inclusive or exclusive ends; fractional days; UTC day boundary; unit of `per_day.day`; `last_days` | Three read-only calls on a real account around a known day, saved as fixtures |
| 6 | Whether `machid` filters `per_day`; whether per-machine calls sum to the unfiltered call; whether `summary` equals the sums | Same test |
| 7 | Whether past days' amounts change | Vast support; and a daily re-import of a trailing window that records any difference |
| 8 | Earnings currency | Vast support; assume nothing beyond the USD wording of other pages |
| 9 | Rental-state fields of a machine (`current_rentals_*`, `clients`, listed flag, listing end date, meaning and format of `gpu_occupancy`, values of `verification`, `error_description`) | A raw `vastai show machines --raw` capture from a real host account, plus Vast support for the meanings. Field names seen in a capture are still undocumented semantics |
| 10 | Mapping of console counters `Occ`, `#Running D/I/R`, `#Stored D/I/R` to API fields; expansion of D, I, R | Vast support |
| 11 | Whether `machine_read` covers `GET /machines/{id}` and `GET /machines/maintenances`; whether a key can be constrained to machine ids | Create a scoped key and test read-only calls |
| 12 | Unit of the rate-limit `threshold`; real limits; pagination for large fleets | Vast support ("contact support with the endpoint(s), your expected call rate, and your account details") |
| 13 | `schedule maint` `sdate` format accepted by the server (ISO string or epoch seconds); `maintenance_reason` | Vast support, or a test on an idle machine owned by HappyMining |
| 14 | General minimum notice for maintenance outside the three procedures that state 48 hours | Hosting agreement or Vast support |
| 15 | Documented storage requirement wording (XFS, mount point, quotas), port range numbers, IOMMU section, recommended driver install method and version | Saved copy of the setup page |
| 16 | Whether the account key given to the installer is stored on the host | Byte-exact reading of the installer and inspection of a test install |
| 17 | Byte-exact content and hash of the installer and uninstaller | Download both from an unrestricted network and record sha256 and date |
| 18 | Authorization to operate third-party-owned machines and redistribute earnings | See "Commercial authorization" |
| 19 | How the Terms' ban on scripts and automation applies to use of the published API | Written statement from Vast |
| 20 | Whether subaccounts or teams give per-owner earnings and payouts | Vast support |
| 21 | Which invoice rows and fields represent host payout status Pending and Paid; which earnings days a payout covers | A real payout cycle captured from `GET /api/v1/invoices`, compared with Payout History |
| 22 | Host notification webhook event keys | The "List notification types" endpoint on a real account |
| 23 | Autoinstall: schema file name in the repository; whether `path` accepts `/dev/disk/by-id/...`; layout `mode` | Read the Subiquity repository at the tag shipped in the 24.04 ISO in use; test in a VM with two disks |
| 24 | nvidia-smi identifiers `index`, `uuid`, `memory.total`, `power.draw`, `fan.speed`; CSV text for unsupported values; memory unit | `nvidia-smi --help-query-gpu` and one CSV sample on the target driver, committed as fixtures |

## Commercial authorization

Authorization from Vast.ai for HappyMining to operate machines owned by third parties
under a HappyMining host account, and to redistribute the resulting earnings to those
owners, is an **external launch prerequisite**. As of 2026-10-02 it is **unverified**. No
evidence of such authorization has been supplied, and no page read grants or denies it.
The hosting agreement was not readable.

The pages read contain terms that bear on it and do not settle it: "You may not use
anyone else's account at any time"; the account "may not be assigned by you without our
express written consent"; automation is prohibited "except as expressly authorized in a
separate written agreement with Company"; hosts must receive payouts as B2B payments to a
single payout method; no payout splitting is documented.

Evidence that would close it:

1. A written statement from Vast.ai (signed agreement, or email from an identifiable Vast
   representative) that HappyMining may list machines owned by its customers under its
   host account or accounts.
2. The same for receiving payouts for those machines and paying the owners.
3. Confirmation of the account structure Vast wants: one account, subaccounts per owner,
   or a team.
4. Confirmation that automated use of the host API at HappyMining's polling rate is
   permitted, with any rate limits.
5. A dated copy of the hosting agreement accepted by the HappyMining account, and of the
   Datacenter Hosting Agreement if that programme is pursued.
6. The current fee terms that apply to the account.

Until then the product is built and tested offline, LIVE mode stays read-only, and no
image contains a Vast account credential.

## Not HappyMining endpoints vs Vast endpoints

Everything in this file belongs to someone else:

- Every path beginning `/api/v0/` or `/api/v1/` on `console.vast.ai` (or `vast.ai`) is
  **Vast.ai's**. So are the `vastai` CLI, the host daemon, its files under
  `/var/lib/vastai_kaalia`, the installer and the uninstaller.
- Autoinstall, Subiquity, cloud-init and curtin behaviour is **Canonical's**.
- `nvidia-smi` behaviour is **NVIDIA's**.

HappyMining's own API (`/api/v1/...` on HappyMining's hosts, including pairing, device
credentials, heartbeats and typed operations) is documented in `docs/agent-protocol.md`.
The two `/api/v1` prefixes are unrelated: Vast's `GET /api/v1/invoices` is a Vast endpoint.

HappyMining does not add, rename or assume any Vast endpoint, field, permission, webhook
event or payout feature beyond what is marked Confirmed above.
