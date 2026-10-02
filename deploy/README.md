# Deployment

Two ways to run the control plane (API, dashboard, worker, PostgreSQL). Both
are single-host Docker Compose stacks for pilot scale.

| | Stand-alone host | Host that already runs Traefik |
|---|---|---|
| Files | `deploy/docker-compose.yml` (+ `docker-compose.demo.yml`) | `deploy/hostinger/docker-compose.yml` |
| Reverse proxy | Caddy, in the stack, publishes 80/443 | The host's Traefik; the stack publishes nothing |
| Source | A checkout of this repository on the host | Built by Docker from the Git repository at a pinned commit |
| Config | `deploy/.env` (from `deploy/.env.example`) | The project's environment (from `deploy/hostinger/.env.example`) |

What neither of them does: deploy a LIVE instance for you. LIVE needs
decisions and credentials that are not in this repository (see "Going LIVE").

## Modes are deployments

A DEMO instance and a LIVE instance are two stacks, with two databases, two
sets of secrets and two host names. A database records the mode that first
used it, and a process in the other mode refuses to start against it. There is
no switch that turns a demo into a pilot.

## A. Stand-alone host (Caddy)

```sh
cp deploy/.env.example deploy/.env        # fill it in; never commit it

# LIVE (or whatever deploy/.env selects)
docker compose -f deploy/docker-compose.yml --env-file deploy/.env up -d --build

# DEMO staging: synthetic data, basic auth in front of every page
docker compose -p happymining-demo \
  -f deploy/docker-compose.yml -f deploy/docker-compose.demo.yml \
  --env-file deploy/.env.demo up -d --build
```

`make compose-config` validates every compose file against the example
configuration without a Docker daemon.

## B. The Hostinger VPS (Traefik)

What is on that server (looked at on 2026-10-02, through the Hostinger API,
read-only): Ubuntu 24.04, 4 vCPU, 16 GB. Traefik v3 owns ports 80 and 443 and
routes by container label over the external Docker network `proxy`, entry
point `websecure`, certificate resolver `letsencrypt`. About fifteen other
Compose projects run there (a mining manager and its pre-production copy,
observability, object storage, and others). The firewall accepts 22, 80, 443
and one UDP port.

Consequences:

- This stack must not publish ports and must not bring its own proxy on
  80/443. `deploy/hostinger/docker-compose.yml` joins `proxy` and is routed by
  label.
- The Hostinger API can deploy a Compose project from a compose file and an
  environment block. It cannot copy files to the server or run commands on it.
  So the image is built by Docker from this Git repository
  (`build.context: <repo>.git#<commit>`). **The commit has to be pushed to
  GitHub first**, and the repository has to be readable by the server (it is
  public).
- It is a shared host. Several containers there mount the Docker socket, which
  is root on the host. Acceptable for a demo with synthetic data. For LIVE,
  with beneficiary bank details and the Vast account key, use a host that runs
  nothing else, or accept that risk in writing.

### Deploy or redeploy

1. Push the commit to deploy.
2. Create (or replace) the project with the Hostinger API operation
   `vps_docker_create`: `project_name` `happymining-os`, `content` the text of
   `deploy/hostinger/docker-compose.yml`, `environment` the filled-in
   variables from `deploy/hostinger/.env.example`, with `HM_GIT_REF` set to
   the commit SHA.
3. Check: `vps_docker_containers` (the `api` container must be `healthy`,
   `migrate` exited 0), `vps_docker_logs`, then
   `https://<HM_PUBLIC_HOST>/healthz`.

A redeploy with a new `HM_GIT_REF` builds a new image tag and recreates the
containers; the database volume stays. Deleting the project deletes the
volume.

### Host names

`HM_PUBLIC_HOST` (and optionally `HM_API_HOST`) must resolve to the server
*before* deploying: Traefik requests a certificate for each name in the
routing rule, and failed attempts are rate limited by Let's Encrypt.

- `happymining.fr` is on Shopify, and its DNS is not managed in the Hostinger
  account. To use `cloud.happymining.fr` and `api.happymining.fr`, add A
  records for those two names pointing at the server's IPv4 address at
  whoever hosts the zone. This does not touch the shop.
- Until then the only name that resolves to the server is its Hostinger host
  name (`srv<id>.hstgr.cloud`).

### The staging gate

The demo login has no passwords, so a DEMO instance must not be open to the
internet. Traefik asks for HTTP basic authentication on every page and on the
two sign-in endpoints of the API. The rest of `/api/v1` (which needs a session
token or a device credential anyway), `/healthz` and `/static` are not gated:
an agent could not pair through basic authentication.

If `HM_BASIC_AUTH_USERS` is not set, the gate uses an account whose password
nobody has. Forgetting to configure it locks the pages; it does not open them.

For LIVE, where people sign in with a password and MFA, set
`HM_GATE_MIDDLEWARES=hmos-limit,hmos-headers`.

### Mole Hash on the same server

Mole Hash (`mine_manager`, behind the same Traefik) reaches the integration
API through the public host name, like any other caller: `/api/v1/` is routed
without the staging gate, because it has its own authentication. Give the
Mole Hash backend `HAPPYMINING_API_URL` and `HAPPYMINING_API_TOKEN`
(`integrations/molehash/README.md`). Do not point it at the container over
the Docker network: the API answers only its configured host names, and the
token should travel over TLS.

### Not included in the Traefik variant

- The on-demand backup job. Run `scripts/backup.sh` from the host against the
  `db` container, and copy the dumps off the server. `scripts/restore-verify.sh`
  is the tested restore procedure. See `docs/operations.md`.
- A second proxy. If Cloudflare or a load balancer is put in front of Traefik,
  set `HM_TRUSTED_PROXY_HOPS=2`, or every client shares one rate limit.

## Going LIVE

The software refuses to start in LIVE until the configuration is real, and
holds or blocks the parts whose prerequisites are not met. In order:

1. A written agreement with Vast covering the operation of third-party
   machines and API use for it. Its reference goes in
   `HM_VAST_COMMERCIAL_AUTHORIZATION_REF`; while empty, the adapter does not
   call Vast.
2. A scoped Vast API key (`machine_read`, `billing_read`, `user_read`) in
   `HM_VAST_API_KEY`.
3. Generated secrets, a strong database password, real host names with HTTPS.
4. `python -m happymining.cli create-admin <email>`, then MFA enrollment.
5. The unresolved points in `docs/integration-evidence.md`. Until the earnings
   semantics are verified against real data, LIVE earnings are fetched and
   held, not posted. Until Vast exposes rental state, disruptive maintenance
   stays blocked.
6. Backups running and a restore rehearsed.
7. Payouts stay off (`HM_PAYOUTS_ENABLED=false`) until the above is done and
   someone has decided, in writing, to turn them on.

`docs/limitations.md` lists everything that is not built or not verified.
