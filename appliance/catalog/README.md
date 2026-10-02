# Plugin catalog

The plugins a HappyMining machine can run, as the firmware ships them. The
contract is `docs/appliance.md`, section 7 (and sections 1, 2, 10 and 11 for
the modes, backups and the vectorizer). This file explains how an entry is
written, how to add one, and what was verified about each shipped entry.

The cloud names a plugin and sends typed settings; it never sends a Compose
file, an image, a command or a path. A new plugin, or a new version of one,
arrives with a firmware update.

## Where the catalog is read

| Reader | Reads | Where |
|---|---|---|
| Root helper on the machine | `plugin.json` (strictly); checks that `compose.yaml` is a regular file | `agent/internal/appliance` (`LoadCatalog`) |
| Control plane | `plugin.json`, from `HM_CATALOG_DIR` | `api/happymining/services/catalog.py` |
| Repository tests | both files, every rule below | `tests/appliance/catalog/catalog_rules.py` (`check_catalog`), run by `test_catalog_rules.py` |

The package installs this directory to `/usr/share/happymining/catalog/`. The
helper starts an entry with

```
docker compose -p hm-<id> --env-file <root-only file> -f /usr/share/happymining/catalog/<id>/compose.yaml up -d
```

and stops it with the matching `down`. Every service joins the Docker network
`hm-appliance`, which the helper creates, and is reached there by its service
name (`http://ollama:11434`, `http://qdrant:6333`, …).

## An entry

A directory `<id>/` holding exactly two regular files, `plugin.json` and
`compose.yaml` (no symbolic link, no `.env`, no override file). Files directly
in the catalog directory, such as this README, are not entries.

### `plugin.json`

Strict JSON (no duplicate key, no `NaN`), at most 64 KiB. Every key below is
required except `build`; an unknown key is an error.

| Key | Rule |
|---|---|
| `schema` | the integer `1` |
| `id` | `^[a-z][a-z0-9-]{0,30}$`, equal to the directory name |
| `version` | a string; it changes whenever the entry changes (the helper reports it in the heartbeat) |
| `name`, `summary`, `license` | text for people, no control character (name ≤ 80, summary ≤ 300, license ≤ 80 characters) |
| `homepage` | an `https://` address |
| `gpu` | `true` when a service reserves the GPUs. The helper does not start such a plugin while a container HappyMining did not start is running, unless `ALLOW_FOREIGN_CONTAINERS=true` |
| `modes` | non-empty, from `private_ai` and `vectorize`; never `vast` |
| `requires` | other plugin ids; each must exist, must run in every mode this one runs in, and the requirements must not form a cycle |
| `ports` | `{"name", "port", "protocol", "ui"}`: the only ports the Compose file publishes, unique across the catalog |
| `settings` | name → `{"type", "label", "env", "default", …}`; see below |
| `secrets` | `{"key", "env", "label", "required"}`; the document's secret name is `plugin.<id>.<key>` (at most 63 characters in all, section 5) |
| `images` | every image the Compose file uses (or, with `build`, the base images of the Dockerfile): `{"ref", "digest", "verified"}` |
| `volumes` | `{"name", "backup"}` for each named volume; `backup` is `always`, `models` (only with `include_models`) or `never` |
| `build` | optional, `{"context", "image"}`: an image built on the machine from `/usr/share/happymining/<context>`; `image` is `happymining/<name>:<version of the entry>` |
| `post_start` | `{"service", "exec", "timeout_s"}` and optionally `"for_each"`: argv arrays run in a service after it started, no shell. `{item}` is replaced by each item of the `string_list` setting named by `for_each`; it cannot be the command itself |

Settings:

| `type` | Extra keys | Passed to Compose as |
|---|---|---|
| `bool` | — | `true` / `false` |
| `int` | `min`, `max` | a decimal number |
| `enum` | `values` | the value |
| `string` | `pattern`, `max_len` ≤ 200 | the value |
| `string_list` | `pattern`, `max_items` ≤ 32 | the items joined by one space |

- `env` is `^HM_SET_[A-Z0-9_]{1,40}$`; a setting's variable and a secret's
  variable are never the same.
- A pattern is `^…$` as a whole, in the syntax Python and Go (RE2) share, with
  explicit character classes (no `\d`, `\w`, `.`, negated class, look-around,
  back-reference or flag). It is checked on the parsed expression, not on
  samples: it must be impossible for it to match a control character, a quote,
  `$`, `` ` `` or `\`. A list pattern must also be unable to match a space (the
  list travels as one space-separated variable) or a value that starts with a
  dash (an item can become an argument of a `post_start` command, where
  `-x` would be read as an option; the helper also refuses such an item).
- A setting named `bind` is the enum of `lan` and `localhost` in
  `HM_SET_BIND`: whether the plugin's ports are reachable from the owner's
  network or from this machine only. See "Open points".

Secrets: `key` is `^[a-z][a-z0-9_]{0,30}$` and `env` is `^[A-Z][A-Z0-9_]{1,60}$`.
The variable may not start with `HM_`, `COMPOSE_`, `DOCKER_` or `BUILDKIT_`
and may not be `PATH`, `HOME`, `PWD`, `USER`, `SHELL`, `HOSTNAME`,
`LD_PRELOAD`, `LD_LIBRARY_PATH` or `TMPDIR`. The helper writes opened secrets
to the root-only env file it passes to Compose; a secret that is not set must
be left out of that file, not written empty (see "Open points").

Images: `ref` names the registry and a tag (`docker.io/ollama/ollama:0.35.0`),
in lower case, never a moving tag such as `latest`, `main` or `stable`.
`verified` is `true` exactly when `digest` (`sha256:` and 64 hexadecimal
characters) is given, which is only when the digest was read from the registry
for that tag. The Compose file then uses `ref@digest`; an unverified image is
used by its `ref`, and the helper refuses to start that plugin unless
`ALLOW_UNPINNED_IMAGES=true`.

### `compose.yaml`

Plain YAML, at most 64 KiB, one document: no duplicate key, anchor, alias,
merge key (`<<`) or tag (`!reset`, `!override`, `!!python/…`). Top-level keys:
`services`, `volumes`, `networks` only. In every service:

- `restart: unless-stopped` and the label `eu.happymining.plugin: <id>`;
- `networks: [hm-appliance]`, and the file declares `hm-appliance` with
  `external: true` and nothing else;
- services are named `<id>` (the main one, required) or `<id>-…`, and no two
  entries of the catalog use the same service name;
- no `privileged`, `cap_add`, `network_mode`, `pid`, `ipc`, `uts`,
  `userns_mode`, `cgroup`, `devices`, `gpus`, `runtime`; `security_opt` only
  `no-new-privileges:true`; a GPU is reserved with
  `deploy.resources.reservations.devices: [{driver: nvidia, count: all, capabilities: [gpu]}]`
  (or `device_ids` instead of `count`), and only when `gpu` is `true`;
- the allowed keys are `image`, `restart`, `labels`, `networks`, `ports`,
  `volumes`, `environment`, `command`, `entrypoint`, `deploy` (resources only),
  `healthcheck`, `init`, `cap_drop`, `security_opt`, `pull_policy`, `user`,
  `working_dir`, `stop_grace_period`, `stop_signal`, `read_only`, `tmpfs`,
  `depends_on`, `expose`; everything else is refused (`build`, `env_file`,
  `container_name`, `extra_hosts`, `volumes_from`, `extends`, `sysctls`, …);
- volumes: a named volume declared at the top level without options, the same
  set as `plugin.json`; or a bind mount of `${HM_PLUGIN_DATA}/…`,
  `/var/lib/happymining-plugins/<id>/…` or `/srv/happymining/…` (read-only),
  written as a plain path (no `..`, `.`, `//`, trailing `/`). Never a socket;
- ports: exactly `"${HM_BIND}:<host>:<container>"`, TCP, and the host ports are
  exactly those of `plugin.json`;
- images: as listed in `plugin.json` (`ref@digest` when verified); the image of
  `build` is used with `pull_policy: never`.

Variables, always written `${NAME}` (no default, no `$NAME`; `$$` is a literal
dollar):

| Variable | Where |
|---|---|
| `${HM_BIND}` | the address of published ports, in `ports` only |
| `${HM_PLUGIN_DATA}` | `/var/lib/happymining-plugins/<id>`, as the source of a bind mount only |
| `${HM_SET_…}` of a setting of the entry | `environment`, `command`, `entrypoint`, `healthcheck` |
| a secret's variable | in `environment` only, as a pass-through (`- NAME`) or as the whole value of an entry (`KEY=${NAME}`) |
| `HM_ANSWER_API_KEY` | pass-through in the plugin `vectorizer` only (the key of section 4.4, not a plugin secret) |

A setting that reaches a `command`, `entrypoint` or healthcheck `test` must be
one element of an argv list: not a string form (Compose splits it into words),
not `CMD-SHELL`, not after a shell (`sh`, `bash`, `env`, …) and not the program
itself; and an element that begins with a setting needs a setting that cannot
start with a dash (`int` with `min` ≥ 0, no enum value or pattern that starts
with `-`).

### Every rule the tests enforce

`check_catalog(Path("appliance/catalog"))` returns a list of violations, each
with the plugin, one of these codes and a detail. An empty list means the
catalog respects every rule. Each code is produced by at least one broken
example in `test_catalog_rules.py`, which also checks that no other code is.

| Code | Meaning |
|---|---|
| `bad-id` | a directory of the catalog is not named after a plugin id, or the id differs from it |
| `missing-file` | plugin.json or compose.yaml is missing, is not a regular file or is a symbolic link |
| `extra-file` | the entry holds something else than plugin.json and compose.yaml |
| `json-invalid` | plugin.json is not strict JSON (syntax, duplicate key, size, not an object) |
| `unknown-key` | a key the contract does not define |
| `missing-key` | a required key is absent |
| `bad-schema` | schema is not the integer 1 |
| `bad-text` | version, name, summary, homepage, license or a label is not acceptable text |
| `bad-type` | a value has the wrong JSON type |
| `bad-modes` | modes is empty, repeats a mode or names an unknown one |
| `vast-mode` | modes contains vast: no plugin runs in that mode |
| `bad-requires` | requires is malformed, repeats an id or names the plugin itself |
| `requires-unknown` | requires names a plugin that is not in the catalog |
| `requires-cycle` | the plugin's requirements lead back to it |
| `requires-mode` | a required plugin does not run in a mode in which this one runs |
| `bad-port` | an entry of ports is malformed or repeats a name or a number |
| `bad-setting` | a setting is malformed or its default is not acceptable |
| `bad-setting-env` | a setting's variable is not HM_SET_… |
| `bad-pattern` | a pattern is not anchored, not portable, or can let a forbidden character (or, for a list, a space or a leading dash) through |
| `bad-bind` | the setting named bind is not the enum of lan and localhost in HM_SET_BIND |
| `env-duplicate` | two settings or secrets use the same variable |
| `bad-secret` | an entry of secrets is malformed, or its secret name would exceed 63 characters |
| `secret-env-reserved` | a secret's variable is reserved for the helper, for settings or for Docker |
| `bad-image` | an entry of images is malformed, has no registry, no tag or a moving tag |
| `image-pin` | verified and digest disagree: verified is true exactly when a digest is given |
| `bad-volume` | an entry of volumes is malformed |
| `bad-build` | build is malformed, or its image is not `happymining/<name>:<version of the entry>` |
| `bad-post-start` | an entry of post_start is malformed |
| `yaml-invalid` | compose.yaml is not acceptable YAML (syntax, duplicate key, anchor, alias, merge key, tag, nesting, size) |
| `compose-unknown-key` | a Compose key that no catalog entry may use |
| `no-services` | compose.yaml defines no service |
| `main-service-missing` | no service is named after the plugin |
| `service-name` | a service is named neither `<id>` nor `<id>-…` |
| `service-name-duplicate` | two entries define a service with the same name |
| `restart-policy` | a service does not have restart: unless-stopped |
| `label-missing` | a service does not carry `eu.happymining.plugin=<id>` |
| `network` | a service does not join exactly hm-appliance, or that network is not declared external |
| `privileged` | a service asks for privileged (even `privileged: false` is refused) |
| `cap-add` | a service adds a capability |
| `host-namespace` | a service uses the host's network, pid, ipc or another host namespace |
| `security-opt` | a service weakens the container's confinement with security_opt |
| `devices` | a service asks for host devices outside the NVIDIA deploy syntax |
| `socket-mount` | a service mounts a socket of the host (the Docker socket) |
| `bind-outside` | a bind mount leaves /srv/happymining and the plugin's data directory |
| `bind-not-readonly` | a bind mount of /srv/happymining is not read-only |
| `volume-syntax` | a volume entry is not a named volume or an allowed bind mount in a known form |
| `volume-undeclared` | a service uses a named volume the Compose file does not declare |
| `volume-options` | a declared volume has options (driver, external, name, …) |
| `volumes-mismatch` | the named volumes of compose.yaml and of plugin.json differ |
| `port-syntax` | a published port is not written `${HM_BIND}:<host>:<container>` |
| `port-bind` | a published port is not bound to ${HM_BIND} |
| `ports-mismatch` | the published ports and the ports of plugin.json differ |
| `port-duplicate` | two entries publish the same port |
| `image-undeclared` | a service uses an image that plugin.json does not list |
| `image-not-pinned` | a verified image is not written ref@digest with the digest of plugin.json |
| `image-pinned-unverified` | compose.yaml pins a digest for an image that is not verified |
| `image-unused` | plugin.json lists an image that compose.yaml does not use |
| `build-pull-policy` | the service that uses the locally built image does not say pull_policy: never |
| `pull-policy` | pull_policy is neither never nor missing |
| `unknown-variable` | a ${VARIABLE} that is neither HM_BIND, HM_PLUGIN_DATA, a setting nor a secret |
| `variable-form` | a variable is not written ${NAME} (no default, no $NAME, no stray $) |
| `variable-place` | a variable is used where it may not be (image, key, label, …) |
| `command-form` | a setting reaches a command, entrypoint or healthcheck that is a string, runs a shell, or is the program itself |
| `argument-dash` | a setting that begins an argument of a command can start with a dash |
| `secret-in-wrong-place` | a secret is used elsewhere than as the whole value of an environment entry |
| `passthrough-unknown` | an environment entry without a value names something that is not a secret or a setting |
| `bad-environment` | an environment entry is malformed |
| `gpu-not-declared` | a service reserves a GPU and plugin.json does not say gpu: true |
| `gpu-syntax` | a GPU reservation is not the NVIDIA deploy syntax |
| `post-start-service` | post_start names a service that compose.yaml does not define |
| `depends-on` | depends_on names a service that compose.yaml does not define |

The fixture catalog `appliance/testdata/catalog/` (the one the document
validators are tested against) is checked with the same rules. Its Compose
files are stubs, so it has three listed deviations per entry (`network`,
`ports-mismatch`, `volumes-mismatch`); the test fails if one disappears or a
new one appears.

When Docker Compose is installed, the tests also run `docker compose config`
on every entry with dummy values (nothing is pulled or started) and compare
what Compose reads with what the checker read.

## Adding a plugin

1. Read the project's own documentation and its Compose example. Choose a
   release tag (never `latest`), read the digest for that tag from the
   registry (Docker Hub: `https://hub.docker.com/v2/repositories/<ns>/<repo>/tags/<tag>`,
   field `digest`; ghcr.io: an anonymous token, then the manifest's
   `Docker-Content-Digest`). Without a digest you read yourself, write
   `"digest": null, "verified": false` and use the tag in `compose.yaml`.
2. Create `<id>/plugin.json` and `<id>/compose.yaml` by the rules above. Name
   the main service `<id>`; publish only what people or other machines need,
   on `${HM_BIND}`; keep the project's own login on, and make a password or
   token a `required` secret. Put persistent data in named volumes and give
   each a backup policy.
3. Turn off what the program sends out on its own (statistics, update checks):
   the image is pinned and updated with the firmware.
4. Add the plugin to `SHIPPED_PLUGINS` in `tests/appliance/catalog/test_catalog_rules.py`
   and a verification section below, then run
   `api/.venv/bin/python -m pytest tests/appliance/catalog -q -p no:cacheprovider`.
5. Change `version` whenever the entry changes after a release.

## What was verified (2026-10-02)

Everything in this section was read on **2026-10-02** from the sources named.
No image was pulled or started and no plugin was run: what a program does at
run time is what its documentation or source says. Digests were read from the
Docker Hub API (`/v2/repositories/<ns>/<repo>/tags/<tag>`, field `digest`: the
digest of the multi-architecture index) twice, from the tag and from the tag
listing; for every plugin image both agreed. The registry itself
(`registry-1.docker.io`) was not reachable from the machine used, so no
manifest was read from it directly. The Docker Hub API can lag: for the moving
tag `python:3.12-slim-bookworm` (the vectorizer's base) the two answers
differed that day. Before a release, confirm each digest against the registry
(`docker buildx imagetools inspect <ref>`) on a machine that reaches it.

### Summary

| Plugin | Image | Tag | Digest |
|---|---|---|---|
| `ollama` | `docker.io/ollama/ollama:0.35.0` | 0.35.0 (latest release; `latest` has the same digest) | verified: `sha256:2a6e883b917fc543389599dae79918f5cac9e1438890506982f44aa4f5625d01` |
| `qdrant` | `docker.io/qdrant/qdrant:v1.19.1` | v1.19.1 (latest release; `latest` has the same digest) | verified: `sha256:12364fe851b9f17356fc88189fc06d1b521262e04659ec7345975b00c9246a10` |
| `vectorizer` | built on the machine as `happymining/vectorizer:1` from `appliance/vectorizer/Dockerfile`; base `docker.io/library/python:3.12-slim-bookworm` | 3.12-slim-bookworm, pinned to the index of Python 3.12.14 | verified: `sha256:392307d22300de8b5986851a12d9176dfc0fc073e65bf6523ebd7dcbeb23564e` (see below) |
| `open-webui` | `docker.io/openwebui/open-webui:0.11.4` | 0.11.4 (newest version tag) | verified: `sha256:9591b13f13843c7721c2b8eaf7382846c81b3ffe126526d1888d1fed50c6a33f` |
| `openclaw` | `docker.io/openclaw/openclaw:2026.9.7` | 2026.9.7 (full release of 2026-09-30) | verified: `sha256:0da12cd49983fcb5e4915fd3135ce7a33d82f93649b1df6964946d2c1d1dbcfc` (same as `2026.9.7-slim`) |
| `hermes` | `docker.io/nousresearch/hermes-agent:v2026.9.24` | v2026.9.24 (newest version tag) | verified: `sha256:fca358f12efd65bfaaca05884166f15c0e2788375ca30d77061ac1ebc96452b7` |

### `ollama` — Ollama

| Fact | Source (read 2026-10-02) |
|---|---|
| Tag 0.35.0 and its digest; 0.35.0 is the newest non-rc tag and `latest` points to the same digest | https://hub.docker.com/v2/repositories/ollama/ollama/tags/0.35.0, https://hub.docker.com/v2/repositories/ollama/ollama/tags?ordering=last_updated |
| v0.35.0 is a full release (2026-09-28) | https://github.com/ollama/ollama/releases/tag/v0.35.0 |
| Docker use: `-v ollama:/root/.ollama -p 11434:11434`, NVIDIA GPUs with the NVIDIA Container Toolkit | https://raw.githubusercontent.com/ollama/ollama/v0.35.0/docs/docker.mdx |
| The image sets `OLLAMA_HOST=0.0.0.0:11434`, `EXPOSE 11434`, entrypoint `/bin/ollama serve` | https://raw.githubusercontent.com/ollama/ollama/v0.35.0/Dockerfile |
| `OLLAMA_KEEP_ALIVE` (duration, default 5m), `OLLAMA_CONTEXT_LENGTH` (default 0: chosen from the GPU memory), `OLLAMA_NO_CLOUD` (boolean: no cloud models, no web search); no server credential among the variables | https://raw.githubusercontent.com/ollama/ollama/v0.35.0/envconfig/config.go |
| Cloud features and their switch; prompts stay local when models run locally | https://raw.githubusercontent.com/ollama/ollama/v0.35.0/docs/faq.mdx |
| Licence MIT | https://raw.githubusercontent.com/ollama/ollama/v0.35.0/LICENSE |
| GPU reservation syntax (`driver: nvidia`, `capabilities: [gpu]`, `count` or `device_ids`, not both) | https://raw.githubusercontent.com/docker/docs/main/content/manuals/compose/how-tos/gpu-support.md, https://raw.githubusercontent.com/compose-spec/compose-spec/main/deploy.md |

- **What the customer gets.** Ollama's HTTP API on port 11434. It has no login
  of its own, so `bind` defaults to `localhost`: the API is reachable from the
  machine itself and, as `http://ollama:11434`, from the other plugins.
  Models listed in "Models to keep installed" are pulled after each start
  (`ollama pull`, one hour at most each).
- **Stored and backed up.** The volume `models` (`/root/.ollama`: the models,
  `~/.ollama/models` in envconfig, and Ollama's `server.json`, in the FAQ);
  backed up only with `include_models`, since models can be downloaded again.
- **Internet.** Model downloads from Ollama's registry. With "Local models
  only" (the default) Ollama's cloud models and web search are off.
- **Not verified.** That `ollama list` works as the healthcheck in this image
  (nothing was run); that Ollama makes no other request of its own (its code
  was not audited). Hermes needs a context length of 64000 or more (see
  `hermes`): set "Context length" accordingly when it uses a local model.

### `qdrant` — Qdrant

| Fact | Source (read 2026-10-02) |
|---|---|
| Tag v1.19.1 and its digest; `latest`, `v1` and `v1.19` point to the same digest | https://hub.docker.com/v2/repositories/qdrant/qdrant/tags/v1.19.1, https://hub.docker.com/v2/repositories/qdrant/qdrant/tags?ordering=last_updated |
| `docker run -p 6333:6333 qdrant/qdrant` | https://raw.githubusercontent.com/qdrant/qdrant/v1.19.1/README.md |
| HTTP 6333, gRPC 6334, `storage_path: ./storage`, `snapshots_path: ./snapshots`, `api_key` (every request must send it), `telemetry_disabled: false` by default | https://raw.githubusercontent.com/qdrant/qdrant/v1.19.1/config/config.yaml |
| Working directory `/qdrant` (so data is in `/qdrant/storage` and `/qdrant/snapshots`), `EXPOSE 6333 6334` | https://raw.githubusercontent.com/qdrant/qdrant/v1.19.1/Dockerfile |
| Configuration from the environment with prefix `QDRANT` and separator `__` (`QDRANT__SERVICE__API_KEY`, `QDRANT__TELEMETRY_DISABLED`); an empty key is treated as no key | https://raw.githubusercontent.com/qdrant/qdrant/v1.19.1/src/settings.rs |
| Licence Apache-2.0 | https://raw.githubusercontent.com/qdrant/qdrant/v1.19.1/LICENSE |

- **What the customer gets.** The vector database of the vectorizer, HTTP API
  on port 6333 (gRPC stays on the plugin network). `bind` defaults to
  `localhost`. Without the optional secret `plugin.qdrant.api_key` it has no
  authentication; the vectorizer sends no key today, so setting one breaks the
  vectorizer.
- **Stored and backed up.** `storage` (`/qdrant/storage`, the index) always;
  `snapshots` never.
- **Internet.** Usage statistics are turned off (`QDRANT__TELEMETRY_DISABLED=true`).
- **Not verified.** That nothing else is sent (the code was not audited).

### `vectorizer` — HappyMining vectorizer

| Fact | Source (read 2026-10-02) |
|---|---|
| Container layout: HTTP on 8765, `/config` read-only (`vectorizer.json`, `token`), `/state` volume, NAS read-only under `/srv/happymining/nas`, cloud key in `HM_ANSWER_API_KEY` | `docs/appliance.md`, section 11 |
| The server listens on `0.0.0.0:8765` in the container and reads `/config` and `/state` by default; it sends no API key to Qdrant | `appliance/vectorizer/hm_vectorizer/__main__.py`, `store.py` |
| Base image of the Dockerfile (both stages): `python:3.12-slim-bookworm@sha256:392307d2…`. That digest is the one the tag endpoint gave for `3.12-slim-bookworm` (last updated 2026-09-19) and the one of `3.12.14-slim-bookworm`; the tag listing shows that `3.12-slim-bookworm` moved on 2026-10-02 to `sha256:54c85f3c47607a77f32adec749d3c81d1348bf25833671f512b26a9b6d778cb3` (3.12.15). The pin keeps 3.12.14 | https://hub.docker.com/v2/repositories/library/python/tags/3.12-slim-bookworm, https://hub.docker.com/v2/repositories/library/python/tags/3.12.14-slim-bookworm, https://hub.docker.com/v2/repositories/library/python/tags?name=slim-bookworm |
| Built from `/usr/share/happymining/vectorizer`; the build downloads from PyPI, PyTorch's CPU index, Hugging Face and modelscope.cn; the image runs as UID 10001, owns `/state`, entrypoint `python -m hm_vectorizer`, command `serve`, its own `HEALTHCHECK` | `appliance/vectorizer/Dockerfile` |

- **What the customer gets.** The search API on port 8765 (`bind` defaults to
  `lan`): `POST /v1/search`, `POST /v1/ask`, `GET /healthz`. Every request
  needs the bearer token created on the machine with
  `sudo happyminingctl appliance token vectorizer`. Whoever holds the token can
  search everything that was indexed.
- **Stored and backed up.** `state` (its database and `status.json`) always.
  `/config` is written by the helper from the document, which is backed up
  itself.
- **Internet.** Building the image on the machine downloads its packages and
  Docling's models (PyPI, PyTorch, Hugging Face, modelscope.cn). Running it
  sends nothing, unless `answer.provider` is a cloud provider: then each
  question and the passages found for it go to that provider with the
  customer's key (section 4.4).
- **Not verified.** Nothing was built or run here. The Dockerfile writes the
  moving tag `3.12-slim-bookworm` with the digest of 3.12.14; writing
  `3.12.14-slim-bookworm@sha256:392307d2…` would say the same thing without
  the ambiguity (that file belongs to the vectorizer, and this entry must list
  its base image exactly as it writes it:
  `test_the_vectorizer_is_built_from_a_directory_that_ships_with_the_package`).
  The helper must make `/config` readable by UID 10001.

### `open-webui` — Open WebUI

| Fact | Source (read 2026-10-02) |
|---|---|
| Tag 0.11.4 and its digest; 0.11.4 is the newest version tag | https://hub.docker.com/v2/repositories/openwebui/open-webui/tags/0.11.4, https://hub.docker.com/v2/repositories/openwebui/open-webui/tags?ordering=last_updated |
| `openwebui/open-webui` on Docker Hub is published by the project: its release workflow copies each GHCR release there as `<version>` and `<major.minor>` | https://raw.githubusercontent.com/open-webui/open-webui/v0.11.4/.github/workflows/docker.yaml |
| `-p 3000:8080`, `-v open-webui:/app/backend/data`, `OLLAMA_BASE_URL` | https://raw.githubusercontent.com/open-webui/open-webui/v0.11.4/README.md, https://raw.githubusercontent.com/open-webui/open-webui/v0.11.4/docker-compose.yaml |
| The start script generates the session key into `WEBUI_SECRET_KEY_FILE` (default `.webui_secret_key` beside the code, outside the data volume, hence the setting), port 8080 | https://raw.githubusercontent.com/open-webui/open-webui/v0.11.4/backend/start.sh |
| `WEBUI_AUTH` defaults to true; `WEBUI_ADMIN_EMAIL` + `WEBUI_ADMIN_PASSWORD` create the administrator at start when no user exists, then sign-up is closed; `ENABLE_VERSION_UPDATE_CHECK` (asks api.github.com), `OFFLINE_MODE` | https://raw.githubusercontent.com/open-webui/open-webui/v0.11.4/backend/open_webui/env.py, https://raw.githubusercontent.com/open-webui/open-webui/v0.11.4/backend/open_webui/main.py, https://raw.githubusercontent.com/open-webui/open-webui/v0.11.4/backend/open_webui/utils/auth.py |
| An address ending in `@localhost` is accepted at sign-in | https://raw.githubusercontent.com/open-webui/open-webui/v0.11.4/backend/open_webui/utils/misc.py |
| `ENABLE_OPENAI_API` defaults to true with `https://api.openai.com/v1`, and the model list queries every enabled connection; connection settings are seeded into the database at the first start and the database wins afterwards; `RAG_EMBEDDING_MODEL_AUTO_UPDATE` | https://raw.githubusercontent.com/open-webui/open-webui/v0.11.4/backend/open_webui/config.py, https://raw.githubusercontent.com/open-webui/open-webui/v0.11.4/backend/open_webui/models/config.py, https://raw.githubusercontent.com/open-webui/open-webui/v0.11.4/backend/open_webui/routers/openai.py, https://raw.githubusercontent.com/open-webui/open-webui/v0.11.4/backend/open_webui/retrieval/utils.py |
| The image sets `ANONYMIZED_TELEMETRY=false`, `SCARF_NO_ANALYTICS=true`, `DO_NOT_TRACK=true`, ships the default embedding model, `EXPOSE 8080` | https://raw.githubusercontent.com/open-webui/open-webui/v0.11.4/Dockerfile |
| Licence: Open WebUI License, BSD-3-Clause terms plus a clause forbidding changes to the branding (above 50 users without permission) | https://raw.githubusercontent.com/open-webui/open-webui/v0.11.4/LICENSE |

- **What the customer gets.** A chat page on port 3000 (`bind` defaults to
  `lan`). At the first start the administrator's account is created from the
  setting "Administrator's e-mail address" (default `admin@localhost`) and the
  required secret `plugin.open-webui.admin_password`, set in the panel; then
  sign-up is closed and the administrator adds the other people in Open WebUI.
  Both are used once: later changes of password are made in Open WebUI.
- **Stored and backed up.** `data` (`/app/backend/data`: accounts, chats,
  uploaded files, Open WebUI's settings and any cloud key entered there, the
  session key) always.
- **Internet.** Off at the first start: no OpenAI-compatible connection
  (`ENABLE_OPENAI_API=false`), no release check, no embedding-model update
  check. Because Open WebUI keeps its connections in its database, cloud
  providers are added by the administrator in Open WebUI's settings, not in
  the HappyMining panel; what is asked of them then leaves the machine.
- **Not verified.** That nothing else is requested at run time (the code was not
  audited beyond the switches above); nothing was run.

### `openclaw` — OpenClaw

| Fact | Source (read 2026-10-02) |
|---|---|
| Tag 2026.9.7 and its digest (equal to `2026.9.7-slim`) | https://hub.docker.com/v2/repositories/openclaw/openclaw/tags/2026.9.7, https://hub.docker.com/v2/repositories/openclaw/openclaw/tags?name=2026.9 |
| v2026.9.7 is a full release (2026-09-30) | https://github.com/openclaw/openclaw/releases/tag/v2026.9.7 |
| `openclaw/openclaw` is the project's Docker Hub mirror of its GHCR images; version tags; token pasted into the Control UI; `config set --batch-json` with `gateway.mode=local` | https://raw.githubusercontent.com/openclaw/openclaw/v2026.9.7/docs/install/docker.md |
| Compose example: `node dist/index.js gateway --bind lan --port 18789`, the `OPENCLAW_*` paths, volumes `/home/node/.openclaw` and `/home/node/.config/openclaw`, `cap_drop: [NET_RAW, NET_ADMIN]`, `no-new-privileges`, `init` | https://raw.githubusercontent.com/openclaw/openclaw/v2026.9.7/docker-compose.yml |
| `WORKDIR /app`, `USER node`, image `HEALTHCHECK`; the image creates `/home/node/.openclaw` and `/home/node/.config/openclaw` owned by `node` (a new named volume starts with that owner) | https://raw.githubusercontent.com/openclaw/openclaw/v2026.9.7/Dockerfile |
| The gateway refuses to start without `gateway.mode=local` unless `--allow-unconfigured`; a non-loopback bind without auth is refused | https://raw.githubusercontent.com/openclaw/openclaw/v2026.9.7/docs/cli/gateway/running.md |
| Auth required by default; `OPENCLAW_GATEWAY_TOKEN` | https://raw.githubusercontent.com/openclaw/openclaw/v2026.9.7/docs/gateway/index.md |
| A new LAN browser needs a one-time approval (`openclaw devices approve <requestId>`); plain HTTP on the LAN works; private LAN origins are accepted | https://raw.githubusercontent.com/openclaw/openclaw/v2026.9.7/docs/web/control-ui/connect-and-pair.md, https://raw.githubusercontent.com/openclaw/openclaw/v2026.9.7/docs/web/control-ui/development.md, https://raw.githubusercontent.com/openclaw/openclaw/v2026.9.7/docs/install/docker/sandbox-and-troubleshooting.md |
| Ollama through its native URL without `/v1`, `api: "ollama"`, `apiKey: "ollama-local"`; with `models: []` discovery stays on | https://raw.githubusercontent.com/openclaw/openclaw/v2026.9.7/docs/providers/ollama.md, https://raw.githubusercontent.com/openclaw/openclaw/v2026.9.7/docs/providers/ollama/configuration.md, https://raw.githubusercontent.com/openclaw/openclaw/v2026.9.7/docs/providers/ollama/model-discovery.md |
| `config set` syntax (values parsed as JSON5), `agents.defaults.model.primary` | https://raw.githubusercontent.com/openclaw/openclaw/v2026.9.7/docs/cli/config.md |
| Provider keys `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `OPENROUTER_API_KEY` (`<PROVIDER>_API_KEY`) | https://raw.githubusercontent.com/openclaw/openclaw/v2026.9.7/docs/gateway/authentication.md |
| A daily update request to telemetry.openclaw.ai by default; `update.checkOnStart: false` and `OPENCLAW_NO_AUTO_UPDATE=1` stop it; anonymous statistics are opt-in | https://raw.githubusercontent.com/openclaw/openclaw/v2026.9.7/docs/gateway/telemetry.md |
| Licence MIT | https://raw.githubusercontent.com/openclaw/openclaw/v2026.9.7/LICENSE |

- **What the customer gets.** The Control UI on port 18789 (`bind` defaults to
  `lan`). The login screen asks for the "Gateway secret": the required secret
  `plugin.openclaw.gateway_token` set in the panel. Each new browser must then
  be approved once on the machine:
  `sudo docker exec -it hm-openclaw-openclaw-1 node dist/index.js devices list`
  and `… devices approve <requestId>` (the container name is the one Docker
  Compose gives it; there is no `happyminingctl` command for this yet). Ollama
  is configured as a provider after each start; "Default model" (for example
  `ollama/hermes3:8b`, a model already installed in Ollama) is set as the
  agent's model after each start when it is not empty. Upstream calls the
  Control UI an administration surface not to be exposed publicly.
- **Stored and backed up.** `state` (`/home/node/.openclaw`: configuration,
  workspace, sessions) and `auth` (`/home/node/.config/openclaw`: provider
  credentials) always.
- **Internet.** What is asked of a cloud provider whose key is set (all
  optional), and the chat channels the customer configures. The daily update
  request is turned off.
- **Not verified.** Nothing was run: that the post_start commands are applied
  by a running gateway without a restart; that a default model not yet pulled
  in Ollama is accepted. Upstream's bridge (18790) and Teams (3978) ports, its
  `openclaw-cli` service and `extra_hosts` are left out on purpose;
  `--allow-unconfigured` (documented for ad-hoc starts) lets the first start
  happen before post_start writes `gateway.mode=local`.

### `hermes` — Hermes Agent (Nous Research)

The customer asked for "Hermes". This entry is Nous Research's **Hermes
Agent**, published as `docker.io/nousresearch/hermes-agent`; the project, its
image and every setting used here are documented upstream (below).

| Fact | Source (read 2026-10-02) |
|---|---|
| Tag v2026.9.24 and its digest; the newest version tag | https://hub.docker.com/v2/repositories/nousresearch/hermes-agent/tags/v2026.9.24, https://hub.docker.com/v2/repositories/nousresearch/hermes-agent/tags?ordering=last_updated |
| `nousresearch/hermes-agent gateway run`; `HERMES_DASHBOARD=1` runs the dashboard in the same container on `0.0.0.0:9119`; on a non-loopback bind it fails closed without an auth provider; `HERMES_DASHBOARD_BASIC_AUTH_USERNAME`/`_PASSWORD`/`_SECRET`; `HERMES_DASHBOARD_INSECURE` is a no-op; the API server (8642) is off unless `API_SERVER_ENABLED=true`; all data in `/opt/data` | https://raw.githubusercontent.com/NousResearch/hermes-agent/v2026.9.24/website/docs/user-guide/docker.md |
| The username/password provider; without a `secret` every session ends at a restart; for trusted networks, not the public internet; config changes apply at the next session or gateway restart | https://raw.githubusercontent.com/NousResearch/hermes-agent/v2026.9.24/website/docs/user-guide/features/web-dashboard.md |
| Local Ollama as a custom endpoint: `model.provider: custom`, `model.base_url: http://…:11434/v1`, `model.default`; Hermes needs at least 64000 tokens of context and refuses less | https://raw.githubusercontent.com/NousResearch/hermes-agent/v2026.9.24/website/docs/integrations/providers.md |
| `hermes config set <dotted key> <value>` writes `config.yaml`; setting `model.provider` drops a `model.base_url` of another provider, so the provider is set first | https://raw.githubusercontent.com/NousResearch/hermes-agent/v2026.9.24/website/docs/reference/cli-commands.md |
| `HERMES_HOME=/opt/data`, `VOLUME /opt/data`; `/opt/hermes/bin/hermes` is the `docker exec` shim that drops to the `hermes` user | https://raw.githubusercontent.com/NousResearch/hermes-agent/v2026.9.24/Dockerfile |
| `ANTHROPIC_API_KEY`, `OPENROUTER_API_KEY` | https://raw.githubusercontent.com/NousResearch/hermes-agent/v2026.9.24/website/docs/reference/environment-variables.md |
| Passive update checks ask GitHub's API at most once a day | https://raw.githubusercontent.com/NousResearch/hermes-agent/v2026.9.24/website/docs/user-guide/configuration.md |
| Licence MIT | https://raw.githubusercontent.com/NousResearch/hermes-agent/v2026.9.24/LICENSE |

- **What the customer gets.** The dashboard on port 9119 (`bind` defaults to
  `lan`): sign in with the user name of the setting "Dashboard user name"
  (default `admin`) and the required secret `plugin.hermes.dashboard_password`.
  The optional `plugin.hermes.dashboard_session_key` keeps people signed in
  across restarts. When "Model installed in Ollama" is set, the agent is
  pointed at `http://ollama:11434/v1` with that model after each start; Ollama's
  "Context length" must then be 64000 or more.
- **Stored and backed up.** `data` (`/opt/data`: configuration, keys entered in
  the dashboard, sessions, memories, skills) always.
- **Internet.** What is asked of a cloud provider whose key is set (optional),
  what the agent's tools fetch when it uses them, and possibly the passive
  update check (documented for installations; not verified for the image).
- **Not verified.** Nothing was run: whether the running gateway uses a model
  changed by post_start before its next session or restart. Upstream's own
  `docker-compose.yml` runs the dashboard as a second container on the host
  network bound to 127.0.0.1; this entry follows the single-container
  "Running the dashboard" form of the Docker guide instead, published on
  `${HM_BIND}` behind the username/password provider.

## Open points

- **`bind` and `${HM_BIND}`.** The contract says what `${HM_BIND}` is (the
  address ports are published on) but not who chooses it. The catalog's
  convention is the `bind` setting: the helper is expected to write
  `HM_BIND=127.0.0.1` for `localhost` and the owner-network address for `lan`.
  That mapping is not implemented in the helper yet, and until it is, the
  defaults above (`localhost` for what has no login) are only a request.
- **`post_start` runs after every start** in the reading this catalog assumes
  (the contract says "after start"); every command here is written to be
  repeated.
- **An unset optional secret** must be absent from the env file (Qdrant treats
  an empty key as none, but other programs may not).
- **The vectorizer's base image** is listed here exactly as its Dockerfile writes it; a change there needs the same change here.
