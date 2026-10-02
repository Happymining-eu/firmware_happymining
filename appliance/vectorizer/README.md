# HappyMining NAS vectorizer

The plugin `vectorizer` of the appliance (contract: `docs/appliance.md`,
sections 4.4, 6.1 and 11). It indexes the files of the NAS shares chosen for
it and answers searches and questions about them on the owner's network.

- It reads the sources, mounted read-only under `/srv/happymining/nas/`.
- Each file with a wanted extension and within the size limit is parsed
  (plain text and Markdown directly; everything else with
  [Docling](https://github.com/docling-project/docling): layout, tables,
  optional OCR), cut into passages of at most 1600 characters, embedded by
  the `ollama` plugin and stored with its passages in the `qdrant` plugin.
- Runs are incremental: a file whose size and modification time are those
  recorded is not opened; otherwise its SHA-256 is computed and, if it is the
  one already indexed, nothing is embedded. Passages of files that
  disappeared are removed. A file that fails is counted and tried again at the
  next run.
- It serves `POST /v1/search`, `POST /v1/ask`, `GET /v1/status`,
  `POST /v1/sync` and `GET /healthz` on port 8765, behind a bearer token.
- It writes `status.json`: the counters of section 6.1, never a file name or
  any text of a document.

**One index, one access level.** The vectorizer does not copy the NAS's
access rights. Anyone who holds the token can search, and read passages of,
everything that was indexed. Index only shares meant for everyone who gets
the token. The passages are stored in Qdrant, which the vectorizer reaches
without an API key (the contract gives it none; a Qdrant with
`QDRANT__SERVICE__API_KEY` set refuses it and runs end in `store_error`):
whoever reaches Qdrant directly — every container on `hm-appliance`, and the
address the `qdrant` plugin publishes its port on — reads the index without
the token.

The code under `hm_vectorizer/` uses the Python standard library only.
Docling is optional and imported only when a file needs it (without it,
text and Markdown are indexed and other formats are counted as
`parser_unavailable`). The image (`Dockerfile`) installs it.

---

## 1. The container

| Path / name | What | Who writes it |
|---|---|---|
| port `8765` | the HTTP API (all interfaces of the container) | |
| `/config/vectorizer.json` | configuration, section 2 | the helper; read-only mount |
| `/config/token` | bearer token, section 3 | the helper; read-only mount |
| `/state` | named volume: `state.db` (SQLite: what is indexed), `status.json`, `sync.lock`, `spool/` (one file at a time while it is parsed) | the vectorizer |
| `/srv/happymining/nas/<id>` | the NAS entries, read-only | the helper mounts them |
| `HM_ANSWER_API_KEY` | environment variable: the key of a cloud answer provider (`ai.answer.api_key`), absent otherwise | the helper (root-only env file) |
| `/tmp` | caches and temporary files | the vectorizer |

The process runs as uid **10001**, gid **10001** (user `hmvec`). It writes
under `/state` and `/tmp` only; the code (`/opt/hm`) and the Docling models
(`/opt/docling-models`) belong to root. Consequences for the helper:

- `vectorizer.json` and `token` must be readable by uid or gid 10001 and
  writable by root only. Suggested: directory
  `/var/lib/happymining-plugins/vectorizer/config` mode `0750` owner
  `root:10001`; both files mode `0640` owner `root:10001`, replaced
  atomically (write beside, then rename).
- Files on the NAS must be readable by uid 10001 inside the container. SMB
  mounts (`file_mode`/`dir_mode` default to `0755`) are; for NFS it depends
  on the server's permissions.

`HM_ANSWER_API_KEY` is taken out of the environment at start-up by `serve`
(and by `sync`, which has no use for it): it is never logged, never put in an
error message or a response, never written to disk, and not passed to the
sync process or the document parsers. A value that cannot be an HTTP header
as it is (empty, non-ASCII, a space or a control character, more than 4096
characters) is treated as absent: `/v1/ask` then answers `503
answer_key_missing`.

**When things change.** The token is re-read at each request when the file
changed (no restart). `vectorizer.json` is read by `serve` at start and by
each sync run: after writing a new one, restart the container (`docker
restart`, or `docker compose restart`), otherwise searches keep using the
old embedding model and addresses. A new `HM_ANSWER_API_KEY` needs the
container to be recreated.

## 2. `/config/vectorizer.json`

A JSON object, UTF-8, at most 64 KiB, a regular file. It is the `vectorizer`
object of the desired-state document (section 4.4), **copied as it is**, plus
four keys the helper adds. Every key below is required and no other key is
accepted, at the top level or in `answer`. A key repeated in an object is an
error. No string may contain a control character (U+0000–U+001F, U+007F).
Integers are JSON integers (`64`, not `"64"`, `64.0` or `true`). A file that
breaks any rule is refused as a whole: `serve` and `sync` exit with code 2
and say which field and which rule, never the value.

| Key | Type | Rule |
|---|---|---|
| `sources` | array of strings | 1 to 8 ids, each `^[a-z][a-z0-9-]{0,30}$`, no duplicate. The `nas` ids of the document (entries with `access: read`) |
| `extensions` | array of strings | 1 to 40, each `^[a-z0-9]{1,8}$` (lower case, no dot). A file is a candidate when the text after the last dot of its name, lower-cased, is in the list |
| `exclude` | array of strings | 0 to 32 relative paths: at most 200 characters, segments separated by `/`, no empty, `.` or `..` segment, no leading or trailing `/` |
| `max_file_mib` | integer | 1 to 2048. Larger files are skipped (`too_large`) |
| `embedding_model` | string | `^[a-z0-9][a-z0-9._/-]{0,80}(:[A-Za-z0-9._-]{1,40})?$`, an Ollama model the `ollama` plugin serves (e.g. `bge-m3`) |
| `ocr` | boolean | run OCR on scanned pages, and accept images (`png`, `jpg`, …) as documents |
| `answer` | object | see below |
| `source_paths` | object | added by the helper. Exactly one key per id of `sources`; the value is the directory to index, as seen in the container: `/srv/happymining/nas/<id>`, or `/srv/happymining/nas/<id>/<subpath>` |
| `ollama_url` | string | added by the helper: `http://ollama:11434` |
| `qdrant_url` | string | added by the helper: `http://qdrant:6333` |
| `collection` | string | added by the helper: `happymining_docs`. `^[A-Za-z0-9_-]{1,64}$` |

`answer`:

| Key | `none` | `local` | `openai_compatible` | `anthropic` |
|---|---|---|---|---|
| `provider` | `"none"` | `"local"` | `"openai_compatible"` | `"anthropic"` |
| `model` | absent | required | required | required |
| `base_url` | absent | absent | required | optional, default `https://api.anthropic.com` |
| `secret` | absent | absent | `"ai.answer.api_key"` | `"ai.answer.api_key"` |

- `model`: 1 to 100 characters of `A-Z a-z 0-9 . _ : / -`. For `local` it is
  an Ollama model of the `ollama` plugin.
- `base_url`: `https://` + host + optional `:port` + optional path, at most
  200 characters. Host: `^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`
  (a name or an IPv4 address; no IPv6 literal, no user info). Port: 1 to
  65535 without a leading zero. Path: segments of `[A-Za-z0-9._~-]*`, each
  after a `/` (no `%`, no query, no fragment). A trailing `/` is ignored.
  This is the rule of the control plane (`services/appliance.py`).
- `secret` is the *name* of the sealed secret; its value reaches the
  container as `HM_ANSWER_API_KEY`.

Rules for the helper's keys:

- `source_paths`: `/srv/happymining/nas/<id>` when that mount point holds the
  directory to index (the NAS entry's `subpath` mounted directly, or an empty
  `subpath`); `/srv/happymining/nas/<id>/<subpath>` when the share's root is
  mounted there and `subpath` is a directory below it. A subpath follows the
  rule of 4.3 (at most 512 characters). Any other value is refused. The
  vectorizer opens the mount point and then each segment of the subpath
  without following links.
- `ollama_url`, `qdrant_url`: `http://` or `https://`, a host as above,
  optional port, optional trailing `/`, nothing else. They are the service
  names on the `hm-appliance` network.
- `collection`: changing it starts a new, empty index; the old collection
  stays in Qdrant.

`exclude` matching: a file is left out when the segments of one pattern are
equal to consecutive segments of the file's path relative to the source
directory. Comparison ignores case and Unicode composition (NFC, case-folded),
because SMB shares do. So `#recycle` excludes `#recycle/…` and
`a/b/#Recycle/…`; `private/hr` excludes `private/hr/x.pdf` and
`teams/Private/HR/y.docx`, but not `private/hr-old/z.pdf`. An excluded
directory is not entered. A pattern can also name a file
(`contracts/secret.pdf`).

Example (the document's `vectorizer` object plus the four keys):

```json
{
  "sources": ["docs"],
  "extensions": ["pdf", "docx", "pptx", "xlsx", "html", "md", "txt"],
  "exclude": ["#recycle", "private/hr"],
  "max_file_mib": 64,
  "embedding_model": "bge-m3",
  "ocr": false,
  "answer": {"provider": "openai_compatible", "base_url": "https://api.openai.com/v1",
             "model": "gpt-4.1-mini", "secret": "ai.answer.api_key"},
  "source_paths": {"docs": "/srv/happymining/nas/docs"},
  "ollama_url": "http://ollama:11434",
  "qdrant_url": "http://qdrant:6333",
  "collection": "happymining_docs"
}
```

What gets indexed, per source: regular files only, reached without following
any symbolic link (a link to a file or a directory, inside or outside the
share, is skipped: `symlink`; what a link inside the share points to is
reached by its real path anyway). Sockets, FIFOs and devices are skipped
(`special`), as are empty files (`empty`), Office and macOS leftovers
(`~$…`, `._…`, `.~lock.…`: `temp_file`), names that are not UTF-8 or paths
over 4096 characters (`bad_name`) and directories deeper than 64 levels
(`too_deep`). Files with another extension and excluded paths are ignored and
not counted. A source whose directory is missing, cannot be opened or is
empty (what an unmounted NAS looks like) is *unavailable*: nothing of it is
indexed or removed, and the run ends in `error`. A directory that cannot be
listed keeps what was indexed below it.

Formats: `txt`, `text`, `md`, `markdown` are read directly (encoding
guessed: byte-order mark, UTF-16 without mark, UTF-8, then Windows-1252).
Through Docling: PDF, DOCX (`docx dotx docm dotm`), PPTX (`pptx potx ppsx
pptm potm ppsm`), XLSX (`xlsx xlsm xltx xltm`), HTML (`html htm xhtml`),
AsciiDoc (`adoc asciidoc asc`), CSV, and with `ocr` images (`jpg jpeg png tif
tiff bmp webp gif`). Audio, video, legacy Office, e-mail and other Docling
formats are not let through (`unsupported_format`). Docling's remote services
and external plugins stay off, and its HTML and AsciiDoc readers do not fetch
what a document references (their defaults, checked in the 2.132.0 source).

## 3. `/config/token`

One line of 16 to 512 printable ASCII characters (`!` to `~`, no space),
optionally followed by `\n` or `\r\n`. Generated on the machine by
`sudo happyminingctl appliance token vectorizer`; 32 random bytes in
base64url (43 characters) are suggested. Requests carry it as
`Authorization: Bearer <token>`; it is compared in constant time (SHA-256 of
both sides, then `hmac.compare_digest`). If the file is missing or invalid,
`serve` refuses to start (exit 2); if it becomes so while serving, every
request is refused with 401.

## 4. HTTP API

Port 8765. Requests and answers are JSON (`application/json; charset=utf-8`),
answers carry `Cache-Control: no-store` and `Connection: close`. Errors are
`{"error": "<code>"}`, with no detail and no upstream text.

Everything but `/healthz` needs the token. Failed authentication is limited
per client address: after 10 wrong tokens within 60 seconds, every request of
that address (the right token included) gets `429
too_many_failed_authentications` with `Retry-After` until the oldest failure
is 60 seconds old. A request without an `Authorization: Bearer` header is
`401` and not counted. Note: if Docker's userland proxy is in use, every
client appears with the same address and shares that limit.

Limits: a body is at most 64 KiB, needs `Content-Length` (chunked bodies are
refused: `411 length_required`) and `Content-Type: application/json`; `query`
and `question` at most 2000 characters; 32 requests at once (more are dropped
at connection); 30 seconds of socket inactivity.

### `GET /healthz`

No token. `200 {"status": "ok"}`. Says nothing else and contacts nothing.

### `POST /v1/search`

```http
POST /v1/search
Authorization: Bearer <token>
Content-Type: application/json

{"query": "pump reference for container C2", "limit": 8}
```

`limit`: integer 1 to 50, default 8. Unknown keys are refused.

```json
{"results": [
  {"score": 0.83, "source": "docs", "path": "maintenance/handbook.docx", "page": null,
   "headings": ["Maintenance handbook", "Pump replacement"],
   "text": "Step 3: close valve V3, wait until the gauge reads zero, …"}
]}
```

`source` is the source id, `path` the file's path relative to the source
directory, `page` the first page of the passage when the format has pages
(PDF) or `null`, `score` the
cosine similarity (higher is closer). `{"results": []}` before anything is
indexed.

### `POST /v1/ask`

```json
{"question": "Which pump replaces the one of container C2?", "limit": 6}
```

`limit`: passages given to the model, 1 to 20, default 6.

```json
{"answer": "The replacement pump is HM-PUMP-7731 [1].",
 "sources": [{"n": 1, "score": 0.83, "source": "docs", "path": "maintenance/handbook.docx",
              "page": null, "headings": ["Maintenance handbook", "Pump replacement"], "text": "…"}]}
```

`[n]` in the answer refers to `sources[n-1]`. When nothing is retrieved the
answer is `{"answer": "", "sources": []}` and nothing is sent to the
provider. With the provider `none`: `501 answer_provider_none`.

Providers (only the configured address is ever contacted; no proxy, whatever
the environment says; no redirect is followed; responses at most 4 MiB):

| Provider | Request |
|---|---|
| `local` | `POST http://ollama:11434/api/chat`, `{"model", "messages": [system, user], "stream": false, "options": {"num_ctx": 16384}}`; answer `message.content`. Ollama's default context is 4096 tokens, too small for the passages and the instructions |
| `openai_compatible` | `POST <base_url>/chat/completions`, `Authorization: Bearer <key>`, `{"model", "messages": [system, user], "stream": false}`; answer `choices[0].message.content` |
| `anthropic` | `POST <base_url>/v1/messages`, `x-api-key: <key>`, `anthropic-version: 2023-06-01`, `{"model", "max_tokens": 2048, "system", "messages": [user]}`; answer: the `text` blocks of `content` |

With a cloud provider, the question and the retrieved passages leave the
machine, to that provider, with the customer's key.

### `GET /v1/status`

The eight fields of `status.json` (section 6) as they are now (`running` is
decided by the run lock, not by the file), plus:

```json
{"state": "idle", "last_run_at": "2026-10-02T02:30:00Z", "last_ok_at": "2026-10-02T02:41:10Z",
 "files_indexed": 1820, "files_failed": 3, "files_skipped": 12, "chunks": 40211,
 "detail": "failed: parse_error=2 read_error=1; skipped: too_large=12",
 "failed_by_reason": {"parse_error": 2, "read_error": 1},
 "skipped_by_reason": {"too_large": 12},
 "answer_provider": "openai_compatible"}
```

### `POST /v1/sync`

No body (a request without `Content-Length` has none). Starts a sync in a
separate process and answers `202 {"started": true}`, or `409 sync_running`
when a run holds the lock (one started here, or by `sync` in the container).
Progress is in `/v1/status`.

### Error codes

| Status | Codes |
|---|---|
| 400 | `bad_request` (not HTTP), `bad_content_length`, `body_incomplete`, `bad_json`, `json_object_required`, `unknown_field`, `query_required`, `query_too_long`, `question_required`, `question_too_long`, `limit_invalid` |
| 401 | `unauthorized` (with `WWW-Authenticate: Bearer`) |
| 404 | `not_found` (answered before authentication) |
| 405 | `method_not_allowed` (with `Allow`) |
| 408 | `body_not_received` |
| 409 | `sync_running` |
| 411 | `length_required` |
| 413 | `body_too_large` (the body is not read) |
| 415 | `json_required` |
| 429 | `too_many_failed_authentications` (with `Retry-After`) |
| 500 | `internal` |
| 501 | `answer_provider_none` |
| 502 | `provider_unreachable` (connection or TLS verification failed), `provider_redirected`, `provider_rejected_key` (401/403), `provider_error`, `provider_bad_response` |
| 503 | `embedder_unavailable`, `embedder_model_missing`, `embedder_rejected`, `embedder_bad_response`, `store_unavailable`, `store_error`, `store_bad_response`, `answer_key_missing` |
| 504 | `provider_timeout` (120 s cloud, 300 s local) |

## 5. Command line

`python -m hm_vectorizer <command>`; in the image the interpreter is
`/opt/venv/bin/python` and the entry point runs `serve`.

| Command | Options (defaults) | Exit codes |
|---|---|---|
| `serve` | `--config-dir /config --state-dir /state --host 0.0.0.0 --port 8765` | 0 stopped by SIGTERM or SIGINT; 2 configuration, token or state directory refused (nothing started) |
| `sync` | `--config-dir /config --state-dir /state` | 0 run finished, state `idle`; 1 run finished, state `error`; 2 configuration refused, or state directory missing or not writable; 3 a sync is already running |
| `status` | `--state-dir /state` | 0; prints the status (section 6) as one JSON line |
| `healthcheck` | `--port 8765` | 0 `GET http://127.0.0.1:<port>/healthz` answered `ok`; 1 otherwise (the image's `HEALTHCHECK`) |
| `selfcheck` | | 0 Docling can parse offline with what is installed; 1 otherwise (run when the image is built) |

(`--nas-root` exists for tests only.)

**Scheduled runs.** For a `vectorize_sync` schedule the helper runs, in the
running container and as its default user:

```
docker exec <container> /opt/venv/bin/python -m hm_vectorizer sync
```

What `sync` does, in order:

1. Reads and validates `/config/vectorizer.json` (exit 2 on any error; nothing
   is written). Removes `HM_ANSWER_API_KEY` from its own environment.
2. Takes the run lock (`flock` on `/state/sync.lock`); if another run holds it
   (one started by `POST /v1/sync`, or another `docker exec`), exits 3 at once
   and changes nothing. The kernel releases the lock when the process ends,
   however it ends.
3. Writes `status.json` with `state: running`.
4. Asks Ollama for one embedding to learn the vector size. Makes sure the
   collection exists with that size and cosine distance; if its size differs,
   or the embedding model changed since the last run, the collection is
   dropped and the index rebuilt. Removes points written under another (lost)
   state database.
5. Lists every source, then processes each candidate file as described at the
   top: unchanged → nothing; changed → copied to `/state/spool` while hashed;
   same hash → nothing embedded; otherwise parsed, cut, embedded (16 passages
   per request) and stored (64 points per request, `wait=true`), and the
   passages of the previous version removed. A file that fails is recorded
   with a reason and the run goes on; when its new content could not be
   parsed its old passages are removed, when it could not be read they are
   kept.
6. Removes the passages of files that are no longer listed, except below a
   directory that could not be listed and in an unavailable source.
7. Writes the final `status.json` (`idle`, or `error` with the reason in
   `detail`) and exits 0 (`idle`) or 1 (`error`).

The run stops with `error` (exit 1) when Ollama or Qdrant is unavailable, when
the embedding model is missing, when 3 files in a row are refused by Ollama,
or on SIGTERM (`error: interrupted`, after the file in progress). It ends
with `error` too when a source is unavailable, after processing the other
sources. What was done stays recorded and the next run resumes from there. A run can take hours; its standard error has one line per source and
one at the end, with counts only (no file name, no text).

Suggested mapping to the schedule's `last_status`: 0 → `ok`, 1 and 2 →
`failed`, 3 → `skipped`. A run killed by SIGKILL leaves `running` in the
file; `status`, `/v1/status` and the next `serve` report or rewrite it as
`error` / `interrupted`.

## 6. `status.json`

`/state/status.json`, replaced atomically, mode `0644`. Exactly these eight
keys, in this order (contract section 6.1, `vectorizer`):

| Key | Type | Value |
|---|---|---|
| `state` | string | `idle`, `running` or `error`. (`disabled` is the helper's own state when there is no vectorizer) |
| `last_run_at` | string | start of the last run, `YYYY-MM-DDTHH:MM:SSZ` (UTC); `""` before the first run |
| `last_ok_at` | string | end of the last run that finished `idle`; `""` if none |
| `files_indexed` | integer | files whose passages are in the index |
| `files_failed` | integer | files that failed at their last attempt (tried again at each run) |
| `files_skipped` | integer | entries the last run left out for a skip reason below: links, special files and non-UTF-8 names whatever their extension, the others among files of a wanted extension |
| `chunks` | integer | passages in the index |
| `detail` | string | at most 500 characters, reason codes and counts only |

`detail` is `""`, or reason groups separated by `; `:
`failed: <code>=<n> …`, `skipped: <code>=<n> …`, `unreadable_directories=<n>`;
for a run that ended in error, `error: <code>` instead, where code is one of
`embedder_unavailable`, `embedder_model_missing`, `embedder_rejected`,
`embedder_bad_response`, `store_unavailable`, `store_error`,
`store_bad_response`, `store_not_completed`, `store_bad_request`,
`state_unusable`, `state_unwritable`, `interrupted`, `internal`, or
`source_unavailable (<n> of <m> sources)`. A run that was killed shows
`interrupted` (without `error: `) once repaired.

File failure codes: `parse_error`, `parse_timeout` (Docling took more than an
hour), `no_text`, `not_text` (a "text" file that is binary),
`too_many_chunks` (over 20000 passages), `parser_unavailable` (Docling or its
models missing), `unsupported_format`, `read_error`, `not_regular_file`
(replaced by a link or a special file after the listing),
`changed_during_read`, `embed_error`. Skip codes: `too_large`, `empty`,
`symlink`, `special`, `temp_file`, `bad_name`, `too_deep`.

The helper can read the file from the volume, or run `docker exec <container>
/opt/venv/bin/python -m hm_vectorizer status`, which prints the same eight
keys with `state` taken from the lock (a killed run shows as `error`).

## 7. Prompt injection: what is done, and its limits

Documents are untrusted input to the answering model. For each question:

- the passages are put between `<<<PASSAGE n <marker>>>>` and
  `<<<END PASSAGE n <marker>>>>` lines, with a marker of 16 random hex
  characters chosen for that request, so a document cannot close its own
  block; the source line of a passage is flattened to one line, so a file
  name cannot start a new one;
- the system message says that the passages are data and not instructions,
  that text in them addressing the model is content to report on, that the
  answer must come from the passages only, cite them as `[n]` and say when
  they do not answer;
- the model gets no tool and no way to act: whatever a document makes it say
  is text in the answer, returned with the passages it came from.

This lowers the risk; it does not remove it. A model can still follow
instructions written in a document, misquote it, or cite the wrong passage.
Check answers against the returned `sources`. A document cannot make the
model reveal more than the token holder can already search. With a cloud
provider, what is sent is the question and the retrieved passages only.

## 8. The image

`Dockerfile` (two stages). The build stage installs everything from PyPI with
the hashes of `requirements.lock` (Docling 2.132.0 with docling-core 2.99.0,
docling-parse 7.22.1, docling-ibm-models 4.0.3 and their dependencies), then
torch 2.14.1 and torchvision 0.29.1 from PyTorch's CPU-only index (no CUDA
libraries; those two are pinned by version, not by hash), runs `pip check`,
and downloads Docling's layout, table-structure and RapidOCR models into
`/opt/docling-models` (`docling-tools models download layout tableformer
rapidocr`). The final stage has no pip and no compiler, runs as 10001:10001,
sets `HF_HUB_OFFLINE=1` and `DOCLING_ARTIFACTS_PATH=/opt/docling-models` so
that parsing never downloads anything, and runs `selfcheck` as that user:
the build fails if Docling cannot prepare its pipelines and convert a PDF
offline.

```
docker build -t happymining/vectorizer:1 /usr/share/happymining/vectorizer
```

The build needs the network (PyPI, download.pytorch.org, Hugging Face and
modelscope.cn for the models); the running container needs none of it
(Ollama and Qdrant on `hm-appliance`, the cloud provider if one is
configured). amd64 only. Change the image tag whenever this directory
changes, so that the machine builds it again. The base image is pinned by
digest: a security update of Debian or Python arrives only when the digest is
updated here.

To regenerate `requirements.lock` after changing the Docling version: see the
command at its top.

## 9. What was verified, and what was not run

Checked on 2026-10-02 against these primary sources; the code follows them:

| What | Source | Result |
|---|---|---|
| Docling version | https://pypi.org/pypi/docling/json | 2.132.0 is the latest (released 2026-10-01), Python ≥ 3.10 |
| Docling API | https://docling-project.github.io/docling/reference/document_converter/, https://docling-project.github.io/docling/reference/pipeline_options/, https://docling-project.github.io/docling/usage/advanced_options/, https://docling-project.github.io/docling/usage/supported_formats/, https://docling-project.github.io/docling/concepts/chunking/, https://docling-project.github.io/docling/examples/hybrid_chunking/, and the installed 2.132.0 source | `DocumentConverter(allowed_formats, format_options)`, `initialize_pipeline`, `convert(source, raises_on_error, max_file_size, …)`, `ConversionStatus`, `has_timeout_errors`, `PdfPipelineOptions` (`do_ocr`, `do_table_structure`, `document_timeout`, `enable_remote_services=False`, `allow_external_plugins=False`, `artifacts_path`), `OcrAutoOptions` default, `InputFormat`/`FormatToExtensions`, `HybridChunker(tokenizer=)`, `BaseTokenizer`, `DOCLING_ARTIFACTS_PATH`, `docling-tools models download`; HTML/AsciiDoc fetching off by default; RapidOCR offline when an artifacts path is set |
| CPU-only install | https://docling-project.github.io/docling/getting_started/installation/ | `--extra-index-url https://download.pytorch.org/whl/cpu` |
| Ollama | https://docs.ollama.com/api/embed, https://github.com/ollama/ollama/blob/main/docs/api.md, https://github.com/ollama/ollama/blob/main/docs/faq.mdx | `/api/embed` `{model, input[]}` → `embeddings`; `truncate` defaults to true; `/api/chat` with `stream: false` → `message.content`; roles `system`/`user`; default context 4096 tokens, `options.num_ctx` |
| Qdrant | https://github.com/qdrant/qdrant/blob/v1.19.1/docs/redoc/master/openapi.json (the version the catalog pins; same schemas as `master`) | collection exists/create/get/delete, payload index `keyword`, upsert with `wait`, delete by `filter` (`must`, `must_not`, `match.value`, `range.gte`), `points/query` with `query`, `limit`, `with_payload` → `result.points[]` with `id`, `score`, `payload`; point ids are unsigned integers or UUIDs |
| OpenAI-compatible | https://github.com/openai/openai-openapi/blob/manual_spec/openapi.yaml (2.3.0) | `POST /chat/completions`, bearer auth, `model` and `messages` required, `choices[].message.content` (nullable) |
| Anthropic | https://github.com/anthropics/anthropic-sdk-python (main, version 1.11.0: `_client.py`, `types/message.py`, `types/message_create_params.py`, `types/text_block.py`, `resources/messages/messages.py`) | `POST /v1/messages`, `X-Api-Key`, `anthropic-version: 2023-06-01`, `model`/`max_tokens`/`messages` required, `system` a string, response `content` blocks `{type: "text", text}`; the create parameters no longer list `temperature`. The API reference on docs.claude.com could not be fetched from where this was written |
| Base image digest | https://hub.docker.com/v2/repositories/library/python/tags/3.12-slim-bookworm | `sha256:392307d2…564e` (index digest, last updated 2026-09-19), read twice through a fetch tool; not pulled |

Run here:

- The whole test suite (`tests/appliance/vectorizer`) with the repository's
  interpreter (Python 3.13, no Docling): fake Ollama, Qdrant and cloud
  providers in process, temporary directories as NAS sources.
- The same suite with Python 3.12.3 and the packages of `requirements.lock`
  installed by `pip install --no-deps --require-hashes` (the Dockerfile's
  command; `pip check` clean), torch 2.14.1 taken from PyPI (the CUDA build,
  running on CPU: PyTorch's CPU index is not reachable from here). The real
  Docling tests passed for DOCX, PPTX, XLSX, HTML, CSV and a sync over real
  documents; Docling's HTML reader fetched nothing.
- `selfcheck` with that interpreter: every format ready except PDF and images,
  whose models cannot be downloaded from here (Hugging Face and modelscope.cn
  are refused): exit 1, reported as `parser_unavailable`.

Not run:

- `docker build` (no Docker here): the Dockerfile is checked by
  `test_vectorizer_image.py` only. The CPU wheels of torch 2.14.1 and
  torchvision 0.29.1 on download.pytorch.org were not seen.
- Docling's PDF pipeline, table structure model and OCR (models not
  downloadable here). The image's `selfcheck` is what checks them, at build.
- A real Ollama, a real Qdrant (`test_vectorizer_qdrant_real.py` runs when
  `HM_TEST_QDRANT_URL` points at one) and the real cloud providers.
- What Ollama answers for an unknown model is not in its documentation:
  404 is read as `embedder_model_missing`, any other 4xx as
  `embedder_rejected`. That Ollama caps `num_ctx` at what the model supports
  was not checked.
