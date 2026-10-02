# Vendored file: Subiquity autoinstall JSON schema

| | |
|---|---|
| File | `autoinstall-schema.json` (copied verbatim, not edited) |
| Upstream repository | https://github.com/canonical/subiquity |
| Upstream path | `autoinstall-schema.json` (repository root) |
| Commit | `088f26086964f35a623864d97aa0f138a710f0da` (committed 2026-09-24) |
| Permanent URL | https://github.com/canonical/subiquity/blob/088f26086964f35a623864d97aa0f138a710f0da/autoinstall-schema.json |
| Raw URL | https://raw.githubusercontent.com/canonical/subiquity/088f26086964f35a623864d97aa0f138a710f0da/autoinstall-schema.json |
| Published in the documentation at | https://canonical-subiquity.readthedocs-hosted.com/en/latest/reference/autoinstall-schema.html (the page includes this file with `literalinclude`) |
| Retrieved | 2026-10-02, by cloning the repository (`git clone --depth 1`) |
| Size, sha256 | 19900 bytes, `beb72fefb590af5dfaaa615f6836c56fd74451f31b21dca631cb8c414f45a2ae` |
| Licence | GPL-3.0-only. Subiquity's `LICENSE` file: "The subiquity/ directory is licensed under the GNU Affero General Public License version 3 or later. All other content is licensed under the GNU General Public License version 3 (only)." This file is in the repository root. |

## How it is used

`os/autoinstall/validate.py` validates the `autoinstall` section of both seeds
against this schema with the Python `jsonschema` module, in addition to its own
structural checks. The schema is a build-time check only: it is not copied into
the installation image, the seed bundles or the agent package.

## What the schema does not prove

Subiquity's documentation says: "the actual runtime validation process is more
involved than a simple JSON schema validation", and lists limits of
pre-validation (for example "a bad match directive" cannot be detected outside
the installer). The schema describes `storage` only as `{"type": "object"}`;
the storage rules of this project are enforced by `validate.py`'s own checks
and by `disk-guard.sh` at install time. This schema is from Subiquity's
development branch; the installer on a given ISO may carry an older one.

## Updating

Replace the file with the one from a newer Subiquity commit, update the commit,
date, size and hash above, and run `pytest tests/os`.
