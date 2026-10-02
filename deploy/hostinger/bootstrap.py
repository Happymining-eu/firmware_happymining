"""Fetch one commit of this repository and its pinned dependencies into a volume.

For hosts whose deployment tool can start containers from stock images but
cannot build an image (the Hostinger Docker manager pulls and runs; it never
builds). A one-shot container runs this script, then the API, the worker and
the migration job start from the prepared directory, read-only.

    python bootstrap.py <owner/repo> <commit sha> <destination root>

Result: ``<destination root>/<sha>/`` containing ``api/``, ``dashboard/``,
``migrations/``, ``alembic.ini``, ``appliance/catalog/`` (the plugin catalog
the API offers, read from next to ``api/``) and ``site/`` (the dependencies),
and a ``.ready`` marker written last. A directory with the marker is never touched
again, so a restart is a no-op. Older versions are removed once the new one is
ready.

What pins what:
- the source is the tarball of exactly this commit, fetched over TLS from
  GitHub; the same 40 hexadecimal characters appear in the URL;
- the dependencies are installed with ``--require-hashes`` from
  ``api/requirements.lock.txt``, wheels only: nothing is resolved and nothing
  is compiled.

Standard library only: it runs before anything is installed.
"""

from __future__ import annotations

import io
import re
import shutil
import subprocess
import sys
import tarfile
import urllib.request
from pathlib import Path, PurePosixPath

WANTED = (
    "api/happymining/",
    "api/requirements.lock.txt",
    "dashboard/",
    "migrations/",
    "alembic.ini",
    # The plugin catalog (docs/appliance.md, section 7). Nothing else under
    # appliance/ runs on the server: not the vectorizer, not the test data.
    "appliance/catalog/",
)
MAX_TARBALL_BYTES = 64 * 1024 * 1024
READY = ".ready"


def tarball_url(repo: str, sha: str) -> str:
    return f"https://codeload.github.com/{repo}/tar.gz/{sha}"


def validate(repo: str, sha: str) -> None:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
        raise SystemExit("repository must look like owner/name")
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise SystemExit("the commit must be a full 40-character SHA, not a branch or a tag")


def fetch(url: str) -> bytes:
    if not url.startswith("https://codeload.github.com/"):
        raise SystemExit("refusing to fetch from anywhere but GitHub over TLS")
    request = urllib.request.Request(url, headers={"User-Agent": "happymining-bootstrap"})  # noqa: S310
    with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310 - scheme and host checked above
        data = response.read(MAX_TARBALL_BYTES + 1)
    if len(data) > MAX_TARBALL_BYTES:
        raise SystemExit("the source tarball is larger than expected; refusing it")
    return data


def extract(tarball: bytes, dest: Path) -> int:
    """Copy the wanted files out of the tarball. Returns how many were written.

    Only regular files under the wanted prefixes are written, each to a path
    that is checked to stay inside ``dest``. Links, devices and anything with
    ``..`` in its name are ignored.
    """
    written = 0
    with tarfile.open(fileobj=io.BytesIO(tarball), mode="r:gz") as archive:
        for member in archive:
            parts = PurePosixPath(member.name).parts
            if len(parts) < 2 or not member.isfile() or ".." in parts:
                continue
            relative = "/".join(parts[1:])  # drop the "<repo>-<sha>/" directory GitHub adds
            if not any(relative == w or (w.endswith("/") and relative.startswith(w)) for w in WANTED):
                continue
            target = (dest / relative).resolve()
            if dest.resolve() not in target.parents:
                continue
            source = archive.extractfile(member)
            if source is None:
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with source, open(target, "wb") as out:
                shutil.copyfileobj(source, out)
            written += 1
    return written


def install_dependencies(dest: Path, pip: list[str]) -> None:
    lock = dest / "api" / "requirements.lock.txt"
    if not lock.is_file():
        raise SystemExit("api/requirements.lock.txt is missing from this commit")
    subprocess.run(  # noqa: S603 - fixed argument list
        [
            *pip,
            "install",
            "--no-cache-dir",
            "--disable-pip-version-check",
            "--no-input",
            "--require-hashes",
            "--only-binary=:all:",
            "--no-compile",
            "--target",
            str(dest / "site"),
            "-r",
            str(lock),
        ],
        check=True,
    )


def prepare(repo: str, sha: str, root: Path, *, fetcher=fetch, pip: list[str] | None = None) -> Path:
    validate(repo, sha)
    final = root / sha
    if (final / READY).is_file():
        print(f"bootstrap: {sha} is already prepared")
        return final
    partial = root / f"{sha}.partial"
    shutil.rmtree(partial, ignore_errors=True)
    partial.mkdir(parents=True)
    count = extract(fetcher(tarball_url(repo, sha)), partial)
    if count == 0 or not (partial / "api" / "happymining" / "main.py").is_file():
        raise SystemExit("the tarball does not contain the application; wrong repository or commit?")
    install_dependencies(partial, pip or [sys.executable, "-m", "pip"])
    (partial / READY).write_text(sha + "\n")
    shutil.rmtree(final, ignore_errors=True)
    partial.rename(final)
    # Older versions are only removed once the new one is complete.
    for other in root.iterdir():
        if other.is_dir() and other != final and re.fullmatch(r"[0-9a-f]{40}(\.partial)?", other.name):
            shutil.rmtree(other, ignore_errors=True)
    print(f"bootstrap: prepared {sha} ({count} source files)")
    return final


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        print(__doc__.split("\n\n")[1], file=sys.stderr)
        return 2
    prepare(argv[1], argv[2], Path(argv[3]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
