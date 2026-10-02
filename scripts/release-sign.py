#!/usr/bin/env python3
"""Sign a firmware release for HappyMining machines (docs/appliance.md, section 9).

A release is the agent package and a manifest signed with an Ed25519 key. The
API accepts a manifest only if its signature verifies against a key listed in
HM_RELEASE_PUBLIC_KEYS, and a machine installs a package only if the manifest
verifies against a key installed with its current package
(/usr/share/happymining/release-keys/*.pub). The private key is on neither:
it is generated here, on the release engineer's machine, and stays out of the
repository.

    release-sign.py keygen   --out <directory outside the repository>
    release-sign.py manifest --deb <package> --version X.Y.Z --key <private key> --out <directory>
                             [--min-upgrade-from X.Y.Z] [--notes "..."]
    release-sign.py verify   --manifest <manifest.json> --signature <manifest.sig> --pub <key.pub>
                             [--deb <package>]

``keygen`` writes ``happymining-release-<key id>.key`` (the private key, PEM,
mode 0600) and ``happymining-release-<key id>.pub`` (one line: the base64 of
the 32-byte public key, the format the agent package installs and
HM_RELEASE_PUBLIC_KEYS takes). ``manifest`` writes ``manifest.json`` and
``manifest.sig`` (the base64 signature of exactly the bytes of manifest.json).

Needs Python 3.11+ and the ``cryptography`` package: ``api/.venv/bin/python scripts/release-sign.py``.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import sys
from datetime import UTC, datetime
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

PRODUCT = "happymining-agent"
MANIFEST_SCHEMA = 1
MAX_MANIFEST_BYTES = 16 * 1024
MAX_NOTES = 4000
VERSION_RE = re.compile(r"(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})")
REPO_ROOT = Path(__file__).resolve().parents[1]


class Refused(Exception):
    """Something this tool will not do. The message is for the person running it."""


def key_id(public_raw: bytes) -> str:
    """First 16 hexadecimal characters of the SHA-256 of the 32-byte public key."""
    return hashlib.sha256(public_raw).hexdigest()[:16]


def version_tuple(text: str) -> tuple[int, int, int]:
    match = VERSION_RE.fullmatch(text or "")
    if not match:
        raise Refused(f"{text!r} is not a version: MAJOR.MINOR.PATCH, numbers only")
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


def inside_a_repository(path: Path) -> Path | None:
    """The working tree ``path`` is in, if any: this repository, or any directory with a .git."""
    resolved = path.resolve()
    for candidate in (resolved, *resolved.parents):
        if candidate == REPO_ROOT or (candidate / ".git").exists():
            return candidate
    return None


def public_raw(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def load_private_key(path: Path) -> Ed25519PrivateKey:
    try:
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    except (OSError, ValueError, TypeError) as exc:
        raise Refused(f"{path} is not a readable PEM private key") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise Refused(f"{path} is not an Ed25519 key")
    return key


def load_public_key(path: Path) -> Ed25519PublicKey:
    try:
        raw = base64.b64decode(path.read_text().strip(), validate=True)
    except (OSError, ValueError) as exc:
        raise Refused(f"{path} is not a readable public key file") from exc
    if len(raw) != 32:
        raise Refused(f"{path} does not hold a 32-byte public key in base64")
    return Ed25519PublicKey.from_public_bytes(raw)


def sha256_of(path: Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    with open(path, "rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
    return size, digest.hexdigest()


# --- commands --------------------------------------------------------------


def keygen(out: Path) -> int:
    tree = inside_a_repository(out)
    if tree is not None:
        raise Refused(
            f"{out} is inside the working tree {tree}; a signing key is never written into a repository"
        )
    out.mkdir(parents=True, exist_ok=True, mode=0o700)
    key = Ed25519PrivateKey.generate()
    raw = public_raw(key.public_key())
    name = f"happymining-release-{key_id(raw)}"
    private_path, public_path = out / f"{name}.key", out / f"{name}.pub"
    pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    # Created with its final mode: the key is never readable by anyone else, not even briefly.
    descriptor = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(pem)
    public_path.write_text(base64.b64encode(raw).decode() + "\n")
    print(f"private key: {private_path}  (keep it offline; it is the only thing that can sign a release)")
    print(f"public key:  {public_path}")
    print(f"key id:      {key_id(raw)}")
    print(f"HM_RELEASE_PUBLIC_KEYS={base64.b64encode(raw).decode()}")
    return 0


def manifest(deb: Path, version: str, key_path: Path, out: Path, min_upgrade_from: str, notes: str) -> int:
    version_tuple(version)
    if version_tuple(min_upgrade_from) > version_tuple(version):
        raise Refused("--min-upgrade-from is newer than the release itself")
    expected_name = f"{PRODUCT}_{version}_amd64.deb"
    if deb.name != expected_name:
        raise Refused(f"the package of release {version} is named {expected_name}, not {deb.name}")
    if not deb.is_file():
        raise Refused(f"{deb} is not a file")
    if len(notes) > MAX_NOTES or any(ord(ch) < 0x20 and ch not in "\n\t" for ch in notes):
        raise Refused(f"--notes is at most {MAX_NOTES} characters of plain text")
    key = load_private_key(key_path)
    size, digest = sha256_of(deb)
    if size == 0:
        raise Refused(f"{deb} is empty")
    document = {
        "schema": MANIFEST_SCHEMA,
        "product": PRODUCT,
        "version": version,
        "created_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "artifact": {"filename": deb.name, "size": size, "sha256": digest},
        "min_upgrade_from": min_upgrade_from,
        "notes": notes,
    }
    raw = (json.dumps(document, indent=2, ensure_ascii=False) + "\n").encode()
    if len(raw) > MAX_MANIFEST_BYTES:
        raise Refused("the manifest is larger than 16 KiB; shorten the notes")
    signature = base64.b64encode(key.sign(raw)).decode()
    out.mkdir(parents=True, exist_ok=True)
    (out / "manifest.json").write_bytes(raw)
    (out / "manifest.sig").write_text(signature + "\n")
    print(f"manifest:  {out / 'manifest.json'}")
    print(f"signature: {out / 'manifest.sig'}")
    print(
        f"signed with key {key_id(public_raw(key.public_key()))}: {deb.name}, {size} bytes, sha256 {digest}"
    )
    return 0


def verify(manifest_path: Path, signature_path: Path, pub: Path, deb: Path | None) -> int:
    key = load_public_key(pub)
    try:
        raw = manifest_path.read_bytes()
        signature = base64.b64decode(signature_path.read_text().strip(), validate=True)
    except (OSError, ValueError) as exc:
        raise Refused("the manifest or its signature cannot be read") from exc
    if len(raw) > MAX_MANIFEST_BYTES:
        raise Refused("the manifest is larger than 16 KiB")
    try:
        key.verify(signature, raw)
    except InvalidSignature as exc:
        raise Refused("the signature does NOT verify against this key") from exc
    try:
        document = json.loads(raw)
        artifact = document["artifact"]
        if document["schema"] != MANIFEST_SCHEMA or document["product"] != PRODUCT:
            raise ValueError("schema or product")
        version_tuple(document["version"])
        version_tuple(document.get("min_upgrade_from", "0.0.0"))
        size, digest = artifact["size"], artifact["sha256"]
        if not isinstance(size, int) or isinstance(size, bool) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("artifact")
    except (ValueError, KeyError, TypeError, Refused) as exc:
        raise Refused(f"the manifest is signed but not well formed ({exc})") from exc
    print(f"signature ok: release {document['version']}, key {key_id(public_raw(key))}")
    if deb is not None:
        actual_size, actual_digest = sha256_of(deb)
        if (actual_size, actual_digest) != (size, digest):
            raise Refused(f"{deb} is NOT the package this manifest describes (size or SHA-256 differs)")
        print(f"package ok: {deb.name}, {size} bytes")
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="release-sign.py", description=__doc__.split("\n\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)
    p = commands.add_parser("keygen", help="generate a signing key pair")
    p.add_argument("--out", type=Path, required=True, help="a directory outside any repository")
    p = commands.add_parser("manifest", help="write and sign the manifest of a package")
    p.add_argument("--deb", type=Path, required=True)
    p.add_argument("--version", required=True)
    p.add_argument("--min-upgrade-from", default="0.0.0")
    p.add_argument("--notes", default="")
    p.add_argument("--key", type=Path, required=True, help="the private key written by keygen")
    p.add_argument("--out", type=Path, required=True)
    p = commands.add_parser("verify", help="check a manifest, its signature and optionally the package")
    p.add_argument("--manifest", type=Path, required=True)
    p.add_argument("--signature", type=Path, required=True)
    p.add_argument("--pub", type=Path, required=True)
    p.add_argument("--deb", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "keygen":
            return keygen(args.out)
        if args.command == "manifest":
            return manifest(args.deb, args.version, args.key, args.out, args.min_upgrade_from, args.notes)
        return verify(args.manifest, args.signature, args.pub, args.deb)
    except Refused as exc:
        print(f"release-sign: {exc}", file=sys.stderr)
        return 1
    except FileExistsError as exc:
        print(f"release-sign: {exc.filename} already exists; nothing was overwritten", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
