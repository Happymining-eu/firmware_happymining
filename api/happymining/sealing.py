"""Sealed secrets and release signatures: the two formats shared with the agent.

**Sealing** lets someone hand a secret (a NAS password, an API key) to one
machine without anyone in between being able to read it. The machine's
privileged helper holds an ECDH P-256 private key; its public key is reported
to the API. Whoever knows the public key can seal; only that machine can open.
The control plane stores and forwards sealed values and never opens them: it
has no key to do so. This module can *seal* (used by tests, the demo and API
clients) and can check that a value looks like a sealed blob. It cannot open.

    blob = "hmseal1." + base64url( ephemeral_public(65) || AES-256-GCM(ciphertext || tag) )
    key  = HKDF-SHA256(ikm = ECDH(ephemeral_private, machine_public),
                       salt = ephemeral_public(65) || machine_public(65),
                       info = b"happymining-seal-v1", length = 32)
    nonce = 12 zero bytes (the key is used once), AAD = the secret's name (UTF-8)

Public keys travel as ``"hmk1." + base64url(uncompressed SEC1 point, 65 bytes)``.

**Release manifests** are signed with Ed25519. The signature covers the exact
bytes of the manifest file. The agent's helper verifies it against keys
installed with the package; the API verifies it too before accepting an
upload, so that an admin session alone cannot publish firmware.

Specified in docs/appliance.md; test vectors in appliance/testdata/.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .errors import InvalidRequest

SEAL_PREFIX = "hmseal1."
KEY_PREFIX = "hmk1."
SEAL_INFO = b"happymining-seal-v1"
POINT_LEN = 65
TAG_LEN = 16
MAX_SECRET_BYTES = 4096
SECRET_NAME_RE = re.compile(r"^[a-z][a-z0-9_.-]{0,62}$")
_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _b64d(text: str) -> bytes:
    if not _B64URL_RE.fullmatch(text or ""):
        raise ValueError("not base64url")
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


# --- machine sealing keys --------------------------------------------------


def parse_seal_public_key(value: str) -> ec.EllipticCurvePublicKey:
    """Validate and load a machine's sealing public key. Raises InvalidRequest."""
    try:
        if not isinstance(value, str) or not value.startswith(KEY_PREFIX):
            raise ValueError("prefix")
        raw = _b64d(value[len(KEY_PREFIX) :])
        if len(raw) != POINT_LEN or raw[0] != 0x04:
            raise ValueError("length")
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)
    except ValueError as exc:
        raise InvalidRequest("not a valid machine sealing key") from exc


def _raw_point(key: ec.EllipticCurvePublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def encode_seal_public_key(key: ec.EllipticCurvePublicKey) -> str:
    return KEY_PREFIX + _b64e(_raw_point(key))


def seal(
    public_key: str,
    name: str,
    plaintext: bytes,
    *,
    _ephemeral: ec.EllipticCurvePrivateKey | None = None,
) -> str:
    """Seal ``plaintext`` under ``name`` for the machine that owns ``public_key``.

    ``_ephemeral`` exists only to produce reproducible test vectors.
    """
    if not SECRET_NAME_RE.fullmatch(name or ""):
        raise InvalidRequest("secret names are lower-case letters, digits, dot, dash and underscore")
    if not isinstance(plaintext, bytes) or not (1 <= len(plaintext) <= MAX_SECRET_BYTES):
        raise InvalidRequest(f"a secret is 1 to {MAX_SECRET_BYTES} bytes")
    machine = parse_seal_public_key(public_key)
    ephemeral = _ephemeral or ec.generate_private_key(ec.SECP256R1())
    ephemeral_public = _raw_point(ephemeral.public_key())
    shared = ephemeral.exchange(ec.ECDH(), machine)
    key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=ephemeral_public + _raw_point(machine), info=SEAL_INFO
    ).derive(shared)
    ciphertext = AESGCM(key).encrypt(b"\x00" * 12, plaintext, name.encode())
    return SEAL_PREFIX + _b64e(ephemeral_public + ciphertext)


def check_sealed(value: str) -> str:
    """Accept only something shaped like a sealed blob. It is not, and cannot be, opened here."""
    try:
        if not isinstance(value, str) or not value.startswith(SEAL_PREFIX):
            raise ValueError("prefix")
        raw = _b64d(value[len(SEAL_PREFIX) :])
        if not (POINT_LEN + TAG_LEN + 1 <= len(raw) <= POINT_LEN + TAG_LEN + MAX_SECRET_BYTES):
            raise ValueError("length")
        if raw[0] != 0x04:
            raise ValueError("point")
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw[:POINT_LEN])
    except ValueError as exc:
        raise InvalidRequest(
            "this value is not sealed for the machine; it must be encrypted before it is sent"
        ) from exc
    return value


# --- release manifests -----------------------------------------------------

MANIFEST_SCHEMA = 1
PRODUCT = "happymining-agent"
VERSION_RE = re.compile(r"^(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})$")
MAX_MANIFEST_BYTES = 16 * 1024


def parse_version(text: str) -> tuple[int, int, int]:
    match = VERSION_RE.fullmatch(text or "")
    if not match:
        raise InvalidRequest("a version is MAJOR.MINOR.PATCH, numbers only")
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


def release_key_id(public_key_raw: bytes) -> str:
    return hashlib.sha256(public_key_raw).hexdigest()[:16]


def load_release_public_keys(encoded: list[str]) -> dict[str, Ed25519PublicKey]:
    """Keys from configuration: base64 of the 32-byte Ed25519 public key."""
    keys: dict[str, Ed25519PublicKey] = {}
    for item in encoded:
        try:
            raw = base64.b64decode(item, validate=True)
            if len(raw) != 32:
                raise ValueError("length")
            keys[release_key_id(raw)] = Ed25519PublicKey.from_public_bytes(raw)
        except ValueError as exc:
            raise InvalidRequest("a release public key is 32 bytes, base64 encoded") from exc
    return keys


@dataclass(frozen=True)
class Manifest:
    version: str
    filename: str
    size: int
    sha256: str
    notes: str
    min_upgrade_from: str
    key_id: str
    raw: bytes


def verify_manifest(raw: bytes, signature_b64: str, keys: dict[str, Ed25519PublicKey]) -> Manifest:
    """Check the signature over the exact manifest bytes, then its content."""
    if not keys:
        raise InvalidRequest("no release public key is configured; releases cannot be accepted")
    if len(raw) > MAX_MANIFEST_BYTES:
        raise InvalidRequest("the manifest is too large")
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except ValueError as exc:
        raise InvalidRequest("the signature is not base64") from exc
    signer = ""
    for key_id, key in keys.items():
        try:
            key.verify(signature, raw)
            signer = key_id
            break
        except InvalidSignature:
            continue
    if not signer:
        raise InvalidRequest("the manifest signature does not verify against any configured release key")
    try:
        doc = json.loads(raw)
        artifact = doc["artifact"]
        if doc["schema"] != MANIFEST_SCHEMA or doc["product"] != PRODUCT:
            raise ValueError("schema or product")
        parse_version(doc["version"])
        min_from = doc.get("min_upgrade_from", "0.0.0")
        parse_version(min_from)
        filename, size, digest = artifact["filename"], artifact["size"], artifact["sha256"]
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,120}\.deb", filename):
            raise ValueError("filename")
        if not isinstance(size, int) or isinstance(size, bool) or not (0 < size <= 512 * 1024 * 1024):
            raise ValueError("size")
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("sha256")
        notes = str(doc.get("notes", ""))[:4000]
    except (ValueError, KeyError, TypeError, InvalidRequest) as exc:
        raise InvalidRequest(f"the manifest is signed but not well formed: {exc}") from exc
    return Manifest(
        version=doc["version"],
        filename=filename,
        size=size,
        sha256=digest,
        notes=notes,
        min_upgrade_from=min_from,
        key_id=signer,
        raw=raw,
    )


def sign_manifest(raw: bytes, private_key: Ed25519PrivateKey) -> str:
    """Used by the release tooling and by tests."""
    return base64.b64encode(private_key.sign(raw)).decode()
