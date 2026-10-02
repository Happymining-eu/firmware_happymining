"""Security primitives. Everything here wraps an established implementation:

- password hashing: Argon2id (argon2-cffi)
- second factor: RFC 6238 TOTP (pyotp)
- field encryption: Fernet (cryptography)
- tokens: ``secrets`` CSPRNG, stored as HMAC-SHA256 keyed with the server secret
- comparisons: ``hmac.compare_digest``

No custom cryptography.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import hmac
import json
import re
import secrets
import time
import uuid
from dataclasses import dataclass
from typing import Any

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from cryptography.fernet import Fernet, InvalidToken

from .config import Settings

_hasher = PasswordHasher()

# --- keyed hashing ---------------------------------------------------------


def _subkey(settings: Settings, purpose: str) -> bytes:
    """Derive an independent key per purpose from the server secret (HKDF-like, HMAC)."""
    root = settings.secret_key.get_secret_value().encode()
    return hmac.new(root, b"happymining/v1/" + purpose.encode(), hashlib.sha256).digest()


def keyed_hash(settings: Settings, purpose: str, value: str) -> str:
    return hmac.new(_subkey(settings, purpose), value.encode(), hashlib.sha256).hexdigest()


def constant_time_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


# --- passwords -------------------------------------------------------------


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(stored_hash: str | None, password: str) -> bool:
    if not stored_hash:
        # Spend comparable time so "no such user" is not distinguishable by timing.
        with contextlib.suppress(VerificationError, InvalidHashError):
            _hasher.verify(_DUMMY_HASH, password)
        return False
    try:
        return _hasher.verify(stored_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


_DUMMY_HASH = _hasher.hash("not-a-real-password")

# --- TOTP ------------------------------------------------------------------


def new_totp_secret() -> str:
    return pyotp.random_base32()


def totp_uri(secret: str, email: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name="HappyMining")


def match_totp_step(secret: str, code: str, now: float | None = None) -> int | None:
    """The time-step a code belongs to, if it is valid now (one step of clock drift allowed).

    Callers compare the step with the last one accepted for the user, so that a
    code is good for one login only (RFC 6238, section 5.2).
    """
    code = (code or "").strip().replace(" ", "")
    if not re.fullmatch(r"\d{6}", code):
        return None
    totp = pyotp.TOTP(secret)
    moment = int(now if now is not None else time.time())
    counter = moment // totp.interval
    matched: int | None = None
    for offset in (0, -1, 1):
        if hmac.compare_digest(totp.at(moment, offset), code) and matched is None:
            matched = counter + offset
    return matched


def verify_totp(secret: str, code: str) -> bool:
    return match_totp_step(secret, code) is not None


# --- field encryption ------------------------------------------------------


def _fernet(settings: Settings) -> Fernet:
    return Fernet(settings.field_encryption_key.get_secret_value().encode())


def encrypt_text(settings: Settings, plaintext: str) -> str:
    return _fernet(settings).encrypt(plaintext.encode()).decode()


def decrypt_text(settings: Settings, token: str) -> str:
    try:
        return _fernet(settings).decrypt(token.encode()).decode()
    except InvalidToken as exc:
        raise ValueError("stored value cannot be decrypted with the configured key") from exc


def encrypt_json(settings: Settings, value: dict[str, Any]) -> str:
    return encrypt_text(settings, json.dumps(value, sort_keys=True, separators=(",", ":")))


def decrypt_json(settings: Settings, token: str) -> dict[str, Any]:
    return json.loads(decrypt_text(settings, token))


# --- human sessions --------------------------------------------------------

SESSION_PREFIX = "hms_"


def new_session_token() -> str:
    return SESSION_PREFIX + secrets.token_urlsafe(32)


def new_csrf_token() -> str:
    return secrets.token_urlsafe(32)


# --- pairing codes ---------------------------------------------------------

CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_CROCKFORD_SET = frozenset(CROCKFORD)
LOCATOR_LEN = 6
SECRET_LEN = 16


def _random_crockford(n: int) -> str:
    return "".join(secrets.choice(CROCKFORD) for _ in range(n))


@dataclass(frozen=True)
class PairingCode:
    locator: str
    secret: str

    @property
    def display(self) -> str:
        groups = [self.secret[i : i + 4] for i in range(0, SECRET_LEN, 4)]
        return f"HM-{self.locator}-" + "-".join(groups)


def new_pairing_code() -> PairingCode:
    return PairingCode(locator=_random_crockford(LOCATOR_LEN), secret=_random_crockford(SECRET_LEN))


def parse_pairing_code(raw: str) -> PairingCode | None:
    """Normalise operator input. Returns None for anything malformed."""
    if not isinstance(raw, str) or len(raw) > 64:
        return None
    text = raw.strip().upper().replace("-", "").replace(" ", "")
    if text.startswith("HM"):
        text = text[2:]
    text = text.replace("O", "0").replace("I", "1").replace("L", "1")
    if len(text) != LOCATOR_LEN + SECRET_LEN or not set(text) <= _CROCKFORD_SET:
        return None
    return PairingCode(locator=text[:LOCATOR_LEN], secret=text[LOCATOR_LEN:])


def pairing_secret_hash(settings: Settings, locator: str, secret: str) -> str:
    return keyed_hash(settings, "pairing", f"{locator}:{secret}")


# --- device credentials ----------------------------------------------------

DEVICE_PREFIX = "hmd_"
_DEVICE_TOKEN_RE = re.compile(r"^hmd_([0-9a-fA-F]{32})\.([A-Za-z0-9_-]{43})$")


def new_device_secret() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")


def format_device_token(credential_id: uuid.UUID, secret: str) -> str:
    return f"{DEVICE_PREFIX}{credential_id.hex}.{secret}"


def parse_device_token(token: str) -> tuple[uuid.UUID, str] | None:
    match = _DEVICE_TOKEN_RE.match(token or "")
    if not match:
        return None
    return uuid.UUID(hex=match.group(1).lower()), match.group(2)


def device_secret_hash(settings: Settings, secret: str) -> str:
    return keyed_hash(settings, "device-credential", secret)


def session_token_hash(settings: Settings, token: str) -> str:
    return keyed_hash(settings, "session", token)


def new_nonce() -> str:
    return secrets.token_urlsafe(18)


# --- redaction -------------------------------------------------------------

# Crockford base32 without I, L, O, U: the pairing-code alphabet.
_CODE_CHARS = "0-9A-HJKMNP-TV-Z"
# Replaced whole.
_REDACT_WHOLE = (
    re.compile(r"hmd_[0-9a-fA-F]{32}\.[A-Za-z0-9_-]{20,}"),
    re.compile(r"hms_[A-Za-z0-9_-]{20,}"),
    # Pairing codes as typed: with the HM prefix, groups joined by hyphens, spaces or nothing...
    re.compile(rf"\bHM[-\s]?[{_CODE_CHARS}]{{6}}(?:[-\s]?[{_CODE_CHARS}]{{4}}){{4}}\b", re.IGNORECASE),
    # ...or without the prefix, which the parser also accepts. Only the grouped
    # form is recognisable then; 22 bare characters would match too much.
    re.compile(rf"\b[{_CODE_CHARS}]{{6}}(?:[-\s][{_CODE_CHARS}]{{4}}){{4}}\b", re.IGNORECASE),
)
# The first group is kept, the rest is replaced.
_REDACT_AFTER_PREFIX = (
    re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+"),
    re.compile(r"(?i)(basic\s+)[A-Za-z0-9+/=]{8,}"),
    re.compile(r"(://[^/\s:@]+:)[^@\s/]+(?=@)"),
    # A logged Cookie / Set-Cookie header line: everything up to the end of the line.
    re.compile(r"(?i)((?:set-)?cookie\"?\s*:\s*)[^\r\n]+"),
)
# name = value / name: value, where the value may be quoted (and then may contain spaces).
_KEY_VALUE = re.compile(
    r"(?i)((?:api[_-]?key|passw(?:or)?d|passphrase|secret|token|authorization)\"?\s*[:=]\s*)"
    r"(\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s\",}]+)"
)
# A key is sensitive if it contains any of these once "-" is read as "_" (so
# "vast_api_key", "X-Api-Key", "Set-Cookie" and "secret_key" are covered, not
# only the exact names).
_SENSITIVE_KEY_PARTS = (
    "password",
    "passwd",
    "passphrase",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "pairing_code",
    "totp",
    "credential",
    "iban",
    "account_number",
    "private_key",
)


def _is_sensitive_key(key: str) -> bool:
    lowered = key.lower().replace("-", "_")
    return any(part in lowered for part in _SENSITIVE_KEY_PARTS)


def _mask_value(match: re.Match[str]) -> str:
    value = match.group(2)
    quote = value[0] if value[0] in "\"'" else ""
    return f"{match.group(1)}{quote}[REDACTED]{quote}"


def redact_text(value: str) -> str:
    """Best-effort removal of credentials from free text.

    Pattern matching cannot recognise every secret. The rule that matters is
    that secrets are not put into log lines or audit details in the first
    place; this is the net underneath.
    """
    out = value
    for pattern in _REDACT_WHOLE:
        out = pattern.sub("[REDACTED]", out)
    for pattern in _REDACT_AFTER_PREFIX:
        out = pattern.sub(r"\1[REDACTED]", out)
    return _KEY_VALUE.sub(_mask_value, out)


def redact(value: Any, _depth: int = 0) -> Any:
    """Recursively redact secrets from anything about to be logged or audited."""
    if _depth > 8:
        return "[TRUNCATED]"
    if isinstance(value, dict):
        return {
            str(k): ("[REDACTED]" if _is_sensitive_key(str(k)) else redact(v, _depth + 1))
            for k, v in value.items()
        }
    if isinstance(value, list | tuple):
        return [redact(v, _depth + 1) for v in value[:200]]
    if isinstance(value, str):
        return redact_text(value)[:4000]
    if isinstance(value, bytes):
        return f"[{len(value)} bytes]"
    return value
