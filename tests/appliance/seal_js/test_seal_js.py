"""The browser's sealing code, ``dashboard/static/seal.js``, against docs/appliance.md, section 5.

``seal.js`` runs under Node (``seal_runner.js``, WebCrypto only, no npm package). Every value it
produces is opened here, in Python, with ``cryptography`` and the published test private key of
``appliance/testdata/seal-vectors.json``, following the format documented in
``api/happymining/sealing.py``. The opener is first checked against the published vectors, so a
mistake in it cannot make a wrong ``seal.js`` look right.

Also covered: what ``seal.js`` refuses (a key that is not a machine key, an empty or oversized
secret, a name that is not a secret name), and ``sealForm``, the part the appliance page runs on
submit, on a minimal stand-in for a form: sealed values go into the hidden inputs under the right
names and the password fields are cleared; on any problem nothing is left to submit.

No database, no browser, no network.
"""

from __future__ import annotations

import base64
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from happymining import sealing
from happymining.errors import InvalidRequest

REPO = Path(__file__).resolve().parents[3]
RUNNER = Path(__file__).with_name("seal_runner.js")
SEAL_JS = REPO / "dashboard" / "static" / "seal.js"
VECTORS = json.loads((REPO / "appliance" / "testdata" / "seal-vectors.json").read_text())
PUBLIC_KEY = VECTORS["machine_public_key"]
PRIVATE_KEY = serialization.load_der_private_key(
    base64.b64decode(VECTORS["machine_private_key_pkcs8_b64"]), password=None
)
NODE = shutil.which("node")

pytestmark = pytest.mark.skipif(NODE is None, reason="Node.js is not installed")


# --- opening, in Python ----------------------------------------------------


def b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def open_sealed(blob: str, name: str, private_key: ec.EllipticCurvePrivateKey = PRIVATE_KEY) -> bytes:
    """Open a sealed value as the machine's helper does. Raises on any mismatch."""
    if not blob.startswith(sealing.SEAL_PREFIX):
        raise ValueError("prefix")
    raw = b64url_decode(blob[len(sealing.SEAL_PREFIX) :])
    ephemeral_public, ciphertext = raw[:65], raw[65:]
    ephemeral = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), ephemeral_public)
    machine_public = private_key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    shared = private_key.exchange(ec.ECDH(), ephemeral)
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=ephemeral_public + machine_public,
        info=b"happymining-seal-v1",
    ).derive(shared)
    return AESGCM(key).decrypt(b"\x00" * 12, ciphertext, name.encode())


def tampered(blob: str, index: int) -> str:
    """The same blob with one bit flipped at byte ``index`` of the decoded payload."""
    raw = bytearray(b64url_decode(blob[len(sealing.SEAL_PREFIX) :]))
    raw[index] ^= 0x01
    return sealing.SEAL_PREFIX + base64.urlsafe_b64encode(bytes(raw)).decode().rstrip("=")


# --- running seal.js -------------------------------------------------------


def run(request: dict[str, Any]) -> list[dict[str, Any]]:
    done = subprocess.run(
        [NODE, str(RUNNER)],
        input=json.dumps(request).encode(),
        capture_output=True,
        timeout=120,
        check=False,
    )
    assert done.returncode == 0, done.stderr.decode()
    return json.loads(done.stdout)["results"]


def js_seal(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return run({"mode": "seal", "items": [{"public_key": PUBLIC_KEY, **item} for item in items]})


def point(x: int, y: int) -> str:
    return sealing.KEY_PREFIX + base64.urlsafe_b64encode(
        b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")
    ).decode().rstrip("=")


# Names the appliance page seals under, and the extremes of the name rule.
NAMES = (
    "nas.docs.password",
    "ai.answer.api_key",
    "backup.s3.secret_key",
    "plugin.assistant.api_key",
    "x",
    "a" + "b" * 62,  # 63 characters, the longest name
)
TEXTS = (
    "correct horse battery staple",
    "pässwörd-with-ünicode ✓",
    "日本語のパスワード",
    "emoji \U0001f512 and a tab\there",
    " leading and trailing spaces are part of a secret ",
    "a" * 4096,  # the largest secret, one byte per character
    "é" * 2048,  # 4096 bytes in two-byte characters
    "€" * 1365 + "a",  # 4096 bytes: 1365 three-byte characters and one more byte
    "x",  # the smallest secret
)


# --- the opener is right ---------------------------------------------------


def test_the_python_opener_opens_the_published_vectors_and_refuses_the_broken_ones():
    for vector in VECTORS["vectors"]:
        assert open_sealed(vector["sealed"], vector["name"]) == base64.b64decode(vector["plaintext_b64"])
    for broken in VECTORS["must_fail"]:
        with pytest.raises((InvalidTag, ValueError)):
            open_sealed(broken["sealed"], broken["name"])


def test_the_published_private_key_is_the_one_of_the_published_public_key():
    assert sealing.encode_seal_public_key(PRIVATE_KEY.public_key()) == PUBLIC_KEY


# --- seal.js produces what the machine opens --------------------------------


def test_what_seal_js_seals_opens_with_the_machine_key_under_its_name():
    items = [{"name": name, "text": text} for name in NAMES for text in TEXTS]
    results = js_seal(items)
    assert len(results) == len(items)
    for item, result in zip(items, results, strict=True):
        assert result["ok"], (item["name"], len(item["text"]), result)
        blob = result["sealed"]
        assert open_sealed(blob, item["name"]) == item["text"].encode("utf-8")
        # The server's shape check accepts it as it is.
        assert sealing.check_sealed(blob) == blob


def test_the_output_has_the_documented_layout():
    (result,) = js_seal([{"name": "nas.docs.password", "text": "hunter2"}])
    blob = result["sealed"]
    assert blob.startswith("hmseal1.")
    body = blob[len("hmseal1.") :]
    assert set(body) <= set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")  # no padding
    raw = b64url_decode(body)
    assert len(raw) == 65 + len(b"hunter2") + 16
    # The ephemeral public key is an uncompressed point on P-256.
    assert raw[0] == 0x04
    ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw[:65])


def test_bytes_are_sealed_as_they_are():
    data = bytes(range(256)) * 16  # 4096 bytes, every byte value
    (result,) = js_seal([{"name": "backup.s3.secret_key", "bytes_b64": base64.b64encode(data).decode()}])
    assert result["ok"] and open_sealed(result["sealed"], "backup.s3.secret_key") == data


def test_every_seal_uses_a_new_ephemeral_key():
    results = js_seal([{"name": "ai.answer.api_key", "text": "same secret"}] * 3)
    blobs = [result["sealed"] for result in results]
    assert len(set(blobs)) == 3 and len({blob[8:95] for blob in blobs}) == 3
    assert all(open_sealed(blob, "ai.answer.api_key") == b"same secret" for blob in blobs)


def test_the_name_is_authenticated_and_any_changed_byte_is_detected():
    (result,) = js_seal([{"name": "nas.docs.password", "text": "correct horse battery staple"}])
    blob = result["sealed"]
    assert open_sealed(blob, "nas.docs.password") == b"correct horse battery staple"
    for other in ("nas.other.password", "nas.docs.passwore", "ai.answer.api_key", "nas.docs.password."):
        with pytest.raises(InvalidTag):
            open_sealed(blob, other)
    size = len(b64url_decode(blob[8:]))
    # In the ciphertext, in the tag, and in the ephemeral key (other key: other AES key, or no point).
    for index in (65, 70, size - 16, size - 1, 1, 40, 64):
        with pytest.raises((InvalidTag, ValueError)):
            open_sealed(tampered(blob, index), "nas.docs.password")
    # Another machine cannot open it.
    with pytest.raises(InvalidTag):
        open_sealed(blob, "nas.docs.password", ec.generate_private_key(ec.SECP256R1()))


# --- what seal.js refuses ---------------------------------------------------


P = 2**256 - 2**224 + 2**192 + 2**96 - 1  # the P-256 field prime
INVALID_KEYS = {
    "empty": "",
    "prefix only": "hmk1.",
    "another prefix": "hmk2." + PUBLIC_KEY[5:],
    "no prefix": PUBLIC_KEY[5:],
    "not base64url": PUBLIC_KEY[:-4] + "+/==",
    "with padding": PUBLIC_KEY + "=",
    "with white space": PUBLIC_KEY[:20] + " " + PUBLIC_KEY[20:],
    "too short": PUBLIC_KEY[:-2],
    "too long": PUBLIC_KEY + "AA",
    "compressed point": sealing.KEY_PREFIX
    + base64.urlsafe_b64encode(
        PRIVATE_KEY.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint
        )
    )
    .decode()
    .rstrip("="),
    "not on the curve": point(1, 1),
    "the point at zero": point(0, 0),
    "coordinates beyond the field": point(P, P),
}


@pytest.mark.parametrize("why", sorted(INVALID_KEYS))
def test_a_key_that_is_not_a_machine_sealing_key_is_refused(why):
    key = INVALID_KEYS[why]
    # The server refuses every one of them too.
    with pytest.raises(InvalidRequest):
        sealing.parse_seal_public_key(key)
    (result,) = run({"mode": "seal", "items": [{"public_key": key, "name": "x", "text": "secret"}]})
    assert result == {"ok": False, "error": "not a valid machine sealing key"}, why


def test_a_key_of_the_wrong_type_is_refused():
    results = run(
        {
            "mode": "seal",
            "items": [{"public_key": value, "name": "x", "text": "s"} for value in (None, 12, [])],
        }
    )
    assert [result["ok"] for result in results] == [False, False, False]


def test_an_empty_or_oversized_secret_is_refused():
    items = [
        {"name": "x", "text": ""},
        {"name": "x", "bytes_b64": ""},
        {"name": "x", "text": "a" * 4097},
        {"name": "x", "text": "é" * 2049},  # 2049 characters, but 4098 bytes
        {"name": "x", "text": "€" * 1366},  # 4098 bytes
    ]
    for result in js_seal(items):
        assert result == {"ok": False, "error": "a secret is 1 to 4096 bytes (UTF-8)"}


def test_a_secret_that_is_neither_text_nor_bytes_is_refused():
    for result in js_seal([{"name": "x", "value": value} for value in (None, 12, True, {"a": 1}, ["a"])]):
        assert result == {"ok": False, "error": "a secret is text or bytes"}


@pytest.mark.parametrize(
    "name",
    ["", "Nas.docs.password", "1nas", ".nas", "-nas", "nas docs", "nas/docs", "näs", "a" * 64, "nas\n"],
)
def test_a_name_that_is_not_a_secret_name_is_refused(name):
    assert not sealing.SECRET_NAME_RE.fullmatch(name)
    (result,) = js_seal([{"name": name, "text": "secret"}])
    assert result["ok"] is False and "secret names are" in result["error"]


# --- sealForm: what the page does on submit ---------------------------------


def secret(target: str, value: str, **attrs: str) -> dict[str, Any]:
    return {"value": value, "attrs": {"data-seal-target": target, **attrs}}


def test_a_form_is_sealed_into_its_hidden_inputs_and_its_password_fields_are_cleared():
    form = {
        "key": PUBLIC_KEY,
        "fields": {
            "nas_id": {"type": "text", "value": " docs "},
            "sealed_secret": {"type": "hidden", "value": "left over"},
            "sealed_secret.api_key": {"type": "hidden", "value": ""},
            "sealed_secret.other": {"type": "hidden", "value": "stale"},
        },
        "secrets": [
            secret(
                "sealed_secret",
                "nas pässword",
                **{"data-seal-name-template": "nas.{id}.password", "data-seal-name-field": "nas_id"},
            ),
            secret("sealed_secret.api_key", "sk-test-123", **{"data-seal-name": "plugin.assistant.api_key"}),
            # Left empty: nothing is sealed, and the hidden input is emptied (the server keeps its value).
            secret("sealed_secret.other", "", **{"data-seal-name": "plugin.assistant.other"}),
        ],
    }
    (result,) = run({"mode": "form", "forms": [form]})
    assert result["ok"] and result["count"] == 2, result
    assert result["secrets"] == ["", "", ""]  # every password field is empty afterwards
    fields = result["fields"]
    assert open_sealed(fields["sealed_secret"], "nas.docs.password") == "nas pässword".encode()
    assert open_sealed(fields["sealed_secret.api_key"], "plugin.assistant.api_key") == b"sk-test-123"
    assert fields["sealed_secret.other"] == "" and fields["nas_id"] == " docs "


def test_a_form_with_nothing_typed_seals_nothing_and_needs_no_key():
    form = {
        "key": None,
        "fields": {"sealed_secret": {"type": "hidden", "value": ""}},
        "secrets": [secret("sealed_secret", "", **{"data-seal-name": "ai.answer.api_key"})],
    }
    (result,) = run({"mode": "form", "forms": [form]})
    assert result["ok"] and result["count"] == 0 and result["fields"] == {"sealed_secret": ""}


FORM_PROBLEMS = {
    "no key reported": (
        {"key": None},
        [secret("s", "pw", **{"data-seal-name": "nas.docs.password"})],
        "has not reported its sealing key",
    ),
    "a key that is not a key": (
        {"key": "hmk1.rubbish"},
        [secret("s", "pw", **{"data-seal-name": "nas.docs.password"})],
        "not a valid machine sealing key",
    ),
    "an id that is not an id": (
        {"key": PUBLIC_KEY, "id": "Docs!"},
        [
            secret(
                "s",
                "pw",
                **{"data-seal-name-template": "nas.{id}.password", "data-seal-name-field": "nas_id"},
            )
        ],
        "Enter a valid id first",
    ),
    "no id at all": (
        {"key": PUBLIC_KEY, "id": ""},
        [
            secret(
                "s",
                "pw",
                **{"data-seal-name-template": "nas.{id}.password", "data-seal-name-field": "nas_id"},
            )
        ],
        "Enter a valid id first",
    ),
    "no name": ({"key": PUBLIC_KEY}, [secret("s", "pw")], "does not say which secret"),
    "no hidden input": (
        {"key": PUBLIC_KEY},
        [secret("missing", "pw", **{"data-seal-name": "nas.docs.password"})],
        "missing the field",
    ),
    "a visible target": (
        {"key": PUBLIC_KEY},
        [secret("nas_id", "pw", **{"data-seal-name": "nas.docs.password"})],
        "missing the field",
    ),
    "an empty secret is fine, a long one is not": (
        {"key": PUBLIC_KEY},
        [
            secret("s", "x" * 4097, **{"data-seal-name": "nas.docs.password"}),
        ],
        "1 to 4096 bytes",
    ),
}


@pytest.mark.parametrize("why", sorted(FORM_PROBLEMS))
def test_a_form_that_cannot_be_sealed_leaves_nothing_to_submit(why):
    options, secrets, message = FORM_PROBLEMS[why]
    # A first secret that would seal fine: it must not be left behind either.
    good = secret("t", "fine", **{"data-seal-name": "ai.answer.api_key"})
    form = {
        "key": options["key"],
        "fields": {
            "nas_id": {"type": "text", "value": options.get("id", "docs")},
            "s": {"type": "hidden", "value": "stale"},
            "t": {"type": "hidden", "value": ""},
        },
        "secrets": [good, *secrets],
    }
    (result,) = run({"mode": "form", "forms": [form]})
    assert result["ok"] is False and message in result["error"], result
    # No hidden input that receives a secret holds anything: not the good one, not a stale value.
    targeted = {s["attrs"]["data-seal-target"] for s in secrets}
    assert result["fields"]["t"] == ""
    assert result["fields"]["s"] == ("" if "s" in targeted else "stale")
    # Nothing was cleared either: the person can correct the form and submit again.
    assert result["secrets"] == ["fine", *[s["value"] for s in secrets]]


def test_seal_js_has_no_dependency_and_runs_as_a_classic_script():
    text = SEAL_JS.read_text()
    assert "require(" not in text and "import " not in text
    # No inline handler could be wired by it either: it attaches listeners.
    assert "addEventListener" in text and "eval(" not in text and "innerHTML" not in text
