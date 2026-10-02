"""Sealed secrets and release signatures: the two formats shared with the agent.

The vectors in ``appliance/testdata`` are the contract (docs/appliance.md,
sections 5 and 9): the Go helper and the browser code must pass the same ones.
The control plane can seal and can check that a value *looks* sealed; it has no
key to open anything. Opening is done here, in the test, with the published
test key, to prove that what ``seal`` produces is what a machine can read.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from helpers import live_settings, make_settings

from happymining import sealing
from happymining.config import TEST_RELEASE_PUBLIC_KEY, ConfigError
from happymining.errors import InvalidRequest

TESTDATA = Path(__file__).resolve().parents[2] / "appliance" / "testdata"
SEAL = json.loads((TESTDATA / "seal-vectors.json").read_text())
RELEASE = json.loads((TESTDATA / "release-vector.json").read_text())
MACHINE_PUBLIC = SEAL["machine_public_key"]


def b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def machine_private_key() -> ec.EllipticCurvePrivateKey:
    """The published TEST key of the vectors. Never a real machine's."""
    return serialization.load_der_private_key(
        base64.b64decode(SEAL["machine_private_key_pkcs8_b64"]), password=None
    )


def open_sealed(private_key: ec.EllipticCurvePrivateKey, name: str, sealed: str) -> bytes:
    """What the machine's helper does. Written from the format in docs/appliance.md, section 5."""
    assert sealed.startswith("hmseal1.")
    raw = b64url_decode(sealed[len("hmseal1.") :])
    ephemeral_public, ciphertext = raw[:65], raw[65:]
    ephemeral = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), ephemeral_public)
    machine_public = private_key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=ephemeral_public + machine_public,
        info=b"happymining-seal-v1",
    ).derive(private_key.exchange(ec.ECDH(), ephemeral))
    return AESGCM(key).decrypt(b"\x00" * 12, ciphertext, name.encode())


# --- sealing ---------------------------------------------------------------


def test_the_published_key_pair_belongs_together():
    private = machine_private_key()
    assert sealing.encode_seal_public_key(private.public_key()) == MACHINE_PUBLIC
    assert format(private.private_numbers().private_value, "064x") == SEAL["machine_private_scalar_hex"]
    assert MACHINE_PUBLIC.startswith("hmk1.") and len(b64url_decode(MACHINE_PUBLIC[5:])) == 65


@pytest.mark.parametrize("vector", SEAL["vectors"], ids=lambda v: v["name"])
def test_every_vector_opens_to_its_plaintext_and_looks_sealed(vector):
    plaintext = base64.b64decode(vector["plaintext_b64"])
    assert open_sealed(machine_private_key(), vector["name"], vector["sealed"]) == plaintext
    # The control plane's own check accepts it, and returns it unchanged.
    assert sealing.check_sealed(vector["sealed"]) == vector["sealed"]


@pytest.mark.parametrize("case", SEAL["must_fail"], ids=lambda c: c["why"])
def test_must_fail_cases_do_not_open(case):
    with pytest.raises((InvalidTag, ValueError, AssertionError)):
        open_sealed(machine_private_key(), case["name"], case["sealed"])


def test_what_seal_produces_only_opens_under_its_own_name():
    secret = "correct horse battery staple é✓".encode()
    sealed = sealing.seal(MACHINE_PUBLIC, "nas.docs.password", secret)
    assert sealed.startswith("hmseal1.") and secret not in sealed.encode()
    assert open_sealed(machine_private_key(), "nas.docs.password", sealed) == secret
    # The name is authenticated: the same value does not open as anything else.
    with pytest.raises(InvalidTag):
        open_sealed(machine_private_key(), "ai.answer.api_key", sealed)
    # Another machine's key opens nothing.
    with pytest.raises(InvalidTag):
        open_sealed(ec.generate_private_key(ec.SECP256R1()), "nas.docs.password", sealed)
    # Each sealing uses a fresh ephemeral key: the same secret never looks the same twice.
    assert sealing.seal(MACHINE_PUBLIC, "nas.docs.password", secret) != sealed


def test_seal_refuses_bad_names_sizes_and_keys():
    for name in ("", "Nas.docs", "nas docs", "1abc", "a" * 64, "nas/docs"):
        with pytest.raises(InvalidRequest):
            sealing.seal(MACHINE_PUBLIC, name, b"x")
    for plaintext in (b"", b"x" * 4097, "text"):
        with pytest.raises(InvalidRequest):
            sealing.seal(MACHINE_PUBLIC, "ok.name", plaintext)
    assert sealing.check_sealed(sealing.seal(MACHINE_PUBLIC, "ok.name", b"x" * 4096))
    for key in (
        "",
        "hmk1.",
        "hmk2." + MACHINE_PUBLIC[5:],
        MACHINE_PUBLIC[:-4],
        MACHINE_PUBLIC + "A",
        None,
        7,
    ):
        with pytest.raises(InvalidRequest):
            sealing.seal(key, "ok.name", b"x")


def test_seal_public_key_must_be_a_point_on_the_curve():
    assert sealing.parse_seal_public_key(MACHINE_PUBLIC)
    raw = bytearray(b64url_decode(MACHINE_PUBLIC[5:]))
    raw[-1] ^= 1  # no longer on the curve
    off_curve = "hmk1." + base64.urlsafe_b64encode(bytes(raw)).decode().rstrip("=")
    compressed = "hmk1." + base64.urlsafe_b64encode(b"\x02" + bytes(raw[1:33])).decode().rstrip("=")
    for bad in (off_curve, compressed, "hmk1.!!!!", "hmk1." + "A" * 87, MACHINE_PUBLIC + "=="):
        with pytest.raises(InvalidRequest):
            sealing.parse_seal_public_key(bad)


def sealed_from(raw: bytes) -> str:
    return "hmseal1." + base64.urlsafe_b64encode(raw).decode().rstrip("=")


def test_check_sealed_accepts_only_the_shape_of_a_sealed_value():
    good = SEAL["vectors"][0]["sealed"]
    raw = b64url_decode(good[len("hmseal1.") :])
    point, rest = raw[:65], raw[65:]
    shortest = sealed_from(point + b"\x00" * 17)  # one byte of plaintext and the tag
    longest = sealed_from(point + b"\x00" * (4096 + 16))
    assert sealing.check_sealed(shortest) and sealing.check_sealed(longest)
    off_curve = bytearray(point)
    off_curve[-1] ^= 1
    refused = {
        "clear text": "hunter2",
        "empty": "",
        "prefix only": "hmseal1.",
        "wrong prefix": "hmseal2." + good[8:],
        "upper-case prefix": "HMSEAL1." + good[8:],
        "not base64url": "hmseal1." + good[8:-2] + "+/",
        "padded": good + "=",
        "white space": good + " ",
        "no plaintext": sealed_from(point + b"\x00" * 16),
        "too long": sealed_from(point + b"\x00" * (4096 + 17)),
        "compressed point": sealed_from(b"\x02" + raw[1:]),
        "point not on the curve": sealed_from(bytes(off_curve) + rest),
        "a number": 12,
        "nothing": None,
        "a list": [good],
        "bytes": good.encode(),
    }
    for why, value in refused.items():
        with pytest.raises(InvalidRequest) as caught:
            sealing.check_sealed(value)
        # The refusal never repeats what was sent: it may have been a password in clear text.
        assert "hunter2" not in caught.value.message, why
    # It is a check of shape only. The control plane cannot tell whether a
    # well-formed blob opens: the last vector with its tag damaged still passes.
    assert sealing.check_sealed(SEAL["must_fail"][1]["sealed"])


# --- release manifests -----------------------------------------------------

MANIFEST = base64.b64decode(RELEASE["manifest_b64"])
SIGNATURE = RELEASE["signature_b64"]


def release_keys():
    return sealing.load_release_public_keys([RELEASE["public_key_b64"]])


def test_the_release_vector_verifies():
    keys = release_keys()
    assert list(keys) == [RELEASE["key_id"]]
    assert sealing.release_key_id(base64.b64decode(RELEASE["public_key_b64"])) == RELEASE["key_id"]
    manifest = sealing.verify_manifest(MANIFEST, SIGNATURE, keys)
    artifact = base64.b64decode(RELEASE["artifact_b64"])
    assert manifest.version == "0.2.0" and manifest.min_upgrade_from == "0.1.0"
    assert manifest.filename == "happymining-agent_0.2.0_amd64.deb"
    assert (manifest.size, manifest.sha256) == (len(artifact), hashlib.sha256(artifact).hexdigest())
    assert manifest.key_id == RELEASE["key_id"] and manifest.raw == MANIFEST
    # The private seed in the vector signs exactly this.
    seed = Ed25519PrivateKey.from_private_bytes(base64.b64decode(RELEASE["private_seed_b64"]))
    assert sealing.sign_manifest(MANIFEST, seed) == SIGNATURE


def test_a_tampered_manifest_or_signature_is_refused():
    keys = release_keys()
    for tampered in (
        MANIFEST.replace(b'"0.2.0"', b'"0.9.0"'),
        MANIFEST + b" ",  # the signature covers the exact bytes, white space included
        MANIFEST.rstrip(b"\n"),
        MANIFEST.replace(b'"size": 11', b'"size": 12'),
    ):
        assert tampered != MANIFEST
        with pytest.raises(InvalidRequest, match="does not verify"):
            sealing.verify_manifest(tampered, SIGNATURE, keys)
    flipped = bytearray(base64.b64decode(SIGNATURE))
    flipped[0] ^= 1
    for bad_signature in (base64.b64encode(bytes(flipped)).decode(), base64.b64encode(b"\x00" * 64).decode()):
        with pytest.raises(InvalidRequest, match="does not verify"):
            sealing.verify_manifest(MANIFEST, bad_signature, keys)
    with pytest.raises(InvalidRequest, match="not base64"):
        sealing.verify_manifest(MANIFEST, "not base64!", keys)


def test_a_manifest_signed_with_an_unknown_key_is_refused():
    stranger = Ed25519PrivateKey.generate()
    signature = sealing.sign_manifest(MANIFEST, stranger)
    with pytest.raises(InvalidRequest, match="does not verify against any configured release key"):
        sealing.verify_manifest(MANIFEST, signature, release_keys())
    # Configured next to the real one, it is accepted and named as the signer.
    raw = stranger.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    keys = sealing.load_release_public_keys([RELEASE["public_key_b64"], base64.b64encode(raw).decode()])
    assert sealing.verify_manifest(MANIFEST, signature, keys).key_id == sealing.release_key_id(raw)


def test_without_a_configured_key_nothing_verifies():
    with pytest.raises(InvalidRequest, match="no release public key is configured"):
        sealing.verify_manifest(MANIFEST, SIGNATURE, {})
    assert sealing.load_release_public_keys([]) == {}
    for bad in ("not-base64!", base64.b64encode(b"short").decode(), ""):
        with pytest.raises(InvalidRequest):
            sealing.load_release_public_keys([bad])


def signed(document: dict) -> tuple[bytes, str]:
    seed = Ed25519PrivateKey.from_private_bytes(base64.b64decode(RELEASE["private_seed_b64"]))
    raw = json.dumps(document).encode()
    return raw, sealing.sign_manifest(raw, seed)


@pytest.mark.parametrize(
    "change",
    [
        {"schema": 2},
        {"product": "something-else"},
        {"version": "1.2"},
        {"version": "01.2.3"},
        {"version": "1.2.3-rc1"},
        {"min_upgrade_from": "latest"},
        {"artifact": {"filename": "../x.deb", "size": 11, "sha256": "0" * 64}},
        {"artifact": {"filename": "x.exe", "size": 11, "sha256": "0" * 64}},
        {"artifact": {"filename": "x.deb", "size": 0, "sha256": "0" * 64}},
        {"artifact": {"filename": "x.deb", "size": True, "sha256": "0" * 64}},
        {"artifact": {"filename": "x.deb", "size": "11", "sha256": "0" * 64}},
        {"artifact": {"filename": "x.deb", "size": 11, "sha256": "ABC"}},
        {"artifact": {"filename": "x.deb", "size": 600 * 1024 * 1024, "sha256": "0" * 64}},
        {"artifact": None},
    ],
)
def test_a_correctly_signed_manifest_must_still_be_well_formed(change):
    """A signature proves who wrote the manifest, not that it makes sense."""
    raw, signature = signed({**json.loads(MANIFEST), **change})
    with pytest.raises(InvalidRequest, match="signed but not well formed"):
        sealing.verify_manifest(raw, signature, release_keys())


def test_a_manifest_larger_than_16_kib_is_refused_before_anything_else():
    raw, signature = signed({**json.loads(MANIFEST), "notes": "x" * (16 * 1024)})
    with pytest.raises(InvalidRequest, match="too large"):
        sealing.verify_manifest(raw, signature, release_keys())


def test_versions_are_three_numbers_compared_as_numbers():
    assert sealing.parse_version("0.10.0") > sealing.parse_version("0.9.9")
    assert sealing.parse_version("1.0.0") > sealing.parse_version("0.99.99")
    for bad in ("", "1", "1.2", "1.2.3.4", "v1.2.3", "1.2.3 ", "1.02.3", "1.2.x", "1.2.3\n", None):
        with pytest.raises(InvalidRequest):
            sealing.parse_version(bad)


# --- configuration ---------------------------------------------------------


def test_live_refuses_to_trust_the_published_test_release_key():
    """Its private half is in the repository: anyone could sign a release with it."""
    assert RELEASE["public_key_b64"] == TEST_RELEASE_PUBLIC_KEY
    settings = live_settings(release_public_keys=[TEST_RELEASE_PUBLIC_KEY])
    assert any("published test key" in problem for problem in settings.problems())
    with pytest.raises(ConfigError, match="published test key"):
        settings.validate_for_startup()
    # In DEMO it is what the tests and the demo sign with.
    assert make_settings(release_public_keys=[TEST_RELEASE_PUBLIC_KEY]).problems() == []
    # A list in the environment is comma separated.
    assert make_settings(release_public_keys="a, b,,c").release_public_keys == ["a", "b", "c"]
