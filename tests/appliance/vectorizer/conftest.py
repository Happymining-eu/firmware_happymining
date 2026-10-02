"""Fixtures for the vectorizer tests.

The vectorizer is a stand-alone package (`appliance/vectorizer/hm_vectorizer`)
that uses the standard library only; these tests put it on `sys.path` and run
in the repository's virtualenv without any extra package. NAS sources are
temporary directories; Ollama, Qdrant and the cloud AI providers are
in-process fake servers (`vz_fakes.py`). No test needs the network or
PostgreSQL.
"""

from __future__ import annotations

import datetime
import ipaddress
import ssl
from collections.abc import Iterator
from pathlib import Path

import pytest
from vz_fakes import FakeLLM, FakeOllama, FakeQdrant
from vz_support import TOKEN, Site, base_document, vz_config  # also puts the package on sys.path


@pytest.fixture(autouse=True)
def _no_api_key_in_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(vz_config.API_KEY_ENV, raising=False)


@pytest.fixture
def ollama() -> Iterator[FakeOllama]:
    server = FakeOllama()
    yield server
    server.close()


@pytest.fixture
def qdrant() -> Iterator[FakeQdrant]:
    server = FakeQdrant()
    yield server
    server.close()


@pytest.fixture(scope="session")
def tls_files(tmp_path_factory: pytest.TempPathFactory) -> tuple[str, str]:
    """A throw-away certificate for 127.0.0.1, made with `cryptography`."""
    pytest.importorskip("cryptography")
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "vectorizer test")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.IPAddress(ipaddress.ip_address("127.0.0.1")), x509.DNSName("localhost")]
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    directory = tmp_path_factory.mktemp("tls")
    cert_path = directory / "cert.pem"
    key_path = directory / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return str(cert_path), str(key_path)


@pytest.fixture
def client_tls(tls_files: tuple[str, str]) -> ssl.SSLContext:
    """A client context that trusts only the test certificate."""
    return ssl.create_default_context(cafile=tls_files[0])


@pytest.fixture
def llm(tls_files: tuple[str, str]) -> Iterator[FakeLLM]:
    server = FakeLLM(tls_files)
    yield server
    server.close()


@pytest.fixture
def other_llm(tls_files: tuple[str, str]) -> Iterator[FakeLLM]:
    """A second HTTPS host: the one nothing must ever be sent to."""
    server = FakeLLM(tls_files)
    yield server
    server.close()


@pytest.fixture
def site(tmp_path: Path, ollama: FakeOllama, qdrant: FakeQdrant) -> Site:
    nas_root = tmp_path / "nas"
    config_dir = tmp_path / "config"
    state_dir = tmp_path / "state"
    for directory in (nas_root / "docs", config_dir, state_dir):
        directory.mkdir(parents=True)
    (config_dir / "token").write_text(TOKEN + "\n", encoding="ascii")
    made = Site(
        root=tmp_path,
        nas_root=nas_root,
        config_dir=config_dir,
        state_dir=state_dir,
        document=base_document(nas_root, ollama.url, qdrant.url),
    )
    made.save()
    return made
