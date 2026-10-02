"""Release checksums and signatures: make-checksums.sh, gen-dev-signing-key.sh
and the verification code that install.sh uses."""

from __future__ import annotations

import os
import stat

import pytest

from hm_os_testlib import INSTALL_DIR, RELEASE_DIR, REPO, build_stub_deb, run, tree_hash

MAKE = RELEASE_DIR / "make-checksums.sh"
GEN = RELEASE_DIR / "gen-dev-signing-key.sh"


def verify(keyring, sig, data, fpr=""):
    script = f'. "{INSTALL_DIR}/lib.sh"; hm_verify_detached "$1" "$2" "$3" "$4" && echo "VERIFIED $HM_SIG_FPR"'
    return run(["bash", "-c", script, "verify", keyring, sig, data, fpr])


@pytest.fixture()
def dist(tmp_path):
    directory = tmp_path / "dist"
    directory.mkdir()
    build_stub_deb(directory)
    (directory / "happymining-seed-generic.tar.gz").write_bytes(b"fake seed bundle")
    (directory / "cache").mkdir()
    (directory / "cache/ubuntu.iso").write_bytes(b"not an artifact")
    (directory / ".work-x").mkdir()
    (directory / ".work-x/scratch").write_bytes(b"scratch")
    (directory / "leftover.iso.partial").write_bytes(b"partial")
    return directory


def test_checksums_and_signature_round_trip(dist, release_key):
    out = run([MAKE, "--dist", dist, "--signing-key-home", release_key.home])
    assert out.returncode == 0, out.stdout + out.stderr
    sums = (dist / "SHA256SUMS").read_text().splitlines()
    names = [line.split("  ", 1)[1] for line in sums]
    assert names == ["happymining-agent_0.1.0_amd64.deb", "happymining-seed-generic.tar.gz"]
    check = run(["sha256sum", "-c", "SHA256SUMS"], cwd=dist)
    assert check.returncode == 0, check.stdout

    ok = verify(release_key.pub_asc, dist / "SHA256SUMS.gpg", dist / "SHA256SUMS", release_key.fingerprint)
    assert ok.returncode == 0, ok.stderr
    assert f"VERIFIED {release_key.fingerprint}" in ok.stdout
    assert "-----BEGIN PGP SIGNATURE-----" in (dist / "SHA256SUMS.gpg").read_text()


def test_signature_does_not_verify_after_tampering_or_with_another_key(dist, release_key, other_key):
    assert run([MAKE, "--dist", dist, "--signing-key-home", release_key.home]).returncode == 0
    wrong_key = verify(other_key.pub_asc, dist / "SHA256SUMS.gpg", dist / "SHA256SUMS")
    assert wrong_key.returncode != 0
    wrong_fpr = verify(release_key.pub_asc, dist / "SHA256SUMS.gpg", dist / "SHA256SUMS", other_key.fingerprint)
    assert wrong_fpr.returncode != 0
    with open(dist / "SHA256SUMS", "a") as fh:
        fh.write("0" * 64 + "  extra-file\n")
    tampered = verify(release_key.pub_asc, dist / "SHA256SUMS.gpg", dist / "SHA256SUMS")
    assert tampered.returncode != 0
    assert "BAD signature" in tampered.stderr


def test_install_sh_accepts_what_make_checksums_produced(tmp_path, dist, release_key):
    from hm_os_testlib import make_fake_root
    assert run([MAKE, "--dist", dist, "--signing-key-home", release_key.home]).returncode == 0
    root = make_fake_root(tmp_path)
    out = run([INSTALL_DIR / "install.sh", "--deb", dist / "happymining-agent_0.1.0_amd64.deb",
               "--keyring", release_key.pub_asc, "--root", root, "--dry-run"])
    assert out.returncode == 0, out.stdout + out.stderr
    assert "good signature on SHA256SUMS" in out.stdout


def test_make_checksums_dry_run_and_errors(dist, release_key, tmp_path):
    before = tree_hash(dist)
    dry = run([MAKE, "--dist", dist, "--signing-key-home", release_key.home, "--dry-run"])
    assert dry.returncode == 0
    listed = [ln.strip() for ln in dry.stdout.splitlines() if ln.startswith("  ")]
    assert listed == ["happymining-agent_0.1.0_amd64.deb", "happymining-seed-generic.tar.gz"]
    assert tree_hash(dist) == before

    assert run([MAKE, "--dist", dist]).returncode == 2
    empty = tmp_path / "empty"
    empty.mkdir()
    assert run([MAKE, "--dist", empty, "--signing-key-home", release_key.home]).returncode == 1
    no_key = tmp_path / "nokey"
    no_key.mkdir(mode=0o700)
    failed = run([MAKE, "--dist", dist, "--signing-key-home", no_key])
    assert failed.returncode == 1
    assert not (dist / "SHA256SUMS").exists()


def test_dev_signing_key_is_local_labelled_and_private(tmp_path):
    home = tmp_path / "signing"
    pub = tmp_path / "out" / "dev.pub.asc"
    before_repo = sorted(p.name for p in REPO.iterdir())
    out = run([GEN, "--signing-key-home", home, "--out-pub", pub])
    try:
        assert out.returncode == 0, out.stdout + out.stderr
        assert stat.S_IMODE(home.stat().st_mode) == 0o700
        assert "-----BEGIN PGP PUBLIC KEY BLOCK-----" in pub.read_text()
        assert "PRIVATE KEY" not in pub.read_text()
        (tmp_path / "scratch-home").mkdir(mode=0o700)
        listing = run(["gpg", "--homedir", tmp_path / "scratch-home", "--show-keys", "--with-colons", pub])
        assert "DEVELOPMENT" in listing.stdout and "NOT FOR PRODUCTION" in listing.stdout
        assert "DEVELOPMENT key" in out.stderr
        # A second run must not touch an existing signing home.
        again = run([GEN, "--signing-key-home", home, "--out-pub", pub])
        assert again.returncode == 5
        # The key can sign, and the signature verifies with the exported public key.
        dist = tmp_path / "dist"
        dist.mkdir()
        (dist / "artifact.bin").write_bytes(os.urandom(64))
        signed = run([MAKE, "--dist", dist, "--signing-key-home", home])
        assert signed.returncode == 0, signed.stderr
        assert "DEVELOPMENT key" in signed.stderr
        assert verify(pub, dist / "SHA256SUMS.gpg", dist / "SHA256SUMS").returncode == 0
    finally:
        run(["gpgconf", "--homedir", home, "--kill", "all"])
        run(["gpgconf", "--homedir", tmp_path / "scratch-home", "--kill", "all"])
    # Nothing was created in the repository (default locations were not used).
    assert sorted(p.name for p in REPO.iterdir()) == before_repo


def test_dev_key_dry_run_creates_nothing(tmp_path):
    home = tmp_path / "signing"
    out = run([GEN, "--signing-key-home", home, "--out-pub", tmp_path / "pub.asc", "--dry-run"])
    assert out.returncode == 0
    assert "DRY-RUN would run: gpg" in out.stdout
    assert not home.exists() and not (tmp_path / "pub.asc").exists()


def test_default_dev_key_location_is_outside_version_control():
    text = GEN.read_text()
    assert 'SIGN_HOME="$REPO_DIR/.signing"' in text
    assert "NOT FOR PRODUCTION" in text
