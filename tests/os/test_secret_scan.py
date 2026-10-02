"""secret_scan.py: every kind of planted secret is found; the trees that are
actually distributed are clean."""

from __future__ import annotations

import shutil

import pytest

from hm_os_testlib import AUTOINSTALL_DIR, IMAGE_DIR, INSTALL_DIR, OS_DIR, build_stub_deb, make_ed25519_pubkey_line, run

SCAN = IMAGE_DIR / "secret_scan.py"

# None of these is a real credential; they only have the shape of one.
PLANTED = {
    "openssh private key": ("keys/deploy", "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----\n"),
    "rsa private key": ("tls/server.pem", "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----\n"),
    "pgp private key": ("signing.asc", "-----BEGIN PGP PRIVATE KEY BLOCK-----\n\nlQOYBF\n-----END PGP PRIVATE KEY BLOCK-----\n"),
    "password hash": ("seed/user-data", "#cloud-config\nusers:\n  - name: x\n    passwd: $6$rounds=4096$saltsaltsalt$" + "h" * 86 + "\n"),
    "yescrypt hash": ("shadow", "admin:$y$j9T$abcdefghijklmnopqrstuv$" + "Z" * 43 + ":19000:0:99999:7:::\n"),
    "plain password field": ("seed/user-data", "#cloud-config\npassword: correct-horse-battery\n"),
    "chpasswd": ("seed/user-data", "#cloud-config\nchpasswd:\n  expire: false\n"),
    "device token": ("etc/credential.txt", "token=hmd_0123456789abcdef0123456789abcdef.AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-abcde\n"),
    "pairing code": ("notes.txt", "pair with HM-7K2M9Q-4F8T-ZP3D-W6NH-R5XA today\n"),
    "vast api key assignment": ("env", "VAST_API_KEY=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n"),
    "vastai set api-key": ("setup.sh", "vastai set api-key 0123456789abcdef0123456789abcdef0123456789abcdef\n"),
    "vast key file": (".vast_api_key", "anything\n"),
    "authorized_keys content": ("home/authorized_keys.bak", make_ed25519_pubkey_line("someone@example.invalid") + "\n"),
    "authorized_keys file": ("root/.ssh/authorized_keys", "\n"),
    "ssh private key file name": ("root/.ssh/id_ed25519", "\n"),
    "device credential file": ("var/lib/happymining/credential.json", "{}\n"),
    "gnupg private keys": ("gnupg/private-keys-v1.d/ABCD.key", "\n"),
}


@pytest.mark.parametrize("name", sorted(PLANTED))
def test_planted_secret_is_found(tmp_path, name):
    rel, content = PLANTED[name]
    tree = tmp_path / "tree"
    target = tree / rel
    target.parent.mkdir(parents=True)
    target.write_text(content)
    (tree / "README.txt").write_text("harmless\n")
    out = run(["python3", SCAN, tree])
    assert out.returncode == 1, f"{name}: not found\n{out.stdout}"
    assert "SECRET FOUND" in out.stdout
    assert str(target) in out.stdout or str(target.parent) in out.stdout


def test_findings_are_redacted(tmp_path):
    tree = tmp_path / "tree"
    tree.mkdir()
    secret = "hmd_0123456789abcdef0123456789abcdef.SuperSecretPartThatMustNotBePrinted00000000"
    (tree / "f").write_text(secret + "\n")
    out = run(["python3", SCAN, tree])
    assert out.returncode == 1
    assert "SuperSecretPartThatMustNotBePrinted" not in out.stdout + out.stderr


def test_secret_in_a_large_binary_file_is_found(tmp_path):
    tree = tmp_path / "tree"
    tree.mkdir()
    blob = b"\x00" * (5 * 1024 * 1024) + b"-----BEGIN OPENSSH PRIVATE KEY-----" + b"\xff" * 1024
    (tree / "blob.bin").write_bytes(blob)
    assert run(["python3", SCAN, tree]).returncode == 1


def test_symlinks_are_reported_not_followed(tmp_path):
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "link").symlink_to("/etc/hostname")
    out = run(["python3", SCAN, tree])
    assert out.returncode == 1
    assert "symbolic link" in out.stdout


def test_clean_tree_passes(tmp_path):
    tree = tmp_path / "tree"
    (tree / "seed").mkdir(parents=True)
    shutil.copy(AUTOINSTALL_DIR / "user-data.generic.yaml", tree / "seed/user-data")
    shutil.copy(AUTOINSTALL_DIR / "meta-data.generic", tree / "seed/meta-data")
    shutil.copy(IMAGE_DIR / "branding/issue", tree / "issue")
    (tree / "SHA256SUMS").write_text("a" * 64 + "  seed/user-data\n" + "b" * 64 + "  issue\n")
    out = run(["python3", SCAN, tree])
    assert out.returncode == 0, out.stdout
    assert "clean" in out.stdout


def test_everything_that_goes_into_the_image_or_the_bundles_is_clean():
    out = run(["python3", SCAN, AUTOINSTALL_DIR / "user-data.generic.yaml", AUTOINSTALL_DIR / "meta-data.generic",
               IMAGE_DIR / "branding", OS_DIR / "maintenance", INSTALL_DIR, OS_DIR / "firstboot",
               OS_DIR / "versions.env"])
    assert out.returncode == 0, out.stdout


def test_staged_iso_payload_is_clean_and_complete(tmp_path, release_key):
    """build-iso.sh --stage-only assembles exactly the /happymining tree of the
    medium (no base ISO or xorriso needed) and scans it."""
    dist = tmp_path / "dist"
    dist.mkdir()
    deb = build_stub_deb(dist)
    stage = tmp_path / "stage"
    out = run([IMAGE_DIR / "build-iso.sh", "--stage-only", stage, "--agent-deb", deb, "--dist", dist,
               "--signing-key-home", release_key.home])
    assert out.returncode == 0, out.stdout + out.stderr
    payload = stage / "happymining"
    files = sorted(str(p.relative_to(payload)) for p in payload.rglob("*") if p.is_file())
    assert files == [
        "README.txt", "SHA256SUMS", "SHA256SUMS.gpg", "happymining-agent_0.1.0_amd64.deb", "issue",
        "maintenance/52happymining-unattended-upgrades", "maintenance/needrestart-happymining.conf",
        "seed/meta-data", "seed/user-data",
    ]
    assert run(["sha256sum", "--quiet", "-c", "SHA256SUMS"], cwd=payload).returncode == 0
    listed = [ln.split("  ", 1)[1] for ln in (payload / "SHA256SUMS").read_text().splitlines()]
    assert sorted(listed) == [f for f in files if not f.startswith("SHA256SUMS")]
    verify = run(["bash", "-c", f'. "{INSTALL_DIR}/lib.sh"; hm_verify_detached "$1" "$2" "$3" "$4"', "v",
                  release_key.pub_asc, payload / "SHA256SUMS.gpg", payload / "SHA256SUMS", release_key.fingerprint])
    assert verify.returncode == 0, verify.stderr
    assert run(["python3", SCAN, stage]).returncode == 0
    assert (payload / "seed/user-data").read_text() == (AUTOINSTALL_DIR / "user-data.generic.yaml").read_text()
    # A per-machine seed can never be part of it.
    assert not list(payload.rglob("*.tmpl"))
    for path in payload.rglob("*"):
        if path.is_file() and path.suffix != ".deb":
            text = path.read_text(errors="replace")
            assert "/dev/disk/by-id/" not in text, path
            assert "ssh_authorized_keys" not in text, path
            assert "happymining-disk-guard" not in text, path


def test_stage_only_refuses_without_a_signing_choice(tmp_path):
    dist = tmp_path / "dist"
    dist.mkdir()
    deb = build_stub_deb(dist)
    out = run([IMAGE_DIR / "build-iso.sh", "--stage-only", tmp_path / "stage", "--agent-deb", deb, "--dist", dist])
    assert out.returncode == 77
    assert not (tmp_path / "stage").exists()
    dev = run([IMAGE_DIR / "build-iso.sh", "--stage-only", tmp_path / "stage", "--agent-deb", deb, "--dist", dist,
               "--allow-unsigned-dev"])
    assert dev.returncode == 0
    assert "UNSIGNED DEVELOPMENT BUILD" in dev.stderr
    assert not (tmp_path / "stage/happymining/SHA256SUMS.gpg").exists()


def test_secret_inside_the_agent_package_stops_the_staging(tmp_path, release_key):
    """The .deb is compressed; the build unpacks it and scans the contents."""
    dist = tmp_path / "dist"
    pkg = dist / "pkgroot"
    (pkg / "DEBIAN").mkdir(parents=True)
    (pkg / "etc/happymining").mkdir(parents=True)
    (pkg / "DEBIAN/control").write_text(
        "Package: happymining-agent\nVersion: 0.1.0\nArchitecture: amd64\n"
        "Maintainer: Test <test@example.invalid>\nDescription: stub with a baked-in credential\n")
    (pkg / "etc/happymining/agent.env").write_text(
        "HM_DEVICE_TOKEN=hmd_0123456789abcdef0123456789abcdef.AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-abcde\n")
    deb = dist / "happymining-agent_0.1.0_amd64.deb"
    assert run(["dpkg-deb", "--root-owner-group", "--build", pkg, deb]).returncode == 0
    shutil.rmtree(pkg)
    out = run([IMAGE_DIR / "build-iso.sh", "--stage-only", tmp_path / "stage", "--agent-deb", deb, "--dist", dist,
               "--signing-key-home", release_key.home])
    assert out.returncode == 1, out.stdout + out.stderr
    assert "secrets found inside the agent package" in out.stderr
    assert "HappyMining device token" in out.stdout
    assert not (tmp_path / "stage").exists()
