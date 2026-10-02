"""Control flow of os/image/build-iso.sh with a FAKE xorriso.

A real ISO cannot be built in the development sandbox (no xorriso, no Ubuntu
image). These tests replace xorriso with tests/os/fixtures/fake_xorriso.py,
which treats an "ISO" as a tar archive, and replace Ubuntu's signing key with
a throwaway key through a temporary versions.env. They check the ORDER and the
REFUSALS of the build script: signature on the checksum list, hash of the base
image, staging, read-back comparison, boot-setup check. They say nothing about
real xorriso behaviour or real bootability.
"""

from __future__ import annotations

import hashlib
import io
import tarfile

import pytest

from hm_os_testlib import FIXTURES, IMAGE_DIR, OS_DIR, build_stub_deb, make_stub, path_with, run

BUILD_ISO = IMAGE_DIR / "build-iso.sh"
ISO_NAME = "ubuntu-24.04.5-live-server-amd64.iso"
OUT_NAME = "happymining-os-0.1.0-ubuntu-24.04.5-amd64.iso"


def make_fake_base_iso(path, extra=b""):
    files = {
        "boot/grub/grub.cfg": (FIXTURES / "ubuntu-live-server-grub.cfg").read_bytes(),
        "md5sum.txt": b"0123456789abcdef0123456789abcdef  ./boot/grub/grub.cfg\n"
                      b"ffffffffffffffffffffffffffffffff  ./casper/vmlinuz\n",
        "casper/vmlinuz": b"fake kernel" + extra,
        "casper/initrd": b"fake initrd",
        ".fake/el_torito": b"El Torito boot img :   1  BIOS  y   none  0x0000  0x00      4         100\n"
                           b"El Torito boot img :   2  UEFI  y   none  0x0000  0x00  10000         200\n",
    }
    with tarfile.open(path, "w") as tar:
        for name, data in sorted(files.items()):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))


@pytest.fixture()
def build_env(tmp_path, release_key, other_key):
    """A complete, fake build environment. 'other_key' plays Ubuntu's CD image key."""
    bin_dir = tmp_path / "bin"
    make_stub(bin_dir, "xorriso", f'exec python3 -B "{FIXTURES}/fake_xorriso.py" "$@"\n')
    base = tmp_path / "base" / ISO_NAME
    base.parent.mkdir()
    make_fake_base_iso(base)

    sums_dir = tmp_path / "ubuntu-sums"
    sums_dir.mkdir()
    (sums_dir / "SHA256SUMS").write_text(
        f"{hashlib.sha256(base.read_bytes()).hexdigest()} *{ISO_NAME}\n"
        f"{'0' * 64} *ubuntu-24.04.5.1-desktop-amd64.iso\n")
    other_key.sign(sums_dir / "SHA256SUMS", sums_dir / "SHA256SUMS.gpg")

    versions = tmp_path / "versions.env"
    versions.write_text((OS_DIR / "versions.env").read_text()
                        + f"\n# test override: a throwaway key plays the Ubuntu CD image key\n"
                          f"UBUNTU_CDIMAGE_KEY_FPR={other_key.fingerprint}\n")

    dist = tmp_path / "dist"
    dist.mkdir()
    deb = build_stub_deb(dist)

    class Env:
        pass

    env = Env()
    env.tmp = tmp_path
    env.base = base
    env.sums_dir = sums_dir
    env.dist = dist
    env.out = dist / OUT_NAME
    env.environ = {"PATH": path_with(bin_dir), "HM_VERSIONS_FILE": str(versions)}
    env.args = [BUILD_ISO, "--dist", dist, "--agent-deb", deb, "--base-iso", base,
                "--ubuntu-sums-dir", sums_dir, "--ubuntu-keyring", other_key.pub_bin,
                "--signing-key-home", release_key.home]
    env.ubuntu_key = other_key
    return env


def leftovers(dist):
    return sorted(p.name for p in dist.iterdir() if p.name.startswith(".work") or p.name.endswith(".partial"))


def test_successful_flow_produces_the_image_and_build_info(build_env, release_key):
    out = run(build_env.args, env=build_env.environ)
    assert out.returncode == 0, out.stdout + out.stderr
    assert build_env.out.is_file()
    assert leftovers(build_env.dist) == []
    assert f"Ubuntu SHA256SUMS: good signature from {build_env.ubuntu_key.fingerprint}" in out.stdout
    assert "base ISO verified" in out.stdout

    with tarfile.open(build_env.out) as tar:
        names = set(tar.getnames())
        grub = tar.extractfile("boot/grub/grub.cfg").read().decode()
        md5 = tar.extractfile("md5sum.txt").read().decode()
        seed = tar.extractfile("happymining/seed/user-data").read().decode()
        kernel = tar.extractfile("casper/vmlinuz").read()
    # Ubuntu's files are carried over unchanged; ours are added.
    assert kernel == b"fake kernel"
    for name in ("happymining/happymining-agent_0.1.0_amd64.deb", "happymining/SHA256SUMS",
                 "happymining/SHA256SUMS.gpg", "happymining/issue", "happymining/seed/meta-data",
                 "happymining/maintenance/52happymining-unattended-upgrades", ".fake/el_torito"):
        assert name in names, name
    assert not any(n in names for n in ("autoinstall.yaml", "user-data", "meta-data"))
    assert seed == (OS_DIR / "autoinstall/user-data.generic.yaml").read_text()
    assert grub.index('menuentry "Install HappyMining OS"') < grub.index('menuentry "Try or Install Ubuntu Server"')
    for line in grub.splitlines():
        if line.strip().startswith("linux"):
            assert "autoinstall" not in line.split()
    assert hashlib.md5(grub.encode()).hexdigest() + "  ./boot/grub/grub.cfg" in md5
    assert "  ./happymining/issue" in md5 and "ffffffffffffffffffffffffffffffff  ./casper/vmlinuz" in md5

    info = (build_env.dist / (OUT_NAME + ".buildinfo")).read_text()
    assert f"base-iso: {ISO_NAME}" in info
    assert f"base-iso-sha256: {hashlib.sha256(build_env.base.read_bytes()).hexdigest()}" in info
    assert f"payload-signed-by: {release_key.fingerprint}" in info


def test_checksum_list_signed_by_another_key_is_refused(build_env, release_key):
    release_key.sign(build_env.sums_dir / "SHA256SUMS", build_env.sums_dir / "SHA256SUMS.gpg")
    args = [str(a) for a in build_env.args]
    args[args.index("--ubuntu-keyring") + 1] = str(release_key.pub_bin)
    out = run(args, env=build_env.environ)
    assert out.returncode == 3, out.stdout + out.stderr
    assert "not signed by the pinned CD image key" in out.stderr
    assert not build_env.out.exists() and leftovers(build_env.dist) == []


def test_tampered_checksum_list_is_refused(build_env):
    with open(build_env.sums_dir / "SHA256SUMS", "a") as fh:
        fh.write(f"{'1' * 64} *extra.iso\n")
    out = run(build_env.args, env=build_env.environ)
    assert out.returncode == 3
    assert not build_env.out.exists()


def test_base_image_that_does_not_match_the_signed_list_is_refused(build_env):
    make_fake_base_iso(build_env.base, extra=b" with an implant")
    out = run(build_env.args, env=build_env.environ)
    assert out.returncode == 3, out.stdout + out.stderr
    assert "sha256 MISMATCH" in out.stderr
    assert "is not the official" in out.stderr
    assert not build_env.out.exists() and leftovers(build_env.dist) == []


def test_missing_entry_for_the_pinned_file_name_is_refused(build_env):
    (build_env.sums_dir / "SHA256SUMS").write_text(f"{'0' * 64} *ubuntu-24.04.6-live-server-amd64.iso\n")
    build_env.ubuntu_key.sign(build_env.sums_dir / "SHA256SUMS", build_env.sums_dir / "SHA256SUMS.gpg")
    out = run(build_env.args, env=build_env.environ)
    assert out.returncode == 3
    assert "newer point release" in out.stderr
    assert not build_env.out.exists()


def test_lost_boot_setup_fails_the_build(build_env):
    out = run(build_env.args, env={**build_env.environ, "FAKE_XORRISO_DROP_BOOT": "1"})
    assert out.returncode == 1, out.stdout + out.stderr
    assert "boot setup was not carried over" in out.stderr
    assert not build_env.out.exists() and leftovers(build_env.dist) == []


def test_unknown_boot_menu_layout_fails_the_build(build_env):
    with tarfile.open(build_env.base, "w") as tar:
        for name, data in {"boot/grub/grub.cfg": b"set timeout=1\n", ".fake/el_torito": b"El Torito boot img : 1\n"}.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    (build_env.sums_dir / "SHA256SUMS").write_text(
        f"{hashlib.sha256(build_env.base.read_bytes()).hexdigest()} *{ISO_NAME}\n")
    build_env.ubuntu_key.sign(build_env.sums_dir / "SHA256SUMS", build_env.sums_dir / "SHA256SUMS.gpg")
    out = run(build_env.args, env=build_env.environ)
    assert out.returncode == 1
    assert "refusing to guess" in out.stderr
    assert not build_env.out.exists()


def test_missing_base_image_or_signing_choice_is_a_skip(build_env):
    args = [str(a) for a in build_env.args]
    no_iso = list(args)
    del no_iso[no_iso.index("--base-iso"):no_iso.index("--base-iso") + 2]
    out = run(no_iso, env=build_env.environ)
    assert out.returncode == 77
    assert "pass --base-iso FILE, or --download" in out.stderr

    no_key = list(args)
    del no_key[no_key.index("--signing-key-home"):no_key.index("--signing-key-home") + 2]
    out = run(no_key, env=build_env.environ)
    assert out.returncode == 77
    assert not build_env.out.exists()


def test_build_installer_reports_the_image_only_when_it_exists(build_env):
    args = [IMAGE_DIR / "build-installer.sh", *build_env.args[1:]]
    out = run(args, env=build_env.environ)
    assert out.returncode == 0, out.stdout + out.stderr
    summary = out.stdout[out.stdout.index("===== build-installer summary ====="):]
    produced, not_produced = summary.split("NOT PRODUCED:")
    assert OUT_NAME in produced and "happymining-seed-generic.tar.gz" in produced
    assert "(nothing)" in not_produced

    make_fake_base_iso(build_env.base, extra=b" tampered")
    build_env.out.unlink()
    failed = run(args, env=build_env.environ)
    assert failed.returncode == 3
    summary = failed.stdout[failed.stdout.index("===== build-installer summary ====="):]
    produced, not_produced = summary.split("NOT PRODUCED:")
    assert OUT_NAME not in produced and OUT_NAME in not_produced
