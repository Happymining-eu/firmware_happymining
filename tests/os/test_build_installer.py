"""build-installer.sh / build-iso.sh in a sandbox without xorriso or a base ISO:
the seed bundle is always built, the ISO is honestly reported as not built."""

from __future__ import annotations

import shutil
import tarfile

import pytest

from hm_os_testlib import AUTOINSTALL_DIR, IMAGE_DIR, REPO, build_stub_deb, run, tree_hash

BUILD = IMAGE_DIR / "build-installer.sh"
BUILD_ISO = IMAGE_DIR / "build-iso.sh"
HAVE_XORRISO = shutil.which("xorriso") is not None


def test_allow_partial_builds_the_seed_bundle_and_reports_the_iso_as_not_built(tmp_path, versions):
    dist = tmp_path / "dist"
    out = run([BUILD, "--dist", dist, "--allow-partial"])
    assert out.returncode == 0, out.stdout + out.stderr
    bundle = dist / "happymining-seed-generic.tar.gz"
    assert bundle.is_file()

    summary = out.stdout[out.stdout.index("===== build-installer summary ====="):]
    produced, not_produced = summary.split("NOT PRODUCED:")
    assert "happymining-seed-generic.tar.gz" in produced
    assert f"happymining-install-scripts-{versions['AGENT_VERSION']}.tar.gz" in produced
    assert ".iso" not in produced
    iso_name = f"happymining-os-{versions['AGENT_VERSION']}-ubuntu-{versions['UBUNTU_POINT_RELEASE']}-amd64.iso"
    assert iso_name in not_produced
    assert "not attempted" in not_produced
    assert "NOT built" in out.stderr
    assert not list(dist.glob("*.iso"))
    # No work directory is left behind.
    assert sorted(p.name for p in dist.iterdir()) == [
        f"happymining-install-scripts-{versions['AGENT_VERSION']}.tar.gz", "happymining-seed-generic.tar.gz"]

    with tarfile.open(bundle) as tar:
        names = sorted(tar.getnames())
        assert names == ["happymining-seed-generic", "happymining-seed-generic/README.txt",
                         "happymining-seed-generic/meta-data", "happymining-seed-generic/user-data"]
        user_data = tar.extractfile("happymining-seed-generic/user-data").read().decode()
        for member in tar.getmembers():
            assert member.uid == 0 and member.gid == 0
    assert user_data == (AUTOINSTALL_DIR / "user-data.generic.yaml").read_text()
    check = run(["python3", AUTOINSTALL_DIR / "validate.py", "--kind", "generic", "--file", "-"], input=user_data)
    assert check.returncode == 0


def test_without_allow_partial_the_exit_code_is_77(tmp_path):
    dist = tmp_path / "dist"
    out = run([BUILD, "--dist", dist])
    assert out.returncode == 77, out.stdout + out.stderr
    assert (dist / "happymining-seed-generic.tar.gz").is_file()
    assert "prerequisite not available" in out.stderr
    assert not list(dist.glob("*.iso"))


def test_bundles_are_reproducible(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    assert run([BUILD, "--dist", a, "--allow-partial"]).returncode == 0
    assert run([BUILD, "--dist", b, "--allow-partial"]).returncode == 0
    for name in ("happymining-seed-generic.tar.gz", "happymining-install-scripts-0.1.0.tar.gz"):
        assert (a / name).read_bytes() == (b / name).read_bytes(), name


def test_install_scripts_bundle_is_self_contained(tmp_path, release_dir, release_key, fake_root):
    dist = tmp_path / "dist"
    assert run([BUILD, "--dist", dist, "--allow-partial"]).returncode == 0
    with tarfile.open(dist / "happymining-install-scripts-0.1.0.tar.gz") as tar:
        tar.extractall(tmp_path / "unpacked", filter="data")
    bundle = tmp_path / "unpacked/happymining-install-scripts-0.1.0"
    names = sorted(p.name for p in bundle.iterdir())
    for needed in ("install.sh", "upgrade.sh", "uninstall.sh", "lib.sh", "forbidden-commands.txt", "versions.env",
                   "nvidia-driver-plan.sh", "sanitize-clone.sh", "apply-patch-policy.sh"):
        assert needed in names
    out = run([bundle / "install.sh", "--deb", release_dir / "happymining-agent_0.1.0_amd64.deb",
               "--keyring", release_key.pub_asc, "--root", fake_root, "--dry-run"])
    assert out.returncode == 0, out.stdout + out.stderr
    assert run([bundle / "sanitize-clone.sh", "--help"]).returncode == 0
    assert run([bundle / "apply-patch-policy.sh", "--root", fake_root, "--dry-run"]).returncode == 0


def test_dry_run_writes_nothing(tmp_path):
    dist = tmp_path / "dist"
    out = run([BUILD, "--dist", dist, "--allow-partial", "--dry-run"])
    assert out.returncode == 0, out.stdout + out.stderr
    assert "DRY RUN: no artifact was produced." in out.stdout
    assert not dist.exists()


def test_invalid_autoinstall_file_stops_the_build(tmp_path):
    """A copy of os/ whose generic seed selects a disk must not produce any artifact."""
    work = tmp_path / "repo"
    shutil.copytree(REPO / "os", work / "os")
    seed = work / "os/autoinstall/user-data.generic.yaml"
    seed.write_text(seed.read_text().replace("  version: 1\n", "  version: 1\n  storage:\n    layout:\n      name: lvm\n", 1))
    out = run([work / "os/image/build-installer.sh", "--dist", tmp_path / "dist", "--allow-partial"])
    assert out.returncode == 1, out.stdout + out.stderr
    assert "INVALID" in out.stdout
    assert not (tmp_path / "dist").exists()


@pytest.mark.skipif(HAVE_XORRISO, reason="xorriso is installed; this test covers the missing-tool path")
def test_build_iso_exits_77_with_a_clear_message_when_xorriso_is_missing(tmp_path, release_key):
    dist = tmp_path / "dist"
    dist.mkdir()
    deb = build_stub_deb(dist)
    before = tree_hash(dist)
    out = run([BUILD_ISO, "--dist", dist, "--agent-deb", deb, "--signing-key-home", release_key.home,
               "--base-iso", tmp_path / "missing.iso"])
    assert out.returncode == 77, out.stdout + out.stderr
    assert "prerequisite not available: 'xorriso'" in out.stderr
    assert tree_hash(dist) == before


def test_build_iso_dry_run_shows_the_repack_and_the_verification_chain(tmp_path, versions):
    out = run([BUILD_ISO, "--dry-run", "--dist", tmp_path / "dist", "--allow-unsigned-dev"])
    assert out.returncode == 0, out.stdout + out.stderr
    text = out.stdout
    assert versions["UBUNTU_SUMS_URL"] in text and versions["UBUNTU_SUMS_SIG_URL"] in text
    assert versions["UBUNTU_CDIMAGE_KEY_FPR"] in text
    assert "-boot_image any replay" in text
    assert "-map '<work>/tree/happymining' /happymining" in text
    assert "/boot/grub/grub.cfg" in text
    repack = next(ln for ln in text.splitlines() if "-boot_image" in ln)
    assert "autoinstall" not in repack and "squashfs" not in repack
    assert not (tmp_path / "dist").exists()


def test_build_iso_never_stores_or_accepts_an_unverified_iso():
    text = BUILD_ISO.read_text()
    # The ISO is checked against the signed list under the PINNED file name,
    # and the list is checked against the pinned key, before anything is built.
    verify_sig = text.index('hm_verify_detached "$UBUNTU_KEYRING" "$SUMS_SIG" "$SUMS" "$UBUNTU_CDIMAGE_KEY_FPR"')
    verify_iso = text.index('hm_verify_sums_entry "$SUMS" "$BASE_ISO" "$UBUNTU_ISO_FILENAME"')
    repack = text.index("-boot_image any replay \\")
    assert verify_sig < verify_iso < repack
    assert "squashfs" not in text.replace("The squashfs", "")


@pytest.mark.skipif(not HAVE_XORRISO, reason="xorriso not installed: the ISO cannot be built in this environment")
def test_build_iso_real_build_needs_a_base_iso():  # pragma: no cover - needs a build host
    pytest.skip("a real ISO build needs the 3.8 GB Ubuntu base ISO; run os/image/build-installer.sh on a build host")
