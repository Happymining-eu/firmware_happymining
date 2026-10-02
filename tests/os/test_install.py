"""install.sh, upgrade.sh and uninstall.sh on a fake system root.

The package database of the fake root is a real dpkg database (dpkg --root),
so "installed" really means installed by dpkg. The agent package is a stub
built with dpkg-deb, signed with a throwaway key made in a temporary GnuPG home.
"""

from __future__ import annotations

import os
import shutil
import stat
import tempfile
from pathlib import Path

import pytest

from hm_os_testlib import (
    INSTALL_DIR,
    THIRD_PARTY_FILES,
    build_stub_deb,
    file_hashes,
    make_fake_root,
    run,
    tree_hash,
    write_sums,
)

INSTALL = INSTALL_DIR / "install.sh"
UPGRADE = INSTALL_DIR / "upgrade.sh"
UNINSTALL = INSTALL_DIR / "uninstall.sh"


def installed_version(root: Path) -> str:
    out = run(["dpkg-query", f"--admindir={root}/var/lib/dpkg", "-W", "-f=${db:Status-Abbrev}|${Version}",
               "happymining-agent"])
    if out.returncode != 0 or not out.stdout.startswith("ii "):
        return ""
    return out.stdout.split("|", 1)[1]


def need_root():
    if os.geteuid() != 0:
        pytest.skip("a real dpkg installation into the fake root needs root privileges")


def install(root, deb, key, *extra, env=None, input=None):
    if "--dry-run" not in extra:
        need_root()
    cmd = [INSTALL, "--deb", deb, "--root", root, *extra]
    if key is not None:
        cmd += ["--keyring", key]
    return run(cmd, env=env, input=input)


# ----- dry run ----------------------------------------------------------------
def test_dry_run_changes_nothing(fake_root, stub_deb, release_key):
    before = tree_hash(fake_root)
    out = install(fake_root, stub_deb, release_key.pub_asc, "--dry-run", "--api-url", "https://api.happymining.fr")
    assert out.returncode == 0, out.stdout + out.stderr
    assert tree_hash(fake_root) == before, "the dry run changed the fake root"
    assert installed_version(fake_root) == ""
    assert "DRY-RUN would run: dpkg" in out.stdout
    dpkg_line = next(ln for ln in out.stdout.splitlines() if ln.startswith("DRY-RUN would run: dpkg"))
    assert f"--root={fake_root}" in dpkg_line and dpkg_line.endswith(f"-i {stub_deb}")
    assert "DRY-RUN would set in" in out.stdout
    assert "DRY RUN complete: nothing was changed" in out.stdout
    # The read-only checks really ran.
    assert "good signature on SHA256SUMS" in out.stdout
    assert "PASS    Operating system" in out.stdout


def test_dry_run_reports_existing_docker_and_vast(fake_root, stub_deb, release_key):
    out = install(fake_root, stub_deb, release_key.pub_asc, "--dry-run")
    assert "existing Docker installation detected" in out.stdout
    assert "existing Vast host software detected" in out.stdout
    assert "left exactly as it is" in out.stdout


# ----- authenticity ---------------------------------------------------------------
def test_refuses_unsigned_package_by_default(tmp_path, fake_root):
    directory = tmp_path / "unsigned"
    directory.mkdir()
    deb = build_stub_deb(directory)
    before = tree_hash(fake_root / "usr")
    out = install(fake_root, deb, None, "--yes")
    assert out.returncode == 3, out.stdout + out.stderr
    assert "no SHA256SUMS" in out.stderr
    assert installed_version(fake_root) == ""
    assert tree_hash(fake_root / "usr") == before


def test_refuses_checksums_without_signature(tmp_path, fake_root, release_key):
    directory = tmp_path / "nosig"
    directory.mkdir()
    deb = build_stub_deb(directory)
    write_sums(directory, None)
    out = install(fake_root, deb, release_key.pub_asc, "--yes")
    assert out.returncode == 3
    assert "unsigned package" in out.stderr
    assert installed_version(fake_root) == ""


def test_refuses_signature_without_keyring(fake_root, stub_deb):
    out = install(fake_root, stub_deb, None, "--yes")
    assert out.returncode == 3
    assert "--keyring FILE is required" in out.stderr
    assert installed_version(fake_root) == ""


@pytest.mark.parametrize("armoured", [True, False])
def test_good_signature_is_verified_and_package_installed(fake_root, stub_deb, release_key, armoured):
    keyring = release_key.pub_asc if armoured else release_key.pub_bin
    out = install(fake_root, stub_deb, keyring, "--yes")
    assert out.returncode == 0, out.stdout + out.stderr
    assert f"good signature on SHA256SUMS from key {release_key.fingerprint}" in out.stdout
    assert installed_version(fake_root) == "0.1.0"
    assert (fake_root / "usr/bin/happyminingctl").is_file()
    assert "sudo happyminingctl pair" in out.stdout
    assert "happyminingctl vast-enroll-help" in out.stdout
    log = (fake_root / "var/log/happymining/install.log").read_text()
    assert "install started" in log and "good signature" in log


def test_expected_fingerprint_is_enforced(fake_root, stub_deb, release_key, other_key):
    wrong = install(fake_root, stub_deb, release_key.pub_asc, "--yes", "--expect-fingerprint", other_key.fingerprint)
    assert wrong.returncode == 3
    assert installed_version(fake_root) == ""
    right = install(fake_root, stub_deb, release_key.pub_asc, "--yes", "--expect-fingerprint",
                    release_key.fingerprint)
    assert right.returncode == 0, right.stderr


def test_signature_from_an_untrusted_key_is_rejected(fake_root, stub_deb, other_key):
    out = install(fake_root, stub_deb, other_key.pub_asc, "--yes")
    assert out.returncode == 3
    assert "could not be verified" in out.stderr
    assert installed_version(fake_root) == ""


def test_tampered_package_is_rejected(fake_root, stub_deb, release_key):
    with open(stub_deb, "ab") as fh:
        fh.write(b"\x00tampered")
    out = install(fake_root, stub_deb, release_key.pub_asc, "--yes")
    assert out.returncode == 3, out.stdout + out.stderr
    assert "sha256 MISMATCH" in out.stderr
    assert installed_version(fake_root) == ""


def test_tampered_package_is_rejected_even_in_unsigned_dev_mode(fake_root, stub_deb):
    with open(stub_deb, "ab") as fh:
        fh.write(b"\x00tampered")
    out = install(fake_root, stub_deb, None, "--yes", "--allow-unsigned-dev")
    assert out.returncode == 3
    assert installed_version(fake_root) == ""


def test_tampered_checksum_list_is_rejected(release_dir, fake_root, stub_deb, release_key):
    with open(stub_deb, "ab") as fh:
        fh.write(b"\x00tampered")
    # The attacker also fixes SHA256SUMS, but cannot re-sign it.
    import hashlib
    (release_dir / "SHA256SUMS").write_text(
        f"{hashlib.sha256(stub_deb.read_bytes()).hexdigest()}  {stub_deb.name}\n")
    out = install(fake_root, stub_deb, release_key.pub_asc, "--yes")
    assert out.returncode == 3
    assert "BAD signature" in out.stderr or "could not be verified" in out.stderr
    assert installed_version(fake_root) == ""


def test_unsigned_dev_mode_warns_loudly(tmp_path, fake_root):
    directory = tmp_path / "dev"
    directory.mkdir()
    deb = build_stub_deb(directory)
    out = install(fake_root, deb, None, "--yes", "--allow-unsigned-dev")
    assert out.returncode == 0, out.stderr
    assert "UNSIGNED DEVELOPMENT INSTALL" in out.stderr
    assert "!!!!!!!!" in out.stderr
    assert "UNSIGNED DEVELOPMENT INSTALL" in (fake_root / "var/log/happymining/install.log").read_text()
    assert installed_version(fake_root) == "0.1.0"


def test_only_the_agent_package_is_accepted(tmp_path, fake_root, release_key):
    directory = tmp_path / "other"
    directory.mkdir()
    deb = build_stub_deb(directory, package="docker-ce")
    write_sums(directory, release_key)
    out = install(fake_root, deb, release_key.pub_asc, "--yes")
    assert out.returncode == 5
    assert "nothing else" in out.stderr


# ----- preflight gate ----------------------------------------------------------------
def test_preflight_runs_from_the_unpacked_package_before_anything_is_installed(tmp_path, fake_root, stub_deb,
                                                                                release_key):
    log = tmp_path / "ctl.log"
    out = install(fake_root, stub_deb, release_key.pub_asc, "--yes",
                  env={"HM_STUB_PREFLIGHT_RC": "1", "HM_STUB_LOG": str(log)})
    assert out.returncode == 4, out.stdout + out.stderr
    assert log.read_text() == "happyminingctl preflight\n"
    assert "FAIL    NVIDIA GPU" in out.stdout
    assert installed_version(fake_root) == ""
    assert not (fake_root / "usr/bin/happyminingctl").exists()
    assert not (fake_root / "var/cache/happymining").exists()


def test_force_preflight_continues_and_is_recorded(fake_root, stub_deb, release_key):
    out = install(fake_root, stub_deb, release_key.pub_asc, "--yes", "--force-preflight",
                  env={"HM_STUB_PREFLIGHT_RC": "1"})
    assert out.returncode == 0, out.stdout + out.stderr
    assert installed_version(fake_root) == "0.1.0"
    log = (fake_root / "var/log/happymining/install.log").read_text()
    assert "OVERRIDE: --force-preflight used" in log
    assert "force-preflight=1" in log


def test_a_crashing_preflight_is_never_overridable(fake_root, stub_deb, release_key):
    out = install(fake_root, stub_deb, release_key.pub_asc, "--yes", "--force-preflight",
                  env={"HM_STUB_PREFLIGHT_RC": "7"})
    assert out.returncode == 1
    assert installed_version(fake_root) == ""


def test_unsupported_ubuntu_release_counts_as_preflight_fail(tmp_path, stub_deb, release_key):
    root = make_fake_root(tmp_path, ubuntu_version="20.04")
    out = install(root, stub_deb, release_key.pub_asc, "--yes")
    assert out.returncode == 4
    assert "not in the supported list" in out.stderr
    assert installed_version(root) == ""


def test_other_distributions_are_refused(tmp_path, stub_deb, release_key):
    root = make_fake_root(tmp_path, os_id="debian", ubuntu_version="12")
    out = install(root, stub_deb, release_key.pub_asc, "--yes", "--force-preflight")
    assert out.returncode == 5
    assert installed_version(root) == ""


# ----- existing Docker / Vast / NVIDIA installation -----------------------------------
def test_existing_docker_and_vast_installation_is_untouched(fake_root, stub_deb, release_key):
    third_party = [fake_root / rel for rel in THIRD_PARTY_FILES]
    before = file_hashes(third_party)
    modes = {str(p): (p.stat().st_mode, p.stat().st_mtime_ns) for p in third_party}
    docker_tree = tree_hash(fake_root / "var/lib/docker")
    vast_tree = tree_hash(fake_root / "var/lib/vastai_kaalia")

    out = install(fake_root, stub_deb, release_key.pub_asc, "--yes", "--api-url", "https://api.happymining.fr")
    assert out.returncode == 0, out.stdout + out.stderr
    assert installed_version(fake_root) == "0.1.0"

    assert file_hashes(third_party) == before
    assert {str(p): (p.stat().st_mode, p.stat().st_mtime_ns) for p in third_party} == modes
    assert tree_hash(fake_root / "var/lib/docker") == docker_tree
    assert tree_hash(fake_root / "var/lib/vastai_kaalia") == vast_tree
    assert "verified: Docker, Vast software, NVIDIA drivers, kernels, mounts and network files are unchanged" in out.stdout
    # Only expected locations were written.
    new_top = sorted(p.name for p in (fake_root / "var").iterdir())
    assert new_top == ["cache", "lib", "log"]
    assert sorted(p.name for p in (fake_root / "etc").iterdir()) == [
        "apt", "docker", "fstab", "happymining", "netplan", "os-release", "systemd"]


def test_no_external_mutating_tool_is_called(tmp_path, fake_root, stub_deb, release_key):
    """Poisoned stand-ins for every tool the installer must never run are put
    first on PATH; the installation must succeed without touching them."""
    bin_dir = tmp_path / "poison"
    bin_dir.mkdir()
    marker = tmp_path / "poison-called"
    for name in ("apt-get", "apt", "snap", "parted", "sgdisk", "wipefs", "mkfs", "mkfs.ext4", "mkfs.xfs", "fdisk",
                 "sfdisk", "dd", "mount", "umount", "reboot", "shutdown", "docker", "ufw", "iptables", "nft",
                 "netplan", "modprobe", "ubuntu-drivers", "update-grub", "lvremove", "vgremove", "pvcreate",
                 "zpool", "mdadm", "systemctl"):
        tool = bin_dir / name
        tool.write_text(f"#!/bin/sh\necho \"{name} $*\" >> '{marker}'\nexit 0\n")
        tool.chmod(0o755)
    out = install(fake_root, stub_deb, release_key.pub_asc, "--yes",
                  env={"PATH": f"{bin_dir}:{os.environ['PATH']}"})
    assert out.returncode == 0, out.stdout + out.stderr
    assert not marker.exists(), f"forbidden tool was called: {marker.read_text() if marker.exists() else ''}"


def test_system_dpkg_log_is_not_written_for_an_alternate_root(fake_root, stub_deb, release_key):
    """dpkg --root still uses the host's log path unless told otherwise; the
    scripts must redirect it into the alternate root."""
    system_log = Path("/var/log/dpkg.log")
    before = system_log.stat().st_size if system_log.exists() else None
    assert install(fake_root, stub_deb, release_key.pub_asc, "--yes").returncode == 0
    assert run([UNINSTALL, "--root", fake_root, "--yes"]).returncode == 0
    after = system_log.stat().st_size if system_log.exists() else None
    assert after == before, "the host's /var/log/dpkg.log was written by a fake-root run"
    assert "happymining-agent" in (fake_root / "var/log/dpkg.log").read_text()


# ----- API URL -------------------------------------------------------------------------
def test_api_url_is_written_when_unset(fake_root, stub_deb, release_key):
    out = install(fake_root, stub_deb, release_key.pub_asc, "--yes", "--api-url", "https://api.example.invalid")
    assert out.returncode == 0, out.stderr
    assert (fake_root / "etc/happymining/agent.env").read_text() == "HM_API_URL=https://api.example.invalid\n"


def test_api_url_is_not_written_without_the_option(fake_root, stub_deb, release_key):
    assert install(fake_root, stub_deb, release_key.pub_asc, "--yes").returncode == 0
    assert not (fake_root / "etc/happymining/agent.env").exists()


def test_api_url_set_by_an_operator_is_never_replaced(fake_root, stub_deb, release_key):
    env_file = fake_root / "etc/happymining/agent.env"
    env_file.parent.mkdir(parents=True)
    env_file.write_text("# site settings\nHM_API_URL=https://operator-choice.example.invalid\n")
    out = install(fake_root, stub_deb, release_key.pub_asc, "--yes", "--api-url", "https://api.example.invalid")
    assert out.returncode == 0, out.stderr
    assert env_file.read_text() == "# site settings\nHM_API_URL=https://operator-choice.example.invalid\n"
    assert "leaving it unchanged" in out.stdout


def test_api_url_replaces_the_default_shipped_in_the_package(tmp_path, fake_root, release_key):
    directory = tmp_path / "withenv"
    directory.mkdir()
    deb = build_stub_deb(directory, with_env_default=True)
    write_sums(directory, release_key)
    out = install(fake_root, deb, release_key.pub_asc, "--yes", "--api-url", "https://api.example.invalid")
    assert out.returncode == 0, out.stdout + out.stderr
    assert (fake_root / "etc/happymining/agent.env").read_text() == (
        "# stub default\nHM_API_URL=https://api.example.invalid\n#HM_LOG_LEVEL=info\n")


@pytest.mark.parametrize("url", ["http://api.example.invalid", "ftp://x", "https://", "https://a b", "javascript:1",
                                 "https://x.invalid/$(id)", "https://x.invalid/;id"])
def test_bad_api_urls_are_usage_errors(fake_root, stub_deb, release_key, url):
    out = install(fake_root, stub_deb, release_key.pub_asc, "--yes", "--api-url", url)
    assert out.returncode == 2
    assert installed_version(fake_root) == ""


# ----- confirmation and privileges ---------------------------------------------------------
def test_confirmation_is_required_without_yes(fake_root, stub_deb, release_key):
    declined = install(fake_root, stub_deb, release_key.pub_asc, input="no\n")
    assert declined.returncode == 5
    assert installed_version(fake_root) == ""
    accepted = install(fake_root, stub_deb, release_key.pub_asc, input="yes\n")
    assert accepted.returncode == 0, accepted.stderr
    assert installed_version(fake_root) == "0.1.0"


@pytest.mark.skipif(os.geteuid() != 0, reason="needs root to drop privileges for the check")
def test_refuses_to_run_without_root_except_for_a_dry_run(release_key):
    # /tmp on purpose: the directory must be reachable by an unprivileged user.
    base = Path(tempfile.mkdtemp(prefix="hm-nonroot-", dir="/tmp"))
    try:
        os.chmod(base, 0o755)
        root = make_fake_root(base)
        build_stub_deb(base)
        write_sums(base, release_key)
        shutil.copy(release_key.pub_asc, base / "key.asc")
        for path in [base, *base.rglob("*")]:
            mode = path.stat().st_mode
            os.chmod(path, mode | stat.S_IROTH | (stat.S_IXOTH if path.is_dir() or mode & 0o100 else 0))
        deb = base / "happymining-agent_0.1.0_amd64.deb"

        def as_nobody(*extra):
            import subprocess
            return subprocess.run(
                [str(INSTALL), "--deb", str(deb), "--keyring", str(base / "key.asc"), "--root", str(root), *extra],
                capture_output=True, text=True, user=65534, group=65534, extra_groups=[], cwd="/",
                env={"PATH": os.environ["PATH"], "HOME": "/nonexistent", "TMPDIR": "/tmp"})

        before = tree_hash(root)
        real = as_nobody("--yes")
        assert real.returncode == 5, real.stdout + real.stderr
        assert "must run as root" in real.stderr
        dry = as_nobody("--dry-run")
        assert dry.returncode == 0, dry.stdout + dry.stderr
        assert "not running as root" in dry.stderr
        assert tree_hash(root) == before
    finally:
        shutil.rmtree(base, ignore_errors=True)


# ----- upgrade, rollback, uninstall ------------------------------------------------------------
@pytest.fixture()
def installed_root(fake_root, stub_deb, release_key):
    need_root()
    assert install(fake_root, stub_deb, release_key.pub_asc, "--yes").returncode == 0
    state = fake_root / "var/lib/happymining"
    state.mkdir(parents=True)
    (state / "identity").write_bytes(os.urandom(32))
    (state / "credential.json").write_text('{"id": "fake", "token": "not-a-real-token"}\n')
    os.chmod(state / "credential.json", 0o600)
    os.chmod(state / "identity", 0o600)
    env_file = fake_root / "etc/happymining/agent.env"
    env_file.parent.mkdir(parents=True, exist_ok=True)
    env_file.write_text("HM_API_URL=https://operator-choice.example.invalid\n")
    return fake_root


def new_release(tmp_path, release_key, version):
    directory = tmp_path / f"release-{version}"
    directory.mkdir()
    deb = build_stub_deb(directory, version=version)
    write_sums(directory, release_key)
    return deb


def test_upgrade_replaces_only_the_agent_and_preserves_credentials(tmp_path, installed_root, release_key):
    root = installed_root
    preserved = [root / "var/lib/happymining/identity", root / "var/lib/happymining/credential.json",
                 root / "etc/happymining/agent.env"]
    before = file_hashes(preserved)
    modes = {str(p): stat.S_IMODE(p.stat().st_mode) for p in preserved}
    third_party = file_hashes(root / rel for rel in THIRD_PARTY_FILES)

    deb = new_release(tmp_path, release_key, "0.2.0")
    out = run([UPGRADE, "--deb", deb, "--keyring", release_key.pub_asc, "--root", root, "--yes"])
    assert out.returncode == 0, out.stdout + out.stderr
    assert installed_version(root) == "0.2.0"
    assert file_hashes(preserved) == before
    assert {str(p): stat.S_IMODE(p.stat().st_mode) for p in preserved} == modes
    assert file_hashes(root / rel for rel in THIRD_PARTY_FILES) == third_party
    assert "verified: device identity, credential and agent.env are unchanged" in out.stdout
    assert "does not\nroll back NVIDIA drivers, kernels" in out.stdout
    cache = root / "var/cache/happymining"
    assert (cache / "current").read_text().strip() == "happymining-agent_0.2.0_amd64.deb"
    assert (cache / "previous").read_text().strip() == "happymining-agent_0.1.0_amd64.deb"
    assert (cache / "happymining-agent_0.1.0_amd64.deb").is_file()


def test_upgrade_dry_run_changes_nothing(tmp_path, installed_root, release_key):
    before = tree_hash(installed_root)
    deb = new_release(tmp_path, release_key, "0.2.0")
    out = run([UPGRADE, "--deb", deb, "--keyring", release_key.pub_asc, "--root", installed_root, "--dry-run"])
    assert out.returncode == 0, out.stdout + out.stderr
    assert tree_hash(installed_root) == before
    assert installed_version(installed_root) == "0.1.0"


def test_upgrade_verifies_signatures_like_install(tmp_path, installed_root, other_key, release_key):
    deb = new_release(tmp_path, other_key, "0.2.0")
    out = run([UPGRADE, "--deb", deb, "--keyring", release_key.pub_asc, "--root", installed_root, "--yes"])
    assert out.returncode == 3
    assert installed_version(installed_root) == "0.1.0"


def test_upgrade_refuses_downgrade_and_fresh_install(tmp_path, installed_root, release_key):
    older = new_release(tmp_path, release_key, "0.0.9")
    out = run([UPGRADE, "--deb", older, "--keyring", release_key.pub_asc, "--root", installed_root, "--yes"])
    assert out.returncode == 5
    assert installed_version(installed_root) == "0.1.0"

    (tmp_path / "second").mkdir()
    empty = make_fake_root(tmp_path / "second")
    fresh = run([UPGRADE, "--deb", older, "--keyring", release_key.pub_asc, "--root", empty, "--yes"])
    assert fresh.returncode == 5
    assert "use install.sh" in fresh.stderr


def test_rollback_restores_previous_agent_only_and_says_what_it_does_not_cover(tmp_path, installed_root, release_key):
    root = installed_root
    deb = new_release(tmp_path, release_key, "0.2.0")
    assert run([UPGRADE, "--deb", deb, "--keyring", release_key.pub_asc, "--root", root, "--yes"]).returncode == 0
    third_party = file_hashes(root / rel for rel in THIRD_PARTY_FILES)
    credential = (root / "var/lib/happymining/credential.json").read_text()

    out = run([UPGRADE, "--rollback", "--root", root, "--yes"])
    assert out.returncode == 0, out.stdout + out.stderr
    assert installed_version(root) == "0.1.0"
    assert "ROLLBACK OF THE AGENT PACKAGE ONLY" in out.stderr
    assert "NOT rolled back" in out.stderr
    assert file_hashes(root / rel for rel in THIRD_PARTY_FILES) == third_party
    assert (root / "var/lib/happymining/credential.json").read_text() == credential


def test_rollback_refuses_a_cached_package_that_was_modified(tmp_path, installed_root, release_key):
    root = installed_root
    deb = new_release(tmp_path, release_key, "0.2.0")
    assert run([UPGRADE, "--deb", deb, "--keyring", release_key.pub_asc, "--root", root, "--yes"]).returncode == 0
    with open(root / "var/cache/happymining/happymining-agent_0.1.0_amd64.deb", "ab") as fh:
        fh.write(b"tampered")
    out = run([UPGRADE, "--rollback", "--root", root, "--yes"])
    assert out.returncode == 3
    assert installed_version(root) == "0.2.0"


@pytest.mark.skipif(os.geteuid() != 0, reason="ownership check needs root")
def test_rollback_refuses_a_store_that_others_can_write(tmp_path, installed_root, release_key):
    root = installed_root
    deb = new_release(tmp_path, release_key, "0.2.0")
    assert run([UPGRADE, "--deb", deb, "--keyring", release_key.pub_asc, "--root", root, "--yes"]).returncode == 0
    os.chmod(root / "var/cache/happymining", 0o777)
    out = run([UPGRADE, "--rollback", "--root", root, "--yes"])
    assert out.returncode == 5
    assert installed_version(root) == "0.2.0"


def test_rollback_without_history_is_refused(installed_root):
    out = run([UPGRADE, "--rollback", "--root", installed_root, "--yes"])
    assert out.returncode == 5
    assert "nothing to roll back to" in out.stderr


def test_uninstall_removes_only_our_package(installed_root):
    root = installed_root
    third_party = file_hashes(root / rel for rel in THIRD_PARTY_FILES)
    before = tree_hash(root)
    dry = run([UNINSTALL, "--root", root, "--dry-run"])
    assert dry.returncode == 0 and tree_hash(root) == before

    out = run([UNINSTALL, "--root", root, "--yes"])
    assert out.returncode == 0, out.stdout + out.stderr
    assert installed_version(root) == ""
    assert not (root / "usr/bin/happyminingctl").exists()
    assert file_hashes(root / rel for rel in THIRD_PARTY_FILES) == third_party
    # State is kept unless --erase-config is given.
    assert (root / "var/lib/happymining/credential.json").exists()
    assert "Docker, the Vast host software and NVIDIA drivers were not touched" in out.stdout
    again = run([UNINSTALL, "--root", root, "--yes"])
    assert again.returncode == 0 and "nothing to do" in again.stdout
