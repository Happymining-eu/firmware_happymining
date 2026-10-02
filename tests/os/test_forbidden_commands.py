"""The ordinary install / upgrade / uninstall path must not contain any
partitioning, formatting, package-removal, firewall or restart command."""

from __future__ import annotations

import re
import shutil

import pytest

from hm_os_testlib import INSTALL_DIR, run

GUARDED = ["install.sh", "upgrade.sh", "uninstall.sh", "lib.sh"]
LIST_FILE = INSTALL_DIR / "forbidden-commands.txt"


def patterns() -> list[str]:
    return [ln for ln in LIST_FILE.read_text().splitlines() if ln.strip() and not ln.lstrip().startswith("#")]


def grep_forbidden(path) -> str:
    """Same matcher as the scripts' own guard: GNU grep -E with the list file."""
    out = run(["grep", "-nE", "-e", "\n".join(patterns()), "--", path])
    assert out.returncode in (0, 1), out.stderr
    return out.stdout


@pytest.mark.parametrize("name", GUARDED)
def test_install_and_upgrade_scripts_contain_no_forbidden_command(name):
    hits = grep_forbidden(INSTALL_DIR / name)
    assert hits == "", f"forbidden command pattern in {name}:\n{hits}"


# Every command named in the specification, in the form it would be typed.
SAMPLES = [
    "parted -s /dev/sdb mklabel gpt",
    "sgdisk --zap-all /dev/sdb",
    "mkfs.ext4 /dev/sdb1",
    "mkfs -t xfs /dev/sdb1",
    "mkfs.xfs -f /dev/nvme0n1p3",
    "wipefs -a /dev/sdb",
    "dd if=/dev/zero of=/dev/sdb bs=1M",
    "fdisk /dev/sdb",
    "sfdisk /dev/sdb < layout",
    "lvremove -f vg/lv",
    "vgremove vg",
    "pvcreate /dev/sdb1",
    "zpool create tank /dev/sdb",
    "mdadm --create /dev/md0 --level=1 /dev/sdb /dev/sdc",
    "apt-get remove -y docker.io",
    "apt-get -y purge nvidia-driver-550",
    "apt remove docker-ce",
    "snap remove docker",
    "apt-get install -y docker.io",
    "ubuntu-drivers install --gpgpu",
    "systemctl reboot",
    "    reboot",
    "shutdown -r now",
    "systemctl restart docker",
    "systemctl stop vastai",
    "ufw allow 22",
    "iptables -F",
    "netplan apply",
    "echo x >> /etc/fstab",
    "mount /dev/sdb1 /mnt",
    "umount /var/lib/docker",
]


@pytest.mark.parametrize("sample", SAMPLES)
def test_the_list_catches_each_forbidden_command(tmp_path, sample):
    probe = tmp_path / "probe.sh"
    probe.write_text(f"#!/usr/bin/env bash\n{sample}\n")
    assert grep_forbidden(probe) != "", f"not caught: {sample}"


def test_the_list_names_every_command_from_the_specification():
    text = LIST_FILE.read_text()
    for word in ("parted", "sgdisk", "mkfs", "wipefs", "of=/dev/", "fdisk", "sfdisk", "lvremove", "vgremove",
                 "pvcreate", "zpool", "mdadm", "remove", "purge", "snap"):
        assert word in text


@pytest.mark.parametrize("script", ["install.sh", "upgrade.sh", "uninstall.sh"])
def test_runtime_guard_refuses_a_tampered_script(tmp_path, script):
    """A copy of the scripts with one forbidden line added must refuse to run."""
    bundle = tmp_path / "bundle"
    shutil.copytree(INSTALL_DIR, bundle)
    shutil.copy(INSTALL_DIR.parent / "versions.env", bundle / "versions.env")
    with open(bundle / script, "a") as fh:
        fh.write("\nwipefs -a /dev/does-not-exist\n")
    deb = tmp_path / "x.deb"
    deb.write_bytes(b"not a package")
    args = [bundle / script, "--dry-run"]
    if script != "uninstall.sh":
        args += ["--deb", deb]
    out = run(args)
    assert out.returncode == 5, out.stdout + out.stderr
    assert "self-guard" in out.stderr
    assert "wipefs" in out.stderr


def test_runtime_guard_fails_closed_when_the_list_is_missing(tmp_path):
    bundle = tmp_path / "bundle"
    shutil.copytree(INSTALL_DIR, bundle)
    shutil.copy(INSTALL_DIR.parent / "versions.env", bundle / "versions.env")
    (bundle / "forbidden-commands.txt").unlink()
    out = run([bundle / "uninstall.sh", "--dry-run"])
    assert out.returncode == 5
    assert "forbidden-command list is missing" in out.stderr


def test_patterns_are_valid_regular_expressions():
    for pattern in patterns():
        # grep -E returns 2 for an invalid expression.
        out = run(["grep", "-E", "-e", pattern, "/dev/null"])
        assert out.returncode == 1, f"invalid pattern: {pattern}"
        assert re.compile is not None
