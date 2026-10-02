"""disk-guard.sh runs inside the installer before any disk is probed. Here it
is exercised with stub udevadm / lsblk / blockdev / readlink on a temporary
PATH and fake device names; no real device is involved."""

from __future__ import annotations

import os

import pytest

from hm_os_testlib import AUTOINSTALL_DIR, make_stub, path_with, run

GUARD = AUTOINSTALL_DIR / "disk-guard.sh"
SERIAL = "FAKE_MODEL_SERIAL0001"
BY_ID = f"/dev/disk/by-id/nvme-{SERIAL}"
GIB = 1024 ** 3


def stubs(tmp_path, *, exists=True, dev_type="disk", serial=SERIAL, other_serial="OTHER_DISK_0002",
          size=500 * GIB, mountpoint=""):
    bin_dir = tmp_path / "bin"
    make_stub(bin_dir, "readlink", f"""
if [ "{int(exists)}" = "1" ]; then
    case "$*" in
        *{BY_ID}*) echo /dev/fakenvme0n1; exit 0 ;;
        */by-id/nvme-SECOND*) echo /dev/fakenvme1n1; exit 0 ;;
    esac
fi
exit 1
""")
    make_stub(bin_dir, "lsblk", f"""
case "$*" in
    "-dno NAME,TYPE") printf 'fakenvme0n1 disk\\nfakenvme1n1 disk\\nsr0 rom\\n' ;;
    "-dno TYPE -- /dev/fakenvme0n1") echo "{dev_type}" ;;
    "-dno TYPE -- /dev/fakenvme1n1") echo disk ;;
    "-no MOUNTPOINT -- /dev/fakenvme0n1") echo "{mountpoint}" ;;
    *) exit 0 ;;
esac
""")
    make_stub(bin_dir, "udevadm", f"""
case "$*" in
    *--name=/dev/fakenvme0n1*) echo "ID_SERIAL={serial}"; echo "ID_MODEL=FAKE_MODEL" ;;
    *--name=/dev/fakenvme1n1*) echo "ID_SERIAL={other_serial}" ;;
esac
""")
    make_stub(bin_dir, "blockdev", f"""
case "$*" in
    "--getsize64 /dev/fakenvme0n1") echo {size} ;;
    "--getsize64 /dev/fakenvme1n1") echo {300 * GIB} ;;
    *) exit 1 ;;
esac
""")
    return {"PATH": path_with(bin_dir)}


def guard(env, *extra, by_id=BY_ID, serial=SERIAL, minimum=302 * GIB):
    return run(["bash", GUARD, "--disk", by_id, serial, str(minimum), *extra], env=env)


def test_passes_for_the_expected_disk(tmp_path):
    out = guard(stubs(tmp_path))
    assert out.returncode == 0, out.stderr
    assert f"OK {BY_ID} -> /dev/fakenvme0n1" in out.stdout


def test_refuses_when_the_by_id_name_is_absent(tmp_path):
    out = guard(stubs(tmp_path, exists=False))
    assert out.returncode == 1
    assert "does not exist on this machine" in out.stderr
    assert "Nothing has been written to any disk" in out.stderr


def test_refuses_a_different_serial(tmp_path):
    out = guard(stubs(tmp_path, serial="SOMEONE_ELSES_DISK"))
    assert out.returncode == 1
    assert "has ID_SERIAL 'SOMEONE_ELSES_DISK'" in out.stderr


def test_refuses_duplicate_serials(tmp_path):
    out = guard(stubs(tmp_path, other_serial=SERIAL))
    assert out.returncode == 1
    assert "2 disks report ID_SERIAL" in out.stderr


def test_refuses_a_partition(tmp_path):
    out = guard(stubs(tmp_path, dev_type="part"))
    assert out.returncode == 1
    assert "not a whole disk" in out.stderr


def test_refuses_a_disk_that_is_too_small(tmp_path):
    out = guard(stubs(tmp_path, size=120 * GIB))
    assert out.returncode == 1
    assert "smaller than" in out.stderr


def test_refuses_the_installation_medium(tmp_path):
    out = guard(stubs(tmp_path, mountpoint="/cdrom"))
    assert out.returncode == 1
    assert "installation medium" in out.stderr


def test_refuses_kernel_device_names_and_bad_arguments(tmp_path):
    env = stubs(tmp_path)
    assert guard(env, by_id="/dev/fakenvme0n1").returncode == 1
    assert run(["bash", GUARD], env=env).returncode == 1
    assert run(["bash", GUARD, "--disk", BY_ID, SERIAL], env=env).returncode == 1
    assert guard(env, minimum="lots").returncode == 1


def test_refuses_the_same_device_twice(tmp_path):
    out = guard(stubs(tmp_path), "--disk", BY_ID, SERIAL, "1")
    assert out.returncode == 1


def test_two_distinct_disks_pass(tmp_path):
    env = stubs(tmp_path, other_serial="SECOND_DISK_SERIAL")
    out = guard(env, "--disk", "/dev/disk/by-id/nvme-SECOND_DISK_SERIAL", "SECOND_DISK_SERIAL", str(201 * GIB))
    assert out.returncode == 0, out.stderr


@pytest.mark.skipif(os.path.isdir("/sys/firmware/efi"), reason="this host is booted with UEFI")
def test_uefi_layout_is_refused_on_a_non_uefi_boot(tmp_path):
    out = run(["bash", GUARD, "--firmware", "uefi", "--disk", BY_ID, SERIAL, "1"], env=stubs(tmp_path))
    assert out.returncode == 1
    assert "UEFI" in out.stderr


def test_guard_only_reads():
    """No command that could write to a block device appears in the guard."""
    text = GUARD.read_text()
    for word in ("mkfs", "wipefs", "parted", "sgdisk", "dd ", " > /dev", "sfdisk", "blkdiscard", "mount "):
        assert word not in text, word
