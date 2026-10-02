"""patch_grub.py on a fixture grub.cfg (the real file only exists inside the ISO)."""

from __future__ import annotations

import hashlib
import re

from hm_os_testlib import AUTOINSTALL_DIR, FIXTURES, IMAGE_DIR, run

PATCH = IMAGE_DIR / "patch_grub.py"
ENTRIES = IMAGE_DIR / "branding/grub-entries.cfg.in"
ORIGINAL = FIXTURES / "ubuntu-live-server-grub.cfg"


def patch(tmp_path, source=ORIGINAL):
    out_file = tmp_path / "grub.cfg"
    out = run(["python3", PATCH, "grub", "--in", source, "--entries", ENTRIES, "--out", out_file])
    return out, out_file


def test_entries_are_added_first_and_originals_are_kept(tmp_path):
    out, new = patch(tmp_path)
    assert out.returncode == 0, out.stderr
    text = new.read_text()
    titles = re.findall(r"^menuentry [\"']([^\"']+)[\"']", text, re.M)
    assert titles[:2] == ["Install HappyMining OS", "Install HappyMining OS with a per-machine seed volume (CIDATA)"]
    assert titles[2:] == ["Try or Install Ubuntu Server", "Ubuntu Server with the HWE kernel", "Boot from next volume",
                          "UEFI Firmware Settings", "Test memory"]
    original = ORIGINAL.read_text()
    for line in original.splitlines():
        assert line in text.splitlines()
    kernel_lines = [ln for ln in text.splitlines() if re.match(r"\s*linux\s", ln)]
    assert kernel_lines[0].split() == ["linux", "/casper/vmlinuz", r"ds=nocloud\;s=file:///cdrom/happymining/seed/", "---"]
    assert kernel_lines[1].split() == ["linux", "/casper/vmlinuz", "---"]
    assert "@@" not in text


def test_result_never_pre_confirms_an_installation(tmp_path):
    _, new = patch(tmp_path)
    for line in new.read_text().splitlines():
        if re.match(r"\s*linux", line):
            assert "autoinstall" not in line.split()
    check = run(["python3", AUTOINSTALL_DIR / "validate.py", "--grub-cfg", new])
    assert check.returncode == 0, check.stdout


def test_refuses_a_base_that_already_pre_confirms(tmp_path):
    bad = tmp_path / "bad.cfg"
    bad.write_text(ORIGINAL.read_text().replace("/casper/vmlinuz  ---", "/casper/vmlinuz autoinstall ---"))
    out, new = patch(tmp_path, bad)
    assert out.returncode == 1
    assert "not an unmodified Ubuntu ISO" in out.stderr
    assert not new.exists()


def test_refuses_an_entries_template_that_pre_confirms(tmp_path):
    entries = tmp_path / "entries.in"
    entries.write_text(ENTRIES.read_text().replace("ds=nocloud", "autoinstall ds=nocloud"))
    out = run(["python3", PATCH, "grub", "--in", ORIGINAL, "--entries", entries, "--out", tmp_path / "o.cfg"])
    assert out.returncode == 1
    assert "confirmation prompt" in out.stderr
    assert not (tmp_path / "o.cfg").exists()


def test_refuses_unknown_layout_and_double_patching(tmp_path):
    odd = tmp_path / "odd.cfg"
    odd.write_text("set timeout=5\nmenuentry 'x' {\n\tlinux /boot/vmlinuz root=/dev/ram0\n}\n")
    out, _ = patch(tmp_path, odd)
    assert out.returncode == 1 and "refusing to guess" in out.stderr
    _, once = patch(tmp_path)
    twice = run(["python3", PATCH, "grub", "--in", once, "--entries", ENTRIES, "--out", tmp_path / "twice.cfg"])
    assert twice.returncode == 1


def test_md5sum_list_is_updated_for_changed_and_added_files(tmp_path):
    root = tmp_path / "tree"
    (root / "boot/grub").mkdir(parents=True)
    (root / "happymining").mkdir()
    (root / "boot/grub/grub.cfg").write_text("new grub\n")
    (root / "happymining/issue").write_text("banner\n")
    original = tmp_path / "md5sum.txt"
    original.write_text("11111111111111111111111111111111  ./boot/grub/grub.cfg\n"
                        "22222222222222222222222222222222  ./casper/vmlinuz\n")
    out_file = tmp_path / "new-md5sum.txt"
    out = run(["python3", PATCH, "md5", "--in", original, "--root", root, "--out", out_file,
               "boot/grub/grub.cfg", "happymining/issue"])
    assert out.returncode == 0, out.stderr
    lines = out_file.read_text().splitlines()
    assert lines == [
        hashlib.md5(b"new grub\n").hexdigest() + "  ./boot/grub/grub.cfg",
        "22222222222222222222222222222222  ./casper/vmlinuz",
        hashlib.md5(b"banner\n").hexdigest() + "  ./happymining/issue",
    ]
