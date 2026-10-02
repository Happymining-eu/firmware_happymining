"""render-seed.sh: explicit disk-by-id, matching erase confirmation, plan shown
before anything is written, key-only account, private output."""

from __future__ import annotations

import stat

import pytest

from hm_os_testlib import AUTOINSTALL_DIR, IMAGE_DIR, OS_DIR, REPO, make_ed25519_pubkey_line, run, validate, yaml_load

RENDER = AUTOINSTALL_DIR / "render-seed.sh"
SERIAL = "Samsung_SSD_990_PRO_2TB_S7KHNJ0X123456"
BY_ID = f"/dev/disk/by-id/nvme-{SERIAL}"
PLAN_TITLE = "DESTRUCTIVE INSTALL PLAN"


def args(pubkey_file, out, **override):
    values = {
        "--disk-by-id": BY_ID,
        "--disk-serial": SERIAL,
        "--confirm-erase": BY_ID,
        "--ssh-authorized-key-file": str(pubkey_file),
        "--hostname": "gpu-01",
        "--out": str(out),
    }
    values.update(override)
    result = [str(RENDER)]
    for key, value in values.items():
        if value is not None:
            result += [key, value]
    return result


def test_renders_a_private_per_machine_seed(tmp_path, pubkey_file):
    out_dir = tmp_path / "seed"
    out = run(args(pubkey_file, out_dir) + ["--yes-i-have-read-the-plan"])
    assert out.returncode == 0, out.stdout + out.stderr
    assert stat.S_IMODE(out_dir.stat().st_mode) == 0o700
    assert sorted(p.name for p in out_dir.iterdir()) == ["meta-data", "user-data"]
    for name in ("user-data", "meta-data"):
        assert stat.S_IMODE((out_dir / name).stat().st_mode) == 0o600

    text = (out_dir / "user-data").read_text()
    assert validate(text, "unattended", "--require-schema").returncode == 0
    ai = yaml_load(text)["autoinstall"]
    # The disk is pinned by the documented Subiquity match key, exactly.
    disks = [a for a in ai["storage"]["config"] if a["type"] == "disk"]
    assert [d["match"] for d in disks] == [{"serial": SERIAL}]
    # The by-id identity is enforced by the guard that runs before any probing.
    guard_call = ai["early-commands"][1]
    assert guard_call[:6] == ["bash", "/run/happymining-disk-guard.sh", "--firmware", "uefi", "--disk", BY_ID]
    assert guard_call[6] == SERIAL
    assert (AUTOINSTALL_DIR / "disk-guard.sh").read_text() in ai["early-commands"][0]
    # Partition plan: ESP, root, and a separate data filesystem as Vast expects it.
    mounts = {a["path"]: a for a in ai["storage"]["config"] if a["type"] == "mount"}
    assert set(mounts) == {"/", "/boot/efi", "/var/lib/docker"}
    assert mounts["/var/lib/docker"]["options"] == "rw,auto,pquota"
    formats = {a["id"]: a["fstype"] for a in ai["storage"]["config"] if a["type"] == "format"}
    assert formats == {"fmt-esp": "fat32", "fmt-root": "ext4", "fmt-data": "xfs"}
    # Account: the operator's public key only.
    user = ai["user-data"]["users"][0]
    assert user["lock_passwd"] is True
    assert user["ssh_authorized_keys"] == [pubkey_file.read_text().strip()]
    assert ai["ssh"] == {"install-server": True, "allow-pw": False}
    assert ai["user-data"]["hostname"] == "gpu-01"
    assert "identity" not in ai and "interactive-sections" not in ai
    for needle in ("password:", "passwd:", "chpasswd", "PRIVATE KEY", "hmd_", "HM_API", "vast"):
        assert needle not in text.replace("lock_passwd", ""), needle
    assert (out_dir / "meta-data").read_text() == "instance-id: happymining-seed-gpu-01\n"


BAD_DISKS = {
    "kernel name sda": "/dev/sda",
    "kernel name sdb1": "/dev/sdb1",
    "kernel name nvme": "/dev/nvme0n1",
    "kernel name vda": "/dev/vda",
    "by-path": "/dev/disk/by-path/pci-0000:00:1f.2-ata-1",
    "by-uuid": "/dev/disk/by-uuid/2f7e6a0e-0000-4000-8000-000000000000",
    "by-label": "/dev/disk/by-label/data",
    "word first": "first",
    "word largest": "largest",
    "word auto": "auto",
    "empty": "",
    "by-id directory only": "/dev/disk/by-id/",
    "by-id partition": f"/dev/disk/by-id/nvme-{SERIAL}-part1",
    "by-id wwn": "/dev/disk/by-id/wwn-0x5002538e40a1b2c3",
    "by-id nvme eui": "/dev/disk/by-id/nvme-eui.0025385a11b2c3d4",
    "by-id usb": "/dev/disk/by-id/usb-SanDisk_Ultra_0101-0:0",
    "by-id with traversal": "/dev/disk/by-id/../sda",
    "by-id with glob": "/dev/disk/by-id/nvme-*",
    "relative": "disk/by-id/nvme-x",
}


@pytest.mark.parametrize("name", sorted(BAD_DISKS))
def test_refuses_every_bad_disk_form(tmp_path, pubkey_file, name):
    bad = BAD_DISKS[name]
    out_dir = tmp_path / "seed"
    out = run(args(pubkey_file, out_dir, **{"--disk-by-id": bad, "--confirm-erase": bad})
              + ["--yes-i-have-read-the-plan"])
    assert out.returncode == 5, f"{name}: exit {out.returncode}\n{out.stderr}"
    assert not out_dir.exists()
    assert PLAN_TITLE not in out.stdout


def test_disk_by_id_is_required(tmp_path, pubkey_file):
    out = run(args(pubkey_file, tmp_path / "seed", **{"--disk-by-id": None}) + ["--yes-i-have-read-the-plan"])
    assert out.returncode == 5
    assert not (tmp_path / "seed").exists()


@pytest.mark.parametrize("confirm", [f"{BY_ID}x", BY_ID.lower(), "/dev/disk/by-id/nvme-OTHER", "yes", BY_ID + " ", None])
def test_refuses_mismatched_erase_confirmation(tmp_path, pubkey_file, confirm):
    out_dir = tmp_path / "seed"
    out = run(args(pubkey_file, out_dir, **{"--confirm-erase": confirm}) + ["--yes-i-have-read-the-plan"])
    assert out.returncode == 5, out.stderr
    assert "confirm-erase" in out.stderr
    assert not out_dir.exists()


def test_serial_must_describe_the_same_disk_and_be_exact(tmp_path, pubkey_file):
    for serial in ("SOME_OTHER_SERIAL", "Samsung*", "Samsung_SSD_990_PRO_2TB_S7KHNJ0X12345?", "[S]amsung"):
        out = run(args(pubkey_file, tmp_path / "seed", **{"--disk-serial": serial}) + ["--yes-i-have-read-the-plan"])
        assert out.returncode == 5, serial
        assert not (tmp_path / "seed").exists()
    out = run(args(pubkey_file, tmp_path / "seed", **{"--disk-serial": None}) + ["--yes-i-have-read-the-plan"])
    assert out.returncode == 2
    assert "ID_SERIAL" in out.stderr


PRIVATE_KEYS = {
    "openssh": "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ==\n-----END OPENSSH PRIVATE KEY-----\n",
    "rsa pem": "-----BEGIN RSA PRIVATE KEY-----\nMIIEfake\n-----END RSA PRIVATE KEY-----\n",
    "pkcs8": "-----BEGIN PRIVATE KEY-----\nMIIEfake\n-----END PRIVATE KEY-----\n",
    "putty": "PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\n",
}


@pytest.mark.parametrize("kind", sorted(PRIVATE_KEYS))
def test_refuses_a_private_key_file(tmp_path, kind):
    key = tmp_path / "id_key"
    key.write_text(PRIVATE_KEYS[kind])
    out_dir = tmp_path / "seed"
    out = run(args(key, out_dir) + ["--yes-i-have-read-the-plan"])
    assert out.returncode == 5, out.stderr
    assert "PRIVATE key" in out.stderr
    assert not out_dir.exists()


@pytest.mark.parametrize("content", [
    "",
    "not a key at all\n",
    "ssh-dss AAAAB3NzaC1kc3MAAACBAfakefakefakefakefakefakefakefakefakefakefake user@host\n",
    "ssh-ed25519 !!!notbase64!!! user@host\n",
    "ssh-rsa AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA mismatch@host\n",
    'command="/bin/sh" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA x\n',
])
def test_refuses_things_that_are_not_public_keys(tmp_path, content):
    key = tmp_path / "key.pub"
    key.write_text(content)
    out = run(args(key, tmp_path / "seed") + ["--yes-i-have-read-the-plan"])
    assert out.returncode == 5, out.stderr
    assert not (tmp_path / "seed").exists()


def test_no_password_option_exists():
    out = run([RENDER, "--help"])
    assert out.returncode == 0
    for word in ("--password", "--passwd", "--hash"):
        assert word not in out.stdout
    bad = run([RENDER, "--password", "x"])
    assert bad.returncode == 2


def test_plan_and_erase_target_are_printed_before_anything_is_written(tmp_path, pubkey_file):
    """With a wrong interactive confirmation the plan must already have been
    shown, and nothing may have been written."""
    out_dir = tmp_path / "seed"
    out = run(args(pubkey_file, out_dir), input="/dev/disk/by-id/nvme-WRONG\n")
    assert out.returncode == 5
    assert PLAN_TITLE in out.stdout
    assert "DISK THAT WILL BE ERASED:" in out.stdout
    assert BY_ID in out.stdout
    assert f"ID_SERIAL = {SERIAL}" in out.stdout
    for row in ("fat32       /boot/efi", "ext4        /", "xfs         /var/lib/docker", "no separate /boot",
                "rw,auto,pquota", "swap: none"):
        assert row in out.stdout, row
    assert "confirmation did not match" in out.stderr
    assert not out_dir.exists()


def test_interactive_confirmation_needs_the_exact_by_id_name(tmp_path, pubkey_file):
    no_input = run(args(pubkey_file, tmp_path / "a"), input="")
    assert no_input.returncode == 5 and not (tmp_path / "a").exists()
    typed_yes = run(args(pubkey_file, tmp_path / "b"), input="yes\n")
    assert typed_yes.returncode == 5 and not (tmp_path / "b").exists()
    typed_right = run(args(pubkey_file, tmp_path / "c"), input=BY_ID + "\n")
    assert typed_right.returncode == 0, typed_right.stderr
    assert (tmp_path / "c/user-data").is_file()
    # The plan comes before the prompt and before the "wrote" line.
    assert typed_right.stdout.index(PLAN_TITLE) < typed_right.stdout.index("wrote ")


def test_dry_run_prints_plan_and_seed_and_writes_nothing(tmp_path, pubkey_file):
    out_dir = tmp_path / "seed"
    before = sorted(p.name for p in tmp_path.iterdir())
    out = run(args(pubkey_file, out_dir) + ["--dry-run"])
    assert out.returncode == 0, out.stderr
    assert PLAN_TITLE in out.stdout
    assert "DRY-RUN would write (mode 0600)" in out.stdout
    assert "----- begin user-data -----" in out.stdout
    assert f"serial: \"{SERIAL}\"" in out.stdout
    assert not out_dir.exists()
    assert sorted(p.name for p in tmp_path.iterdir()) == before


def test_output_may_not_land_in_the_image_source_or_dist_tree(pubkey_file):
    for target in (OS_DIR / "autoinstall" / "seed-should-not-exist", IMAGE_DIR / "seed-should-not-exist",
                   REPO / "dist" / "seed-should-not-exist"):
        if not target.parent.is_dir():
            continue
        out = run(args(pubkey_file, target) + ["--yes-i-have-read-the-plan"])
        assert out.returncode == 5, target
        assert "generic image" in out.stderr
        assert not target.exists()


def test_existing_non_empty_output_directory_is_not_overwritten(tmp_path, pubkey_file):
    out_dir = tmp_path / "seed"
    out_dir.mkdir()
    (out_dir / "notes.txt").write_text("keep me")
    out = run(args(pubkey_file, out_dir) + ["--yes-i-have-read-the-plan"])
    assert out.returncode == 5
    assert sorted(p.name for p in out_dir.iterdir()) == ["notes.txt"]


def test_dedicated_data_disk_needs_its_own_identity_and_confirmation(tmp_path, pubkey_file):
    data_serial = "INTEL_SSDPF2KX038T1_PHAX1234567890"
    data_id = f"/dev/disk/by-id/nvme-{data_serial}"
    base = args(pubkey_file, tmp_path / "seed")
    missing_confirm = run(base + ["--data-disk-by-id", data_id, "--data-disk-serial", data_serial,
                                  "--yes-i-have-read-the-plan"])
    assert missing_confirm.returncode == 5
    same_disk = run(base + ["--data-disk-by-id", BY_ID, "--data-disk-serial", SERIAL,
                            "--confirm-erase-data-disk", BY_ID, "--yes-i-have-read-the-plan"])
    assert same_disk.returncode == 5
    assert not (tmp_path / "seed").exists()

    good = run(base + ["--data-disk-by-id", data_id, "--data-disk-serial", data_serial,
                       "--confirm-erase-data-disk", data_id, "--yes-i-have-read-the-plan"])
    assert good.returncode == 0, good.stderr
    assert "SECOND DISK THAT WILL BE ERASED" in good.stdout
    assert data_id in good.stdout
    ai = yaml_load((tmp_path / "seed/user-data").read_text())["autoinstall"]
    disks = {a["id"]: a["match"] for a in ai["storage"]["config"] if a["type"] == "disk"}
    assert disks == {"disk-root": {"serial": SERIAL}, "disk-data": {"serial": data_serial}}
    guard = ai["early-commands"][1]
    assert guard.count("--disk") == 2 and data_id in guard and data_serial in guard


def test_bad_hostname_and_sizes_are_usage_errors(tmp_path, pubkey_file):
    for override in ({"--hostname": "Bad_Host"}, {"--hostname": "-gpu"}, {"--hostname": "a" * 64}):
        out = run(args(pubkey_file, tmp_path / "seed", **override) + ["--yes-i-have-read-the-plan"])
        assert out.returncode == 2, override
    for extra in (["--root-size", "100"], ["--root-size", "0G"], ["--min-data-size", "lots"],
                  ["--data-fs", "btrfs"], ["--data-mount", "var/lib/docker"], ["--data-mount", "/boot"],
                  ["--data-fs", "ext4"], ["--data-mount-options", "rw;reboot"]):
        out = run(args(pubkey_file, tmp_path / "seed") + extra + ["--yes-i-have-read-the-plan"])
        assert out.returncode == 2, extra
    assert not (tmp_path / "seed").exists()


def test_several_public_keys_are_all_installed(tmp_path):
    keys = tmp_path / "keys.pub"
    lines = [make_ed25519_pubkey_line("a@x"), make_ed25519_pubkey_line("b@x")]
    keys.write_text("# operators\n" + "\n".join(lines) + "\n")
    out = run(args(keys, tmp_path / "seed") + ["--yes-i-have-read-the-plan"])
    assert out.returncode == 0, out.stderr
    ai = yaml_load((tmp_path / "seed/user-data").read_text())["autoinstall"]
    assert ai["user-data"]["users"][0]["ssh_authorized_keys"] == lines
