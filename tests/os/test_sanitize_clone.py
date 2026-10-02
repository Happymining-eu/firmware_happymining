"""sanitize-clone.sh on a fake system tree (never on the machine running the tests)."""

from __future__ import annotations

import os
import stat

import pytest

from hm_os_testlib import OS_DIR, run, tree_hash

SANITIZE = OS_DIR / "firstboot/sanitize-clone.sh"
needs_root = pytest.mark.skipif(os.geteuid() != 0, reason="the script refuses to change anything unless it runs as root")


@pytest.fixture()
def image(tmp_path):
    root = tmp_path / "image"
    for d in ("etc/ssh", "var/lib/dbus", "var/lib/happymining/spool", "var/lib/cloud/instances/iid-1",
              "var/lib/cloud/data", "var/lib/cloud/sem", "var/lib/systemd", "var/lib/docker", "home/hmadmin/.ssh",
              "etc/systemd/system", "etc/netplan"):
        (root / d).mkdir(parents=True)
    (root / "etc/machine-id").write_text("0123456789abcdef0123456789abcdef\n")
    (root / "var/lib/dbus/machine-id").write_text("0123456789abcdef0123456789abcdef\n")
    for kind in ("rsa", "ecdsa", "ed25519"):
        (root / f"etc/ssh/ssh_host_{kind}_key").write_text("fake private host key\n")
        (root / f"etc/ssh/ssh_host_{kind}_key.pub").write_text("fake public host key\n")
    (root / "etc/ssh/sshd_config").write_text("PasswordAuthentication no\n")
    (root / "var/lib/happymining/identity").write_bytes(os.urandom(32))
    (root / "var/lib/happymining/ops.journal").write_text("op-1\n")
    (root / "var/lib/happymining/spool/000001.json").write_text("{}\n")
    (root / "var/lib/cloud/instance").symlink_to("instances/iid-1")
    (root / "var/lib/cloud/instances/iid-1/user-data.txt").write_text("#cloud-config\n")
    (root / "var/lib/cloud/data/instance-id").write_text("iid-1\n")
    (root / "var/lib/cloud/sem/config_scripts_per_once.once").write_text("\n")
    (root / "var/lib/systemd/random-seed").write_bytes(os.urandom(32))
    (root / "var/lib/docker/keep").write_text("docker data\n")
    (root / "home/hmadmin/.ssh/authorized_keys").write_text("operator key stays\n")
    (root / "etc/netplan/50-cloud-init.yaml").write_text("network: {version: 2}\n")
    (root / "etc/hostname").write_text("gpu-01\n")
    return root


def pair(image):
    (image / "var/lib/happymining/credential.json").write_text('{"token": "not-a-real-token"}\n')


def test_dry_run_changes_nothing(image):
    before = tree_hash(image)
    out = run([SANITIZE, "--root", image, "--dry-run"])
    assert out.returncode == 0, out.stdout + out.stderr
    assert tree_hash(image) == before
    assert "will truncate" in out.stdout and "will remove" in out.stdout


@needs_root
def test_sanitizes_identity_keys_and_instance_state(image):
    untouched = {p: (image / p).read_text() for p in (
        "var/lib/docker/keep", "home/hmadmin/.ssh/authorized_keys", "etc/netplan/50-cloud-init.yaml",
        "etc/hostname", "etc/ssh/sshd_config")}
    out = run([SANITIZE, "--root", image])
    assert out.returncode == 0, out.stdout + out.stderr

    machine_id = image / "etc/machine-id"
    assert machine_id.exists() and machine_id.stat().st_size == 0
    assert not (image / "var/lib/dbus/machine-id").exists()
    assert sorted(p.name for p in (image / "etc/ssh").iterdir()) == ["sshd_config"]
    # HappyMining identity and state are gone; the directories the package made are kept.
    state = image / "var/lib/happymining"
    assert sorted(p.name for p in state.iterdir()) == ["spool"]
    assert list((state / "spool").iterdir()) == []
    # cloud-init instance state is cleared.
    assert not (image / "var/lib/cloud/instance").exists()
    assert not (image / "var/lib/cloud/instance").is_symlink()
    for d in ("instances", "data", "sem"):
        assert list((image / "var/lib/cloud" / d).iterdir()) == []
    assert not (image / "var/lib/systemd/random-seed").exists()
    # SSH host keys come back on the next boot through the regeneration unit.
    unit = image / "etc/systemd/system/happymining-regen-ssh-hostkeys.service"
    assert "ssh-keygen -A" in unit.read_text()
    link = image / "etc/systemd/system/multi-user.target.wants/happymining-regen-ssh-hostkeys.service"
    assert link.is_symlink() and os.readlink(link) == "../happymining-regen-ssh-hostkeys.service"
    # Everything else is untouched.
    for rel, content in untouched.items():
        assert (image / rel).read_text() == content


@needs_root
def test_refuses_a_paired_system_without_the_explicit_flag(image):
    pair(image)
    before = tree_hash(image)
    out = run([SANITIZE, "--root", image])
    assert out.returncode == 5, out.stdout + out.stderr
    assert "PAIRED" in out.stderr
    assert "--i-am-preparing-a-clone-image" in out.stderr
    assert tree_hash(image) == before

    ok = run([SANITIZE, "--root", image, "--i-am-preparing-a-clone-image"])
    assert ok.returncode == 0, ok.stderr
    assert not (image / "var/lib/happymining/credential.json").exists()
    assert not (image / "var/lib/happymining/identity").exists()


@needs_root
def test_refuses_when_vast_host_software_is_on_the_image(image):
    (image / "var/lib/vastai_kaalia").mkdir()
    (image / "var/lib/vastai_kaalia/machine_id").write_text("vast identity\n")
    before = tree_hash(image)
    out = run([SANITIZE, "--root", image])
    assert out.returncode == 5
    assert "Vast host software is present" in out.stderr
    assert tree_hash(image) == before

    forced = run([SANITIZE, "--root", image, "--allow-vast-present"])
    assert forced.returncode == 0, forced.stderr
    assert (image / "var/lib/vastai_kaalia/machine_id").read_text() == "vast identity\n"
    assert "NOT sanitized" in forced.stderr


@needs_root
def test_rejects_things_that_are_not_a_system_tree(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    assert run([SANITIZE, "--root", empty]).returncode == 2
    assert run([SANITIZE, "--root", tmp_path / "missing"]).returncode == 2


def test_running_system_needs_confirmation_or_flag():
    """Static check: the live path asks for confirmation and the paired check
    comes before any change. (The live path itself is never executed in tests.)"""
    text = SANITIZE.read_text()
    refuse = text.index('if [[ "$paired" == "1" && "$CLONE_ACK" != "1" ]]; then')
    confirm = text.index('hm_confirm "Sanitize the RUNNING system?')
    first_change = text.index(': >"$ROOT/etc/machine-id"')
    assert refuse < confirm < first_change
    assert stat.S_IMODE(SANITIZE.stat().st_mode) & 0o111
