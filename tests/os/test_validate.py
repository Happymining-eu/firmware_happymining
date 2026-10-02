"""validate.py must catch every forbidden pattern. Bad fixtures are produced by
mutating the known-good documents, one defect at a time."""

from __future__ import annotations

import copy

import pytest

from hm_os_testlib import (
    AUTOINSTALL_DIR,
    FIXTURES,
    cloud_config_from,
    render_dummy,
    run,
    validate,
    yaml_load,
)

FAKE_HASH = "$6$rounds=4096$abcdefghijklmnop$" + "A" * 86
FAKE_PRIVATE_KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAAfakefakefake\n-----END OPENSSH PRIVATE KEY-----"
FAKE_PUBKEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI" + "B" * 43 + " someone@example.invalid"


@pytest.fixture(scope="module")
def good_generic():
    return yaml_load((AUTOINSTALL_DIR / "user-data.generic.yaml").read_text())


@pytest.fixture(scope="module")
def good_unattended():
    return yaml_load(render_dummy(False))


def test_good_documents_pass(good_generic, good_unattended):
    assert validate(cloud_config_from(good_generic), "generic").returncode == 0
    out = validate(cloud_config_from(good_unattended), "unattended")
    assert out.returncode == 0, out.stdout
    out = validate(render_dummy(True), "unattended")
    assert out.returncode == 0, out.stdout


def _set(doc, path, value):
    node = doc
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = value


def _del(doc, path):
    node = doc
    for key in path[:-1]:
        node = node[key]
    del node[path[-1]]


GENERIC_DEFECTS = {
    "version is not 1": lambda d: _set(d, ["autoinstall", "version"], 2),
    "version missing": lambda d: _del(d, ["autoinstall", "version"]),
    "storage not interactive": lambda d: _set(d, ["autoinstall", "interactive-sections"], ["network", "identity"]),
    "identity not interactive": lambda d: _set(d, ["autoinstall", "interactive-sections"], ["network", "storage"]),
    "interactive-sections missing": lambda d: _del(d, ["autoinstall", "interactive-sections"]),
    "storage layout selects largest disk": lambda d: _set(d, ["autoinstall", "storage"], {"layout": {"name": "lvm"}}),
    "storage match selects a disk": lambda d: _set(
        d, ["autoinstall", "storage"], {"layout": {"name": "direct", "match": {"serial": "X"}}}),
    "hard-coded sda": lambda d: _set(d, ["autoinstall", "late-commands"], ["wipe /dev/sda now"]),
    "hard-coded nvme": lambda d: _set(d, ["autoinstall", "late-commands"], ["echo /dev/nvme0n1p2"]),
    "hard-coded vda": lambda d: _set(d, ["autoinstall", "late-commands"], ["echo /dev/vda"]),
    "identity with password hash": lambda d: _set(
        d, ["autoinstall", "identity"], {"username": "u", "hostname": "h", "password": FAKE_HASH}),
    "identity without password": lambda d: _set(
        d, ["autoinstall", "identity"], {"username": "u", "hostname": "h", "password": ""}),
    "chpasswd": lambda d: _set(
        d, ["autoinstall", "user-data"], {"chpasswd": {"expire": False, "users": [{"name": "u", "password": "x"}]}}),
    "user-data with plain password": lambda d: _set(d, ["autoinstall", "user-data"], {"password": "hunter2hunter2"}),
    "ssh authorized key baked in": lambda d: _set(d, ["autoinstall", "ssh", "authorized-keys"], [FAKE_PUBKEY]),
    "ssh password login allowed": lambda d: _set(d, ["autoinstall", "ssh", "allow-pw"], True),
    "private key material": lambda d: _set(d, ["autoinstall", "late-commands"], ["echo '" + FAKE_PRIVATE_KEY + "'"]),
    "pairing code": lambda d: _set(
        d, ["autoinstall", "late-commands"], ["happyminingctl pair HM-7K2M9Q-4F8T-ZP3D-W6NH-R5XA"]),
    "device token": lambda d: _set(
        d, ["autoinstall", "late-commands"], ["echo hmd_0123456789abcdef0123456789abcdef.secretsecret"]),
    "vast api key": lambda d: _set(
        d, ["autoinstall", "late-commands"], ["vastai set api-key 0123456789abcdef0123456789abcdef0123456789abcdef"]),
    "auto-confirm keyword in a command": lambda d: _set(
        d, ["autoinstall", "late-commands"], ["sed -i 's/---/autoinstall ---/' /target/boot/grub/grub.cfg"]),
    "early-commands": lambda d: _set(d, ["autoinstall", "early-commands"], ["true"]),
    "top-level cloud-config directive": lambda d: _set(d, ["runcmd"], ["true"]),
    "autoinstall key missing": lambda d: _del(d, ["autoinstall"]),
    "schema: unknown shutdown value": lambda d: _set(d, ["autoinstall", "shutdown"], "halt"),
    "schema: wrong type": lambda d: _set(d, ["autoinstall", "ssh", "install-server"], "yes please"),
}


@pytest.mark.parametrize("name", sorted(GENERIC_DEFECTS))
def test_generic_defects_are_caught(good_generic, name):
    doc = copy.deepcopy(good_generic)
    GENERIC_DEFECTS[name](doc)
    out = validate(cloud_config_from(doc), "generic")
    assert out.returncode == 1, f"{name}: not caught\n{out.stdout}{out.stderr}"
    assert "INVALID" in out.stdout


def _disk(doc, index=0):
    disks = [a for a in doc["autoinstall"]["storage"]["config"] if a["type"] == "disk"]
    return disks[index]


UNATTENDED_DEFECTS = {
    "layout without match": lambda d: _set(d, ["autoinstall", "storage"], {"layout": {"name": "lvm"}}),
    "layout with empty match": lambda d: _set(d, ["autoinstall", "storage"], {"layout": {"name": "direct", "match": {}}}),
    "layout matching the largest disk": lambda d: _set(
        d, ["autoinstall", "storage"], {"layout": {"name": "direct", "match": {"size": "largest"}}}),
    "layout matching any ssd": lambda d: _set(
        d, ["autoinstall", "storage"], {"layout": {"name": "direct", "match": {"ssd": True}}}),
    "storage missing": lambda d: _del(d, ["autoinstall", "storage"]),
    "disk action without match": lambda d: _disk(d).pop("match"),
    "disk matched by glob serial": lambda d: _disk(d).__setitem__("match", {"serial": "HMDUMMY*"}),
    "disk matched by size": lambda d: _disk(d).__setitem__("match", {"size": "largest"}),
    "disk matched by path glob": lambda d: _disk(d).__setitem__("match", {"path": "/dev/disk/by-id/*"}),
    "disk selected by path": lambda d: _disk(d).__setitem__("path", "/dev/sda"),
    "disk match as fallback list": lambda d: _disk(d).__setitem__(
        "match", [{"serial": "HMDUMMY_MODEL_SERIAL0001"}, {"size": "largest"}]),
    "disk guard removed": lambda d: _del(d, ["autoinstall", "early-commands"]),
    "disk guard for another serial": lambda d: _disk(d).__setitem__("match", {"serial": "SOME_OTHER_SERIAL"}),
    "interactive section left": lambda d: _set(d, ["autoinstall", "interactive-sections"], ["storage"]),
    "identity with password": lambda d: _set(
        d, ["autoinstall", "identity"], {"username": "u", "hostname": "h", "password": FAKE_HASH}),
    "account with password hash": lambda d: d["autoinstall"]["user-data"]["users"][0].__setitem__("passwd", FAKE_HASH),
    "account password not locked": lambda d: d["autoinstall"]["user-data"]["users"][0].__setitem__("lock_passwd", False),
    "account without key": lambda d: d["autoinstall"]["user-data"]["users"][0].__setitem__("ssh_authorized_keys", []),
    "ssh password login allowed": lambda d: _set(d, ["autoinstall", "ssh", "allow-pw"], True),
    "ssh_pwauth enabled": lambda d: _set(d, ["autoinstall", "user-data", "ssh_pwauth"], True),
    "chpasswd": lambda d: _set(d, ["autoinstall", "user-data", "chpasswd"], {"expire": False}),
    "host private keys shipped": lambda d: _set(
        d, ["autoinstall", "user-data", "ssh_keys"], {"ed25519_private": FAKE_PRIVATE_KEY}),
    "hard-coded device in a command": lambda d: d["autoinstall"]["late-commands"].append("echo /dev/sdb1"),
    "pairing code": lambda d: d["autoinstall"]["late-commands"].append("echo HM-7K2M9Q-4F8T-ZP3D-W6NH-R5XA"),
    "luks passphrase in layout": lambda d: _set(
        d, ["autoinstall", "storage"],
        {"layout": {"name": "lvm", "match": {"serial": "HMDUMMY_MODEL_SERIAL0001"}, "password": "secret-passphrase"}}),
    "version as string": lambda d: _set(d, ["autoinstall", "version"], "1"),
}


@pytest.mark.parametrize("name", sorted(UNATTENDED_DEFECTS))
def test_unattended_defects_are_caught(good_unattended, name):
    doc = copy.deepcopy(good_unattended)
    UNATTENDED_DEFECTS[name](doc)
    out = validate(cloud_config_from(doc), "unattended")
    assert out.returncode == 1, f"{name}: not caught\n{out.stdout}{out.stderr}"
    assert "INVALID" in out.stdout


def test_missing_cloud_config_header_is_caught(good_generic):
    text = cloud_config_from(good_generic).replace("#cloud-config\n", "", 1)
    assert validate(text, "generic").returncode == 1


def test_duplicate_keys_are_refused():
    text = "#cloud-config\nautoinstall:\n  version: 1\n  version: 1\n  interactive-sections: [storage, identity]\n"
    out = validate(text, "generic")
    assert out.returncode == 1
    assert "duplicate key" in out.stdout


def test_yaml_that_is_not_safe_is_refused():
    text = "#cloud-config\nautoinstall: !!python/object/apply:os.system ['true']\n"
    out = validate(text, "generic")
    assert out.returncode == 1
    assert "yaml:" in out.stdout


@pytest.mark.parametrize("fixture", ["bad-generic-autoconfirm-grub.cfg"])
def test_grub_fixture_with_auto_confirm_is_caught(fixture):
    out = run(["python3", AUTOINSTALL_DIR / "validate.py", "--grub-cfg", FIXTURES / fixture])
    assert out.returncode == 1
    assert "confirmation prompt" in out.stdout


def test_static_bad_fixtures_are_caught():
    for name, kind in (("bad-generic-password.yaml", "generic"), ("bad-unattended-largest-disk.yaml", "unattended")):
        out = run(["python3", AUTOINSTALL_DIR / "validate.py", "--kind", kind, "--file", FIXTURES / name])
        assert out.returncode == 1, name
        assert "INVALID" in out.stdout


def test_usage_errors_exit_2():
    assert run(["python3", AUTOINSTALL_DIR / "validate.py", "--kind", "generic"]).returncode == 2
    assert run(["python3", AUTOINSTALL_DIR / "validate.py", "--file", "x"]).returncode == 2
