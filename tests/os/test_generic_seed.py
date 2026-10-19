"""The generic seed that ships inside the distributed image."""

from __future__ import annotations

import re

from hm_os_testlib import AUTOINSTALL_DIR, IMAGE_DIR, REPO, run, validate, yaml_load

GENERIC = AUTOINSTALL_DIR / "user-data.generic.yaml"


def generic():
    return yaml_load(GENERIC.read_text())["autoinstall"]


def test_generic_seed_is_valid():
    out = validate(GENERIC.read_text(), "generic", "--require-schema")
    assert out.returncode == 0, out.stdout + out.stderr


def test_repository_files_validate_with_the_official_schema():
    out = run(["python3", AUTOINSTALL_DIR / "validate.py", "--require-schema"])
    assert out.returncode == 0, out.stdout + out.stderr
    assert out.stdout.count("OK ") == 4
    assert "SKIPPED" not in out.stdout


def test_installer_ui_asks_for_disk_and_account():
    ai = generic()
    assert ai["version"] == 1
    for section in ("storage", "identity", "network"):
        assert section in ai["interactive-sections"]


def test_nothing_selects_a_disk():
    ai = generic()
    assert "storage" not in ai
    assert "early-commands" not in ai
    text = GENERIC.read_text()
    code = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))
    assert not re.search(r"/dev/(sd|nvme|vd|hd|xvd|mmcblk)", code)
    assert "/dev/disk/" not in code
    for word in ("match:", "layout:", "serial:", "wipe:", "ptable:"):
        assert word not in code


def test_no_credentials_of_any_kind():
    ai = generic()
    assert "identity" not in ai
    assert "user-data" not in ai
    assert not ai.get("ssh", {}).get("authorized-keys")
    assert ai["ssh"]["allow-pw"] is False
    text = GENERIC.read_text()
    code = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))
    for needle in ("password", "passwd", "chpasswd", "ssh-rsa ", "ssh-ed25519 ", "PRIVATE KEY", "hmd_", "api-key",
                   "api_key", "HM_API", "pairing_code"):
        assert needle not in code, needle
    assert not re.search(r"\bHM-[0-9A-Za-z]{6}-", code)
    scan = run(["python3", IMAGE_DIR / "secret_scan.py", GENERIC])
    assert scan.returncode == 0, scan.stdout


def test_generic_path_is_not_auto_confirming():
    """Neither the seed nor the boot menu carries the kernel keyword that
    removes the installer's confirmation prompt."""
    ai = generic()

    def strings(node):
        if isinstance(node, dict):
            for value in node.values():
                yield from strings(value)
        elif isinstance(node, list):
            for value in node:
                yield from strings(value)
        elif isinstance(node, str):
            yield node

    for value in strings(ai):
        assert "autoinstall" not in value.lower(), value

    entries = (IMAGE_DIR / "branding/grub-entries.cfg.in").read_text()
    kernel_lines = [ln for ln in entries.splitlines() if re.match(r"\s*linux\s", ln)]
    assert len(kernel_lines) == 2
    for line in kernel_lines:
        assert "autoinstall" not in line
    assert r"ds=nocloud\;s=file:///cdrom/happymining/seed/" in kernel_lines[0]
    assert "ds=" not in kernel_lines[1]
    assert 'menuentry "Install HappyMining OS"' in entries


def test_agent_package_comes_from_the_medium_and_first_boot_unit_is_enabled():
    ai = generic()
    commands = "\n".join(ai["late-commands"])
    assert "sha256sum --quiet -c SHA256SUMS" in commands
    assert "dpkg -i /var/cache/happymining/happymining-agent_" in commands
    assert "systemctl enable happymining-firstboot.service happymining-agent.service" in commands
    assert "/target/etc/issue.d/50-happymining-os.issue" in commands
    assert ai["ssh"]["install-server"] is True
    # Nothing is fetched from the network and no third-party software is added.
    for needle in ("curl", "wget", "http://", "https://", "docker", "nvidia", "vastai", "apt-get", "apt install"):
        assert needle not in commands, needle
    assert ai["drivers"]["install"] is False


def test_console_banner_explains_pairing_without_secrets():
    banner = (IMAGE_DIR / "branding/issue").read_text()
    assert "sudo happyminingctl pair" in banner
    assert "happyminingctl vast-enroll-help" in banner
    scan = run(["python3", IMAGE_DIR / "secret_scan.py", IMAGE_DIR / "branding"])
    assert scan.returncode == 0, scan.stdout


def test_console_banner_wordmark_survives_agetty_escapes():
    """agetty treats backslash sequences in /etc/issue as escapes; the wordmark
    rows therefore carry doubled backslashes, and only \\n, \\l and \\4 appear
    single (host name, console name, IPv4 address)."""
    banner = (IMAGE_DIR / "branding/issue").read_text()
    singles = set(re.findall(r"(?<!\\)\\(?!\\)(.)", banner.replace("\\\\", "")))
    assert singles == {"n", "l", "4"}, singles
    assert "Happy" not in banner.splitlines()[1]            # the name is drawn, not typed, in the art
    assert all(ord(c) < 128 for c in banner), "the console font may lack non-ASCII glyphs"
    assert "Lost?" in banner and "happyminingctl status" in banner


def test_motd_is_valid_shell_and_names_the_next_step():
    motd = REPO / "agent/packaging/motd/60-happymining"
    assert run(["sh", "-n", motd]).returncode == 0
    out = run(["sh", motd])
    assert out.returncode == 0, out.stderr
    assert "|_||_" in out.stdout                               # the wordmark
    unpaired = "NOT PAIRED" in out.stdout and "sudo happyminingctl pair" in out.stdout
    paired = "is paired with HappyMining" in out.stdout and "happyminingctl status" in out.stdout
    assert unpaired or paired
    assert "credential" not in out.stdout                     # the state is shown, the file is not
