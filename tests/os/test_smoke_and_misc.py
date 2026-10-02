"""QEMU smoke test script (dry run only here), seed volume helper, patch policy
script and documentation statements."""

from __future__ import annotations

import os
import shutil

import pytest

from hm_os_testlib import AUTOINSTALL_DIR, OS_DIR, REPO, make_stub, path_with, run, tree_hash

SMOKE = OS_DIR / "smoke/qemu-smoke.sh"
SEED_VOLUME = AUTOINSTALL_DIR / "make-seed-volume.sh"
POLICY = OS_DIR / "maintenance/apply-patch-policy.sh"
HAVE_QEMU = shutil.which("qemu-system-x86_64") is not None


# ----- QEMU smoke test ---------------------------------------------------------
def test_smoke_dry_run_prints_the_qemu_command_lines():
    out = run([SMOKE, "--dry-run", "--second-vm"])
    assert out.returncode == 0, out.stdout + out.stderr
    install_lines = [ln for ln in out.stdout.splitlines() if "would run (install" in ln]
    boot_lines = [ln for ln in out.stdout.splitlines() if "would run (boot installed disk)" in ln]
    assert len(install_lines) == 2 and len(boot_lines) == 2
    first = install_lines[0]
    assert "qemu-system-x86_64" in first and "timeout " in first
    assert "if=pflash,format=raw,readonly=on" in first, "UEFI firmware (OVMF) is used"
    assert "virtio-blk-pci,drive=hd0,serial=HMSMOKE0001" in first, "the disk serial is set on the command line"
    assert "-serial 'file:<workdir>/vm1-install-serial.log'" in first
    assert "-no-reboot" in first
    assert "-append 'autoinstall console=ttyS0,115200n8'" in first
    assert "HMSMOKE0002" in install_lines[1]
    assert "hostfwd=tcp:127.0.0.1:2222-:22" in boot_lines[0] and "hostfwd=tcp:127.0.0.1:2223-:22" in boot_lines[1]
    assert "-kernel" not in boot_lines[0], "the installed system boots from its own disk"
    # The seed is rendered for the by-id name that matches the serial, with a throwaway key.
    assert "--disk-by-id /dev/disk/by-id/virtio-HMSMOKE0001 --disk-serial HMSMOKE0001" in out.stdout
    assert "ssh-keygen -q -t ed25519 -N '' -C hm-smoke-throwaway" in out.stdout
    for check in ("VERSION_ID", "happymining-firstboot ran", "unpaired", "preflight --offline",
                  "password login is refused", "second VM: SSH host key"):
        assert check in out.stdout, check


@pytest.mark.skipif(HAVE_QEMU, reason="QEMU is installed; this test covers the missing-prerequisite path")
def test_smoke_exits_77_when_qemu_is_missing():
    out = run([SMOKE])
    assert out.returncode == 77
    assert "prerequisite not available: 'qemu-system-x86_64'" in out.stderr


def test_smoke_exits_77_when_the_iso_is_missing(tmp_path):
    """With stand-ins for every tool and firmware file, the missing ISO alone
    must lead to exit 77 (nothing is started)."""
    bin_dir = tmp_path / "bin"
    for tool in ("qemu-system-x86_64", "qemu-img", "xorriso", "ssh", "ssh-keygen"):
        make_stub(bin_dir, tool, f'echo "{tool} $*" >> "{tmp_path}/called"\nexit 0\n')
    code = tmp_path / "OVMF_CODE.fd"
    code.write_bytes(b"x")
    out = run([SMOKE, "--iso", tmp_path / "no-such.iso", "--ovmf-code", code, "--ovmf-vars", code,
               "--workdir", tmp_path / "work"], env={"PATH": path_with(bin_dir)})
    assert out.returncode == 77, out.stdout + out.stderr
    assert "prerequisite not available: ISO" in out.stderr
    assert not (tmp_path / "called").exists()
    assert not (tmp_path / "work").exists()


def test_smoke_throwaway_key_is_always_deleted_and_seed_never_in_tree():
    text = SMOKE.read_text()
    assert 'rm -f -- "$W/throwaway_key" "$W/throwaway_key.pub"' in text
    assert "trap cleanup EXIT" in text
    assert "--workdir must be outside os/ and dist/" in text


@pytest.mark.skipif(not (HAVE_QEMU and os.environ.get("HM_RUN_QEMU_SMOKE") == "1"),
                    reason="needs QEMU, OVMF, a built ISO and HM_RUN_QEMU_SMOKE=1 (not available in this sandbox)")
def test_smoke_real_run():  # pragma: no cover - build host only
    out = run([SMOKE], timeout=6 * 3600)
    assert out.returncode == 0, out.stdout[-4000:] + out.stderr[-4000:]


def test_smoke_readme_states_the_limits():
    text = (OS_DIR / "smoke/README.md").read_text()
    for needle in ("TCG", "KVM", "GPU", "Vast", "bare-metal", "77"):
        assert needle in text, needle


# ----- seed volume ------------------------------------------------------------------
def test_seed_volume_helper_dry_run_and_refusals(tmp_path):
    seed = tmp_path / "seed"
    seed.mkdir()
    (seed / "user-data").write_text("#cloud-config\n")
    (seed / "meta-data").write_text("instance-id: x\n")
    out = run([SEED_VOLUME, "--seed-dir", seed, "--out", tmp_path / "seed.iso", "--dry-run"])
    assert out.returncode == 0, out.stderr
    assert "CIDATA" in out.stdout and "-joliet" in out.stdout and "-rock" in out.stdout
    assert not (tmp_path / "seed.iso").exists()
    inside = run([SEED_VOLUME, "--seed-dir", seed, "--out", OS_DIR / "image/should-not-exist.iso", "--dry-run"])
    assert inside.returncode == 5
    assert run([SEED_VOLUME, "--seed-dir", tmp_path, "--out", tmp_path / "x.iso"]).returncode == 2


@pytest.mark.skipif(any(shutil.which(t) for t in ("xorriso", "genisoimage", "cloud-localds")),
                    reason="an ISO tool is installed; this test covers the missing-tool path")
def test_seed_volume_helper_exits_77_without_an_iso_tool(tmp_path):
    seed = tmp_path / "seed"
    seed.mkdir()
    (seed / "user-data").write_text("#cloud-config\n")
    (seed / "meta-data").write_text("instance-id: x\n")
    out = run([SEED_VOLUME, "--seed-dir", seed, "--out", tmp_path / "seed.iso"])
    assert out.returncode == 77
    assert not (tmp_path / "seed.iso").exists()


# ----- patch policy -------------------------------------------------------------------
def test_patch_policy_files_hold_back_kernel_nvidia_and_docker():
    conf = (OS_DIR / "maintenance/52happymining-unattended-upgrades").read_text()
    for needle in ('"^linux-image-"', '"^nvidia-"', '"^libnvidia-"', '"^docker-ce"', '"^containerd"',
                   'Automatic-Reboot "false"'):
        assert needle in conf, needle
    needrestart = (OS_DIR / "maintenance/needrestart-happymining.conf").read_text()
    assert "$nrconf{restart} = 'l';" in needrestart


@pytest.mark.skipif(os.geteuid() != 0, reason="the script refuses to change anything unless it runs as root")
def test_apply_patch_policy_copies_two_files_and_nothing_else(tmp_path):
    root = tmp_path / "root"
    (root / "etc/apt/apt.conf.d").mkdir(parents=True)
    (root / "etc/apt/apt.conf.d/50unattended-upgrades").write_text("// ubuntu default\n")
    before = tree_hash(root)
    dry = run([POLICY, "--root", root, "--dry-run"])
    assert dry.returncode == 0 and tree_hash(root) == before
    out = run([POLICY, "--root", root])
    assert out.returncode == 0, out.stderr
    files = sorted(str(p.relative_to(root)) for p in root.rglob("*") if p.is_file())
    assert files == ["etc/apt/apt.conf.d/50unattended-upgrades", "etc/apt/apt.conf.d/52happymining-unattended-upgrades",
                     "etc/needrestart/conf.d/50-happymining.conf"]
    assert (root / "etc/apt/apt.conf.d/50unattended-upgrades").read_text() == "// ubuntu default\n"
    again = run([POLICY, "--root", root])
    assert again.returncode == 0 and "already in place" in again.stdout


# ----- documentation statements the specification asks for --------------------------------
def test_docs_state_the_rollback_limit_and_the_maintenance_gate():
    maintenance = (REPO / "docs/os-maintenance.md").read_text()
    lowered = " ".join(maintenance.lower().split())
    for needle in (
        "does not roll back",
        "zero gpu utilisation is not proof",
        "unlisting does not end existing rentals",
        "maintenance gate",
        "unattended-upgrades",
        "maintenance window",
    ):
        assert needle in lowered, needle
    trust = " ".join((REPO / "docs/trust-chain.md").read_text().lower().split())
    for needle in ("sha256sums.gpg", "843938df228d22f7b3742bc0d94aa3f0efe21092", "not installed from an apt repository",
                   "revocation", "rotation", "hardware token", "development"):
        assert needle in trust, needle


def test_readme_has_verified_and_unverified_sections_with_sources():
    readme = (OS_DIR / "README.md").read_text()
    assert "## Verified against" in readme and "## Unverified" in readme
    assert "2026-10-02" in readme
    for url in ("https://docs.vast.ai/host/verification-stages",
                "https://canonical-subiquity.readthedocs-hosted.com/en/latest/tutorial/providing-autoinstall.html",
                "https://ubuntu.com/server/docs/how-to/graphics/install-nvidia-drivers/",
                "https://ubuntu.com/tutorials/how-to-verify-ubuntu"):
        assert url in readme, url
    assert "**ISO has not been built**" in readme and "**smoke test has not been run**" in readme
