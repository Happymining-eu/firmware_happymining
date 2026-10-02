"""nvidia-driver-plan.sh only prints. Every package or driver tool is replaced
by a recording stub; the test fails if a mutating invocation is made."""

from __future__ import annotations

from hm_os_testlib import INSTALL_DIR, make_stub, path_with, run

PLAN = INSTALL_DIR / "nvidia-driver-plan.sh"


def stub_env(tmp_path, *, smi_version="550.120", gpu=True, recommended="nvidia-driver-570-server, (kernel modules provided by linux-modules-nvidia-570-server-generic)"):
    bin_dir = tmp_path / "bin"
    log = tmp_path / "calls.log"
    record = f'echo "$(basename "$0") $*" >> "{log}"\n'
    make_stub(bin_dir, "ubuntu-drivers", record + f'[ "$1" = list ] && echo "{recommended}"\nexit 0\n')
    make_stub(bin_dir, "nvidia-smi", record + (f'echo "{smi_version}"\n' if smi_version else "exit 9\n"))
    make_stub(bin_dir, "lspci", record + (
        'echo "01:00.0 VGA compatible controller [0300]: NVIDIA Corporation Device [10de:2684]"\n' if gpu else "exit 0\n"))
    make_stub(bin_dir, "dpkg-query", record + 'echo "ii  nvidia-driver-550-server 550.120-0ubuntu0.24.04.1"\n')
    make_stub(bin_dir, "apt-mark", record + 'echo "nvidia-driver-550-server"\n')
    make_stub(bin_dir, "mokutil", record + 'echo "SecureBoot enabled"\n')
    for forbidden in ("apt-get", "apt", "dpkg", "modprobe", "rmmod", "dkms", "snap", "systemctl", "reboot",
                      "update-initramfs", "update-grub"):
        make_stub(bin_dir, forbidden, record + "exit 0\n")
    return {"PATH": path_with(bin_dir)}, log


def calls(log):
    return log.read_text().splitlines() if log.exists() else []


def test_prints_a_plan_and_installs_nothing(tmp_path):
    env, log = stub_env(tmp_path)
    out = run([PLAN], env=env)
    assert out.returncode == 0, out.stderr
    assert "prints only; changes nothing" in out.stdout
    assert "This script changed nothing." in out.stdout
    assert "KEEP the present driver (550.120)" in out.stdout
    assert "nvidia-driver-570-server" in out.stdout
    assert "Secure Boot is ENABLED" in out.stdout
    made = calls(log)
    assert "ubuntu-drivers list --gpgpu" in made
    for call in made:
        tool, _, rest = call.partition(" ")
        assert tool in {"ubuntu-drivers", "nvidia-smi", "lspci", "dpkg-query", "apt-mark", "mokutil"}, call
        assert not any(word in rest.split() for word in ("install", "remove", "purge", "upgrade", "autoinstall",
                                                         "hold", "unhold")), call
    assert "ubuntu-drivers list --gpgpu" in "\n".join(made)
    assert not any(c.startswith("ubuntu-drivers install") for c in made)


def test_old_driver_leads_to_a_scheduled_update_recommendation(tmp_path):
    env, log = stub_env(tmp_path, smi_version="470.256.02")
    out = run([PLAN], env=env)
    assert out.returncode == 0
    assert "PLAN A DRIVER UPDATE" in out.stdout
    assert "520.61.05" in out.stdout
    assert "maintenance window" in out.stdout
    assert not any(c.split()[0] in ("apt-get", "apt", "dpkg") for c in calls(log))


def test_missing_driver_is_reported_not_fixed(tmp_path):
    env, log = stub_env(tmp_path, smi_version="")
    out = run([PLAN], env=env)
    assert out.returncode == 0
    assert "PLAN A DRIVER INSTALLATION" in out.stdout
    assert "sudo ubuntu-drivers install --gpgpu nvidia:<BRANCH>-server" in out.stdout  # printed text only
    assert not any("install" in c for c in calls(log))


def test_dry_run_lists_the_read_only_inspection_commands(tmp_path):
    env, _ = stub_env(tmp_path)
    out = run([PLAN, "--dry-run"], env=env)
    assert out.returncode == 0
    assert "read-only inspection: ubuntu-drivers list --gpgpu" in out.stderr


def test_explains_why_driver_changes_are_manual():
    text = PLAN.read_text()
    assert "active Vast" in text and "maintenance" in text
    assert "never installs" in text
