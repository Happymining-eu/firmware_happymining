"""Shared helpers for the HappyMining OS installer tests (imported by conftest.py and the test modules).

Everything here works on temporary directories and fake paths. No test
partitions, formats or mounts anything, and no test touches the real system
outside pytest's temporary directory (plus a short-lived, short-named GnuPG
home under the system temp dir, removed at the end of the session).
"""

from __future__ import annotations

import base64
import hashlib
import os
import shutil
import stat
import struct
import subprocess
import tempfile
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
OS_DIR = REPO / "os"
INSTALL_DIR = OS_DIR / "install"
AUTOINSTALL_DIR = OS_DIR / "autoinstall"
IMAGE_DIR = OS_DIR / "image"
RELEASE_DIR = OS_DIR / "release"
FIXTURES = Path(__file__).resolve().parent / "fixtures"

SHELL_SCRIPTS = sorted(
    p for p in OS_DIR.rglob("*.sh")
)


def run(cmd, *, env=None, input=None, cwd=None, timeout=120):
    """Run a command, capture text output, never raise on a non-zero exit."""
    full_env = dict(os.environ)
    # Keep tests hermetic: no inherited dry-run switches or GnuPG homes.
    for key in ("HM_DRY_RUN", "HM_LOG_FILE", "HM_VERSIONS_FILE", "GNUPGHOME"):
        full_env.pop(key, None)
    if env:
        full_env.update(env)
    return subprocess.run(
        [str(c) for c in cmd],
        env=full_env,
        input=input,
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def tree_hash(root: Path) -> str:
    """Hash of every path, type, mode, link target and file content under root."""
    digest = hashlib.sha256()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in sorted(dirnames + filenames):
            full = Path(dirpath) / name
            st = full.lstat()
            digest.update(str(full.relative_to(root)).encode())
            digest.update(f"|{stat.S_IFMT(st.st_mode)}|{stat.S_IMODE(st.st_mode)}|".encode())
            if full.is_symlink():
                digest.update(os.readlink(full).encode())
            elif full.is_file():
                digest.update(hashlib.sha256(full.read_bytes()).digest())
    return digest.hexdigest()


def file_hashes(paths) -> dict[str, str]:
    return {str(p): hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in paths}


def load_versions() -> dict[str, str]:
    out = run(["bash", "-c", f"set -a; . '{OS_DIR}/versions.env'; env"])
    assert out.returncode == 0, out.stderr
    result = {}
    for line in out.stdout.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            result[key] = value
    return result


# ---------------------------------------------------------------------------
# Throwaway OpenPGP keys
# ---------------------------------------------------------------------------
class GpgKey:
    def __init__(self, home: Path, fingerprint: str, pub_asc: Path, pub_bin: Path):
        self.home = home
        self.fingerprint = fingerprint
        self.pub_asc = pub_asc
        self.pub_bin = pub_bin

    def sign(self, data: Path, signature: Path) -> None:
        out = run(
            ["gpg", "--homedir", self.home, "--batch", "--yes", "--pinentry-mode", "loopback", "--passphrase", "",
             "--armor", "--detach-sign", "--output", signature, data]
        )
        assert out.returncode == 0, out.stderr


def make_key(base: Path, name: str) -> GpgKey:
    home = base / name
    home.mkdir(mode=0o700)
    out = run(
        ["gpg", "--homedir", home, "--batch", "--pinentry-mode", "loopback", "--passphrase", "",
         "--quick-generate-key", f"HappyMining TEST key {name} (throwaway) <{name}@example.invalid>",
         "ed25519", "sign", "1d"]
    )
    assert out.returncode == 0, out.stderr
    listing = run(["gpg", "--homedir", home, "--batch", "--with-colons", "--list-secret-keys"])
    fpr = next(line.split(":")[9] for line in listing.stdout.splitlines() if line.startswith("fpr:"))
    pub_asc = base / f"{name}.pub.asc"
    pub_bin = base / f"{name}.pub.gpg"
    asc = run(["gpg", "--homedir", home, "--batch", "--armor", "--export", fpr])
    pub_asc.write_text(asc.stdout)
    with open(pub_bin, "wb") as fh:
        subprocess.run(["gpg", "--homedir", str(home), "--batch", "--export", fpr], stdout=fh, check=True)
    return GpgKey(home, fpr, pub_asc, pub_bin)


# ---------------------------------------------------------------------------
# Stub agent package
# ---------------------------------------------------------------------------
STUB_CTL = """#!/bin/sh
# Stub happyminingctl for the installer tests.
if [ -n "${HM_STUB_LOG:-}" ]; then
    echo "happyminingctl $*" >> "$HM_STUB_LOG"
fi
case "$1" in
    preflight)
        echo "PASS    Operating system      stub"
        if [ "${HM_STUB_PREFLIGHT_RC:-0}" = "1" ]; then
            echo "FAIL    NVIDIA GPU            no NVIDIA GPU detected (stub)"
        else
            echo "WARN    NVIDIA GPU            stub warning"
        fi
        exit "${HM_STUB_PREFLIGHT_RC:-0}"
        ;;
    version) echo "happyminingctl stub" ;;
esac
exit 0
"""


def build_stub_deb(directory: Path, version: str = "0.1.0", package: str = "happymining-agent",
                   with_env_default: bool = False) -> Path:
    """Build a minimal stand-in for the agent package with dpkg-deb."""
    pkg = directory / f"pkgroot-{package}-{version}"
    (pkg / "DEBIAN").mkdir(parents=True)
    (pkg / "usr/bin").mkdir(parents=True)
    (pkg / "DEBIAN/control").write_text(
        f"Package: {package}\nVersion: {version}\nArchitecture: amd64\n"
        "Maintainer: Test <test@example.invalid>\nDescription: stub agent package for tests\n"
    )
    ctl = pkg / "usr/bin/happyminingctl"
    ctl.write_text(STUB_CTL)
    ctl.chmod(0o755)
    (pkg / "usr/bin/happymining-agent").write_text(f"#!/bin/sh\necho stub agent {version}\n")
    (pkg / "usr/bin/happymining-agent").chmod(0o755)
    if with_env_default:
        (pkg / "etc/happymining").mkdir(parents=True)
        (pkg / "etc/happymining/agent.env").write_text(
            "# stub default\nHM_API_URL=https://api.happymining.fr\n#HM_LOG_LEVEL=info\n"
        )
        (pkg / "DEBIAN/conffiles").write_text("/etc/happymining/agent.env\n")
    deb = directory / f"{package}_{version}_amd64.deb"
    out = run(["dpkg-deb", "--root-owner-group", "--build", pkg, deb])
    assert out.returncode == 0, out.stderr
    shutil.rmtree(pkg)
    return deb


def write_sums(directory: Path, key: GpgKey | None) -> None:
    """Write SHA256SUMS (and SHA256SUMS.gpg when a key is given) over *.deb."""
    lines = []
    for deb in sorted(directory.glob("*.deb")):
        lines.append(f"{hashlib.sha256(deb.read_bytes()).hexdigest()}  {deb.name}\n")
    (directory / "SHA256SUMS").write_text("".join(lines))
    sig = directory / "SHA256SUMS.gpg"
    if sig.exists():
        sig.unlink()
    if key is not None:
        key.sign(directory / "SHA256SUMS", sig)


# ---------------------------------------------------------------------------
# Fake system root with an existing Docker / Vast / NVIDIA installation
# ---------------------------------------------------------------------------
def make_fake_root(base: Path, ubuntu_version: str = "24.04", os_id: str = "ubuntu") -> Path:
    root = base / "fakeroot"
    for d in ("var/lib/dpkg/updates", "var/lib/dpkg/info", "etc/docker", "etc/systemd/system",
              "var/lib/docker/overlay2", "var/lib/vastai_kaalia/data", "etc/netplan", "etc/apt/preferences.d",
              "usr/bin"):
        (root / d).mkdir(parents=True)
    (root / "var/lib/dpkg/status").write_text("")
    (root / "etc/os-release").write_text(f'ID={os_id}\nVERSION_ID="{ubuntu_version}"\nNAME="Ubuntu"\n')
    (root / "etc/fstab").write_text("UUID=1111 / ext4 defaults 0 1\nUUID=2222 /var/lib/docker xfs rw,auto,pquota 0 0\n")
    (root / "etc/docker/daemon.json").write_text('{"runtimes": {"nvidia": {"path": "/var/lib/vastai_kaalia/latest/kaalia_docker_shim"}}}\n')
    (root / "etc/systemd/system/vastai.service").write_text("[Service]\nExecStart=/var/lib/vastai_kaalia/latest/launch_kaalia.sh\n")
    (root / "etc/apt/preferences.d/vast-packages").write_text("Package: docker-ce\nPin: version 5:28.*\nPin-Priority: 1001\n")
    (root / "var/lib/vastai_kaalia/machine_id").write_text("fake-vast-machine-identifier\n")
    (root / "var/lib/vastai_kaalia/data/state.json").write_text("{}\n")
    (root / "var/lib/docker/overlay2/layer").write_text("fake renter layer\n")
    (root / "usr/bin/docker").write_text("#!/bin/sh\necho Docker version 28.0.0\n")
    (root / "usr/bin/nvidia-smi").write_text("#!/bin/sh\necho 550.120\n")
    (root / "etc/netplan/50-cloud-init.yaml").write_text("network: {version: 2}\n")
    return root


THIRD_PARTY_FILES = [
    "etc/fstab",
    "etc/docker/daemon.json",
    "etc/systemd/system/vastai.service",
    "etc/apt/preferences.d/vast-packages",
    "var/lib/vastai_kaalia/machine_id",
    "var/lib/vastai_kaalia/data/state.json",
    "var/lib/docker/overlay2/layer",
    "usr/bin/docker",
    "usr/bin/nvidia-smi",
    "etc/netplan/50-cloud-init.yaml",
]


# ---------------------------------------------------------------------------
# SSH keys for the seed tests (generated without ssh-keygen)
# ---------------------------------------------------------------------------
def make_ed25519_pubkey_line(comment: str = "operator@example.invalid") -> str:
    blob = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32) + os.urandom(32)
    return f"ssh-ed25519 {base64.b64encode(blob).decode()} {comment}"


# ---------------------------------------------------------------------------
# Stub tools on a temporary PATH
# ---------------------------------------------------------------------------
def make_stub(bin_dir: Path, name: str, body: str) -> Path:
    bin_dir.mkdir(parents=True, exist_ok=True)
    path = bin_dir / name
    path.write_text("#!/bin/bash\n" + body)
    path.chmod(0o755)
    return path


def path_with(bin_dir: Path) -> str:
    return f"{bin_dir}:{os.environ.get('PATH', '/usr/bin:/bin')}"


# ---------------------------------------------------------------------------
# YAML through the system python3 (the interpreter the tools themselves use).
# The interpreter that runs pytest may not have PyYAML installed.
# ---------------------------------------------------------------------------
def yaml_load(text: str):
    import json

    import pytest

    out = run(
        ["python3", "-c", "import sys, json, yaml; print(json.dumps(yaml.safe_load(sys.stdin.read())))"],
        input=text,
    )
    if out.returncode != 0 and "No module named" in out.stderr:
        pytest.skip("PyYAML is not available to python3")
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


def cloud_config_from(obj) -> str:
    """Serialise a document as '#cloud-config' + JSON (JSON is valid YAML)."""
    import json

    return "#cloud-config\n" + json.dumps(obj, indent=1) + "\n"


def validate(text: str, kind: str, *extra):
    """Run os/autoinstall/validate.py on a document given as text."""
    return run(["python3", AUTOINSTALL_DIR / "validate.py", "--kind", kind, "--file", "-", *extra], input=text)


def render_dummy(dedicated_data_disk: bool = False) -> str:
    """The unattended template rendered with validate.py's dummy values."""
    code = (
        "import sys; sys.path.insert(0, sys.argv[1]); import validate; "
        "sys.stdout.write(validate.render_dummy(sys.argv[2] == '1'))"
    )
    out = run(["python3", "-B", "-c", code, AUTOINSTALL_DIR, "1" if dedicated_data_disk else "0"])
    assert out.returncode == 0, out.stderr
    return out.stdout
