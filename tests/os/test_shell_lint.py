"""Static checks on every shell script under os/."""

from __future__ import annotations

import re
import shutil

import pytest

from hm_os_testlib import OS_DIR, REPO, SHELL_SCRIPTS, run

SCRIPT_IDS = [str(p.relative_to(REPO)) for p in SHELL_SCRIPTS]


def test_scripts_were_found():
    names = {p.name for p in SHELL_SCRIPTS}
    for expected in (
        "install.sh", "upgrade.sh", "uninstall.sh", "lib.sh", "nvidia-driver-plan.sh",
        "render-seed.sh", "disk-guard.sh", "make-seed-volume.sh", "sanitize-clone.sh",
        "build-iso.sh", "build-installer.sh", "make-checksums.sh", "gen-dev-signing-key.sh",
        "qemu-smoke.sh", "apply-patch-policy.sh",
    ):
        assert expected in names


@pytest.mark.parametrize("script", SHELL_SCRIPTS, ids=SCRIPT_IDS)
def test_bash_syntax(script):
    out = run(["bash", "-n", script])
    assert out.returncode == 0, out.stderr


@pytest.mark.parametrize("script", SHELL_SCRIPTS, ids=SCRIPT_IDS)
def test_shebang_strict_mode_and_no_eval(script):
    text = script.read_text()
    lines = text.splitlines()
    assert lines[0] == "#!/usr/bin/env bash"
    if script.name != "lib.sh":  # the library is sourced; strict mode is set by its callers
        assert re.search(r"^set -euo pipefail$", text, re.M), "missing 'set -euo pipefail'"
        assert script.stat().st_mode & 0o111, "script is not executable"
    code = [ln for ln in lines if not ln.lstrip().startswith("#")]
    assert not any(re.search(r"(^|[;&|(\s])eval\s", ln) for ln in code), "eval is not allowed"


@pytest.mark.skipif(shutil.which("shellcheck") is None,
                    reason="shellcheck not installed (pip install shellcheck-py)")
def test_shellcheck_clean():
    out = run(["shellcheck", "-x", *[p.relative_to(REPO) for p in SHELL_SCRIPTS]], cwd=REPO)
    assert out.returncode == 0, out.stdout + out.stderr


@pytest.mark.parametrize("script", [p for p in SHELL_SCRIPTS if p.name not in ("lib.sh", "disk-guard.sh")],
                         ids=[i for i in SCRIPT_IDS if not i.endswith(("lib.sh", "disk-guard.sh"))])
def test_every_script_has_help_and_dry_run(script):
    out = run([script, "--help"])
    assert out.returncode == 0, out.stderr
    assert "--dry-run" in out.stdout, "every script documents --dry-run"
    bad = run([script, "--definitely-not-an-option"])
    assert bad.returncode == 2


def test_python_tools_compile():
    for tool in (OS_DIR / "autoinstall/validate.py", OS_DIR / "autoinstall/render_template.py",
                 OS_DIR / "image/patch_grub.py", OS_DIR / "image/secret_scan.py"):
        # Compile in memory: py_compile would leave __pycache__ in the source tree.
        out = run(["python3", "-B", "-c", "import sys; compile(open(sys.argv[1]).read(), sys.argv[1], 'exec')", tool])
        assert out.returncode == 0, out.stderr


def test_tools_leave_no_bytecode_in_the_source_tree():
    run(["python3", OS_DIR / "autoinstall/validate.py"])
    assert not list(OS_DIR.rglob("__pycache__")), "python bytecode directories under os/"
