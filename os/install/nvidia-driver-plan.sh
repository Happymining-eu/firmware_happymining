#!/usr/bin/env bash
#
# HappyMining OS — NVIDIA driver PLAN for this machine. Prints only.
#
#   ./nvidia-driver-plan.sh [--dry-run]
#
# This script inspects the machine with read-only commands and prints the
# driver action it recommends under the policy in versions.env
# (NVIDIA_DRIVER_POLICY, NVIDIA_MIN_DRIVER_VERSION). It never installs,
# removes, loads or unloads anything, and it needs no root privileges.
#
# Why driver changes stay manual and scheduled: on a host with active Vast
# rentals, replacing the NVIDIA user-space libraries or kernel module breaks
# the GPUs inside running customer containers ("Driver/library version
# mismatch") until the machine is restarted, and the restart itself stops every
# instance. A driver change is therefore a maintenance action that goes through
# the HappyMining maintenance gate and a Vast maintenance window
# (docs/os-maintenance.md) — never something an installer does on its own.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
HM_PROG="nvidia-driver-plan.sh"
# shellcheck source=os/install/lib.sh
. "$SCRIPT_DIR/lib.sh"

usage() {
    cat <<'USAGE'
Usage: ./nvidia-driver-plan.sh [--dry-run]

Prints the recommended NVIDIA driver action for this machine. It only prints:
nothing is installed, removed or changed, with or without --dry-run.
(--dry-run is accepted for symmetry with the other scripts and additionally
lists the read-only commands that are used for the inspection.)

Exit codes: 0 plan printed, 2 usage.
USAGE
}

SHOW_COMMANDS=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run) SHOW_COMMANDS=1; shift ;;
        -h | --help) usage; exit 0 ;;
        *) usage >&2; hm_die "$HM_EXIT_USAGE" "unknown argument: $1" ;;
    esac
done

hm_load_versions

inspect() {
    # Run a read-only inspection command; never fail the script.
    if [[ "$SHOW_COMMANDS" == "1" ]]; then
        printf 'read-only inspection: %s\n' "$(hm_quote_cmd "$@")" >&2
    fi
    "$@" 2>/dev/null || true
}

say() { printf '%s\n' "$*"; }

version_ge() {
    # version_ge A B — true when A >= B (dotted numeric versions).
    [[ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n 1)" == "$2" ]]
}

say "HappyMining OS — NVIDIA driver plan (prints only; changes nothing)"
say "policy: $NVIDIA_DRIVER_POLICY; minimum driver version: $NVIDIA_MIN_DRIVER_VERSION"
say ""

# ----- facts ----------------------------------------------------------------
os_version="unknown"
if [[ -r /etc/os-release ]]; then
    os_version="$(awk -F= '$1 == "VERSION_ID" { gsub(/"/, "", $2); print $2 }' /etc/os-release)"
fi
kernel="$(uname -r)"

gpu_lines=""
if hm_have lspci; then
    gpu_lines="$(inspect lspci -nn | grep -iE '(VGA|3D|Display).*NVIDIA' || true)"
fi

loaded_version=""
if [[ -r /proc/driver/nvidia/version ]]; then
    loaded_version="$(sed -nE 's/.*Kernel Module[^0-9]*([0-9]+(\.[0-9]+)+).*/\1/p' /proc/driver/nvidia/version | head -n 1)"
fi
smi_version=""
if hm_have nvidia-smi; then
    smi_version="$(inspect nvidia-smi --query-gpu=driver_version --format=csv,noheader | head -n 1 | tr -d '[:space:]')"
fi

pkg_lines=""
if hm_have dpkg-query; then
    # shellcheck disable=SC2016  # dpkg-query format string, not a shell expansion
    pkg_lines="$(inspect dpkg-query -W -f='${db:Status-Abbrev} ${Package} ${Version}\n' 'nvidia-driver-*' 'nvidia-headless-*' 'linux-modules-nvidia-*' 'nvidia-dkms-*' | awk '$1 == "ii" { print "  " $2 " " $3 }')"
fi

recommended=""
if hm_have ubuntu-drivers; then
    recommended="$(inspect ubuntu-drivers list --gpgpu)"
fi

holds=""
if hm_have apt-mark; then
    holds="$(inspect apt-mark showhold | grep -E '^(nvidia|libnvidia|linux-)' || true)"
fi

secure_boot="unknown"
if hm_have mokutil; then
    case "$(inspect mokutil --sb-state)" in
        *enabled*) secure_boot="enabled" ;;
        *disabled*) secure_boot="disabled" ;;
    esac
fi

vast_present=0
if [[ -d /var/lib/vastai_kaalia || -f /etc/systemd/system/vastai.service ]]; then
    vast_present=1
fi

say "Facts found on this machine:"
say "  Ubuntu release:            $os_version (supported: $SUPPORTED_UBUNTU_VERSIONS)"
say "  running kernel:            $kernel"
if [[ -n "$gpu_lines" ]]; then
    say "  NVIDIA devices (lspci):"
    while IFS= read -r l; do say "    $l"; done <<<"$gpu_lines"
elif hm_have lspci; then
    say "  NVIDIA devices (lspci):    none found"
else
    say "  NVIDIA devices (lspci):    lspci is not available; not checked"
fi
say "  loaded kernel module:      ${loaded_version:-none}"
say "  nvidia-smi driver version: ${smi_version:-not available}"
if [[ -n "$pkg_lines" ]]; then
    say "  NVIDIA driver packages from APT:"
    say "$pkg_lines"
else
    say "  NVIDIA driver packages from APT: none"
fi
if hm_have ubuntu-drivers; then
    say "  'ubuntu-drivers list --gpgpu' offers:"
    if [[ -n "$recommended" ]]; then
        while IFS= read -r l; do say "    $l"; done <<<"$recommended"
    else
        say "    (nothing)"
    fi
else
    say "  ubuntu-drivers:            not available (package ubuntu-drivers-common)"
fi
say "  held packages (nvidia/linux): ${holds:-none}"
say "  Secure Boot:               $secure_boot"
say "  Vast host software:        $([[ "$vast_present" == "1" ]] && echo present || echo 'not present')"
say ""

# ----- recommendation ---------------------------------------------------------
current="${loaded_version:-$smi_version}"
say "Recommendation:"
if [[ -z "$gpu_lines" && -z "$current" ]] && hm_have lspci; then
    say "  No NVIDIA GPU was found. No driver action is recommended on this machine."
elif [[ -n "$current" ]] && version_ge "$current" "$NVIDIA_MIN_DRIVER_VERSION"; then
    say "  KEEP the present driver ($current). It meets the minimum ($NVIDIA_MIN_DRIVER_VERSION,"
    say "  the lowest driver for CUDA 11.8, which is Vast's minimum CUDA version)."
    if [[ -z "$pkg_lines" ]]; then
        say "  Note: the driver does not come from Ubuntu packages (probably NVIDIA's .run"
        say "  installer). Do not mix the two methods: either keep it as it is, or plan a"
        say "  full replacement in a maintenance window."
    fi
    say "  Check that this branch is still supported by NVIDIA for your GPU model; Vast"
    say "  asks for \"a currently supported release for your GPU\"."
elif [[ -n "$current" ]]; then
    say "  PLAN A DRIVER UPDATE. The present driver ($current) is older than the minimum"
    say "  ($NVIDIA_MIN_DRIVER_VERSION). Do it in a scheduled maintenance window (see below)."
else
    say "  PLAN A DRIVER INSTALLATION before listing this machine. No NVIDIA driver is loaded."
fi
say ""
say "How, when a change is needed (a human runs this, in a maintenance window):"
say "  1. Policy '$NVIDIA_DRIVER_POLICY': take the '-server' branch that Ubuntu offers for"
say "     this GPU, from the Ubuntu archive — not 'the newest', not a PPA:"
say "         sudo ubuntu-drivers list --gpgpu"
say "         sudo ubuntu-drivers install --gpgpu nvidia:<BRANCH>-server"
say "     (source: https://ubuntu.com/server/docs/how-to/graphics/install-nvidia-drivers/)"
say "  2. The chosen branch must be >= $NVIDIA_MIN_DRIVER_VERSION."
say "  3. Restart the machine afterwards and check 'nvidia-smi' lists every GPU."
say ""
say "Before any change:"
if [[ "$vast_present" == "1" ]]; then
    say "  * The Vast host software is present. A driver change breaks GPU access in running"
    say "    customer instances and needs a restart that stops every instance."
    say "    Request maintenance through HappyMining first; the maintenance gate checks the"
    say "    Vast rental state. Zero GPU utilisation is NOT proof that the machine is idle,"
    say "    and unlisting does NOT end existing rentals. See docs/os-maintenance.md."
else
    say "  * The Vast host software is not present yet. The Vast installer has options that"
    say "    concern the driver (--no-driver: 'assume nvidia driver is installed'). If you"
    say "    install the driver from Ubuntu packages first, read Vast's host setup guide"
    say "    (https://cloud.vast.ai/host/setup/) before you run their installer, so that"
    say "    two installation methods are not mixed."
fi
if [[ "$secure_boot" == "enabled" ]]; then
    say "  * Secure Boot is ENABLED. Vast's verification requirements list 'Secure Boot:"
    say "    Disabled'. Changing it is a firmware setting and a manual decision."
fi
say ""
say "This script changed nothing."
