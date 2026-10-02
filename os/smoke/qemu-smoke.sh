#!/usr/bin/env bash
#
# HappyMining OS — QEMU smoke test of the installation image.
#
# On a build host with QEMU it:
#   1. creates a blank qcow2 disk and a throwaway per-VM seed (render-seed.sh)
#      with a throwaway SSH key generated in a temporary directory;
#   2. boots the kernel and initrd taken from the built ISO under UEFI (OVMF),
#      with the ISO attached as CD-ROM, the seed attached as a CIDATA volume
#      and a serial console; the disk is a virtio disk whose serial is set on
#      the QEMU command line and matched by the seed;
#   3. waits (with a timeout) for the installer to finish and restart;
#   4. boots the installed disk under UEFI and checks the result over SSH;
#   5. deletes the throwaway key and, unless --keep is given, everything else.
#
# The kernel parameter that pre-confirms an automatic installation is passed
# here on the QEMU command line, for a disposable VM only. It is never in the
# image (see os/README.md).
#
# What this proves and what it does not: os/smoke/README.md.
# Exit codes: 0 all checks passed, 1 a check failed, 2 usage,
# 77 skipped: QEMU, OVMF, the ISO or another prerequisite is not available.

set -euo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
OS_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
REPO_DIR="$(cd -- "$OS_DIR/.." && pwd)"
HM_PROG="qemu-smoke.sh"
# shellcheck source=os/install/lib.sh
. "$OS_DIR/install/lib.sh"
hm_load_versions

ISO="$REPO_DIR/dist/happymining-os-${AGENT_VERSION}-ubuntu-${UBUNTU_POINT_RELEASE}-${UBUNTU_ARCH}.iso"
WORKDIR=""
KEEP=0
SECOND_VM=0
MEMORY_MB=4096
CPUS=2
DISK_SIZE="40G"
SSH_PORT=2222
TIMEOUT_INSTALL=""
TIMEOUT_BOOT=""
OVMF_CODE=""
OVMF_VARS=""
GRUB_SCREENSHOT=0
UNPAIRED_REGEX="${HM_SMOKE_UNPAIRED_REGEX:-unpaired|not paired}"
VM_USER="hmadmin"

usage() {
    cat <<USAGE
Usage: qemu-smoke.sh [options]

  --iso FILE             ISO to test (default: dist/happymining-os-${AGENT_VERSION}-ubuntu-${UBUNTU_POINT_RELEASE}-${UBUNTU_ARCH}.iso)
  --workdir DIR          working directory (default: a new temporary directory;
                         about 12 GB of free space are needed)
  --keep                 keep disk images and logs afterwards (the throwaway SSH
                         private key is deleted in every case)
  --second-vm            install a second VM and check that SSH host keys,
                         machine-id and HappyMining identity differ
  --memory MB            guest memory (default 4096)
  --cpus N               guest CPUs (default 2)
  --ssh-port PORT        first host port forwarded to guest port 22 (default 2222;
                         the second VM uses PORT+1)
  --timeout-install SEC  installer timeout (default 3600 with KVM, 14400 without)
  --timeout-boot SEC     first-boot/SSH timeout (default 600 with KVM, 2400 without)
  --ovmf-code FILE       OVMF firmware code image (default: searched in /usr/share)
  --ovmf-vars FILE       OVMF variable store template
  --grub-screenshot      additionally boot the ISO through its own boot loader
                         for 40 seconds and save a screenshot of the menu
                         (grub-menu.ppm, for a person to look at; not asserted)
  --dry-run              print the QEMU command lines and the checks; run nothing
  -h, --help             this text

Exit codes: 0 passed, 1 failed, 2 usage, 77 skipped (prerequisite not available).
USAGE
}

need_value() { [[ $# -ge 2 ]] || hm_die "$HM_EXIT_USAGE" "$1 needs a value"; }
while [[ $# -gt 0 ]]; do
    case "$1" in
        --iso) need_value "$@"; ISO="$2"; shift 2 ;;
        --workdir) need_value "$@"; WORKDIR="$2"; shift 2 ;;
        --keep) KEEP=1; shift ;;
        --second-vm) SECOND_VM=1; shift ;;
        --memory) need_value "$@"; MEMORY_MB="$2"; shift 2 ;;
        --cpus) need_value "$@"; CPUS="$2"; shift 2 ;;
        --ssh-port) need_value "$@"; SSH_PORT="$2"; shift 2 ;;
        --timeout-install) need_value "$@"; TIMEOUT_INSTALL="$2"; shift 2 ;;
        --timeout-boot) need_value "$@"; TIMEOUT_BOOT="$2"; shift 2 ;;
        --ovmf-code) need_value "$@"; OVMF_CODE="$2"; shift 2 ;;
        --ovmf-vars) need_value "$@"; OVMF_VARS="$2"; shift 2 ;;
        --grub-screenshot) GRUB_SCREENSHOT=1; shift ;;
        --dry-run) HM_DRY_RUN=1; shift ;;
        -h | --help) usage; exit 0 ;;
        *) usage >&2; hm_die "$HM_EXIT_USAGE" "unknown argument: $1" ;;
    esac
done
for n in "$MEMORY_MB" "$CPUS" "$SSH_PORT"; do
    [[ "$n" =~ ^[1-9][0-9]*$ ]] || hm_die "$HM_EXIT_USAGE" "--memory, --cpus and --ssh-port take positive integers"
done
for n in "$TIMEOUT_INSTALL" "$TIMEOUT_BOOT"; do
    [[ -z "$n" || "$n" =~ ^[1-9][0-9]*$ ]] || hm_die "$HM_EXIT_USAGE" "timeouts are whole seconds"
done

# ----- acceleration -----------------------------------------------------------
if [[ -r /dev/kvm && -w /dev/kvm ]]; then
    ACCEL="kvm"
    CPU_MODEL="host"
    : "${TIMEOUT_INSTALL:=3600}"
    : "${TIMEOUT_BOOT:=600}"
else
    ACCEL="tcg"
    CPU_MODEL="max"
    : "${TIMEOUT_INSTALL:=14400}"
    : "${TIMEOUT_BOOT:=2400}"
fi

# ----- firmware ------------------------------------------------------------------
find_ovmf() {
    local pair code vars
    for pair in \
        "/usr/share/OVMF/OVMF_CODE_4M.fd:/usr/share/OVMF/OVMF_VARS_4M.fd" \
        "/usr/share/OVMF/OVMF_CODE.fd:/usr/share/OVMF/OVMF_VARS.fd" \
        "/usr/share/edk2/ovmf/OVMF_CODE.fd:/usr/share/edk2/ovmf/OVMF_VARS.fd" \
        "/usr/share/edk2/x64/OVMF_CODE.4m.fd:/usr/share/edk2/x64/OVMF_VARS.4m.fd"; do
        code="${pair%%:*}"
        vars="${pair##*:}"
        if [[ -r "$code" && -r "$vars" ]]; then
            OVMF_CODE="$code"
            OVMF_VARS="$vars"
            return 0
        fi
    done
    return 1
}
ovmf_found=1
if [[ -z "$OVMF_CODE" || -z "$OVMF_VARS" ]]; then
    find_ovmf || ovmf_found=0
elif [[ ! -r "$OVMF_CODE" || ! -r "$OVMF_VARS" ]]; then
    ovmf_found=0
fi

# ----- command lines (also printed by --dry-run) ----------------------------------
vm_serial() { printf 'HMSMOKE%04d' "$1"; }
vm_port() { printf '%s' "$((SSH_PORT + $1 - 1))"; }

qemu_common() {
    # qemu_common VM_INDEX NAME — arguments shared by the install and run phases.
    local i="$1" name="$2"
    QEMU_ARGS=(
        qemu-system-x86_64
        -name "$name"
        -machine "q35,accel=$ACCEL"
        -cpu "$CPU_MODEL"
        -smp "$CPUS"
        -m "$MEMORY_MB"
        -drive "if=pflash,format=raw,readonly=on,file=${OVMF_CODE:-<OVMF_CODE.fd>}"
        -drive "if=pflash,format=raw,file=$W/vm$i-vars.fd"
        -drive "file=$W/vm$i-disk.qcow2,if=none,id=hd0,format=qcow2"
        -device "virtio-blk-pci,drive=hd0,serial=$(vm_serial "$i"),bootindex=1"
        -display none
    )
}

qemu_install_cmd() {
    local i="$1"
    qemu_common "$i" "hm-smoke-install-$i"
    QEMU_ARGS+=(
        -drive "file=$ISO,if=none,id=cd0,media=cdrom,format=raw,readonly=on"
        -device "ide-cd,drive=cd0"
        -drive "file=$W/vm$i-seed.iso,if=none,id=seed0,format=raw,readonly=on"
        -device "virtio-blk-pci,drive=seed0,serial=HMSEED$i"
        -nic "user,model=virtio-net-pci"
        -kernel "$W/vmlinuz"
        -initrd "$W/initrd"
        -append "autoinstall console=ttyS0,115200n8"
        -serial "file:$W/vm$i-install-serial.log"
        -no-reboot
    )
}

qemu_run_cmd() {
    local i="$1"
    qemu_common "$i" "hm-smoke-run-$i"
    QEMU_ARGS+=(
        -nic "user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:$(vm_port "$i")-:22"
        -serial "file:$W/vm$i-boot-serial.log"
        -daemonize
        -pidfile "$W/vm$i-qemu.pid"
    )
}

CHECKS=(
    "os-release VERSION_ID is $UBUNTU_RELEASE"
    "package $AGENT_PACKAGE is installed, version $AGENT_VERSION"
    "happymining-firstboot ran: /var/lib/happymining/identity exists and is not empty"
    "happymining-agent.service is enabled"
    "agent is unpaired: no /var/lib/happymining/credential.json, and 'happyminingctl status' says so"
    "'happyminingctl preflight --offline' runs (exit 0 or 1) and reports the missing GPU as WARN or FAIL"
    "SSH password login is refused; the account's password is locked"
    "data filesystem: $VAST_DOCKER_DATA_MOUNT is $VAST_DOCKER_DATA_FS with project quota"
    "no Docker, containerd or NVIDIA package was installed by the image"
    "hostname is the one in the seed; console banner and patch policy files are present"
)

if [[ "$HM_DRY_RUN" == "1" ]]; then
    W='<workdir>'
    hm_log "DRY RUN: nothing is started"
    missing=()
    for tool in qemu-system-x86_64 qemu-img xorriso ssh ssh-keygen python3 timeout; do
        hm_have "$tool" || missing+=("$tool")
    done
    [[ "$ovmf_found" == "1" ]] || missing+=("OVMF firmware (package ovmf)")
    [[ -f "$ISO" ]] || missing+=("ISO $ISO")
    if [[ ${#missing[@]} -gt 0 ]]; then
        hm_warn "not available on this host (a real run would exit $HM_EXIT_SKIP): ${missing[*]}"
    fi
    printf 'acceleration: %s (install timeout %ss, boot timeout %ss)\n' "$ACCEL" "$TIMEOUT_INSTALL" "$TIMEOUT_BOOT"
    printf 'DRY-RUN would run: %s\n' "$(hm_quote_cmd ssh-keygen -q -t ed25519 -N '' -C hm-smoke-throwaway -f "$W/throwaway_key")"
    printf 'DRY-RUN would run: %s\n' "$(hm_quote_cmd xorriso -osirrox on -indev "$ISO" -extract /casper/vmlinuz "$W/vmlinuz" -extract /casper/initrd "$W/initrd")"
    vms=(1)
    [[ "$SECOND_VM" != "1" ]] || vms=(1 2)
    for i in "${vms[@]}"; do
        printf 'DRY-RUN would run: %s\n' "$(hm_quote_cmd qemu-img create -f qcow2 "$W/vm$i-disk.qcow2" "$DISK_SIZE")"
        printf 'DRY-RUN would run: %s\n' "$(hm_quote_cmd "$OS_DIR/autoinstall/render-seed.sh" --disk-by-id "/dev/disk/by-id/virtio-$(vm_serial "$i")" --disk-serial "$(vm_serial "$i")" --confirm-erase "/dev/disk/by-id/virtio-$(vm_serial "$i")" --yes-i-have-read-the-plan --ssh-authorized-key-file "$W/throwaway_key.pub" --hostname "hm-smoke-$i" --root-size 12G --min-data-size 8G --out "$W/vm$i-seed")"
        printf 'DRY-RUN would run: %s\n' "$(hm_quote_cmd "$OS_DIR/autoinstall/make-seed-volume.sh" --seed-dir "$W/vm$i-seed" --out "$W/vm$i-seed.iso")"
        qemu_install_cmd "$i"
        printf 'DRY-RUN would run (install, at most %ss): %s\n' "$TIMEOUT_INSTALL" "$(hm_quote_cmd timeout "$TIMEOUT_INSTALL" "${QEMU_ARGS[@]}")"
        qemu_run_cmd "$i"
        printf 'DRY-RUN would run (boot installed disk): %s\n' "$(hm_quote_cmd "${QEMU_ARGS[@]}")"
    done
    printf 'Checks over SSH (%s@127.0.0.1, key login):\n' "$VM_USER"
    for c in "${CHECKS[@]}"; do printf '  - %s\n' "$c"; done
    [[ "$SECOND_VM" != "1" ]] || printf '  - second VM: SSH host key, machine-id and HappyMining identity differ from the first\n'
    exit 0
fi

# ----- prerequisites ------------------------------------------------------------------
hm_need_tools qemu-system-x86_64 qemu-img xorriso ssh ssh-keygen python3 timeout
if [[ "$ovmf_found" != "1" ]]; then
    hm_err "prerequisite not available: OVMF UEFI firmware (package ovmf), or pass --ovmf-code/--ovmf-vars"
    exit "$HM_EXIT_SKIP"
fi
if [[ ! -f "$ISO" ]]; then
    hm_err "prerequisite not available: ISO $ISO (build it with os/image/build-installer.sh)"
    exit "$HM_EXIT_SKIP"
fi
if [[ "$ACCEL" == "tcg" ]]; then
    hm_banner "No KVM on this host: using software emulation (TCG)." \
        "Expect the installation to take one to three hours instead of about fifteen minutes."
fi

if [[ -z "$WORKDIR" ]]; then
    W="$(mktemp -d "${TMPDIR:-/tmp}/hm-smoke.XXXXXXXX")"
else
    mkdir -p -- "$WORKDIR"
    W="$(cd -- "$WORKDIR" && pwd)"
    case "$W/" in
        "$OS_DIR"/* | "$REPO_DIR/dist"/*)
            hm_die "$HM_EXIT_USAGE" "--workdir must be outside os/ and dist/ (it holds a per-VM seed and a throwaway key)"
            ;;
    esac
fi
chmod 0700 -- "$W"

FAILED=0
PIDFILES=()
# shellcheck disable=SC2329  # invoked through the EXIT trap
cleanup() {
    local pf pid
    for pf in "${PIDFILES[@]}"; do
        if [[ -f "$pf" ]]; then
            pid="$(cat -- "$pf" 2>/dev/null || true)"
            if [[ "$pid" =~ ^[0-9]+$ ]]; then
                kill "$pid" 2>/dev/null || true
            fi
        fi
    done
    # The throwaway key never outlives the run.
    rm -f -- "$W/throwaway_key" "$W/throwaway_key.pub"
    rm -rf -- "$W"/vm*-seed
    if [[ "$KEEP" == "1" ]]; then
        hm_log "kept disk images and logs in $W (the throwaway key was deleted)"
    else
        rm -rf -- "$W"
    fi
}
trap cleanup EXIT

pass() { printf 'PASS  %s\n' "$*"; }
fail() {
    printf 'FAIL  %s\n' "$*"
    FAILED=1
}

ssh_opts=(
    -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
    -o IdentitiesOnly=yes -o ConnectTimeout=10 -o LogLevel=ERROR
)
vm_ssh() {
    # vm_ssh VM_INDEX COMMAND... — run a command in the VM with the throwaway key.
    local i="$1"
    shift
    ssh "${ssh_opts[@]}" -i "$W/throwaway_key" -p "$(vm_port "$i")" "$VM_USER@127.0.0.1" "$@"
}

# ----- shared preparation ------------------------------------------------------------------
ssh-keygen -q -t ed25519 -N '' -C hm-smoke-throwaway -f "$W/throwaway_key"
xorriso -osirrox on -indev "$ISO" -extract /casper/vmlinuz "$W/vmlinuz" -extract /casper/initrd "$W/initrd" \
    >"$W/xorriso.log" 2>&1 || hm_die "$HM_EXIT_FAIL" "could not read the kernel and initrd from $ISO (see $W/xorriso.log)"
chmod u+w -- "$W/vmlinuz" "$W/initrd"

if [[ "$GRUB_SCREENSHOT" == "1" ]]; then
    hm_log "booting the ISO through its own boot loader for a screenshot of the menu"
    cp -- "$OVMF_VARS" "$W/shot-vars.fd"
    (
        sleep 40
        printf 'screendump %s\nquit\n' "$W/grub-menu.ppm"
    ) | timeout 90 qemu-system-x86_64 -name hm-smoke-grub -machine "q35,accel=$ACCEL" -cpu "$CPU_MODEL" -m 2048 \
        -drive "if=pflash,format=raw,readonly=on,file=$OVMF_CODE" -drive "if=pflash,format=raw,file=$W/shot-vars.fd" \
        -drive "file=$ISO,if=none,id=cd0,media=cdrom,format=raw,readonly=on" -device "ide-cd,drive=cd0,bootindex=1" \
        -display none -monitor stdio >"$W/grub-shot.log" 2>&1 || true
    if [[ -s "$W/grub-menu.ppm" ]]; then
        cp -- "$W/grub-menu.ppm" "$PWD/grub-menu.ppm"
        hm_log "saved $PWD/grub-menu.ppm — look at it: 'Install HappyMining OS' must be the first entry (not asserted automatically)"
    else
        hm_warn "no screenshot was produced (see $W/grub-shot.log); this optional step is not a test result"
    fi
fi

install_vm() {
    local i="$1" serial rc=0
    serial="$(vm_serial "$i")"
    hm_log "VM $i: creating disk and throwaway seed (disk serial $serial)"
    qemu-img create -q -f qcow2 "$W/vm$i-disk.qcow2" "$DISK_SIZE"
    cp -- "$OVMF_VARS" "$W/vm$i-vars.fd"
    chmod u+w -- "$W/vm$i-vars.fd"
    "$OS_DIR/autoinstall/render-seed.sh" \
        --disk-by-id "/dev/disk/by-id/virtio-$serial" --disk-serial "$serial" \
        --confirm-erase "/dev/disk/by-id/virtio-$serial" --yes-i-have-read-the-plan \
        --ssh-authorized-key-file "$W/throwaway_key.pub" --hostname "hm-smoke-$i" \
        --root-size 12G --min-data-size 8G --out "$W/vm$i-seed" >"$W/vm$i-render.log" 2>&1 ||
        hm_die "$HM_EXIT_FAIL" "render-seed.sh failed (see $W/vm$i-render.log)"
    "$OS_DIR/autoinstall/make-seed-volume.sh" --seed-dir "$W/vm$i-seed" --out "$W/vm$i-seed.iso" >>"$W/vm$i-render.log" 2>&1 ||
        hm_die "$HM_EXIT_FAIL" "make-seed-volume.sh failed (see $W/vm$i-render.log)"

    qemu_install_cmd "$i"
    hm_log "VM $i: installing (timeout ${TIMEOUT_INSTALL}s, serial log $W/vm$i-install-serial.log)"
    timeout --signal=TERM "$TIMEOUT_INSTALL" "${QEMU_ARGS[@]}" >"$W/vm$i-qemu-install.log" 2>&1 || rc=$?
    if [[ "$rc" == "124" ]]; then
        fail "VM $i: the installer did not finish within ${TIMEOUT_INSTALL}s"
        grep -a -E 'HAPPYMINING DISK GUARD|Traceback|error|failed' "$W/vm$i-install-serial.log" | tail -n 20 || true
        return 1
    elif [[ "$rc" != "0" ]]; then
        fail "VM $i: QEMU exited with code $rc during the installation (see $W/vm$i-qemu-install.log)"
        return 1
    fi
    if grep -a -q 'HAPPYMINING DISK GUARD: REFUSING' "$W/vm$i-install-serial.log"; then
        fail "VM $i: the disk guard refused the installation"
        return 1
    fi
    pass "VM $i: installer finished and restarted the machine"
}

boot_vm() {
    local i="$1" waited=0
    qemu_run_cmd "$i"
    PIDFILES+=("$W/vm$i-qemu.pid")
    hm_log "VM $i: booting the installed disk; waiting for SSH on 127.0.0.1:$(vm_port "$i") (timeout ${TIMEOUT_BOOT}s)"
    "${QEMU_ARGS[@]}" >"$W/vm$i-qemu-run.log" 2>&1 ||
        hm_die "$HM_EXIT_FAIL" "QEMU could not start the installed system (see $W/vm$i-qemu-run.log)"
    until vm_ssh "$i" true 2>/dev/null; do
        sleep 10
        waited=$((waited + 10))
        if ((waited >= TIMEOUT_BOOT)); then
            fail "VM $i: no SSH login with the throwaway key within ${TIMEOUT_BOOT}s"
            return 1
        fi
    done
    # Let first-boot units settle.
    vm_ssh "$i" 'cloud-init status --wait >/dev/null 2>&1 || true; sudo systemctl is-system-running --wait >/dev/null 2>&1 || true' || true
    pass "VM $i: installed system booted under UEFI and accepts the SSH key"
}

check_vm() {
    local i="$1" out rc

    # shellcheck disable=SC2016  # expanded by the shell in the guest
    out="$(vm_ssh "$i" '. /etc/os-release; echo "$VERSION_ID"' || true)"
    if [[ "$out" == "$UBUNTU_RELEASE" ]]; then pass "VM $i: Ubuntu $out"; else fail "VM $i: VERSION_ID is '$out', expected $UBUNTU_RELEASE"; fi

    # shellcheck disable=SC2016  # expanded by dpkg-query in the guest
    out="$(vm_ssh "$i" "dpkg-query -W -f='\${Status} \${Version}' $AGENT_PACKAGE" || true)"
    if [[ "$out" == "install ok installed $AGENT_VERSION" ]]; then pass "VM $i: $AGENT_PACKAGE $AGENT_VERSION installed"; else fail "VM $i: package state is '$out'"; fi

    if vm_ssh "$i" 'sudo test -s /var/lib/happymining/identity'; then
        pass "VM $i: first boot created the device identity"
    else
        fail "VM $i: /var/lib/happymining/identity is missing or empty (happymining-firstboot did not run)"
        vm_ssh "$i" 'systemctl status happymining-firstboot.service --no-pager' || true
    fi

    out="$(vm_ssh "$i" 'systemctl is-enabled happymining-agent.service' || true)"
    if [[ "$out" == "enabled" ]]; then pass "VM $i: agent service enabled"; else fail "VM $i: agent service is '$out'"; fi

    if vm_ssh "$i" 'sudo test ! -e /var/lib/happymining/credential.json'; then
        pass "VM $i: no device credential (unpaired)"
    else
        fail "VM $i: a device credential exists on a freshly installed machine"
    fi
    out="$(vm_ssh "$i" 'sudo happyminingctl status 2>&1; echo "rc=$?"' || true)"
    rc="$(sed -n 's/^rc=//p' <<<"$out" | tail -n 1)"
    if [[ "$rc" =~ ^[0-9]+$ ]] && ((rc < 126)) && grep -Eiq -- "$UNPAIRED_REGEX" <<<"$out"; then
        pass "VM $i: 'happyminingctl status' reports the unpaired state"
    else
        fail "VM $i: 'happyminingctl status' did not report the unpaired state (exit ${rc:-?}): $(head -n 5 <<<"$out")"
    fi

    out="$(vm_ssh "$i" 'sudo happyminingctl preflight --offline 2>&1; echo "rc=$?"' || true)"
    rc="$(sed -n 's/^rc=//p' <<<"$out" | tail -n 1)"
    if [[ "$rc" == "0" || "$rc" == "1" ]] && grep -Eiq '^(WARN|FAIL).*(gpu|nvidia)' <<<"$out"; then
        pass "VM $i: preflight ran (exit $rc) and reports the missing GPU"
    else
        fail "VM $i: preflight --offline: exit '${rc:-?}', or no WARN/FAIL line about the GPU"
        head -n 30 <<<"$out"
    fi

    if vm_ssh "$i" "sudo sshd -T | grep -qi '^passwordauthentication no'"; then
        pass "VM $i: sshd has PasswordAuthentication no"
    else
        fail "VM $i: sshd allows password authentication"
    fi
    out="$(vm_ssh "$i" "sudo passwd -S $VM_USER | cut -d' ' -f2" || true)"
    if [[ "$out" == "L" ]]; then pass "VM $i: account password is locked"; else fail "VM $i: account password state is '$out', expected L"; fi
    if ssh "${ssh_opts[@]}" -o PreferredAuthentications=password -o PubkeyAuthentication=no \
        -p "$(vm_port "$i")" "$VM_USER@127.0.0.1" true 2>/dev/null; then
        fail "VM $i: a login without the key succeeded"
    else
        pass "VM $i: login without the key is refused"
    fi

    out="$(vm_ssh "$i" "findmnt -no FSTYPE,OPTIONS $VAST_DOCKER_DATA_MOUNT" || true)"
    if [[ "$out" == "$VAST_DOCKER_DATA_FS "* && "$out" == *prjquota* ]]; then
        pass "VM $i: $VAST_DOCKER_DATA_MOUNT is $VAST_DOCKER_DATA_FS with project quota"
    else
        fail "VM $i: $VAST_DOCKER_DATA_MOUNT mount is '$out'"
    fi

    out="$(vm_ssh "$i" "dpkg -l | awk '\$1 == \"ii\" && \$2 ~ /^(docker|containerd|nvidia|libnvidia)/ { print \$2 }'" || true)"
    if [[ -z "$out" ]]; then pass "VM $i: no Docker, containerd or NVIDIA package installed"; else fail "VM $i: unexpected packages: $out"; fi

    out="$(vm_ssh "$i" 'hostname' || true)"
    if [[ "$out" == "hm-smoke-$i" ]]; then pass "VM $i: hostname $out"; else fail "VM $i: hostname is '$out'"; fi
    if vm_ssh "$i" 'test -s /etc/issue.d/50-happymining-os.issue && test -s /etc/apt/apt.conf.d/52happymining-unattended-upgrades && test -s /etc/needrestart/conf.d/50-happymining.conf'; then
        pass "VM $i: console banner and patch policy files present"
    else
        fail "VM $i: console banner or patch policy file missing"
    fi
}

run_vm() {
    # Install, boot and check one VM; stop at the first phase that fails.
    local i="$1"
    install_vm "$i" || return 1
    boot_vm "$i" || return 1
    check_vm "$i"
}

run_vm 1 || FAILED=1

if [[ "$SECOND_VM" == "1" && "$FAILED" == "0" ]]; then
    run_vm 2 || FAILED=1
    if [[ "$FAILED" == "0" ]]; then
        for item in "SSH host key:cat /etc/ssh/ssh_host_ed25519_key.pub | cut -d' ' -f2" \
            "machine-id:cat /etc/machine-id" \
            "HappyMining identity:sudo sha256sum /var/lib/happymining/identity | cut -d' ' -f1"; do
            label="${item%%:*}"
            cmd="${item#*:}"
            a="$(vm_ssh 1 "$cmd" || true)"
            b="$(vm_ssh 2 "$cmd" || true)"
            if [[ -n "$a" && -n "$b" && "$a" != "$b" ]]; then
                pass "$label differs between the two VMs"
            else
                fail "$label is empty or identical on both VMs"
            fi
        done
    fi
fi

for i in 1 2; do
    if [[ -f "$W/vm$i-qemu.pid" ]]; then
        vm_ssh "$i" 'sudo systemctl poweroff' >/dev/null 2>&1 || true
    fi
done
sleep 5

printf '\n'
if [[ "$FAILED" == "0" ]]; then
    hm_log "SMOKE TEST PASSED (VM only: says nothing about real GPUs, drivers, Vast verification or bare-metal firmware)"
    exit 0
fi
hm_err "SMOKE TEST FAILED"
exit 1
