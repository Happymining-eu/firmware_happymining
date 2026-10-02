# QEMU smoke test of the HappyMining OS image

`os/smoke/qemu-smoke.sh` installs the built ISO into a disposable virtual
machine and checks the installed system over SSH.

> **Not run yet.** The development sandbox has no QEMU, no OVMF, no KVM and no
> built ISO. The script's argument handling and its `--dry-run` output are
> tested in `tests/os/test_smoke_and_misc.py`; the installation itself has
> never been executed. Run it on a build host before any image leaves the
> building.

## Requirements on the build host

Ubuntu 22.04 or 24.04 with:

```sh
sudo apt-get install qemu-system-x86 qemu-utils ovmf xorriso openssh-client python3-yaml python3-jsonschema
```

and the ISO from `os/image/build-installer.sh`
(`dist/happymining-os-<agent version>-ubuntu-<point release>-amd64.iso`), about
12 GB of free disk space and 4 GB of free memory. When QEMU, OVMF, the ISO or
another tool is missing, the script names what is missing and exits with code
**77** ("skipped: prerequisite not available").

## Running it

```sh
os/smoke/qemu-smoke.sh --dry-run          # prints the QEMU command lines and the checks
os/smoke/qemu-smoke.sh                    # one VM
os/smoke/qemu-smoke.sh --second-vm        # two VMs, also checks that identities differ
os/smoke/qemu-smoke.sh --keep --workdir /var/tmp/hm-smoke   # keep disk images and serial logs
os/smoke/qemu-smoke.sh --grub-screenshot  # also saves a picture of the ISO's boot menu
```

## What it does

1. Creates a temporary working directory (mode 0700) with a blank 40 GB qcow2
   disk and a **throwaway** ed25519 SSH key pair. The key exists only for this
   run and is deleted at the end, also with `--keep`. A generated key is
   acceptable here because the VM is disposable; nothing like it is used for
   real machines.
2. Renders a per-VM seed with `os/autoinstall/render-seed.sh` for
   `/dev/disk/by-id/virtio-HMSMOKE0001`. The disk is a virtio disk whose serial
   is set on the QEMU command line (`-device virtio-blk-pci,serial=HMSMOKE0001`),
   so the seed's `match: {serial: HMSMOKE0001}` and the disk guard see the same
   value a real machine would provide through udev.
3. Boots under UEFI (OVMF, `-machine q35`) with a serial console logged to a
   file. Kernel and initrd are taken from the ISO and started directly with
   `-kernel/-initrd -append 'autoinstall console=ttyS0,115200n8'`; the ISO is
   attached as CD-ROM and the seed as a CIDATA volume. This is the method of
   Subiquity's own quick start. The `autoinstall` keyword pre-confirms the
   installation; it is given here on the QEMU command line for a disposable VM
   and is never part of the image.
4. Waits for the installer to finish and restart (QEMU runs with `-no-reboot`
   and exits). Timeout: 3600 s with KVM, 14400 s without.
5. Boots the installed disk under UEFI with a forwarded SSH port and waits for
   a key login (timeout 600 s with KVM, 2400 s without).
6. Asserts over SSH:
   - `VERSION_ID` is the pinned Ubuntu release;
   - `happymining-agent` is installed in the pinned version;
   - `happymining-firstboot` ran: `/var/lib/happymining/identity` exists;
   - `happymining-agent.service` is enabled, there is no device credential and
     `happyminingctl status` reports the unpaired state;
   - `happyminingctl preflight --offline` runs, exits 0 or 1, and reports the
     missing GPU as WARN or FAIL (a VM has no GPU; a crash would be a failure);
   - `sshd` has `PasswordAuthentication no`, the account's password is locked,
     and a login without the key is refused;
   - `/var/lib/docker` is xfs with project quota;
   - no Docker, containerd or NVIDIA package was installed;
   - hostname, console banner and patch-policy files are as expected;
   - with `--second-vm`: SSH host key, machine-id and HappyMining identity
     differ between two installations.

## Expected duration

- With KVM (`/dev/kvm` usable): roughly 10 to 20 minutes per VM, mostly the
  installer copying the system and applying security updates. This is an
  estimate; it has not been measured yet.
- Without KVM the script falls back to software emulation (TCG, `-accel tcg`,
  `-cpu max`) and says so. Expect one to three hours per VM, and raise
  `--timeout-install` if the host is slow. TCG proves the same things as KVM,
  only slower.

## What a passing smoke test does NOT prove

A VM smoke test says nothing about:

- **real GPUs**: detection, VRAM, PCIe bandwidth, power, temperatures;
- **NVIDIA drivers**: none is installed in the VM, and the image installs none;
- **Vast verification** or the Vast self-test, the Vast host installer, port
  forwarding, public reachability, network speed;
- **bare-metal firmware**: Secure Boot state, IOMMU settings, vendor UEFI
  quirks, BMC behaviour, real NVMe/SATA by-id names and serials;
- the ISO's own boot loader path. The test starts the kernel directly, so the
  GRUB menu of the ISO is not exercised. `--grub-screenshot` saves a picture of
  the menu for a person to look at; booting a real machine (or a VM without
  `-kernel`) from the medium remains a manual check;
- the generic, interactive path. It needs a person at the installer UI.

Those need a physical test machine and are reported separately.
