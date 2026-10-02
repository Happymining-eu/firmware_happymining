# HappyMining OS — installation tooling

HappyMining OS is Ubuntu Server plus the HappyMining monitoring agent, prepared
for machines that are hosted on Vast.ai. "Firmware" means this installation
image and the management software. Nothing here flashes a GPU BIOS, and
nothing here installs or replaces Vast's host software, Docker or NVIDIA
drivers: the local operator installs the official Vast host software, and
HappyMining only adds its agent.

> **Status of this directory.** The scripts are written and their logic is
> tested (`tests/os/`, see "Tests" below).
> The installation **ISO has not been built**
> and the QEMU **smoke test has not been run**:
> the development sandbox has no `xorriso`, no QEMU and no access to the Ubuntu
> ISO. Both need a normal Ubuntu build host. Until that has happened, treat the
> image path as untested.

**Base release: Ubuntu Server 24.04 LTS.** Vast's documentation lists "Ubuntu
Server 22.04 LTS, 24.04 LTS recommended", so 24.04 is the default and 22.04 is
the only other accepted release. The base release is one variable,
`UBUNTU_RELEASE` in [`versions.env`](versions.env).

## Two ways to install

| | A. Existing Ubuntu server | B. Dedicated empty machine |
|---|---|---|
| Tool | `install/install.sh` | HappyMining OS installation ISO |
| Touches disks | never | yes, after the operator chooses the disk |
| Who chooses the disk | nobody, nothing is repartitioned | the operator in the installer UI (generic image), or a per-machine seed that names one disk by id (opt-in) |
| Docker, NVIDIA, Vast | reported, left exactly as they are | not installed by the image; added later by the operator |

After either path: `sudo happyminingctl pair`, then
`happyminingctl vast-enroll-help` (the Vast enrolment is a local operator step).

### A. Non-destructive install on an existing supported Ubuntu server

```sh
# Files from the release: the .deb, SHA256SUMS, SHA256SUMS.gpg, the public key,
# and the install scripts bundle (happymining-install-scripts-<version>.tar.gz).
sudo ./install.sh --deb ./happymining-agent_0.1.0_amd64.deb \
                  --keyring ./happymining-release.pub.asc \
                  --dry-run            # shows everything, changes nothing
sudo ./install.sh --deb ./happymining-agent_0.1.0_amd64.deb \
                  --keyring ./happymining-release.pub.asc
```

Order of operations:

1. Self-guard: the script refuses to start if it, or `lib.sh`, contains a
   command from [`install/forbidden-commands.txt`](install/forbidden-commands.txt).
2. Refuses when not root (a `--dry-run` may run unprivileged).
3. Refuses anything that is not Ubuntu.
4. Verifies the package: sha256 against `SHA256SUMS` next to it, and the
   detached signature `SHA256SUMS.gpg` against `--keyring` (optionally pinned
   with `--expect-fingerprint`). Unsigned packages are refused;
   `--allow-unsigned-dev` exists for developer builds and prints a loud warning.
   A checksum mismatch or a bad signature is fatal in every mode. Only after
   that is the package opened; anything other than `happymining-agent` for this
   machine's architecture is refused.
5. Read-only inventory of Docker, the Vast host software, NVIDIA packages,
   kernels, `/etc/fstab`, netplan files, mounts.
6. Preflight **before anything is changed**: the package is unpacked with
   `dpkg-deb -x` into a private temporary directory and the `happyminingctl`
   found there runs `preflight`. The alternative, a first `dpkg -i` followed by
   the installed `happyminingctl`, would already have changed the machine
   (files, system user, units) before the checks had passed. A FAIL stops the
   installation with exit code 4. `--force-preflight` continues and is recorded
   in `/var/log/happymining/install.log`. A preflight that crashes is never
   overridable.
7. `dpkg --force-confold --force-confdef -i <deb>` (dpkg never stops to ask
   about a configuration file; a file the administrator changed is kept), after
   a copy of the package was put in `/var/cache/happymining/`.
8. `HM_API_URL` is written to `/etc/happymining/agent.env` only if `--api-url`
   was given **and** the key was not set before this run. A value an operator
   set earlier is never replaced; the default that ships in the package is.
9. Enables `happymining-firstboot.service` and `happymining-agent.service`.
10. Repeats the inventory of step 5 and fails loudly if anything differs.

The only thing written before the checks pass is the log file
`/var/log/happymining/install.log`.

What `install.sh`, `upgrade.sh` and `uninstall.sh` never do: change partitions,
filesystems, mounts or `/etc/fstab`; install, remove or replace Docker, NVIDIA
drivers, kernels or Vast software; change network or firewall configuration;
restart the machine. `tests/os/test_forbidden_commands.py` proves that none of
the forbidden commands appears in these scripts, and
`tests/os/test_install.py` runs a real `dpkg` installation into a fake system
tree with a fake Docker/Vast installation and compares every third-party file
before and after.

```sh
sudo ./upgrade.sh --deb ./happymining-agent_0.2.0_amd64.deb --keyring ./happymining-release.pub.asc
sudo ./upgrade.sh --rollback      # previous agent package from /var/cache/happymining/
sudo ./uninstall.sh               # removes only happymining-agent
./nvidia-driver-plan.sh           # PRINTS a driver recommendation; installs nothing
```

`upgrade.sh` preserves the device identity, the device credential and
`agent.env` (fingerprinted before, compared after, put back if the package
changed them). **Agent rollback does not roll back NVIDIA drivers, kernels,
Docker, the Vast host software or filesystem changes.** It reinstalls the
previous agent `.deb`, nothing more. See `docs/os-maintenance.md`.

`nvidia-driver-plan.sh` only prints. Driver changes stay a manual, scheduled
maintenance action because a driver change on a host with active rentals
breaks GPU access in running customer containers, and the restart it needs
stops every instance.

Exit codes of all scripts in `os/`: `0` done, `1` failure, `2` usage,
`3` signature or checksum verification failed, `4` preflight FAIL,
`5` safety refusal, `77` skipped because a prerequisite is not available.
Every script has `--dry-run` and `--help`.

### B1. Generic installation image (default)

The ISO is the official Ubuntu Server live ISO, repacked with:

- `/happymining/`: the agent package, the generic seed, a text banner, the
  patch-policy files, `SHA256SUMS` and `SHA256SUMS.gpg` (the staged tree and
  the unpacked contents of the agent package are scanned for secrets, and the
  build fails on any finding);
- two extra boot menu entries in `/boot/grub/grub.cfg`.

```sh
make build-agent                                   # colleague's target: dist/happymining-agent_0.1.0_amd64.deb
os/release/gen-dev-signing-key.sh                  # development key in .signing/ (never for production)
os/image/build-installer.sh --download --signing-key-home .signing
os/release/make-checksums.sh --signing-key-home .signing
os/smoke/qemu-smoke.sh
```

`build-installer.sh` always validates the autoinstall files and builds
`dist/happymining-seed-generic.tar.gz` and
`dist/happymining-install-scripts-<version>.tar.gz`. It builds the ISO only when
`xorriso`, a base ISO, the agent package and a signing choice are available.
Otherwise it lists exactly what was and was not produced and exits `77`, or `0`
only with `--allow-partial`.

Menu entry 1, **"Install HappyMining OS"**, boots the installer with
`ds=nocloud\;s=file:///cdrom/happymining/seed/`. That seed
([`autoinstall/user-data.generic.yaml`](autoinstall/user-data.generic.yaml))

- makes `storage`, `identity`, `network`, `keyboard` and `ssh` **interactive**:
  the Ubuntu installer UI asks which disk to use and which account to create;
- selects no disk and contains no password, SSH key, pairing code, API or Vast
  credential;
- installs the OpenSSH server (password login off by default), copies the agent
  package from the medium, installs it, enables the first-boot unit and puts a
  console message in `/etc/issue.d/`;
- is **not auto-confirming**: the kernel keyword `autoinstall` is not on the
  kernel command line, so the installer's own prompt
  "Continue with autoinstall? (yes|no)" remains. `validate.py` and
  `patch_grub.py` refuse any configuration that carries the keyword.

SSH on the generic path: the seed's default is "OpenSSH server installed,
password login off", but the SSH screen is interactive and the operator's
choice there wins. If no key is imported in the installer, add one after the
first console login and make sure password login is off before listing the
machine (Vast: "SSH keys only, password authentication disabled";
https://docs.vast.ai/host/disable-ssh-password-login). How exactly the
installer screen treats "no key imported" was not checked.

### B2. Per-machine unattended seed (opt-in, for a fleet operator)

```sh
# On the target machine (or from its inventory): find the stable name and ID_SERIAL
ls -l /dev/disk/by-id/
udevadm info --query=property --name=/dev/disk/by-id/nvme-Samsung_SSD_990_PRO_2TB_S7KHNJ0X123456 | grep '^ID_SERIAL='

# On the operator's workstation
os/autoinstall/render-seed.sh \
    --disk-by-id   /dev/disk/by-id/nvme-Samsung_SSD_990_PRO_2TB_S7KHNJ0X123456 \
    --disk-serial  Samsung_SSD_990_PRO_2TB_S7KHNJ0X123456 \
    --confirm-erase /dev/disk/by-id/nvme-Samsung_SSD_990_PRO_2TB_S7KHNJ0X123456 \
    --ssh-authorized-key-file ~/.ssh/gpu-01.pub \
    --hostname gpu-01 \
    --out ~/hm-seeds/gpu-01
os/autoinstall/make-seed-volume.sh --seed-dir ~/hm-seeds/gpu-01 --out ~/hm-seeds/gpu-01.iso
```

Boot the HappyMining OS medium with the seed volume (label `CIDATA`) attached
and choose menu entry 2, "Install HappyMining OS with a per-machine seed volume
(CIDATA)". The installer still asks for confirmation on the console.

Default partition plan (GPT, UEFI only):

| # | Size | Filesystem | Mount point | Purpose |
|---|---|---|---|---|
| 1 | 1G | fat32 | `/boot/efi` | EFI system partition |
| – | – | – | – | no separate `/boot` (no LVM, no encryption) |
| 2 | 100G (`--root-size`) | ext4 | `/` | operating system |
| 3 | remainder | xfs | `/var/lib/docker` | Docker / Vast instance storage, options `rw,auto,pquota` |

No swap. With `--data-disk-by-id`, `--data-disk-serial` and
`--confirm-erase-data-disk` the data filesystem goes on a second, dedicated
disk (also erased). Vast's requirement reads "Dedicated drive for Docker
container storage: 200 GB"; the script warns when the data filesystem shares
the system disk.

## Safety model for destructive installs

1. **Never "the first disk".** There is no default disk. `render-seed.sh`
   accepts only `/dev/disk/by-id/<bus>-<serial>` (`ata-`, `nvme-`, `scsi-`,
   `virtio-`). It refuses `/dev/sdX`, `/dev/nvmeXnY`, `/dev/vdX`, by-path,
   by-uuid, by-label, WWN/EUI names, partitions, wildcards, "first", "largest"
   and an empty value.
2. **Matching erase confirmation.** `--confirm-erase` must repeat the by-id
   string exactly.
3. **Plan before write.** The partition plan and the exact identifier that will
   be ERASED are printed before anything is written. Unless
   `--yes-i-have-read-the-plan` is given, the by-id name must be typed again
   interactively.
4. **How the disk is pinned in the installer.** Subiquity documents these disk
   match keys: `model`, `vendor`, `path`, `id_path`, `devpath`, `serial`, `ssd`,
   `size`, `install-media`. None of them is the `/dev/disk/by-id/` name:
   `path` is compared with the kernel path (`/dev/sda`), `id_path` with udev
   `ID_PATH`. The by-id name of a disk is `<bus>-<ID_SERIAL>` (systemd udev
   rules), and `serial` is compared with udev `ID_SERIAL`. Therefore the seed
   matches on `serial` (exact value, glob characters refused), the operator
   must pass `--disk-serial`, and the two must agree:
   by-id name = `<bus>-<serial>`.
5. **Guard in the installer.** The rendered seed embeds
   [`autoinstall/disk-guard.sh`](autoinstall/disk-guard.sh) in `early-commands`.
   It runs before the installer probes block devices and only reads. It aborts
   unless the machine booted in UEFI mode, the by-id name exists on that
   machine, resolves to a whole disk, has exactly the expected `ID_SERIAL`, is
   the only disk with that serial, is large enough for the plan and is not the
   installation medium.
6. **Still a confirmation prompt.** The image never carries the `autoinstall`
   kernel keyword. An operator who wants a zero-touch install adds it by hand
   for that one boot.
7. **Key-only account.** The only credential in a per-machine seed is the
   operator's own SSH public key. Private key files are refused, there is no
   password option, the account's password is locked, SSH password login is
   off. The account can use `sudo` without a password (as on Ubuntu cloud
   images); set a password after first login if your policy requires one.
   Vast asks for "A unique key pair per machine, never shared or reused".
8. **Per-machine seeds stay out of the image.** Output directories are `0700`,
   files `0600`; `render-seed.sh` and `make-seed-volume.sh` refuse output paths
   inside `os/` and `dist/`; the generic image is scanned for
   `authorized_keys` content, keys, hashes, tokens and pairing codes.
9. **Ordinary install and upgrade never repartition.** See path A.

## Unique identity on first boot, and cloned disks

Fresh Subiquity install (read from the Subiquity and cloud-init sources, not
boot-tested here; the smoke test checks it with `--second-vm`):

- `machine-id`: Subiquity writes the installer session's `/etc/machine-id`
  into the target (`write_files.etc_machine_id`); that id is created when the
  installer boots, so it differs per installation.
- SSH host keys: `openssh-server` is installed into the target during the
  installation, and on first boot cloud-init's `ssh` module removes
  `/etc/ssh/ssh_host_*key*` (`ssh_deletekeys`, default true) and creates new
  keys. No host key is in the image.
- HappyMining identity: `happymining-firstboot.service`
  (`ConditionPathExists=!/var/lib/happymining/identity`) creates it on first
  boot. The image carries none.

Cloning an **installed** disk copies all three. Before taking a clone image:

```sh
sudo os/firstboot/sanitize-clone.sh --root /mnt/image            # image mounted, not running
sudo os/firstboot/sanitize-clone.sh --i-am-preparing-a-clone-image   # paired source machine
```

It truncates `/etc/machine-id`, removes `/var/lib/dbus/machine-id`, removes the
SSH host keys and installs a small unit that recreates them on the next boot
(`ssh-keygen -A`), removes every file under `/var/lib/happymining/` (identity,
credential, journal, spool) so the clone must be paired again, clears
cloud-init instance state (`/var/lib/cloud/{instance,instances,data,sem}`) and
the systemd random seed. It refuses a paired system without
`--i-am-preparing-a-clone-image`, and refuses an image that contains the Vast
host software (its machine identity would be duplicated) unless
`--allow-vast-present` is given; Vast's files are never modified. It does not
call `cloud-init clean`, because that also removes the installer's cloud-init
configuration.

## Artifacts

| Artifact | Produced by | Built in the sandbox? |
|---|---|---|
| `dist/happymining-seed-generic.tar.gz` | `os/image/build-installer.sh` | yes, in a temporary directory by the tests |
| `dist/happymining-install-scripts-<ver>.tar.gz` | `os/image/build-installer.sh` | yes, in a temporary directory by the tests |
| `dist/happymining-os-<ver>-ubuntu-<point release>-amd64.iso` and `.buildinfo` | `os/image/build-iso.sh` | **no** (needs xorriso and the Ubuntu ISO) |
| `dist/SHA256SUMS`, `dist/SHA256SUMS.gpg` | `os/release/make-checksums.sh` | yes, in a temporary directory by the tests |
| `dist/happymining-dev-release.pub.asc`, `.signing/` | `os/release/gen-dev-signing-key.sh` | yes, in a temporary directory by the tests |
| `dist/happymining-agent_<ver>_amd64.deb` | `agent/scripts/build-deb.sh` (not part of `os/`) | – |

## Files

```
os/versions.env                      pinned release, key fingerprint, policies (with sources)
os/install/install.sh                non-destructive install
os/install/upgrade.sh                agent upgrade / rollback
os/install/uninstall.sh              removes only the agent package
os/install/nvidia-driver-plan.sh     prints a driver recommendation
os/install/lib.sh                    shared helpers (verification, guard, inventory)
os/install/forbidden-commands.txt    patterns that must never appear in the install path
os/autoinstall/user-data.generic.yaml       generic seed (interactive disk and account)
os/autoinstall/meta-data.generic
os/autoinstall/user-data.unattended.yaml.tmpl   per-machine seed template
os/autoinstall/render-seed.sh        renders a per-machine seed
os/autoinstall/render_template.py    strict template renderer
os/autoinstall/disk-guard.sh         read-only disk checks run inside the installer
os/autoinstall/make-seed-volume.sh   packs a seed as a CIDATA volume
os/autoinstall/validate.py           structural + official-schema validation
os/autoinstall/schema/               vendored Subiquity JSON schema and its provenance
os/firstboot/sanitize-clone.sh       makes an installed disk safe to clone
os/firstboot/happymining-regen-ssh-hostkeys.service
os/image/build-installer.sh          entry point for `make build-installer`
os/image/build-iso.sh                xorriso repack of the verified Ubuntu ISO
os/image/patch_grub.py               adds menu entries, updates md5sum.txt
os/image/secret_scan.py              secret scanner for distributed trees
os/image/branding/                   banner text and menu entry template
os/maintenance/                      patch policy files and opt-in script
os/release/make-checksums.sh         SHA256SUMS + detached signature
os/release/gen-dev-signing-key.sh    local development signing key
os/smoke/qemu-smoke.sh               VM smoke test
```

## Tests

```sh
pytest tests/os          # needs: bash, dpkg, gpg/gpgv, python3 with PyYAML and jsonschema
```

The suite shells out to the scripts with temporary directories, a fake system
root and stub tools on a temporary `PATH`. Tests that need a tool that is not
installed are skipped with the reason. No test partitions, formats or mounts
anything.

`tests/os/test_build_iso_flow.py` runs `build-iso.sh` with a **fake** xorriso
(`tests/os/fixtures/fake_xorriso.py`, which treats an "ISO" as a tar archive)
and a throwaway key in the role of Ubuntu's signing key. It tests the order of
the checks and the refusals of the build script. It is not evidence that real
xorriso produces a bootable image.

Not covered by the suite, and not run anywhere yet: building the ISO, booting
it, the installation itself, the first boot. Those are the QEMU smoke test's
job on a build host (`os/smoke/README.md`).

## Verified against

Access date for everything below: **2026-10-02**.

**Subiquity autoinstall.** Page named in the project brief:
https://canonical-subiquity.readthedocs-hosted.com/en/latest/tutorial/providing-autoinstall.html
and the reference
https://canonical-subiquity.readthedocs-hosted.com/en/latest/reference/autoinstall-reference.html .
The hosted pages could not be fetched in the development session (the fetch
needed an approval that was not available), so their **source files** were read
instead, from https://github.com/canonical/subiquity at commit
`088f26086964f35a623864d97aa0f138a710f0da` (2026-09-24):
`doc/tutorial/providing-autoinstall.rst`, `doc/reference/autoinstall-reference.rst`,
`doc/reference/autoinstall-schema.rst`, `doc/howto/autoinstall-quickstart.rst`,
`doc/explanation/zero-touch-autoinstall.rst`,
`doc/explanation/cloudinit-autoinstall-interaction.rst`, `autoinstall-schema.json`,
and for behaviour `subiquity/models/storage.py`, `subiquity/models/subiquity.py`.

- Delivery: cloud-config with a `#cloud-config` header and a top-level
  `autoinstall:` key, or an `autoinstall.yaml` on the installation medium (root
  of the medium, root of the installer's filesystem, or the kernel parameter
  `subiquity.autoinstallpath=`). Precedence: kernel command line, root of the
  installation system, cloud-config, root of the installation medium.
- `version`: integer, must be `1`. `interactive-sections`: list of section
  names (`*` for all); a value given for an interactive section is the default
  of that screen.
- `identity`: "the only configuration key that must be present (unless the
  user-data section is present)"; the schema requires `username`, `hostname`
  and `password`. That is why the unattended seed uses `user-data` instead.
- `ssh`: `install-server`, `authorized-keys`, `allow-pw` (default true when no
  key is given).
- `storage`: layouts `lvm`, `direct`, `zfs` (and `hybrid`); "By default, these
  layouts install to the largest disk in a system"; `match: {}` "matches an
  arbitrary disk"; action-based `config` is a superset of curtin's; sizes may
  be `1G`, a percentage, or `-1` for the rest.
- **Disk match keys that exist:** `model`, `vendor`, `path`, `id_path`,
  `devpath`, `serial`, `ssd`, `size` (`largest`|`smallest`), `install-media`.
  `serial` "matches a disk where `ID_SERIAL=value` in udev, supporting
  globbing"; `path` is compared with the kernel path (code:
  `fnmatch(disk.path, match["path"])`). Ordered lists of match specs exist
  since Subiquity 24.08.1 (not used).
- `packages`, `late-commands` ("run in the installer environment with the
  installed system mounted at `/target`", `curtin in-target --`),
  `error-commands`, `early-commands` (run "before probing for block and network
  devices"; a non-zero exit aborts), `shutdown` (`reboot`|`poweroff`),
  `refresh-installer` (`update`, `channel`), `updates` (`security`|`all`),
  `drivers.install`, `user-data` (cloud-config applied on first boot of the
  target).
- Confirmation: "The installer prompts for a confirmation before modifying the
  disk. To skip the need for a confirmation ... add the `autoinstall` parameter
  to the kernel command line." Prompt text: "Continue with autoinstall? (yes|no)".
- Quick start example for a VM: `-append 'autoinstall ds=nocloud-net;s=http://_gateway:3003/'`
  with `-kernel /mnt/casper/vmlinuz -initrd /mnt/casper/initrd` (the smoke test
  uses the same direct-kernel method).
- The official JSON schema is vendored verbatim in
  [`autoinstall/schema/`](autoinstall/schema/SOURCE.md).

**cloud-init NoCloud** (https://github.com/canonical/cloud-init at commit
`2e8bf860c16b3f2db200fbb3daee48d3932680bf`, `doc/rtd/reference/datasources/nocloud.rst`,
`cloudinit/sources/DataSourceNoCloud.py`, `cloudinit/config/schemas/schema-cloud-config-v1.json`):

- Volume: "A labeled vfat or iso9660 filesystem may be used. The filesystem
  volume must be labelled `CIDATA`." Files `user-data` and `meta-data` in its
  root; `meta-data` must contain an `instance-id`.
- **Kernel syntax:** `ds=nocloud;s=file:///path/to/directory/` ("A valid
  seedfrom value consists of a URI which must contain a trailing /"); "If using
  kernel command line arguments with GRUB, note that an unescaped semicolon is
  interpreted as the end of a statement", hence `ds=nocloud\;s=...` in
  `grub.cfg`. The code accepts seed locations that start with `/` or `file://`.
  The widely used `ds=nocloud;s=/cdrom/...` form is the same thing without the
  scheme; this project uses the documented `file://` form.
- A seed location on the kernel command line replaces the user-data of a
  CIDATA volume (menu entry 1 always uses the generic seed).
- User keys used by the unattended seed: `lock_passwd` ("Disable password
  login. Default: true"), `ssh_authorized_keys`, `sudo`, `ssh_pwauth`,
  `manage_etc_hosts`, `hostname`; `ssh_deletekeys` default true.

**curtin storage** (https://github.com/canonical/curtin at commit
`e2fc55b133be30aadf03e236edd3d18e6f5ce6c7`, `doc/topics/storage.rst`): `ptable`,
`wipe`, `grub_device`, partition `flag: boot` ("On gpt partition tables, the
boot flag sets partition type guid to the appropriate value for the EFI System
Partition"), `fstype` list including `ext4`, `fat32`, `xfs`, mount `options`.
The storage actions of the rendered seed were validated once against curtin's
own schema (`curtin.storage_config.validate_config`) after replacing the two
Subiquity extensions (`match`, `size: -1`) with plain values: both layouts pass.

**udev by-id names** (https://github.com/systemd/systemd at commit
`b43fed88efe34889a49a7710a92141849dc4906d`, `rules.d/60-persistent-storage.rules.in`):
`disk/by-id/nvme-$env{ID_SERIAL}`, `disk/by-id/virtio-$env{ID_SERIAL}`,
`disk/by-id/$env{ID_BUS}-$env{ID_SERIAL}`; `wwn-$env{ID_WWN_WITH_EXTENSION}` is a
different identity. (This is systemd's current tree; Ubuntu 24.04 ships an
older systemd with the same long-standing naming.)

**Vast.ai host requirements.**

- https://docs.vast.ai/host/verification-stages ("Minimum Requirements for
  Verification"): "Ubuntu Server 22.04 LTS, 24.04 LTS recommended"; "Use a
  server edition"; kernel at the "Latest security patch level for your Ubuntu
  release"; NVIDIA driver "A currently supported release for your GPU"; CUDA
  "11.8 or newer"; "SSH keys only, password authentication disabled"; "A unique
  key pair per machine, never shared or reused"; Secure Boot "Disabled";
  storage "SSD", "Dedicated drive for Docker container storage | 200 GB",
  "Root partition free space | 20 GB"; network 500 Mbps down and up, "Public
  IPv4 address", "5 ports per GPU, 100 ports per GPU recommended".
- https://docs.vast.ai/host/hosting-overview : the host setup guide is "the
  official documentation for setting up a machine"; unlisting "does not affect
  existing" contracts.
- https://docs.vast.ai/host/upgrade-kernel and
  https://docs.vast.ai/host/upgrade-docker-and-packages : "The steps are the
  same on Ubuntu Server 22.04 and 24.04"; maintenance window "at least 48 hours
  in advance"; `NEEDRESTART_MODE=l apt upgrade`; `daemon.json` must keep
  `runtimes.nvidia.path` pointing at `kaalia_docker_shim`.
- https://docs.vast.ai/host/disable-ssh-password-login : password login enabled
  "will not pass verification".
- The official host installer, https://console.vast.ai/install (redirects to
  https://s3.amazonaws.com/public.vast.ai/kaalia/scripts/vast_host_installer.py):
  `DOCKER_DIR_NOS = "/var/lib/docker"`; it requires that mount to be **xfs with
  `pquota`/`prjquota`** and writes `UUID="..." /var/lib/docker xfs rw,auto,pquota 0 0`;
  when `/var/lib/docker` is already in `/etc/fstab` as xfs with pquota it reuses
  it; `--docker-partition DEVICE` ("Empty partitions are formatted XFS; existing
  XFS partitions are reused; non-XFS partitions are rejected"); without it the
  installer may create a partition in unallocated space (`--no-partitioning`
  turns that off) or fall back to a loop file; it removes non-`docker-ce`
  Docker packages and installs `docker-ce` itself; `--no-driver` means "assume
  nvidia driver is installed". The script was read through a text extraction
  tool, not as a byte-exact local copy. The colleague's
  `docs/integration-evidence.md` reached the same findings independently.
  Consequences here: the image installs no Docker; the unattended seed creates
  `/var/lib/docker` as xfs with `rw,auto,pquota`, which that installer accepts
  as it is.

**Ubuntu.**

- https://releases.ubuntu.com/24.04/ : `ubuntu-24.04.5-live-server-amd64.iso`
  (2026-09-09), `SHA256SUMS`, `SHA256SUMS.gpg`.
- https://ubuntu.com/tutorials/how-to-verify-ubuntu : the CD image signing key
  `8439 38DF 228D 22F7 B374 2BC0 D94A A3F0 EFE2 1092`; the same key is in
  `/usr/share/keyrings/ubuntu-archive-keyring.gpg` of the `ubuntu-keyring`
  package ("Ubuntu CD Image Automatic Signing Key (2012) <cdimage@ubuntu.com>").
- https://ubuntu.com/server/docs/how-to/graphics/install-nvidia-drivers/ :
  `sudo ubuntu-drivers list --gpgpu`, `sudo ubuntu-drivers install --gpgpu`,
  `-server` (ERD) branches "recommended on servers and for computing tasks",
  pre-built signed modules preferred over DKMS.

**NVIDIA.** https://docs.nvidia.com/cuda/cuda-toolkit-release-notes/index.html :
CUDA 11.8 GA needs Linux driver `>=520.61.05` (used as `NVIDIA_MIN_DRIVER_VERSION`).

## Unverified

- **The ISO build has never been executed.** `xorriso -indev ... -outdev ...
  -boot_image any replay -map ...` is written from the xorriso manual as known
  to the author; the copy of the manual that could be fetched
  (https://www.gnu.org/software/xorriso/man_1_xorriso.html) was truncated and
  confirmed only `-indev`/`-outdev` modifying, `-map`, `-chown_r`, `-chgrp_r`
  and `-rm_r`. `-boot_image any replay`, `-osirrox on -extract` and
  `-report_el_torito plain` (including its output format, which the build uses
  to count boot images) are unverified.
- **The layout of the Ubuntu 24.04.5 ISO**: that `/boot/grub/grub.cfg` serves
  both BIOS and UEFI boot, that its first entry boots `/casper/vmlinuz` with
  `/casper/initrd`, and that `/md5sum.txt` exists. `build-iso.sh` reads the real
  files from the verified ISO and refuses an unknown layout; the test fixture
  is written from memory.
- Whether `/cdrom` is mounted early enough for `s=file:///cdrom/happymining/seed/`
  in every boot mode (Subiquity itself reads `/cdrom/...`; not boot-tested).
- Which Subiquity version the 24.04.5 ISO carries. The documentation read is
  "latest". The features used (serial match, action-based storage,
  early-commands, user-data, interactive sections) are old ones; this is still
  an assumption until the smoke test passes.
- That a fresh install gets a unique machine-id and unique SSH host keys: read
  from source code, not observed. `qemu-smoke.sh --second-vm` checks it.
- How the agent package's maintainer scripts behave under `curtin in-target`.
- The wording of Vast's host setup guide (https://cloud.vast.ai/host/setup/):
  the page is rendered by JavaScript and could not be read. Its storage, port
  and driver-installation instructions are known here only through the
  installer script and the other documentation pages. In particular the
  driver installation method Vast recommends, and what the installer does to
  drivers without `--no-driver`, are open.
- Behaviour of `unattended-upgrades` (`Package-Blacklist`) and `needrestart`
  (`conf.d`, `$nrconf{restart}`) on Ubuntu 24.04, and `/etc/issue.d` support in
  `agetty`: from general knowledge of these packages, not checked against a
  primary source today.
- That old point-release ISOs move to old-releases.ubuntu.com when a new one is
  published.
- Subiquity's own pre-validation script
  (`scripts/validate-autoinstall-user-data.py`) was not run: it needs the
  Subiquity development dependencies. Run it on a build host.

## Known limitations

- The image path is untested end to end (see the status note at the top).
- The unattended seed supports UEFI boot only, one system disk and optionally
  one data disk; no RAID, LVM, encryption or multipath. Use the generic image
  for anything else.
- `disk-guard.sh` refuses disks behind multipath (two block devices with the
  same serial) and by-id names that are not `<bus>-<ID_SERIAL>`.
- The agent package is delivered as a signed file, not from an APT repository
  (`docs/trust-chain.md`).
- The vendored autoinstall schema is part of Subiquity and licensed GPL-3.0
  (see `autoinstall/schema/SOURCE.md`). It is used only by `validate.py` on the
  build host and is not shipped in the image or the agent.
- The patch policy keeps automatic security updates for packages other than
  kernels, NVIDIA and the container runtime. Vast's hosting overview says to
  "disable auto-updates so that your machine doesn't drop a client job to
  update a driver". The policy excludes exactly the packages that could do
  that, but it is a HappyMining decision, not Vast's wording; see
  `docs/os-maintenance.md`.
