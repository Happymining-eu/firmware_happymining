# OS and driver maintenance on HappyMining OS hosts

Scope: security patching, kernel, NVIDIA driver and container-runtime
maintenance, and recovery, on machines that host Vast.ai rentals. Files:
`os/maintenance/`, `os/install/upgrade.sh`, `os/install/nvidia-driver-plan.sh`.

Status: the policy files and scripts exist and are tested for what they write
(`tests/os/test_smoke_and_misc.py`). The procedures below have **not** been
exercised on a real host, and the behaviour of `unattended-upgrades` and
`needrestart` on Ubuntu 24.04 is described from general knowledge of those
packages, not from a primary source checked today. Vast statements are quoted
from Vast's pages, either as read for this document on 2026-10-02
(verification-stages, upgrade-kernel, upgrade-docker-and-packages,
disable-ssh-password-login, hosting-overview) or as recorded with their source
in `docs/integration-evidence.md` (machine-offline, set-maintenance-window and
the contract rules).

## Principles

1. **A HappyMining outage never stops Vast hosting.** The agent observes and
   reports. Nothing in this document depends on the HappyMining API being up,
   except permission to start disruptive work.
2. **Nothing that can interrupt a rental happens automatically.** No automatic
   restart of the machine, the Docker daemon, the Vast daemon or the GPU driver.
3. **Disruptive work goes through the maintenance gate**, which looks at the
   Vast rental state, not at how busy the GPUs look.
4. **Security patching is scheduled, not abandoned.** What is excluded from
   automatic updates has a fixed place in a recurring maintenance window.
5. **Rollback claims are narrow.** `upgrade.sh --rollback` reinstalls the
   previous HappyMining agent package. It **does not roll back** NVIDIA
   drivers, kernels, Docker, the Vast host software, firmware settings or any
   filesystem change, and nothing in HappyMining can.

## 1. Scheduled security patching

| Package class | How it is patched | When |
|---|---|---|
| Ordinary packages (openssl, openssh, libc, sudo, ...) | `unattended-upgrades`, Ubuntu `-security` pocket | automatically, on Ubuntu's daily timers |
| Kernel (`linux-image-*`, `linux-headers-*`, `linux-modules-*`, meta packages) | by hand, section 3 | monthly window; sooner for an exploited vulnerability |
| NVIDIA driver (`nvidia-*`, `libnvidia-*`) | by hand, section 3 | monthly window, only when needed |
| Docker, containerd, runc | by hand, following Vast's upgrade guide | when Vast's guide or a security advisory requires it |
| HappyMining agent | `os/install/upgrade.sh` | any time; no restart of the machine, no effect on rentals |
| Vast host software | Vast's own mechanism | not managed by HappyMining |

The policy is two small files (installed by the HappyMining OS image; on an
existing server put them in place with the opt-in
`os/maintenance/apply-patch-policy.sh`, which copies the files and changes no
package):

- `/etc/apt/apt.conf.d/52happymining-unattended-upgrades` adds the kernel,
  NVIDIA and container-runtime packages to `Unattended-Upgrade::Package-Blacklist`
  and sets `Unattended-Upgrade::Automatic-Reboot "false"`.
- `/etc/needrestart/conf.d/50-happymining.conf` sets needrestart to list-only
  (`$nrconf{restart} = 'l'`), so a library update never restarts the Docker
  daemon or the Vast daemon on its own.

### Why kernel, NVIDIA and container packages are held back

- **NVIDIA.** Replacing the NVIDIA user-space libraries while the old kernel
  module is loaded produces a driver/library version mismatch: running
  customer containers keep working until they next initialise the GPU, new GPU
  initialisation fails, and the cure is a restart of the machine, which stops
  every instance. Vast: "Do not restart or modify NVIDIA drivers while active
  customer instances are running unless instructed by Support"
  (machine-offline), and from the upgrade guide: "GPUs are unusable from here
  until the reboot."
- **Kernel.** A new kernel does nothing until the machine restarts, and "a
  reboot stops every running instance on the machine" (upgrade-kernel). If the
  machine restarts unplanned (power loss) into a kernel for which the NVIDIA
  module was not built, the GPUs are gone and the machine is offline. The
  kernel and the driver are therefore changed together, in a window, with the
  previous kernel kept in the boot menu.
- **Docker / containerd.** "Every running container stops when Docker
  restarts" (upgrade-docker-and-packages). Vast's installer pins these
  packages and Vast's daemon re-applies its own `apt-mark` holds.

### How this relates to Vast's "disable auto-updates"

Vast's hosting overview says: "Make sure to disable auto-updates so that your
machine doesn't drop a client job to update a driver." Vast's verification
requirements also say the kernel must be at the "Latest security patch level
for your Ubuntu release" and that "Machines running a kernel with a known
exploited vulnerability are restricted on the marketplace and can lose
verification."

HappyMining's policy keeps automatic security updates only for packages whose
update cannot drop a job, and moves everything that can (driver, kernel,
container runtime, restarts) into scheduled windows. This is HappyMining's
reading, not Vast's wording. An operator who wants to follow Vast's sentence
literally can switch `unattended-upgrades` off completely
(`APT::Periodic::Unattended-Upgrade "0";`) and must then patch **all** packages
in the monthly window; the window is then mandatory, not optional.

### Checking the policy on a host

```sh
apt-config dump | grep -i 'Unattended-Upgrade::'      # blacklist and Automatic-Reboot "false"
sudo unattended-upgrade --dry-run -d 2>&1 | less      # what would be installed, what is skipped
ls -l /var/log/unattended-upgrades/
apt list --upgradable 2>/dev/null | grep -E '^(linux-|nvidia-|libnvidia-|docker-ce|containerd)'   # waiting for a window
apt-mark showhold                                     # Vast's holds
```

### Rhythm

- **Daily, automatic:** security updates of ordinary packages.
- **Weekly, by the operator:** look at what is waiting (`apt list --upgradable`)
  and at Ubuntu security notices for the kernel and at NVIDIA security
  bulletins. Decide whether the next window is enough.
- **Monthly, per machine:** a maintenance window for kernel, driver and
  container-runtime updates (section 3). No pending update: no window.
- **Out of band:** a kernel vulnerability that is being exploited does not
  wait for the monthly window. It still goes through section 3.

## 2. The maintenance gate

Any action that can interrupt a rental (restart, kernel, driver, Docker,
Vast daemon restart, storage work, reinstall) starts with a maintenance
request in HappyMining. The HappyMining API's **maintenance gate** decides from
the Vast rental state obtained through the provider adapter. The local
operator does not start before the gate has approved, and the gate checks
again immediately before the work.

Rules the gate applies, and that an operator must not shortcut:

- **Zero GPU utilisation is not proof of idleness.** A rented instance can sit
  idle, be loading data, or be stopped. Vast: "`Exited` still counts as a
  rental: the client keeps the disk and can restart it."
- **Unlisting does not end existing rentals.** Vast: "Unlisting the offer will
  prevent new rental contracts from being created, but does not affect
  existing ones." It is the supported way to stop new admissions, nothing more.
- **A Vast maintenance window is a notification, not an action.** "It does not
  stop instances, unlist the machine, or block new rentals."
- Active contracts, stopped instances and stored customer data are all
  obligations. "All rental contracts must be honored, you cannot take the
  machine offline until every active rental contract has ended."
- Customer workloads are never killed and customer storage is never deleted to
  make room for maintenance.
- If the rental state cannot be established (provider API unreachable, data
  stale, machine not bound), the answer is **no**, and a person at HappyMining
  handles it.

The agent's remote operations `reboot` and `restart_vast_daemon` are disabled
by default (`docs/agent-protocol.md`). In the pilot, maintenance is carried
out by the local operator at the machine or over SSH.

## 3. Controlled OS / driver maintenance procedure

1. **Request.** Open a maintenance request in HappyMining for the machine,
   stating what will change (kernel, driver branch, Docker) and when.
2. **Stop new admissions.** Unlist the machine on Vast through the supported
   control (`vastai unlist machine <id>` or the console), and confirm that the
   listing is gone. Existing rentals continue.
3. **Notify renters.** If anything is rented or stored, schedule a Vast
   maintenance window "at least 48 hours in advance" (Vast's kernel and Docker
   upgrade pages). Vast: "Work performed outside the scheduled maintenance
   window may be treated as an operational failure."
4. **Wait** until the obligations allow the work: all contracts on the machine
   have ended, or the announced window has arrived under Vast's rules. Do not
   stop or delete client containers.
5. **Re-check immediately before starting.** The gate re-evaluates the rental
   state. On the machine:
   ```sh
   docker ps -a --format '{{.Names}}\t{{.Status}}'      # read-only
   ```
   and in the Vast console "Occ, #Running, and #Stored all read 0" when the
   work needs an empty machine. If the gate says no, stop here.
6. **Note the starting point** (needed for recovery; nothing rolls this back
   for you):
   ```sh
   uname -r; ls -1 /boot/vmlinuz-*
   nvidia-smi --query-gpu=name,driver_version --format=csv,noheader
   dpkg -l | grep -E '^ii +(nvidia-driver|linux-modules-nvidia|linux-image|docker-ce|containerd)'
   apt-mark showhold
   cat /etc/docker/daemon.json
   os/install/nvidia-driver-plan.sh        # prints a recommendation; changes nothing
   ```
7. **Do the work by Vast's own procedure**, not an improvised one:
   - kernel: https://docs.vast.ai/host/upgrade-kernel (upgrade the kernel meta
     package so that headers and modules come with it; restart; the previous
     kernel stays installed);
   - Docker, containerd, NVIDIA stack: https://docs.vast.ai/host/upgrade-docker-and-packages
     (stop and mask the Vast daemon, keep the kernel held, upgrade,
     `sudo NEEDRESTART_MODE=l apt upgrade`, restart, unmask);
   - driver selection: the policy in `os/versions.env` — the `-server` branch
     Ubuntu offers for the GPU (`ubuntu-drivers list --gpgpu`), at least the
     minimum version, not "the newest". Do not mix Ubuntu packages with
     NVIDIA's `.run` installer.
   Never run `nvidia-ctk runtime configure` on a Vast machine and never add a
   second Docker distribution: Vast's `daemon.json` must keep
   `runtimes.nvidia.path` pointing at `kaalia_docker_shim`.
8. **Verify.**
   ```sh
   uname -r; ls -1 /boot/vmlinuz-* | sed 's|.*/vmlinuz-||' | sort -V | tail -1   # must match
   nvidia-smi                                   # every GPU listed
   sudo systemctl is-active containerd docker
   cat /etc/docker/daemon.json                  # kaalia_docker_shim still there
   sudo systemctl status vastai --no-pager
   happyminingctl preflight
   happyminingctl status
   ```
   Then Vast's self-test (`vastai self-test machine <id>`) and relist.
9. **Close the request** in HappyMining with what was changed and the versions
   before and after.

## 4. Recovery

Out-of-band access (BMC, IPMI, iDRAC, iLO, or a keyboard and monitor) is a
precondition for kernel and SSH work. Without it, a failed restart means a
visit to the machine.

| Situation | What to do |
|---|---|
| Machine came back on the **old kernel** | The new kernel is installed but GRUB did not boot it. Follow "If the machine booted the old kernel" in https://docs.vast.ai/host/upgrade-kernel (`GRUB_DEFAULT`, `update-grub`), then restart again inside the window. |
| Machine **does not come back** | Console through the BMC. In the GRUB menu choose "Advanced options for Ubuntu" and the previous kernel. That is the kernel fallback, and the reason old kernels are not removed automatically. Find out why the new kernel failed before trying again. |
| `nvidia-smi`: "couldn't communicate with the NVIDIA driver" after a kernel change | The driver module does not exist for the running kernel. Boot the previous kernel (above) to get the GPUs back, then install the matching module packages for the new kernel in the window. See https://docs.vast.ai/host/machine-offline . |
| "Driver/library version mismatch" | User-space libraries and kernel module differ, usually after a partial driver upgrade. Only a restart (in a window, through the gate) or returning to the previous driver packages fixes it. The patch policy exists to prevent this. |
| Locked out of SSH after disabling password login | Vast's procedure "If you are locked out" in https://docs.vast.ai/host/disable-ssh-password-login : console access, restore the saved `sshd_config` copies. Password login must be off again before the machine can verify. |
| Agent upgrade went wrong | `sudo ./upgrade.sh --rollback` reinstalls the previous agent package. Vast hosting was never affected. Identity and credential in `/var/lib/happymining` are preserved. |
| Agent missing or damaged | `sudo ./install.sh --deb ... --keyring ...` again. If `/var/lib/happymining` still holds the credential the machine stays paired; otherwise `sudo happyminingctl pair` with a new code. |
| Device credential revoked or lost | `sudo happyminingctl pair` with a new pairing code from a HappyMining administrator. |
| Docker storage full | Never delete customer data to recover space. Use Vast's supported controls (storage pricing, `vastai cleanup machine <id>` for storage Vast considers expired) and ask Vast support. |
| Disk replaced or cloned | Run `os/firstboot/sanitize-clone.sh` on the image before it is copied; each clone must be paired again. Clone before Vast enrolment, never after. |
| System disk lost | Reinstall with the HappyMining OS image (`os/README.md`). This is a destructive install: it needs the explicit disk-by-id selection and confirmation, and it is only possible when no rental or stored customer data is on the machine. How Vast treats a reinstalled machine (same or new machine identity) is not established; ask Vast before reinstalling a listed machine. |

## 5. What can and cannot be rolled back

| Change | Way back | Limits |
|---|---|---|
| HappyMining agent package | `upgrade.sh --rollback` (previous `.deb` kept in `/var/cache/happymining/`) | agent only; one step back |
| HappyMining agent configuration | `/etc/happymining/agent.env` is never overwritten by an upgrade | – |
| Kernel | boot the previous kernel from the GRUB menu | needs console access; the NVIDIA module must exist for that kernel |
| NVIDIA driver | install the previously noted driver packages again, in a window | not automatic; needs a restart; depends on the old packages still being available |
| Docker / containerd | none documented by Vast | treat as one-way; follow Vast's guide and their pins |
| Partitioning, formatting, moving Docker data, reinstalling | none | data is gone; never done by install, upgrade or agent tooling |
| Firmware / BIOS settings | manual | outside HappyMining's tooling |

**HappyMining agent rollback does not imply that driver, kernel or filesystem
changes can be rolled back.** `upgrade.sh` prints this every time, and
`upgrade.sh --rollback` prints it again before it acts.

## 6. Open points

- The procedures in sections 3 and 4 follow Vast's published pages; they have
  not been rehearsed on a HappyMining test machine.
- Vast's host setup guide (https://cloud.vast.ai/host/setup/) could not be
  read; it may contain further rules for updates and drivers.
- Whether Vast's daemon changes packages or holds on its own beyond what the
  upgrade guide describes.
- The exact blacklist needed on machines that run a non-generic kernel flavour
  (OEM, HWE edge) should be checked on the first such machine with
  `unattended-upgrade --dry-run -d`.
