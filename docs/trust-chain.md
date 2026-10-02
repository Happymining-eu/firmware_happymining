# Trust chain of HappyMining OS artifacts

How an operator can know that the software put on a machine is the software
HappyMining released, which links are checked by which tool, and which things
are **not** authenticated. Tooling: `os/image/`, `os/release/`, `os/install/`.

Status: the checksum, signature and verification code is implemented and
tested (`tests/os/test_release.py`, `tests/os/test_install.py`). The ISO build
has not been run yet (see `os/README.md`), so the first link below has been
tested only up to the point where a base ISO is needed.

## The chain at a glance

```
Canonical                                   HappyMining release signer
---------                                   --------------------------
Ubuntu CD image signing key                 release signing key
  843938DF228D22F7B3742BC0D94AA3F0EFE21092     (production: hardware token, see below)
        | signs                                      | signs
        v                                            v
SHA256SUMS.gpg -> SHA256SUMS (Ubuntu)        dist/SHA256SUMS.gpg -> dist/SHA256SUMS
        | lists                                      | lists
        v                                            v
ubuntu-<point release>-live-server-amd64.iso   happymining-agent_<ver>_amd64.deb
        |                                      happymining-os-<...>.iso
        | repacked unchanged by build-iso.sh   happymining-install-scripts-<ver>.tar.gz
        v                                      happymining-seed-generic.tar.gz
happymining-os-<...>.iso  <------ contains ---- /happymining/ (deb, seed, SHA256SUMS[.gpg])
                                                     |
              install.sh / upgrade.sh verify --------+   (existing servers)
              the operator verifies the ISO file ----+   (dedicated machines)
```

## Link 1 — the Ubuntu base ISO

`os/image/build-iso.sh`:

1. downloads `SHA256SUMS` and `SHA256SUMS.gpg` from
   `https://releases.ubuntu.com/<release>/` (or takes them from
   `--ubuntu-sums-dir`);
2. verifies the detached signature with `gpgv` against the keyring given with
   `--ubuntu-keyring` (default `/usr/share/keyrings/ubuntu-archive-keyring.gpg`
   from the `ubuntu-keyring` package) **and** requires the signer to be the
   pinned fingerprint `843938DF228D22F7B3742BC0D94AA3F0EFE21092`
   ("Ubuntu CD Image Automatic Signing Key (2012) <cdimage@ubuntu.com>");
3. checks the ISO (downloaded, or passed with `--base-iso`) against the entry
   for the pinned file name in that signed list.

No ISO hash is stored in the repository. The fingerprint was taken from
https://ubuntu.com/tutorials/how-to-verify-ubuntu and compared with the copy of
the key in the `ubuntu-keyring` package (2026-10-02). HTTPS is used for the
downloads but is not the trust anchor; the signature is.

The repack keeps Ubuntu's files byte-identical (the squashfs is not opened) and
adds `/happymining/` and a changed `/boot/grub/grub.cfg` and `/md5sum.txt`.
`<iso>.buildinfo` records the base ISO's sha256 and the signer.

What this link does not give: a proof that the output ISO equals "Ubuntu ISO +
these exact files". The build is not yet shown to be reproducible. Whoever
builds the release is trusted to run the unmodified script on a clean host.

## Link 2 — HappyMining artifacts

`os/release/make-checksums.sh --signing-key-home DIR` writes `dist/SHA256SUMS`
over every artifact in `dist/` and an ASCII-armoured detached signature
`dist/SHA256SUMS.gpg`. It then verifies its own output with the public key
only, the same way `install.sh` will, before it publishes the two files.

`build-iso.sh` does the same for the payload on the medium: `/happymining/SHA256SUMS`
and `/happymining/SHA256SUMS.gpg`.

The signature covers the checksum list, and the list covers the files. The
`.deb` itself carries no embedded signature.

## Link 3 — verification on an existing server (`install.sh`, `upgrade.sh`)

```sh
sudo ./install.sh --deb happymining-agent_0.1.0_amd64.deb \
                  --keyring happymining-release.pub.asc \
                  --expect-fingerprint <40 hex digits published by HappyMining>
```

- `SHA256SUMS` must sit next to the package and list it with the right hash.
- `SHA256SUMS.gpg` must be a good signature over `SHA256SUMS` from a key in
  `--keyring`. Verification uses `gpgv` with a private, empty GnuPG home and
  reads gpgv's machine-readable status lines: a signature counts only with
  `GOODSIG` and `VALIDSIG` for the same key and without `BADSIG`. Expired and
  revoked keys and expired signatures do not count. gpgv's exit code alone is
  never trusted.
- With `--expect-fingerprint` the signer's primary key fingerprint must match.
  Use it: a keyring file is only as trustworthy as the way it reached you.
- Missing signature, missing keyring or missing checksum list: refused.
  `--allow-unsigned-dev` turns that into a loud warning for developer builds. A
  checksum mismatch or a bad signature is fatal in every mode.
- Only the package named `happymining-agent` is accepted.
- The copy kept for rollback lives in `/var/cache/happymining/` with its sha256
  recorded at the time it was verified. `upgrade.sh --rollback` refuses the
  store unless it is owned by root and not writable by others, and re-checks
  the recorded hash. That is the same level of trust as dpkg's own database:
  it protects against corruption and against the unprivileged agent user, not
  against root on that machine.

The install scripts themselves arrive in
`happymining-install-scripts-<ver>.tar.gz`, which is listed in `dist/SHA256SUMS`.
Check it by hand before unpacking:

```sh
gpgv --keyring ./happymining-release.pub.gpg SHA256SUMS.gpg SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS
```

(`gpgv` needs the binary form of the key: `gpg --dearmor < happymining-release.pub.asc > happymining-release.pub.gpg`.)

## Link 4 — a dedicated machine installed from the ISO

The operator verifies the **ISO file** with the two commands above before
writing it to a USB stick. That is the authentication step for everything on
the medium.

During installation the seed's `late-commands` run
`sha256sum -c /cdrom/happymining/SHA256SUMS`. This detects a damaged medium. It
is **not** an authenticity check: a tampered medium could carry a tampered
checksum list and a tampered seed. The signature file is copied to
`/var/cache/happymining/` only so that it can be inspected later.

The agent package is then installed with `dpkg -i` from the medium, without
network access to HappyMining.

## What is authenticated, and what is not

| Item | Authenticated by | Checked by |
|---|---|---|
| Ubuntu base ISO | Ubuntu CD image key over SHA256SUMS | `build-iso.sh` (every build) |
| HappyMining ISO, `.deb`, bundles | release key over `dist/SHA256SUMS` | operator (`gpgv` + `sha256sum`), `install.sh`, `upgrade.sh` |
| Files in `/happymining/` on the medium | release key over the medium's SHA256SUMS; in practice by verifying the ISO file | operator, before writing the medium |
| Ubuntu packages fetched during or after installation | Ubuntu's own APT signatures | APT (outside this chain) |

Not authenticated by this chain:

- **There is no APT repository.** In the pilot the agent package is not
  installed from an APT repository. `dpkg -i` verifies nothing by itself; all
  verification is done by `install.sh`/`upgrade.sh` or by the operator. There
  are no automatic agent updates, no signed repository metadata, and no
  freshness guarantee: an attacker who controls what an operator downloads
  could offer an old, correctly signed release. `upgrade.sh` refuses a
  downgrade unless `--allow-downgrade` or `--rollback` is given; that is the
  only protection against replay today.
- **Per-machine seeds are not signed.** They are made by the operator for one
  machine and protected by possession (mode 0700/0600, never in the image).
  Anyone who can alter a seed volume before the installation controls that
  installation.
- **The boot chain.** Vast's verification requirements list "Secure Boot:
  Disabled". With Secure Boot off, nothing verifies the boot loader, the kernel
  or `grub.cfg` at boot. `grub.cfg` is never signed, with or without Secure
  Boot.
- **The Vast host software, Docker and NVIDIA drivers.** They are installed
  later by the local operator from their vendors. HappyMining neither ships nor
  vouches for them.
- **The public key file.** A keyring handed over together with the artifacts
  proves nothing. The fingerprint must come through a second channel.
- **The build.** No independent rebuild confirms that the ISO corresponds to a
  given source commit. The two tar bundles are reproducible; the ISO has not
  been tested for that.
- **The machine after installation.** An owner with root access can replace or
  remove the agent. This chain is about delivery, not about a hostile owner.

## Keys

### Development key

`os/release/gen-dev-signing-key.sh` creates an ed25519 key in `.signing/` at the
repository root (excluded from version control) and exports the public half to
`dist/happymining-dev-release.pub.asc`. Its user ID reads
"HappyMining DEVELOPMENT release signing key (NOT FOR PRODUCTION)", it has no
passphrase and it expires after 90 days. `make-checksums.sh` prints a warning
whenever such a key signs. Artifacts signed with a development key must never
reach a customer, and no development key may be added to a keyring that is
given to customers.

### Production key custody (to be set up before the first customer release)

None of this exists yet. It is the procedure to follow.

- **Generation.** On an offline machine, or directly on hardware tokens. The
  primary key is certify-only and stays offline (two sealed copies in separate
  safes). Signing is done with a signing subkey that lives on a hardware token
  (OpenPGP smart card or HSM) that requires PIN and touch. Two tokens, two
  named custodians. A revocation certificate is created at generation time and
  stored apart from the key copies.
- **No production key on build or CI hosts.** The build host produces
  `dist/SHA256SUMS`; a custodian checks it and signs it on a signing
  workstation with the token (`make-checksums.sh --signing-key-home <home that
  points at the token>`). Each signing is entered in a release log: date,
  commit, artifact hashes, custodian.
- **Publication.** The public key and its full fingerprint are published
  through at least two independent channels (for example the HTTPS site and
  the onboarding documents handed to owners). Operators pass the fingerprint
  with `--expect-fingerprint`.
- **Rotation.** The signing subkey gets a validity of about one year and is
  replaced on schedule; the updated public key is published before the old
  subkey expires. Consequence of the strict verifier: once a key has expired,
  `install.sh` refuses signatures made with it. Either extend the validity and
  republish the public key, or re-sign the releases that must stay installable.
- **Revocation.** On suspected compromise: publish the revocation, issue a new
  key, re-sign current releases, tell every operator the new fingerprint and to
  discard the old public key. There is **no automatic revocation channel** in
  the pilot: `install.sh` trusts the keyring file the operator passes on that
  day. Until operators replace their copy, a revoked key is still accepted on
  their machines. Showing the current fingerprint in the HappyMining dashboard
  would shorten that window; it is not implemented here.
- **Separation.** The release key is used for nothing else: not for TLS, not
  for device credentials, not for the APT repository key described below.

## Next step: a signed APT repository (does not exist yet)

The planned replacement for hand-delivered `.deb` files:

- an APT repository whose `InRelease` file is signed by a dedicated repository
  key, with `Valid-Until` so that stale metadata is rejected;
- on each machine a source entry with `signed-by=/usr/share/keyrings/happymining-archive-keyring.gpg`
  and an APT pin that limits the repository to the `happymining-*` packages;
- the keyring delivered by a `happymining-archive-keyring` package, which also
  gives a path for key rotation;
- agent updates applied under the patch policy in `docs/os-maintenance.md`.

Until that repository exists, nothing in this project may describe agent
packages as coming from, or being verified by, APT.
