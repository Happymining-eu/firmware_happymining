#!/usr/bin/env python3
"""Scan files that are about to be distributed for secrets.

  secret_scan.py PATH [PATH...]          (files or directories)

Looks for:
  * private keys (PEM / OpenSSH / PGP / PuTTY);
  * password hashes (crypt(3) formats) and cloud-config password fields;
  * HappyMining device tokens ("hmd_<id>.<secret>") and pairing codes
    ("HM-XXXXXX-XXXX-XXXX-XXXX-XXXX");
  * Vast API keys (file names and assignments);
  * authorized_keys content (SSH public keys) and files named authorized_keys;
  * GnuPG secret keyrings.

Matches are printed with the secret itself redacted. Symbolic links are
reported and not followed. Exit codes: 0 clean, 1 findings, 2 usage/IO error.

A distributed image must be clean. A per-machine seed is NOT scanned with this
tool: it legitimately contains the operator's SSH public key, and it is never
distributed.
"""

from __future__ import annotations

import argparse
import os
import re
import sys

CHUNK = 4 * 1024 * 1024
OVERLAP = 4096

RULES: list[tuple[str, re.Pattern[bytes]]] = [
    ("private key", re.compile(rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY( BLOCK)?-----")),
    ("private key (PuTTY)", re.compile(rb"PuTTY-User-Key-File-\d")),
    ("password hash", re.compile(rb"\$(?:1|2[abxy]?|5|6|7|y|gy|sha1)\$[A-Za-z0-9./$=,+-]{12,}")),
    (
        "password field with a value",
        re.compile(rb"(?im)^[ \t-]*(?:password|passwd|hashed_passwd|plain_text_passwd)[ \t]*:[ \t]*[\"']?[^\s\"'#$][^\n]*$"),
    ),
    ("chpasswd directive", re.compile(rb"(?m)^[ \t-]*chpasswd[ \t]*:")),
    ("HappyMining device token", re.compile(rb"hmd_[0-9a-fA-F]{8,}")),
    ("HappyMining pairing code", re.compile(rb"\bHM-[0-9A-Za-z]{6}(?:-[0-9A-Za-z]{4}){4}\b")),
    (
        "Vast API key",
        re.compile(
            rb"(?i)(?:vast[^\n]{0,40}(?:api[_ -]?key|key)[\"' ]*[:=][\"' ]*[0-9a-f]{32,}"
            rb"|vastai\s+set\s+api-key\s+[0-9a-f]{16,}"
            rb"|--api-key[ =]+[0-9a-f]{32,})"
        ),
    ),
    (
        "authorized_keys content (SSH public key)",
        re.compile(
            rb"(?:ssh-(?:rsa|ed25519|dss)|ecdsa-sha2-nistp(?:256|384|521)|sk-[a-z0-9-]+@openssh\.com) AAAA[0-9A-Za-z+/]{40,}"
        ),
    ),
]

NAME_RULES: list[tuple[str, re.Pattern[str]]] = [
    ("file named like an SSH authorized_keys file", re.compile(r"^authorized_keys2?$")),
    ("file named like an SSH private key", re.compile(r"^(id_(rsa|dsa|ecdsa|ed25519)(_sk)?|ssh_host_[a-z0-9]+_key)$")),
    ("Vast API key file", re.compile(r"^\.?vast_api_key$")),
    ("HappyMining device credential file", re.compile(r"^credential\.json$")),
    ("GnuPG secret key material", re.compile(r"^(secring\.gpg|.*\.key)$")),
]
DIR_NAME_RULES: list[tuple[str, re.Pattern[str]]] = [
    ("GnuPG private key directory", re.compile(r"^private-keys-v1\.d$")),
]


def redact(match: bytes) -> str:
    text = match.decode("utf-8", "replace").replace("\n", " ")
    if len(text) <= 12:
        return text[:4] + "…"
    return text[:10] + "…[redacted]"


def scan_file(path: str) -> list[tuple[str, str]]:
    findings: list[tuple[str, str]] = []
    seen: set[tuple[str, bytes]] = set()
    with open(path, "rb") as fh:
        tail = b""
        while True:
            chunk = fh.read(CHUNK)
            if not chunk:
                break
            data = tail + chunk
            for name, regex in RULES:
                for m in regex.finditer(data):
                    key = (name, m.group(0))
                    if key not in seen:
                        seen.add(key)
                        findings.append((name, redact(m.group(0))))
            tail = data[-OVERLAP:]
    return findings


def scan(paths: list[str]) -> list[str]:
    report: list[str] = []
    for top in paths:
        if not os.path.lexists(top):
            raise OSError(f"{top} does not exist")
        if os.path.islink(top) or os.path.isfile(top):
            entries = [(os.path.dirname(top) or ".", [], [os.path.basename(top)])]
        else:
            entries = os.walk(top, followlinks=False)
        for dirpath, dirnames, filenames in entries:
            dirnames.sort()
            for dirname in dirnames:
                for what, regex in DIR_NAME_RULES:
                    if regex.match(dirname):
                        report.append(f"{os.path.join(dirpath, dirname)}: {what}")
            for filename in sorted(filenames):
                full = os.path.join(dirpath, filename)
                for what, regex in NAME_RULES:
                    if regex.match(filename):
                        report.append(f"{full}: {what}")
                if os.path.islink(full):
                    report.append(f"{full}: symbolic link (not allowed in a distributed tree; target not scanned)")
                    continue
                if not os.path.isfile(full):
                    continue
                for what, sample in scan_file(full):
                    report.append(f"{full}: {what}: {sample}")
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("paths", nargs="+")
    parser.add_argument("--quiet", action="store_true", help="print nothing when clean")
    args = parser.parse_args(argv)
    try:
        report = scan(args.paths)
    except OSError as exc:
        print(f"secret_scan.py: {exc}", file=sys.stderr)
        return 2
    if report:
        for line in report:
            print(f"SECRET FOUND {line}")
        print(f"secret_scan.py: {len(report)} finding(s); refusing", file=sys.stderr)
        return 1
    if not args.quiet:
        print(f"secret_scan.py: clean ({', '.join(args.paths)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
