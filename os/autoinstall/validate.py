#!/usr/bin/env python3
"""Validate the HappyMining OS autoinstall files.

  validate.py                         validate the files in this repository:
                                      user-data.generic.yaml, the unattended
                                      template rendered with dummy values (both
                                      layouts), and the GRUB entry template.
  validate.py --kind generic --file F
  validate.py --kind unattended --rendered F     (F may be "-" for stdin)
  validate.py --grub-cfg F

Checks:
  * safe YAML load (duplicate keys are an error), "#cloud-config" header,
    a single top-level "autoinstall" mapping, "version: 1";
  * the official Subiquity autoinstall JSON schema vendored in ./schema
    (skipped with a notice when the "jsonschema" module is not installed,
    unless --require-schema is given);
  * forbidden content by path: password fields with a value, chpasswd,
    private key material, password hashes, HappyMining device tokens and
    pairing codes, Vast API keys, hard-coded /dev/sdX, /dev/nvmeXnY, /dev/vdX
    device paths;
  * generic seed: storage and identity interactive, nothing selects a disk,
    no account or key, no early-commands, no auto-confirm keyword;
  * unattended seed: nothing interactive, every disk pinned by an exact
    "serial" match and covered by the disk guard, key-only account;
  * GRUB configuration: no "linux" line carries the auto-confirm keyword.

Exit codes: 0 valid, 1 violations found, 2 usage or environment error.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Any, Iterator

try:
    import yaml
except ImportError:  # pragma: no cover - environment problem, reported in main()
    yaml = None  # type: ignore[assignment]

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
# Do not leave __pycache__ directories in the source tree that feeds the image.
sys.dont_write_bytecode = True
import render_template  # noqa: E402  (local module, same directory)

DEFAULT_SCHEMA = os.path.join(HERE, "schema", "autoinstall-schema.json")
GENERIC_FILE = os.path.join(HERE, "user-data.generic.yaml")
TEMPLATE_FILE = os.path.join(HERE, "user-data.unattended.yaml.tmpl")
GUARD_FILE = os.path.join(HERE, "disk-guard.sh")
GRUB_ENTRIES_FILE = os.path.join(HERE, "..", "image", "branding", "grub-entries.cfg.in")

# The kernel command-line keyword that makes Subiquity skip its confirmation
# prompt ("Add 'autoinstall' to your kernel command line to avoid this").
AUTOCONFIRM_KEYWORD = "autoinstall"

PASSWORD_KEYS = {
    "password", "passwd", "hashed_passwd", "hashed-passwd", "plain_text_passwd",
    "plain-text-passwd", "passphrase",
}
FORBIDDEN_KEYS = {
    "chpasswd": "chpasswd sets passwords and is never allowed",
    "ssh_keys": "ssh_keys would ship SSH host private keys",
    "ssh_import_id": "ssh_import_id pulls keys from a third party at install time",
}

RE_PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY( BLOCK)?-----")
RE_CRYPT_HASH = re.compile(r"\$(?:1|2[abxy]?|5|6|7|y|gy|sha1)\$[A-Za-z0-9./$=,+-]{12,}")
RE_DEVICE_PATH = re.compile(
    r"/dev/(?:sd[a-z]+|hd[a-z]+|vd[a-z]+|xvd[a-z]+|nvme[0-9]+n[0-9]+|mmcblk[0-9]+)(?:p?[0-9]+)?(?![A-Za-z0-9_])"
)
RE_HM_TOKEN = re.compile(r"hmd_[0-9a-fA-F]{8,}")
RE_PAIRING_CODE = re.compile(r"\bHM-[0-9A-Za-z]{6}(?:-[0-9A-Za-z]{4}){4}\b")
RE_VAST_KEY = re.compile(
    r"(?i)(?:vast[^\n]{0,40}(?:api[_ -]?key|key)[\"' ]*[:=][\"' ]*[0-9a-f]{32,}"
    r"|vastai\s+set\s+api-key\s+[0-9a-f]{16,}"
    r"|vast_api_key)"
)
RE_SSH_PUBKEY = re.compile(
    r"(?:ssh-(?:rsa|ed25519|dss)|ecdsa-sha2-nistp(?:256|384|521)|sk-[a-z0-9-]+@openssh\.com) AAAA[0-9A-Za-z+/]{40,}"
)
RE_GLOB = re.compile(r"[*?\[\]]")

STRING_RULES = [
    (RE_PRIVATE_KEY, "private key material"),
    (RE_CRYPT_HASH, "password hash"),
    (RE_DEVICE_PATH, "hard-coded kernel device path (use /dev/disk/by-id/ and a serial match)"),
    (RE_HM_TOKEN, "HappyMining device token"),
    (RE_PAIRING_CODE, "HappyMining pairing code"),
    (RE_VAST_KEY, "Vast API key"),
]

# Dummy values used to render the template for validation. The key is a
# syntactically valid ed25519 public key whose 32 key bytes are all zero.
DUMMY_SERIAL = "HMDUMMY_MODEL_SERIAL0001"
DUMMY_DATA_SERIAL = "HMDUMMY_MODEL_SERIAL0002"
DUMMY_SSH_KEY = (
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA validate.py-dummy"
)


class _UniqueKeyLoader(yaml.SafeLoader if yaml else object):  # type: ignore[misc]
    """SafeLoader that refuses duplicate mapping keys."""

    def construct_mapping(self, node, deep=False):  # type: ignore[no-untyped-def]
        seen = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=deep)
            try:
                if key in seen:
                    raise yaml.constructor.ConstructorError(
                        None, None, f"duplicate key {key!r}", key_node.start_mark
                    )
                seen.add(key)
            except TypeError:
                pass
        return super().construct_mapping(node, deep=deep)


def walk(node: Any, path: str = "") -> Iterator[tuple[str, Any, Any]]:
    """Yield (path, key, value) for every mapping entry and list item."""
    if isinstance(node, dict):
        for key, value in node.items():
            sub = f"{path}.{key}" if path else str(key)
            yield sub, key, value
            yield from walk(value, sub)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            sub = f"{path}[{index}]"
            yield sub, index, value
            yield from walk(value, sub)


def _is_set(value: Any) -> bool:
    return value is not None and value != "" and value != [] and value != {}


def common_checks(text: str, doc: Any, errors: list[str]) -> dict | None:
    first_line = text.splitlines()[0].rstrip() if text.strip() else ""
    if first_line != "#cloud-config":
        errors.append("header: the first line must be exactly '#cloud-config'")
    if not isinstance(doc, dict):
        errors.append("document: top level must be a mapping")
        return None
    extra = sorted(k for k in doc if k != "autoinstall")
    if extra:
        errors.append(
            f"document: only 'autoinstall' is allowed at top level; found {extra} "
            "(top-level cloud-config directives would run in the installer environment)"
        )
    ai = doc.get("autoinstall")
    if not isinstance(ai, dict):
        errors.append("autoinstall: missing or not a mapping")
        return None
    version = ai.get("version")
    if isinstance(version, bool) or version != 1 or not isinstance(version, int):
        errors.append(f"autoinstall.version: must be the integer 1, found {version!r}")

    for path, key, value in walk(doc):
        if isinstance(key, str):
            if key.lower() in PASSWORD_KEYS and _is_set(value):
                # storage.layout.password would be a LUKS passphrase: also refused.
                errors.append(f"{path}: password field with a value is forbidden")
            if key in FORBIDDEN_KEYS:
                errors.append(f"{path}: {FORBIDDEN_KEYS[key]}")
            if key == "lock_passwd" and value is not True:
                errors.append(f"{path}: lock_passwd must be true (no password login)")
            if key in ("allow-pw", "ssh_pwauth") and value is not False:
                errors.append(f"{path}: must be false (SSH password login is not allowed)")
        if isinstance(value, str):
            for regex, what in STRING_RULES:
                if regex.search(value):
                    errors.append(f"{path}: contains {what}")
    return ai


def schema_check(ai: dict, schema_path: str, require: bool, errors: list[str], notices: list[str]) -> None:
    try:
        import jsonschema
    except ImportError:
        msg = "python module 'jsonschema' is not installed: official schema validation SKIPPED"
        if require:
            errors.append(msg)
        else:
            notices.append(msg)
        return
    try:
        with open(schema_path, encoding="utf-8") as fh:
            schema = json.load(fh)
    except OSError as exc:
        msg = f"cannot read schema {schema_path}: {exc}: official schema validation SKIPPED"
        if require:
            errors.append(msg)
        else:
            notices.append(msg)
        return
    validator_cls = jsonschema.validators.validator_for(schema)
    validator = validator_cls(schema)
    for err in sorted(validator.iter_errors(ai), key=lambda e: list(e.absolute_path)):
        where = ".".join(str(p) for p in err.absolute_path) or "(root)"
        errors.append(f"schema: autoinstall.{where}: {err.message}")


def generic_checks(ai: dict, errors: list[str]) -> None:
    interactive = ai.get("interactive-sections")
    if not isinstance(interactive, list):
        errors.append("autoinstall.interactive-sections: required in the generic seed")
        interactive = []
    for needed in ("storage", "identity"):
        if needed not in interactive and "*" not in interactive:
            errors.append(
                f"autoinstall.interactive-sections: must contain '{needed}' so that the installer asks for it"
            )
    if "storage" in ai:
        errors.append("autoinstall.storage: the generic seed must not select or pre-configure any disk")
    if "identity" in ai:
        errors.append("autoinstall.identity: the generic seed must not define an account")
    if "user-data" in ai:
        errors.append("autoinstall.user-data: the generic seed must not carry first-boot cloud-config (accounts, keys)")
    if "early-commands" in ai:
        errors.append("autoinstall.early-commands: not allowed in the generic seed (they can rewrite the configuration)")
    ssh = ai.get("ssh")
    if isinstance(ssh, dict) and _is_set(ssh.get("authorized-keys")):
        errors.append("autoinstall.ssh.authorized-keys: the generic seed must not contain SSH keys")
    for path, _key, value in walk(ai):
        if isinstance(value, str):
            if RE_SSH_PUBKEY.search(value):
                errors.append(f"{path}: contains an SSH public key; the generic seed must not contain keys")
            # The generic seed has no legitimate use for this word in any
            # command or value, so every occurrence is refused: it is the
            # kernel keyword that removes the installer's confirmation prompt.
            if AUTOCONFIRM_KEYWORD in value.lower():
                errors.append(
                    f"{path}: mentions '{AUTOCONFIRM_KEYWORD}' (the kernel keyword that removes the "
                    "installer's confirmation prompt); not allowed in the generic path"
                )


def _exact_serial(value: Any) -> bool:
    return isinstance(value, str) and bool(value) and not RE_GLOB.search(value)


def _guarded_disks(ai: dict, errors: list[str]) -> dict[str, str]:
    """Return {serial: by-id} for every --disk triple passed to the disk guard."""
    guarded: dict[str, str] = {}
    commands = ai.get("early-commands")
    if not isinstance(commands, list):
        errors.append("autoinstall.early-commands: the unattended seed must run the disk guard")
        return guarded
    for command in commands:
        if not (isinstance(command, list) and any("happymining-disk-guard.sh" in str(part) for part in command)):
            continue
        args = [str(part) for part in command]
        i = 0
        while i < len(args):
            if args[i] == "--disk":
                if i + 3 >= len(args):
                    errors.append("autoinstall.early-commands: incomplete --disk argument for the disk guard")
                    break
                by_id, serial, min_bytes = args[i + 1], args[i + 2], args[i + 3]
                if not re.fullmatch(r"/dev/disk/by-id/[A-Za-z0-9][A-Za-z0-9._:+=@-]*", by_id):
                    errors.append(f"autoinstall.early-commands: disk guard target {by_id!r} is not a /dev/disk/by-id/ name")
                elif not by_id.endswith("-" + serial):
                    errors.append(
                        f"autoinstall.early-commands: by-id name {by_id!r} does not end with the serial {serial!r}"
                    )
                if not min_bytes.isdigit() or int(min_bytes) <= 0:
                    errors.append("autoinstall.early-commands: disk guard minimum size must be a positive number")
                guarded[serial] = by_id
                i += 4
            else:
                i += 1
    if not guarded:
        errors.append("autoinstall.early-commands: no disk guard invocation with --disk found")
    return guarded


def unattended_checks(ai: dict, errors: list[str]) -> None:
    if _is_set(ai.get("interactive-sections")):
        errors.append("autoinstall.interactive-sections: must be empty in the unattended seed")
    if "identity" in ai:
        errors.append("autoinstall.identity: not allowed (it requires a password hash); use user-data.users with a key")

    guarded = _guarded_disks(ai, errors)

    storage = ai.get("storage")
    if not isinstance(storage, dict):
        errors.append("autoinstall.storage: required; without it the installer picks a disk on its own")
        storage = {}
    serials: list[str] = []
    layout = storage.get("layout")
    config = storage.get("config")
    if layout is None and config is None:
        errors.append("autoinstall.storage: needs 'config' (or 'layout' with a match); the default layout takes the largest disk")
    if layout is not None:
        match = layout.get("match") if isinstance(layout, dict) else None
        if not isinstance(match, dict) or not match:
            errors.append(
                "autoinstall.storage.layout: a layout without an exact 'match' is forbidden "
                "(by default a layout installs to the largest disk; 'match: {}' matches an arbitrary disk)"
            )
        else:
            _check_match(match, "autoinstall.storage.layout.match", errors, serials)
    if config is not None:
        if not isinstance(config, list):
            errors.append("autoinstall.storage.config: must be a list of actions")
            config = []
        disks = [a for a in config if isinstance(a, dict) and a.get("type") == "disk"]
        if not disks:
            errors.append("autoinstall.storage.config: no disk action")
        for index, action in enumerate(config):
            if not isinstance(action, dict) or action.get("type") != "disk":
                continue
            where = f"autoinstall.storage.config[{index}]"
            if "path" in action:
                errors.append(f"{where}.path: disks must not be selected by path")
            match = action.get("match")
            direct = action.get("serial")
            if match is None and direct is None:
                errors.append(f"{where}: disk action without 'match' matches an arbitrary disk")
            if direct is not None:
                if _exact_serial(direct):
                    serials.append(direct)
                else:
                    errors.append(f"{where}.serial: must be an exact, non-empty serial")
            if match is not None:
                if not isinstance(match, dict):
                    errors.append(f"{where}.match: must be a single mapping (ordered fallback lists are not allowed)")
                else:
                    _check_match(match, f"{where}.match", errors, serials)
    if len(set(serials)) != len(serials):
        errors.append("autoinstall.storage: the same serial is used for more than one disk")
    for serial in serials:
        if serial not in guarded:
            errors.append(f"autoinstall.storage: disk with serial {serial!r} is not covered by the disk guard")
    for serial in guarded:
        if serial not in serials:
            errors.append(f"autoinstall.early-commands: the disk guard checks serial {serial!r}, which storage does not use")

    ssh = ai.get("ssh")
    if not isinstance(ssh, dict) or ssh.get("install-server") is not True:
        errors.append("autoinstall.ssh.install-server: must be true")
    if not isinstance(ssh, dict) or ssh.get("allow-pw") is not False:
        errors.append("autoinstall.ssh.allow-pw: must be false")

    user_data = ai.get("user-data")
    if not isinstance(user_data, dict):
        errors.append("autoinstall.user-data: required (creates the key-only operator account on first boot)")
        return
    if user_data.get("ssh_pwauth") is not False:
        errors.append("autoinstall.user-data.ssh_pwauth: must be false")
    hostname = user_data.get("hostname")
    if not (isinstance(hostname, str) and re.fullmatch(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?", hostname)):
        errors.append("autoinstall.user-data.hostname: required, RFC 1123 label in lower case")
    users = user_data.get("users")
    if not isinstance(users, list) or not users:
        errors.append("autoinstall.user-data.users: at least one account is required")
        return
    have_key = False
    for index, user in enumerate(users):
        where = f"autoinstall.user-data.users[{index}]"
        if not isinstance(user, dict):
            errors.append(f"{where}: must be a mapping")
            continue
        if user.get("lock_passwd") is not True:
            errors.append(f"{where}.lock_passwd: must be true")
        keys = user.get("ssh_authorized_keys")
        if isinstance(keys, list) and keys:
            for key in keys:
                if not (isinstance(key, str) and RE_SSH_PUBKEY.match(key)):
                    errors.append(f"{where}.ssh_authorized_keys: entry is not an SSH public key")
                else:
                    have_key = True
    if not have_key:
        errors.append("autoinstall.user-data.users: no account has an SSH public key; nobody could log in")


def _check_match(match: dict, where: str, errors: list[str], serials: list[str]) -> None:
    allowed = {"serial"}
    for key in match:
        if key not in allowed:
            errors.append(
                f"{where}.{key}: only an exact 'serial' match is allowed "
                "(size/ssd/path/model matches can select a different disk)"
            )
    serial = match.get("serial")
    if not _exact_serial(serial):
        errors.append(f"{where}.serial: required, exact, without wildcard characters")
    else:
        serials.append(serial)


def kernel_line_has_autoconfirm(line: str) -> bool:
    """True when a GRUB 'linux' line passes the bare keyword to the kernel."""
    stripped = line.strip()
    if stripped.startswith("#") or not re.match(r"(linux|linuxefi|linux16)\s", stripped):
        return False
    for token in stripped.split()[1:]:
        if token.strip("\"'\\;") == AUTOCONFIRM_KEYWORD:
            return True
    return False


def grub_checks(text: str, errors: list[str], name: str) -> None:
    for lineno, line in enumerate(text.splitlines(), start=1):
        if kernel_line_has_autoconfirm(line):
            errors.append(
                f"{name}:{lineno}: kernel command line contains '{AUTOCONFIRM_KEYWORD}', which removes the "
                "installer's confirmation prompt"
            )


def validate_text(
    text: str, kind: str, schema_path: str | None, require_schema: bool
) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    notices: list[str] = []
    try:
        doc = yaml.load(text, Loader=_UniqueKeyLoader)  # noqa: S506 - SafeLoader subclass
    except yaml.YAMLError as exc:
        return [f"yaml: {exc}"], notices
    ai = common_checks(text, doc, errors)
    if ai is None:
        return errors, notices
    if schema_path is not None:
        schema_check(ai, schema_path, require_schema, errors, notices)
    if kind == "generic":
        generic_checks(ai, errors)
    elif kind == "unattended":
        unattended_checks(ai, errors)
    else:  # pragma: no cover - guarded by argparse
        raise ValueError(kind)
    return errors, notices


def render_dummy(dedicated_data_disk: bool) -> str:
    with open(TEMPLATE_FILE, encoding="utf-8") as fh:
        template = fh.read()
    with open(GUARD_FILE, encoding="utf-8") as fh:
        guard = fh.read()
    values = {
        "DISK_BY_ID": f"/dev/disk/by-id/nvme-{DUMMY_SERIAL}",
        "DISK_SERIAL": DUMMY_SERIAL,
        "DISK_MIN_BYTES": str(302 * 1024**3),
        "ROOT_SIZE": "100G",
        "DATA_FS": "xfs",
        "DATA_MOUNT": "/var/lib/docker",
        "DATA_MOUNT_OPTIONS": "rw,auto,pquota",
        "HOSTNAME": "hm-dummy-host",
        "USERNAME": "hmadmin",
        "TIMEZONE": "Etc/UTC",
    }
    flags = {"DATA_ON_ROOT_DISK"}
    if dedicated_data_disk:
        flags = {"DATA_DISK"}
        values.update(
            {
                "DATA_DISK_BY_ID": f"/dev/disk/by-id/nvme-{DUMMY_DATA_SERIAL}",
                "DATA_DISK_SERIAL": DUMMY_DATA_SERIAL,
                "DATA_DISK_MIN_BYTES": str(201 * 1024**3),
            }
        )
    return render_template.render(
        template, values, {"SSH_AUTHORIZED_KEYS": [DUMMY_SSH_KEY]}, {"DISK_GUARD": guard}, flags
    )


def report(name: str, errors: list[str], notices: list[str]) -> bool:
    for notice in notices:
        print(f"NOTICE {name}: {notice}")
    if errors:
        for error in errors:
            print(f"INVALID {name}: {error}")
        return False
    print(f"OK {name}")
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--kind", choices=["generic", "unattended"])
    parser.add_argument("--file", "--rendered", dest="file", metavar="FILE",
                        help="YAML file to validate ('-' reads standard input)")
    parser.add_argument("--grub-cfg", metavar="FILE", help="GRUB configuration (or entry template) to check")
    parser.add_argument("--schema", default=DEFAULT_SCHEMA, help="autoinstall JSON schema (default: vendored copy)")
    parser.add_argument("--no-schema", action="store_true", help="skip the JSON schema validation")
    parser.add_argument("--require-schema", action="store_true",
                        help="fail when the schema validation cannot be performed")
    args = parser.parse_args(argv)

    if yaml is None:
        print("validate.py: python module 'yaml' (PyYAML) is required", file=sys.stderr)
        return 2
    if args.file and not args.kind:
        parser.error("--file/--rendered requires --kind")
    if args.kind and not args.file:
        parser.error("--kind requires --file/--rendered")
    schema_path = None if args.no_schema else args.schema

    ok = True
    try:
        if args.file:
            if args.file == "-":
                text = sys.stdin.read()
            else:
                with open(args.file, encoding="utf-8") as fh:
                    text = fh.read()
            errors, notices = validate_text(text, args.kind, schema_path, args.require_schema)
            ok &= report(f"{args.kind}:{args.file}", errors, notices)
        if args.grub_cfg:
            errors = []
            with open(args.grub_cfg, encoding="utf-8") as fh:
                grub_checks(fh.read(), errors, args.grub_cfg)
            ok &= report(f"grub:{args.grub_cfg}", errors, [])
        if not args.file and not args.grub_cfg:
            with open(GENERIC_FILE, encoding="utf-8") as fh:
                errors, notices = validate_text(fh.read(), "generic", schema_path, args.require_schema)
            ok &= report("generic:user-data.generic.yaml", errors, notices)
            for dedicated, label in ((False, "data partition on the system disk"), (True, "dedicated data disk")):
                errors, notices = validate_text(render_dummy(dedicated), "unattended", schema_path, args.require_schema)
                ok &= report(f"unattended:user-data.unattended.yaml.tmpl rendered with dummy values ({label})", errors, notices)
            errors = []
            with open(GRUB_ENTRIES_FILE, encoding="utf-8") as fh:
                grub_checks(fh.read(), errors, "grub-entries.cfg.in")
            ok &= report("grub:image/branding/grub-entries.cfg.in", errors, [])
    except (OSError, ValueError) as exc:
        print(f"validate.py: {exc}", file=sys.stderr)
        return 2
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
