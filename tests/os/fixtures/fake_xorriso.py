#!/usr/bin/env python3
"""FAKE xorriso for the unit tests of os/image/build-iso.sh.

This is NOT xorriso and proves nothing about real ISO images. It treats an
"ISO" as a tar archive and implements only the handful of commands that
build-iso.sh issues, so that the script's control flow (verification order,
refusals, staging, read-back checks) can be tested without the real tool and
without the 3.8 GB Ubuntu image:

  -version
  -osirrox on -indev IMG -extract /iso/path dest [...]
  -indev IMG -outdev OUT -boot_image any replay -map src /iso/path [...]
         -chown_r N /path -- -chgrp_r N /path --
  -indev IMG -report_el_torito plain

The boot information of the fake image is the tar member ".fake/el_torito".
It is carried into the output only when "-boot_image any replay" was given,
unless FAKE_XORRISO_DROP_BOOT=1 simulates a build that loses the boot setup.
"""

import io
import os
import sys
import tarfile


def main(argv):
    indev = outdev = None
    replay = False
    maps = []
    extracts = []
    report = False
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg == "-version":
            print("xorriso 0.0.0 (FAKE for tests)")
            return 0
        if arg == "-osirrox":
            i += 2
        elif arg == "-indev":
            indev = argv[i + 1]
            i += 2
        elif arg == "-outdev":
            outdev = argv[i + 1]
            i += 2
        elif arg == "-boot_image":
            replay = argv[i + 1:i + 3] == ["any", "replay"]
            i += 3
        elif arg == "-map":
            maps.append((argv[i + 1], argv[i + 2].lstrip("/")))
            i += 3
        elif arg == "-extract":
            extracts.append((argv[i + 1].lstrip("/"), argv[i + 2]))
            i += 3
        elif arg in ("-chown_r", "-chgrp_r", "-chmod_r"):
            i += 1
            while i < len(argv) and argv[i] != "--":
                i += 1
            i += 1
        elif arg == "-report_el_torito":
            report = True
            i += 2
        else:
            print(f"fake xorriso: unsupported argument {arg}", file=sys.stderr)
            return 5
    if indev is None or not os.path.isfile(indev):
        print("fake xorriso: no input image", file=sys.stderr)
        return 5

    with tarfile.open(indev) as tar:
        members = {m.name: (m, tar.extractfile(m).read() if m.isfile() else None) for m in tar.getmembers()}

    status = 0
    for src, dest in extracts:
        hits = {name: data for name, (m, data) in members.items()
                if data is not None and (name == src or name.startswith(src + "/"))}
        if not hits:
            print(f"fake xorriso: {src} not found in image", file=sys.stderr)
            status = 32
            continue
        for name, data in hits.items():
            target = dest if name == src else os.path.join(dest, name[len(src) + 1:])
            os.makedirs(os.path.dirname(target) or ".", exist_ok=True)
            with open(target, "wb") as fh:
                fh.write(data)
            os.chmod(target, 0o444)  # like files read from a read-only medium

    if report:
        boot = members.get(".fake/el_torito")
        if boot and boot[1]:
            sys.stdout.write(boot[1].decode())

    if outdev:
        files = {name: data for name, (m, data) in members.items() if data is not None}
        if not replay or os.environ.get("FAKE_XORRISO_DROP_BOOT") == "1":
            files.pop(".fake/el_torito", None)
        for src, dest in maps:
            if os.path.isdir(src):
                for dirpath, _dirs, names in os.walk(src):
                    for name in names:
                        full = os.path.join(dirpath, name)
                        rel = os.path.relpath(full, src)
                        with open(full, "rb") as fh:
                            files[f"{dest}/{rel}"] = fh.read()
            else:
                with open(src, "rb") as fh:
                    files[dest] = fh.read()
        with tarfile.open(outdev, "w") as out:
            for name in sorted(files):
                info = tarfile.TarInfo(name)
                info.size = len(files[name])
                out.addfile(info, io.BytesIO(files[name]))
    return status


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
