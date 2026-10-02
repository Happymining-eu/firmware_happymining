#!/bin/sh
# Build dist/happymining-agent_<version>_amd64.deb and print its SHA-256.
#
#   agent/scripts/build-deb.sh
#
# Environment: as for build.sh, plus
#   HM_DEB_MAINTAINER  Maintainer field (default: an explicit placeholder)
#
# The package contains no credential, no pairing code and no Vast key, and it
# declares no dependency on Docker, NVIDIA or Vast packages.
set -eu

scripts_dir=$(cd "$(dirname "$0")" && pwd)
agent_dir=$(dirname "$scripts_dir")
repo_dir=$(dirname "$agent_dir")
dist_dir=${HM_DIST_DIR:-$repo_dir/dist}
pkg_dir=$agent_dir/packaging
maintainer=${HM_DEB_MAINTAINER:-HappyMining (placeholder, set HM_DEB_MAINTAINER) <packages@happymining.invalid>}

: "${SOURCE_DATE_EPOCH:=1767225600}"
export SOURCE_DATE_EPOCH
umask 022

"$scripts_dir/build.sh"

version=${HM_VERSION:-$(sed -n 's/^var Version = "\(.*\)"$/\1/p' "$agent_dir/internal/version/version.go")}
deb=$dist_dir/happymining-agent_${version}_amd64.deb
stage=$dist_dir/deb-stage

rm -rf "$stage"
install -d -m 0755 \
    "$stage/DEBIAN" \
    "$stage/usr/bin" \
    "$stage/usr/lib/happymining" \
    "$stage/lib/systemd/system" \
    "$stage/etc/happymining" \
    "$stage/etc/update-motd.d" \
    "$stage/etc/issue.d" \
    "$stage/usr/share/doc/happymining-agent/examples"

install -m 0755 "$dist_dir/bin/happymining-agent" "$dist_dir/bin/happyminingctl" "$stage/usr/bin/"
install -m 0755 "$dist_dir/bin/hm-helper" "$stage/usr/lib/happymining/hm-helper"

for unit in happymining-agent.service happymining-firstboot.service \
    happymining-helper.socket happymining-helper@.service; do
    install -m 0644 "$pkg_dir/systemd/$unit" "$stage/lib/systemd/system/$unit"
done

install -m 0644 "$pkg_dir/etc/happymining/agent.env" "$stage/etc/happymining/agent.env"
install -m 0644 "$pkg_dir/etc/happymining/helper.conf" "$stage/etc/happymining/helper.conf"
install -m 0755 "$pkg_dir/motd/60-happymining" "$stage/etc/update-motd.d/60-happymining"
install -m 0644 "$pkg_dir/issue/happymining.issue" "$stage/etc/issue.d/happymining.issue"
install -m 0644 "$agent_dir/README.md" "$stage/usr/share/doc/happymining-agent/README.md"
install -m 0644 "$pkg_dir/examples/device-policy.conf" \
    "$stage/usr/share/doc/happymining-agent/examples/device-policy.conf"

install -m 0644 "$pkg_dir/debian/conffiles" "$stage/DEBIAN/conffiles"
for script in postinst prerm postrm; do
    install -m 0755 "$pkg_dir/debian/$script" "$stage/DEBIAN/$script"
done

installed_size=$(du -k -s --exclude=DEBIAN "$stage" | cut -f1)
sed -e "s/@VERSION@/$version/" \
    -e "s/@INSTALLED_SIZE@/$installed_size/" \
    -e "s|@MAINTAINER@|$maintainer|" \
    "$pkg_dir/debian/control.in" >"$stage/DEBIAN/control"
chmod 0644 "$stage/DEBIAN/control"

# The unit files must parse before they are packaged. systemd-analyze also
# checks that the ExecStart= programs exist on the build machine, where the
# package is not installed: those three expected messages are dropped, any
# other message fails the build.
if command -v systemd-analyze >/dev/null 2>&1; then
    problems=$(systemd-analyze verify "$stage"/lib/systemd/system/happymining-* 2>&1 |
        grep -v -E '^happymining-[a-z@.]+: Command /usr/(bin/happymining-agent|bin/happyminingctl|lib/happymining/hm-helper) is not executable: No such file or directory$' || true)
    if [ -n "$problems" ]; then
        echo "build-deb.sh: systemd-analyze verify reported problems:" >&2
        echo "$problems" >&2
        exit 1
    fi
    echo "systemd-analyze verify: unit files parse (ExecStart existence is not checked on the build machine)"
    for unit in happymining-agent.service happymining-firstboot.service happymining-helper@.service; do
        systemd-analyze security --offline=true "$stage/lib/systemd/system/$unit" 2>/dev/null | tail -n 1 || true
    done
else
    echo "build-deb.sh: systemd-analyze not available; unit files were NOT verified" >&2
fi

# Reproducible archive: fixed mtimes, root ownership, one compressor thread.
find "$stage" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
dpkg-deb --root-owner-group -Zxz --threads-max=1 --build "$stage" "$deb" >/dev/null
rm -rf "$stage"

echo
dpkg-deb --info "$deb"
echo
dpkg-deb --contents "$deb"
echo
(cd "$dist_dir" && sha256sum "$(basename "$deb")" | tee "$(basename "$deb").sha256")

# Scan what was just built: no secrets, no Docker socket, expected layout.
echo
(cd "$agent_dir" && HM_REQUIRE_DEB=1 HM_DIST_DIR="$dist_dir" GOFLAGS='' GOPROXY=off GOTOOLCHAIN=local \
    CGO_ENABLED=0 go test ./packaging/ -run 'TestDeb' -count=1 -v | grep -E '^(=== RUN|--- |PASS|FAIL|ok)')
