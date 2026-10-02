#!/bin/sh
# Build dist/happymining-agent_<version>_amd64.deb and print its SHA-256.
#
#   agent/scripts/build-deb.sh
#
# Environment: as for build.sh, plus
#   HM_DEB_MAINTAINER    Maintainer field (default: an explicit placeholder)
#   HM_RELEASE_KEYS_DIR  directory whose *.pub files (base64 Ed25519 release
#                        public keys) are installed as the keys the machine
#                        trusts for firmware updates. Default: none, and then
#                        the machine refuses every update. The published test
#                        key of appliance/testdata is refused.
#
# The package contains no credential, no pairing code, no Vast key and no
# private key, and it declares no dependency on Docker, NVIDIA or Vast
# packages. It carries the plugin catalog and the vectorizer's build context
# (docs/appliance.md, sections 7, 9 and 11).
set -eu

scripts_dir=$(cd "$(dirname "$0")" && pwd)
agent_dir=$(dirname "$scripts_dir")
repo_dir=$(dirname "$agent_dir")
dist_dir=${HM_DIST_DIR:-$repo_dir/dist}
pkg_dir=$agent_dir/packaging
appliance_dir=$repo_dir/appliance
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
    "$stage/usr/share/doc/happymining-agent/examples" \
    "$stage/usr/share/happymining/catalog" \
    "$stage/usr/share/happymining/vectorizer" \
    "$stage/usr/share/happymining/release-keys"

install -m 0755 "$dist_dir/bin/happymining-agent" "$dist_dir/bin/happyminingctl" "$stage/usr/bin/"
install -m 0755 "$dist_dir/bin/hm-helper" "$stage/usr/lib/happymining/hm-helper"

# Every unit file of the packaging tree, whoever added it.
units=0
for unit in "$pkg_dir"/systemd/*; do
    [ -f "$unit" ] || continue
    case $(basename "$unit") in
        *.service | *.socket | *.timer) ;;
        *)
            echo "build-deb.sh: $(basename "$unit") in packaging/systemd is not a unit file" >&2
            exit 1
            ;;
    esac
    install -m 0644 "$unit" "$stage/lib/systemd/system/$(basename "$unit")"
    units=$((units + 1))
done
if [ "$units" -lt 4 ]; then
    echo "build-deb.sh: only $units unit files found in $pkg_dir/systemd" >&2
    exit 1
fi

# The plugin catalog: exactly plugin.json and compose.yaml of each plugin.
plugins=0
for plugin in "$appliance_dir"/catalog/*/; do
    id=$(basename "$plugin")
    for file in plugin.json compose.yaml; do
        if [ ! -f "$plugin/$file" ] || [ -L "$plugin/$file" ]; then
            echo "build-deb.sh: catalog entry $id has no regular $file" >&2
            exit 1
        fi
    done
    install -d -m 0755 "$stage/usr/share/happymining/catalog/$id"
    install -m 0644 "$plugin/plugin.json" "$plugin/compose.yaml" "$stage/usr/share/happymining/catalog/$id/"
    plugins=$((plugins + 1))
done
if [ "$plugins" -eq 0 ]; then
    echo "build-deb.sh: no plugin found in $appliance_dir/catalog" >&2
    exit 1
fi

# The vectorizer's build context: its Python sources, Dockerfile and README.
vectorizer=$appliance_dir/vectorizer
(cd "$vectorizer" && find hm_vectorizer -name '__pycache__' -prune -o -type f -name '*.py' -print) | sort |
    while read -r source; do
        install -D -m 0644 "$vectorizer/$source" "$stage/usr/share/happymining/vectorizer/$source"
    done
if [ ! -f "$stage/usr/share/happymining/vectorizer/hm_vectorizer/__main__.py" ]; then
    echo "build-deb.sh: the vectorizer sources were not found in $vectorizer" >&2
    exit 1
fi
# The Dockerfile copies requirements.lock (hash-pinned dependencies): without
# either of them the image cannot be built on the machine, so both are required.
for file in Dockerfile requirements.lock .dockerignore README.md; do
    if [ -f "$vectorizer/$file" ]; then
        install -m 0644 "$vectorizer/$file" "$stage/usr/share/happymining/vectorizer/$file"
    elif [ "$file" = Dockerfile ] || [ "$file" = requirements.lock ]; then
        echo "build-deb.sh: appliance/vectorizer/$file is missing: the vectorizer image could not be built" >&2
        exit 1
    else
        echo "build-deb.sh: WARNING: appliance/vectorizer/$file does not exist; it is not in the package" >&2
    fi
done

# Release public keys: only from HM_RELEASE_KEYS_DIR, never the test key.
test_key=$(sed -n 's/.*"public_key_b64": *"\([^"]*\)".*/\1/p' "$appliance_dir/testdata/release-vector.json")
if [ -z "$test_key" ]; then
    echo "build-deb.sh: cannot read the test key from appliance/testdata/release-vector.json" >&2
    exit 1
fi
keys=0
if [ -n "${HM_RELEASE_KEYS_DIR:-}" ]; then
    for key in "$HM_RELEASE_KEYS_DIR"/*.pub; do
        [ -e "$key" ] || continue
        value=$(tr -d '\n' <"$key")
        if ! printf '%s' "$value" | grep -Eq '^[A-Za-z0-9+/]{43}=$'; then
            echo "build-deb.sh: $key is not the base64 of a 32-byte Ed25519 public key" >&2
            exit 1
        fi
        if [ "$value" = "$test_key" ]; then
            echo "build-deb.sh: $key is the published TEST key of appliance/testdata; it is never shipped" >&2
            exit 1
        fi
        install -m 0644 "$key" "$stage/usr/share/happymining/release-keys/$(basename "$key")"
        keys=$((keys + 1))
    done
fi
if [ "$keys" -eq 0 ]; then
    echo "build-deb.sh: no release public key is packaged: machines with this package refuse every firmware update" >&2
fi

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
        grep -v -E '^happymining-[a-z@.-]+: Command /usr/(bin/happymining-agent|bin/happyminingctl|lib/happymining/hm-helper) is not executable: No such file or directory$' || true)
    if [ -n "$problems" ]; then
        echo "build-deb.sh: systemd-analyze verify reported problems:" >&2
        echo "$problems" >&2
        exit 1
    fi
    echo "systemd-analyze verify: unit files parse (ExecStart existence is not checked on the build machine)"
    for unit in "$stage"/lib/systemd/system/*.service; do
        printf '%s: ' "$(basename "$unit")"
        systemd-analyze security --offline=true "$unit" 2>/dev/null | tail -n 1 || echo "(not assessed)"
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

# Scan what was just built: no secrets, no test key, no Docker socket,
# expected layout. A package that fails the scan is removed: it must not be
# used. (The exit status of the scan is checked itself, not that of a pipe.)
echo
scan_log=$dist_dir/deb-scan.log
if (cd "$agent_dir" && HM_REQUIRE_DEB=1 HM_DIST_DIR="$dist_dir" GOFLAGS='' GOPROXY=off GOTOOLCHAIN=local \
    CGO_ENABLED=0 go test ./packaging/ -run 'TestDeb' -count=1 -v) >"$scan_log" 2>&1; then
    grep -E '^(=== RUN|--- |PASS|FAIL|ok)' "$scan_log" || true
    rm -f "$scan_log"
else
    cat "$scan_log" >&2
    rm -f "$scan_log" "$deb" "$deb.sha256"
    echo "build-deb.sh: the package scan failed; $(basename "$deb") was removed" >&2
    exit 1
fi
