#!/bin/sh
# Build the four HappyMining agent binaries reproducibly into dist/bin/.
#
#   agent/scripts/build.sh
#
# Environment:
#   HM_VERSION         version to inject (default: the constant in
#                      internal/version/version.go, the single source of truth)
#   HM_DIST_DIR        output directory (default: <repository>/dist)
#   SOURCE_DATE_EPOCH  timestamp for reproducible builds (default: fixed)
#
# Only the Go standard library is used; no module is downloaded.
set -eu

scripts_dir=$(cd "$(dirname "$0")" && pwd)
agent_dir=$(dirname "$scripts_dir")
repo_dir=$(dirname "$agent_dir")
dist_dir=${HM_DIST_DIR:-$repo_dir/dist}
module=github.com/Happymining-eu/firmware_happymining/agent

version=${HM_VERSION:-$(sed -n 's/^var Version = "\(.*\)"$/\1/p' "$agent_dir/internal/version/version.go")}
if [ -z "$version" ]; then
    echo "build.sh: cannot determine the version" >&2
    exit 1
fi
case "$version" in
    *[!0-9A-Za-z.+~-]*)
        echo "build.sh: invalid version '$version'" >&2
        exit 1
        ;;
esac

# 2026-01-01T00:00:00Z unless the caller provides a value.
: "${SOURCE_DATE_EPOCH:=1767225600}"
export SOURCE_DATE_EPOCH

export CGO_ENABLED=0 GOOS=linux GOARCH=amd64
# Never fetch a toolchain or a module: the build must work offline.
export GOTOOLCHAIN=local GOFLAGS='' GOPROXY=off

mkdir -p "$dist_dir/bin"
for bin in happymining-agent happyminingctl hm-helper hm-simulator; do
    (cd "$agent_dir" && go build -trimpath -buildvcs=false \
        -ldflags "-s -w -buildid= -X $module/internal/version.Version=$version" \
        -o "$dist_dir/bin/$bin" "./cmd/$bin")
    touch -d "@$SOURCE_DATE_EPOCH" "$dist_dir/bin/$bin"
done

(cd "$dist_dir/bin" && sha256sum happymining-agent happyminingctl hm-helper hm-simulator >SHA256SUMS)
echo "built version $version into $dist_dir/bin:"
cat "$dist_dir/bin/SHA256SUMS"
