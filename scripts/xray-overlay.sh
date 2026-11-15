#!/bin/sh
# Puts xray-overlay/ on top of the pinned Xray-core source, for development.
#   scripts/xray-overlay.sh <dir>         prepare the tree (Dockerfile does the same)
#   scripts/xray-overlay.sh <dir> proto   also regenerate config.pb.go after editing config.proto
#   cd <dir> && go test ./proxy/mtproto/ ./app/iplimit/
set -eu

dest=${1:?usage: xray-overlay.sh <dir> [proto]}
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
version=$(sed -n 's/^ARG XRAY_CORE_VERSION=//p' "$root/docker/Dockerfile" | head -n 1)

[ -d "$dest/.git" ] || git clone -q --depth 1 --branch "$version" https://github.com/XTLS/Xray-core "$dest"
git -C "$dest" checkout -q -- . # undo the last run's patches (and any edits to upstream files)
cp -R "$root/xray-overlay/." "$dest/"
(cd "$dest" && git apply patches/*.patch)

if [ "${2:-}" = proto ]; then
    # needs protoc and protoc-gen-go on PATH
    for pkg in proxy/mtproto app/iplimit; do
        (cd "$dest" && protoc --go_out=. --go_opt=paths=source_relative -I . "$pkg/config.proto")
        cp "$dest/$pkg/config.pb.go" "$root/xray-overlay/$pkg/config.pb.go"
    done
fi
