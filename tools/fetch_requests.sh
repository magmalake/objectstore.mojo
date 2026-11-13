#!/usr/bin/env bash
# Checks out Mosaad-M/requests and the packages it needs (tls, tcp, url,
# json) at pinned revisions into .deps/, for the objectstore_requests backend
# (objectstore#24), and applies tools/requests-patches/: fixes this backend
# needs that are not upstream yet. Each patch is one fix with its test.
#
#   bash tools/fetch_requests.sh [dir]     # default: .deps
#   OBJECTSTORE_REQUESTS_DEPS=.deps pixi run test
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="${1:-$ROOT/.deps}"
mkdir -p "$DEST"

pin() { # name rev
    local name=$1 rev=$2 dir="$DEST/$1"
    if [ ! -d "$dir/.git" ]; then
        git clone -q "https://github.com/Mosaad-M/$name.git" "$dir"
    fi
    git -C "$dir" fetch -q origin
    git -C "$dir" checkout -q --detach "$rev"
    local patches="$ROOT/tools/requests-patches/$name"
    if [ -d "$patches" ]; then
        git -C "$dir" -c user.name=objectstore -c user.email=objectstore@localhost \
            am -q "$patches"/*.patch
    fi
    echo "$name $(git -C "$dir" rev-parse --short HEAD) (pinned $rev)"
}

pin requests cdb1102192ef2ae1410db045860dc88db722af64
pin tls      e85825a03d1822b7e2e46c0a49632a980919edd4
pin tcp      0250b702b7b81d3ea74e1328ad77d6b44bf69d48
pin url      c048d3720d2c347eeb3134fd12c3641852f5b62d
pin json     6f88547505156823f275cd38fa619368598ec6de
