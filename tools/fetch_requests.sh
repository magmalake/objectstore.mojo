#!/usr/bin/env bash
# Checks out Mosaad-M/requests and the packages it needs (tls, tcp, url,
# json) at pinned releases into .deps/, for the objectstore_requests backend
# (objectstore#24). No local patches: every fix the backend needed is
# upstream as of requests v1.11.0 and tls v1.11.0. tcp, url and json are the
# versions requests v1.11.0's mojo.lock names.
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
    git -C "$dir" fetch -q --tags origin
    git -C "$dir" checkout -q --detach "$rev"
    echo "$name $(git -C "$dir" rev-parse --short HEAD) (pinned $rev)"
}

# Tags, with the commit each pointed at when pinned, so a moved tag shows.
pin requests 29fe2a27c0e11303f3934700c0001efedf7bc415  # v1.11.0
pin tls      0ff1a82ecd8aa1b6c6abfad1466e99e0bd45a5c6  # v1.11.0
pin tcp      0250b702b7b81d3ea74e1328ad77d6b44bf69d48  # v2.1.0
pin url      c048d3720d2c347eeb3134fd12c3641852f5b62d  # v1.2.0
pin json     6f88547505156823f275cd38fa619368598ec6de  # v3.1.0
