#!/usr/bin/env bash
# Builds the benchmark, serves a 100 MB file over the local HTTP server, runs.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/objectstore-bench.XXXXXX")"
PIDS=()
cleanup() {
    for pid in "${PIDS[@]:-}"; do [ -n "$pid" ] && kill "$pid" 2>/dev/null; done
    rm -rf "$WORK"
}
trap cleanup EXIT

mkdir -p build "$WORK/www"
mojo build bench/bench_objectstore.mojo -I src -o build/objectstore-bench || exit 1

python -c "
import sys
sys.stdout.buffer.write(bytes((i % 251) for i in range(100 * 1024 * 1024)))
" > "$WORK/www/bench.bin"

python tests/http_server.py "$WORK/www" > "$WORK/http.url" &
PIDS+=($!)
for _ in $(seq 1 100); do [ -s "$WORK/http.url" ] && break; sleep 0.1; done

export OBJECTSTORE_BENCH_HTTP="$(cat "$WORK/http.url")"
export OBJECTSTORE_BENCH_DIR="$WORK"
./build/objectstore-bench
