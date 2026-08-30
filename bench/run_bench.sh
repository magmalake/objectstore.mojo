#!/usr/bin/env bash
# Builds the benchmark, serves a 100 MB file over the local HTTP server, brings
# up MinIO if one can be found (same search order as tests/run_tests.sh), runs.
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

# ── MinIO, so the signed-request number is against a real object store ──────
MINIO="${MINIO_BINARY:-}"
[ -z "$MINIO" ] && [ -x "build/minio" ] && MINIO="$ROOT/build/minio"
[ -z "$MINIO" ] && command -v minio >/dev/null 2>&1 && MINIO="$(command -v minio)"
if [ -n "$MINIO" ]; then
    S3_PORT=$(python -c "
import socket
s = socket.socket()
s.bind(('127.0.0.1', 0))
print(s.getsockname()[1])
s.close()
")
    mkdir -p "$WORK/minio-data"
    MINIO_ROOT_USER=minioadmin MINIO_ROOT_PASSWORD=minioadmin \
        "$MINIO" server "$WORK/minio-data" --address ":$S3_PORT" \
        > "$WORK/minio.log" 2>&1 &
    PIDS+=($!)
    export AWS_ACCESS_KEY_ID=minioadmin
    export AWS_SECRET_ACCESS_KEY=minioadmin
    export AWS_REGION=us-east-1
    export AWS_ENDPOINT_URL_S3="http://127.0.0.1:$S3_PORT"
    export OBJECTSTORE_BENCH_S3_BUCKET=objectstore-bench
    for _ in $(seq 1 150); do
        curl -s -o /dev/null "http://127.0.0.1:$S3_PORT/minio/health/live" && break
        sleep 0.2
    done
    if python tests/make_bucket.py "http://127.0.0.1:$S3_PORT" \
        "$OBJECTSTORE_BENCH_S3_BUCKET" "$AWS_ACCESS_KEY_ID" \
        "$AWS_SECRET_ACCESS_KEY"; then
        export OBJECTSTORE_BENCH_S3="http://127.0.0.1:$S3_PORT"
    fi
fi

./build/objectstore-bench
