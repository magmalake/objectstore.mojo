#!/usr/bin/env bash
#
# Builds the test binary, brings up the servers the tests need, runs them, and
# tears everything down.
#
# Two servers:
#   * tests/http_server.py — the HTTP client tests (all verbs, ranges, error
#     statuses, timeouts). Always available; python is a workspace dependency.
#   * an S3 server for the s3.mojo tests. MinIO is strongly preferred because
#     it actually *verifies* SigV4 signatures, which is the whole point of
#     testing against it; moto does not, so it only proves the request shapes.
#     Found in this order: $MINIO_BINARY, build/minio, `minio` on PATH,
#     then `moto_server`. If none is there the S3 tests skip with a message.
#
# Nothing here is secret: MinIO's well-known test credentials are the only
# ones used, and they only ever reach a server on 127.0.0.1.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/objectstore-test.XXXXXX")"
PIDS=()

cleanup() {
    for pid in "${PIDS[@]:-}"; do
        [ -n "$pid" ] && kill "$pid" 2>/dev/null
    done
    rm -rf "$WORK"
}
trap cleanup EXIT

mkdir -p build

echo "== building tests"
mojo build tests/objectstore_test.mojo -I src -I tests -o build/objectstore-test || exit 1

# ── HTTP server ────────────────────────────────────────────────────────────
mkdir -p "$WORK/www"
printf 'hello objectstore\n' > "$WORK/www/hello.txt"
python -c "
import sys
sys.stdout.write(''.join(chr(48 + i % 10) for i in range(100000)))
" > "$WORK/www/digits.txt"

python tests/http_server.py "$WORK/www" > "$WORK/http.url" &
PIDS+=($!)
for _ in $(seq 1 100); do
    [ -s "$WORK/http.url" ] && break
    sleep 0.1
done
export OBJECTSTORE_TEST_HTTP="$(cat "$WORK/http.url")"
export OBJECTSTORE_TEST_WWW="$WORK/www"
export OBJECTSTORE_TEST_DIR="$WORK/scratch"
mkdir -p "$OBJECTSTORE_TEST_DIR"
echo "== http server at $OBJECTSTORE_TEST_HTTP"

# ── S3 server ──────────────────────────────────────────────────────────────
S3_PORT=$(python -c "
import socket
s = socket.socket()
s.bind(('127.0.0.1', 0))
print(s.getsockname()[1])
s.close()
")

MINIO="${MINIO_BINARY:-}"
[ -z "$MINIO" ] && [ -x "build/minio" ] && MINIO="$ROOT/build/minio"
[ -z "$MINIO" ] && command -v minio >/dev/null 2>&1 && MINIO="$(command -v minio)"

if [ -n "$MINIO" ]; then
    echo "== starting minio ($MINIO) on :$S3_PORT"
    mkdir -p "$WORK/minio-data"
    MINIO_ROOT_USER=minioadmin MINIO_ROOT_PASSWORD=minioadmin \
        MINIO_DOMAIN=localhost \
        "$MINIO" server "$WORK/minio-data" --address ":$S3_PORT" \
        > "$WORK/minio.log" 2>&1 &
    PIDS+=($!)
    export AWS_ACCESS_KEY_ID=minioadmin
    export AWS_SECRET_ACCESS_KEY=minioadmin
    export OBJECTSTORE_TEST_S3_KIND=minio
elif python -c "import moto" 2>/dev/null; then
    echo "== starting moto_server on :$S3_PORT (signatures are NOT verified)"
    python -m moto.server -p "$S3_PORT" -H 127.0.0.1 > "$WORK/moto.log" 2>&1 &
    PIDS+=($!)
    export AWS_ACCESS_KEY_ID=testing
    export AWS_SECRET_ACCESS_KEY=testing
    export OBJECTSTORE_TEST_S3_KIND=moto
else
    echo "== no S3 server available (set MINIO_BINARY, put one at build/minio,"
    echo "   or install moto) — the S3 end-to-end tests will skip"
    export OBJECTSTORE_TEST_S3_KIND=none
fi

if [ "$OBJECTSTORE_TEST_S3_KIND" != "none" ]; then
    export AWS_REGION=us-east-1
    export AWS_ENDPOINT_URL_S3="http://127.0.0.1:$S3_PORT"
    export OBJECTSTORE_TEST_S3="http://127.0.0.1:$S3_PORT"
    export OBJECTSTORE_TEST_S3_BUCKET=objectstore-test
    # Wait for it to answer, then create the bucket with a plain PUT — this
    # is the one place the tests use an outside client, and using curl keeps
    # bucket creation from depending on the code under test.
    ready=0
    for _ in $(seq 1 150); do
        if curl -s -o /dev/null "http://127.0.0.1:$S3_PORT/minio/health/live" \
            || curl -s -o /dev/null "http://127.0.0.1:$S3_PORT/"; then
            ready=1
            break
        fi
        sleep 0.2
    done
    if [ "$ready" != "1" ]; then
        echo "== S3 server never became ready; skipping those tests"
        export OBJECTSTORE_TEST_S3_KIND=none
        unset OBJECTSTORE_TEST_S3
    else
        python tests/make_bucket.py "http://127.0.0.1:$S3_PORT" \
            "$OBJECTSTORE_TEST_S3_BUCKET" "$AWS_ACCESS_KEY_ID" \
            "$AWS_SECRET_ACCESS_KEY" || {
                echo "== bucket creation failed; skipping S3 tests"
                export OBJECTSTORE_TEST_S3_KIND=none
                unset OBJECTSTORE_TEST_S3
            }
    fi
fi

# Virtual-host addressing needs `<bucket>.localhost` to resolve. It does on
# macOS and on systemd-resolved Linux, but that is not something to assume.
if [ "${OBJECTSTORE_TEST_S3_KIND}" = "minio" ] && python -c "
import socket, sys
try:
    socket.getaddrinfo('$OBJECTSTORE_TEST_S3_BUCKET.localhost', 80)
except Exception:
    sys.exit(1)
" 2>/dev/null; then
    export OBJECTSTORE_TEST_S3_VHOST="http://localhost:$S3_PORT"
    echo "== virtual-host addressing enabled via *.localhost"
fi

echo "== running tests"
./build/objectstore-test
exit $?
