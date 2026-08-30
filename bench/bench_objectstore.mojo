"""Throughput for the paths that matter: whole-file reads, range reads, and
the SHA-256 that SigV4 makes every signed PUT pay for.

The HTTP numbers are against the same local `tests/http_server.py` the tests
use — a single-threaded Python server, so they measure this client plus
loopback plus that server, not a CDN. That is still the useful number: it is
the ceiling the client is nowhere near.
"""

from std.os import getenv
from std.time import monotonic

from objectstore.crypto import sha256
from objectstore.http import HttpClient, Header, curl_version
from objectstore.httpio import HttpInputFile
from objectstore.local import LocalInputFile, LocalOutputFile, local_delete
from objectstore.s3 import S3Client, S3Config


comptime MB = 1024 * 1024


def _rate(label: String, bytes: Int, elapsed_ns: Int) -> None:
    var secs = Float64(elapsed_ns) / 1.0e9
    var mbps = (Float64(bytes) / Float64(MB)) / secs
    print(label, "  ", bytes // MB, "MB in", secs, "s  =", mbps, "MB/s")


def _per_request(label: String, requests: Int, bytes: Int, elapsed_ns: Int) -> None:
    """Range reads are latency-bound, so the number that matters is the cost of
    one request, not the aggregate throughput."""
    var secs = Float64(elapsed_ns) / 1.0e9
    var mbps = (Float64(bytes) / Float64(MB)) / secs
    var ms = (secs * 1000.0) / Float64(requests)
    print(label, "  ", requests, "requests in", secs, "s  =", ms,
          "ms/request  (", mbps, "MB/s )")


def main() raises:
    print(curl_version())
    var scratch = getenv("OBJECTSTORE_BENCH_DIR", "build")
    var path = scratch + "/bench-100mb.bin"
    var n = 100 * MB

    print("\n== preparing", n // MB, "MB")
    var data = List[UInt8](capacity=n)
    for i in range(n):
        data.append(UInt8(i % 251))
    LocalOutputFile(path).overwrite(Span(data))

    # ── local whole-file read ──────────────────────────────────────────────
    var f = LocalInputFile(path)
    var t0 = monotonic()
    var got = f.read_all()
    var t1 = monotonic()
    _rate("local read_all      ", len(got), t1 - t0)
    _ = got^

    # ── local range reads: a Parquet footer pattern ────────────────────────
    t0 = monotonic()
    var total = 0
    for k in range(1000):
        total += len(f.read_range(k * 64 * 1024, 64 * 1024))
    t1 = monotonic()
    _rate("local read_range x1k", total, t1 - t0)

    # ── SHA-256, the cost SigV4 adds to a signed PUT ───────────────────────
    t0 = monotonic()
    var digest = sha256(Span(data))
    t1 = monotonic()
    _rate("sha256 (signed PUT) ", n, t1 - t0)
    _ = digest^

    # ── HTTP ───────────────────────────────────────────────────────────────
    var base = getenv("OBJECTSTORE_BENCH_HTTP", "")
    if base == "":
        print("\n(no OBJECTSTORE_BENCH_HTTP — skipping the HTTP benchmarks)")
        local_delete(path)
        return

    var url = base + "/files/bench.bin"
    var hf = HttpInputFile(url)
    t0 = monotonic()
    var body = hf.read_all()
    t1 = monotonic()
    _rate("http read_all       ", len(body), t1 - t0)
    _ = body^

    t0 = monotonic()
    total = 0
    for k in range(200):
        total += len(hf.read_range(k * 64 * 1024, 64 * 1024))
    t1 = monotonic()
    _per_request("http read_range x200", 200, total, t1 - t0)

    # ── S3 / MinIO ─────────────────────────────────────────────────────────
    # The same 200-range pattern, but signed and against a real object store:
    # this is the number an Iceberg scan actually pays.
    var s3 = getenv("OBJECTSTORE_BENCH_S3", "")
    if s3 != "":
        var bucket = getenv("OBJECTSTORE_BENCH_S3_BUCKET", "objectstore-bench")
        var client = S3Client(S3Config.from_env())
        var key = String("bench/ranges.bin")
        var payload = List[UInt8](capacity=16 * MB)
        for i in range(16 * MB):
            payload.append(UInt8(i % 251))
        t0 = monotonic()
        client.put_object(bucket, key, Span(payload))
        t1 = monotonic()
        _rate("s3   put_object      ", len(payload), t1 - t0)

        t0 = monotonic()
        total = 0
        for k in range(200):
            total += len(
                client.get_object(
                    bucket, key, k * 64 * 1024, (k + 1) * 64 * 1024 - 1
                )
            )
        t1 = monotonic()
        _per_request("s3   read_range x200", 200, total, t1 - t0)

        t0 = monotonic()
        var whole = client.get_object(bucket, key)
        t1 = monotonic()
        _rate("s3   get_object      ", len(whole), t1 - t0)
        _ = whole^
        client.delete_object(bucket, key)
    else:
        print("\n(no OBJECTSTORE_BENCH_S3 — skipping the S3 benchmarks)")

    local_delete(path)
