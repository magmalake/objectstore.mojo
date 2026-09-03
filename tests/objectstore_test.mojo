"""Test suite for objectstore.mojo.

Tests that need a server look for one in the environment and print a `SKIP`
line with the reason when it is absent, rather than failing — `tests/run_tests.sh`
is what puts the servers there. Everything else (crypto, URIs, SigV4, XML,
addressing) runs unconditionally and needs no network at all.
"""

from std.collections import Dict
from std.os import getenv, remove
from std.os.path import exists as path_exists
from std.ffi import OwnedDLHandle, c_size_t
from std.testing import TestSuite, assert_equal, assert_raises, assert_true

from sigv4_vectors import sigv4_cases

from objectstore.crypto import (
    Sha256,
    from_hex,
    hmac_sha256,
    sha256,
    sha256_backend,
    sha256_hex,
    sha256_scalar,
    sha256_target_features,
    to_hex,
)
from objectstore.azure import (
    AzureClient,
    AzureConfig,
    BLOB_API_VERSION,
    parse_azure_uri,
)
from objectstore.fileio import (
    BACKEND_AZURE,
    BACKEND_GCS,
    BACKEND_HTTP,
    BACKEND_LOCAL,
    BACKEND_S3,
    FileIOResolver,
)
from objectstore.gcs import GcsConfig, split_gcs_uri
from objectstore.http import (
    Header,
    HttpClient,
    RetryPolicy,
    SHARED_POOL,
    backoff_delay_ms,
    free_connection_pool,
    header_blob,
    is_idempotent,
    new_connection_pool,
    parse_headers,
    pool_stats,
    reset_pool_stats,
    retryable_status,
    s3_retryable_error,
    shim_abi,
)
from objectstore.httpio import HttpInputFile
from objectstore.local import (
    LocalInputFile,
    LocalOutputFile,
    local_delete,
    local_list,
)
from objectstore.ranges import (
    ByteRange,
    DEFAULT_COALESCE_GAP,
    plan_ranges,
    read_ranges_coalesced,
)
from objectstore.path import (
    basename,
    join,
    parent,
    parse_uri,
    strip_scheme,
    url_encode,
)
from objectstore.s3 import (
    ListResult,
    MIN_PART_SIZE,
    S3Client,
    S3Config,
    S3Credentials,
    parse_list_objects,
    split_s3_uri,
    xml_blocks,
    xml_text,
    xml_unescape,
)
from objectstore.sigv4 import (
    AmzTime,
    canonical_path,
    canonical_query,
    QueryParam,
    sign_request,
)


def _bytes(s: String) -> List[UInt8]:
    var out = List[UInt8]()
    var b = s.as_bytes()
    for k in range(len(b)):
        out.append(b[k])
    return out^


def _repeat(byte: UInt8, n: Int) -> List[UInt8]:
    var out = List[UInt8](capacity=n)
    for _ in range(n):
        out.append(byte)
    return out^


# ---------------------------------------------------------------------------
# crypto
# ---------------------------------------------------------------------------


def test_sha256_vectors() raises:
    assert_equal(
        sha256_hex(String("abc")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    )
    assert_equal(
        sha256_hex(String("")),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    )
    assert_equal(
        sha256_hex(
            String("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
        ),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    )


def test_sha256_one_million_a() raises:
    """FIPS 180-4's long-message vector, fed in awkward chunk sizes so the
    block-buffering path is exercised rather than the aligned one."""
    var h = Sha256()
    var chunk = _repeat(97, 1000)
    for _ in range(1000):
        h.update(Span(chunk))
    assert_equal(
        to_hex(Span(h.digest())),
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
    )

    var h2 = Sha256()
    var odd = _repeat(97, 7)
    for _ in range(142857):
        h2.update(Span(odd))
    h2.update(Span(_repeat(97, 1)))
    assert_equal(
        to_hex(Span(h2.digest())),
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
    )


@always_inline
def _xorshift32(mut state: UInt32) -> UInt32:
    """A deterministic PRNG, so a failure is reproducible from the seed alone.
    """
    var x = state
    x ^= x << UInt32(13)
    x ^= x >> UInt32(17)
    x ^= x << UInt32(5)
    state = x
    return x


def _random_bytes(mut state: UInt32, n: Int) -> List[UInt8]:
    var out = List[UInt8](capacity=n)
    for _ in range(n):
        out.append(UInt8(Int(_xorshift32(state) & UInt32(0xFF))))
    return out^


@always_inline
def _digests_equal(a: List[UInt8], b: List[UInt8]) -> Bool:
    if len(a) != len(b):
        return False
    for k in range(len(a)):
        if a[k] != b[k]:
            return False
    return True


def test_sha256_hardware_matches_scalar() raises:
    """Cross-check whichever backend this build compiled in against the
    portable one, over 1000 pseudo-random buffers of 0..10 KB.

    The FIPS vectors cover three lengths; a message-schedule bug in the
    hardware path would sail past them and show up only at some particular
    block count, so the randomized sweep is the test that actually guards the
    intrinsics. Mismatches are counted and asserted once — `assert_equal` is
    expensive enough that a thousand of them would dominate the suite.
    """
    print("sha256 backend:", sha256_backend())
    print("sha256 target features:", sha256_target_features())
    var rng = UInt32(0x9E3779B9)
    var buf = _random_bytes(rng, 10240)
    var bad = 0
    var checked = 0
    for trial in range(1000):
        if trial % 100 == 0:
            buf = _random_bytes(rng, 10240)
        var n = Int(_xorshift32(rng) % UInt32(10241))
        var span = Span(buf)[0:n]
        if not _digests_equal(sha256(span), sha256_scalar(span)):
            bad += 1
            print("sha256 != sha256_scalar at length", n)
        checked += 1
    assert_equal(checked, 1000)
    assert_equal(bad, 0)


def test_sha256_streaming_matches_one_shot() raises:
    """The same bytes fed in ragged chunks must hash the same as one call —
    the multi-block fast path only runs on the whole-blocks remainder, so the
    held-over partial block is where a streaming bug would hide."""
    var rng = UInt32(0x12345678)
    var buf = _random_bytes(rng, 5000)
    var bad = 0
    for _ in range(200):
        var n = Int(_xorshift32(rng) % UInt32(5001))
        var h = Sha256()
        var off = 0
        while off < n:
            var take = Int(_xorshift32(rng) % UInt32(200)) + 1
            if off + take > n:
                take = n - off
            h.update(Span(buf)[off : off + take])
            off += take
        if not _digests_equal(h.digest(), sha256(Span(buf)[0:n])):
            bad += 1
            print("streaming != one-shot at length", n)
    assert_equal(bad, 0)


def _libcrypto_path() -> String:
    """libcrypto ships in this environment as a libcurl dependency. It is a
    test-only oracle — nothing in `objectstore` links it."""
    var prefix = getenv("CONDA_PREFIX", "")
    if prefix == "":
        return String("")
    var candidates: List[String] = [
        String("/lib/libcrypto.3.dylib"),
        String("/lib/libcrypto.so.3"),
        String("/lib/libcrypto.dylib"),
        String("/lib/libcrypto.so"),
    ]
    for k in range(len(candidates)):
        var path = prefix + candidates[k]
        if path_exists(path):
            return path^
    return String("")


def test_sha256_matches_openssl() raises:
    """Cross-check against a second, independent implementation: OpenSSL's
    `SHA256()`. libcrypto is already in the environment as a libcurl
    dependency — this is a test-only oracle, nothing in `objectstore` links
    it."""
    var path = _libcrypto_path()
    if path == "":
        print("SKIP test_sha256_matches_openssl: no libcrypto in CONDA_PREFIX")
        return
    var lib = OwnedDLHandle(path)
    var f = lib.get_function[UnsafePointer[UInt8, MutUntrackedOrigin]]("SHA256")
    var rng = UInt32(0xC0FFEE11)
    var buf = _random_bytes(rng, 10240)
    var out = List[UInt8](length=32, fill=0)
    var bad = 0
    var checked = 0
    for trial in range(1000):
        if trial % 100 == 0:
            buf = _random_bytes(rng, 10240)
        var n = Int(_xorshift32(rng) % UInt32(10241))
        _ = f(buf.unsafe_ptr(), c_size_t(n), out.unsafe_ptr())
        var span = Span(buf)[0:n]
        if not _digests_equal(sha256(span), out):
            bad += 1
            print("sha256 != OpenSSL at length", n)
        if not _digests_equal(sha256_scalar(span), out):
            bad += 1
            print("sha256_scalar != OpenSSL at length", n)
        checked += 1
    assert_equal(checked, 1000)
    assert_equal(bad, 0)
    # Keep `lib` alive past `f`'s last call in the loop above: Mojo destroys a
    # value at its last syntactic use, and `f` was obtained from
    # `lib.get_function`, so without this `lib.__del__` (dlclose) would run
    # before the loop even started — see the FFI-handle-lifetime note in
    # src/objectstore/http.mojo.
    _ = lib^
    _ = buf^
    _ = out^


def test_hmac_sha256_rfc4231() raises:
    assert_equal(
        to_hex(Span(hmac_sha256(Span(_repeat(0x0B, 20)), String("Hi There")))),
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
    )
    assert_equal(
        to_hex(
            Span(
                hmac_sha256(
                    _bytes(String("Jefe")),
                    String("what do ya want for nothing?"),
                )
            )
        ),
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
    )
    assert_equal(
        to_hex(
            Span(hmac_sha256(Span(_repeat(0xAA, 20)), Span(_repeat(0xDD, 50))))
        ),
        "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
    )
    var key4 = List[UInt8]()
    for i in range(1, 26):
        key4.append(UInt8(i))
    assert_equal(
        to_hex(Span(hmac_sha256(Span(key4), Span(_repeat(0xCD, 50))))),
        "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
    )
    # Cases 6 and 7: a key longer than the 64-byte block, which must be
    # hashed down first.
    assert_equal(
        to_hex(
            Span(
                hmac_sha256(
                    Span(_repeat(0xAA, 131)),
                    String(
                        "Test Using Larger Than Block-Size Key - Hash Key First"
                    ),
                )
            )
        ),
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
    )
    assert_equal(
        to_hex(
            Span(
                hmac_sha256(
                    Span(_repeat(0xAA, 131)),
                    String(
                        "This is a test using a larger than block-size key"
                        " and a larger than block-size data. The key needs"
                        " to be hashed before being used by the HMAC"
                        " algorithm."
                    ),
                )
            )
        ),
        "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
    )


def test_hex_roundtrip() raises:
    var data = List[UInt8]()
    for i in range(256):
        data.append(UInt8(i))
    var hex = to_hex(Span(data))
    assert_equal(hex.byte_length(), 512)
    var back = from_hex(hex)
    assert_equal(len(back), 256)
    for i in range(256):
        assert_equal(back[i], UInt8(i))
    with assert_raises():
        _ = from_hex(String("abc"))
    with assert_raises():
        _ = from_hex(String("zz"))


# ---------------------------------------------------------------------------
# path / URI
# ---------------------------------------------------------------------------


def test_parse_uri_s3() raises:
    var u = parse_uri(String("s3://my-bucket/warehouse/db/table/data.parquet"))
    assert_equal(u.scheme, "s3")
    assert_equal(u.bucket, "my-bucket")
    assert_equal(u.key, "warehouse/db/table/data.parquet")
    assert_true(u.is_object_store())
    assert_equal(
        u.canonical(), "s3://my-bucket/warehouse/db/table/data.parquet"
    )

    var bare = parse_uri(String("s3://only-bucket"))
    assert_equal(bare.bucket, "only-bucket")
    assert_equal(bare.key, "")


def test_parse_uri_file_and_bare() raises:
    var u = parse_uri(String("file:///var/warehouse/x.avro"))
    assert_equal(u.scheme, "file")
    assert_equal(u.local_path(), "/var/warehouse/x.avro")
    assert_true(u.is_local())

    # `file://host/path` — the host is not addressable, the path survives.
    assert_equal(
        parse_uri(String("file://localhost/var/x")).local_path(), "/var/x"
    )
    assert_equal(parse_uri(String("/etc/hosts")).local_path(), "/etc/hosts")
    assert_equal(
        parse_uri(String("tests/fixtures/a")).local_path(), "tests/fixtures/a"
    )
    assert_equal(strip_scheme(String("file:///a/b")), "/a/b")
    assert_equal(strip_scheme(String("s3://b/k")), "s3://b/k")


def test_parse_uri_http_query() raises:
    var u = parse_uri(
        String("https://host.example:8443/bucket/key?X-Amz-Signature=abc&z=1")
    )
    assert_equal(u.scheme, "https")
    assert_equal(u.bucket, "host.example:8443")
    assert_equal(u.key, "bucket/key")
    assert_equal(u.query, "X-Amz-Signature=abc&z=1")
    assert_true(not u.is_object_store())


def test_path_algebra() raises:
    assert_equal(join(String("s3://b/a"), String("c")), "s3://b/a/c")
    assert_equal(join(String("s3://b/a/"), String("c")), "s3://b/a/c")
    assert_equal(join(String("s3://b/a"), String("s3://x/y")), "s3://x/y")
    assert_equal(basename(String("s3://b/a/c.parquet")), "c.parquet")
    assert_equal(basename(String("s3://b/a/c?sig=1")), "c")
    assert_equal(parent(String("s3://b/a/c")), "s3://b/a")
    assert_equal(parent(String("s3://b/c")), "s3://b")
    assert_equal(parent(String("s3://b")), "s3://b")
    assert_equal(parent(String("/a/b/c")), "/a/b")
    assert_equal(parent(String("solo")), "")


def test_url_encode() raises:
    assert_equal(url_encode(String("a b")), "a%20b")
    assert_equal(url_encode(String("a/b")), "a%2Fb")
    assert_equal(url_encode(String("a/b"), encode_slash=False), "a/b")
    assert_equal(url_encode(String("-._~")), "-._~")
    assert_equal(url_encode(String("ሴ")), "%E1%88%B4")


# ---------------------------------------------------------------------------
# local filesystem
# ---------------------------------------------------------------------------


def _scratch() raises -> String:
    var d = getenv("OBJECTSTORE_TEST_DIR", "")
    if d == "":
        return String("build/scratch")
    return d^


def test_local_roundtrip() raises:
    var path = _scratch() + "/local-roundtrip.bin"
    var data = List[UInt8]()
    for i in range(5000):
        data.append(UInt8(i % 251))

    var out = LocalOutputFile(path)
    out.overwrite(Span(data))
    var inp = LocalInputFile(path)
    assert_true(inp.exists())
    assert_equal(inp.length(), 5000)
    var got = inp.read_all()
    assert_equal(len(got), 5000)
    for i in range(0, 5000, 137):
        assert_equal(got[i], data[i])

    # `create` refuses to clobber; `overwrite` does not.
    with assert_raises():
        out.create(Span(data))
    out.overwrite(Span(_bytes(String("short"))))
    assert_equal(LocalInputFile(path).length(), 5)

    local_delete(path)
    assert_true(not LocalInputFile(path).exists())
    # Deleting again is not an error.
    local_delete(path)


def test_local_range_reads() raises:
    var path = _scratch() + "/local-range.bin"
    var data = List[UInt8]()
    for i in range(1000):
        data.append(UInt8(i % 256))
    LocalOutputFile(path).overwrite(Span(data))
    var f = LocalInputFile(path)

    var mid = f.read_range(100, 50)
    assert_equal(len(mid), 50)
    assert_equal(mid[0], data[100])
    assert_equal(mid[49], data[149])

    # A negative offset is a suffix read, the way an HTTP suffix range is.
    var tail = f.read_range(-16, 16)
    assert_equal(len(tail), 16)
    assert_equal(tail[15], data[999])

    # A short read at EOF is not an error.
    assert_equal(len(f.read_range(990, 100)), 10)
    assert_equal(len(f.read_range(0, 0)), 0)
    local_delete(path)


def test_local_list() raises:
    var root = _scratch() + "/listing"
    LocalOutputFile(root + "/a.txt").overwrite(Span(_bytes(String("a"))))
    LocalOutputFile(root + "/sub/b.txt").overwrite(Span(_bytes(String("b"))))
    var found = local_list(root)
    assert_equal(len(found), 2)
    var have_a = False
    var have_b = False
    for k in range(len(found)):
        if found[k].endswith("/a.txt"):
            have_a = True
        if found[k].endswith("/sub/b.txt"):
            have_b = True
    assert_true(have_a)
    assert_true(have_b)
    # A prefix that names a file lists that file, matching S3's semantics.
    assert_equal(len(local_list(root + "/a.txt")), 1)
    assert_equal(len(local_list(root + "/nope")), 0)


# ---------------------------------------------------------------------------
# HTTP client
# ---------------------------------------------------------------------------


def _http_base() -> String:
    return getenv("OBJECTSTORE_TEST_HTTP", "")


def test_http_headers_encoding() raises:
    var hs = List[Header]()
    hs.append(Header("Accept", "application/json"))
    hs.append(Header("X-Test", "abc"))
    assert_equal(header_blob(hs), "Accept: application/json\nX-Test: abc")

    var parsed = parse_headers(
        String(
            "HTTP/1.1 301 Moved\r\nLocation: /x\r\n\r\nHTTP/1.1 200 OK\r\n"
            'Content-Type: text/plain\r\nETag: "abc"\r\n\r\n'
        )
    )
    # Only the final response block survives: a redirect chain would otherwise
    # leave the caller reading the wrong headers.
    assert_equal(len(parsed), 2)
    assert_equal(parsed[0].name, "Content-Type")
    assert_equal(parsed[1].value, '"abc"')


def test_http_get_and_range() raises:
    var base = _http_base()
    if base == "":
        print("SKIP test_http_get_and_range: OBJECTSTORE_TEST_HTTP unset")
        return
    var c = HttpClient()
    var r = c.get(base + "/files/hello.txt")
    assert_equal(r.status, 200)
    assert_equal(r.text(), "hello objectstore\n")
    assert_equal(r.header("content-type"), "application/octet-stream")
    assert_true(r.ok())

    var ranged = c.get(base + "/files/digits.txt", List[Header](), 10, 19)
    assert_equal(ranged.status, 206)
    assert_equal(len(ranged.body), 10)
    assert_equal(ranged.text(), "0123456789")

    var open_ended = c.get(base + "/files/hello.txt", List[Header](), 6, -1)
    assert_equal(open_ended.status, 206)
    assert_equal(open_ended.text(), "objectstore\n")


def test_http_head_and_errors() raises:
    var base = _http_base()
    if base == "":
        print("SKIP test_http_head_and_errors: OBJECTSTORE_TEST_HTTP unset")
        return
    var c = HttpClient()
    var h = c.head(base + "/files/digits.txt")
    assert_equal(h.status, 200)
    assert_equal(h.header("Content-Length"), "100000")
    assert_equal(len(h.body), 0)

    assert_equal(c.get(base + "/files/missing.txt").status, 404)
    var e500 = c.get(base + "/status/500")
    assert_equal(e500.status, 500)
    assert_true(not e500.ok())
    assert_true(e500.body_excerpt().find("status 500") >= 0)
    with assert_raises():
        e500.raise_for_status("boom")
    assert_equal(c.get(base + "/status/403").status, 403)


def test_http_verbs_and_custom_headers() raises:
    var base = _http_base()
    if base == "":
        print("SKIP test_http_verbs_and_custom_headers: no server")
        return
    var c = HttpClient()
    var hs = List[Header]()
    hs.append(Header("X-Test", "marker"))

    var body = _bytes(String("payload-bytes"))
    var posted = c.post(base + "/echo", Span(body), hs)
    assert_equal(posted.status, 200)
    assert_true(posted.text().find("method=POST") >= 0)
    assert_true(posted.text().find("x-test=marker") >= 0)
    assert_true(posted.text().find("body-len=13") >= 0)

    var put = c.put(base + "/echo", Span(body), hs)
    assert_true(put.text().find("method=PUT") >= 0)
    assert_true(put.text().find("body=payload-bytes") >= 0)

    var deleted = c.delete(base + "/echo")
    assert_true(deleted.text().find("method=DELETE") >= 0)

    # A real PUT/DELETE lifecycle against a file resource.
    var created = c.put(base + "/files/created.txt", Span(body))
    assert_equal(created.status, 201)
    assert_equal(c.get(base + "/files/created.txt").text(), "payload-bytes")
    assert_equal(c.put(base + "/files/created.txt", Span(body)).status, 204)
    assert_equal(c.delete(base + "/files/created.txt").status, 204)
    assert_equal(c.delete(base + "/files/created.txt").status, 404)


def test_http_timeout() raises:
    var base = _http_base()
    if base == "":
        print("SKIP test_http_timeout: no server")
        return
    var c = HttpClient()
    c.timeout_ms = 300
    # A transport failure raises; an HTTP error status does not.
    with assert_raises():
        _ = c.get(base + "/slow?ms=3000")


def test_http_input_file() raises:
    var base = _http_base()
    if base == "":
        print("SKIP test_http_input_file: no server")
        return
    var f = HttpInputFile(base + "/files/digits.txt")
    assert_true(f.exists())
    assert_equal(f.length(), 100000)
    assert_equal(len(f.read_all()), 100000)

    var mid = f.read_range(500, 10)
    assert_equal(len(mid), 10)
    assert_equal(String(StringSlice(unsafe_from_utf8=Span(mid))), "0123456789")

    # Suffix range: the last 5 bytes of 100 000 digits.
    var tail = f.read_range(-5, 5)
    assert_equal(len(tail), 5)
    assert_equal(String(StringSlice(unsafe_from_utf8=Span(tail))), "56789")

    assert_true(not HttpInputFile(base + "/files/nope.txt").exists())


def test_http_connection_reuse() raises:
    """Twenty requests, one TCP connection — asserted from both ends.

    curl's own connection counter says how many sockets it opened; the test
    server counts the distinct client ports it saw. Timing would only suggest
    reuse, these two prove it.
    """
    var base = _http_base()
    if base == "":
        print("SKIP test_http_connection_reuse: no server")
        return
    if shim_abi() < 2:
        print("SKIP test_http_connection_reuse: shim ABI", shim_abi(), "< 2")
        return
    var c = HttpClient()
    reset_pool_stats()
    # This one may reuse a connection an earlier test left open, which is
    # itself the behaviour under test; what must not happen is a new socket
    # for each of the twenty that follow.
    assert_equal(c.get(base + "/ports/reset").status, 200)
    for _ in range(20):
        assert_equal(c.get(base + "/files/hello.txt").status, 200)
    var stats = pool_stats()
    assert_equal(stats[0], 21)
    assert_true(stats[1] <= 1)
    assert_true(c.get(base + "/ports").text().find("count=1") >= 0)


def test_http_dedicated_pool() raises:
    """A private pool opens exactly one connection and no more."""
    var base = _http_base()
    if base == "":
        print("SKIP test_http_dedicated_pool: no server")
        return
    if shim_abi() < 2:
        print("SKIP test_http_dedicated_pool: shim ABI", shim_abi(), "< 2")
        return
    var pool = new_connection_pool()
    assert_true(pool != SHARED_POOL)
    var c = HttpClient()
    c.pool = pool
    for _ in range(5):
        assert_equal(c.get(base + "/files/hello.txt").status, 200)
    var stats = pool_stats(pool)
    assert_equal(stats[0], 5)
    assert_equal(stats[1], 1)
    free_connection_pool(pool)


# ---------------------------------------------------------------------------
# Range coalescing
# ---------------------------------------------------------------------------


def _digits(offset: Int, length: Int) -> String:
    """What `www/digits.txt` holds at `[offset, offset+length)`."""
    var out = List[UInt8](capacity=length)
    for i in range(offset, offset + length):
        out.append(UInt8(48 + i % 10))
    return String(StringSlice(unsafe_from_utf8=Span(out)))


def test_plan_ranges() raises:
    var near = List[ByteRange]()
    near.append(ByteRange(0, 100))
    near.append(ByteRange(100, 100))  # adjacent
    near.append(ByteRange(1200, 50))  # 1000 bytes on
    var plan = plan_ranges(near, 1024)
    assert_equal(len(plan.fetches), 1)
    assert_equal(plan.fetches[0].offset, 0)
    assert_equal(plan.fetches[0].length, 1250)
    assert_equal(plan.group_offset[2], 1200)
    assert_equal(plan.requests_saved(3), 2)

    # The same ranges with a gap too small to bridge the hole.
    var split = plan_ranges(near, 512)
    assert_equal(len(split.fetches), 2)
    assert_equal(split.fetches[0].length, 200)
    assert_equal(split.fetches[1].offset, 1200)
    assert_equal(split.group[2], 1)
    assert_equal(split.group_offset[2], 0)

    # Out of order in, original order out — a footer asked for last is
    # answered last even though it is fetched first.
    var jumbled = List[ByteRange]()
    jumbled.append(ByteRange(900, 100))
    jumbled.append(ByteRange(0, 100))
    jumbled.append(ByteRange(400, 100))
    var jp = plan_ranges(jumbled, DEFAULT_COALESCE_GAP)
    assert_equal(len(jp.fetches), 1)
    assert_equal(jp.fetches[0].offset, 0)
    assert_equal(jp.fetches[0].length, 1000)
    assert_equal(jp.group_offset[0], 900)
    assert_equal(jp.group_offset[1], 0)
    assert_equal(jp.group_offset[2], 400)

    # Overlapping ranges are one fetch, not two, and neither is stretched.
    var overlap = List[ByteRange]()
    overlap.append(ByteRange(0, 100))
    overlap.append(ByteRange(50, 20))
    var op = plan_ranges(overlap, 0)
    assert_equal(len(op.fetches), 1)
    assert_equal(op.fetches[0].length, 100)

    # A suffix range has no known position, so it is left on its own.
    var suffix = List[ByteRange]()
    suffix.append(ByteRange(0, 10))
    suffix.append(ByteRange(-5, 5))
    suffix.append(ByteRange(20, 0))
    var sp = plan_ranges(suffix, DEFAULT_COALESCE_GAP)
    assert_equal(len(sp.fetches), 1)
    assert_equal(sp.group[1], -1)
    assert_equal(sp.group[2], -1)

    assert_equal(len(plan_ranges(List[ByteRange]()).fetches), 0)


def test_http_read_ranges_coalesce() raises:
    """Six ranges, one request — and the same bytes as six requests."""
    var base = _http_base()
    if base == "":
        print("SKIP test_http_read_ranges_coalesce: no server")
        return
    var f = HttpInputFile(base + "/files/digits.txt")
    var want = List[ByteRange]()
    want.append(ByteRange(10, 10))
    want.append(ByteRange(37, 13))
    want.append(ByteRange(1000, 8))
    want.append(ByteRange(1008, 8))
    want.append(ByteRange(5000, 20))
    want.append(ByteRange(3, 4))

    reset_pool_stats()
    var got = f.read_ranges(want)
    var stats = pool_stats()
    assert_equal(len(got), 6)
    for k in range(len(want)):
        assert_equal(
            String(StringSlice(unsafe_from_utf8=Span(got[k]))),
            _digits(want[k].offset, want[k].length),
        )
    if shim_abi() >= 2:
        assert_equal(stats[0], 1)

    # A 64-byte gap splits them into three groups — the three clusters at 3,
    # at 1000 and at 5000 — and the bytes are identical either way.
    reset_pool_stats()
    var split = read_ranges_coalesced(f, want, 64)
    assert_equal(len(split), 6)
    for k in range(len(want)):
        assert_equal(
            String(StringSlice(unsafe_from_utf8=Span(split[k]))),
            _digits(want[k].offset, want[k].length),
        )
    if shim_abi() >= 2:
        assert_equal(pool_stats()[0], 3)


def test_resolver_read_ranges() raises:
    """The resolver's `read_ranges` over a local file — the default loop."""
    var dir = getenv("OBJECTSTORE_TEST_DIR", "")
    if dir == "":
        print("SKIP test_resolver_read_ranges: OBJECTSTORE_TEST_DIR unset")
        return
    var path = dir + "/ranges.bin"
    var data = List[UInt8](capacity=4096)
    for i in range(4096):
        data.append(UInt8(i % 256))
    LocalOutputFile(path).overwrite(Span(data))

    var io = FileIOResolver()
    var want = List[ByteRange]()
    want.append(ByteRange(0, 16))
    want.append(ByteRange(2048, 16))
    want.append(ByteRange(4080, 16))
    var got = io.read_ranges(String("file://") + path, want)
    assert_equal(len(got), 3)
    assert_equal(got[0][0], data[0])
    assert_equal(got[1][0], data[2048])
    assert_equal(got[2][15], data[4095])
    local_delete(path)


# ---------------------------------------------------------------------------
# Retries
# ---------------------------------------------------------------------------


def _fast_retries(max_retries: Int) -> RetryPolicy:
    """The default policy with the waiting taken out, so the suite stays fast.

    `backoff_delay_ms` is unit-tested separately; what these tests are about
    is *which* requests are repeated, not how long the pause is.
    """
    var p = RetryPolicy()
    p.max_retries = max_retries
    p.base_delay_ms = 1
    p.max_delay_ms = 4
    return p^


def _attempts(base: String, key: String) raises -> Int:
    var c = HttpClient()
    var r = c.get(base + "/attempts?key=" + key)
    var text = r.text()
    var at = text.find("attempts=")
    var end = text.find("\n", at)
    return Int(
        String(
            StringSlice(unsafe_from_utf8=Span(text.as_bytes())[at + 9 : end])
        )
    )


def test_retry_classification() raises:
    """Which statuses and bodies are worth trying again — no server needed."""
    assert_true(retryable_status(429))
    assert_true(retryable_status(500))
    assert_true(retryable_status(503))
    assert_true(retryable_status(504))
    # Permanent facts about the server, not weather.
    assert_true(not retryable_status(501))
    assert_true(not retryable_status(505))
    assert_true(not retryable_status(404))
    assert_true(not retryable_status(403))
    assert_true(not retryable_status(200))

    var slow = _bytes(
        String("<Error><Code>SlowDown</Code><Message>x</Message></Error>")
    )
    assert_true(s3_retryable_error(Span(slow)))
    var timeout = _bytes(String("<Error><Code>RequestTimeout</Code></Error>"))
    assert_true(s3_retryable_error(Span(timeout)))
    var denied = _bytes(String("<Error><Code>AccessDenied</Code></Error>"))
    assert_true(not s3_retryable_error(Span(denied)))

    var plain = List[Header]()
    assert_true(is_idempotent(String("GET"), plain))
    assert_true(is_idempotent(String("PUT"), plain))
    assert_true(is_idempotent(String("DELETE"), plain))
    assert_true(not is_idempotent(String("POST"), plain))
    var keyed = List[Header]()
    keyed.append(Header("Idempotency-Key", "abc-123"))
    assert_true(is_idempotent(String("POST"), keyed))
    # iceberg.mojo sets the header with this exact casing; matching is
    # case-insensitive because HTTP is.
    var lower = List[Header]()
    lower.append(Header("idempotency-key", "abc-123"))
    assert_true(is_idempotent(String("POST"), lower))


def test_backoff_delay() raises:
    """Exponential, jittered, and capped."""
    var p = RetryPolicy()
    assert_equal(p.max_retries, 3)
    for attempt in range(1, 5):
        var window = 100 * (1 << (attempt - 1))
        var d = backoff_delay_ms(p, attempt)
        assert_true(d >= window // 2)
        assert_true(d <= window)
    # The ceiling holds however many attempts have gone by.
    assert_true(backoff_delay_ms(p, 20) <= p.max_delay_ms)
    assert_true(backoff_delay_ms(p, 20) >= p.max_delay_ms // 2)
    # A one-millisecond window degenerates instead of jittering to zero.
    var tiny = RetryPolicy()
    tiny.base_delay_ms = 1
    assert_equal(backoff_delay_ms(tiny, 1), 1)
    assert_true(backoff_delay_ms(RetryPolicy.none(), 1) <= 100)


def test_retry_transient_failures() raises:
    """Two 503s then a 200, and the same for a 429."""
    var base = _http_base()
    if base == "":
        print("SKIP test_retry_transient_failures: no server")
        return
    var c = HttpClient()
    c.retry = _fast_retries(3)

    var r = c.get(base + "/flaky/503/2?key=t503")
    assert_equal(r.status, 200)
    assert_true(r.text().find("attempts=3") >= 0)
    assert_equal(_attempts(base, String("t503")), 3)

    var r429 = c.get(base + "/flaky/429/1?key=t429")
    assert_equal(r429.status, 200)
    assert_equal(_attempts(base, String("t429")), 2)

    # 501 is permanent: one attempt, and the caller sees the real status.
    var r501 = c.get(base + "/flaky/501/5?key=t501")
    assert_equal(r501.status, 501)
    assert_equal(_attempts(base, String("t501")), 1)


def test_retry_gives_up() raises:
    """A server that never recovers: the caller gets the server's own answer."""
    var base = _http_base()
    if base == "":
        print("SKIP test_retry_gives_up: no server")
        return
    var c = HttpClient()
    c.retry = _fast_retries(2)
    var r = c.get(base + "/flaky/503/-1?key=always")
    assert_equal(r.status, 503)
    # One try plus two retries — not an invented transport error.
    assert_equal(_attempts(base, String("always")), 3)

    var off = HttpClient()
    off.retry = RetryPolicy.none()
    assert_equal(off.get(base + "/flaky/503/-1?key=off").status, 503)
    assert_equal(_attempts(base, String("off")), 1)

    # A transport failure still raises once the retries are spent.
    var dead = HttpClient()
    dead.retry = _fast_retries(2)
    dead.timeout_ms = 400
    with assert_raises():
        _ = dead.get(String("http://127.0.0.1:9/never-listening"))


def test_retry_only_when_repeatable() raises:
    """A bare POST is never repeated; one with an `Idempotency-Key` is."""
    var base = _http_base()
    if base == "":
        print("SKIP test_retry_only_when_repeatable: no server")
        return
    var c = HttpClient()
    c.retry = _fast_retries(3)
    var body = _bytes(String("commit"))

    var bare = c.post(base + "/flaky/503/2?key=post-bare", Span(body))
    assert_equal(bare.status, 503)
    assert_equal(_attempts(base, String("post-bare")), 1)

    # This is exactly what iceberg.mojo's REST commit sends.
    var hs = List[Header]()
    hs.append(Header("Idempotency-Key", "commit-42"))
    var keyed = c.post(base + "/flaky/503/2?key=post-key", Span(body), hs)
    assert_equal(keyed.status, 200)
    assert_true(keyed.text().find("idem=commit-42") >= 0)
    assert_equal(_attempts(base, String("post-key")), 3)

    # PUT is idempotent by definition, so it needs no header.
    var put = c.put(base + "/flaky/503/2?key=put", Span(body))
    assert_equal(put.status, 200)
    assert_equal(_attempts(base, String("put")), 3)


def test_retry_s3_error_codes() raises:
    """`SlowDown` and `RequestTimeout` arrive as a 400 and are still transient.
    """
    var base = _http_base()
    if base == "":
        print("SKIP test_retry_s3_error_codes: no server")
        return
    var c = HttpClient()
    c.retry = _fast_retries(3)

    var slow = c.get(base + "/flaky/400/2?key=slow&payload=s3slowdown")
    assert_equal(slow.status, 200)
    assert_equal(_attempts(base, String("slow")), 3)

    var to = c.get(base + "/flaky/400/1?key=reqto&payload=s3timeout")
    assert_equal(to.status, 200)
    assert_equal(_attempts(base, String("reqto")), 2)

    # A plain 400 is the caller's fault and is not repeated.
    var bad = c.get(base + "/flaky/400/5?key=plain400")
    assert_equal(bad.status, 400)
    assert_equal(_attempts(base, String("plain400")), 1)


# ---------------------------------------------------------------------------
# SigV4
# ---------------------------------------------------------------------------


def test_sigv4_test_suite() raises:
    """Every usable case of the published `aws-sig-v4-test-suite`."""
    var cases = sigv4_cases()
    assert_true(len(cases) >= 30)
    for i in range(len(cases)):
        ref c = cases[i]
        var when = AmzTime.from_amz_date(c.amz_date)
        var got = sign_request(
            c.method,
            c.path,
            c.params,
            c.headers,
            c.payload_hash,
            c.access_key,
            c.secret_key,
            c.region,
            c.service,
            when,
            c.normalize,
        )
        assert_equal(got.canonical_request, c.canonical)
        assert_equal(got.string_to_sign, c.sts)
        assert_equal(got.signature, c.signature)


def test_sigv4_canonical_pieces() raises:
    # S3 does not normalize: `..` is a legal key segment.
    assert_equal(canonical_path(String("/a/../b"), False), "/a/../b")
    assert_equal(canonical_path(String("/a/../b"), True), "/b")
    assert_equal(canonical_path(String(""), False), "/")
    assert_equal(canonical_path(String("/a b"), False), "/a%20b")

    var params = List[QueryParam]()
    params.append(QueryParam("b", "2"))
    params.append(QueryParam("a", "1"))
    params.append(QueryParam("a", "0"))
    assert_equal(canonical_query(params), "a=0&a=1&b=2")


def test_amz_time_from_epoch() raises:
    # 2015-08-30T12:36:00Z, the test suite's timestamp.
    var t = AmzTime.from_epoch(1440938160)
    assert_equal(t.amz_date, "20150830T123600Z")
    assert_equal(t.date_stamp, "20150830")
    # A leap day, and the epoch itself.
    assert_equal(AmzTime.from_epoch(1709208000).date_stamp, "20240229")
    assert_equal(AmzTime.from_epoch(0).amz_date, "19700101T000000Z")
    assert_equal(AmzTime.now().amz_date.byte_length(), 16)


# ---------------------------------------------------------------------------
# S3 — unit
# ---------------------------------------------------------------------------


def test_s3_addressing() raises:
    var creds = S3Credentials("AK", "SK", "")
    var virt = S3Client(S3Config("", "eu-west-1", False, creds.copy()))
    var a = virt.url_for(String("my-bucket"), String("a/b c.parquet"))
    assert_equal(
        a[0], "https://my-bucket.s3.eu-west-1.amazonaws.com/a/b%20c.parquet"
    )
    assert_equal(a[1], "my-bucket.s3.eu-west-1.amazonaws.com")
    assert_equal(a[2], "/a/b c.parquet")

    var pathy = S3Client(
        S3Config("http://minio.local:9000", "us-east-1", True, creds.copy())
    )
    var b = pathy.url_for(String("my-bucket"), String("k"))
    assert_equal(b[0], "http://minio.local:9000/my-bucket/k")
    assert_equal(b[1], "minio.local:9000")
    assert_equal(b[2], "/my-bucket/k")

    # A default port must be absent from the signed Host, because that is what
    # curl sends; signing it would produce SignatureDoesNotMatch.
    var defport = S3Client(
        S3Config("https://s3.example:443", "us-east-1", True, creds.copy())
    )
    assert_equal(defport.url_for(String("b"), String("k"))[1], "s3.example")


def test_split_s3_uri() raises:
    var p = split_s3_uri(String("s3://bucket/a/b/c"))
    assert_equal(p[0], "bucket")
    assert_equal(p[1], "a/b/c")
    # The Hadoop schemes address the same objects.
    assert_equal(split_s3_uri(String("s3a://bucket/k"))[0], "bucket")
    assert_equal(split_s3_uri(String("s3n://bucket/k"))[1], "k")
    with assert_raises():
        _ = split_s3_uri(String("gs://bucket/k"))


def test_s3_config_from_properties() raises:
    var props = Dict[String, String]()
    props["s3.endpoint"] = "http://minio:9000"
    props["s3.access-key-id"] = "AK"
    props["s3.secret-access-key"] = "SK"
    props["s3.session-token"] = "TOKEN"
    props["client.region"] = "ap-south-1"
    var c = S3Config.from_properties(props)
    assert_equal(c.endpoint, "http://minio:9000")
    assert_equal(c.credentials.access_key_id, "AK")
    assert_equal(c.credentials.session_token, "TOKEN")
    assert_equal(c.region, "ap-south-1")
    # A custom endpoint implies path style unless told otherwise.
    assert_true(c.path_style)
    assert_true(not c.anonymous)

    props["s3.region"] = "us-west-2"
    props["s3.path-style-access"] = "false"
    var c2 = S3Config.from_properties(props)
    assert_equal(c2.region, "us-west-2")
    assert_true(not c2.path_style)
    # Payload signing is on unless asked otherwise.
    assert_true(c2.sign_payload)

    props["s3.multipart.part-size-bytes"] = "16777216"
    props["s3.unsigned-payload"] = "true"
    var c3 = S3Config.from_properties(props)
    assert_equal(c3.multipart_part_size, 16777216)
    assert_equal(c3.multipart_threshold, 16777216)
    assert_true(not c3.sign_payload)


def test_s3_xml_parsing() raises:
    var body = String(
        '<?xml version="1.0" encoding="UTF-8"?>'
        "<ListBucketResult><Name>b</Name><IsTruncated>true</IsTruncated>"
        "<NextContinuationToken>tok/1+2</NextContinuationToken>"
        "<Contents><Key>a/b&amp;c.parquet</Key><Size>1234</Size>"
        "<LastModified>2026-08-29T00:00:00.000Z</LastModified>"
        "<ETag>&quot;abc&quot;</ETag></Contents>"
        "<Contents><Key>a/d.parquet</Key><Size>0</Size></Contents>"
        "<CommonPrefixes><Prefix>a/sub/</Prefix></CommonPrefixes>"
        "</ListBucketResult>"
    )
    var r = parse_list_objects(body)
    assert_equal(len(r.objects), 2)
    assert_equal(r.objects[0].key, "a/b&c.parquet")
    assert_equal(r.objects[0].size, 1234)
    assert_equal(r.objects[0].etag, '"abc"')
    assert_equal(r.objects[1].size, 0)
    assert_equal(len(r.common_prefixes), 1)
    assert_equal(r.common_prefixes[0], "a/sub/")
    assert_true(r.is_truncated)
    assert_equal(r.next_continuation_token, "tok/1+2")

    assert_equal(xml_unescape(String("&lt;a&gt;&amp;&apos;&quot;")), "<a>&'\"")
    assert_equal(
        xml_text(
            String("<Error><Code>NoSuchKey</Code></Error>"), String("Code")
        ),
        "NoSuchKey",
    )


# ---------------------------------------------------------------------------
# FileIOResolver
# ---------------------------------------------------------------------------


def test_resolver_scheme_dispatch() raises:
    var io = FileIOResolver()
    assert_equal(io.backend_for(String("file:///a/b")), BACKEND_LOCAL)
    assert_equal(io.backend_for(String("/a/b")), BACKEND_LOCAL)
    assert_equal(io.backend_for(String("s3://b/k")), BACKEND_S3)
    assert_equal(io.backend_for(String("s3a://b/k")), BACKEND_S3)
    assert_equal(io.backend_for(String("https://h/k")), BACKEND_HTTP)
    assert_equal(io.backend_for(String("gs://b/k")), BACKEND_GCS)
    assert_equal(io.backend_for(String("gcs://b/k")), BACKEND_GCS)
    assert_equal(
        io.backend_for(String("abfss://c@a.dfs.core.windows.net/k")),
        BACKEND_AZURE,
    )
    assert_equal(
        io.backend_for(String("wasbs://c@a.blob.core.windows.net/k")),
        BACKEND_AZURE,
    )
    with assert_raises():
        _ = io.backend_for(String("hdfs://nn/k"))
    with assert_raises():
        _ = io.backend_for(String("ftp://h/k"))


def test_resolver_rebase() raises:
    var io = FileIOResolver()
    io.rebase(String("s3://prod/warehouse"), String("file:///tmp/copy"))
    assert_equal(
        io.resolve(String("s3://prod/warehouse/db/t/m.json")),
        "file:///tmp/copy/db/t/m.json",
    )
    assert_equal(io.resolve(String("s3://other/k")), "s3://other/k")
    assert_equal(
        io.backend_for(String("s3://prod/warehouse/db/t/m.json")),
        BACKEND_LOCAL,
    )


def test_resolver_storage_credentials_longest_prefix() raises:
    var io = FileIOResolver()
    io.set(String("s3.region"), String("us-east-1"))
    io.set(String("s3.access-key-id"), String("TABLE-KEY"))
    io.set(String("s3.secret-access-key"), String("TABLE-SECRET"))

    var broad = Dict[String, String]()
    broad["s3.access-key-id"] = "BROAD"
    broad["s3.secret-access-key"] = "BROAD-SECRET"
    broad["s3.session-token"] = "BROAD-TOKEN"
    io.add_storage_credential(String("s3://bucket/warehouse/"), broad^)

    var narrow = Dict[String, String]()
    narrow["s3.access-key-id"] = "NARROW"
    narrow["s3.secret-access-key"] = "NARROW-SECRET"
    narrow["s3.session-token"] = "NARROW-TOKEN"
    io.add_storage_credential(
        String("s3://bucket/warehouse/db/table/"), narrow^
    )

    # Longest prefix wins, whichever order the entries arrived in.
    var deep = io.s3_config_for(
        String("s3://bucket/warehouse/db/table/data/f.parquet")
    )
    assert_equal(deep.credentials.access_key_id, "NARROW")
    assert_equal(deep.credentials.session_token, "NARROW-TOKEN")

    var shallow = io.s3_config_for(
        String("s3://bucket/warehouse/other/f.parquet")
    )
    assert_equal(shallow.credentials.access_key_id, "BROAD")

    # No matching prefix: the resolver's own properties stand.
    var none = io.s3_config_for(String("s3://elsewhere/f.parquet"))
    assert_equal(none.credentials.access_key_id, "TABLE-KEY")
    assert_equal(none.region, "us-east-1")


def test_resolver_local_io() raises:
    var io = FileIOResolver()
    var loc = String("file://") + _scratch() + "/resolver.bin"
    var data = _bytes(String("resolver round trip"))
    io.write(loc, Span(data))
    assert_true(io.exists(loc))
    assert_equal(io.read_text(loc), "resolver round trip")
    assert_equal(io.new_input(loc).length(), 19)
    var mid = io.read_range(loc, 9, 5)
    assert_equal(String(StringSlice(unsafe_from_utf8=Span(mid))), "round")
    io.delete(loc)
    assert_true(not io.exists(loc))


def test_resolver_http_input() raises:
    var base = _http_base()
    if base == "":
        print("SKIP test_resolver_http_input: no server")
        return
    var io = FileIOResolver()
    var f = io.new_input(base + "/files/hello.txt")
    assert_equal(f.length(), 18)
    assert_equal(len(f.read_range(0, 5)), 5)
    with assert_raises():
        io.delete(base + "/files/hello.txt")


# ---------------------------------------------------------------------------
# GCS and Azure
#
# No live gate exists for either: there is no local emulator in the toolchain
# and neither takes credentials this repo could hold. What is tested is
# everything that is not the network — URL construction, the auth headers, the
# property names a REST catalog vends, and the listing documents — since that
# is where these backends can actually be wrong.
# ---------------------------------------------------------------------------


def test_gcs_urls_and_auth() raises:
    var props = Dict[String, String]()
    props["gcs.oauth2.token"] = "ya29.TOKEN"
    var c = GcsConfig.from_properties(props)
    assert_equal(c.endpoint, "https://storage.googleapis.com")
    assert_equal(
        c.url_for(String("bkt"), String("a/b c.parquet")),
        "https://storage.googleapis.com/bkt/a/b%20c.parquet",
    )
    var h = c.headers()
    assert_equal(len(h), 1)
    assert_equal(h[0].name, "Authorization")
    assert_equal(h[0].value, "Bearer ya29.TOKEN")

    # Iceberg calls the endpoint override `gcs.service.host`.
    props["gcs.service.host"] = "https://gcs.test:8443"
    assert_equal(
        GcsConfig.from_properties(props).url_for(String("b"), String("k")),
        "https://gcs.test:8443/b/k",
    )

    # With no token the requests go out anonymous rather than malformed.
    assert_equal(len(GcsConfig().headers()), 0)

    var parts = split_gcs_uri(String("gs://bucket/a/b"))
    assert_equal(parts[0], "bucket")
    assert_equal(parts[1], "a/b")
    assert_equal(split_gcs_uri(String("gcs://bucket/k"))[0], "bucket")
    with assert_raises():
        _ = split_gcs_uri(String("s3://bucket/k"))


def test_gcs_listing_is_s3_shaped() raises:
    """GCS's XML API answers with S3's `ListBucketResult`, which is the whole
    reason this backend needs no JSON parser."""
    var body = String(
        "<ListBucketResult><Name>b</Name><IsTruncated>false</IsTruncated>"
        "<Contents><Key>db/t/data/f.parquet</Key><Size>4096</Size></Contents>"
        "</ListBucketResult>"
    )
    var r = parse_list_objects(body)
    assert_equal(len(r.objects), 1)
    assert_equal(r.objects[0].key, "db/t/data/f.parquet")
    assert_equal(r.objects[0].size, 4096)
    assert_true(not r.is_truncated)


def test_azure_uri_parsing() raises:
    var a = parse_azure_uri(
        String("abfss://warehouse@acct.dfs.core.windows.net/db/t/m.json")
    )
    assert_equal(a.account, "acct")
    assert_equal(a.container, "warehouse")
    assert_equal(a.path, "db/t/m.json")

    var w = parse_azure_uri(String("wasbs://c@acct.blob.core.windows.net/x/y"))
    assert_equal(w.account, "acct")
    assert_equal(w.container, "c")
    assert_equal(w.path, "x/y")

    # `az://container/path` leaves the account to the configuration.
    var bare = parse_azure_uri(String("az://cont/p/q"))
    assert_equal(bare.account, "")
    assert_equal(bare.container, "cont")
    with assert_raises():
        _ = parse_azure_uri(String("s3://b/k"))


def test_azure_sas_urls_and_headers() raises:
    var props = Dict[String, String]()
    props["adls.sas-token.acct"] = "sv=2021-12-02&sig=SIGNATURE"
    var c = AzureConfig.from_properties(props, String("acct"))
    assert_equal(
        c.url_for(String("cont"), String("a/b c.parquet")),
        (
            "https://acct.blob.core.windows.net/cont/a/b%20c.parquet"
            "?sv=2021-12-02&sig=SIGNATURE"
        ),
    )
    # The SAS query already begins the query string, so a list request has to
    # append with `&`, not `?`.
    assert_true(
        c.list_url(String("cont"), String("db/"), String("")).find(
            "?sv=2021-12-02&sig=SIGNATURE&restype=container&comp=list"
        )
        > 0
    )
    var h = c.headers()
    assert_equal(len(h), 1)
    assert_equal(h[0].name, "x-ms-version")
    assert_equal(h[0].value, BLOB_API_VERSION)
    # Every Azure PUT must declare the blob type.
    var wh = c.write_headers()
    assert_equal(len(wh), 2)
    assert_equal(wh[1].name, "x-ms-blob-type")
    assert_equal(wh[1].value, "BlockBlob")

    # An account-specific token beats the generic one.
    props["adls.sas-token"] = "sig=GENERIC"
    assert_true(
        AzureConfig.from_properties(props, String("acct"))
        .url_for(String("c"), String("k"))
        .find("SIGNATURE")
        > 0
    )
    assert_true(
        AzureConfig.from_properties(props, String("other"))
        .url_for(String("c"), String("k"))
        .find("GENERIC")
        > 0
    )

    var no_account = AzureConfig()
    with assert_raises():
        _ = no_account.base_url()


def test_azure_listing_xml() raises:
    var body = String(
        "<EnumerationResults><Blobs>"
        "<Blob><Name>db/t/a.parquet</Name>"
        "<Properties><Content-Length>128</Content-Length></Properties></Blob>"
        "<Blob><Name>db/t/b.parquet</Name>"
        "<Properties><Content-Length>0</Content-Length></Properties></Blob>"
        "</Blobs><NextMarker /></EnumerationResults>"
    )
    var blobs = xml_blocks(body, String("Blob"))
    assert_equal(len(blobs), 2)
    assert_equal(xml_text(blobs[0], String("Name")), "db/t/a.parquet")
    assert_equal(xml_text(blobs[0], String("Content-Length")), "128")
    # A self-closing `<NextMarker />` must not read as a marker value.
    assert_equal(xml_text(body, String("NextMarker")), "")


# ---------------------------------------------------------------------------
# S3 — end to end
# ---------------------------------------------------------------------------


def _s3_endpoint() -> String:
    return getenv("OBJECTSTORE_TEST_S3", "")


def _s3_bucket() -> String:
    return getenv("OBJECTSTORE_TEST_S3_BUCKET", "objectstore-test")


def _s3_client() raises -> S3Client:
    return S3Client(S3Config.from_env())


def test_s3_unsigned_payload() raises:
    """`s3.unsigned-payload=true` signs `UNSIGNED-PAYLOAD` in place of the
    body hash. MinIO verifies signatures, so a successful round trip is proof
    the canonical request is right — and a multipart body exercises the same
    path per part."""
    if _s3_endpoint() == "":
        print("SKIP test_s3_unsigned_payload: no S3 server")
        return
    var props = Dict[String, String]()
    props["s3.unsigned-payload"] = "true"
    var config = S3Config.from_properties(props)
    assert_true(not config.sign_payload)
    var c = S3Client(config^)
    var bucket = _s3_bucket()
    var key = String("unsigned/payload.bin")

    var data = List[UInt8]()
    for i in range(4096):
        data.append(UInt8((i * 7) % 256))
    c.put_object(bucket, key, Span(data), String("application/octet-stream"))
    assert_equal(
        sha256_hex(Span(c.get_object(bucket, key))), sha256_hex(Span(data))
    )
    c.delete_object(bucket, key)
    assert_true(not c.object_exists(bucket, key))


def test_s3_roundtrip() raises:
    if _s3_endpoint() == "":
        print(
            "SKIP test_s3_roundtrip: no S3 server (OBJECTSTORE_TEST_S3 unset;"
            " set MINIO_BINARY or install moto)"
        )
        return
    var c = _s3_client()
    var bucket = _s3_bucket()
    var key = String("round/trip.bin")

    var data = List[UInt8]()
    for i in range(4096):
        data.append(UInt8(i % 256))
    c.put_object(bucket, key, Span(data), String("application/octet-stream"))

    assert_true(c.object_exists(bucket, key))
    assert_equal(c.object_length(bucket, key), 4096)

    var got = c.get_object(bucket, key)
    assert_equal(len(got), 4096)
    for i in range(0, 4096, 97):
        assert_equal(got[i], data[i])

    var ranged = c.get_object(bucket, key, 100, 149)
    assert_equal(len(ranged), 50)
    assert_equal(ranged[0], data[100])
    assert_equal(ranged[49], data[149])

    c.delete_object(bucket, key)
    assert_true(not c.object_exists(bucket, key))
    # Deleting a missing key is not an error.
    c.delete_object(bucket, key)
    with assert_raises():
        _ = c.get_object(bucket, key)


def test_s3_keys_needing_encoding() raises:
    if _s3_endpoint() == "":
        print("SKIP test_s3_keys_needing_encoding: no S3 server")
        return
    var c = _s3_client()
    var bucket = _s3_bucket()
    # Iceberg partition paths look exactly like this.
    var key = String("db/table/data/region=eu west/00000-1-a b.parquet")
    var body = _bytes(String("encoded-key"))
    c.put_object(bucket, key, Span(body))
    assert_equal(
        String(StringSlice(unsafe_from_utf8=Span(c.get_object(bucket, key)))),
        "encoded-key",
    )
    c.delete_object(bucket, key)


def test_s3_listing() raises:
    if _s3_endpoint() == "":
        print("SKIP test_s3_listing: no S3 server")
        return
    var c = _s3_client()
    var bucket = _s3_bucket()
    var body = _bytes(String("x"))
    for i in range(7):
        c.put_object(
            bucket, String("listing/part-") + String(i) + ".txt", Span(body)
        )
    c.put_object(bucket, String("listing/sub/deep.txt"), Span(body))

    var flat = c.list_all(bucket, String("listing/"))
    assert_equal(len(flat.objects), 8)

    # A delimiter turns the flat key space into one level of "directories".
    var grouped = c.list_objects_v2(bucket, String("listing/"), String("/"))
    assert_equal(len(grouped.objects), 7)
    assert_equal(len(grouped.common_prefixes), 1)
    assert_equal(grouped.common_prefixes[0], "listing/sub/")

    # Pagination: max-keys forces more than one page.
    var page = c.list_objects_v2(bucket, String("listing/"), String(""), 3)
    assert_equal(len(page.objects), 3)
    assert_true(page.is_truncated)
    assert_true(page.next_continuation_token != "")
    var page2 = c.list_objects_v2(
        bucket, String("listing/"), String(""), 3, page.next_continuation_token
    )
    assert_equal(len(page2.objects), 3)
    assert_true(page2.objects[0].key != page.objects[0].key)

    for i in range(len(flat.objects)):
        c.delete_object(bucket, flat.objects[i].key)


def test_s3_large_object() raises:
    if _s3_endpoint() == "":
        print("SKIP test_s3_large_object: no S3 server")
        return
    var config = S3Config.from_env()
    # Force the single-`PUT` path: 20 MB is over the multipart threshold now,
    # and S3 takes a single PUT up to 5 GB, so this half still has to work.
    config.multipart_threshold = 0
    var c = S3Client(config^)
    var bucket = _s3_bucket()
    var key = String("large/20mb.bin")
    var n = 20 * 1024 * 1024
    var data = List[UInt8](capacity=n)
    for i in range(n):
        data.append(UInt8(i % 251))

    c.put_object(bucket, key, Span(data))
    assert_equal(c.object_length(bucket, key), n)
    var tail = c.get_object(bucket, key, n - 16, n - 1)
    assert_equal(len(tail), 16)
    assert_equal(tail[15], data[n - 1])
    var whole = c.get_object(bucket, key)
    assert_equal(len(whole), n)
    assert_equal(whole[n - 1], data[n - 1])
    c.delete_object(bucket, key)


def test_s3_multipart_upload() raises:
    """20 MB and 40 MB through `CreateMultipartUpload`/`UploadPart`/`Complete`.

    Verified by hash rather than by length: a part uploaded out of order, or a
    part list assembled wrong, produces an object of exactly the right size and
    entirely the wrong contents.
    """
    if _s3_endpoint() == "":
        print("SKIP test_s3_multipart_upload: no S3 server")
        return
    var c = _s3_client()
    var bucket = _s3_bucket()

    # ── 20 MB with the default 8 MiB parts: three parts, the last short ────
    var n = 20 * 1024 * 1024
    var data = List[UInt8](capacity=n)
    for i in range(n):
        data.append(UInt8((i * 7 + 3) % 251))
    var key = String("multipart/20mb.bin")
    c.put_object(bucket, key, Span(data), String("application/octet-stream"))

    assert_equal(c.object_length(bucket, key), n)
    var digest = sha256_hex(Span(data))
    assert_equal(sha256_hex(Span(c.get_object(bucket, key))), digest)
    # A multipart object's ETag is a digest of the part digests plus `-<parts>`,
    # which is how the server itself says the upload really was multipart.
    var etag = c.head_object(bucket, key).header("ETag")
    assert_true(etag.find("-3") > 0)
    # Ranges still address the assembled object, not a part.
    var mid = c.get_object(bucket, key, 9 * 1024 * 1024, 9 * 1024 * 1024 + 15)
    assert_equal(len(mid), 16)
    assert_equal(mid[0], data[9 * 1024 * 1024])
    c.delete_object(bucket, key)

    # ── 40 MB in 5 MiB parts: eight of them, the minimum S3 allows ─────────
    var big_n = 40 * 1024 * 1024
    var big = List[UInt8](capacity=big_n)
    for i in range(big_n):
        big.append(UInt8((i * 13 + 101) % 251))
    var big_config = S3Config.from_env()
    big_config.multipart_part_size = 5 * 1024 * 1024
    big_config.multipart_threshold = 5 * 1024 * 1024
    var big_client = S3Client(big_config^)
    var big_key = String("multipart/40mb.bin")
    big_client.put_object(bucket, big_key, Span(big))

    assert_equal(big_client.object_length(bucket, big_key), big_n)
    assert_equal(
        sha256_hex(Span(big_client.get_object(bucket, big_key))),
        sha256_hex(Span(big)),
    )
    assert_true(
        big_client.head_object(bucket, big_key).header("ETag").find("-8") > 0
    )
    big_client.delete_object(bucket, big_key)


def test_s3_multipart_abort() raises:
    """An abandoned upload can be aborted, and is gone once it has been."""
    if _s3_endpoint() == "":
        print("SKIP test_s3_multipart_abort: no S3 server")
        return
    var c = _s3_client()
    var bucket = _s3_bucket()
    var key = String("multipart/aborted.bin")
    var upload_id = c.create_multipart_upload(bucket, key)
    assert_true(upload_id != "")

    var part = List[UInt8](capacity=MIN_PART_SIZE)
    for i in range(MIN_PART_SIZE):
        part.append(UInt8(i % 251))
    var etag = c.upload_part(bucket, key, upload_id, 1, Span(part))
    assert_true(etag != "")

    c.abort_multipart_upload(bucket, key, upload_id)
    # Nothing was ever committed, and the id no longer exists.
    assert_true(not c.object_exists(bucket, key))
    var etags = List[String]()
    etags.append(etag)
    with assert_raises():
        c.complete_multipart_upload(bucket, key, upload_id, etags)


def test_s3_multipart_via_resolver() raises:
    """`FileIOResolver.write` picks up multipart without being told."""
    if _s3_endpoint() == "":
        print("SKIP test_s3_multipart_via_resolver: no S3 server")
        return
    var io = FileIOResolver()
    io.set(String("s3.endpoint"), _s3_endpoint())
    io.set(String("s3.access-key-id"), getenv("AWS_ACCESS_KEY_ID", ""))
    io.set(String("s3.secret-access-key"), getenv("AWS_SECRET_ACCESS_KEY", ""))
    io.set(String("s3.region"), String("us-east-1"))
    # Iceberg's own property name, in Iceberg's own units.
    io.set(String("s3.multipart.part-size-bytes"), String(MIN_PART_SIZE))

    var n = 12 * 1024 * 1024
    var data = List[UInt8](capacity=n)
    for i in range(n):
        data.append(UInt8((i * 31 + 5) % 251))
    var loc = String("s3://") + _s3_bucket() + "/multipart/resolver.bin"
    io.write(loc, Span(data))
    assert_equal(sha256_hex(Span(io.read_all(loc))), sha256_hex(Span(data)))
    io.delete(loc)


def test_s3_read_ranges_coalesce() raises:
    """A Parquet-shaped read against MinIO: many chunks, few requests."""
    if _s3_endpoint() == "":
        print("SKIP test_s3_read_ranges_coalesce: no S3 server")
        return
    var io = FileIOResolver()
    io.set(String("s3.endpoint"), _s3_endpoint())
    io.set(String("s3.access-key-id"), getenv("AWS_ACCESS_KEY_ID", ""))
    io.set(String("s3.secret-access-key"), getenv("AWS_SECRET_ACCESS_KEY", ""))
    io.set(String("s3.region"), String("us-east-1"))

    var n = 256 * 1024
    var data = List[UInt8](capacity=n)
    for i in range(n):
        data.append(UInt8((i * 17 + 7) % 251))
    var loc = String("s3://") + _s3_bucket() + "/ranges/chunks.bin"
    io.write(loc, Span(data))

    # Eight "column chunks", consecutive but for the columns skipped between.
    var want = List[ByteRange]()
    for k in range(8):
        want.append(ByteRange(k * 16 * 1024, 4096))
    # …and the footer, asked for last, as a Parquet reader would.
    want.append(ByteRange(n - 1024, 1024))

    var f = io.new_input(loc)
    reset_pool_stats()
    var got = f.read_ranges(want)
    var requests = pool_stats()[0]
    assert_equal(len(got), 9)
    for k in range(len(want)):
        assert_equal(len(got[k]), want[k].length)
        assert_equal(got[k][0], data[want[k].offset])
        assert_equal(
            got[k][want[k].length - 1],
            data[want[k].offset + want[k].length - 1],
        )
    if shim_abi() >= 2:
        # All nine spans fall inside one 256 KiB window, so one GET answers
        # them; nine separate `read_range` calls would be nine.
        assert_equal(requests, 1)
    io.delete(loc)


def test_s3_virtual_host_addressing() raises:
    var vhost = getenv("OBJECTSTORE_TEST_S3_VHOST", "")
    if vhost == "":
        print(
            "SKIP test_s3_virtual_host_addressing: needs MinIO with"
            " MINIO_DOMAIN and *.localhost resolution"
        )
        return
    var config = S3Config.from_env()
    config.endpoint = vhost
    config.path_style = False
    var c = S3Client(config^)
    var bucket = _s3_bucket()
    var key = String("vhost/object.txt")
    var body = _bytes(String("virtual host addressing"))
    c.put_object(bucket, key, Span(body))
    assert_equal(
        String(StringSlice(unsafe_from_utf8=Span(c.get_object(bucket, key)))),
        "virtual host addressing",
    )
    c.delete_object(bucket, key)


def test_s3_presigned_url() raises:
    if _s3_endpoint() == "":
        print("SKIP test_s3_presigned_url: no S3 server")
        return
    var c = _s3_client()
    var bucket = _s3_bucket()
    var key = String("presigned/data.txt")
    var body = _bytes(String("presigned payload"))
    c.put_object(bucket, key, Span(body))

    var url = c.presign_get(bucket, key, 900)
    assert_true(url.find("X-Amz-Signature=") > 0)
    assert_true(url.find("X-Amz-Credential=") > 0)

    # The whole point: a client with no credentials at all can read it.
    var anon = HttpInputFile(url)
    assert_equal(
        String(StringSlice(unsafe_from_utf8=Span(anon.read_all()))),
        "presigned payload",
    )
    var ranged = anon.read_range(0, 9)
    assert_equal(
        String(StringSlice(unsafe_from_utf8=Span(ranged))), "presigned"
    )
    c.delete_object(bucket, key)


def test_s3_via_resolver() raises:
    if _s3_endpoint() == "":
        print("SKIP test_s3_via_resolver: no S3 server")
        return
    var io = FileIOResolver()
    io.set(String("s3.endpoint"), _s3_endpoint())
    io.set(String("s3.access-key-id"), getenv("AWS_ACCESS_KEY_ID", ""))
    io.set(String("s3.secret-access-key"), getenv("AWS_SECRET_ACCESS_KEY", ""))
    io.set(String("s3.region"), String("us-east-1"))

    var loc = String("s3://") + _s3_bucket() + "/resolver/via.txt"
    var data = _bytes(String("resolver over s3"))
    io.write(loc, Span(data))
    assert_true(io.exists(loc))
    assert_equal(io.read_text(loc), "resolver over s3")
    assert_equal(
        String(StringSlice(unsafe_from_utf8=Span(io.read_range(loc, 9, 4)))),
        "over",
    )
    var listed = io.list(String("s3://") + _s3_bucket() + "/resolver/")
    assert_equal(len(listed), 1)
    assert_equal(listed[0], loc)
    io.delete(loc)
    assert_true(not io.exists(loc))


def test_s3_bad_credentials() raises:
    if _s3_endpoint() == "":
        print("SKIP test_s3_bad_credentials: no S3 server")
        return
    if getenv("OBJECTSTORE_TEST_S3_KIND", "") != "minio":
        print("SKIP test_s3_bad_credentials: only MinIO verifies signatures")
        return
    var config = S3Config.from_env()
    config.credentials = S3Credentials("wrong", "alsowrong", "")
    config.anonymous = False
    var c = S3Client(config^)
    with assert_raises():
        _ = c.get_object(_s3_bucket(), String("anything"))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
