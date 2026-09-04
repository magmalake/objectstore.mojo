"""`objectstore.http` — an HTTP/HTTPS client over libcurl.

**Why libcurl.** Nothing in the Mojo package ecosystem gives this repo a TLS
capable HTTP client: `floki`, `flare`, `lightbug-http` and `fire-http` all fail
to resolve from conda ("No candidates were found") on both the stable and the
nightly toolchain, and an object store without HTTPS is not an object store.
conda-forge's `libcurl` ships TLS and a CA bundle for every platform we target,
so this tin follows the magmalake FFI recipe (zstd.mojo, lz4.mojo): a tiny C
shim built as a `pixi-build-cmake` package into `$CONDA_PREFIX/lib`, dlopened
through an `OwnedDLHandle`.

The shim exists because `curl_easy_setopt` is a C variadic, which a dlopened
symbol cannot express; `shim/curl_wrapper.c` collapses a whole request into one
fixed-arity call and hands back an opaque result object read through accessors.

Every FFI-calling worker takes the handle as a borrowed `imm` parameter: Mojo
destroys a value at its last syntactic use, so a function that both owned the
handle and called `get_function` on it would `dlclose` the library before the
returned function pointer is invoked.

**Connection reuse.** The curl easy handle lives in the shim and persists
across requests, so a second request to the same host reuses its TCP and TLS
session instead of shaking hands again — the difference between ~2.9 ms and
~0.2 ms per range read on loopback. Requests go to a process-wide pool by
default; `new_connection_pool` hands out a private one for a caller that wants
its connections kept apart.

**Threads.** An `HttpClient` — and the pool behind it — is single-threaded.
Mojo has no threads today, so this costs nothing and is why the shim's share
handle installs no locking callbacks; if that changes, each thread needs its
own pool.

**Retries.** Transport failures, 429 and most 5xx are retried with exponential
backoff and jitter, but only for requests that can safely be repeated — see
`RetryPolicy`. A response that is *returned* is never retried behind the
caller's back on a method the server might have already acted on.
"""

from std.ffi import OwnedDLHandle, c_int, c_long, c_long_long, c_size_t
from std.os import getenv
from std.time import monotonic, sleep


comptime DEFAULT_TIMEOUT_MS = 30000
"""Total request deadline. Range reads of a Parquet footer are small; a 20 MB
object over a slow link is not, so this is generous rather than tight."""


def _find_lib() -> String:
    """Path to libobjectstoremojo.so: `$CONDA_PREFIX/lib` (installed by the
    objectstore-shim pixi package), else `build/` for a bare checkout."""
    var prefix = getenv("CONDA_PREFIX", "")
    if prefix == "":
        return String("build/libobjectstoremojo.so")
    var out = String("")
    out += prefix
    out += "/lib/libobjectstoremojo.so"
    return out^


def _cstr(s: String) -> List[UInt8]:
    """A NUL-terminated copy of `s`, owned by the caller.

    Kept as an explicit buffer rather than reaching for `String`'s internal
    pointer so the lifetime is visible: the caller holds it across the FFI
    call.
    """
    var out = List[UInt8]()
    var b = s.as_bytes()
    for k in range(len(b)):
        out.append(b[k])
    out.append(0)
    return out^


def _read_cstring(addr: Int) -> String:
    if addr == 0:
        return String("")
    var p = Pointer[UInt8, ImmUntrackedOrigin](unsafe_from_address=addr)
    return String(unsafe_from_utf8_ptr=p)


comptime SHARED_POOL = 0
"""The process-wide connection pool, which is what every `HttpClient` uses
unless it is given one of its own."""


# ---------------------------------------------------------------------------
# Connection pools
# ---------------------------------------------------------------------------


def new_connection_pool() raises -> Int:
    """A private pool: one persistent curl handle, its own connections.

    Returns an opaque handle to pass as `HttpClient.pool`. **The caller owns
    it** and must call `free_connection_pool`; there is no destructor here
    because `HttpClient` is `Copyable`, and a copyable owner of a C resource
    is a double free waiting to happen. Most callers want `SHARED_POOL`.
    """
    var lib = OwnedDLHandle(_find_lib())
    return _pool_new(lib)


def _pool_new(imm lib: OwnedDLHandle) raises -> Int:
    var new_fn = lib.get_function[Int]("os_http_client_new")
    var p = Int(new_fn())
    if p == 0:
        raise Error("objectstore.http: could not create a connection pool")
    return p


def free_connection_pool(pool: Int) raises:
    """Closes a pool from `new_connection_pool` and its live connections."""
    if pool == SHARED_POOL:
        return
    var lib = OwnedDLHandle(_find_lib())
    _pool_free(lib, pool)


def _pool_free(imm lib: OwnedDLHandle, pool: Int) raises:
    var free_fn = lib.get_function[NoneType]("os_http_client_free")
    _ = free_fn(pool)


def pool_stats(pool: Int = SHARED_POOL) raises -> Tuple[Int, Int]:
    """`(requests, connections)` for a pool since the last `reset_pool_stats`.

    `connections` is what curl actually opened, so reuse is the observation
    that it stays at 1 while `requests` climbs — which is how the tests prove
    it rather than inferring it from a stopwatch.
    """
    var lib = OwnedDLHandle(_find_lib())
    return _pool_stats(lib, pool)


def _pool_stats(imm lib: OwnedDLHandle, pool: Int) raises -> Tuple[Int, Int]:
    var req_fn = lib.get_function[c_long]("os_http_client_requests")
    var con_fn = lib.get_function[c_long]("os_http_client_connects")
    return Tuple(Int(req_fn(pool)), Int(con_fn(pool)))


def reset_pool_stats(pool: Int = SHARED_POOL) raises:
    var lib = OwnedDLHandle(_find_lib())
    var reset_fn = lib.get_function[NoneType]("os_http_client_reset_stats")
    _ = reset_fn(pool)


def shim_abi() raises -> Int:
    """1 = a fresh curl handle per request (0.1.x); 2 = pooled connections."""
    var lib = OwnedDLHandle(_find_lib())
    var abi_fn = lib.get_function[c_long]("os_http_shim_abi")
    return Int(abi_fn())


# ---------------------------------------------------------------------------
# Headers
# ---------------------------------------------------------------------------


@fieldwise_init
struct Header(Copyable, Movable, Writable):
    """One `Name: Value` pair. Names are compared case-insensitively."""

    var name: String
    var value: String

    def write_to(self, mut writer: Some[Writer]):
        writer.write(self.name, ": ", self.value)


def _ascii_lower(s: String) -> String:
    var out = List[UInt8]()
    var b = s.as_bytes()
    for k in range(len(b)):
        var c = b[k]
        if c >= 65 and c <= 90:
            c += 32
        out.append(c)
    return String(StringSlice(unsafe_from_utf8=Span(out)))


def _trim(s: String) -> String:
    var b = s.as_bytes()
    var i = 0
    var j = len(b)
    while i < j and (b[i] == 32 or b[i] == 9 or b[i] == 13 or b[i] == 10):
        i += 1
    while j > i and (
        b[j - 1] == 32 or b[j - 1] == 9 or b[j - 1] == 13 or b[j - 1] == 10
    ):
        j -= 1
    if i >= j:
        return String("")
    return String(StringSlice(unsafe_from_utf8=Span(b)[i:j]))


def header_blob(headers: List[Header]) -> String:
    """Headers as the shim wants them: `Name: Value` lines joined by LF.

    An HTTP header value cannot contain a bare LF, so this encoding is
    lossless and spares the FFI boundary a `char*[]`.
    """
    var out = String("")
    for k in range(len(headers)):
        if k > 0:
            out += "\n"
        out += headers[k].name
        out += ": "
        out += headers[k].value
    return out^


# ---------------------------------------------------------------------------
# Retries
# ---------------------------------------------------------------------------


@fieldwise_init
struct RetryPolicy(Copyable, Movable):
    """When to try again, and how long to wait first.

    Defaults: three retries (four attempts), 100 ms doubling to a 20 s ceiling,
    and **idempotent requests only**. `POST` is retried only when the caller
    has said the server can deduplicate it by supplying an `Idempotency-Key`
    header — which is exactly what an Iceberg REST commit does, and why the
    header is the trigger rather than a flag on the client.
    """

    var max_retries: Int
    """Attempts *after* the first. 0 disables retrying entirely."""
    var base_delay_ms: Int
    var max_delay_ms: Int
    var retry_non_idempotent: Bool
    """Escape hatch for a caller that knows its `POST` is safe to repeat and
    cannot add a header. Off, because guessing wrong duplicates a write."""

    def __init__(out self):
        self.max_retries = 3
        self.base_delay_ms = 100
        self.max_delay_ms = 20000
        self.retry_non_idempotent = False

    @staticmethod
    def none() -> Self:
        """One request, one answer — the 0.1.x behaviour."""
        var p = Self()
        p.max_retries = 0
        return p^


def is_idempotent(method: String, headers: List[Header]) -> Bool:
    """RFC 9110 idempotency, plus the `Idempotency-Key` convention.

    `GET`, `HEAD`, `PUT`, `DELETE`, `OPTIONS` and `TRACE` are idempotent by
    definition: repeating one cannot commit a second effect. `POST` and
    `PATCH` are not, so they are only repeatable when the request carries a
    key the server can deduplicate on.
    """
    if method == "POST" or method == "PATCH":
        for k in range(len(headers)):
            if _ascii_lower(headers[k].name) == "idempotency-key":
                return True
        return False
    return True


def retryable_status(status: Int) -> Bool:
    """429 and 5xx, except the two that mean "never, no matter how often".

    501 Not Implemented and 505 HTTP Version Not Supported are permanent facts
    about the server; retrying them is pure latency.
    """
    if status == 429:
        return True
    if status == 501 or status == 505:
        return False
    return status >= 500 and status < 600


comptime S3_RETRYABLE_CODES = 2


def s3_retryable_error(body: Span[UInt8, _]) -> Bool:
    """S3's two "come back later" errors, which arrive with unhelpful statuses.

    `SlowDown` is throttling and `RequestTimeout` means the server gave up
    waiting on the body; AWS returns the latter as a **400**, so status alone
    would call it permanent. Only the first bytes are inspected, and only for
    a response that already failed, so this never touches an object body.
    """
    var n = len(body)
    if n > 1024:
        n = 1024
    var head = String(StringSlice(unsafe_from_utf8=Span(body)[0:n]))
    if head.find("<Code>SlowDown</Code>") >= 0:
        return True
    return head.find("<Code>RequestTimeout</Code>") >= 0


def backoff_delay_ms(policy: RetryPolicy, attempt: Int) -> Int:
    """Exponential backoff with jitter: half the window fixed, half random.

    `attempt` counts from 1. Full jitter would sometimes retry instantly and
    hammer a server that is already asking for room; half is the usual
    compromise. The jitter source is the monotonic clock's low bits — there is
    no RNG in reach here, and a retry schedule does not need a good one.
    """
    var window = policy.base_delay_ms
    for _ in range(attempt - 1):
        if window >= policy.max_delay_ms:
            break
        window *= 2
    if window > policy.max_delay_ms:
        window = policy.max_delay_ms
    if window <= 1:
        return window
    var half = window // 2
    var jitter = Int(monotonic()) % (half + 1)
    if jitter < 0:
        jitter = -jitter
    return half + jitter


# ---------------------------------------------------------------------------
# Response
# ---------------------------------------------------------------------------


struct Response(Copyable, Movable):
    """A completed HTTP response: status line, headers, and the whole body."""

    var status: Int
    var headers: List[Header]
    var body: List[UInt8]

    def __init__(
        out self, status: Int, var headers: List[Header], var body: List[UInt8]
    ):
        self.status = status
        self.headers = headers^
        self.body = body^

    def ok(self) -> Bool:
        return self.status >= 200 and self.status < 300

    def header(self, name: String) -> String:
        """The first value for `name` (case-insensitive), or `""`."""
        var want = _ascii_lower(name)
        for k in range(len(self.headers)):
            if _ascii_lower(self.headers[k].name) == want:
                return self.headers[k].value
        return String("")

    def has_header(self, name: String) -> Bool:
        var want = _ascii_lower(name)
        for k in range(len(self.headers)):
            if _ascii_lower(self.headers[k].name) == want:
                return True
        return False

    def text(self) -> String:
        return String(StringSlice(unsafe_from_utf8=Span(self.body)))

    def body_excerpt(self, limit: Int = 256) -> String:
        """The first `limit` bytes of the body, for error messages.

        S3 and Iceberg REST both answer errors with a short XML or JSON
        document; truncating keeps a raised `Error` readable when the body is
        a 20 MB object instead.
        """
        var n = len(self.body)
        if n > limit:
            n = limit
        var s = String(StringSlice(unsafe_from_utf8=Span(self.body)[0:n]))
        if len(self.body) > limit:
            s += "…"
        return s^

    def raise_for_status(self, what: String) raises:
        if not self.ok():
            raise Error(
                what
                + ": HTTP "
                + String(self.status)
                + " "
                + self.body_excerpt()
            )


def parse_headers(raw: String) -> List[Header]:
    """Parses curl's raw header text into pairs.

    curl emits one header block per response it sees, so a redirect chain or a
    `100 Continue` produces several. Only the last block describes the
    response the caller gets, so a new status line resets the accumulator.
    """
    var out = List[Header]()
    var b = raw.as_bytes()
    var i = 0
    var n = len(b)
    while i < n:
        var j = i
        while j < n and b[j] != 10:
            j += 1
        var line = _trim(String(StringSlice(unsafe_from_utf8=Span(b)[i:j])))
        i = j + 1
        if line == "":
            continue
        if line.startswith("HTTP/"):
            out = List[Header]()
            continue
        var c = line.find(":")
        if c < 0:
            continue
        var lb = line.as_bytes()
        var name = _trim(String(StringSlice(unsafe_from_utf8=Span(lb)[0:c])))
        var value = _trim(
            String(StringSlice(unsafe_from_utf8=Span(lb)[c + 1 : len(lb)]))
        )
        out.append(Header(name^, value^))
    return out^


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------


def _do_request(
    imm lib: OwnedDLHandle,
    pool: Int,
    method: String,
    url: String,
    headers: String,
    body: Span[UInt8, _],
    range_start: Int,
    range_end: Int,
    timeout_ms: Int,
    follow_redirects: Bool,
    verify_tls: Bool,
) raises -> Response:
    var m = _cstr(method)
    var u = _cstr(url)
    var h = _cstr(headers)

    var body_addr = 0
    if len(body) > 0:
        body_addr = Int(body.unsafe_ptr())
    var res: Int
    if pool == SHARED_POOL:
        # The 0.1.x entry point, still exported and still meaning "the
        # process-wide client". Calling it rather than `_ex` for the default
        # case is what lets a consumer whose lock file pins an older
        # objectstore-shim build compile against these sources unchanged.
        var request_fn = lib.get_function[Int]("os_http_request")
        res = request_fn(
            Int(m.unsafe_ptr()),
            Int(u.unsafe_ptr()),
            Int(h.unsafe_ptr()),
            body_addr,
            c_size_t(len(body)),
            c_long_long(range_start),
            c_long_long(range_end),
            c_long(timeout_ms),
            c_int(1) if follow_redirects else c_int(0),
            c_int(1) if verify_tls else c_int(0),
        )
    else:
        var request_ex_fn = lib.get_function[Int]("os_http_request_ex")
        res = request_ex_fn(
            pool,
            Int(m.unsafe_ptr()),
            Int(u.unsafe_ptr()),
            Int(h.unsafe_ptr()),
            body_addr,
            c_size_t(len(body)),
            c_long_long(range_start),
            c_long_long(range_end),
            c_long(timeout_ms),
            c_int(1) if follow_redirects else c_int(0),
            c_int(1) if verify_tls else c_int(0),
        )
    # The three buffers must outlive the call above; naming them here is the
    # documented way to stop Mojo destroying them at their last use.
    _ = m^
    _ = u^
    _ = h^

    if res == 0:
        raise Error("objectstore.http: out of memory allocating result")

    var rc_fn = lib.get_function[c_long]("os_http_result_rc")
    var status_fn = lib.get_function[c_long]("os_http_result_status")
    var body_fn = lib.get_function[Int]("os_http_result_body")
    var body_len_fn = lib.get_function[c_size_t]("os_http_result_body_len")
    var hdr_fn = lib.get_function[Int]("os_http_result_headers")
    var err_fn = lib.get_function[Int]("os_http_result_error")
    var free_fn = lib.get_function[NoneType]("os_http_result_free")

    var rc = Int(rc_fn(res))
    if rc != 0:
        var msg = _read_cstring(Int(err_fn(res)))
        _ = free_fn(res)
        raise Error(
            "objectstore.http: " + method + " " + url + " failed: " + msg
        )

    var status = Int(status_fn(res))
    var raw_headers = _read_cstring(Int(hdr_fn(res)))
    var n = Int(body_len_fn(res))
    var out = List[UInt8](capacity=n if n > 0 else 1)
    if n > 0:
        var src = Pointer[UInt8, ImmUntrackedOrigin](
            unsafe_from_address=Int(body_fn(res))
        )
        out.extend(Span[UInt8, ImmUntrackedOrigin](unsafe_ptr=src, length=n))
    _ = free_fn(res)

    return Response(status, parse_headers(raw_headers), out^)


@fieldwise_init
struct HttpClient(Copyable, Movable):
    """An HTTP client over a persistent, reused connection.

    The client itself holds no socket: `pool` names a curl handle living in
    the shim, and `SHARED_POOL` — the default — is the process-wide one. Two
    `HttpClient` values therefore share connections, which is what makes an
    Iceberg scan that opens a new `S3Client` per file cheap. Single-threaded,
    like everything else in Mojo today.

    Redirects are **off** by default: a presigned S3 URL carries its signature
    in the query string and must never be silently re-issued elsewhere.
    """

    var timeout_ms: Int
    var follow_redirects: Bool
    var verify_tls: Bool
    var pool: Int
    """`SHARED_POOL`, or a handle from `new_connection_pool()` that the caller
    is responsible for freeing."""
    var retry: RetryPolicy

    def __init__(out self):
        self.timeout_ms = DEFAULT_TIMEOUT_MS
        self.follow_redirects = False
        self.verify_tls = True
        self.pool = SHARED_POOL
        self.retry = RetryPolicy()

    def request(
        self,
        method: String,
        url: String,
        headers: List[Header] = List[Header](),
        body: Span[UInt8, _] = Span[UInt8, ImmUntrackedOrigin](),
        range_start: Int = -1,
        range_end: Int = -1,
    ) raises -> Response:
        """Performs the request, retrying per `self.retry`.

        Raises only on *transport* failure — a 404 or a 500 comes back as a
        `Response` so the caller can decide. A retryable status that survives
        the last attempt is returned too: the caller sees the server's own
        answer rather than an invented error.
        """
        var repeatable = self.retry.retry_non_idempotent or is_idempotent(
            method, headers
        )
        var blob = header_blob(headers)
        var attempt = 0
        while True:
            try:
                var lib = OwnedDLHandle(_find_lib())
                var resp = _do_request(
                    lib,
                    self.pool,
                    method,
                    url,
                    blob,
                    body,
                    range_start,
                    range_end,
                    self.timeout_ms,
                    self.follow_redirects,
                    self.verify_tls,
                )
                if attempt >= self.retry.max_retries or not repeatable:
                    return resp^
                if not (
                    retryable_status(resp.status)
                    or (not resp.ok() and s3_retryable_error(Span(resp.body)))
                ):
                    return resp^
                attempt += 1
                sleep(Float64(backoff_delay_ms(self.retry, attempt)) / 1000.0)
            except e:
                # A transport failure — no response at all, so for an
                # idempotent request there is nothing to be inconsistent
                # about. This is also the case connection reuse makes more
                # likely: a pooled socket the server closed while it was idle.
                if attempt >= self.retry.max_retries or not repeatable:
                    raise e
                attempt += 1
                sleep(Float64(backoff_delay_ms(self.retry, attempt)) / 1000.0)

    def get(
        self,
        url: String,
        headers: List[Header] = List[Header](),
        range_start: Int = -1,
        range_end: Int = -1,
    ) raises -> Response:
        return self.request(
            "GET",
            url,
            headers,
            Span[UInt8, ImmUntrackedOrigin](),
            range_start,
            range_end,
        )

    def head(
        self, url: String, headers: List[Header] = List[Header]()
    ) raises -> Response:
        return self.request("HEAD", url, headers)

    def put(
        self,
        url: String,
        body: Span[UInt8, _],
        headers: List[Header] = List[Header](),
    ) raises -> Response:
        return self.request("PUT", url, headers, body)

    def post(
        self,
        url: String,
        body: Span[UInt8, _],
        headers: List[Header] = List[Header](),
    ) raises -> Response:
        return self.request("POST", url, headers, body)

    def delete(
        self, url: String, headers: List[Header] = List[Header]()
    ) raises -> Response:
        return self.request("DELETE", url, headers)


def curl_version() raises -> String:
    """Libcurl's own version banner, e.g. `libcurl/8.9.1 OpenSSL/3.3.1 …`."""
    var lib = OwnedDLHandle(_find_lib())
    return _do_curl_version(lib)


def _do_curl_version(imm lib: OwnedDLHandle) raises -> String:
    var version_fn = lib.get_function[Int]("os_http_curl_version")
    return _read_cstring(Int(version_fn()))
