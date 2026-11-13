"""objectstore's transport over `requests` (Mosaad-M/requests + tls).

What maps to what:

| objectstore              | here                                             |
|--------------------------|--------------------------------------------------|
| `SHARED_POOL`            | a free list of `requests.HttpClient`s; a thread  |
|                          | takes one per request, so threads never share a  |
|                          | client (each keeps its own keep-alive sockets)   |
| `new_connection_pool`    | one dedicated client                             |
| `pool_stats`             | requests made, `connections_opened` deltas       |
| `request_many`           | sequential on one client: requests has no multi  |
|                          | interface, so ranges are not in flight together  |
| `timeout_ms`             | `timeout_secs`, rounded up; it bounds each socket |
|                          | read and write, not the whole request            |
| `verify_tls=False`       | refused: tls has no way to skip verification     |
| `follow_redirects`       | `follow_redirects`, at most 5 hops               |
| the SigV4 clock          | `time()` through requests                        |
| IMDSv2 credentials       | the same three requests the shim makes, cached   |
|                          | until five minutes before they expire            |

Every request sends no Accept-Encoding and decodes nothing (an object store
serves bytes: a transparently decoded body would not match its
Content-Length or its Range), sends no Content-Type unless the caller gives
one, and allows
private addresses (MinIO on 127.0.0.1, the metadata service on
169.254.169.254) — objectstore talks to the endpoints it is configured with.
"""

from std.atomic import Atomic
from std.collections import Dict
from std.ffi import _Global
from std.os import getenv
from std.memory import OwnedPointer

from http_client import HttpClient as RClient, HttpHeaders, HttpResponse
from http_client import _unix_time_secs

from objectstore.http import (
    BATCH_POOL,
    BatchRequest,
    Header,
    HttpBackend,
    Response,
    SHARED_POOL,
    install_backend,
)

comptime _USER_AGENT = "objectstore.mojo/0.2 (requests)"
comptime _MAX_BODY = 1 << 40
"""requests buffers a whole response; its default 100 MB cap is per client,
and an object store's objects are routinely larger."""


struct _Client(Movable):
    """A heap-allocated requests client and the timeout it was made with
    (sockets take their timeout when they connect). The client never moves,
    so its address can be handed out while the list holding it grows."""

    var owned: OwnedPointer[RClient]
    var timeout_secs: Int

    def __init__(out self, timeout_secs: Int) raises:
        var c = RClient(allow_private_ips=True, timeout_secs=timeout_secs)
        c.user_agent = _USER_AGENT
        c.default_content_type = ""
        c.max_response_bytes = _MAX_BODY
        c.follow_redirects = False
        c.decompress = False
        self.owned = OwnedPointer(c^)
        self.timeout_secs = timeout_secs

    def address(self) -> Int:
        return Int(Pointer(to=self.owned[]))


def _at(address: Int) -> Pointer[RClient, MutUntrackedOrigin]:
    return Pointer[RClient, MutUntrackedOrigin](unsafe_from_address=address)


struct _State(Movable):
    var lock: Int64
    var free: List[_Client]
    var private: Dict[Int, Int]
    """pool id -> index into `dedicated`"""
    var dedicated: List[_Client]
    var next_pool: Int
    var stats: Dict[Int, Tuple[Int, Int]]
    """pool id (SHARED_POOL, BATCH_POOL or a private one) -> (requests, connects)"""
    var imds_known: Bool
    var imds_endpoint: String
    var imds_blob: String
    var imds_refresh: Int

    def __init__(out self):
        self.lock = 0
        self.free = List[_Client]()
        self.private = Dict[Int, Int]()
        self.dedicated = List[_Client]()
        self.next_pool = 1
        self.stats = Dict[Int, Tuple[Int, Int]]()
        self.imds_known = False
        self.imds_endpoint = ""
        self.imds_blob = ""
        self.imds_refresh = 0


def _new_state() -> _State:
    return _State()


comptime _STATE = _Global["objectstore_requests_state", _new_state]


def _lock() raises:
    var st = _STATE.get_or_create_ptr()
    while True:
        var expected = Int64(0)
        if Atomic[Int64].compare_exchange(
            Pointer(to=st[].lock), expected, Int64(1)
        ):
            return


def _unlock() raises:
    var st = _STATE.get_or_create_ptr()
    Atomic[Int64].store(Pointer(to=st[].lock), Int64(0))


def _count(pool: Int, requests: Int, connects: Int) raises:
    _lock()
    ref st = _STATE.get_or_create_ptr()[]
    var cur = st.stats.get(pool, Tuple(0, 0))
    st.stats[pool] = Tuple(cur[0] + requests, cur[1] + connects)
    _unlock()


def _checkout(timeout_secs: Int) raises -> _Client:
    """A pooled client made with this timeout, or a new one."""
    _lock()
    ref st = _STATE.get_or_create_ptr()[]
    for k in range(len(st.free) - 1, -1, -1):
        if st.free[k].timeout_secs == timeout_secs:
            var c = st.free.pop(k)
            _unlock()
            return c^
    _unlock()
    return _Client(timeout_secs)


def _checkin(var c: _Client) raises:
    _lock()
    _STATE.get_or_create_ptr()[].free.append(c^)
    _unlock()


def _timeout_secs(timeout_ms: Int) -> Int:
    if timeout_ms <= 0:
        return 3600
    return max(1, (timeout_ms + 999) // 1000)


def _headers(
    headers: List[Header], range_start: Int, range_end: Int
) -> HttpHeaders:
    var out = HttpHeaders()
    for k in range(len(headers)):
        out.add(headers[k].name, headers[k].value)
    if range_start >= 0:
        var r = "bytes=" + String(range_start) + "-"
        if range_end >= 0:
            r += String(range_end)
        out.add("Range", r)
    return out^


def _convert(resp: HttpResponse) -> Response:
    var hs = List[Header]()
    for k in range(len(resp.headers)):
        hs.append(Header(resp.headers._keys[k], resp.headers._values[k]))
    var body = List[UInt8](capacity=resp.body.byte_length())
    body.extend(resp.body.as_bytes())
    return Response(resp.status_code, hs^, body^)


def _do(
    mut c: RClient,
    method: String,
    url: String,
    headers: HttpHeaders,
    body: String,
    follow_redirects: Bool,
) raises -> HttpResponse:
    c.follow_redirects = follow_redirects
    c.max_redirects = 5
    # _follow_redirects is requests' general entry point: every public verb
    # method calls it (or _do_request) with fixed arguments.
    return c._follow_redirects(method, url, body, headers, follow_redirects, 5)


def _request(
    pool: Int,
    method: String,
    url: String,
    headers: List[Header],
    body_addr: Int,
    body_len: Int,
    range_start: Int,
    range_end: Int,
    timeout_ms: Int,
    follow_redirects: Bool,
    verify_tls: Bool,
) raises -> Response:
    if not verify_tls:
        raise Error(
            "the requests backend always verifies TLS (verify_tls=False is"
            " libcurl only)"
        )
    var body = String()
    if body_len > 0:
        var p = Pointer[UInt8, ImmUntrackedOrigin](
            unsafe_from_address=body_addr
        )
        body = String(
            StringSlice(
                unsafe_from_utf8=Span[UInt8, ImmUntrackedOrigin](
                    unsafe_ptr=p, length=body_len
                )
            )
        )
    var hs = _headers(headers, range_start, range_end)
    if pool != SHARED_POOL:
        _lock()
        ref st = _STATE.get_or_create_ptr()[]
        if pool not in st.private:
            _unlock()
            raise Error("objectstore_requests: unknown pool " + String(pool))
        var ptr = _at(st.dedicated[st.private[pool]].address())
        _unlock()
        # A private pool belongs to one thread at a time (objectstore.http).
        var before = ptr[].connections_opened
        var resp = _do(ptr[], method, url, hs, body, follow_redirects)
        _count(pool, 1, ptr[].connections_opened - before)
        return _convert(resp)
    var c = _checkout(_timeout_secs(timeout_ms))
    var before = c.owned[].connections_opened
    var got: Optional[HttpResponse] = None
    var failure = String()
    try:
        got = _do(c.owned[], method, url, hs, body, follow_redirects)
    except e:
        failure = String(e)
    _count(SHARED_POOL, 1, c.owned[].connections_opened - before)
    _checkin(c^)
    if not got:
        raise Error(failure)
    return _convert(got.value())


def _request_many(
    reqs: List[BatchRequest],
    timeout_ms: Int,
    verify_tls: Bool,
    max_parallel: Int,
) raises -> List[Optional[Response]]:
    """One after another on one client: requests has no way to keep several
    in flight from one thread. `max_parallel` is ignored."""
    if not verify_tls:
        raise Error("the requests backend always verifies TLS")
    var out = List[Optional[Response]](capacity=len(reqs))
    var c = _checkout(_timeout_secs(timeout_ms))
    var before = c.owned[].connections_opened
    for k in range(len(reqs)):
        ref r = reqs[k]
        try:
            var resp = _do(
                c.owned[],
                r.method,
                r.url,
                _headers(r.headers, r.range_start, r.range_end),
                String(),
                False,
            )
            out.append(_convert(resp))
        except:
            out.append(None)
    _count(BATCH_POOL, len(reqs), c.owned[].connections_opened - before)
    _checkin(c^)
    return out^


def _pool_new() raises -> Int:
    var c = _Client(_timeout_secs(30000))
    _lock()
    ref st = _STATE.get_or_create_ptr()[]
    var id = st.next_pool
    st.next_pool += 1
    st.private[id] = len(st.dedicated)
    st.dedicated.append(c^)
    _unlock()
    return id


def _pool_free(pool: Int) raises:
    """Closes the pool's connections. The client's slot stays allocated
    (indices into `dedicated` must not move), which a prototype can afford."""
    _lock()
    ref st = _STATE.get_or_create_ptr()[]
    if pool in st.private:
        var idx = st.private.pop(pool)
        # Replacing the client closes the old one's sockets as it is
        # destroyed; the slot itself stays, so other pools' indices hold.
        st.dedicated[idx] = _Client(_timeout_secs(30000))
        _unlock()
        return
    _unlock()


def _stats(pool: Int) raises -> Tuple[Int, Int]:
    _lock()
    ref st = _STATE.get_or_create_ptr()[]
    var got = st.stats.get(pool, Tuple(0, 0))
    _unlock()
    return got


def _reset_stats(pool: Int) raises:
    _lock()
    ref st = _STATE.get_or_create_ptr()[]
    st.stats[pool] = Tuple(0, 0)
    _unlock()


def _epoch_now() raises -> Int:
    return Int(_unix_time_secs())


def _version() raises -> String:
    return String("requests (Mosaad-M/requests, pure-Mojo HTTP/1.1 + tls)")


def _iso8601_epoch(s: String) -> Int:
    """`2026-11-13T18:04:05Z` -> epoch seconds; 0 when malformed."""
    var b = s.as_bytes()
    if len(b) < 19:
        return 0

    def num(b: Span[UInt8, _], at: Int, n: Int) -> Int:
        var v = 0
        for k in range(at, at + n):
            if b[k] < 48 or b[k] > 57:
                return -1
            v = v * 10 + Int(b[k] - 48)
        return v

    var y = num(b, 0, 4)
    var mo = num(b, 5, 2)
    var d = num(b, 8, 2)
    var hh = num(b, 11, 2)
    var mi = num(b, 14, 2)
    var ss = num(b, 17, 2)
    if y < 0 or mo < 1 or d < 1 or hh < 0 or mi < 0 or ss < 0:
        return 0
    # Days from civil (Howard Hinnant's algorithm).
    var yy = y - 1 if mo <= 2 else y
    var era = yy // 400
    var yoe = yy - era * 400
    var mp = mo + 9 if mo <= 2 else mo - 3
    var doy = (153 * mp + 2) // 5 + d - 1
    var doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    var days = era * 146097 + doe - 719468
    return days * 86400 + hh * 3600 + mi * 60 + ss


def _json_field(doc: String, key: String) -> String:
    """The string value of `"key": "..."` in a flat JSON object (IMDS's
    credential document), or `""`."""
    var at = doc.find('"' + key + '"')
    if at < 0:
        return String()
    var colon = doc.find(":", at)
    if colon < 0:
        return String()
    var q1 = doc.find('"', colon)
    if q1 < 0:
        return String()
    var q2 = doc.find('"', q1 + 1)
    if q2 < 0:
        return String()
    return String(doc[byte = q1 + 1 : q2])


def _imds_fetch(endpoint: String) raises -> Tuple[String, Int]:
    """IMDSv2: a session token, the role's name, its credentials."""
    var c = RClient(allow_private_ips=True, timeout_secs=2)
    c.user_agent = _USER_AGENT
    c.follow_redirects = False
    c.default_content_type = ""
    var th = HttpHeaders()
    th.add("X-aws-ec2-metadata-token-ttl-seconds", "21600")
    var tok = c._do_request("PUT", endpoint + "/latest/api/token", "", th)
    if tok.status_code != 200 or tok.body.byte_length() == 0:
        return Tuple(String(), 0)
    var auth = HttpHeaders()
    auth.add("X-aws-ec2-metadata-token", tok.body)
    var base = endpoint + "/latest/meta-data/iam/security-credentials/"
    var role = c._do_request("GET", base, "", auth)
    if role.status_code != 200:
        return Tuple(String(), 0)
    var name = String(role.body.split("\n")[0].strip())
    if name.byte_length() == 0 or name.byte_length() > 256:
        return Tuple(String(), 0)
    var creds = c._do_request("GET", base + name, "", auth)
    if creds.status_code != 200:
        return Tuple(String(), 0)
    var akid = _json_field(creds.body, "AccessKeyId")
    var secret = _json_field(creds.body, "SecretAccessKey")
    var token = _json_field(creds.body, "Token")
    var expiry = _iso8601_epoch(_json_field(creds.body, "Expiration"))
    if akid == "" or secret == "" or token == "" or expiry == 0:
        return Tuple(String(), 0)
    return Tuple(
        akid + "\n" + secret + "\n" + token + "\n" + String(expiry), expiry
    )


def _instance_credentials() raises -> String:
    """As the shim's `os_imds_credentials`: cached per process, "none"
    included, until five minutes before expiry or an endpoint change."""
    var disabled = getenv("AWS_EC2_METADATA_DISABLED", "").lower()
    if disabled == "true" or disabled == "1":
        return String()
    var endpoint = getenv(
        "AWS_EC2_METADATA_SERVICE_ENDPOINT", "http://169.254.169.254"
    )
    if endpoint.endswith("/"):
        var trimmed = String(endpoint[byte = 0 : endpoint.byte_length() - 1])
        endpoint = trimmed^
    var now = Int(_unix_time_secs())
    _lock()
    ref st = _STATE.get_or_create_ptr()[]
    var stale = (
        not st.imds_known
        or st.imds_endpoint != endpoint
        or (st.imds_blob != "" and now >= st.imds_refresh)
    )
    if not stale:
        var blob = st.imds_blob
        _unlock()
        return blob^
    _unlock()
    var got = Tuple(String(), 0)
    try:
        got = _imds_fetch(endpoint)
    except:
        pass
    _lock()
    ref st2 = _STATE.get_or_create_ptr()[]
    st2.imds_known = True
    st2.imds_endpoint = endpoint
    st2.imds_blob = got[0]
    st2.imds_refresh = got[1] - 300
    _unlock()
    return got[0]


def install() raises:
    """Routes all of objectstore's HTTP through requests (see the module
    docstring). Call once, before the first request."""
    install_backend(
        HttpBackend(
            String("requests"),
            _request,
            _request_many,
            _pool_new,
            _pool_free,
            _stats,
            _reset_stats,
            _epoch_now,
            _instance_credentials,
            _version,
        )
    )
