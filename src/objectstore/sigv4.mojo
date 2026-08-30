"""`objectstore.sigv4` — AWS Signature Version 4, header and query flavours.

Split out of `s3` because it is pure string algebra over `crypto`: given a
method, a path, query parameters, headers and a payload hash it produces the
canonical request, the string to sign, and the signature. That shape is what
makes it testable against the published `aws-sig-v4-test-suite` vectors
without a network or an S3 server anywhere in the picture.

Two callers use it: `S3Client`, which signs with an `Authorization` header,
and `presign_url`, which moves the same material into the query string so a
URL can be handed to something that knows nothing about AWS.
"""

from std.ffi import OwnedDLHandle, c_long_long

from .crypto import hmac_sha256, sha256_hex, to_hex
from .http import Header, _ascii_lower, _find_lib, _trim
from .path import url_encode


comptime ALGORITHM = String("AWS4-HMAC-SHA256")
comptime UNSIGNED_PAYLOAD = String("UNSIGNED-PAYLOAD")
comptime EMPTY_SHA256 = String(
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)
"""SHA-256 of the empty string — the payload hash of every bodyless request."""


@fieldwise_init
struct QueryParam(Copyable, Movable):
    """One query parameter, **unencoded**. Signing encodes it."""

    var name: String
    var value: String


# ---------------------------------------------------------------------------
# Time
# ---------------------------------------------------------------------------


def epoch_now() raises -> Int:
    """Seconds since the Unix epoch, via the FFI shim.

    Mojo's `std.time` offers only a monotonic clock, and SigV4 needs a real
    UTC timestamp — AWS rejects requests more than 15 minutes out of skew.
    """
    var lib = OwnedDLHandle(_find_lib())
    return _do_epoch_now(lib)


def _do_epoch_now(imm lib: OwnedDLHandle) raises -> Int:
    var epoch_fn = lib.get_function[c_long_long]("os_time_epoch")
    return Int(epoch_fn())


def _pad2(v: Int) -> String:
    if v < 10:
        return String("0") + String(v)
    return String(v)


@fieldwise_init
struct AmzTime(Copyable, Movable):
    """A signing timestamp in the two forms SigV4 needs."""

    var amz_date: String
    """`20150830T123600Z` — the `X-Amz-Date` header value."""
    var date_stamp: String
    """`20150830` — the date half of the credential scope."""

    @staticmethod
    def from_epoch(epoch: Int) -> Self:
        """UTC calendar date from a Unix timestamp.

        Days-to-civil from Howard Hinnant's `chrono`-compatible algorithm: it
        shifts the era so that leap days land at the end, which makes the
        whole conversion branch-free integer arithmetic. Mojo has no calendar
        library, and re-deriving this is cheaper than another FFI call.
        """
        var days = epoch // 86400
        var secs = epoch - days * 86400
        var z = days + 719468
        var era = (z if z >= 0 else z - 146096) // 146097
        var doe = z - era * 146097
        var yoe = (doe - doe // 1460 + doe // 36524 - doe // 146096) // 365
        var y = yoe + era * 400
        var doy = doe - (365 * yoe + yoe // 4 - yoe // 100)
        var mp = (5 * doy + 2) // 153
        var d = doy - (153 * mp + 2) // 5 + 1
        var m = mp + 3 if mp < 10 else mp - 9
        if m <= 2:
            y += 1

        var date_stamp = String(y) + _pad2(m) + _pad2(d)
        var hh = secs // 3600
        var mm = (secs % 3600) // 60
        var ss = secs % 60
        var amz = (
            date_stamp + "T" + _pad2(hh) + _pad2(mm) + _pad2(ss) + "Z"
        )
        return Self(amz^, date_stamp^)

    @staticmethod
    def now() raises -> Self:
        return Self.from_epoch(epoch_now())

    @staticmethod
    def from_amz_date(amz_date: String) raises -> Self:
        """Reuses an `X-Amz-Date` value the caller already has (the test
        vectors, or a retried request that must keep its timestamp)."""
        if amz_date.byte_length() < 8:
            raise Error("objectstore.sigv4: malformed X-Amz-Date " + amz_date)
        var b = amz_date.as_bytes()
        var stamp = String(StringSlice(unsafe_from_utf8=Span(b)[0:8]))
        return Self(amz_date, stamp^)


# ---------------------------------------------------------------------------
# Canonicalization
# ---------------------------------------------------------------------------


def canonical_path(path: String, normalize: Bool = False) -> String:
    """The canonical URI: each segment percent-encoded once, `/` left alone.

    `normalize` collapses `.`/`..` and duplicate slashes, which is what every
    AWS service except S3 wants. **S3 signs the un-normalized path** — an S3
    key may legitimately contain a literal `..` segment — so the S3 client
    leaves this off.
    """
    var p = path
    if p == "":
        return String("/")
    if not p.startswith("/"):
        p = String("/") + p

    if not normalize:
        return url_encode(p, encode_slash=False)

    var segs = List[String]()
    var parts = p.split("/")
    for k in range(len(parts)):
        var seg = String(parts[k])
        if seg == "" or seg == ".":
            continue
        if seg == "..":
            if len(segs) > 0:
                _ = segs.pop()
            continue
        segs.append(seg^)
    var out = String("")
    for k in range(len(segs)):
        out += "/"
        out += url_encode(segs[k], encode_slash=True)
    if out == "":
        return String("/")
    if p.endswith("/") and not out.endswith("/"):
        out += "/"
    return out^


def canonical_query(params: List[QueryParam]) -> String:
    """Encoded `k=v` pairs sorted by encoded name, then encoded value."""
    var names = List[String]()
    var values = List[String]()
    for k in range(len(params)):
        names.append(url_encode(params[k].name, encode_slash=True))
        values.append(url_encode(params[k].value, encode_slash=True))

    # Insertion sort: a request never carries more than a handful of
    # parameters, and this keeps the ordering rule visible.
    for i in range(1, len(names)):
        var n = names[i]
        var v = values[i]
        var j = i - 1
        while j >= 0 and (names[j] > n or (names[j] == n and values[j] > v)):
            names[j + 1] = names[j]
            values[j + 1] = values[j]
            j -= 1
        names[j + 1] = n^
        values[j + 1] = v^

    var out = String("")
    for k in range(len(names)):
        if k > 0:
            out += "&"
        out += names[k]
        out += "="
        out += values[k]
    return out^


def _collapse_spaces(value: String) -> String:
    """Trim the value and squeeze every internal whitespace run to one space.

    The SigV4 prose exempts quoted sections, but the published test suite does
    not: `get-header-value-trim` signs `My-Header2: "a   b   c"` as
    `"a b c"`. The vectors are what servers actually verify against, so they
    win over the prose.
    """
    var b = _trim(value).as_bytes()
    var out = List[UInt8]()
    var prev_space = False
    for k in range(len(b)):
        var c = b[k]
        if c == 32 or c == 9:
            if prev_space:
                continue
            prev_space = True
            out.append(32)
            continue
        prev_space = False
        out.append(c)
    return String(StringSlice(unsafe_from_utf8=Span(out)))


def canonical_headers(
    headers: List[Header],
) -> Tuple[String, String]:
    """Returns `(canonical header block, signed header list)`.

    Names are lowercased and sorted; repeated names are joined with commas in
    the order they appeared, per the SigV4 spec.
    """
    var names = List[String]()
    var vals = List[String]()
    for k in range(len(headers)):
        var n = _ascii_lower(headers[k].name)
        var v = _collapse_spaces(headers[k].value)
        var found = -1
        for j in range(len(names)):
            if names[j] == n:
                found = j
                break
        if found >= 0:
            vals[found] = vals[found] + "," + v
        else:
            names.append(n^)
            vals.append(v^)

    for i in range(1, len(names)):
        var n = names[i]
        var v = vals[i]
        var j = i - 1
        while j >= 0 and names[j] > n:
            names[j + 1] = names[j]
            vals[j + 1] = vals[j]
            j -= 1
        names[j + 1] = n^
        vals[j + 1] = v^

    var block = String("")
    var signed = String("")
    for k in range(len(names)):
        block += names[k]
        block += ":"
        block += vals[k]
        block += "\n"
        if k > 0:
            signed += ";"
        signed += names[k]
    return Tuple(block^, signed^)


def canonical_request(
    method: String,
    path: String,
    params: List[QueryParam],
    headers: List[Header],
    payload_hash: String,
    normalize: Bool = False,
) -> Tuple[String, String]:
    """Returns `(canonical request, signed headers)`."""
    var ch = canonical_headers(headers)
    var out = method
    out += "\n"
    out += canonical_path(path, normalize)
    out += "\n"
    out += canonical_query(params)
    out += "\n"
    out += ch[0]
    out += "\n"
    out += ch[1]
    out += "\n"
    out += payload_hash
    return Tuple(out^, ch[1])


def credential_scope(
    date_stamp: String, region: String, service: String
) -> String:
    return date_stamp + "/" + region + "/" + service + "/aws4_request"


def string_to_sign(
    amz_date: String, scope: String, canonical_req: String
) -> String:
    var out = ALGORITHM
    out += "\n"
    out += amz_date
    out += "\n"
    out += scope
    out += "\n"
    out += sha256_hex(canonical_req)
    return out^


def signing_key(
    secret_key: String, date_stamp: String, region: String, service: String
) -> List[UInt8]:
    """The four-step HMAC ladder: date, region, service, `aws4_request`."""
    var k0 = (String("AWS4") + secret_key).as_bytes()
    var k1 = hmac_sha256(k0, date_stamp)
    var k2 = hmac_sha256(Span(k1), region)
    var k3 = hmac_sha256(Span(k2), service)
    return hmac_sha256(Span(k3), String("aws4_request"))


def sign(
    secret_key: String,
    date_stamp: String,
    region: String,
    service: String,
    to_sign: String,
) -> String:
    var key = signing_key(secret_key, date_stamp, region, service)
    return to_hex(Span(hmac_sha256(Span(key), to_sign)))


@fieldwise_init
struct SignedRequest(Copyable, Movable):
    """Everything a signing pass produced, so tests can check each stage."""

    var canonical_request: String
    var string_to_sign: String
    var signature: String
    var signed_headers: String
    var authorization: String


def sign_request(
    method: String,
    path: String,
    params: List[QueryParam],
    headers: List[Header],
    payload_hash: String,
    access_key: String,
    secret_key: String,
    region: String,
    service: String,
    when: AmzTime,
    normalize: Bool = False,
) -> SignedRequest:
    """Header-flavoured SigV4.

    `headers` must already contain `host`, `x-amz-date` and, when a session
    token is in play, `x-amz-security-token`: which headers are signed is the
    caller's decision, and S3 in particular insists that
    `x-amz-content-sha256` be among them.
    """
    var cr = canonical_request(
        method, path, params, headers, payload_hash, normalize
    )
    var scope = credential_scope(when.date_stamp, region, service)
    var sts = string_to_sign(when.amz_date, scope, cr[0])
    var sig = sign(secret_key, when.date_stamp, region, service, sts)
    var auth = ALGORITHM
    auth += " Credential="
    auth += access_key
    auth += "/"
    auth += scope
    auth += ", SignedHeaders="
    auth += cr[1]
    auth += ", Signature="
    auth += sig
    return SignedRequest(cr[0], sts^, sig^, cr[1], auth^)


def presign_query(
    method: String,
    path: String,
    params: List[QueryParam],
    headers: List[Header],
    access_key: String,
    secret_key: String,
    session_token: String,
    region: String,
    service: String,
    when: AmzTime,
    expires_seconds: Int,
    normalize: Bool = False,
) -> String:
    """Query-flavoured SigV4: returns the full canonical query string,
    `X-Amz-Signature` included.

    The payload hash for a presigned URL is `UNSIGNED-PAYLOAD`: the point of
    presigning is that whoever follows the URL never sees the credentials, so
    they cannot be expected to hash a body the signer never had.
    """
    var ch = canonical_headers(headers)
    var scope = credential_scope(when.date_stamp, region, service)

    var all_params = List[QueryParam]()
    for k in range(len(params)):
        all_params.append(params[k].copy())
    all_params.append(QueryParam("X-Amz-Algorithm", ALGORITHM))
    all_params.append(
        QueryParam("X-Amz-Credential", access_key + "/" + scope)
    )
    all_params.append(QueryParam("X-Amz-Date", when.amz_date))
    all_params.append(
        QueryParam("X-Amz-Expires", String(expires_seconds))
    )
    all_params.append(QueryParam("X-Amz-SignedHeaders", ch[1]))
    if session_token != "":
        all_params.append(QueryParam("X-Amz-Security-Token", session_token))

    var cr = canonical_request(
        method, path, all_params, headers, UNSIGNED_PAYLOAD, normalize
    )
    var sts = string_to_sign(when.amz_date, scope, cr[0])
    var sig = sign(secret_key, when.date_stamp, region, service, sts)
    return canonical_query(all_params) + "&X-Amz-Signature=" + sig
