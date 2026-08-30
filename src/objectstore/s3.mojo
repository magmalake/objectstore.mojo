"""`objectstore.s3` — an S3 client over `HttpClient`, signed with SigV4.

Covers what an Iceberg reader and writer actually issue: `GetObject` (with
`Range`, because a Parquet reader wants the footer before anything else),
`PutObject`, `HeadObject`, `DeleteObject` and a paginated `ListObjectsV2`.
Multipart upload is deliberately absent — see the README.

Addressing works both ways. Virtual-host style (`bucket.s3.region.amazonaws.com`)
is what AWS prefers; path style (`endpoint/bucket/key`) is what MinIO, Ceph and
most S3-compatible servers default to, and what a bucket name with dots forces
even on AWS. `S3Config.path_style` picks, and a custom `endpoint` makes this
work against MinIO, R2 or anything else that speaks the protocol.

Credentials come from four places, in the order a caller should expect:
explicit properties, the `AWS_*` environment, REST-catalog **vended
credentials** (which are just properties under a location prefix — see
`fileio.FileIOResolver`), and presigned URLs, which carry the signature in the
query string and need no credentials at the point of use at all.
"""

from std.collections import Dict
from std.os import getenv

from .crypto import sha256_hex
from .http import Header, HttpClient, Response
from .path import Uri, parse_uri, url_encode
from .sigv4 import (
    AmzTime,
    EMPTY_SHA256,
    QueryParam,
    UNSIGNED_PAYLOAD,
    presign_query,
    sign_request,
)


comptime SERVICE = String("s3")
comptime DEFAULT_REGION = String("us-east-1")


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@fieldwise_init
struct S3Credentials(Copyable, Movable):
    var access_key_id: String
    var secret_access_key: String
    var session_token: String

    def __init__(out self):
        self.access_key_id = ""
        self.secret_access_key = ""
        self.session_token = ""

    def is_set(self) -> Bool:
        return self.access_key_id != "" and self.secret_access_key != ""


struct S3Config(Copyable, Movable):
    """Everything needed to address and sign against one S3 endpoint."""

    var endpoint: String
    """`https://minio.local:9000`, or `""` for the AWS regional endpoint."""
    var region: String
    var path_style: Bool
    var credentials: S3Credentials
    var sign_payload: Bool
    """When false, `PUT` bodies are signed as `UNSIGNED-PAYLOAD` — a real
    option for a large object over TLS, where hashing the payload twice is
    pure overhead."""
    var anonymous: Bool
    """Skip signing entirely: public buckets, and presigned URLs, need no
    credentials and are rejected by some servers if signed anyway."""

    def __init__(out self):
        self.endpoint = ""
        self.region = DEFAULT_REGION
        self.path_style = False
        self.credentials = S3Credentials()
        self.sign_payload = True
        self.anonymous = False

    def __init__(
        out self,
        var endpoint: String,
        var region: String,
        path_style: Bool,
        var credentials: S3Credentials,
        sign_payload: Bool = True,
        anonymous: Bool = False,
    ):
        self.endpoint = endpoint^
        self.region = region^
        self.path_style = path_style
        self.credentials = credentials^
        self.sign_payload = sign_payload
        self.anonymous = anonymous

    @staticmethod
    def from_env() raises -> Self:
        """The standard `AWS_*` variables, plus `AWS_ENDPOINT_URL[_S3]`."""
        var c = Self()
        c.credentials = S3Credentials(
            getenv("AWS_ACCESS_KEY_ID", ""),
            getenv("AWS_SECRET_ACCESS_KEY", ""),
            getenv("AWS_SESSION_TOKEN", ""),
        )
        var region = getenv("AWS_REGION", "")
        if region == "":
            region = getenv("AWS_DEFAULT_REGION", "")
        if region != "":
            c.region = region^
        var ep = getenv("AWS_ENDPOINT_URL_S3", "")
        if ep == "":
            ep = getenv("AWS_ENDPOINT_URL", "")
        if ep != "":
            c.endpoint = ep^
            # A custom endpoint is almost always a MinIO/Ceph-style server,
            # where virtual-host addressing needs wildcard DNS nobody sets up
            # for a test container.
            c.path_style = True
        if _truthy(getenv("AWS_S3_FORCE_PATH_STYLE", "")):
            c.path_style = True
        c.anonymous = not c.credentials.is_set()
        return c^

    @staticmethod
    def from_properties(props: Dict[String, String]) raises -> Self:
        """Iceberg property names, which is what a REST catalog hands back.

        Recognised: `s3.endpoint`, `s3.access-key-id`, `s3.secret-access-key`,
        `s3.session-token`, `s3.region`, `s3.path-style-access`, and
        `client.region` as a fallback for the region.
        """
        var c = Self.from_env()
        if "s3.endpoint" in props:
            c.endpoint = props["s3.endpoint"]
            c.path_style = True
        if "s3.access-key-id" in props:
            c.credentials.access_key_id = props["s3.access-key-id"]
        if "s3.secret-access-key" in props:
            c.credentials.secret_access_key = props["s3.secret-access-key"]
        if "s3.session-token" in props:
            c.credentials.session_token = props["s3.session-token"]
        if "s3.region" in props:
            c.region = props["s3.region"]
        elif "client.region" in props:
            c.region = props["client.region"]
        if "s3.path-style-access" in props:
            c.path_style = _truthy(props["s3.path-style-access"])
        c.anonymous = not c.credentials.is_set()
        return c^


def _truthy(v: String) -> Bool:
    return v == "true" or v == "True" or v == "1" or v == "yes"


# ---------------------------------------------------------------------------
# Listing results
# ---------------------------------------------------------------------------


@fieldwise_init
struct ObjectInfo(Copyable, Movable):
    var key: String
    var size: Int
    var last_modified: String
    var etag: String


struct ListResult(Copyable, Movable):
    var objects: List[ObjectInfo]
    var common_prefixes: List[String]
    var is_truncated: Bool
    var next_continuation_token: String

    def __init__(out self):
        self.objects = []
        self.common_prefixes = []
        self.is_truncated = False
        self.next_continuation_token = ""


# ---------------------------------------------------------------------------
# A very small XML reader
# ---------------------------------------------------------------------------
#
# S3's list and error documents are shallow and machine-generated: no
# namespaces on the elements we read, no attributes, no CDATA, no mixed
# content. A real parser would be dead weight, so this walks the text looking
# for `<Tag>` … `</Tag>` spans and decodes the five predefined entities.


def _substr(s: String, start: Int, end: Int) -> String:
    var b = s.as_bytes()
    var i = start
    var j = end
    if i < 0:
        i = 0
    if j > len(b):
        j = len(b)
    if i >= j:
        return String("")
    return String(StringSlice(unsafe_from_utf8=Span(b)[i:j]))


def xml_unescape(s: String) -> String:
    if s.find("&") < 0:
        return s
    var out = String("")
    var b = s.as_bytes()
    var i = 0
    while i < len(b):
        if b[i] == 38:  # '&'
            var semi = s.find(";", i)
            if semi > i and semi - i <= 8:
                var name = _substr(s, i + 1, semi)
                if name == "amp":
                    out += "&"
                elif name == "lt":
                    out += "<"
                elif name == "gt":
                    out += ">"
                elif name == "quot":
                    out += '"'
                elif name == "apos":
                    out += "'"
                elif name == "#39":
                    out += "'"
                else:
                    out += _substr(s, i, semi + 1)
                i = semi + 1
                continue
        out += String(StringSlice(unsafe_from_utf8=Span(b)[i : i + 1]))
        i += 1
    return out^


def xml_element(body: String, tag: String, start: Int = 0) -> Int:
    """Byte offset of `<tag>`'s content, or -1. Feeds `xml_text`."""
    var open_tag = String("<") + tag + ">"
    var at = body.find(open_tag, start)
    if at < 0:
        return -1
    return at + open_tag.byte_length()


def xml_text(body: String, tag: String, start: Int = 0) -> String:
    """The text of the first `<tag>` at or after `start`; `""` if absent."""
    var content = xml_element(body, tag, start)
    if content < 0:
        return String("")
    var close = body.find(String("</") + tag + ">", content)
    if close < 0:
        return String("")
    return xml_unescape(_substr(body, content, close))


def xml_blocks(body: String, tag: String) -> List[String]:
    """Every `<tag>` … `</tag>` body, in document order."""
    var out = List[String]()
    var open_tag = String("<") + tag + ">"
    var close_tag = String("</") + tag + ">"
    var i = 0
    while True:
        var at = body.find(open_tag, i)
        if at < 0:
            break
        var content = at + open_tag.byte_length()
        var close = body.find(close_tag, content)
        if close < 0:
            break
        out.append(_substr(body, content, close))
        i = close + close_tag.byte_length()
    return out^


def parse_list_objects(body: String) raises -> ListResult:
    var out = ListResult()
    var contents = xml_blocks(body, String("Contents"))
    for k in range(len(contents)):
        ref c = contents[k]
        var size_text = xml_text(c, String("Size"))
        var size = 0
        if size_text != "":
            size = Int(size_text)
        out.objects.append(
            ObjectInfo(
                xml_text(c, String("Key")),
                size,
                xml_text(c, String("LastModified")),
                xml_text(c, String("ETag")),
            )
        )
    var prefixes = xml_blocks(body, String("CommonPrefixes"))
    for k in range(len(prefixes)):
        out.common_prefixes.append(xml_text(prefixes[k], String("Prefix")))
    out.is_truncated = xml_text(body, String("IsTruncated")) == "true"
    out.next_continuation_token = xml_text(
        body, String("NextContinuationToken")
    )
    return out^


def s3_error_message(resp: Response) -> String:
    """`<Error><Code>…</Code><Message>…</Message></Error>` if that is what came
    back, else the first bytes of whatever did."""
    var body = resp.text()
    var code = xml_text(body, String("Code"))
    if code == "":
        return resp.body_excerpt()
    var msg = xml_text(body, String("Message"))
    if msg == "":
        return code
    return code + ": " + msg


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------


struct S3Client(Copyable, Movable):
    var config: S3Config
    var http: HttpClient

    def __init__(out self, var config: S3Config):
        self.config = config^
        self.http = HttpClient()

    def __init__(out self, var config: S3Config, var http: HttpClient):
        self.config = config^
        self.http = http^

    # ── addressing ─────────────────────────────────────────────────────────
    def _endpoint_parts(self) raises -> Tuple[String, String]:
        """Returns `(scheme, host[:port])` for the configured endpoint."""
        if self.config.endpoint == "":
            return Tuple(
                String("https"),
                String("s3.") + self.config.region + ".amazonaws.com",
            )
        var u = self.config.endpoint
        var scheme = String("https")
        var rest = u
        var sep = u.find("://")
        if sep >= 0:
            scheme = _substr(u, 0, sep)
            rest = _substr(u, sep + 3, u.byte_length())
        var slash = rest.find("/")
        if slash >= 0:
            rest = _substr(rest, 0, slash)
        return Tuple(scheme^, rest^)

    def url_for(self, bucket: String, key: String) raises -> Tuple[String, String, String]:
        """Returns `(url, host header value, signing path)`.

        The signing path is the request target *before* the query string, and
        it must match byte for byte what the server reconstructs — hence
        building it here rather than re-deriving it from the URL later.
        """
        var parts = self._endpoint_parts()
        var scheme = parts[0]
        var host = parts[1]
        var path: String
        if self.config.path_style:
            path = String("/") + bucket
            if key != "":
                path += "/" + key
        else:
            host = bucket + "." + host
            path = String("/") + key
        var url = scheme + "://" + host + url_encode(path, encode_slash=False)
        return Tuple(url^, _host_header(scheme, host), path^)

    # ── signing ────────────────────────────────────────────────────────────
    def _signed_headers(
        self,
        method: String,
        host: String,
        path: String,
        params: List[QueryParam],
        payload_hash: String,
        var extra: List[Header],
    ) raises -> List[Header]:
        var headers = List[Header]()
        headers.append(Header("Host", host))
        for k in range(len(extra)):
            headers.append(extra[k].copy())
        if self.config.anonymous:
            return headers^

        var when = AmzTime.now()
        headers.append(Header("x-amz-date", when.amz_date))
        headers.append(Header("x-amz-content-sha256", payload_hash))
        if self.config.credentials.session_token != "":
            headers.append(
                Header(
                    "x-amz-security-token",
                    self.config.credentials.session_token,
                )
            )
        var signed = sign_request(
            method,
            path,
            params,
            headers,
            payload_hash,
            self.config.credentials.access_key_id,
            self.config.credentials.secret_access_key,
            self.config.region,
            SERVICE,
            when,
            # S3 signs the *un-normalized* path: `..` is a legal key segment.
            normalize=False,
        )
        headers.append(Header("Authorization", signed.authorization))
        return headers^

    def request(
        self,
        method: String,
        bucket: String,
        key: String,
        params: List[QueryParam] = List[QueryParam](),
        body: Span[UInt8, _] = Span[UInt8, ImmUntrackedOrigin](),
        extra_headers: List[Header] = List[Header](),
        range_start: Int = -1,
        range_end: Int = -1,
    ) raises -> Response:
        var addr = self.url_for(bucket, key)
        var url = addr[0]
        var query = _query_string(params)
        if query != "":
            url += "?" + query

        var payload_hash = EMPTY_SHA256
        if len(body) > 0:
            if self.config.sign_payload:
                payload_hash = sha256_hex(body)
            else:
                payload_hash = UNSIGNED_PAYLOAD

        var headers = self._signed_headers(
            method, addr[1], addr[2], params, payload_hash, extra_headers.copy()
        )
        return self.http.request(
            method, url, headers, body, range_start, range_end
        )

    # ── operations ─────────────────────────────────────────────────────────
    def get_object(
        self,
        bucket: String,
        key: String,
        range_start: Int = -1,
        range_end: Int = -1,
    ) raises -> List[UInt8]:
        """Whole object, or the inclusive byte range `[start, end]`."""
        var r = self.request(
            "GET",
            bucket,
            key,
            List[QueryParam](),
            Span[UInt8, ImmUntrackedOrigin](),
            List[Header](),
            range_start,
            range_end,
        )
        if not r.ok():
            raise Error(
                "s3: GET "
                + bucket
                + "/"
                + key
                + ": HTTP "
                + String(r.status)
                + " "
                + s3_error_message(r)
            )
        return r.body.copy()

    def head_object(self, bucket: String, key: String) raises -> Response:
        return self.request("HEAD", bucket, key)

    def object_length(self, bucket: String, key: String) raises -> Int:
        var r = self.head_object(bucket, key)
        if not r.ok():
            raise Error(
                "s3: HEAD "
                + bucket
                + "/"
                + key
                + ": HTTP "
                + String(r.status)
            )
        var cl = r.header("Content-Length")
        if cl == "":
            raise Error("s3: HEAD " + bucket + "/" + key + ": no Content-Length")
        return Int(cl)

    def object_exists(self, bucket: String, key: String) raises -> Bool:
        return self.head_object(bucket, key).ok()

    def put_object(
        self,
        bucket: String,
        key: String,
        body: Span[UInt8, _],
        content_type: String = "",
    ) raises:
        var extra = List[Header]()
        if content_type != "":
            extra.append(Header("Content-Type", content_type))
        var r = self.request(
            "PUT", bucket, key, List[QueryParam](), body, extra
        )
        if not r.ok():
            raise Error(
                "s3: PUT "
                + bucket
                + "/"
                + key
                + ": HTTP "
                + String(r.status)
                + " "
                + s3_error_message(r)
            )

    def delete_object(self, bucket: String, key: String) raises:
        var r = self.request("DELETE", bucket, key)
        # S3 answers 204 for a successful delete and, for a missing key,
        # still 204 — deletion is idempotent by design.
        if not r.ok() and r.status != 404:
            raise Error(
                "s3: DELETE "
                + bucket
                + "/"
                + key
                + ": HTTP "
                + String(r.status)
                + " "
                + s3_error_message(r)
            )

    def list_objects_v2(
        self,
        bucket: String,
        prefix: String = "",
        delimiter: String = "",
        max_keys: Int = 0,
        continuation_token: String = "",
    ) raises -> ListResult:
        """One page of `ListObjectsV2`. See `list_all` for every page."""
        var params = List[QueryParam]()
        params.append(QueryParam("list-type", "2"))
        if prefix != "":
            params.append(QueryParam("prefix", prefix))
        if delimiter != "":
            params.append(QueryParam("delimiter", delimiter))
        if max_keys > 0:
            params.append(QueryParam("max-keys", String(max_keys)))
        if continuation_token != "":
            params.append(
                QueryParam("continuation-token", continuation_token)
            )
        var r = self.request("GET", bucket, "", params)
        if not r.ok():
            raise Error(
                "s3: LIST "
                + bucket
                + ": HTTP "
                + String(r.status)
                + " "
                + s3_error_message(r)
            )
        return parse_list_objects(r.text())

    def list_all(
        self, bucket: String, prefix: String = "", delimiter: String = ""
    ) raises -> ListResult:
        """Every page, concatenated. Bounded at 10 000 requests so a server
        that keeps handing back the same token cannot spin forever."""
        var out = ListResult()
        var token = String("")
        var pages = 0
        while True:
            var page = self.list_objects_v2(
                bucket, prefix, delimiter, 0, token
            )
            for k in range(len(page.objects)):
                out.objects.append(page.objects[k].copy())
            for k in range(len(page.common_prefixes)):
                out.common_prefixes.append(page.common_prefixes[k])
            if not page.is_truncated or page.next_continuation_token == "":
                break
            token = page.next_continuation_token
            pages += 1
            if pages > 10000:
                raise Error("s3: list pagination did not terminate")
        return out^

    # ── presigning ─────────────────────────────────────────────────────────
    def presign_get(
        self, bucket: String, key: String, expires_seconds: Int = 3600
    ) raises -> String:
        """A URL that grants `GET` on one object for `expires_seconds`.

        Everything travels in the query string, so the holder needs no
        credentials — which is the whole point, and why `HttpClient` keeps
        redirects off: re-issuing a signed URL elsewhere would leak it.
        """
        var addr = self.url_for(bucket, key)
        var headers = List[Header]()
        headers.append(Header("Host", addr[1]))
        var query = presign_query(
            "GET",
            addr[2],
            List[QueryParam](),
            headers,
            self.config.credentials.access_key_id,
            self.config.credentials.secret_access_key,
            self.config.credentials.session_token,
            self.config.region,
            SERVICE,
            AmzTime.now(),
            expires_seconds,
            normalize=False,
        )
        return addr[0] + "?" + query


def _host_header(scheme: String, host: String) -> String:
    """The `Host` value curl will actually send — default ports omitted.

    SigV4 signs the host, so getting this wrong produces a
    `SignatureDoesNotMatch` that looks like a credential problem.
    """
    if scheme == "https" and host.endswith(":443"):
        return _substr(host, 0, host.byte_length() - 4)
    if scheme == "http" and host.endswith(":80"):
        return _substr(host, 0, host.byte_length() - 3)
    return host


def _query_string(params: List[QueryParam]) -> String:
    var out = String("")
    for k in range(len(params)):
        if k > 0:
            out += "&"
        out += url_encode(params[k].name, encode_slash=True)
        out += "="
        out += url_encode(params[k].value, encode_slash=True)
    return out^


def split_s3_uri(location: String) raises -> Tuple[String, String]:
    """`s3://bucket/a/b` -> `("bucket", "a/b")`.

    `s3a://` and `s3n://` (the Hadoop schemes, still common in older Iceberg
    metadata) address the same objects and are accepted here.
    """
    var u = parse_uri(location)
    if u.scheme != "s3" and u.scheme != "s3a" and u.scheme != "s3n":
        raise Error("s3: not an S3 location: " + location)
    if u.bucket == "":
        raise Error("s3: no bucket in " + location)
    return Tuple(u.bucket, u.key)
