"""`objectstore.path` — URI parsing and location handling.

Iceberg stores **absolute** locations everywhere: a table's `location`, a
snapshot's `manifest-list`, a manifest entry's `file_path`. Those strings are
the only addressing this stack has, so parsing them precisely — and rewriting
them when a warehouse is copied somewhere else — is a first-class concern
rather than string fiddling scattered across call sites.

Grammar handled here:

    s3://bucket/key/parts        object stores (s3, s3a, s3n, gs, gcs, abfs*, wasb*)
    https://host/path?query      HTTP(S), including presigned URLs
    file:///abs/path             a local file, RFC 8089 style
    file://host/abs/path         tolerated; the host is ignored
    /abs/path or rel/path        a bare filesystem path, scheme `file`
"""


comptime SCHEME_FILE = String("file")
comptime SCHEME_S3 = String("s3")
comptime SCHEME_HTTP = String("http")
comptime SCHEME_HTTPS = String("https")
comptime SCHEME_GS = String("gs")
comptime SCHEME_ABFS = String("abfs")


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


struct Uri(Copyable, Movable, Writable):
    """A parsed location.

    `bucket` is the authority: an S3/GCS bucket, an Azure container's account
    host, or an HTTP host[:port]. `key` is everything after it with no leading
    slash — which is exactly what an S3 request needs, and exactly what a
    filesystem path needs once the leading slash is put back for `file`.
    """

    var scheme: String
    var bucket: String
    var key: String
    var query: String
    var raw: String

    def __init__(
        out self,
        var scheme: String,
        var bucket: String,
        var key: String,
        var query: String,
        var raw: String,
    ):
        self.scheme = scheme^
        self.bucket = bucket^
        self.key = key^
        self.query = query^
        self.raw = raw^

    def is_local(self) -> Bool:
        return self.scheme == SCHEME_FILE

    def is_object_store(self) -> Bool:
        return not (
            self.scheme == SCHEME_FILE
            or self.scheme == SCHEME_HTTP
            or self.scheme == SCHEME_HTTPS
        )

    def local_path(self) -> String:
        """The filesystem path for a `file:` URI.

        `file:///a/b` and `/a/b` both give `/a/b`; a relative bare path is
        returned unchanged so `tests/fixtures/x` keeps working.
        """
        if (
            self.bucket == ""
            and self.key != ""
            and not self.raw.startswith("/")
        ):
            if not self.raw.startswith(SCHEME_FILE + "://"):
                return self.key
        return String("/") + self.key

    def canonical(self) -> String:
        """The location rebuilt from its parts — round-trips `parse_uri`."""
        if self.scheme == SCHEME_FILE:
            return SCHEME_FILE + "://" + self.bucket + "/" + self.key
        var out = self.scheme + "://" + self.bucket
        if self.key != "":
            out += "/" + self.key
        if self.query != "":
            out += "?" + self.query
        return out^

    def write_to(self, mut writer: Some[Writer]):
        writer.write(self.canonical())


def parse_uri(location: String) raises -> Uri:
    var sep = location.find("://")
    if sep < 0:
        # A bare path. Anything with a colon but no `://` (a Windows drive, a
        # stray `mailto:`) is still treated as a path: this stack only ever
        # sees Iceberg locations and POSIX paths.
        var key = location
        if key.startswith("/"):
            key = _substr(location, 1, location.byte_length())
        return Uri(SCHEME_FILE, String(""), key^, String(""), location)

    var scheme = _ascii_lower(_substr(location, 0, sep))
    var rest = _substr(location, sep + 3, location.byte_length())
    var query = String("")
    var q = rest.find("?")
    if q >= 0:
        query = _substr(rest, q + 1, rest.byte_length())
        rest = _substr(rest, 0, q)

    var slash = rest.find("/")
    var bucket = rest
    var key = String("")
    if slash >= 0:
        bucket = _substr(rest, 0, slash)
        key = _substr(rest, slash + 1, rest.byte_length())

    if scheme == SCHEME_FILE:
        # RFC 8089 gives `file:///abs`, i.e. an empty authority. Some writers
        # emit `file://host/abs`; the host is not addressable here, so drop it
        # and keep the path.
        return Uri(SCHEME_FILE, String(""), key^, query^, location)

    return Uri(scheme^, bucket^, key^, query^, location)


def _ascii_lower(s: String) -> String:
    var out = List[UInt8]()
    var b = s.as_bytes()
    for k in range(len(b)):
        var c = b[k]
        if c >= 65 and c <= 90:
            c += 32
        out.append(c)
    return String(StringSlice(unsafe_from_utf8=Span(out)))


# ---------------------------------------------------------------------------
# Path algebra
# ---------------------------------------------------------------------------


def join(base: String, child: String) -> String:
    """Joins a location with a relative child. An absolute `child` wins."""
    if child.startswith("/") or child.find("://") >= 0:
        return child
    if base == "":
        return child
    if base.endswith("/"):
        return base + child
    return base + "/" + child


def basename(location: String) -> String:
    var stripped = _strip_query(location)
    var i = stripped.rfind("/")
    if i < 0:
        return stripped
    return _substr(stripped, i + 1, stripped.byte_length())


def parent(location: String) -> String:
    """The containing directory/prefix, with no trailing slash.

    `s3://b/a/b/c` -> `s3://b/a/b`; `s3://b/c` -> `s3://b`; a bare name with
    no slash has no parent and yields `""`.
    """
    var stripped = _strip_query(location)
    var sep = stripped.find("://")
    var start = 0
    if sep >= 0:
        start = sep + 3
        var s2 = stripped.find("/", start)
        if s2 < 0:
            return stripped
    var i = stripped.rfind("/")
    if i < 0:
        return String("")
    if sep >= 0 and i < start:
        return stripped
    if i == 0:
        return String("/")
    return _substr(stripped, 0, i)


def _strip_query(location: String) -> String:
    var q = location.find("?")
    if q < 0:
        return location
    return _substr(location, 0, q)


def strip_scheme(location: String) -> String:
    """`file:///a/b` -> `/a/b`; other schemes are returned unchanged.

    Kept byte-compatible with `iceberg.io.strip_scheme` so iceberg.mojo can
    swap its copy for this one.
    """
    if location.startswith("file://"):
        var rest = _substr(location, 7, location.byte_length())
        if rest.startswith("/"):
            return rest
        # `file://host/path` — drop the host, keep an absolute path.
        var slash = rest.find("/")
        if slash < 0:
            return String("/")
        return _substr(rest, slash, rest.byte_length())
    return location


comptime _HEXUP = String("0123456789ABCDEF")


def url_encode(s: String, encode_slash: Bool = True) -> String:
    """RFC 3986 percent-encoding of everything outside the unreserved set.

    SigV4 needs both variants: path segments keep `/` literal, query keys and
    values do not (SigV4 §canonical query string).
    """
    var out = String("")
    var b = s.as_bytes()
    for k in range(len(b)):
        var c = b[k]
        var unreserved = (
            (c >= 48 and c <= 57)
            or (c >= 65 and c <= 90)
            or (c >= 97 and c <= 122)
            or c == 45
            or c == 46
            or c == 95
            or c == 126
        )
        if unreserved or (c == 47 and not encode_slash):
            out += String(StringSlice(unsafe_from_utf8=Span(b)[k : k + 1]))
        else:
            out += "%"
            out += String(_HEXUP[byte=Int(c >> 4)])
            out += String(_HEXUP[byte=Int(c & 0xF)])
    return out^
