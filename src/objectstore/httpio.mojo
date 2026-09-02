"""`objectstore.httpio` — a read-only `InputFile` over `http(s)://`.

Two things make this worth having beyond "download the file". A `HEAD` gives
the length without a body, and a `Range` request gives an arbitrary slice — so
a Parquet file published over plain HTTP is as lazily readable as one in S3.
And a **presigned S3 URL** is, at the point of use, just an HTTPS URL with a
signature in the query string: this is the backend that reads it, with no
credentials involved.

Servers are allowed to ignore `Range` and answer `200` with the whole body.
That is handled rather than trusted: a `200` where a `206` was expected is
sliced locally, so the caller always gets the bytes it asked for.
"""

from .http import Header, HttpClient, Response
from .ranges import ByteRange, RangeReader, read_ranges_coalesced


@fieldwise_init
struct HttpInputFile(Copyable, Movable, RangeReader):
    var url: String
    var client: HttpClient
    var headers: List[Header]
    """Sent with every request. This is what makes the module reusable for
    GCS (`Authorization: Bearer …`) and Azure (`x-ms-version`) — both reduce
    to an HTTPS URL plus a fixed set of headers."""

    def __init__(out self, var url: String):
        self.url = url^
        self.client = HttpClient()
        self.headers = []

    def __init__(out self, var url: String, var client: HttpClient):
        self.url = url^
        self.client = client^
        self.headers = []

    def _with(self, var extra: List[Header]) -> List[Header]:
        var out = List[Header]()
        for k in range(len(self.headers)):
            out.append(self.headers[k].copy())
        for k in range(len(extra)):
            out.append(extra[k].copy())
        return out^

    def location(self) -> String:
        return self.url

    def exists(self) raises -> Bool:
        var r = self.client.head(self.url, self.headers.copy())
        if r.ok():
            return True
        if r.status == 404 or r.status == 403 or r.status == 410:
            return False
        # A server that refuses HEAD (405) still says something useful about
        # a one-byte GET.
        var g = self.client.get(self.url, self.headers.copy(), 0, 0)
        return g.ok()

    def length(self) raises -> Int:
        var r = self.client.head(self.url, self.headers.copy())
        if not r.ok():
            raise Error(
                "objectstore.httpio: HEAD "
                + self.url
                + ": HTTP "
                + String(r.status)
            )
        var cl = r.header("Content-Length")
        if cl == "":
            raise Error("objectstore.httpio: no Content-Length for " + self.url)
        return Int(cl)

    def read_all(self) raises -> List[UInt8]:
        var r = self.client.get(self.url, self.headers.copy())
        r.raise_for_status("objectstore.httpio: GET " + self.url)
        return r.body.copy()

    def read_range(self, offset: Int, length: Int) raises -> List[UInt8]:
        """`length` bytes from `offset`. A negative `offset` is a suffix range
        (`bytes=-N`), the way HTTP itself spells "the last N bytes"."""
        if length <= 0:
            return List[UInt8]()
        var r: Response
        if offset < 0:
            # RFC 9110 suffix-range: `Range: bytes=-N`. The shim spells an
            # open-ended range as `start-`, so this one is sent verbatim.
            var headers = List[Header]()
            headers.append(Header("Range", "bytes=-" + String(length)))
            r = self.client.get(self.url, self._with(headers^))
        else:
            r = self.client.get(
                self.url, self.headers.copy(), offset, offset + length - 1
            )
        r.raise_for_status("objectstore.httpio: GET " + self.url)
        if r.status == 206:
            return r.body.copy()
        # 200: the server ignored the Range and sent everything. Slice it.
        var start = offset
        if start < 0:
            start = len(r.body) + start
            if start < 0:
                start = 0
        var end = start + length
        if end > len(r.body):
            end = len(r.body)
        if start >= end:
            return List[UInt8]()
        var out = List[UInt8](capacity=end - start)
        out.extend(Span(r.body)[start:end])
        return out^

    def read_ranges(self, ranges: List[ByteRange]) raises -> List[List[UInt8]]:
        """One request per *group* of nearby ranges rather than one per range.

        Connection reuse made a request cheap; this makes it rare. A Parquet
        row group whose column chunks are laid out consecutively becomes a
        single `Range` request, and the bytes of the columns the scan skipped
        are read and thrown away — which is cheaper than the round trip that
        would have avoided them.
        """
        return read_ranges_coalesced(self, ranges)


@fieldwise_init
struct HttpOutputFile(Copyable, Movable):
    """A write-only file behind a single `PUT`.

    Only usable where a plain `PUT` to a URL means "store this object" — a
    presigned S3 upload URL, GCS's XML endpoint with a bearer token, an Azure
    blob URL with a SAS token. It is not a general HTTP writer, because HTTP
    itself has no create-versus-overwrite distinction: `create` is implemented
    as "check, then write", which is racy and says so.
    """

    var url: String
    var client: HttpClient
    var headers: List[Header]

    def __init__(out self, var url: String, var headers: List[Header]):
        self.url = url^
        self.client = HttpClient()
        self.headers = headers^

    def location(self) -> String:
        return self.url

    def exists(self) raises -> Bool:
        return HttpInputFile(
            self.url, self.client.copy(), self.headers.copy()
        ).exists()

    def create(self, data: Span[UInt8, _]) raises:
        if self.exists():
            raise Error("objectstore.httpio: " + self.url + " already exists")
        self.overwrite(data)

    def overwrite(self, data: Span[UInt8, _]) raises:
        var r = self.client.put(self.url, data, self.headers.copy())
        r.raise_for_status("objectstore.httpio: PUT " + self.url)


def http_delete(url: String, headers: List[Header], client: HttpClient) raises:
    var r = client.delete(url, headers.copy())
    if not r.ok() and r.status != 404:
        r.raise_for_status("objectstore.httpio: DELETE " + url)
