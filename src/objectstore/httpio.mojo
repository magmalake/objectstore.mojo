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


@fieldwise_init
struct HttpInputFile(Copyable, Movable):
    var url: String
    var client: HttpClient

    def __init__(out self, var url: String):
        self.url = url^
        self.client = HttpClient()

    def location(self) -> String:
        return self.url

    def exists(self) raises -> Bool:
        var r = self.client.head(self.url)
        if r.ok():
            return True
        if r.status == 404 or r.status == 403 or r.status == 410:
            return False
        # A server that refuses HEAD (405) still says something useful about
        # a one-byte GET.
        var g = self.client.get(self.url, List[Header](), 0, 0)
        return g.ok()

    def length(self) raises -> Int:
        var r = self.client.head(self.url)
        if not r.ok():
            raise Error(
                "objectstore.httpio: HEAD "
                + self.url
                + ": HTTP "
                + String(r.status)
            )
        var cl = r.header("Content-Length")
        if cl == "":
            raise Error(
                "objectstore.httpio: no Content-Length for " + self.url
            )
        return Int(cl)

    def read_all(self) raises -> List[UInt8]:
        var r = self.client.get(self.url)
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
            r = self.client.get(self.url, headers)
        else:
            r = self.client.get(
                self.url, List[Header](), offset, offset + length - 1
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
