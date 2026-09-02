"""`objectstore.azure` — Azure Blob Storage through SAS-token URLs.

Azure's own signing schemes are `SharedKey` (an HMAC-SHA256 over a canonical
form that is close to but not the same as SigV4) and Entra ID bearer tokens.
Neither is implemented. What is implemented is the **SAS token**: a query
string that already carries a signature someone else produced, which is what
Iceberg's `adls.sas-token.<account>` property holds and what a catalog vends.
With a SAS token, a blob is an HTTPS URL, and the whole backend is URL
construction plus two required headers.

Iceberg addresses ADLS Gen2 as `abfss://container@account.dfs.core.windows.net/path`.
The Blob endpoint (`account.blob.core.windows.net`) serves the same data with
the simpler API, so that is what this targets; `wasbs://` names the Blob
endpoint directly and is accepted as well.
"""

from std.collections import Dict

from .http import Header, HttpClient
from .httpio import HttpInputFile, HttpOutputFile, http_delete
from .path import parse_uri, url_encode
from .s3 import xml_blocks, xml_text


comptime BLOB_API_VERSION = String("2021-12-02")
"""Sent as `x-ms-version`. Azure requires it on every request, and older
services reject versions they do not know — this one is old enough to be
universally supported and new enough for everything used here."""


@fieldwise_init
struct AzureLocation(Copyable, Movable):
    """A parsed `abfs(s)://` or `wasb(s)://` location."""

    var account: String
    var container: String
    var path: String


def parse_azure_uri(location: String) raises -> AzureLocation:
    """`abfss://container@account.dfs.core.windows.net/a/b` ->
    account `account`, container `container`, path `a/b`.

    `wasbs://container@account.blob.core.windows.net/a/b` parses the same way.
    A bare `az://container/path` is accepted with the account left empty, for
    callers that configure the endpoint explicitly.
    """
    var u = parse_uri(location)
    if not (
        u.scheme == "abfs"
        or u.scheme == "abfss"
        or u.scheme == "wasb"
        or u.scheme == "wasbs"
        or u.scheme == "az"
    ):
        raise Error("azure: not an Azure location: " + location)

    var authority = u.bucket
    var at = authority.find("@")
    var container = authority
    var host = String("")
    if at >= 0:
        var b = authority.as_bytes()
        container = String(StringSlice(unsafe_from_utf8=Span(b)[0:at]))
        host = String(StringSlice(unsafe_from_utf8=Span(b)[at + 1 : len(b)]))
    var account = String("")
    if host != "":
        var dot = host.find(".")
        if dot > 0:
            var hb = host.as_bytes()
            account = String(StringSlice(unsafe_from_utf8=Span(hb)[0:dot]))
        else:
            account = host
    return AzureLocation(account^, container^, u.key)


struct AzureConfig(Copyable, Movable):
    var account: String
    var sas_token: String
    """The query string of a SAS URL, with or without its leading `?`."""
    var endpoint: String
    """Overrides the derived `https://<account>.blob.core.windows.net`, for
    Azurite or a sovereign cloud."""

    def __init__(out self):
        self.account = ""
        self.sas_token = ""
        self.endpoint = ""

    def __init__(
        out self,
        var account: String,
        var sas_token: String,
        var endpoint: String,
    ):
        self.account = account^
        self.sas_token = sas_token^
        self.endpoint = endpoint^

    @staticmethod
    def from_properties(
        props: Dict[String, String], account: String = ""
    ) raises -> Self:
        """Reads Iceberg's `adls.sas-token.<account>` (and a plain
        `adls.sas-token` / `azure.sas-token` fallback)."""
        var c = Self()
        c.account = account
        var keyed = String("adls.sas-token.") + account
        if account != "" and keyed in props:
            c.sas_token = props[keyed]
        elif "adls.sas-token" in props:
            c.sas_token = props["adls.sas-token"]
        elif "azure.sas-token" in props:
            c.sas_token = props["azure.sas-token"]
        if "adls.endpoint" in props:
            c.endpoint = props["adls.endpoint"]
        elif "azure.endpoint" in props:
            c.endpoint = props["azure.endpoint"]
        return c^

    def base_url(self) raises -> String:
        if self.endpoint != "":
            var e = self.endpoint
            while e.endswith("/"):
                var b = e.as_bytes()
                var trimmed = String(
                    StringSlice(unsafe_from_utf8=Span(b)[0 : len(b) - 1])
                )
                e = trimmed^
            return e^
        if self.account == "":
            raise Error("azure: no account and no endpoint configured")
        return String("https://") + self.account + ".blob.core.windows.net"

    def _query(self) -> String:
        if self.sas_token == "":
            return String("")
        if self.sas_token.startswith("?"):
            return self.sas_token
        return String("?") + self.sas_token

    def url_for(self, container: String, blob: String) raises -> String:
        var out = self.base_url() + "/" + container
        if blob != "":
            out += "/" + url_encode(blob, encode_slash=False)
        return out + self._query()

    def list_url(
        self, container: String, prefix: String, marker: String
    ) raises -> String:
        var out = self.base_url() + "/" + container
        var q = self._query()
        if q == "":
            out += "?"
        else:
            out += q + "&"
        out += "restype=container&comp=list"
        if prefix != "":
            out += "&prefix=" + url_encode(prefix, encode_slash=True)
        if marker != "":
            out += "&marker=" + url_encode(marker, encode_slash=True)
        return out^

    def headers(self) -> List[Header]:
        var out = List[Header]()
        out.append(Header("x-ms-version", BLOB_API_VERSION))
        return out^

    def write_headers(self) -> List[Header]:
        var out = self.headers()
        # Every Azure PUT must say what kind of blob it is creating.
        out.append(Header("x-ms-blob-type", "BlockBlob"))
        return out^


@fieldwise_init
struct BlobInfo(Copyable, Movable):
    var name: String
    var size: Int


struct AzureClient(Copyable, Movable):
    var config: AzureConfig
    var http: HttpClient

    def __init__(out self, var config: AzureConfig):
        self.config = config^
        self.http = HttpClient()

    def __init__(out self, var config: AzureConfig, var http: HttpClient):
        self.config = config^
        self.http = http^

    def input(self, container: String, blob: String) raises -> HttpInputFile:
        return HttpInputFile(
            self.config.url_for(container, blob),
            self.http.copy(),
            self.config.headers(),
        )

    def output(self, container: String, blob: String) raises -> HttpOutputFile:
        return HttpOutputFile(
            self.config.url_for(container, blob),
            self.http.copy(),
            self.config.write_headers(),
        )

    def delete_blob(self, container: String, blob: String) raises:
        http_delete(
            self.config.url_for(container, blob),
            self.config.headers(),
            self.http.copy(),
        )

    def list_blobs(
        self, container: String, prefix: String = ""
    ) raises -> List[BlobInfo]:
        """Every blob under `prefix`, following `NextMarker` pages.

        The response is `<EnumerationResults><Blobs><Blob><Name>…`, which the
        same shallow XML reader handles as S3's `ListBucketResult`.
        """
        var out = List[BlobInfo]()
        var marker = String("")
        var pages = 0
        while True:
            var url = self.config.list_url(container, prefix, marker)
            var r = self.http.get(url, self.config.headers())
            r.raise_for_status("azure: LIST " + container)
            var body = r.text()
            var blobs = xml_blocks(body, String("Blob"))
            for k in range(len(blobs)):
                var size_text = xml_text(blobs[k], String("Content-Length"))
                var size = 0
                if size_text != "":
                    size = Int(size_text)
                out.append(BlobInfo(xml_text(blobs[k], String("Name")), size))
            marker = xml_text(body, String("NextMarker"))
            if marker == "":
                break
            pages += 1
            if pages > 10000:
                raise Error("azure: list pagination did not terminate")
        return out^
