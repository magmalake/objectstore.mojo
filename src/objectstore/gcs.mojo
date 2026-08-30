"""`objectstore.gcs` — Google Cloud Storage over the S3-compatible XML endpoint.

GCS exposes two APIs. The JSON API (`storage.googleapis.com/storage/v1/…`)
returns JSON, which would mean carrying a JSON parser here purely to read an
object listing. The **XML API** (`storage.googleapis.com/<bucket>/<key>`) is
byte-for-byte the S3 protocol for everything this tin does — `GET` with
`Range`, `PUT`, `DELETE`, and a `ListBucketResult` document the S3 parser in
`s3.mojo` already reads. So this module uses the XML endpoint, and is
correspondingly small.

**Authentication is an OAuth2 bearer token supplied by the caller.** Minting
one from a service-account key requires RS256 JWT signing, and RSA is out of
scope — it is a great deal more code than SHA-256 was, for something
`gcloud auth print-access-token`, a metadata server, or the surrounding
application already has. Pass the token in as `gcs.oauth2.token`, which is
Iceberg's own property name for exactly this.

GCS also accepts SigV4 with HMAC "interoperability" keys; a caller who has
those can point `S3Client` at `https://storage.googleapis.com` instead.
"""

from std.collections import Dict

from .http import Header, HttpClient
from .httpio import HttpInputFile, HttpOutputFile, http_delete
from .path import parse_uri, url_encode
from .s3 import ListResult, parse_list_objects, s3_error_message


comptime DEFAULT_GCS_ENDPOINT = String("https://storage.googleapis.com")


struct GcsConfig(Copyable, Movable):
    var endpoint: String
    var oauth_token: String

    def __init__(out self):
        self.endpoint = DEFAULT_GCS_ENDPOINT
        self.oauth_token = ""

    def __init__(out self, var endpoint: String, var oauth_token: String):
        self.endpoint = endpoint^
        self.oauth_token = oauth_token^

    @staticmethod
    def from_properties(props: Dict[String, String]) raises -> Self:
        """Iceberg's GCS property names: `gcs.oauth2.token` and
        `gcs.service.host`."""
        var c = Self()
        if "gcs.oauth2.token" in props:
            c.oauth_token = props["gcs.oauth2.token"]
        if "gcs.service.host" in props:
            c.endpoint = props["gcs.service.host"]
        elif "gcs.endpoint" in props:
            c.endpoint = props["gcs.endpoint"]
        return c^

    def headers(self) -> List[Header]:
        var out = List[Header]()
        if self.oauth_token != "":
            out.append(Header("Authorization", "Bearer " + self.oauth_token))
        return out^

    def url_for(self, bucket: String, key: String) -> String:
        var out = self.endpoint + "/" + bucket
        if key != "":
            out += "/" + url_encode(key, encode_slash=False)
        return out^


struct GcsClient(Copyable, Movable):
    var config: GcsConfig
    var http: HttpClient

    def __init__(out self, var config: GcsConfig):
        self.config = config^
        self.http = HttpClient()

    def __init__(out self, var config: GcsConfig, var http: HttpClient):
        self.config = config^
        self.http = http^

    def input(self, bucket: String, key: String) -> HttpInputFile:
        return HttpInputFile(
            self.config.url_for(bucket, key),
            self.http.copy(),
            self.config.headers(),
        )

    def output(self, bucket: String, key: String) -> HttpOutputFile:
        return HttpOutputFile(
            self.config.url_for(bucket, key),
            self.http.copy(),
            self.config.headers(),
        )

    def delete_object(self, bucket: String, key: String) raises:
        http_delete(
            self.config.url_for(bucket, key),
            self.config.headers(),
            self.http.copy(),
        )

    def list_objects(
        self,
        bucket: String,
        prefix: String = "",
        delimiter: String = "",
        continuation_token: String = "",
    ) raises -> ListResult:
        """One page of the XML API's `ListBucketResult`.

        GCS implements S3's `list-type=2` continuation tokens, so the response
        parses with `s3.parse_list_objects` unchanged.
        """
        var url = self.config.url_for(bucket, String("")) + "?list-type=2"
        if prefix != "":
            url += "&prefix=" + url_encode(prefix, encode_slash=True)
        if delimiter != "":
            url += "&delimiter=" + url_encode(delimiter, encode_slash=True)
        if continuation_token != "":
            url += "&continuation-token=" + url_encode(
                continuation_token, encode_slash=True
            )
        var r = self.http.get(url, self.config.headers())
        if not r.ok():
            raise Error(
                "gcs: LIST "
                + bucket
                + ": HTTP "
                + String(r.status)
                + " "
                + s3_error_message(r)
            )
        return parse_list_objects(r.text())

    def list_all(
        self, bucket: String, prefix: String = ""
    ) raises -> ListResult:
        var out = ListResult()
        var token = String("")
        var pages = 0
        while True:
            var page = self.list_objects(bucket, prefix, String(""), token)
            for k in range(len(page.objects)):
                out.objects.append(page.objects[k].copy())
            for k in range(len(page.common_prefixes)):
                out.common_prefixes.append(page.common_prefixes[k])
            if not page.is_truncated or page.next_continuation_token == "":
                break
            token = page.next_continuation_token
            pages += 1
            if pages > 10000:
                raise Error("gcs: list pagination did not terminate")
        return out^


def split_gcs_uri(location: String) raises -> Tuple[String, String]:
    """`gs://bucket/a/b` -> `("bucket", "a/b")`. `gcs://` is accepted too."""
    var u = parse_uri(location)
    if u.scheme != "gs" and u.scheme != "gcs":
        raise Error("gcs: not a GCS location: " + location)
    if u.bucket == "":
        raise Error("gcs: no bucket in " + location)
    return Tuple(u.bucket, u.key)
