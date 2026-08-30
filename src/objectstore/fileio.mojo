"""`objectstore.fileio` — the `InputFile` / `OutputFile` / `FileIO` traits and
the scheme resolver.

This is the seam iceberg.mojo already anticipates. Its `src/iceberg/io.mojo`
declares an `InputFile` trait with `location()`, `exists()` and `read_all()`,
and a local-only `FileIO`; the traits here are a **superset** of that, so an
`objectstore` input file satisfies the Iceberg trait unchanged, while adding
the two things a lazy Parquet reader needs: `length()` and
`read_range(offset, length)`.

`FileIOResolver` is the dynamic half. Mojo dispatches traits statically, so a
"pick a backend by URI scheme" API cannot return an arbitrary trait
implementation; `AnyInputFile` and `AnyOutputFile` are small tagged unions over
the three backends, and they conform to the traits themselves. Generic code can
keep using the traits; code that resolves locations at runtime uses the
resolver.

Per-scheme configuration follows Iceberg's property names (`s3.endpoint`,
`s3.access-key-id`, …) so a `LoadTableResult`'s `config` map can be handed
straight over, and `storage-credentials` — the REST spec's list of
`{prefix, config}` entries — is matched **longest prefix first**, exactly as
the spec requires when a catalog vends different credentials for different
paths within one table.
"""

from std.collections import Dict

from .azure import AzureClient, AzureConfig, parse_azure_uri
from .gcs import GcsClient, GcsConfig, split_gcs_uri
from .http import Header, HttpClient
from .httpio import HttpInputFile, HttpOutputFile, http_delete
from .local import LocalInputFile, LocalOutputFile, local_delete, local_list
from .path import Uri, parse_uri
from .ranges import (
    ByteRange,
    DEFAULT_COALESCE_GAP,
    RangeReader,
    read_ranges_coalesced,
)
from .s3 import S3Client, S3Config, split_s3_uri


# ---------------------------------------------------------------------------
# Traits
# ---------------------------------------------------------------------------


trait InputFile(Copyable, Movable):
    """A readable byte source addressed by a location.

    `location`, `exists` and `read_all` are byte-compatible with
    `iceberg.io.InputFile`; `length` and `read_range` are the additions that
    let a reader fetch a Parquet footer without pulling the whole file.
    """

    def location(self) -> String:
        ...

    def exists(self) raises -> Bool:
        ...

    def length(self) raises -> Int:
        ...

    def read_all(self) raises -> List[UInt8]:
        ...

    def read_range(self, offset: Int, length: Int) raises -> List[UInt8]:
        ...

    def read_ranges(
        self, ranges: List[ByteRange]
    ) raises -> List[List[UInt8]]:
        """Several ranges at once, in the order asked for.

        The default is one `read_range` per range, which is exactly right for
        a file the process can seek. Backends where a range costs a round trip
        override it to coalesce (see `objectstore.ranges`), which is what
        turns a Parquet scan's per-column-chunk reads into a handful of
        requests.
        """
        var out = List[List[UInt8]]()
        for k in range(len(ranges)):
            out.append(self.read_range(ranges[k].offset, ranges[k].length))
        return out^


trait OutputFile(Copyable, Movable):
    """A writable destination.

    `create` fails if the location already exists; `overwrite` does not. That
    is Iceberg's own distinction — metadata files are written with `create` so
    that two writers racing on the same version number cannot both believe
    they won.
    """

    def location(self) -> String:
        ...

    def exists(self) raises -> Bool:
        ...

    def create(self, data: Span[UInt8, _]) raises:
        ...

    def overwrite(self, data: Span[UInt8, _]) raises:
        ...


trait FileIO(Copyable, Movable):
    """A namespace of locations: open, delete, list."""

    comptime InputType: InputFile
    comptime OutputType: OutputFile

    def new_input(self, location: String) raises -> Self.InputType:
        ...

    def new_output(self, location: String) raises -> Self.OutputType:
        ...

    def delete(self, location: String) raises:
        ...

    def list(self, prefix: String) raises -> List[String]:
        ...


# ---------------------------------------------------------------------------
# Backend tags
# ---------------------------------------------------------------------------

comptime BACKEND_LOCAL = 0
comptime BACKEND_HTTP = 1
comptime BACKEND_S3 = 2
comptime BACKEND_GCS = 3
comptime BACKEND_AZURE = 4
"""GCS and Azure reduce to `BACKEND_HTTP` once a location has been turned into
a URL plus headers — a bearer token for GCS, a SAS query string and
`x-ms-version` for Azure — so only the resolver distinguishes them. The
open files themselves are `HttpInputFile`/`HttpOutputFile`."""


struct AnyInputFile(InputFile, RangeReader, Copyable, Movable):
    """An `InputFile` whose backend is chosen at runtime by URI scheme."""

    var backend: Int
    var uri: String
    var _local: LocalInputFile
    var _http: HttpInputFile
    var _s3: S3Client
    var _bucket: String
    var _key: String

    def __init__(
        out self,
        backend: Int,
        var uri: String,
        var local: LocalInputFile,
        var http: HttpInputFile,
        var s3: S3Client,
        var bucket: String,
        var key: String,
    ):
        self.backend = backend
        self.uri = uri^
        self._local = local^
        self._http = http^
        self._s3 = s3^
        self._bucket = bucket^
        self._key = key^

    def location(self) -> String:
        return self.uri

    def exists(self) raises -> Bool:
        if self.backend == BACKEND_LOCAL:
            return self._local.exists()
        if self.backend == BACKEND_HTTP:
            return self._http.exists()
        return self._s3.object_exists(self._bucket, self._key)

    def length(self) raises -> Int:
        if self.backend == BACKEND_LOCAL:
            return self._local.length()
        if self.backend == BACKEND_HTTP:
            return self._http.length()
        return self._s3.object_length(self._bucket, self._key)

    def read_all(self) raises -> List[UInt8]:
        if self.backend == BACKEND_LOCAL:
            return self._local.read_all()
        if self.backend == BACKEND_HTTP:
            return self._http.read_all()
        return self._s3.get_object(self._bucket, self._key)

    def read_range(self, offset: Int, length: Int) raises -> List[UInt8]:
        if self.backend == BACKEND_LOCAL:
            return self._local.read_range(offset, length)
        if self.backend == BACKEND_HTTP:
            return self._http.read_range(offset, length)
        if length <= 0:
            return List[UInt8]()
        return self._s3.get_object(
            self._bucket, self._key, offset, offset + length - 1
        )

    def read_ranges(
        self, ranges: List[ByteRange]
    ) raises -> List[List[UInt8]]:
        """Coalesced for HTTP and S3, one seek per range for local files."""
        if self.backend == BACKEND_LOCAL:
            var out = List[List[UInt8]]()
            for k in range(len(ranges)):
                out.append(
                    self._local.read_range(ranges[k].offset, ranges[k].length)
                )
            return out^
        return read_ranges_coalesced(self, ranges)


struct AnyOutputFile(OutputFile, Copyable, Movable):
    """An `OutputFile` whose backend is chosen at runtime by URI scheme.

    The HTTP backend covers three cases that all reduce to a single `PUT`: a
    presigned S3 upload URL, GCS's XML endpoint with a bearer token, and an
    Azure blob with a SAS token. `create` there is "check, then write", which
    is racy — HTTP has no atomic create.
    """

    var backend: Int
    var uri: String
    var _local: LocalOutputFile
    var _http: HttpOutputFile
    var _s3: S3Client
    var _bucket: String
    var _key: String

    def __init__(
        out self,
        backend: Int,
        var uri: String,
        var local: LocalOutputFile,
        var http: HttpOutputFile,
        var s3: S3Client,
        var bucket: String,
        var key: String,
    ):
        self.backend = backend
        self.uri = uri^
        self._local = local^
        self._http = http^
        self._s3 = s3^
        self._bucket = bucket^
        self._key = key^

    def location(self) -> String:
        return self.uri

    def exists(self) raises -> Bool:
        if self.backend == BACKEND_LOCAL:
            return self._local.exists()
        if self.backend == BACKEND_S3:
            return self._s3.object_exists(self._bucket, self._key)
        return self._http.exists()

    def create(self, data: Span[UInt8, _]) raises:
        if self.exists():
            raise Error("objectstore: " + self.uri + " already exists")
        self.overwrite(data)

    def overwrite(self, data: Span[UInt8, _]) raises:
        if self.backend == BACKEND_LOCAL:
            self._local.overwrite(data)
            return
        if self.backend == BACKEND_S3:
            self._s3.put_object(self._bucket, self._key, data)
            return
        self._http.overwrite(data)


# ---------------------------------------------------------------------------
# Resolver
# ---------------------------------------------------------------------------


@fieldwise_init
struct StorageCredential(Copyable, Movable):
    """One entry of a REST `LoadTableResult`'s `storage-credentials`.

    Same shape as `iceberg.catalog.rest.StorageCredential`, so a parsed
    response can be forwarded without translation.
    """

    var prefix: String
    var config: Dict[String, String]


struct FileIOResolver(Copyable, Movable):
    """Picks a backend by URI scheme and configures it from properties.

    Property resolution for a given location, most specific first:

    1. the longest matching `storage-credentials` prefix,
    2. the resolver's own properties (an Iceberg table's `config`),
    3. `AWS_*` environment variables.

    Location rewrites (`rebase`) are applied before any of that, because
    Iceberg metadata records absolute locations and a warehouse that has been
    copied elsewhere — or a test fixture checked into a repo — needs them
    redirected without rewriting the metadata.
    """

    var properties: Dict[String, String]
    var storage_credentials: List[StorageCredential]
    var from_prefixes: List[String]
    var to_prefixes: List[String]
    var http: HttpClient

    def __init__(out self):
        self.properties = Dict[String, String]()
        self.storage_credentials = []
        self.from_prefixes = []
        self.to_prefixes = []
        self.http = HttpClient()

    def __init__(out self, var properties: Dict[String, String]):
        self.properties = properties^
        self.storage_credentials = []
        self.from_prefixes = []
        self.to_prefixes = []
        self.http = HttpClient()

    def set(mut self, var key: String, var value: String):
        self.properties[key^] = value^

    def add_storage_credential(
        mut self, var prefix: String, var config: Dict[String, String]
    ):
        self.storage_credentials.append(StorageCredential(prefix^, config^))

    def rebase(mut self, var old_prefix: String, var new_prefix: String):
        """Redirect every location under `old_prefix` to `new_prefix`.

        Byte-compatible with `iceberg.io.FileIO.rebase`.
        """
        self.from_prefixes.append(old_prefix^)
        self.to_prefixes.append(new_prefix^)

    def resolve(self, location: String) -> String:
        """The location this one should actually be read from."""
        for k in range(len(self.from_prefixes)):
            if location.startswith(self.from_prefixes[k]):
                var b = location.as_bytes()
                var rest = String(
                    StringSlice(
                        unsafe_from_utf8=Span(b)[
                            self.from_prefixes[k].byte_length() : len(b)
                        ]
                    )
                )
                return self.to_prefixes[k] + rest
        return location

    def properties_for(self, location: String) -> Dict[String, String]:
        """Merged properties for one location, most specific last.

        `storage-credentials` entries are matched by prefix and the **longest**
        match wins: a catalog may vend one credential for a table's data
        prefix and a narrower one for a single partition, and the narrower
        entry is the one that was meant.
        """
        var out = Dict[String, String]()
        for entry in self.properties.items():
            out[entry.key] = entry.value
        var best = -1
        var best_len = -1
        for k in range(len(self.storage_credentials)):
            ref sc = self.storage_credentials[k]
            if location.startswith(sc.prefix):
                if sc.prefix.byte_length() > best_len:
                    best_len = sc.prefix.byte_length()
                    best = k
        if best >= 0:
            for entry in self.storage_credentials[best].config.items():
                out[entry.key] = entry.value
        return out^

    def s3_config_for(self, location: String) raises -> S3Config:
        return S3Config.from_properties(self.properties_for(location))

    def gcs_config_for(self, location: String) raises -> GcsConfig:
        return GcsConfig.from_properties(self.properties_for(location))

    def azure_config_for(
        self, location: String, account: String
    ) raises -> AzureConfig:
        return AzureConfig.from_properties(
            self.properties_for(location), account
        )

    def backend_for(self, location: String) raises -> Int:
        var u = parse_uri(self.resolve(location))
        if u.scheme == "s3" or u.scheme == "s3a" or u.scheme == "s3n":
            return BACKEND_S3
        if u.scheme == "http" or u.scheme == "https":
            return BACKEND_HTTP
        if u.scheme == "gs" or u.scheme == "gcs":
            return BACKEND_GCS
        if (
            u.scheme == "abfs"
            or u.scheme == "abfss"
            or u.scheme == "wasb"
            or u.scheme == "wasbs"
            or u.scheme == "az"
        ):
            return BACKEND_AZURE
        if u.scheme == "file":
            return BACKEND_LOCAL
        raise Error(
            "objectstore: no implementation for scheme '"
            + u.scheme
            + "' in "
            + location
        )

    def _blob_input(self, target: String, backend: Int) raises -> HttpInputFile:
        """GCS and Azure locations, resolved to a URL plus auth headers."""
        if backend == BACKEND_GCS:
            var parts = split_gcs_uri(target)
            return GcsClient(
                self.gcs_config_for(target), self.http.copy()
            ).input(parts[0], parts[1])
        var az = parse_azure_uri(target)
        return AzureClient(
            self.azure_config_for(target, az.account), self.http.copy()
        ).input(az.container, az.path)

    def _blob_output(
        self, target: String, backend: Int
    ) raises -> HttpOutputFile:
        if backend == BACKEND_GCS:
            var parts = split_gcs_uri(target)
            return GcsClient(
                self.gcs_config_for(target), self.http.copy()
            ).output(parts[0], parts[1])
        var az = parse_azure_uri(target)
        return AzureClient(
            self.azure_config_for(target, az.account), self.http.copy()
        ).output(az.container, az.path)

    def new_input(self, location: String) raises -> AnyInputFile:
        var target = self.resolve(location)
        var backend = self.backend_for(location)
        var u = parse_uri(target)
        var bucket = String("")
        var key = String("")
        if backend == BACKEND_S3:
            var parts = split_s3_uri(target)
            bucket = parts[0]
            key = parts[1]
        var http_file = HttpInputFile(target, self.http.copy())
        var open_as = backend
        if backend == BACKEND_GCS or backend == BACKEND_AZURE:
            # Both are HTTPS plus fixed headers once the URL is built, so the
            # open file is an ordinary HttpInputFile.
            http_file = self._blob_input(target, backend)
            open_as = BACKEND_HTTP
        return AnyInputFile(
            open_as,
            target,
            LocalInputFile(u.local_path() if backend == BACKEND_LOCAL else ""),
            http_file^,
            S3Client(self.s3_config_for(location), self.http.copy()),
            bucket^,
            key^,
        )

    def new_output(self, location: String) raises -> AnyOutputFile:
        var target = self.resolve(location)
        var backend = self.backend_for(location)
        var u = parse_uri(target)
        var bucket = String("")
        var key = String("")
        if backend == BACKEND_S3:
            var parts = split_s3_uri(target)
            bucket = parts[0]
            key = parts[1]
        var http_file = HttpOutputFile(target, List[Header]())
        var open_as = backend
        if backend == BACKEND_GCS or backend == BACKEND_AZURE:
            http_file = self._blob_output(target, backend)
            open_as = BACKEND_HTTP
        return AnyOutputFile(
            open_as,
            target,
            LocalOutputFile(u.local_path() if backend == BACKEND_LOCAL else ""),
            http_file^,
            S3Client(self.s3_config_for(location), self.http.copy()),
            bucket^,
            key^,
        )

    def delete(self, location: String) raises:
        var target = self.resolve(location)
        var backend = self.backend_for(location)
        if backend == BACKEND_LOCAL:
            local_delete(parse_uri(target).local_path())
            return
        if backend == BACKEND_S3:
            var parts = split_s3_uri(target)
            var client = S3Client(
                self.s3_config_for(location), self.http.copy()
            )
            client.delete_object(parts[0], parts[1])
            return
        if backend == BACKEND_GCS:
            var parts = split_gcs_uri(target)
            GcsClient(
                self.gcs_config_for(target), self.http.copy()
            ).delete_object(parts[0], parts[1])
            return
        if backend == BACKEND_AZURE:
            var az = parse_azure_uri(target)
            AzureClient(
                self.azure_config_for(target, az.account), self.http.copy()
            ).delete_blob(az.container, az.path)
            return
        raise Error("objectstore: cannot delete over HTTP: " + location)

    def list(self, prefix: String) raises -> List[String]:
        """Locations under `prefix`, as full URIs.

        Local listing is recursive; S3 listing is flat by nature — an object
        store has no directories, only key prefixes.
        """
        var target = self.resolve(prefix)
        var backend = self.backend_for(prefix)
        if backend == BACKEND_LOCAL:
            return local_list(parse_uri(target).local_path())
        if backend == BACKEND_S3:
            var parts = split_s3_uri(target)
            var client = S3Client(self.s3_config_for(prefix), self.http.copy())
            var res = client.list_all(parts[0], parts[1])
            var out = List[String]()
            for k in range(len(res.objects)):
                out.append(String("s3://") + parts[0] + "/" + res.objects[k].key)
            return out^
        if backend == BACKEND_GCS:
            var parts = split_gcs_uri(target)
            var res = GcsClient(
                self.gcs_config_for(target), self.http.copy()
            ).list_all(parts[0], parts[1])
            var out = List[String]()
            for k in range(len(res.objects)):
                out.append(String("gs://") + parts[0] + "/" + res.objects[k].key)
            return out^
        if backend == BACKEND_AZURE:
            var az = parse_azure_uri(target)
            var blobs = AzureClient(
                self.azure_config_for(target, az.account), self.http.copy()
            ).list_blobs(az.container, az.path)
            var out = List[String]()
            var head = parse_uri(target).scheme + "://" + parse_uri(target).bucket + "/"
            for k in range(len(blobs)):
                out.append(head + blobs[k].name)
            return out^
        raise Error("objectstore: cannot list over HTTP: " + prefix)

    # ── convenience, mirroring iceberg.io.FileIO ───────────────────────────
    def read_all(self, location: String) raises -> List[UInt8]:
        return self.new_input(location).read_all()

    def read_range(
        self, location: String, offset: Int, length: Int
    ) raises -> List[UInt8]:
        """The bytes `[offset, offset+length)`.

        This is the entry point a lazy Parquet reader wants: fetch the last
        64 KiB for the footer, then exactly the row groups the scan needs.
        """
        return self.new_input(location).read_range(offset, length)

    def read_ranges(
        self, location: String, ranges: List[ByteRange]
    ) raises -> List[List[UInt8]]:
        """Several ranges of one object, coalesced where that saves requests.

        One `new_input` for the lot, so an S3 location is signed and addressed
        once rather than once per range.
        """
        return self.new_input(location).read_ranges(ranges)

    def read_text(self, location: String) raises -> String:
        var data = self.new_input(location).read_all()
        return String(StringSlice(unsafe_from_utf8=Span(data)))

    def exists(self, location: String) -> Bool:
        try:
            return self.new_input(location).exists()
        except:
            return False

    def write(
        self, location: String, data: Span[UInt8, _]
    ) raises:
        self.new_output(location).overwrite(data)
