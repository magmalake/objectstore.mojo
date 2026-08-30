# objectstore.mojo

Storage and HTTP for Apache Iceberg tables in Mojo: a `FileIO` abstraction over
local files, HTTP(S) range reads and S3, with the HTTP transport the rest of the
stack was missing.

Part of **magmalake** — data lake building blocks in Mojo

```mojo
from objectstore import FileIOResolver

var io = FileIOResolver()
io.set("s3.region", "us-east-1")

var f = io.new_input("s3://warehouse/db/table/data/00000-1.parquet")
var footer = f.read_range(f.length() - 65536, 65536)   # just the footer
```

```console
$ objectstore-mojo ls s3://warehouse/db/table/metadata/
$ objectstore-mojo cat s3://warehouse/db/table/metadata/v3.metadata.json
$ objectstore-mojo presign s3://warehouse/data/f.parquet 900
```

---

## Why libcurl

Phase 2 of this stack established that **no Mojo HTTP client resolves from
conda** on either toolchain this repo supports:

```
floki          -> No candidates were found
flare          -> No candidates were found
lightbug-http  -> No candidates were found
fire-http      -> No candidates were found
```

`flare` exists as a source checkout, but it is unpublished and builds OpenSSL
FFI shims from activation scripts, which would make this tin unbuildable in CI.
Meanwhile an Iceberg REST catalog needs HTTPS, an S3 client needs HTTPS, and a
presigned URL is nothing but HTTPS. So this tin supplies the transport.

It does it the way every other magmalake FFI tin binds a C library (zstd.mojo,
lz4.mojo): **a tiny C shim built as a `pixi-build-cmake` package into
`$CONDA_PREFIX/lib`, dlopened through an `OwnedDLHandle`.** conda-forge's
`libcurl` brings TLS and a CA bundle on every platform we target, and
`pixi-build-cmake` is already proven to find a C compiler on both the ubuntu
and macos runners.

The shim (`shim/curl_wrapper.c`, ~260 lines) exists for a specific reason:
`curl_easy_setopt` is a C variadic, and while Mojo 1.0's `external_call` can
express variadics through `num_fixed_args`, a **dlopened** symbol cannot. So the
shim collapses a whole request into one fixed-arity call —

```c
os_http_result *os_http_request(method, url, headers_blob, body, body_len,
                                range_start, range_end, timeout_ms,
                                follow_redirects, verify_tls);
```

— and returns an opaque result read through accessors (`_status`, `_body`,
`_body_len`, `_headers`, `_error`) and released with `os_http_result_free`, so
buffer ownership never straddles the boundary. Headers cross as one
LF-separated blob of `Name: Value` lines, which is lossless (an HTTP header
value cannot contain a bare LF) and spares the Mojo side a `char*[]`.

Defaults, and why:

| Default | Reason |
|---|---|
| redirects **off** | a presigned URL carries its signature in the query string and must never be silently re-issued elsewhere |
| TLS verification **on** | `verify_tls=False` exists for self-signed test servers and is never the default |
| no `Accept-Encoding` | transparent gzip would make `Content-Length` describe the *compressed* body, so `HEAD` would report the wrong object size and `Range` would address the wrong bytes |
| `Expect:` cleared | curl adds `Expect: 100-continue` to large uploads, costing a round trip S3 does not need |
| proxies from the environment | `http_proxy` / `https_proxy` / `no_proxy` work as they do for curl itself |

`HttpClient.request` raises only on **transport** failure. A 404 or a 500 comes
back as a `Response` — the caller is the one that knows whether a missing object
is an error.

## Layout

| Module | What it is |
|---|---|
| `http.mojo` + `shim/` | `HttpClient` (`get`/`put`/`post`/`delete`/`head`), `Response{status, headers, body}`, custom headers, `Range`, timeouts |
| `crypto.mojo` | SHA-256 and HMAC-SHA256, pure Mojo, plus hex |
| `sigv4.mojo` | AWS Signature V4: canonical request, string to sign, signing key, header and query flavours |
| `path.mojo` | URI parsing (`scheme://bucket/key`, `file:///…`, bare paths), `join`, `parent`, `basename`, RFC 3986 encoding |
| `fileio.mojo` | the `InputFile` / `OutputFile` / `FileIO` traits, `AnyInputFile`/`AnyOutputFile`, and `FileIOResolver` |
| `local.mojo` | the filesystem backend, with real `seek`-based range reads |
| `httpio.mojo` | read-only `InputFile` over `http(s)://` — `HEAD` for length, `Range` for reads |
| `s3.mojo` | `get_object` (ranged), `put_object`, `head_object`, `delete_object`, paginated `list_objects_v2`, presigning, and a small XML reader |
| `gcs.mojo` | GCS over its **S3-compatible XML endpoint**, authenticated with a caller-supplied OAuth2 bearer token |
| `azure.mojo` | Azure Blob through **SAS-token URLs** |
| `src/main.mojo` | the `objectstore-mojo` CLI |

`crypto.mojo` is here because nothing in the Mojo ecosystem provides SHA-2:
hashes.mojo covers only the *non-cryptographic* hashes Iceberg needs for
partition transforms (murmur3, xxhash, CRC32). Adding a second FFI shim for
OpenSSL's EVP surface — which moves between conda builds — was not worth it for
two functions whose cost is irrelevant next to the round trip they
authenticate. If a general-purpose home appears, this belongs in hashes.mojo.

## The FileIO traits, and how iceberg.mojo adopts them

iceberg.mojo's `src/iceberg/io.mojo` already declares the seam:

```mojo
trait InputFile(Copyable, Movable):
    def location(self) -> String: ...
    def exists(self) raises -> Bool: ...
    def read_all(self) raises -> List[UInt8]: ...
```

The trait here is a **superset** — same three methods, same signatures, plus the
two a lazy Parquet reader needs:

```mojo
trait InputFile(Copyable, Movable):
    def location(self) -> String: ...
    def exists(self) raises -> Bool: ...
    def length(self) raises -> Int: ...
    def read_all(self) raises -> List[UInt8]: ...
    def read_range(self, offset: Int, length: Int) raises -> List[UInt8]: ...
```

so anything satisfying `objectstore.fileio.InputFile` already satisfies
`iceberg.io.InputFile`. The mapping iceberg.mojo should adopt:

| iceberg.mojo today | objectstore.mojo | Note |
|---|---|---|
| `iceberg.io.InputFile` | `objectstore.fileio.InputFile` | superset; drop the local declaration |
| `iceberg.io.LocalInputFile` | `objectstore.local.LocalInputFile` | gains `length()` and `read_range()` |
| `iceberg.io.FileIO` | `objectstore.fileio.FileIOResolver` | see below |
| `FileIO.local()` | `FileIOResolver()` | the default resolver is already local-capable |
| `FileIO.rebase(old, new)` | `FileIOResolver.rebase(old, new)` | identical semantics: ordered prefix rewrites, first match wins |
| `FileIO.resolve(loc)` | `FileIOResolver.resolve(loc)` | returns a *location*, not a stripped path — `parse_uri(...).local_path()` gives the path |
| `FileIO.new_input(loc)` | `FileIOResolver.new_input(loc)` | returns `AnyInputFile` instead of `LocalInputFile` |
| `FileIO.read_all(loc)` | `FileIOResolver.read_all(loc)` | identical |
| `FileIO.read_text(loc)` | `FileIOResolver.read_text(loc)` | identical |
| `FileIO.exists(loc)` | `FileIOResolver.exists(loc)` | identical, non-raising |
| `iceberg.io.strip_scheme` | `objectstore.path.strip_scheme` | byte-compatible |
| `basename` / `dirname` / `join_path` | `path.basename` / `path.parent` / `path.join` | `parent` also handles `s3://bucket` correctly |
| `rest.StorageCredential` | `fileio.StorageCredential` | same `{prefix, config}` shape; forward a parsed `LoadTableResult` directly |
| *(new)* | `FileIOResolver.new_output` / `.write` / `.delete` / `.list` | what a writer will need |
| *(new)* | `FileIOResolver.read_range(loc, offset, len)` | what a lazy Parquet reader wants |

For the REST catalog, iceberg.mojo's `RestCatalogConfig` is described in its own
source as "everything but the socket". The socket is `HttpClient`:

```mojo
var client = HttpClient()
var resp = client.get(config.config_url(), config.headers())
resp.raise_for_status("iceberg: GET /v1/config")
config.apply_config(resp.text())
```

`objectstore.http.Header` has the same `{name, value}` shape as
`iceberg.catalog.rest.Header`, so `config.headers()` can be passed straight
through once one of the two declarations is dropped.

Mojo dispatches traits **statically**, so a "pick a backend by URI scheme" API
cannot return an arbitrary trait implementation. `AnyInputFile` and
`AnyOutputFile` are small tagged unions over the three backends that conform to
the traits themselves: generic code keeps using the traits, code that resolves
locations at runtime uses the resolver.

## S3 authentication

| Source | How | Where |
|---|---|---|
| explicit properties | `S3Config.from_properties(dict)` — Iceberg names: `s3.endpoint`, `s3.access-key-id`, `s3.secret-access-key`, `s3.session-token`, `s3.region`, `s3.path-style-access`, `client.region` | a table's `config` from `loadTable` |
| environment | `S3Config.from_env()` — `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `AWS_REGION` / `AWS_DEFAULT_REGION`, `AWS_ENDPOINT_URL_S3` / `AWS_ENDPOINT_URL`, `AWS_S3_FORCE_PATH_STYLE` | the CLI, CI, local MinIO |
| vended credentials | `FileIOResolver.add_storage_credential(prefix, config)` — the REST spec's `storage-credentials` list; **longest matching prefix wins** | a catalog that vends per-prefix STS credentials |
| presigned URL | `S3Client.presign_get(bucket, key, seconds)` produces a URL readable by `HttpInputFile` with no credentials at all | handing an object to something that knows nothing about AWS |
| anonymous | `S3Config.anonymous` — signing skipped entirely | public buckets |

Resolution order for a given location, most specific first: the longest matching
`storage-credentials` prefix, then the resolver's own properties, then the
`AWS_*` environment.

Signing is `AWS4-HMAC-SHA256` with `host`, `x-amz-date` and
`x-amz-content-sha256` always signed, plus `x-amz-security-token` when a session
token is present. The payload hash is the real SHA-256 of the body; set
`S3Config.sign_payload = False` to send `UNSIGNED-PAYLOAD` instead, which is a
real option for a large object over TLS. **S3 signs the un-normalized path** —
`..` is a legal key segment — so path normalization is off for S3 and on only
where the test vectors ask for it.

### Endpoint styles

| Style | URL | When |
|---|---|---|
| virtual-host (default) | `https://bucket.s3.region.amazonaws.com/key` | AWS |
| path (`path_style = True`) | `https://endpoint/bucket/key` | MinIO, Ceph, R2, anything with a custom endpoint, and bucket names containing dots |

Setting `s3.endpoint` (or `AWS_ENDPOINT_URL*`) turns on path style
automatically, because a custom endpoint almost never has the wildcard DNS
virtual-host addressing needs. Set `s3.path-style-access = false` to override.

The signed `Host` omits a default port (`:443` on https, `:80` on http) because
that is what curl actually sends; signing it produces a `SignatureDoesNotMatch`
that looks like a credential problem.

## GCS and Azure

Both are implemented, and both are deliberately narrow: they cover the case
where **someone else has already produced the credential**, which is exactly
what an Iceberg REST catalog vends.

**GCS** goes through the S3-compatible **XML endpoint**
(`storage.googleapis.com/<bucket>/<key>`), not the JSON API. The XML API is
byte-for-byte the S3 protocol for `GET` with `Range`, `PUT`, `DELETE` and
`ListBucketResult`, so `s3.mojo`'s parser reads the listings unchanged and this
backend needs no JSON parser at all. Authentication is an OAuth2 bearer token
passed in as Iceberg's `gcs.oauth2.token`; `gcs.service.host` overrides the
endpoint. Minting a token from a service-account key needs RS256 JWT signing,
and **RSA is out of scope** — far more code than SHA-256 was, for something
`gcloud auth print-access-token`, the metadata server, or the surrounding
application already has. A caller holding HMAC "interoperability" keys can
point `S3Client` at `https://storage.googleapis.com` instead and get real
SigV4.

**Azure Blob** goes through **SAS-token URLs** — the query string Iceberg
stores as `adls.sas-token.<account>`. `abfs(s)://container@account.dfs…`,
`wasb(s)://` and `az://container/path` all parse; requests carry `x-ms-version`
and, on writes, `x-ms-blob-type: BlockBlob`. Azure's own `SharedKey` HMAC
scheme and Entra ID bearer flows are **not** implemented.

Both reduce, once a location is turned into a URL plus fixed headers, to
`HttpInputFile` / `HttpOutputFile` — which is why `AnyInputFile` has three
backends and not five.

Neither has a live gate: there is no emulator in the toolchain and neither
takes credentials this repo could hold. What is tested is everything that is
not the network — URL construction, auth headers, the property names a catalog
vends, and the listing documents.

## Not implemented

* **GCS service-account JWT signing (RSA)** and **Azure `SharedKey` / Entra
  ID.** See above: both backends require a credential the caller already has.
* **Multipart upload.** `put_object` is a single `PUT`. Tested to 20 MB; S3's
  single-PUT ceiling is 5 GB. Iceberg data files are usually well under that,
  but a writer that needs more will need multipart.
* **Retries and backoff.** One request, one answer. A `Response` with a 503 is
  returned, not retried.
* **Connection reuse.** Each request is a fresh libcurl easy handle, so each is
  a fresh TCP and TLS handshake. That costs about 3 ms per request on loopback
  and rather more against a real endpoint; a shared multi handle is the obvious
  next optimisation.
* **`s3.signer` / remote signing.** The REST spec's `remote-signing` delegation
  mode is not implemented; `vended-credentials` is.
* **Server-side encryption headers, ACLs, versioning, object tagging.**
* **HDFS and other schemes.** `FileIOResolver.backend_for` raises a clear
  error naming the scheme rather than pretending.

## Perf

M4, one core, 100 MB, `pixi run bench`:

| Operation | Throughput |
|---|---|
| local `read_all` | 3400 MB/s |
| local `read_range` × 1000 (64 KiB each) | 5700 MB/s |
| HTTP `read_all` (loopback, python server) | 1770 MB/s |
| HTTP `read_range` × 200 (64 KiB each) | 22 MB/s — ~2.9 ms per request, dominated by connection setup |
| SHA-256 (what SigV4 costs a signed PUT) | 60 MB/s |

The HTTP numbers include a single-threaded Python server on the other end, so
they are a floor, not a ceiling. SHA-256 at 60 MB/s is the scalar reference
implementation; it only matters for `put_object`, and `sign_payload = False`
removes it.

## Tests

`pixi run test` builds the suite, brings up the servers it needs, runs 43 tests,
and tears them down:

* SHA-256 and HMAC against FIPS 180-4 and RFC 4231, including the one-million-`a`
  vector fed in chunk sizes that exercise the block-buffering path;
* **all 37 usable cases of the published `aws-sig-v4-test-suite`**, checked at
  every stage — canonical request, string to sign, signature.
  `get-header-value-multiline` is excluded: obs-fold header values were removed
  from HTTP/1.1 by RFC 7230 and cannot be expressed as a `Name: Value` pair.
  Regenerate with `tools/gen_sigv4_vectors.py`;
* the HTTP client against `tests/http_server.py` — every verb, custom headers,
  ranges (including open-ended and suffix), 404/403/500, and a timeout;
* **S3 end to end against MinIO**: put, get, ranged get, head, list with
  delimiter and pagination, delete, a 20 MB single-`PUT` object, keys containing
  spaces and `=`, both addressing styles, a presigned URL read by a client with
  no credentials, and a wrong-credentials request that MinIO rejects;
* GCS and Azure URL construction, auth headers, Iceberg property names and
  listing documents, which is everything about those backends that is not the
  network.

MinIO rather than moto because **moto does not verify signatures**, which is the
only thing worth testing there. The runner looks for `$MINIO_BINARY`, then
`build/minio`, then `minio` on `PATH`, then `moto_server`, and skips the S3
tests with a printed reason if none is there. CI fetches the MinIO binary in a
workflow step, so those tests run on all four legs. The only credentials
anywhere are MinIO's well-known defaults, reaching a server on `127.0.0.1`.

## Consuming this tin

Sibling magmalake tins are consumed **by source path**, not as packages: the
`pixi-build-mojo` backend emits a precompiled artifact built with mojo-compiler
1.0.0 and the nightly compiler rejects it outright, so a package dependency
cannot satisfy both environments.

```
mojo build my.mojo -I ../objectstore.mojo/src
```

CI for a consumer therefore has to check this repo out next to its own, and the
`objectstore-shim` package must be in the environment — add
`objectstore-shim = { path = "../objectstore.mojo/shim" }` to its dependencies,
or depend on the `objectstore-mojo` conda package, which pulls the shim in as a
run dependency.

## License

Apache-2.0. Copyright 2026 Marius Seritan.
