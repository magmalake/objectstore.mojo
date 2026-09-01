# objectstore.mojo

[![mojoshelf](https://mojoshelf.org/badge/objectstore-mojo.svg)](https://mojoshelf.org/tins/objectstore-mojo) [![mojo nightly](https://mojoshelf.org/badge/objectstore-mojo/nightly.svg)](https://mojoshelf.org/tins/objectstore-mojo)

Storage and HTTP for Apache Iceberg tables in Mojo: a `FileIO` abstraction over
local files, HTTP(S) range reads and S3, with the HTTP transport the rest of the
stack was missing.

Part of [**magmalake**](https://magmalake.org) — data lake building blocks in Mojo

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

## Install

```sh
pixi shelf add objectstore-mojo
```

That resolves the tin from [mojoshelf](https://mojoshelf.org) and adds it — along with the tins it depends on — as **pixi git source dependencies**. magmalake tins are not published to a conda channel, so `pixi add objectstore-mojo` will not find them.

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

Since 0.2 the curl handle **persists** between requests, in an opaque client
(`os_http_client_new` / `_free`, taken by `os_http_request_ex`) — see
[Connection reuse](#connection-reuse). `os_http_request` keeps its 0.1
signature and now means "on the process-wide client", because a consumer's
lock file can pin an older `objectstore-shim` build while it compiles against
newer Mojo sources; `os_http_shim_abi()` returns 1 for the old shim and 2 for a
pooling one.

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
| `http.mojo` + `shim/` | `HttpClient` (`get`/`put`/`post`/`delete`/`head`), `Response{status, headers, body}`, custom headers, `Range`, timeouts, pooled connections, `RetryPolicy` |
| `crypto.mojo` | SHA-256 and HMAC-SHA256, pure Mojo, plus hex — with hardware backends (ARMv8 crypto extension, x86 SHA-NI) and a portable scalar fallback |
| `sigv4.mojo` | AWS Signature V4: canonical request, string to sign, signing key, header and query flavours |
| `ranges.mojo` | `ByteRange` and the plan that coalesces many nearby ranges into few requests |
| `path.mojo` | URI parsing (`scheme://bucket/key`, `file:///…`, bare paths), `join`, `parent`, `basename`, RFC 3986 encoding |
| `fileio.mojo` | the `InputFile` / `OutputFile` / `FileIO` traits, `AnyInputFile`/`AnyOutputFile`, and `FileIOResolver` |
| `local.mojo` | the filesystem backend, with real `seek`-based range reads |
| `httpio.mojo` | read-only `InputFile` over `http(s)://` — `HEAD` for length, `Range` for reads |
| `s3.mojo` | `get_object` (ranged), `put_object` (multipart above a threshold), `head_object`, `delete_object`, paginated `list_objects_v2`, presigning, and a small XML reader |
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
token is present. The payload hash is the real SHA-256 of the body; the
`s3.unsigned-payload` property (or `S3Config.sign_payload = False`) sends
`UNSIGNED-PAYLOAD` instead, which SigV4 permits and which is a real option for
a large object over TLS. It is **off by default**: it drops the guarantee that
what S3 stored is what was signed, and now that hashing runs at gigabytes per
second there is much less to buy. **S3 signs the un-normalized path** —
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

## Connection reuse

Every request used to create and destroy a libcurl easy handle, so every
request paid a fresh TCP and TLS handshake. That is the whole of the old
2.9 ms; the bytes were never the problem.

The handle now lives in the shim and persists. `curl_easy_reset` between
requests clears every option (so nothing leaks from the last one) while
explicitly keeping the live connections, the DNS cache and the TLS session
cache — which is the entire reason it is worth keeping the handle rather than
the options. `CURLOPT_TCP_KEEPALIVE` is on, `MAXCONNECTS` is 16 so alternating
hosts (a REST catalog and an S3 endpoint) do not evict each other, and
`FORBID_REUSE`/`FRESH_CONNECT` stay off. A process-wide share handle carries
DNS entries and TLS sessions between clients.

`HttpClient` holds no socket of its own: `pool` names a handle in the shim, and
`SHARED_POOL` — the default — is the process-wide one. Two `HttpClient` values
therefore share connections, which is what makes an Iceberg scan that
constructs a fresh `S3Client` per file cheap. `new_connection_pool()` hands out
a private one; **the caller owns it** and must `free_connection_pool` it, since
`HttpClient` is `Copyable` and a copyable owner of a C resource is a double
free waiting to happen.

Two things this needed:

* **The shim pins itself.** Mojo closes its `OwnedDLHandle` when the value
  dies, and a loader that honoured the `dlclose` would unmap the pooled
  connections along with the library, silently turning reuse back into a
  handshake per request. The shim takes a permanent `dlopen` reference to
  itself the first time it is called.
* **Threads.** A pool is **not** thread safe, and neither is the process-wide
  one. Mojo has no threads today, so this costs nothing and is why the share
  handle installs no locking callbacks; if that changes, each thread needs its
  own pool and the share handle needs `CURLSHOPT_LOCKFUNC`.

The tests assert reuse from both ends rather than inferring it from a
stopwatch: curl's own connection counter (`pool_stats` → `(requests,
connections)`) and the test server counting the distinct client ports it saw.

## Retries

`RetryPolicy` on `HttpClient`: three retries by default, 100 ms doubling to a
20 s ceiling, half the window fixed and half jittered. `S3Client.set_max_retries`
is the shorthand; `client.http.retry` is the policy; `RetryPolicy.none()` is
the 0.1 behaviour of one request, one answer.

| Retried | Not retried |
|---|---|
| transport failures | 4xx other than 429 |
| 429 | 501, 505 — permanent facts about the server, not weather |
| 5xx | `POST`/`PATCH` without an `Idempotency-Key` |
| S3 `SlowDown` and `RequestTimeout`, read out of the error document | anything, once `max_retries` is spent |

Connection reuse makes transport retries *more* valuable, not less: a pooled
socket that the server closed while it was idle fails on the next write, and
retrying is the correct answer to a race nobody can avoid.

`RequestTimeout` is why the error document is read at all — AWS returns it as a
**400**, so status alone would call it final. Only the first bytes of a
response that already failed are inspected, so this never touches an object
body.

Idempotency is RFC 9110's: `GET`, `HEAD`, `PUT`, `DELETE`, `OPTIONS` and
`TRACE` can be repeated by definition. `POST` and `PATCH` cannot, and are
retried **only** when the request carries an `Idempotency-Key` header — the
caller saying the server can deduplicate it. The header is the trigger rather
than a flag on the client because the decision belongs to the code that knows
whether the server honours it. `retry_non_idempotent` is the escape hatch for a
caller that cannot add a header, and is off.

> **Consumers, note.** A `POST` that carries `Idempotency-Key` is now retried on
> a 5xx. A caller that would rather be told the state is unknown — because its
> server does not in fact deduplicate — should set `client.retry =
> RetryPolicy.none()` on the `HttpClient` it commits with.

A response that survives the last attempt is **returned**, not turned into an
error: the caller sees the server's own answer.

## Multipart upload

`put_object` switches to `CreateMultipartUpload` / `UploadPart` /
`CompleteMultipartUpload` when the body is larger than
`S3Config.multipart_threshold` (8 MiB), in `multipart_part_size` chunks (8 MiB,
clamped up to S3's 5 MiB floor — a smaller part is rejected at completion,
*after* the bytes have been sent). Setting the threshold to 0 restores the
single `PUT`, which is still correct up to S3's 5 GB ceiling.

Nothing about the call changes, so `AnyOutputFile.overwrite` and
`FileIOResolver.write` get it for free: a Parquet writer should not have to
know how big its own output turned out to be.

Parts are `Span` slices of the caller's buffer, so the object is never held
twice — peak memory is the caller's bytes plus one part's SigV4 hashing state.
Every failure path aborts the upload, because unaborted parts are billed until
a lifecycle rule collects them, and an abort that itself fails is appended to
the error rather than swallowed.

Two details that would otherwise bite: `CompleteMultipartUpload` answers 200
and *then* streams an error, because completion can take minutes and the status
line has already gone out — so the body is checked; and the completion `POST`
carries no `Idempotency-Key`, so the retry policy leaves it alone, which is
right.

`s3.multipart.part-size-bytes` is read from properties, with Iceberg's own name
and units. Iceberg's `s3.multipart.threshold` is a decimal *factor* of the part
size, which needs a float parser this module does not have; the threshold
follows the part size instead, and `S3Config.multipart_threshold` sets it
directly.

## Reading many ranges at once

A Parquet scan does not read a file, it reads a list of spans: the footer, then
one span per column chunk of each row group it kept. Locally that is a list of
seeks and costs nothing. Over HTTP it is a list of *requests*, and even at
0.15 ms each the useful optimisation is not making them faster but making fewer
of them.

```mojo
var spans = List[ByteRange]()
spans.append(ByteRange(row_group_start, row_group_bytes))
spans.append(ByteRange(f.length() - 65536, 65536))   # the footer, asked last
var chunks = f.read_ranges(spans)                     # answered in that order
```

`InputFile.read_ranges` is on the trait with a **default that loops**, which is
exactly right for a file the process can seek and means nothing that already
conforms has to change. HTTP and S3 override it: `objectstore.ranges` groups
ranges that are adjacent, overlapping, or within `max_gap` (1 MiB) of each
other, fetches the groups, and slices the caller's ranges back out. Column
chunks of one row group are laid out consecutively, so a scan's reads collapse
to a handful of requests and the columns it skipped are read and thrown away —
cheaper than the round trip that would have avoided them. The waste is bounded
by `max_gap` per join.

Input order is preserved, a suffix range (`offset < 0`) is left on its own
because where it lands is not known until the length is, and a short read is
truncated rather than sliced past the end.

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

## SHA-256, and why it is not scalar any more

SigV4 hashes the whole payload of every signed request, so the compression
function was the ceiling on upload: at 60 MB/s of SHA-256, a 16 MB multipart
`put_object` ran at 53 MB/s against a MinIO that will take gigabytes.

`crypto.mojo` now has three backends and picks one at compile time:

| Backend | Instructions | Where |
|---|---|---|
| `armv8-crypto` | `sha256h` / `sha256h2` / `sha256su0` / `sha256su1` | every Apple Silicon Mac, every server aarch64 part with the SHA-2 extension |
| `x86-sha-ni` | `sha256rnds2` / `sha256msg1` / `sha256msg2` | AMD Zen, and Intel from Goldmont / Ice Lake onwards |
| `scalar` | none | everything else — and it is now 10× the old one, being unrolled over all 64 rounds with a 16-word rolling schedule that keeps every index a compile-time constant |

The choice is a `comptime` query of the *target's* CPU features, and `mojo`
compiles for the host CPU unless told otherwise, so on any normal build the
compile-time answer is the run-time truth. `sha256_backend()` reports which one
is live and `sha256_target_features()` reports the features it saw — both are
printed by the test suite and by `pixi run bench`, so a CI log says which path
it exercised.

One wrinkle earned its own code path. On a GitHub `macos-latest` runner `mojo`
resolves *no* host CPU: the target comes back as baseline aarch64
(`apple-silicon=0 neon=1 sha2=0`) even though the machine is an arm64 Mac and
certainly has the extension, and the `llvm.aarch64.crypto.*` intrinsics would
fail to select. So the same four instructions have a second way in — inline
assembly under `.arch_extension sha2`, which the assembler accepts whatever the
target CPU is, at about 4% off the intrinsics. Whether they may actually *run*
is then a run-time question with a platform-specific answer: on macOS always
(the crypto extension is mandatory on Apple Silicon), on Linux whatever the
kernel says through `AT_HWCAP`, otherwise scalar. That path reports itself as
`armv8-crypto (asm)`.

**OpenSSL is still faster** — 3178 MB/s to our 2700 on the same M4, since
libcrypto has had hand-written assembly for this for a decade. The point was
never to beat it. The point was to stop paying a 45× penalty for *not* linking
it: `objectstore` still has exactly one native dependency, and it is libcurl.

## Not implemented

* **GCS service-account JWT signing (RSA)** and **Azure `SharedKey` / Entra
  ID.** See above: both backends require a credential the caller already has.
* **`s3.signer` / remote signing.** The REST spec's `remote-signing` delegation
  mode — `POST …/v1/{prefix}/s3-sign/{routing}`, where the catalog signs each
  request instead of vending credentials — is not implemented;
  `vended-credentials` is. The seam exists: it is a different way of producing
  the headers `S3Client._signed_headers` builds, so it wants an
  `S3Client.signer` indirection rather than a new backend.
* **Parallel or streaming multipart.** Parts go up one at a time from a buffer
  the caller already holds; there is no upload from a file handle, and no
  concurrency, because Mojo has no threads.
* **Concurrent requests.** One connection pool, one request at a time, for the
  same reason.
* **Server-side encryption headers, ACLs, versioning, object tagging.**
* **HDFS and other schemes.** `FileIOResolver.backend_for` raises a clear
  error naming the scheme rather than pretending.

## Perf

M4, one core, 100 MB, `pixi run bench` (which now brings up MinIO too, so the
signed numbers are against a real object store):

| Operation | 0.1 | 0.2 | 0.3 |
|---|---|---|---|
| local `read_all` | 3400 MB/s | 3491 MB/s | 2982 MB/s |
| local `read_range` × 1000 (64 KiB each) | 5700 MB/s | 5774 MB/s | 5677 MB/s |
| HTTP `read_all` (loopback, python server) | 1770 MB/s | 2220 MB/s | 1998 MB/s |
| **HTTP `read_range` × 200** (64 KiB each) | **2.85 ms/request**, 22 MB/s | **0.147 ms/request**, 424 MB/s | 0.142 ms/request, 442 MB/s |
| **MinIO ranged `get_object` × 200** (signed) | **5.91 ms/request**, 11 MB/s | **0.521 ms/request**, 120 MB/s | 0.502 ms/request, 125 MB/s |
| HTTP `read_ranges` × 200 (coalesced) | — | 0.021 ms/request, 2914 MB/s | 0.028 ms/request, 2208 MB/s |
| MinIO `read_ranges` × 200 (coalesced) | — | 0.027 ms/request, 2304 MB/s | 0.030 ms/request, 2092 MB/s |
| **MinIO `put_object`, 16 MB (multipart)** | — | **53 MB/s** | **409 MB/s** |
| **SHA-256** (what SigV4 costs a signed request) | 60 MB/s | 60 MB/s | **2700 MB/s** |
| SHA-256, scalar fallback | 60 MB/s | 60 MB/s | 610 MB/s |
| SHA-256, OpenSSL `SHA256()` for reference | 3178 MB/s | 3178 MB/s | 3178 MB/s |
| HMAC-SHA256, 8 KB × 10 000 | — | — | 4.18 µs/op |

**19× on loopback and 11× against MinIO** in 0.2, and the whole of it was the
handshake that no longer happens; **7.7× on multipart upload** in 0.3, and the
whole of that is the hash. The two coalescing rows are the same 200
spans asked for in one call: adjacent, so they become one request, and the
per-request figure is the total divided by 200 rather than a request that got
faster.

The HTTP numbers include a single-threaded Python server on the other end, so
they are a floor, not a ceiling. `put_object` used to be bounded by SHA-256 at
60 MB/s; it is not any more, and what is left is MinIO and the loopback. The
SHA-256 row is the backend this machine compiled in (`armv8-crypto`); the two
rows under it are the portable fallback and OpenSSL, measured on the same
64 MiB in the same run. OpenSSL is unchanged across versions because it was
never ours — it is there to say how much is left on the table.

## Tests

`pixi run test` builds the suite, brings up the servers it needs, runs 62 tests,
and tears them down:

* SHA-256 and HMAC against FIPS 180-4 and RFC 4231, including the one-million-`a`
  vector fed in chunk sizes that exercise the block-buffering path;
* **SHA-256 cross-checks, 1000 pseudo-random buffers of 0..10 KB each**, of
  whichever backend this build compiled in against the portable scalar one
  *and* against OpenSSL's `SHA256()` — libcrypto is already in the environment
  as a libcurl dependency, so it is free as a test oracle even though nothing
  links it. Three fixed vectors would not catch a message-schedule bug that
  only appears at some particular block count, which is exactly the bug the
  intrinsics could have. Plus a ragged-chunk streaming check against the
  one-shot digest;
* **all 37 usable cases of the published `aws-sig-v4-test-suite`**, checked at
  every stage — canonical request, string to sign, signature.
  `get-header-value-multiline` is excluded: obs-fold header values were removed
  from HTTP/1.1 by RFC 7230 and cannot be expressed as a `Name: Value` pair.
  Regenerate with `tools/gen_sigv4_vectors.py`;
* the HTTP client against `tests/http_server.py` — every verb, custom headers,
  ranges (including open-ended and suffix), 404/403/500, and a timeout;
* **connection reuse**, asserted from both ends: twenty requests, one socket
  by curl's own counter and one client port by the server's;
* **retries**, against a route that fails N times and then succeeds and counts
  the attempts it saw — transient recovery, giving up, 501 left alone, a bare
  `POST` not repeated, a keyed one repeated, and the two S3 error codes hiding
  behind a 400;
* **range coalescing**: the planner (adjacency, gaps, out-of-order input,
  overlap, suffixes), six HTTP ranges answered by one request and by three at a
  64-byte gap with identical bytes, and nine S3 "column chunks" plus a footer
  answered by one `GET`;
* **S3 end to end against MinIO**: put, get, ranged get, head, list with
  delimiter and pagination, delete, a 20 MB single-`PUT` object, **multipart at
  20 MB (three parts) and 40 MB (eight 5 MiB parts)** verified by SHA-256 of
  the object read back — a part uploaded out of order produces exactly the
  right size and entirely the wrong contents — plus the `-<parts>` ETag suffix,
  which is the server itself confirming the upload was multipart, and an
  aborted upload that cannot then be completed; keys containing spaces and `=`,
  both addressing styles, a presigned URL read by a client with no credentials,
  and a wrong-credentials request that MinIO rejects;
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

Those two halves can be **different versions**, because a lock file pins the
git dependency to a commit while `-I` follows the checkout. So the shim's ABI
is additive: `os_http_request` still has its 0.1 signature, and 0.2's Mojo
sources call it for the default pool. A consumer pinned to a 0.1 shim compiles
and runs unchanged against 0.2 sources — it simply does not get connection
reuse until it updates the pin. `objectstore.http.shim_abi()` says which it
has.

## License

Apache-2.0. Copyright 2026 Marius Seritan.
