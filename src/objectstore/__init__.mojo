"""`objectstore` — storage and HTTP for magmalake.

    from objectstore import FileIOResolver, HttpClient, S3Client

Modules: `http` (a libcurl-backed client, because no Mojo HTTP package
resolves from conda), `crypto` (SHA-256/HMAC, because nothing provides them
and SigV4 is made of them), `sigv4`, `path` (URI handling), `fileio` (the
`InputFile`/`OutputFile`/`FileIO` traits and the scheme resolver), `local`,
`ranges` (coalescing many byte ranges into few requests), `httpio`, `s3`, and
— over SAS/bearer URLs only — `gcs` and `azure`.
"""

from .azure import AzureClient, AzureConfig, parse_azure_uri
from .crypto import (
    Sha256,
    from_hex,
    hmac_sha256,
    sha256,
    sha256_backend,
    sha256_hex,
    sha256_scalar,
    to_hex,
)
from .fileio import (
    AnyInputFile,
    AnyOutputFile,
    FileIO,
    FileIOResolver,
    InputFile,
    OutputFile,
    StorageCredential,
)
from .gcs import GcsClient, GcsConfig, split_gcs_uri
from .http import (
    Header,
    HttpClient,
    Response,
    RetryPolicy,
    curl_version,
    free_connection_pool,
    new_connection_pool,
    pool_stats,
)
from .httpio import HttpInputFile, HttpOutputFile
from .local import LocalInputFile, LocalOutputFile, local_delete, local_list
from .path import Uri, basename, join, parent, parse_uri, url_encode
from .ranges import (
    ByteRange,
    CoalescedPlan,
    DEFAULT_COALESCE_GAP,
    RangeReader,
    plan_ranges,
    read_ranges_coalesced,
)
from .s3 import (
    ListResult,
    ObjectInfo,
    S3Client,
    S3Config,
    S3Credentials,
    split_s3_uri,
)
from .sigv4 import AmzTime, QueryParam, presign_query, sign_request
