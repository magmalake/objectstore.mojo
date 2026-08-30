"""`objectstore` — storage and HTTP for magmalake.

    from objectstore import FileIOResolver, HttpClient, S3Client

Modules: `http` (a libcurl-backed client, because no Mojo HTTP package
resolves from conda), `crypto` (SHA-256/HMAC, because nothing provides them
and SigV4 is made of them), `sigv4`, `path` (URI handling), `fileio` (the
`InputFile`/`OutputFile`/`FileIO` traits and the scheme resolver), `local`,
`httpio`, `s3`.
"""

from .crypto import (
    Sha256,
    from_hex,
    hmac_sha256,
    sha256,
    sha256_hex,
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
from .http import Header, HttpClient, Response, curl_version
from .httpio import HttpInputFile
from .local import LocalInputFile, LocalOutputFile, local_delete, local_list
from .path import Uri, basename, join, parent, parse_uri, url_encode
from .s3 import (
    ListResult,
    ObjectInfo,
    S3Client,
    S3Config,
    S3Credentials,
    split_s3_uri,
)
from .sigv4 import AmzTime, QueryParam, presign_query, sign_request
