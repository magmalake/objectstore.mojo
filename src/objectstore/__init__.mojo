"""`objectstore` — storage and HTTP for magmalake.

See the module docstrings for the pieces: `http` (libcurl-backed client),
`crypto` (SHA-256/HMAC for SigV4), `path` (URI handling), `fileio` (the
`InputFile`/`OutputFile`/`FileIO` traits and the scheme resolver), `local`,
`httpio`, `s3`.
"""

from .crypto import sha256, sha256_hex, hmac_sha256, to_hex, from_hex
from .http import HttpClient, Response, Header, curl_version
