"""`objectstore_requests` — objectstore's HTTP over the pure-Mojo `requests`.

A prototype for objectstore#24. libcurl stays objectstore's default; a
program opts in with one call before its first request:

```mojo
import objectstore_requests

def main() raises:
    objectstore_requests.install()
    ...  # every objectstore request now goes through requests + tls
```

It needs https://github.com/Mosaad-M/requests and its `tls`, `tcp`, `url`
and `json` packages on the include path (`tools/fetch_requests.sh` checks
out the pinned revisions), and is not part of the objectstore conda
package. See `backend.mojo` for what maps to what, and the gaps.
"""

from .backend import install
