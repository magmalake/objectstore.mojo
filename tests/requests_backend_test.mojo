"""The whole objectstore test suite again, over the requests backend.

Built and run by tests/run_tests.sh when OBJECTSTORE_REQUESTS_DEPS names a
directory with Mosaad-M's requests, tls, tcp, url and json checkouts (see
tools/fetch_requests.sh).
"""

from std.os import getenv

import objectstore_requests
import objectstore_test
from objectstore.http import HttpClient, backend_name


def main() raises:
    objectstore_requests.install()
    print("== HTTP backend:", backend_name())
    # The libcurl run already counted its /flaky/ attempts on this server.
    var base = getenv("OBJECTSTORE_TEST_HTTP", "")
    if base != "":
        _ = HttpClient().get(base + "/attempts/reset")
    objectstore_test.main()
