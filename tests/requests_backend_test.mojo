"""The whole objectstore test suite again, over the requests backend.

tests/run_tests.sh builds and runs it when OBJECTSTORE_REQUESTS_DEPS names a
directory with Mosaad-M's requests, tls, tcp, url and json checkouts (see
tools/fetch_requests.sh). It generates the binary's main under build/: that
main imports each `def test_*` of tests/objectstore_test.mojo by name, calls
`before_tests` below, then runs them, and the script checks how many ran.

objectstore_test's own main is not called from here, and this file does not
import it. `__functions_in_module()` returns an incomplete list in a module
that is imported rather than built as the main file (Mojo 1.2.0), so a suite
found that way could run fewer tests than it has and still pass.
"""

from std.os import getenv

import objectstore_requests
from objectstore.http import HttpClient, backend_name


def before_tests() raises:
    """Switches to the requests backend, before any test runs."""
    objectstore_requests.install()
    print("== HTTP backend:", backend_name())
    # The libcurl run already counted its /flaky/ attempts on this server.
    var base = getenv("OBJECTSTORE_TEST_HTTP", "")
    if base != "":
        _ = HttpClient().get(base + "/attempts/reset")
