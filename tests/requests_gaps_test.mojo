"""What the requests backend still cannot do with upstream's own releases.

Each test here fails on requests v1.11.0 and passes on libcurl. They are not
part of the suite's verdict: tests/run_tests.sh runs them after the suite on
the requests backend and reports the result without failing the run. When
one starts passing, upstream has fixed it: move it into objectstore_test.

- test_chunked_body_over_100mb: requests v1.11.0 applies max_response_bytes
  while reading a chunked body, but `_decode_chunked` (via `_parse_response`)
  still checks the compile-time 100 MB MAX_RESPONSE_BYTES, so a chunked
  response over 100 MB fails whatever the client allows. Content-Length
  bodies (every S3 GET) are not affected. Mosaad-M/requests#28; the local
  patch 0005 that objectstore#25 used to carry threaded the limit through.
"""

from std.os import getenv
from std.testing import TestSuite, assert_equal

import objectstore_requests
from objectstore.http import HttpClient, backend_name


def test_chunked_body_over_100mb() raises:
    var base = getenv("OBJECTSTORE_TEST_HTTP", "")
    if base == "":
        print("skip: OBJECTSTORE_TEST_HTTP unset")
        return
    var n = 101 * 1024 * 1024
    var resp = HttpClient().get(base + "/bigchunked/" + String(n))
    assert_equal(resp.status, 200)
    assert_equal(len(resp.body), n)


def main() raises:
    if getenv("OBJECTSTORE_GAPS_ON_LIBCURL", "") == "":
        objectstore_requests.install()
    print("== known upstream gaps, HTTP backend:", backend_name())
    TestSuite.discover_tests[__functions_in_module()]().run()
