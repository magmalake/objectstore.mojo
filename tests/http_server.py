#!/usr/bin/env python3
"""A throwaway HTTP server for the client tests.

`python -m http.server` only speaks GET and HEAD, and the point of these tests
is the whole verb surface plus ranges, error statuses and timeouts. This is
the smallest thing that exercises all of it. It listens on an ephemeral port
and prints the URL on stdout so the test runner can capture it.

Routes:
  /files/<name>   GET/HEAD (Range aware), PUT (201/204), DELETE (204/404)
  /echo           any method; body reports method, a chosen header, body length
  /status/<code>  answers with that status and a short body
  /slow?ms=N      sleeps N milliseconds first (timeout tests)
  /noclen         a chunked response, so Content-Length is absent
  /ports          "count=N": distinct client ports seen since the last reset,
                  which is how the connection-reuse test observes that N
                  requests rode one TCP connection
  /ports/reset    forgets them, then counts its own
  /flaky/<code>/<n>?key=k  fails with <code> the first n times a key is used,
                  then answers 200 — the retry tests' server
"""
import os
import re
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = sys.argv[1] if len(sys.argv) > 1 else "."

# Distinct client ports seen, i.e. distinct TCP connections. A keep-alive
# client that reuses its connection shows up here as exactly one.
SEEN_PORTS = set()
# Per-key attempt counters for /flaky.
ATTEMPTS = {}
STATE_LOCK = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    # ── helpers ────────────────────────────────────────────────────────────
    def _path_and_query(self):
        path, _, query = self.path.partition("?")
        params = {}
        for part in query.split("&"):
            if "=" in part:
                k, v = part.split("=", 1)
                params[k] = v
        return path, params

    def _send(self, code, body=b"", ctype="application/octet-stream", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD" and body:
            self.wfile.write(body)

    def _file_for(self, path):
        name = path[len("/files/"):]
        if not re.fullmatch(r"[A-Za-z0-9._-]+", name or ""):
            return None
        return os.path.join(ROOT, name)

    # ── verbs ──────────────────────────────────────────────────────────────
    def _serve(self):
        path, params = self._path_and_query()
        with STATE_LOCK:
            if path == "/ports/reset":
                SEEN_PORTS.clear()
            SEEN_PORTS.add(self.client_address[1])
            n_ports = len(SEEN_PORTS)

        if path == "/ports/reset":
            return self._send(200, b"reset", "text/plain")

        if path == "/ports":
            return self._send(
                200, ("count=%d\n" % n_ports).encode("ascii"), "text/plain"
            )

        if path.startswith("/flaky/"):
            # /flaky/<code>/<n>: the first <n> requests for a key answer
            # <code>, the rest answer 200. `n=-1` never succeeds.
            parts = path.split("/")
            code = int(parts[2])
            fails = int(parts[3]) if len(parts) > 3 else 1
            key = params.get("key", "default")
            body = b""
            if int(self.headers.get("Content-Length") or 0):
                body = self.rfile.read(int(self.headers["Content-Length"]))
            with STATE_LOCK:
                seen = ATTEMPTS.get(key, 0) + 1
                ATTEMPTS[key] = seen
            if fails < 0 or seen <= fails:
                extra = {"Retry-After": "0"} if code == 429 else None
                payload = params.get("payload", "")
                if payload == "s3slowdown":
                    return self._send(
                        code,
                        b"<?xml version=\"1.0\"?><Error><Code>SlowDown</Code>"
                        b"<Message>Please reduce your request rate.</Message>"
                        b"</Error>",
                        "application/xml",
                        extra,
                    )
                return self._send(
                    code, b"transient failure %d" % seen,
                    "text/plain", extra,
                )
            return self._send(
                200,
                ("attempts=%d\nmethod=%s\nidem=%s\nbody-len=%d\n" % (
                    seen, self.command,
                    self.headers.get("Idempotency-Key", ""), len(body),
                )).encode("ascii"),
                "text/plain",
            )

        if path == "/attempts":
            with STATE_LOCK:
                seen = ATTEMPTS.get(params.get("key", "default"), 0)
            return self._send(
                200, ("attempts=%d\n" % seen).encode("ascii"), "text/plain"
            )

        if path.startswith("/slow"):
            time.sleep(int(params.get("ms", "1000")) / 1000.0)
            return self._send(200, b"slow")

        if path.startswith("/status/"):
            code = int(path.rsplit("/", 1)[1])
            return self._send(code, b'{"error":"status %d"}' % code, "application/json")

        if path == "/noclen":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(b"5\r\nchunk\r\n0\r\n\r\n")
            return

        if path == "/echo":
            n = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(n) if n else b""
            out = "method=%s\nx-test=%s\nbody-len=%d\nbody=%s\n" % (
                self.command,
                self.headers.get("X-Test", ""),
                len(body),
                body.decode("utf-8", "replace"),
            )
            return self._send(200, out.encode("utf-8"), "text/plain")

        if path.startswith("/files/"):
            target = self._file_for(path)
            if target is None:
                return self._send(400, b"bad name")

            if self.command in ("GET", "HEAD"):
                if not os.path.exists(target):
                    return self._send(404, b"not found")
                total = os.path.getsize(target)
                rng = self.headers.get("Range")
                if rng and rng.startswith("bytes="):
                    # Seek rather than read-then-slice: the benchmark issues
                    # hundreds of range requests against a 100 MB file, and a
                    # server that read it whole each time would be measuring
                    # itself.
                    spec = rng[len("bytes="):]
                    if spec.startswith("-"):
                        n = min(int(spec[1:]), total)
                        start = total - n
                        end = total - 1
                    else:
                        lo, _, hi = spec.partition("-")
                        start = int(lo)
                        end = min(int(hi), total - 1) if hi else total - 1
                    with open(target, "rb") as fh:
                        fh.seek(start)
                        chunk = fh.read(end - start + 1)
                    return self._send(206, chunk, extra={
                        "Content-Range": "bytes %d-%d/%d" % (start, end, total),
                        "Accept-Ranges": "bytes",
                    })
                data = open(target, "rb").read()
                return self._send(200, data, extra={"Accept-Ranges": "bytes"})

            if self.command == "PUT":
                n = int(self.headers.get("Content-Length") or 0)
                existed = os.path.exists(target)
                with open(target, "wb") as f:
                    f.write(self.rfile.read(n) if n else b"")
                return self._send(204 if existed else 201, b"")

            if self.command == "DELETE":
                if not os.path.exists(target):
                    return self._send(404, b"not found")
                os.remove(target)
                return self._send(204, b"")

        return self._send(404, b"no route")

    do_GET = do_HEAD = do_PUT = do_POST = do_DELETE = _serve


def main():
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    print("http://127.0.0.1:%d" % server.server_address[1], flush=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass


main()
