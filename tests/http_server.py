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
"""
import os
import re
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = sys.argv[1] if len(sys.argv) > 1 else "."


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
                data = open(target, "rb").read()
                rng = self.headers.get("Range")
                if rng and rng.startswith("bytes="):
                    spec = rng[len("bytes="):]
                    if spec.startswith("-"):
                        chunk = data[-int(spec[1:]):]
                        start = len(data) - len(chunk)
                        end = len(data) - 1
                    else:
                        lo, _, hi = spec.partition("-")
                        start = int(lo)
                        end = int(hi) if hi else len(data) - 1
                        end = min(end, len(data) - 1)
                        chunk = data[start:end + 1]
                    return self._send(206, chunk, extra={
                        "Content-Range": "bytes %d-%d/%d" % (start, end, len(data)),
                        "Accept-Ranges": "bytes",
                    })
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
