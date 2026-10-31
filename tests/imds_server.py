#!/usr/bin/env python3
"""A throwaway EC2 instance metadata service for the instance-role tests.

Speaks just enough IMDSv2: PUT /latest/api/token hands out a session token,
and the two credential GETs answer only when that token comes back in
`X-aws-ec2-metadata-token`, as the real service does with v1 disabled. It
listens on an ephemeral port and prints its URL on stdout.
"""
import datetime as dt
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOKEN = "mock-imds-token"
ROLE = "objectstore-test-role"
CREDS_PATH = "/latest/meta-data/iam/security-credentials/"


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, status, body=b"", ctype="text/plain"):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_PUT(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        if self.path != "/latest/api/token" or not self.headers.get(
            "X-aws-ec2-metadata-token-ttl-seconds"
        ):
            return self._send(400)
        self._send(200, TOKEN.encode())

    def do_GET(self):
        if self.headers.get("X-aws-ec2-metadata-token") != TOKEN:
            return self._send(401)
        if self.path == CREDS_PATH:
            return self._send(200, (ROLE + "\n").encode())
        if self.path == CREDS_PATH + ROLE:
            expires = dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=6)
            body = json.dumps(
                {
                    "Code": "Success",
                    "Type": "AWS-HMAC",
                    "AccessKeyId": "ASIAMOCKIMDSKEY",
                    "SecretAccessKey": "mock/imds/secret",
                    "Token": "mock-imds-session-token",
                    "Expiration": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
                },
                indent=2,
            ).encode()
            return self._send(200, body, "application/json")
        self._send(404)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    print(f"http://127.0.0.1:{server.server_address[1]}", flush=True)
    server.serve_forever()
