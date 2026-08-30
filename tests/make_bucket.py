#!/usr/bin/env python3
"""Creates the test bucket with a signed `PUT /<bucket>`.

Bucket creation deliberately does not go through the code under test: if
objectstore's own signing were broken, a bucket created with it would make the
S3 tests fail in a confusing place. This is a self-contained SigV4 signer in
40 lines of stdlib.
"""
import datetime
import hashlib
import hmac
import sys
import urllib.error
import urllib.request

endpoint, bucket, access_key, secret_key = sys.argv[1:5]
host = endpoint.split("://", 1)[1]
now = datetime.datetime.now(datetime.timezone.utc)
amz_date = now.strftime("%Y%m%dT%H%M%SZ")
stamp = now.strftime("%Y%m%d")
region = "us-east-1"
payload_hash = hashlib.sha256(b"").hexdigest()

canonical = "\n".join([
    "PUT", "/" + bucket, "",
    "host:%s" % host,
    "x-amz-content-sha256:%s" % payload_hash,
    "x-amz-date:%s" % amz_date,
    "", "host;x-amz-content-sha256;x-amz-date", payload_hash,
])
scope = "%s/%s/s3/aws4_request" % (stamp, region)
to_sign = "\n".join([
    "AWS4-HMAC-SHA256", amz_date, scope,
    hashlib.sha256(canonical.encode()).hexdigest(),
])
key = ("AWS4" + secret_key).encode()
for part in (stamp, region, "s3", "aws4_request"):
    key = hmac.new(key, part.encode(), hashlib.sha256).digest()
signature = hmac.new(key, to_sign.encode(), hashlib.sha256).hexdigest()

req = urllib.request.Request(
    "%s/%s" % (endpoint, bucket), method="PUT", data=b"",
    headers={
        "Host": host,
        "x-amz-date": amz_date,
        "x-amz-content-sha256": payload_hash,
        "Authorization": (
            "AWS4-HMAC-SHA256 Credential=%s/%s, "
            "SignedHeaders=host;x-amz-content-sha256;x-amz-date, "
            "Signature=%s" % (access_key, scope, signature)
        ),
    },
)
try:
    urllib.request.urlopen(req).read()
    print("created bucket", bucket)
except urllib.error.HTTPError as e:
    body = e.read().decode("utf-8", "replace")
    if "BucketAlreadyOwnedByYou" in body or e.code == 409:
        print("bucket", bucket, "already exists")
    else:
        print("bucket creation failed:", e.code, body[:300])
        raise SystemExit(1)
