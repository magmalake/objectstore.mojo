"""libcurl vs the requests backend (objectstore#24), on the same URLs.

    BACKEND=curl|requests URL=<object url> MODE=<mode> ./bench-http-backends

Modes (SIZE and COUNT in the environment, sizes in bytes):
    whole    GET the whole object COUNT times
    ranges   COUNT sequential range GETs of SIZE bytes, spread over the object
    batch    the same ranges through request_many, 16 at a time (libcurl
             keeps 16 in flight; the requests backend runs them one by one)
    threads  the same ranges from THREADS threads, each its own requests
    setup    PUT a SIZE-byte object to S3 (BUCKET, KEY; S3Config.from_env)
             and print a presigned GET URL for it, valid for a day

Prints one line: mode, backend, requests, bytes, seconds, MB/s. CPU time is
measured from outside (bench/run_backend_bench.sh).
"""

from std.os import getenv
from std.time import perf_counter_ns

import objectstore_requests
from objectstore.http import BatchRequest, Header, HttpClient
from objectstore.s3 import S3Client, S3Config
from threads import parallel_for


struct Job(Movable):
    var url: String
    var size: Int
    var per_thread: Int
    var object_len: Int
    var bytes: List[Int]
    var errors: List[String]

    def __init__(
        out self, url: String, size: Int, per_thread: Int, object_len: Int, threads: Int
    ):
        self.url = url
        self.size = size
        self.per_thread = per_thread
        self.object_len = object_len
        self.bytes = List[Int](length=threads, fill=0)
        self.errors = List[String](length=threads, fill=String())


def _offset(k: Int, size: Int, object_len: Int) -> Int:
    # A stride that is not a multiple of the range size, so reads don't line
    # up with whatever the server caches.
    var slots = max(1, (object_len - size) // 4096)
    return ((k * 7919) % slots) * 4096


def _thread_task(t: Int, mut job: Job) -> None:
    try:
        var c = HttpClient()
        var total = 0
        for k in range(job.per_thread):
            var at = _offset(t * job.per_thread + k, job.size, job.object_len)
            var r = c.get(job.url, List[Header](), at, at + job.size - 1)
            if r.status != 206:
                raise Error("status " + String(r.status))
            total += len(r.body)
        job.bytes[t] = total
    except e:
        job.errors[t] = String(e)


def main() raises:
    var backend = getenv("BACKEND", "curl")
    if backend == "requests":
        objectstore_requests.install()
    var mode = getenv("MODE", "ranges")
    var size = atol(getenv("SIZE", "1048576"))
    var count = atol(getenv("COUNT", "64"))

    if mode == "setup":
        var bucket = getenv("BUCKET", "bench")
        var key = getenv("KEY", "big.bin")
        var s3 = S3Client(S3Config.from_env())
        var data = List[UInt8](capacity=size)
        for i in range(size):
            data.append(UInt8((i * 131 + i // 4096) % 251))
        s3.put_object(bucket, key, Span(data))
        print(s3.presign_get(bucket, key, 86400))
        return

    var url = getenv("URL")
    var c = HttpClient()
    # A one-byte range rather than a HEAD: a presigned URL is signed for GET.
    var probe = c.get(url, List[Header](), 0, 0)
    var cr = probe.header("Content-Range")
    var slash = cr.find("/")
    if probe.status != 206 or slash < 0:
        raise Error("no Content-Range from " + url + ": " + String(probe.status))
    var object_len = atol(String(cr[byte = slash + 1 :]))
    var total = 0
    var n = 0
    var t0 = perf_counter_ns()
    if mode == "whole":
        for _ in range(count):
            var r = c.get(url)
            r.raise_for_status("GET")
            if len(r.body) != object_len:
                raise Error("short body: " + String(len(r.body)))
            total += len(r.body)
            n += 1
    elif mode == "ranges":
        for k in range(count):
            var at = _offset(k, size, object_len)
            var r = c.get(url, List[Header](), at, at + size - 1)
            if r.status != 206 or len(r.body) != size:
                raise Error("bad range answer " + String(r.status))
            total += len(r.body)
            n += 1
    elif mode == "batch":
        var k = 0
        while k < count:
            var reqs = List[BatchRequest]()
            for j in range(k, min(count, k + 16)):
                var at = _offset(j, size, object_len)
                reqs.append(BatchRequest.get(url, List[Header](), at, at + size - 1))
            var got = c.request_many(reqs, max_parallel=16)
            for g in range(len(got)):
                if got[g].status != 206 or len(got[g].body) != size:
                    raise Error("bad batch answer " + String(got[g].status))
                total += len(got[g].body)
            n += len(got)
            k += 16
    elif mode == "threads":
        var threads = atol(getenv("THREADS", "8"))
        var job = Job(url, size, count // threads, object_len, threads)
        parallel_for[_thread_task](threads, job, num_workers=threads)
        for t in range(threads):
            if job.errors[t] != "":
                raise Error("thread " + String(t) + ": " + job.errors[t])
            total += job.bytes[t]
        n = (count // threads) * threads
    else:
        raise Error("unknown MODE " + mode)
    var secs = Float64(perf_counter_ns() - t0) / 1e9
    print(
        mode,
        backend,
        "requests=" + String(n),
        "bytes=" + String(total),
        "secs=" + String(secs),
        "MBps=" + String(Float64(total) / 1e6 / secs),
    )
