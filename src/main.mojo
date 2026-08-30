"""`objectstore-mojo` — a small CLI over the same `FileIOResolver` the library
exposes, so the storage layer can be poked at without writing a program.

Every subcommand takes a URI, not a path: `file:///…`, `https://…`,
`s3://bucket/key`. Credentials come from the environment (`AWS_ACCESS_KEY_ID`,
`AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `AWS_REGION`,
`AWS_ENDPOINT_URL[_S3]`), which is what makes it usable against MinIO in a
test loop.
"""

from std.sys import argv

from objectstore.fileio import FileIOResolver
from objectstore.http import curl_version, shim_abi
from objectstore.local import local_input
from objectstore.path import parse_uri
from objectstore.s3 import S3Client, S3Config, split_s3_uri


comptime USAGE = String(
    """objectstore-mojo — storage and HTTP for magmalake

usage:
  objectstore-mojo cat <uri>                  write an object to stdout
  objectstore-mojo head <uri> [n]             first n bytes (default 1024)
  objectstore-mojo get <uri> <local-path>     download to a file
  objectstore-mojo ls <prefix>                list locations under a prefix
  objectstore-mojo put <uri> <local-path>     upload a file
  objectstore-mojo rm <uri>                   delete an object
  objectstore-mojo stat <uri>                 existence and length
  objectstore-mojo presign <s3-uri> [secs]    a presigned GET URL
  objectstore-mojo version                    tin, shim ABI, libcurl build

Credentials come from AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY /
AWS_SESSION_TOKEN / AWS_REGION / AWS_ENDPOINT_URL_S3."""
)


def _as_text(data: List[UInt8]) -> String:
    return String(StringSlice(unsafe_from_utf8=Span(data)))


def main() raises:
    var args = argv()
    if len(args) < 2:
        print(USAGE)
        return
    var cmd = String(args[1])
    var io = FileIOResolver()

    if cmd == "version":
        # The shim ABI is worth printing: a consumer whose lock file pins an
        # older objectstore-shim gets 1 and no connection reuse, and nothing
        # else would tell it so.
        print("objectstore.mojo 0.2.0, shim ABI", shim_abi())
        print(curl_version())
        return

    if cmd == "help" or cmd == "--help" or cmd == "-h":
        print(USAGE)
        return

    if len(args) < 3:
        print(USAGE)
        raise Error("objectstore-mojo: " + cmd + " needs a URI")
    var uri = String(args[2])

    if cmd == "cat":
        print(_as_text(io.new_input(uri).read_all()), end="")
        return

    if cmd == "head":
        var n = 1024
        if len(args) > 3:
            n = Int(String(args[3]))
        print(_as_text(io.new_input(uri).read_range(0, n)), end="")
        return

    if cmd == "get":
        if len(args) < 4:
            raise Error("objectstore-mojo: get needs a local destination")
        var data = io.new_input(uri).read_all()
        with open(String(args[3]), "w") as f:
            f.write_bytes(Span(data))
        print("wrote", len(data), "bytes to", String(args[3]))
        return

    if cmd == "ls":
        var entries = io.list(uri)
        for k in range(len(entries)):
            print(entries[k])
        return

    if cmd == "put":
        if len(args) < 4:
            raise Error("objectstore-mojo: put needs a local source file")
        var src = local_input(String(args[3])).read_all()
        io.new_output(uri).overwrite(Span(src))
        print("put", len(src), "bytes to", uri)
        return

    if cmd == "rm":
        io.delete(uri)
        print("deleted", uri)
        return

    if cmd == "stat":
        var f = io.new_input(uri)
        if not f.exists():
            print(uri, "does not exist")
            return
        print(uri, "exists, length", f.length())
        return

    if cmd == "presign":
        var expires = 3600
        if len(args) > 3:
            expires = Int(String(args[3]))
        var parts = split_s3_uri(uri)
        var client = S3Client(S3Config.from_env())
        print(client.presign_get(parts[0], parts[1], expires))
        return

    print(USAGE)
    raise Error("objectstore-mojo: unknown command '" + cmd + "'")
