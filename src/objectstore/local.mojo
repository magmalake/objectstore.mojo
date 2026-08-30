"""`objectstore.local` — the filesystem backend.

Range reads use `seek` + `read_bytes(n)`, which Mojo's `FileHandle` supports,
so reading a Parquet footer out of a 2 GB file costs 64 KiB rather than 2 GB.
Everything else is a thin wrapper whose value is uniformity: the same
`InputFile`/`OutputFile` shape as S3 and HTTP, so a caller never branches on
where a table happens to live.
"""

from std.os import listdir, makedirs, remove
from std.os.path import exists as path_exists, getsize, isdir

from .path import parse_uri


def _dirname(path: String) -> String:
    var i = path.rfind("/")
    if i < 0:
        return String(".")
    if i == 0:
        return String("/")
    var b = path.as_bytes()
    return String(StringSlice(unsafe_from_utf8=Span(b)[0:i]))


@fieldwise_init
struct LocalInputFile(Copyable, Movable):
    """A readable file at an ordinary filesystem path."""

    var path: String

    def location(self) -> String:
        return self.path

    def exists(self) raises -> Bool:
        return path_exists(self.path) and not isdir(self.path)

    def length(self) raises -> Int:
        return Int(getsize(self.path))

    def read_all(self) raises -> List[UInt8]:
        with open(self.path, "r") as f:
            return f.read_bytes()

    def read_range(self, offset: Int, length: Int) raises -> List[UInt8]:
        """`length` bytes from `offset`; a short read at EOF is not an error.

        A negative `offset` counts back from the end, the way an HTTP suffix
        range does — which is how a Parquet reader asks for a footer.
        """
        if length <= 0:
            return List[UInt8]()
        var start = offset
        if start < 0:
            var size = self.length()
            start = size + start
            if start < 0:
                start = 0
        with open(self.path, "r") as f:
            _ = f.seek(start)
            return f.read_bytes(length)


@fieldwise_init
struct LocalOutputFile(Copyable, Movable):
    """A writable file at an ordinary filesystem path.

    Parent directories are created on demand: Iceberg writes to deep,
    partition-shaped paths that no one has made in advance.
    """

    var path: String

    def location(self) -> String:
        return self.path

    def exists(self) raises -> Bool:
        return path_exists(self.path)

    def create(self, data: Span[UInt8, _]) raises:
        if self.exists():
            raise Error("objectstore.local: " + self.path + " already exists")
        self.overwrite(data)

    def overwrite(self, data: Span[UInt8, _]) raises:
        var parent = _dirname(self.path)
        if parent != "" and parent != "." and not path_exists(parent):
            makedirs(parent, exist_ok=True)
        with open(self.path, "w") as f:
            f.write_bytes(data)


def local_delete(path: String) raises:
    """Removes a file. A missing file is not an error — deletion is
    idempotent here for the same reason it is on S3."""
    if path_exists(path):
        remove(path)


def local_list(prefix: String) raises -> List[String]:
    """Every file under `prefix`, recursively, as `file://` URIs.

    A prefix that names a file lists just that file, which keeps the contract
    the same as S3's: a prefix is a prefix, not necessarily a directory.
    """
    var out = List[String]()
    if not path_exists(prefix):
        return out^
    if not isdir(prefix):
        out.append(String("file://") + prefix)
        return out^
    var stack = List[String]()
    stack.append(prefix)
    while len(stack) > 0:
        var dir = stack.pop()
        var entries = listdir(dir)
        for k in range(len(entries)):
            var child = dir
            if not child.endswith("/"):
                child += "/"
            child += String(entries[k])
            if isdir(child):
                stack.append(child^)
            else:
                out.append(String("file://") + child)
    return out^


def local_input(location: String) raises -> LocalInputFile:
    """Opens a `file://` URI or a bare path."""
    return LocalInputFile(parse_uri(location).local_path())


def local_output(location: String) raises -> LocalOutputFile:
    return LocalOutputFile(parse_uri(location).local_path())
