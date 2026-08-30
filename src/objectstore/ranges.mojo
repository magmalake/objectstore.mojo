"""`objectstore.ranges` — byte ranges, and the plan that turns many into few.

A Parquet scan does not read a file, it reads a list of spans: the footer,
then one span per column chunk of each row group it kept. Over local storage
that is a list of seeks and costs nothing. Over HTTP it is a list of *requests*,
and even with connection reuse each one still costs a round trip — so the
useful optimisation is not making requests faster, it is making fewer of them.

Column chunks of the same row group are laid out consecutively, which means the
spans a scan asks for are usually adjacent or separated by the columns it
skipped. Fetching across a small hole and throwing the hole away is cheaper
than a second round trip: this module works out where those holes are.

The bound is `max_gap` (1 MiB by default), applied per join, so the bytes read
and discarded are at most `max_gap` times the number of joins — never more than
the caller asked for plus that.

This module deliberately knows nothing about transports; `fileio` and `httpio`
execute the plan.
"""


@fieldwise_init
struct ByteRange(Copyable, Movable, Writable):
    """`length` bytes starting at `offset`.

    A negative `offset` means what it means to `read_range` — a suffix range,
    "the last `length` bytes" — and is never coalesced, because where it lands
    is not known until the length is.
    """

    var offset: Int
    var length: Int

    def end(self) -> Int:
        return self.offset + self.length

    def write_to(self, mut writer: Some[Writer]):
        writer.write("[", self.offset, ", ", self.end(), ")")


comptime DEFAULT_COALESCE_GAP = 1024 * 1024
"""Holes up to this size are read and discarded rather than skipped. A MiB is
roughly where a loopback round trip stops being cheaper than the bytes; over a
real network the crossover is much higher, so this is the conservative end."""


struct CoalescedPlan(Copyable, Movable):
    """How to answer `n` ranges with `len(fetches)` requests.

    For each input range `i`: `group[i]` is the fetch it comes from, or -1 if
    it has to be read on its own (a suffix or empty range), and `group_offset[i]`
    is where inside that fetch its bytes begin.
    """

    var fetches: List[ByteRange]
    var group: List[Int]
    var group_offset: List[Int]

    def __init__(out self):
        self.fetches = []
        self.group = []
        self.group_offset = []

    def requests_saved(self, asked: Int) -> Int:
        var alone = 0
        for k in range(len(self.group)):
            if self.group[k] < 0:
                alone += 1
        return asked - len(self.fetches) - alone


def _sorted_by_offset(ranges: List[ByteRange], idx: List[Int]) -> List[Int]:
    """Merge sort on indices — stable, and O(n log n) because a wide scan can
    ask for thousands of chunks and this must not become the slow part."""
    var n = len(idx)
    if n <= 1:
        return idx.copy()
    var mid = n // 2
    var left = List[Int]()
    var right = List[Int]()
    for k in range(mid):
        left.append(idx[k])
    for k in range(mid, n):
        right.append(idx[k])
    var a = _sorted_by_offset(ranges, left)
    var b = _sorted_by_offset(ranges, right)
    var out = List[Int](capacity=n)
    var i = 0
    var j = 0
    while i < len(a) and j < len(b):
        if ranges[b[j]].offset < ranges[a[i]].offset:
            out.append(b[j])
            j += 1
        else:
            out.append(a[i])
            i += 1
    while i < len(a):
        out.append(a[i])
        i += 1
    while j < len(b):
        out.append(b[j])
        j += 1
    return out^


def plan_ranges(
    ranges: List[ByteRange], max_gap: Int = DEFAULT_COALESCE_GAP
) -> CoalescedPlan:
    """Groups ranges that are adjacent, overlapping, or `max_gap` apart.

    The input order is preserved in the result — a caller that asked for the
    footer last still gets the footer last — and ranges are sorted internally
    only to find the groups.
    """
    var plan = CoalescedPlan()
    var sortable = List[Int]()
    for k in range(len(ranges)):
        plan.group.append(-1)
        plan.group_offset.append(0)
        if ranges[k].offset >= 0 and ranges[k].length > 0:
            sortable.append(k)
    if len(sortable) == 0:
        return plan^

    var order = _sorted_by_offset(ranges, sortable)
    var start = ranges[order[0]].offset
    var end = ranges[order[0]].end()
    var members = List[Int]()
    members.append(order[0])
    for k in range(1, len(order)):
        ref r = ranges[order[k]]
        if r.offset <= end + max_gap:
            members.append(order[k])
            if r.end() > end:
                end = r.end()
            continue
        _close_group(plan, ranges, members, start, end)
        members = List[Int]()
        members.append(order[k])
        start = r.offset
        end = r.end()
    _close_group(plan, ranges, members, start, end)
    return plan^


def _close_group(
    mut plan: CoalescedPlan,
    ranges: List[ByteRange],
    members: List[Int],
    start: Int,
    end: Int,
) -> None:
    var g = len(plan.fetches)
    plan.fetches.append(ByteRange(start, end - start))
    for k in range(len(members)):
        plan.group[members[k]] = g
        plan.group_offset[members[k]] = ranges[members[k]].offset - start


trait RangeReader(Copyable, Movable):
    """The one method coalescing needs. `InputFile` is a superset."""

    def read_range(self, offset: Int, length: Int) raises -> List[UInt8]:
        ...


def read_ranges_coalesced[
    T: RangeReader
](
    reader: T,
    ranges: List[ByteRange],
    max_gap: Int = DEFAULT_COALESCE_GAP,
) raises -> List[List[UInt8]]:
    """Fetches the plan's groups and slices the caller's ranges back out."""
    var plan = plan_ranges(ranges, max_gap)
    var buffers = List[List[UInt8]]()
    for k in range(len(plan.fetches)):
        buffers.append(
            reader.read_range(plan.fetches[k].offset, plan.fetches[k].length)
        )

    var out = List[List[UInt8]]()
    for k in range(len(ranges)):
        var g = plan.group[k]
        if g < 0:
            # A suffix or empty range: nothing to coalesce it with.
            out.append(reader.read_range(ranges[k].offset, ranges[k].length))
            continue
        var at = plan.group_offset[k]
        var stop = at + ranges[k].length
        # A server may answer a range with fewer bytes than asked for; slicing
        # past the end would be a crash rather than a short read.
        if stop > len(buffers[g]):
            stop = len(buffers[g])
        var piece = List[UInt8]()
        if at < stop:
            piece = List[UInt8](capacity=stop - at)
            piece.extend(Span(buffers[g])[at:stop])
        out.append(piece^)
    return out^
