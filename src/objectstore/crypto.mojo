"""`objectstore.crypto` — SHA-256, HMAC-SHA256 and hex, in pure Mojo.

AWS SigV4 is built entirely out of these two primitives, and nothing in the
Mojo ecosystem provides either: hashes.mojo covers the *non-cryptographic*
hashes Iceberg needs for partition transforms (murmur3, xxhash, CRC32), and no
conda-resolvable package offers SHA-2. Rather than pull OpenSSL in through a
second FFI shim — libcurl already links it, but its EVP surface is a moving
target across conda builds — this module implements FIPS 180-4 and RFC 2104
directly.

SigV4 hashes the *whole* payload of every signed PUT, so this is not a
negligible cost: a purely scalar compression function caps a multipart upload
at the speed of the hash. The block loop therefore has three backends, chosen
at compile time by `_BACKEND`:

* `armv8-crypto` — the ARMv8 SHA-2 extension (`sha256h`/`sha256h2`/`sha256su0`
  /`sha256su1`), which every Apple Silicon and every server aarch64 part has.
* `x86-sha-ni`   — Intel SHA extensions (`sha256rnds2`/`sha256msg1`
  /`sha256msg2`), present on AMD Zen and on Intel from Goldmont/Ice Lake
  client onwards, but *not* on Ice Lake / Sapphire Rapids Xeons.
* `scalar`       — portable FIPS 180-4, fully unrolled with a 16-word rolling
  schedule so the whole working set stays in registers.

The choice is a `comptime` query of the *target's* CPU features, and `mojo`
compiles for the host CPU unless told otherwise, so on a normal build (pixi
source dependency, `pixi run`, CI) the compile-time answer is the run-time
truth. A binary deliberately cross-built with `--target-cpu` for a CPU it will
not run on is the one case that would fault, and that is the same contract as
every other `-march=native` build.

If a general-purpose home ever appears, this belongs in hashes.mojo.
"""

from std.sys import llvm_intrinsic
from std.sys.info import CompilationTarget


comptime _K = SIMD[DType.uint32, 64](
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
)
"""The 64 round constants: the first 32 bits of the fractional parts of the
cube roots of the first 64 primes (FIPS 180-4 §4.2.2)."""

comptime SHA256_DIGEST_SIZE = 32
comptime SHA256_BLOCK_SIZE = 64

comptime _U4 = SIMD[DType.uint32, 4]

comptime _HAS_ARM_SHA2 = (
    CompilationTarget._has_feature["neon"]()
    and CompilationTarget._has_feature["sha2"]()
)
"""`neon` is aarch64-only and `sha2` is the ARMv8 SHA-2 crypto extension."""

comptime _HAS_X86_SHA_NI = (
    CompilationTarget.is_x86()
    and CompilationTarget._has_feature["sha"]()
    and CompilationTarget._has_feature["ssse3"]()
    and CompilationTarget._has_feature["sse4.1"]()
)
"""SHA-NI proper, plus the two shuffle/blend families the schedule needs."""

comptime _BACKEND = "armv8-crypto" if _HAS_ARM_SHA2 else (
    "x86-sha-ni" if _HAS_X86_SHA_NI else "scalar"
)


def sha256_backend() -> String:
    """Which compression backend this build compiled in: `armv8-crypto`,
    `x86-sha-ni` or `scalar`. Benchmarks and tests print it so a CI log says
    which path it actually exercised."""
    return String(_BACKEND)


def sha256_target_features() -> String:
    """The CPU features this build was compiled against, as the backend choice
    saw them. A `scalar` backend on hardware that plainly has the extension
    means `mojo` did not resolve the host CPU — this is the line that says
    so."""
    var out = String("x86=")
    out += "1" if CompilationTarget.is_x86() else "0"
    out += " apple-silicon="
    out += "1" if CompilationTarget.is_apple_silicon() else "0"
    out += " neon="
    out += "1" if CompilationTarget._has_feature["neon"]() else "0"
    out += " sha2="
    out += "1" if CompilationTarget._has_feature["sha2"]() else "0"
    out += " aes="
    out += "1" if CompilationTarget._has_feature["aes"]() else "0"
    out += " sha="
    out += "1" if CompilationTarget._has_feature["sha"]() else "0"
    out += " ssse3="
    out += "1" if CompilationTarget._has_feature["ssse3"]() else "0"
    out += " sse4.1="
    out += "1" if CompilationTarget._has_feature["sse4.1"]() else "0"
    return out^


# ---------------------------------------------------------------------------
# Scalar backend (FIPS 180-4 §6.2, portable)
# ---------------------------------------------------------------------------


@always_inline
def _rotr(x: UInt32, n: Int) -> UInt32:
    """Right rotation. Both operands must be `UInt32`: Mojo's SIMD shifts
    reject a mixed-width right-hand side."""
    var s = UInt32(n)
    return (x >> s) | (x << (UInt32(32) - s))


@always_inline
def _load_be16(data: Span[UInt8, _], start: Int) -> SIMD[DType.uint32, 16]:
    """The block's 16 big-endian words, in one unaligned 64-byte load."""
    var p = data.unsafe_ptr().unsafe_offset(start).unsafe_bitcast[UInt32]()
    return llvm_intrinsic["llvm.bswap", SIMD[DType.uint32, 16]](
        p.unsafe_load[width=16, alignment=1]()
    )


def _blocks_scalar(
    mut hv: SIMD[DType.uint32, 8], data: Span[UInt8, _], start: Int, nblocks: Int
):
    """FIPS 180-4 compression, unrolled over the 64 rounds with a 16-word
    rolling message schedule — every `w` index is a compile-time constant, so
    the schedule lives in registers instead of on the stack."""
    var a = hv[0]
    var b = hv[1]
    var c = hv[2]
    var d = hv[3]
    var e = hv[4]
    var f = hv[5]
    var g = hv[6]
    var h = hv[7]
    var off = start

    for _ in range(nblocks):
        var s0: UInt32
        var s1: UInt32
        var t1: UInt32
        var t2: UInt32
        var w = _load_be16(data, off)
        var sa = a
        var sb = b
        var sc = c
        var sd = d
        var se = e
        var sf = f
        var sg = g
        var sh = h

        comptime for t in range(64):
            comptime if t >= 16:
                var x = w[(t + 1) % 16]
                var y = w[(t + 14) % 16]
                s0 = _rotr(x, 7) ^ _rotr(x, 18) ^ (x >> UInt32(3))
                s1 = _rotr(y, 17) ^ _rotr(y, 19) ^ (y >> UInt32(10))
                w[t % 16] = w[t % 16] + s0 + w[(t + 9) % 16] + s1
            s1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
            t1 = h + s1 + ((e & f) ^ ((~e) & g)) + _K[t] + w[t % 16]
            s0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)
            t2 = s0 + ((a & b) ^ (a & c) ^ (b & c))
            h = g
            g = f
            f = e
            e = d + t1
            d = c
            c = b
            b = a
            a = t1 + t2

        a += sa
        b += sb
        c += sc
        d += sd
        e += se
        f += sf
        g += sg
        h += sh
        off += SHA256_BLOCK_SIZE

    hv = SIMD[DType.uint32, 8](a, b, c, d, e, f, g, h)


# ---------------------------------------------------------------------------
# ARMv8 SHA-2 extension backend
# ---------------------------------------------------------------------------


@always_inline
def _sha256h(abcd: _U4, efgh: _U4, wk: _U4) -> _U4:
    return llvm_intrinsic["llvm.aarch64.crypto.sha256h", _U4](abcd, efgh, wk)


@always_inline
def _sha256h2(efgh: _U4, abcd: _U4, wk: _U4) -> _U4:
    return llvm_intrinsic["llvm.aarch64.crypto.sha256h2", _U4](efgh, abcd, wk)


@always_inline
def _sha256su0(w0: _U4, w4: _U4) -> _U4:
    return llvm_intrinsic["llvm.aarch64.crypto.sha256su0", _U4](w0, w4)


@always_inline
def _sha256su1(tw0: _U4, w8: _U4, w12: _U4) -> _U4:
    return llvm_intrinsic["llvm.aarch64.crypto.sha256su1", _U4](tw0, w8, w12)


def _blocks_arm(
    mut hv: SIMD[DType.uint32, 8], data: Span[UInt8, _], start: Int, nblocks: Int
):
    """The standard four-instruction ARMv8 schedule: 16 groups of four rounds,
    each `sha256h`+`sha256h2` on the (abcd, efgh) state pair, with the first
    twelve groups also running `sha256su0`+`sha256su1` to build the message
    words four rounds' worth ahead. Dataflow follows the reference in ARM's
    own examples and in BoringSSL's `sha256-armv8`."""
    var s0 = hv.slice[4, offset=0]()
    var s1 = hv.slice[4, offset=4]()
    var p = data.unsafe_ptr().unsafe_offset(start).unsafe_bitcast[UInt32]()
    for _ in range(nblocks):
        var save: _U4
        var wk: _U4
        var abef = s0
        var cdgh = s1
        var m0 = llvm_intrinsic["llvm.bswap", _U4](
            p.unsafe_load[width=4, alignment=1]()
        )
        var m1 = llvm_intrinsic["llvm.bswap", _U4](
            p.unsafe_offset(4).unsafe_load[width=4, alignment=1]()
        )
        var m2 = llvm_intrinsic["llvm.bswap", _U4](
            p.unsafe_offset(8).unsafe_load[width=4, alignment=1]()
        )
        var m3 = llvm_intrinsic["llvm.bswap", _U4](
            p.unsafe_offset(12).unsafe_load[width=4, alignment=1]()
        )
        var cur = m0 + _K.slice[4, offset=0]()

        # Groups 0-11 (rounds 0-47): rounds plus message schedule. Group j
        # consumes `m[j % 4] + K[4j]`, prepares `m[(j+1) % 4] + K[4(j+1)]` for
        # its successor, and rolls `m[j % 4]` forward sixteen words.
        comptime for gr in range(3):
            m0 = _sha256su0(m0, m1)
            save = s0
            wk = m1 + _K.slice[4, offset = 16 * gr + 4]()
            s0 = _sha256h(s0, s1, cur)
            s1 = _sha256h2(s1, save, cur)
            m0 = _sha256su1(m0, m2, m3)
            cur = wk

            m1 = _sha256su0(m1, m2)
            save = s0
            wk = m2 + _K.slice[4, offset = 16 * gr + 8]()
            s0 = _sha256h(s0, s1, cur)
            s1 = _sha256h2(s1, save, cur)
            m1 = _sha256su1(m1, m3, m0)
            cur = wk

            m2 = _sha256su0(m2, m3)
            save = s0
            wk = m3 + _K.slice[4, offset = 16 * gr + 12]()
            s0 = _sha256h(s0, s1, cur)
            s1 = _sha256h2(s1, save, cur)
            m2 = _sha256su1(m2, m0, m1)
            cur = wk

            m3 = _sha256su0(m3, m0)
            save = s0
            wk = m0 + _K.slice[4, offset = 16 * gr + 16]()
            s0 = _sha256h(s0, s1, cur)
            s1 = _sha256h2(s1, save, cur)
            m3 = _sha256su1(m3, m1, m2)
            cur = wk

        # Groups 12-15 (rounds 48-63): the schedule is complete.
        save = s0
        wk = m1 + _K.slice[4, offset=52]()
        s0 = _sha256h(s0, s1, cur)
        s1 = _sha256h2(s1, save, cur)
        cur = wk

        save = s0
        wk = m2 + _K.slice[4, offset=56]()
        s0 = _sha256h(s0, s1, cur)
        s1 = _sha256h2(s1, save, cur)
        cur = wk

        save = s0
        wk = m3 + _K.slice[4, offset=60]()
        s0 = _sha256h(s0, s1, cur)
        s1 = _sha256h2(s1, save, cur)
        cur = wk

        save = s0
        s0 = _sha256h(s0, s1, cur)
        s1 = _sha256h2(s1, save, cur)

        s0 += abef
        s1 += cdgh
        p = p.unsafe_offset(16)

    hv = s0.join(s1)


# ---------------------------------------------------------------------------
# x86 SHA-NI backend
# ---------------------------------------------------------------------------


@always_inline
def _rnds2(cdgh: _U4, abef: _U4, wk: _U4) -> _U4:
    return llvm_intrinsic["llvm.x86.sha256rnds2", _U4](cdgh, abef, wk)


@always_inline
def _msg1(a: _U4, b: _U4) -> _U4:
    return llvm_intrinsic["llvm.x86.sha256msg1", _U4](a, b)


@always_inline
def _msg2(a: _U4, b: _U4) -> _U4:
    return llvm_intrinsic["llvm.x86.sha256msg2", _U4](a, b)


@always_inline
def _alignr4(hi: _U4, lo: _U4) -> _U4:
    """`_mm_alignr_epi8(hi, lo, 4)` — the four 32-bit lanes starting one lane
    into the 256-bit concatenation `lo:hi`."""
    return lo.shuffle[1, 2, 3, 4](hi)


def _blocks_x86(
    mut hv: SIMD[DType.uint32, 8], data: Span[UInt8, _], start: Int, nblocks: Int
):
    """Intel's SHA-NI schedule, as laid out in Intel's SHA Extensions white
    paper and implemented in OpenSSL/BoringSSL's `sha256-x86`.

    SHA-NI keeps the state as ABEF/CDGH rather than ABCD/EFGH, and
    `sha256rnds2` does *two* rounds per instruction using only the low two
    words of its constant operand, so each group of four rounds is two
    `rnds2` with the upper half of `W+K` shuffled down in between. Group `j`
    consumes `m[j % 4] + K[4j]`; `sha256msg2` (groups 3-14) finishes the words
    for group `j+1` and `sha256msg1` (groups 1-12) starts the ones for group
    `j+2`.
    """
    var abcd = hv.slice[4, offset=0]()
    var efgh = hv.slice[4, offset=4]()
    # abef = (f, e, b, a) and cdgh = (h, g, d, c) — the lane order the
    # instruction pair expects (Intel's ABEF/CDGH, written high lane first).
    var s0 = abcd.shuffle[5, 4, 1, 0](efgh)
    var s1 = abcd.shuffle[7, 6, 3, 2](efgh)
    var p = data.unsafe_ptr().unsafe_offset(start).unsafe_bitcast[UInt32]()
    for _ in range(nblocks):
        var msg: _U4
        var tmp: _U4
        var abef = s0
        var cdgh = s1
        var m = llvm_intrinsic["llvm.bswap", SIMD[DType.uint32, 16]](
            p.unsafe_load[width=16, alignment=1]()
        )

        comptime for j in range(16):
            comptime i = j % 4
            msg = m.slice[4, offset = 4 * i]() + _K.slice[4, offset = 4 * j]()
            s1 = _rnds2(s1, s0, msg)
            comptime if j >= 3 and j <= 14:
                comptime nx = (j + 1) % 4
                tmp = _alignr4(
                    m.slice[4, offset = 4 * i](),
                    m.slice[4, offset = 4 * ((j + 3) % 4)](),
                )
                m = m.insert[offset = 4 * nx](
                    _msg2(
                        m.slice[4, offset = 4 * nx]() + tmp,
                        m.slice[4, offset = 4 * i](),
                    )
                )
            msg = msg.shuffle[2, 3, 2, 3]()
            s0 = _rnds2(s0, s1, msg)
            comptime if j >= 1 and j <= 12:
                comptime pv = (j + 3) % 4
                m = m.insert[offset = 4 * pv](
                    _msg1(
                        m.slice[4, offset = 4 * pv](),
                        m.slice[4, offset = 4 * i](),
                    )
                )

        s0 += abef
        s1 += cdgh
        p = p.unsafe_offset(16)

    # abef/cdgh -> abcd/efgh
    hv = s0.shuffle[3, 2, 7, 6](s1).join(s0.shuffle[1, 0, 5, 4](s1))


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------


@always_inline
def _compress_blocks(
    mut hv: SIMD[DType.uint32, 8], data: Span[UInt8, _], start: Int, nblocks: Int
):
    comptime if _HAS_ARM_SHA2:
        _blocks_arm(hv, data, start, nblocks)
    comptime if _HAS_X86_SHA_NI:
        _blocks_x86(hv, data, start, nblocks)
    comptime if not (_HAS_ARM_SHA2 or _HAS_X86_SHA_NI):
        _blocks_scalar(hv, data, start, nblocks)


def sha256_scalar(data: Span[UInt8, _]) -> List[UInt8]:
    """SHA-256 forced through the portable backend, whatever `_BACKEND` is.

    Exists so the test suite can cross-check the hardware path against the
    reference implementation on the very machine that runs it — the two are
    entirely separate code, and the FIPS vectors alone would not catch a
    schedule bug that only shows up past the first block.
    """
    var padded = List[UInt8](capacity=len(data) + 72)
    padded.extend(data)
    var bitlen = UInt64(len(data)) * UInt64(8)
    padded.append(0x80)
    while len(padded) % SHA256_BLOCK_SIZE != 56:
        padded.append(0)
    for k in range(8):
        padded.append(
            UInt8(Int((bitlen >> UInt64((7 - k) * 8)) & UInt64(0xFF)))
        )
    var state = SIMD[DType.uint32, 8](
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
    )
    _blocks_scalar(
        state, Span(padded), 0, len(padded) // SHA256_BLOCK_SIZE
    )
    var out = List[UInt8](capacity=SHA256_DIGEST_SIZE)
    for k in range(8):
        var v = state[k]
        out.append(UInt8(Int((v >> UInt32(24)) & UInt32(0xFF))))
        out.append(UInt8(Int((v >> UInt32(16)) & UInt32(0xFF))))
        out.append(UInt8(Int((v >> UInt32(8)) & UInt32(0xFF))))
        out.append(UInt8(Int(v & UInt32(0xFF))))
    return out^


struct Sha256(Copyable, Movable):
    """Streaming FIPS 180-4 SHA-256.

    Streaming rather than one-shot because a SigV4 `PUT` has to hash the whole
    payload, which for a data file is larger than anything worth copying into
    one contiguous buffer just to hash it.
    """

    var _h: SIMD[DType.uint32, 8]
    var _block: List[UInt8]
    var _total: Int

    def __init__(out self):
        self._h = SIMD[DType.uint32, 8](
            0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
            0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
        )
        self._block = List[UInt8](capacity=SHA256_BLOCK_SIZE)
        self._total = 0

    def update(mut self, data: Span[UInt8, _]):
        self._total += len(data)
        var i = 0
        var n = len(data)
        # Finish any partial block held over from the previous update.
        if len(self._block) > 0:
            while i < n and len(self._block) < SHA256_BLOCK_SIZE:
                self._block.append(data[i])
                i += 1
            if len(self._block) == SHA256_BLOCK_SIZE:
                var held = self._block^
                self._block = List[UInt8](capacity=SHA256_BLOCK_SIZE)
                _compress_blocks(self._h, Span(held), 0, 1)
        # Then consume every whole block left in the caller's buffer in one
        # call: the state stays in registers across the run.
        var whole = (n - i) // SHA256_BLOCK_SIZE
        if whole > 0:
            _compress_blocks(self._h, data, i, whole)
            i += whole * SHA256_BLOCK_SIZE
        while i < n:
            self._block.append(data[i])
            i += 1

    def digest(self) -> List[UInt8]:
        """The digest of everything fed so far. Does not consume `self`, so a
        caller can keep hashing afterwards."""
        var tail = List[UInt8]()
        for k in range(len(self._block)):
            tail.append(self._block[k])
        var bitlen = UInt64(self._total) * UInt64(8)
        tail.append(0x80)
        while len(tail) % SHA256_BLOCK_SIZE != 56:
            tail.append(0)
        for k in range(8):
            tail.append(
                UInt8(Int((bitlen >> UInt64((7 - k) * 8)) & UInt64(0xFF)))
            )
        var state = self._h
        _compress_blocks(
            state, Span(tail), 0, len(tail) // SHA256_BLOCK_SIZE
        )
        var out = List[UInt8](capacity=SHA256_DIGEST_SIZE)
        for k in range(8):
            var v = state[k]
            out.append(UInt8(Int((v >> UInt32(24)) & UInt32(0xFF))))
            out.append(UInt8(Int((v >> UInt32(16)) & UInt32(0xFF))))
            out.append(UInt8(Int((v >> UInt32(8)) & UInt32(0xFF))))
            out.append(UInt8(Int(v & UInt32(0xFF))))
        return out^


def sha256(data: Span[UInt8, _]) -> List[UInt8]:
    var h = Sha256()
    h.update(data)
    return h.digest()


def sha256_hex(data: Span[UInt8, _]) -> String:
    return to_hex(Span(sha256(data)))


def sha256_hex(s: String) -> String:
    return sha256_hex(s.as_bytes())


# ---------------------------------------------------------------------------
# HMAC (RFC 2104)
# ---------------------------------------------------------------------------


def hmac_sha256(key: Span[UInt8, _], msg: Span[UInt8, _]) -> List[UInt8]:
    """RFC 2104 HMAC with SHA-256. Keys longer than the 64-byte block are
    hashed first; shorter keys are zero-padded."""
    var k = List[UInt8]()
    if len(key) > SHA256_BLOCK_SIZE:
        k = sha256(key)
    else:
        for i in range(len(key)):
            k.append(key[i])
    while len(k) < SHA256_BLOCK_SIZE:
        k.append(0)

    var inner = Sha256()
    var ipad = List[UInt8](capacity=SHA256_BLOCK_SIZE)
    for i in range(SHA256_BLOCK_SIZE):
        ipad.append(k[i] ^ 0x36)
    inner.update(Span(ipad))
    inner.update(msg)
    var inner_digest = inner.digest()

    var outer = Sha256()
    var opad = List[UInt8](capacity=SHA256_BLOCK_SIZE)
    for i in range(SHA256_BLOCK_SIZE):
        opad.append(k[i] ^ 0x5C)
    outer.update(Span(opad))
    outer.update(Span(inner_digest))
    return outer.digest()


def hmac_sha256(key: Span[UInt8, _], msg: String) -> List[UInt8]:
    return hmac_sha256(key, msg.as_bytes())


def hmac_sha256_hex(key: Span[UInt8, _], msg: String) -> String:
    return to_hex(Span(hmac_sha256(key, msg.as_bytes())))


# ---------------------------------------------------------------------------
# Hex
# ---------------------------------------------------------------------------


comptime _HEXLOW = String("0123456789abcdef")


def to_hex(data: Span[UInt8, _]) -> String:
    """Lowercase hex — the case SigV4's canonical request requires."""
    var out = List[UInt8](capacity=2 * len(data) + 1)
    var tbl = _HEXLOW.as_bytes()
    for k in range(len(data)):
        out.append(tbl[Int(data[k] >> 4)])
        out.append(tbl[Int(data[k] & 0xF)])
    return String(StringSlice(unsafe_from_utf8=Span(out)))


def from_hex(s: String) raises -> List[UInt8]:
    var b = s.as_bytes()
    if len(b) % 2 != 0:
        raise Error("objectstore.crypto: odd-length hex string")
    var out = List[UInt8](capacity=len(b) // 2)
    for k in range(0, len(b), 2):
        out.append(UInt8((_nibble(b[k]) << 4) | _nibble(b[k + 1])))
    return out^


def _nibble(c: UInt8) raises -> Int:
    if c >= 48 and c <= 57:
        return Int(c) - 48
    if c >= 97 and c <= 102:
        return Int(c) - 87
    if c >= 65 and c <= 70:
        return Int(c) - 55
    raise Error("objectstore.crypto: bad hex digit")
