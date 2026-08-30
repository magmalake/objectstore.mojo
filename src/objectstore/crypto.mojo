"""`objectstore.crypto` — SHA-256, HMAC-SHA256 and hex, in pure Mojo.

AWS SigV4 is built entirely out of these two primitives, and nothing in the
Mojo ecosystem provides either: hashes.mojo covers the *non-cryptographic*
hashes Iceberg needs for partition transforms (murmur3, xxhash, CRC32), and no
conda-resolvable package offers SHA-2. Rather than pull OpenSSL in through a
second FFI shim — libcurl already links it, but its EVP surface is a moving
target across conda builds — this module implements FIPS 180-4 and RFC 2104
directly. It is a few hundred lines, dependency-free, and its cost is
irrelevant next to the network round trip it authenticates.

If a general-purpose home ever appears, this belongs in hashes.mojo.
"""


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


@always_inline
def _rotr(x: UInt32, n: Int) -> UInt32:
    """Right rotation. Both operands must be `UInt32`: Mojo's SIMD shifts
    reject a mixed-width right-hand side."""
    var s = UInt32(n)
    return (x >> s) | (x << (UInt32(32) - s))


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

    def _compress(mut self, data: Span[UInt8, _], start: Int):
        var w = SIMD[DType.uint32, 64](0)
        for t in range(16):
            var o = start + t * 4
            w[t] = (
                (UInt32(Int(data[o])) << UInt32(24))
                | (UInt32(Int(data[o + 1])) << UInt32(16))
                | (UInt32(Int(data[o + 2])) << UInt32(8))
                | UInt32(Int(data[o + 3]))
            )
        for t in range(16, 64):
            var s0 = _rotr(w[t - 15], 7) ^ _rotr(w[t - 15], 18) ^ (
                w[t - 15] >> UInt32(3)
            )
            var s1 = _rotr(w[t - 2], 17) ^ _rotr(w[t - 2], 19) ^ (
                w[t - 2] >> UInt32(10)
            )
            w[t] = w[t - 16] + s0 + w[t - 7] + s1

        var a = self._h[0]
        var b = self._h[1]
        var c = self._h[2]
        var d = self._h[3]
        var e = self._h[4]
        var f = self._h[5]
        var g = self._h[6]
        var h = self._h[7]

        for t in range(64):
            var s1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
            var ch = (e & f) ^ ((~e) & g)
            var t1 = h + s1 + ch + _K[t] + w[t]
            var s0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)
            var maj = (a & b) ^ (a & c) ^ (b & c)
            var t2 = s0 + maj
            h = g
            g = f
            f = e
            e = d + t1
            d = c
            c = b
            b = a
            a = t1 + t2

        self._h[0] += a
        self._h[1] += b
        self._h[2] += c
        self._h[3] += d
        self._h[4] += e
        self._h[5] += f
        self._h[6] += g
        self._h[7] += h

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
                self._compress(Span(held), 0)
        # Then consume whole blocks straight out of the caller's buffer.
        while n - i >= SHA256_BLOCK_SIZE:
            self._compress(data, i)
            i += SHA256_BLOCK_SIZE
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
        var clone = self.copy()
        var s = Span(tail)
        var off = 0
        while off < len(tail):
            clone._compress(s, off)
            off += SHA256_BLOCK_SIZE
        var out = List[UInt8](capacity=SHA256_DIGEST_SIZE)
        for k in range(8):
            var v = clone._h[k]
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
