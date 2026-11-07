"""RakNet BitStream primitives (MSB-first), reader + writer.

DST / RakNet serialize bits MSB-first: the first bit written occupies the top
bit (0x80) of byte 0. These primitives mirror RakNet's BitStream so we can parse
a construction/serialize frame exactly the way the mobile client does, then
re-emit it in the format the mobile client expects.

Only the primitives actually used by ReplicaManager3::OnConstruction / OnSerialize
are implemented (verified against libDontStarve.so arm64 v64020301):
  ReadBit, ReadBits, AlignToByteBoundary, ReadAlignedBytes,
  ReadBitsFromIntegerRange (range-coded ints), and the symmetric writer ops.

NOTE on endianness: both binaries' BitStream::IsNetworkOrderInternal returns 0
(server FUN_003ecf70 stores 0; mobile VA 0x8f5740 is `mov w0, wzr; ret`).
WriteBits/ReadBits therefore do NOT byte-swap. A multi-byte integer is the
little-endian memory image, written with rightAligned=true: full low bytes
first, then the low bits of the next byte. `read_bits`/`write_bits` are the
raw MSB-first stream and are NOT that integer layout. Use `read_le_bits` /
`write_le_bits` for network ids and ReadBitsFromIntegerRange.

RakString length is a u16 in that LE layout (16 bits, so just the two bytes
swapped relative to `read_bits`), then raw aligned bytes. No Huffman.
"""
from __future__ import annotations


class BitReader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0  # bit offset, MSB-first
        self.nbits = len(data) * 8

    def remaining(self) -> int:
        return self.nbits - self.pos

    def read_bit(self) -> int:
        if self.pos >= self.nbits:
            raise EOFError("read_bit past end")
        byte = self.data[self.pos >> 3]
        bit = (byte >> (7 - (self.pos & 7))) & 1
        self.pos += 1
        return bit

    def read_bits(self, n: int) -> int:
        """Read n bits MSB-first; first bit read is the MSB of the result."""
        if n < 0:
            raise ValueError("n<0")
        if self.pos + n > self.nbits:
            raise EOFError(f"read_bits({n}) past end at pos={self.pos}/{self.nbits}")
        v = 0
        for _ in range(n):
            v = (v << 1) | self.read_bit()
        return v

    def read_le_bits(self, n: int) -> int:
        """RakNet ReadBits(..., rightAligned=1) into an LE integer, no byte swap.

        Full bytes land in little-endian order. A trailing partial byte is the
        low (n % 8) bits of the next byte. Numerically this is the low n bits.
        """
        if n < 0:
            raise ValueError("n<0")
        if n == 0:
            return 0
        full, rem = divmod(n, 8)
        buf = bytearray(full + (1 if rem else 0))
        for i in range(full):
            buf[i] = self.read_bits(8)
        if rem:
            buf[full] = self.read_bits(rem)
        return int.from_bytes(buf, "little")

    def align(self) -> None:
        if self.pos & 7:
            self.pos = (self.pos + 7) & ~7

    def read_aligned_bytes(self, n: int) -> bytes:
        self.align()
        start = self.pos >> 3
        if start + n > len(self.data):
            raise EOFError(f"read_aligned_bytes({n}) past end")
        self.pos += n * 8
        return self.data[start:start + n]

    def read_u16_rev(self) -> int:
        """u16 as RakString length is written WriteBits(16) with byte reversal on LE."""
        raw = self.read_bits(16)  # MSB-first 16 bits = big-endian value
        # RakString::Serialize stored strlen as u16 then ReverseBytes on LE -> wire is LE.
        # read_bits gives big-endian interpretation; swap to little-endian:
        return ((raw & 0xFF) << 8) | ((raw >> 8) & 0xFF)

    def read_rakstring(self) -> bytes:
        """RakString::Deserialize = u16 length + ReadAlignedBytes(len). Raw, no Huffman."""
        n = self.read_u16_rev()
        if n == 0:
            return b""
        return self.read_aligned_bytes(n)

    def read_ranged(self, minimum: int, maximum: int, allow_outside: bool = False, width: int = 32) -> int:
        """RakNet ReadBitsFromIntegerRange, IsNetworkOrderInternal == 0.

        requiredBits = 32 - clz32(max-min) = bit_length(max-min). allowOutside
        reads one flag bit; if set, the next `width` bits are a byte-swapped
        full value (the server reader swaps after ReadBits). Unsigned int
        call sites in OnConstruction use width 32.
        """
        if maximum < minimum:
            raise ValueError("maximum < minimum")
        if allow_outside and self.read_bit():
            if width <= 0 or width % 8:
                raise ValueError("outside-range width must be a positive multiple of 8")
            raw = self.read_le_bits(width)
            return int.from_bytes(raw.to_bytes(width // 8, "little"), "big")
        req = (maximum - minimum).bit_length()
        return minimum + (self.read_le_bits(req) if req else 0)


class BitWriter:
    def __init__(self):
        self.bits: list[int] = []

    def write_bit(self, b: int) -> None:
        self.bits.append(b & 1)

    def write_bits(self, value: int, n: int) -> None:
        for i in range(n - 1, -1, -1):
            self.bits.append((value >> i) & 1)

    def write_le_bits(self, value: int, n: int) -> None:
        """Inverse of BitReader.read_le_bits. Writes the low n bits."""
        if n < 0:
            raise ValueError("n<0")
        if n == 0:
            return
        nbytes = (n + 7) // 8
        raw = (int(value) & ((1 << (nbytes * 8)) - 1)).to_bytes(nbytes, "little")
        full, rem = divmod(n, 8)
        for i in range(full):
            self.write_bits(raw[i], 8)
        if rem:
            self.write_bits(raw[full], rem)

    def align(self) -> None:
        while len(self.bits) & 7:
            self.bits.append(0)

    def write_aligned_bytes(self, data: bytes) -> None:
        self.align()
        for byte in data:
            self.write_bits(byte, 8)

    def write_u16_rev(self, v: int) -> None:
        self.write_bits(((v & 0xFF) << 8) | ((v >> 8) & 0xFF), 16)

    def write_rakstring(self, s: bytes) -> None:
        self.write_u16_rev(len(s))
        if s:
            self.write_aligned_bytes(s)

    def write_ranged(self, value: int, minimum: int, maximum: int, allow_outside: bool = False, width: int = 32) -> None:
        """Inverse of BitReader.read_ranged for IsNetworkOrderInternal == 0."""
        if maximum < minimum:
            raise ValueError("maximum < minimum")
        if allow_outside and (value < minimum or value > maximum):
            if width <= 0 or width % 8:
                raise ValueError("outside-range width must be a positive multiple of 8")
            self.write_bit(1)
            swapped = int.from_bytes(int(value).to_bytes(width // 8, "little"), "big")
            self.write_le_bits(swapped, width)
            return
        if allow_outside:
            self.write_bit(0)
        req = (maximum - minimum).bit_length()
        if req:
            self.write_le_bits(value - minimum, req)

    def to_bytes(self) -> bytes:
        out = bytearray((len(self.bits) + 7) // 8)
        for i, b in enumerate(self.bits):
            if b:
                out[i >> 3] |= 1 << (7 - (i & 7))
        return bytes(out)

    def bit_len(self) -> int:
        return len(self.bits)
