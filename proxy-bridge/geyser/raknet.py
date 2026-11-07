"""RakNet datagram walker for the frames this bridge is allowed to rewrite.

Proven against ReliabilityLayer internal-packet parse FUN_00417bd0 (server file
0x317bd0) and against every untruncated 0x84 datagram in the checked-in join
pcap. Two integer layouts must not be mixed:

- Generic BitStream reads (dataBitLength uint16, split count/index uint32,
  split id uint16) are big-endian on the wire because IsNetworkOrderInternal
  is 0 and those reads reverse bytes.
- Network ids inside a DST message are little-endian right-aligned bits.
  That codec lives in bitstream.py, not here.

A user datagram has IsValid set and isACK/isNAK clear (``(b0 & 0xE0) == 0x80``),
with the two alignment bits clear. isPacketPair, isContinuousSend and
needsBAndAs are flag bits in that same byte; a world burst sets
isContinuousSend and the byte is ``0x88`` or ``0x8c``. Bytes 1-3 are the
datagram number (uint24 LE). ACK (``0xC0``) is not parsed; ``nak_numbers``
reads a NAK (``0xA0``).

The first byte of an internal packet is ``rrr s 0000``: 3 reliability bits, the
split bit, then zero padding from the byte align. A non-zero low nibble means
this model does not match the bytes; the caller must forward the datagram
unchanged.
"""
from __future__ import annotations

from dataclasses import dataclass

# reliability - 2 < 3 in the decompile. ACK-receipt reliabilities 6 and 7 are
# not in this set; do not invent a message number for them.
_RELIABLE_MSG = (2, 3, 4)
# Read before the ordering block.
_SEQUENCED = (1, 4)
# Mask 0x9a: reliabilities 1, 3, 4, 7. uint24 ordering index, then one channel byte.
_ORDERED = (1, 3, 4, 7)
# A larger count is not held. The datagram is left for the caller to forward.
_MAX_SPLIT_COUNT = 4096


def is_data_datagram(flags: int) -> bool:
    """True for a RakNet user datagram, including a continuous-send burst.

    Bit 7 is IsValid, bit 6 isACK, bit 5 isNAK. Bits 4..2 are isPacketPair,
    isContinuousSend and needsBAndAs. The low two bits are the align padding.
    """
    return (flags & 0xE0) == 0x80 and (flags & 0x03) == 0


def datagram_number(data: bytes) -> int | None:
    if len(data) < 4 or not is_data_datagram(data[0]):
        return None
    return data[1] | (data[2] << 8) | (data[3] << 16)


def nak_numbers(data: bytes) -> list[int]:
    """Datagram numbers in a NAK: flags, u16 BE range count, then per range a
    minEqualsMax byte, u24 LE min and (unless equal) u24 LE max."""
    if len(data) < 3 or (data[0] & 0xE0) != 0xA0:
        return []
    return _range_numbers(data, 1)


def ack_numbers(data: bytes) -> list[int]:
    """Datagram numbers in an ACK. Same range list as a NAK; when hasBAndAS
    (bit 5) is set a 4-byte float sits between the flags and the count."""
    if len(data) < 3 or (data[0] & 0xC0) != 0xC0:
        return []
    return _range_numbers(data, 5 if data[0] & 0x20 else 1)


def _range_numbers(data: bytes, pos: int) -> list[int]:
    if pos + 2 > len(data):
        return []
    count = int.from_bytes(data[pos:pos + 2], "big")
    out: list[int] = []
    pos += 2
    for _ in range(count):
        if pos + 4 > len(data):
            return out
        single = data[pos]
        lo = int.from_bytes(data[pos + 1:pos + 4], "little")
        pos += 4
        hi = lo
        if not single:
            if pos + 3 > len(data):
                return out
            hi = int.from_bytes(data[pos:pos + 3], "little")
            pos += 3
        out.extend(range(lo, min(hi, lo + 4096) + 1))
    return out


def ack_datagram(number: int) -> bytes:
    """One-range ACK for a single datagram number. Matches the phone's 7-byte ACKs."""
    return bytes((0xC0, 0x00, 0x01, 0x01, number & 0xFF, (number >> 8) & 0xFF, (number >> 16) & 0xFF))


@dataclass(frozen=True)
class InternalPacket:
    """One internal packet. ``header`` is every byte before ``payload``."""

    header: bytes
    bitlen: int
    payload: bytes
    reliability: int
    split: tuple[int, int, int] | None  # count, split_id, index


def walk_datagram(data: bytes) -> list[InternalPacket] | None:
    """Return the internal packets, or None if the datagram is not a simple data frame.

    None means "do not rewrite". The walk must consume the buffer exactly.
    """
    if len(data) < 4 or not is_data_datagram(data[0]):
        return None
    packets: list[InternalPacket] = []
    offset = 4
    while offset < len(data):
        parsed = _read_internal(data, offset)
        if parsed is None:
            return None
        packet, offset = parsed
        packets.append(packet)
    if offset != len(data) or not packets:
        return None
    return packets


def build_datagram(head: bytes, packets: list[InternalPacket]) -> bytes:
    """head is the 4-byte outer header (flags + datagram number)."""
    parts = [head]
    for packet in packets:
        parts.append(packet.header)
        parts.append(packet.payload)
    return b"".join(parts)


def replace_payload(packet: InternalPacket, payload: bytes, bitlen: int) -> InternalPacket:
    """New internal packet with the same reliability tail and an updated uint16 BE bitlen."""
    if len(packet.header) < 3:
        raise ValueError("internal header shorter than flags + bitlen")
    header = bytearray(packet.header)
    header[1] = (bitlen >> 8) & 0xFF
    header[2] = bitlen & 0xFF
    return InternalPacket(bytes(header), bitlen, payload, packet.reliability, packet.split)


def _read_internal(data: bytes, offset: int) -> tuple[InternalPacket, int] | None:
    start = offset
    if offset >= len(data):
        return None
    flags = data[offset]
    if flags & 0x0F:
        return None
    reliability = flags >> 5
    has_split = bool(flags & 0x10)
    offset += 1
    if offset + 2 > len(data):
        return None
    bitlen = (data[offset] << 8) | data[offset + 1]
    offset += 2
    # puVar5[6] != 0 is required before a split piece can be reassembled.
    if bitlen <= 0:
        return None

    def take(n: int) -> bool:
        nonlocal offset
        if offset + n > len(data):
            return False
        offset += n
        return True

    if reliability in _RELIABLE_MSG and not take(3):
        return None
    if reliability in _SEQUENCED and not take(3):
        return None
    if reliability in _ORDERED and not take(4):
        return None

    split = None
    if has_split:
        if offset + 10 > len(data):
            return None
        count = int.from_bytes(data[offset:offset + 4], "big")
        split_id = int.from_bytes(data[offset + 4:offset + 6], "big")
        index = int.from_bytes(data[offset + 6:offset + 10], "big")
        offset += 10
        if not (0 < count <= _MAX_SPLIT_COUNT) or index >= count:
            return None
        split = (count, split_id, index)

    nbytes = (bitlen + 7) // 8
    if offset + nbytes > len(data):
        return None
    header = data[start:offset]
    payload = data[offset:offset + nbytes]
    offset += nbytes
    return InternalPacket(header, bitlen, payload, reliability, split), offset
