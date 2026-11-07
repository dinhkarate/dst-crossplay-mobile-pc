"""Checks for the 0x87 re-encoder, plus a scan that only runs on a real 0x87 frame.

The checked-in sample is a 0x2a download-started buffer. It is refused on purpose.
The synthetic tests build a server-width frame (24-bit network ids) and check that
an 18-bit parse recovers the planted payload only after re-encoding. They do not
prove a live server payload is a raw RakString.

Datagram tests replay the checked-in handshake pcap. Every datagram must come
back byte-identical, because that capture has no 0x87 body.

Run from proxy-bridge/:  python3 -m geyser.selftest
"""
from __future__ import annotations
import os
import struct
from .bitstream import BitReader, BitWriter
from .raknet import ack_datagram, build_datagram, datagram_number, is_data_datagram, walk_datagram
from .translator import (
    GeyserTranslator,
    TranslatorConfig,
    _SPLIT_TIMEOUT_S,
    _reencode_construction,
    _reencode_destruction,
    _reencode_serialize,
    _rewrite_serialize_records,
    klei_to_vanilla_construction,
)

SAMPLE = os.path.join(os.path.dirname(__file__), "sample_construction_0x2a.bin")
LIVE_FRAME = "/tmp/dst-join/frame87.bin"
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
CAPTURES = os.path.join(ROOT, "docs", "analysis", "captures")

# DST initial-construction prefabs are world singletons; names are lowercase ascii.
def _plausible(name: bytes) -> bool:
    if not (3 <= len(name) <= 40):
        return False
    return all(0x61 <= c <= 0x7A or 0x30 <= c <= 0x39 or c in (0x5F,) for c in name)


def scan(frame: bytes):
    body = frame[1:] if frame and frame[0] == 0x87 else frame  # drop msg id
    nbits = len(body) * 8
    hits = []
    for p in range(0, nbits - 16):
        r = BitReader(body)
        r.pos = p
        try:
            n = r.read_u16_rev()
            if not (3 <= n <= 40):
                continue
            name = r.read_aligned_bytes(n)
        except Exception:
            continue
        if _plausible(name):
            hits.append((p, n, name.decode("latin1")))
    return hits


def _expect(cond: bool, msg: str) -> None:
    if not cond:
        raise AssertionError(msg)


def _copy_n(src: BitReader, dst: BitWriter, n: int) -> None:
    while n > 0:
        k = 32 if n >= 32 else n
        dst.write_bits(src.read_bits(k), k)
        n -= k


def test_le_layout() -> None:
    """Lock WriteBits(rightAligned) with IsNetworkOrderInternal == 0.

    24-bit 0x12345 is the three little-endian bytes. 18-bit 0x2ABCD is two
    bytes plus the low 2 bits (1,0) in the next byte's high end. Ranged 7
    (0..1023, allowOutside) is a 0 flag then 10 LE bits of 7, packed as 03 80.
    """
    w = BitWriter()
    w.write_le_bits(0x12345, 24)
    _expect(w.to_bytes() == bytes([0x45, 0x23, 0x01]), w.to_bytes().hex())

    w = BitWriter()
    w.write_le_bits(0x2ABCD, 18)
    _expect(w.to_bytes() == bytes([0xCD, 0xAB, 0x80]), w.to_bytes().hex())

    w = BitWriter()
    w.write_ranged(7, 0, 0x3FF, allow_outside=True)
    raw = w.to_bytes()
    _expect(raw == bytes([0x03, 0x80]), raw.hex())
    _expect(BitReader(raw).read_ranged(0, 0x3FF, allow_outside=True) == 7, "ranged 7")

    w = BitWriter()
    w.write_ranged(1024, 0, 0x3FF, allow_outside=True)
    got = BitReader(w.to_bytes()).read_ranged(0, 0x3FF, allow_outside=True)
    _expect(got == 1024, f"outside-range value {got}")


def _name_payload(name: bytes) -> BitWriter:
    w = BitWriter()
    w.write_rakstring(name)
    return w


def _server_frame(records: list, destructions: list) -> tuple[bytes, int]:
    """records: (net_id, flag, payload writer). destructions: (net_id, guid int)."""
    w = BitWriter()
    w.write_bits(0x87, 8)
    w.write_bit(1 if records else 0)
    if records:
        w.write_ranged(len(records), 0, 0x3FF, allow_outside=True)
    w.write_bit(1 if destructions else 0)
    if destructions:
        w.write_ranged(len(destructions), 0, 0x3FF, allow_outside=True)
    for net_id, flag, payload in records:
        w.write_le_bits(net_id, 24)
        w.write_bit(flag)
        n = payload.bit_len()
        w.write_ranged(n, 0, 0x3FF, allow_outside=True)
        _copy_n(BitReader(payload.to_bytes()), w, n)
    for net_id, guid in destructions:
        w.write_le_bits(net_id, 24)
        w.write_le_bits(guid, 64)
    return w.to_bytes(), w.bit_len()


def _parse(frame: bytes, id_bits: int):
    r = BitReader(frame)
    _expect(r.read_bits(8) == 0x87, "msg id")
    has_c = r.read_bit()
    c_count = r.read_ranged(0, 0x3FF, allow_outside=True) if has_c else 0
    has_d = r.read_bit()
    d_count = r.read_ranged(0, 0x3FF, allow_outside=True) if has_d else 0
    recs = []
    for _ in range(c_count):
        net_id = r.read_le_bits(id_bits)
        flag = r.read_bit()
        n = r.read_ranged(0, 0x3FF, allow_outside=True)
        payload = BitWriter()
        _copy_n(r, payload, n)
        recs.append((net_id, flag, payload))
    dests = []
    for _ in range(d_count):
        net_id = r.read_le_bits(id_bits)
        guid = r.read_le_bits(64)
        dests.append((net_id, guid))
    return recs, dests


def _rak_name(payload: BitWriter) -> bytes:
    return BitReader(payload.to_bytes()).read_rakstring()


def test_roundtrip() -> None:
    evergreen = _name_payload(b"evergreen")
    firepit = _name_payload(b"firepit")
    wide_bits = BitWriter()
    for _ in range(32):
        wide_bits.write_le_bits(0xA5, 32)  # 1024 bits, forces allowOutside
    frame, frame_bits = _server_frame(
        [(0x11, 0, evergreen), (0x3FFFF, 1, firepit), (0x7, 0, wide_bits)],
        [(0x42, 0xA5A5A5A5A5A5A5A5)],
    )
    _expect((frame_bits + 7) // 8 == len(frame), "frame byte length")
    server_recs, server_dests = _parse(frame, 24)
    _expect(_rak_name(server_recs[0][2]) == b"evergreen", "server parse name")
    _expect(server_dests[0] == (0x42, 0xA5A5A5A5A5A5A5A5), "server parse guid")

    try:
        shifted, _ = _parse(frame, 18)
        shifted_name = _rak_name(shifted[0][2])
    except EOFError:
        shifted_name = b""
    _expect(shifted_name != b"evergreen", "18-bit read of a 24-bit frame must miss the name")

    cfg = TranslatorConfig(translate_construction=True)
    out = klei_to_vanilla_construction(frame, cfg)
    _expect(out != frame and out[0] == 0x87, "rewritten 0x87")
    recs, dests = _parse(out, 18)
    _expect(len(recs) == 3 and len(dests) == 1, f"counts {len(recs)} {len(dests)}")
    _expect(recs[0][0] == 0x11 and recs[0][1] == 0, recs[0][:2])
    _expect(_rak_name(recs[0][2]) == b"evergreen", "mobile name 1")
    _expect(recs[1][0] == 0x3FFFF and recs[1][1] == 1, recs[1][:2])
    _expect(_rak_name(recs[1][2]) == b"firepit", "mobile name 2")
    _expect(recs[2][2].bit_len() == 1024, f"outside length {recs[2][2].bit_len()}")
    _expect(recs[2][2].to_bytes() == wide_bits.to_bytes(), "1024 payload bits changed")
    _expect(dests[0] == (0x42, 0xA5A5A5A5A5A5A5A5), f"guid {dests[0]}")

    # An id that does not fit in 18 bits must passthrough the whole frame.
    too_wide, _too_wide_bits = _server_frame([(1 << 18, 0, evergreen)], [])
    same = klei_to_vanilla_construction(too_wide, cfg)
    _expect(same == too_wide, "wide id was rewritten")

    off = klei_to_vanilla_construction(frame, TranslatorConfig(translate_construction=False))
    _expect(off == frame, "flag off still rewrote")


def _tx() -> GeyserTranslator:
    return GeyserTranslator(TranslatorConfig(enabled=True, translate_construction=True))


def _peer():
    return ("192.168.1.2", 40000)


def _wrap(payload: bytes, bitlen: int, dgram_num: int, msg_num: int, flags: int = 0x60,
          split: tuple[int, int, int] | None = None) -> bytes:
    """rel 3 (or rel 3 + split) datagram. Ordering index and channel stay 0."""
    header = bytearray([
        flags,
        (bitlen >> 8) & 0xFF,
        bitlen & 0xFF,
        msg_num & 0xFF, (msg_num >> 8) & 0xFF, (msg_num >> 16) & 0xFF,
        0, 0, 0,
        0,
    ])
    if split is not None:
        count, split_id, index = split
        header += count.to_bytes(4, "big")
        header += split_id.to_bytes(2, "big")
        header += index.to_bytes(4, "big")
    head = bytes((0x84, dgram_num & 0xFF, (dgram_num >> 8) & 0xFF, (dgram_num >> 16) & 0xFF))
    return head + bytes(header) + payload


def _sample_frame() -> tuple[bytes, int]:
    return _server_frame([
        (0x11, 0, _name_payload(b"evergreen")),
        (0x42, 1, _name_payload(b"firepit")),
    ], [])


def test_config_accepts_log() -> None:
    seen = []
    cfg = TranslatorConfig(enabled=True, translate_construction=True, log=seen.append)
    GeyserTranslator(cfg)._log("hi")
    _expect(seen == ["hi"], f"log callback {seen}")


def test_datagram_rewrite() -> None:
    frame, bitlen = _sample_frame()
    cfg = TranslatorConfig(translate_construction=True)
    translated = klei_to_vanilla_construction(frame, cfg)
    encoded = _reencode_construction(frame)
    _expect(encoded is not None and encoded[0] == translated, "bit length helper diverged")
    _expect(encoded[1] == bitlen - 12, f"two ids should save 12 bits, {bitlen}->{encoded[1]}")

    original = _wrap(frame, bitlen, dgram_num=9, msg_num=4)
    tx = _tx()
    outs = tx.translate_datagram("s2c", original, peer=_peer(), now=0.0)
    _expect(len(outs) == 1, f"non-split emits one datagram, got {len(outs)}")
    out = outs[0]
    _expect(out[:4] == original[:4], "datagram number changed")
    _expect(out[4] == 0x60, "reliability changed")
    _expect(out[7:14] == original[7:14], "message number or ordering changed")
    new_bits = (out[5] << 8) | out[6]
    _expect(out[14:] == translated, "payload is not the 18-bit frame")
    _expect(new_bits == encoded[1], f"datagram bitlen {new_bits} != writer {encoded[1]}")
    _expect((new_bits + 7) // 8 == len(out) - 14, "bitlen does not match payload bytes")
    recs, _dests = _parse(out[14:], 18)
    _expect(_rak_name(recs[0][2]) == b"evergreen", "wrapped mobile name")

    # The same bytes from the phone are not rewritten: mobile already sends 18-bit ids.
    _expect(tx.translate_datagram("c2s", original, peer=_peer(), now=0.0) == [original], "c2s rewritten")
    off = GeyserTranslator(TranslatorConfig(enabled=True, translate_construction=False))
    _expect(off.translate_datagram("s2c", original, peer=_peer(), now=0.0) == [original], "flag off rewritten")

    wide, wide_bits = _server_frame([(1 << 18, 0, _name_payload(b"evergreen"))], [])
    wide_d = _wrap(wide, wide_bits, dgram_num=3, msg_num=1)
    _expect(tx.translate_datagram("s2c", wide_d, peer=_peer(), now=1.0) == [wide_d], "wide id rewritten")

    ack = b"\xc0\x00\x01\x01\x07\x00\x00"
    _expect(tx.translate_datagram("s2c", ack, peer=_peer(), now=1.0) == [ack], "ACK changed")
    # 0x8c is a real data datagram only when the internal packets parse.
    # A bare frame after the flag is forwarded unchanged.
    band = bytes([0x8C, 0x01, 0x00, 0x00]) + frame
    _expect(tx.translate_datagram("s2c", band, peer=_peer(), now=1.0) == [band], "malformed 0x8c rewritten")

    timestamp = _wrap(b"\x1b" + frame, 8 + bitlen, dgram_num=5, msg_num=2)
    _expect(tx.translate_datagram("s2c", timestamp, peer=_peer(), now=1.0) == [timestamp], "0x1b rewritten")

    # A datagram can carry a small message beside the construction frame.
    # Only the 0x87 payload and its bitlen change.
    prefix = bytes([0x00, 0x00, 0x08, 0x15])
    mixed = bytes([0x84, 0x02, 0x00, 0x00]) + prefix + original[4:]
    mixed_out = tx.translate_datagram("s2c", mixed, peer=_peer(), now=2.0)
    _expect(len(mixed_out) == 1, "mixed datagram count")
    _expect(mixed_out[0][:8] == mixed[:8], "leading internal packet changed")
    _expect(mixed_out[0][8:] == out[4:], "0x87 tail of a mixed datagram mismatch")

    # rel 0 and rel 2 still carry a message id in the payload.
    for flags, extra in ((0x00, b""), (0x40, bytes([0x05, 0x00, 0x00]))):
        header = bytes([flags, (bitlen >> 8) & 0xFF, bitlen & 0xFF]) + extra
        wrapped = bytes([0x84, 0x03, 0x00, 0x00]) + header + frame
        got = tx.translate_datagram("s2c", wrapped, peer=_peer(), now=2.0)[0]
        _expect(got[:4] == wrapped[:4] and got[4] == flags, f"flags {flags:#x} changed")
        _expect(((got[5] << 8) | got[6]) == encoded[1], f"rel {flags:#x} bitlen")
        _expect(got[7 + len(extra):] == translated, f"rel {flags:#x} payload")


def test_split_rewrite() -> None:
    frame, bitlen = _sample_frame()
    mid = max(1, len(frame) // 2)
    part0, part1 = frame[:mid], frame[mid:]
    bits0 = mid * 8
    bits1 = bitlen - bits0
    _expect((bits1 + 7) // 8 == len(part1), "tail piece byte length")
    d0 = _wrap(part0, bits0, dgram_num=20, msg_num=8, flags=0x70, split=(2, 0x1234, 0))
    d1 = _wrap(part1, bits1, dgram_num=21, msg_num=9, flags=0x70, split=(2, 0x1234, 1))
    tx = _tx()
    _expect(tx.translate_datagram("s2c", d0, peer=_peer(), now=5.0) == [], "first split piece was forwarded")
    outs = tx.translate_datagram("s2c", d1, peer=_peer(), now=5.1)
    _expect(len(outs) == 2, f"completed split emitted {len(outs)}")
    _expect(outs[0][:4] == d0[:4] and outs[1][:4] == d1[:4], "split datagram numbers changed")
    _expect(bits1 > 12, f"tail piece too small to keep the savings inside it ({bits1})")
    p0 = walk_datagram(outs[0])[0]
    p1 = walk_datagram(outs[1])[0]
    _expect(p0.bitlen == bits0 and p0.split == (2, 0x1234, 0), (p0.bitlen, p0.split))
    _expect(p1.bitlen == bits1 - 12 and p1.split == (2, 0x1234, 1), (p1.bitlen, p1.split))
    _expect(p0.bitlen + p1.bitlen == bitlen - 12, "split bit lengths do not sum to the rewritten frame")
    header0 = len(d0) - len(part0)
    header1 = len(d1) - len(part1)
    _expect(outs[0][:header0] == d0[:header0], "piece 0 header or bitlen changed")
    _expect(outs[1][4] == d1[4] and outs[1][7:header1] == d1[7:header1], "piece 1 message header changed")
    _expect(len(outs[1]) < len(d1), "tail piece was not shortened")
    cat = p0.payload + p1.payload
    translated = klei_to_vanilla_construction(frame, TranslatorConfig(translate_construction=True))
    _expect(cat == translated, "split payload is not exactly the rewritten frame")
    recs, _dests = _parse(cat, 18)
    _expect(_rak_name(recs[0][2]) == b"evergreen" and _rak_name(recs[1][2]) == b"firepit",
            "split names")

    # Out of order on the wire: emit in receive order, but pack the translated
    # bytes in split-index order so piece 0 still holds the front of the frame.
    tx = _tx()
    _expect(tx.translate_datagram("s2c", d1, peer=_peer(), now=6.0) == [], "later index forwarded early")
    swapped = tx.translate_datagram("s2c", d0, peer=_peer(), now=6.1)
    _expect([d[:4] for d in swapped] == [d1[:4], d0[:4]], "receive order not kept")
    s1 = walk_datagram(swapped[0])[0]
    s0 = walk_datagram(swapped[1])[0]
    _expect(s0.split[2] == 0 and s1.split[2] == 1, "swapped indexes")
    _expect(s0.payload + s1.payload == cat, "index-order packing changed when pieces arrived reversed")

    # A retransmit of a held piece must not escape ahead of the rewrite.
    tx = _tx()
    _expect(tx.translate_datagram("s2c", d0, peer=_peer(), now=0.0) == [], "hold")
    _expect(tx.translate_datagram("s2c", d0, peer=_peer(), now=0.2) == [], "retransmit escaped")
    late = tx.flush(now=_SPLIT_TIMEOUT_S)
    _expect(len(late) == 1 and late[0][2] == d0, "timeout did not forward the original piece")


def _payload_bits(n: int, seed: int) -> BitWriter:
    w = BitWriter()
    value = seed & 0xFF
    left = n
    while left:
        k = 8 if left >= 8 else left
        w.write_bits(value & ((1 << k) - 1), k)
        value = (value * 17 + 3) & 0xFF
        left -= k
    return w


def _append_serialize(w: BitWriter, records: list) -> None:
    """records: (net_id, flag, payload). flag 0 is 15 bits of length, flag 1 is 31."""
    for net_id, flag, payload in records:
        w.write_le_bits(net_id, 24)
        w.write_bit(flag)
        n = payload.bit_len()
        maximum = 0x7FFFFFFF if flag else 0x7FFF
        w.write_ranged(n, 0, maximum, allow_outside=False)
        _copy_n(BitReader(payload.to_bytes()), w, n)


def _server_frame_with_serialize(records: list, destructions: list, serializes: list) -> tuple[bytes, int]:
    w = BitWriter()
    w.write_bits(0x87, 8)
    w.write_bit(1 if records else 0)
    if records:
        w.write_ranged(len(records), 0, 0x3FF, allow_outside=True)
    w.write_bit(1 if destructions else 0)
    if destructions:
        w.write_ranged(len(destructions), 0, 0x3FF, allow_outside=True)
    for net_id, flag, payload in records:
        w.write_le_bits(net_id, 24)
        w.write_bit(flag)
        n = payload.bit_len()
        w.write_ranged(n, 0, 0x3FF, allow_outside=True)
        _copy_n(BitReader(payload.to_bytes()), w, n)
    for net_id, guid in destructions:
        w.write_le_bits(net_id, 24)
        w.write_le_bits(guid, 64)
    _append_serialize(w, serializes)
    return w.to_bytes(), w.bit_len()


def _serialize_frame(records: list) -> tuple[bytes, int]:
    w = BitWriter()
    w.write_bits(0x88, 8)
    _append_serialize(w, records)
    return w.to_bytes(), w.bit_len()


def _parse_serialize(reader: BitReader, id_bits: int):
    recs = []
    while reader.remaining() > 39:
        net_id = reader.read_le_bits(id_bits)
        flag = reader.read_bit()
        maximum = 0x7FFFFFFF if flag else 0x7FFF
        n = reader.read_ranged(0, maximum, allow_outside=False)
        payload = BitWriter()
        _copy_n(reader, payload, n)
        recs.append((net_id, flag, payload))
    return recs, reader.remaining()


def _parse_limited(frame: bytes, id_bits: int, nbits: int):
    reader = BitReader(frame)
    reader.nbits = nbits
    msg = reader.read_bits(8)
    has_c = reader.read_bit()
    c_count = reader.read_ranged(0, 0x3FF, allow_outside=True) if has_c else 0
    has_d = reader.read_bit()
    d_count = reader.read_ranged(0, 0x3FF, allow_outside=True) if has_d else 0
    recs = []
    for _ in range(c_count):
        net_id = reader.read_le_bits(id_bits)
        flag = reader.read_bit()
        n = reader.read_ranged(0, 0x3FF, allow_outside=True)
        payload = BitWriter()
        _copy_n(reader, payload, n)
        recs.append((net_id, flag, payload))
    dests = []
    for _ in range(d_count):
        net_id = reader.read_le_bits(id_bits)
        guid = reader.read_le_bits(64)
        dests.append((net_id, guid))
    serial, left = _parse_serialize(reader, id_bits)
    return msg, recs, dests, serial, left


def test_serialize_tail() -> None:
    """A live 0x87 is construction records followed by OnSerialize records.

    Each id, construction or serialize, shrinks by 6 bits. A serialize id that
    does not fit in 18 bits refuses the whole frame, including construction.
    """
    evergreen = _name_payload(b"evergreen")
    firepit = _name_payload(b"firepit")
    ser_a = _payload_bits(341, 0x11)
    ser_b = _payload_bits(40, 0x22)
    ser_long = _payload_bits(20, 0x33)
    frame, bitlen = _server_frame_with_serialize(
        [(33919, 1, evergreen), (16385, 1, firepit)],
        [],
        [(33919, 0, ser_a), (16385, 0, ser_b), (7, 1, ser_long)],
    )
    encoded = _reencode_construction(frame, bitlen)
    _expect(encoded is not None, "construction plus serialize tail was refused")
    _expect(encoded[1] == bitlen - 30, f"five ids should save 30 bits, {bitlen}->{encoded[1]}")
    msg, recs, dests, serial, left = _parse_limited(encoded[0], 18, encoded[1])
    _expect(msg == 0x87 and not dests and left == 0, f"rewritten tail msg={msg} dests={dests} left={left}")
    _expect(_rak_name(recs[0][2]) == b"evergreen" and recs[0][0] == 33919 and recs[0][1] == 1, recs[0][:2])
    _expect(_rak_name(recs[1][2]) == b"firepit" and recs[1][0] == 16385, recs[1][:2])
    _expect(
        [(item[0], item[1], item[2].bit_len()) for item in serial] == [(33919, 0, 341), (16385, 0, 40), (7, 1, 20)],
        [(item[0], item[1], item[2].bit_len()) for item in serial],
    )
    _expect(serial[0][2].to_bytes() == ser_a.to_bytes(), "serialize payload 0")
    _expect(serial[1][2].to_bytes() == ser_b.to_bytes(), "serialize payload 1")
    _expect(serial[2][2].to_bytes() == ser_long.to_bytes(), "flag-1 serialize payload")

    wide, wide_bits = _server_frame_with_serialize(
        [(0x11, 0, evergreen)],
        [],
        [(1 << 18, 0, ser_a)],
    )
    _expect(_reencode_construction(wide, wide_bits) is None, "wide serialize id was rewritten")
    cfg = TranslatorConfig(translate_construction=True)
    _expect(klei_to_vanilla_construction(wide, cfg) == wide, "wide serialize id changed the construction frame")

    original = _wrap(frame, bitlen, dgram_num=9, msg_num=4)
    tx = GeyserTranslator(TranslatorConfig(
        enabled=True, translate_construction=True, translate_serialize=True,
    ))
    out = tx.translate_datagram("s2c", original, peer=_peer(), now=0.0)[0]
    new_bits = (out[5] << 8) | out[6]
    _expect(new_bits == bitlen - 30, f"datagram bitlen {new_bits}")
    _expect(out[:4] == original[:4] and out[7:14] == original[7:14], "serialize tail moved the raknet header")


def test_serialize_message() -> None:
    ser_a = _payload_bits(341, 0x11)
    ser_b = _payload_bits(40, 0x22)
    frame, bitlen = _serialize_frame([(33919, 0, ser_a), (16385, 0, ser_b)])
    encoded = _reencode_serialize(frame, bitlen)
    _expect(encoded is not None and encoded[1] == bitlen - 12, f"0x88 savings {None if encoded is None else encoded[1]}")
    reader = BitReader(encoded[0])
    reader.nbits = encoded[1]
    _expect(reader.read_bits(8) == 0x88, "0x88 id")
    recs, left = _parse_serialize(reader, 18)
    _expect(left == 0, f"0x88 leftover {left}")
    _expect(recs[0][0] == 33919 and recs[0][2].bit_len() == 341, recs[0][:2])
    _expect(recs[0][2].to_bytes() == ser_a.to_bytes(), "0x88 payload 0")
    _expect(recs[1][0] == 16385 and recs[1][2].bit_len() == 40, recs[1][:2])
    _expect(recs[1][2].to_bytes() == ser_b.to_bytes(), "0x88 payload 1")

    tx = GeyserTranslator(TranslatorConfig(
        enabled=True, translate_construction=True, translate_serialize=True,
    ))
    original = _wrap(frame, bitlen, dgram_num=11, msg_num=5)
    out = tx.translate_datagram("s2c", original, peer=_peer(), now=0.0)[0]
    _expect(((out[5] << 8) | out[6]) == bitlen - 12, "0x88 datagram bitlen")
    _expect(out[14:] == encoded[0], "0x88 datagram payload")
    _expect(tx.translate_datagram("c2s", original, peer=_peer(), now=0.0) == [original], "c2s 0x88 rewritten")

    wide, wide_bits = _serialize_frame([(1 << 18, 0, ser_a)])
    wide_d = _wrap(wide, wide_bits, dgram_num=3, msg_num=1)
    _expect(tx.translate_datagram("s2c", wide_d, peer=_peer(), now=1.0) == [wide_d], "wide 0x88 rewritten")

    mid = max(1, len(frame) // 2)
    part0, part1 = frame[:mid], frame[mid:]
    bits0 = mid * 8
    bits1 = bitlen - bits0
    d0 = _wrap(part0, bits0, dgram_num=30, msg_num=8, flags=0x70, split=(2, 0x88, 0))
    d1 = _wrap(part1, bits1, dgram_num=31, msg_num=9, flags=0x70, split=(2, 0x88, 1))
    tx = GeyserTranslator(TranslatorConfig(
        enabled=True, translate_construction=True, translate_serialize=True,
    ))
    _expect(tx.translate_datagram("s2c", d0, peer=_peer(), now=2.0) == [], "0x88 split forwarded early")
    outs = tx.translate_datagram("s2c", d1, peer=_peer(), now=2.1)
    _expect(len(outs) == 2 and outs[0][:4] == d0[:4] and outs[1][:4] == d1[:4], "0x88 split headers")
    q0 = walk_datagram(outs[0])[0]
    q1 = walk_datagram(outs[1])[0]
    _expect(q0.bitlen == bits0 and q1.bitlen == bits1 - 12, (q0.bitlen, q1.bitlen, bits1))
    _expect(q0.split == (2, 0x88, 0) and q1.split == (2, 0x88, 1), (q0.split, q1.split))
    _expect(q0.payload + q1.payload == encoded[0], "0x88 split payload")


def test_live_frame87() -> None:
    """The captured join datagram: 0x2a, one 0x87, 0x2b. Four ids, all fit in 18 bits."""
    if not os.path.isfile(LIVE_FRAME):
        print("live 0x87 fixture absent; skip")
        return
    datagram = open(LIVE_FRAME, "rb").read()
    packets = walk_datagram(datagram)
    _expect(packets is not None and len(packets) == 3, f"live walk {0 if packets is None else len(packets)}")
    _expect(packets[0].payload == b"\x2a" and packets[0].bitlen == 8, "live 0x2a")
    _expect(packets[1].payload[:1] == b"\x87" and packets[1].bitlen == 1791, f"live 0x87 {packets[1].bitlen}")
    _expect(len(packets[1].payload) == 224, f"live 0x87 bytes {len(packets[1].payload)}")
    _expect(packets[2].payload == b"\x2b" and packets[2].bitlen == 8, "live 0x2b")
    msg, recs, dests, serial, left = _parse_limited(packets[1].payload, 24, packets[1].bitlen)
    got = ([(item[0], item[1], item[2].bit_len()) for item in recs],
           [(item[0], item[1], item[2].bit_len()) for item in serial], left, len(dests), msg)
    _expect(got == ([(33919, 1, 712), (16385, 1, 224)],
                    [(33919, 0, 341), (16385, 0, 341)], 0, 0, 0x87), got)

    tx = GeyserTranslator(TranslatorConfig(
        enabled=True, translate_construction=True, translate_serialize=True,
    ))
    outs = tx.translate_datagram("s2c", datagram, peer=_peer(), now=0.0)
    _expect(len(outs) == 1 and outs[0][:4] == datagram[:4], "live datagram number")
    out_packets = walk_datagram(outs[0])
    _expect(out_packets is not None and len(out_packets) == 3, "live rewritten walk")
    _expect(out_packets[0].payload == b"\x2a" and out_packets[0].bitlen == 8, "0x2a changed")
    _expect(out_packets[2].payload == b"\x2b" and out_packets[2].bitlen == 8, "0x2b changed")
    _expect(out_packets[1].bitlen == 1767, f"live rewritten bitlen {out_packets[1].bitlen}")
    msg2, recs2, dests2, serial2, left2 = _parse_limited(out_packets[1].payload, 18, out_packets[1].bitlen)
    got2 = ([(item[0], item[1], item[2].bit_len()) for item in recs2],
            [(item[0], item[1], item[2].bit_len()) for item in serial2], left2, len(dests2), msg2)
    _expect(got2 == got[:2] + (0, 0, 0x87), got2)
    _expect(recs2[0][2].to_bytes() == recs[0][2].to_bytes(), "live construction payload 0")
    _expect(recs2[1][2].to_bytes() == recs[1][2].to_bytes(), "live construction payload 1")
    _expect(serial2[0][2].to_bytes() == serial[0][2].to_bytes(), "live serialize payload 0")
    _expect(serial2[1][2].to_bytes() == serial[1][2].to_bytes(), "live serialize payload 1")
    print("live 0x87: 1791->1767 bits, four ids round-trip at 18 bits")


def test_split_listing() -> None:
    """A Caves shard makes the 0x86 listing too big for one datagram. The split one is
    held, rewritten to the mobile front (longer), and the last piece takes the growth."""
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from listing_rewrite import rewrite_listing_payload
    body = (b"\x86" + bytes(4) + b"\x00\x06" + bytes(range(1, 21)) + bytes.fromhex("03d0df4d00000001")
            + b"\x00\x10" + b"0123456789ABCDEF" + b"\x84\x61" + b"\x00\x02US" + bytes(1100))
    want = rewrite_listing_payload(body)
    _expect(want is not None and len(want) > len(body), "fixture is not a PC listing")
    mid = 1000
    d0 = _wrap(body[:mid], mid * 8, 40, 12, flags=0x70, split=(2, 0x55, 0))
    d1 = _wrap(body[mid:], (len(body) - mid) * 8, 41, 13, flags=0x70, split=(2, 0x55, 1))
    tx = GeyserTranslator(TranslatorConfig(enabled=True, translate_construction=True,
                                           listing=rewrite_listing_payload))
    _expect(tx.translate_datagram("s2c", d0, peer=_peer(), now=0.0) == [], "split listing was not held")
    outs = tx.translate_datagram("s2c", d1, peer=_peer(), now=0.1)
    pieces = [walk_datagram(d)[0] for d in outs]
    _expect(len(pieces) == 2 and pieces[0].bitlen == mid * 8, [p.bitlen for p in pieces])
    _expect(b"".join(p.payload for p in pieces) == want, "split listing not rewritten whole")
    _expect(sum(p.bitlen for p in pieces) == len(want) * 8, "split listing bit length")
    # Without the listing hook a split listing still passes piece by piece.
    tx = _tx()
    _expect(tx.translate_datagram("s2c", d0, peer=_peer(), now=0.0) == [d0], "listing held without hook")


def test_split_passthrough() -> None:
    # A split 0x8b (two destruction records) is held and rewritten whole.
    body = b"\x8b" + b"\x05\x40\x00" + bytes(range(8)) + b"\x06\x40\x00" + bytes(range(8))
    mid = 16
    d0 = _wrap(body[:mid], mid * 8, 1, 1, flags=0x70, split=(2, 7, 0))
    d1 = _wrap(body[mid:], (len(body) - mid) * 8, 2, 2, flags=0x70, split=(2, 7, 1))
    tx = _tx()
    _expect(tx.translate_datagram("s2c", d0, peer=_peer(), now=0.0) == [], "0x8b split was not held")
    outs = tx.translate_datagram("s2c", d1, peer=_peer(), now=0.1)
    _expect(outs and outs != [d0, d1], "0x8b split was not rewritten")
    pieces = [walk_datagram(d)[0] for d in outs]
    _expect(sum(p.bitlen for p in pieces) == 8 + 2 * (18 + 64), [p.bitlen for p in pieces])

    # A file-transfer split (not 0x87/0x88) is forwarded as each piece arrives,
    # including pieces whose datagram flag is the continuous-send bit.
    body = b"\x4b" + bytes(range(30))
    mid = 16
    file0 = _wrap(body[:mid], mid * 8, 11, 11, flags=0x70, split=(2, 9, 0))
    file1 = _wrap(body[mid:], (len(body) - mid) * 8, 12, 12, flags=0x70, split=(2, 9, 1))
    file0 = bytes([0x8C]) + file0[1:]
    file1 = bytes([0x8C]) + file1[1:]
    tx = _tx()
    _expect(tx.translate_datagram("s2c", file0, peer=_peer(), now=1.0) == [file0], "file split was held")
    _expect(tx.translate_datagram("s2c", file1, peer=_peer(), now=1.1) == [file1], "file tail was held")
    _expect(tx.flush(now=1.1) == [], "file split left a held piece")

    # A slow file transfer outlasts the split timeout. Every piece still goes out
    # as it arrives, and a server resend of a forwarded piece is forwarded again.
    pieces = [b"\x4b" + bytes(15)] + [bytes(16) for _ in range(3)]
    slow = [
        bytes([0x8C]) + _wrap(p, len(p) * 8, 20 + i, 20 + i, flags=0x70, split=(4, 10, i))[1:]
        for i, p in enumerate(pieces)
    ]
    tx = _tx()
    for i, dgram in enumerate(slow):
        t = i * (_SPLIT_TIMEOUT_S * 0.75)
        _expect(tx.flush(now=t) == [], "slow file split flushed a piece")
        _expect(tx.translate_datagram("s2c", dgram, peer=_peer(), now=t) == [dgram],
                f"slow file split held piece {i}")
        if i == 1:
            _expect(tx.translate_datagram("s2c", slow[0], peer=_peer(), now=t) == [slow[0]],
                    "file split resend was dropped")

    # A piece that is not on a byte boundary cannot be concatenated safely.
    short = _wrap(b"\x87\xff", 12, 3, 3, flags=0x70, split=(2, 8, 0))
    rest = _wrap(b"\x00\x00", 16, 4, 4, flags=0x70, split=(2, 8, 1))
    tx = _tx()
    _expect(tx.translate_datagram("s2c", short, peer=_peer(), now=0.0) == [], "odd piece forwarded")
    _expect(tx.translate_datagram("s2c", rest, peer=_peer(), now=0.1) == [short, rest],
            "unaligned split was rewritten")


def _iter_udp_payloads(path: str):
    data = open(path, "rb").read()
    magic, version_major, version_minor, _tz, _sig, snap, link = struct.unpack_from("<IHHIIII", data, 0)
    _expect(magic == 0xA1B2C3D4, f"pcap magic {magic:#x}")
    _expect(link == 276, f"pcap link type {link}")
    offset = 24
    while offset + 16 <= len(data):
        _ts_sec, _ts_usec, incl, orig = struct.unpack_from("<IIII", data, offset)
        offset += 16
        pkt = data[offset:offset + incl]
        offset += incl
        if incl != orig or len(pkt) < 20 + 20 + 8:
            continue
        proto = struct.unpack_from(">H", pkt, 0)[0]
        if proto != 0x0800:
            continue
        ip = pkt[20:]
        if (ip[0] >> 4) != 4:
            continue
        ihl = (ip[0] & 0x0F) * 4
        if ip[9] != 17 or len(ip) < ihl + 8:
            continue
        udp = ip[ihl:]
        ulen = struct.unpack_from(">H", udp, 4)[0]
        if ulen < 8 or len(udp) < ulen:
            continue
        yield udp[8:ulen]
    _ = (version_major, version_minor, snap)


def test_continuous_send() -> None:
    """A world burst sets isContinuousSend. The datagram flag becomes 0x8c, not 0x84."""
    _expect(is_data_datagram(0x84) and is_data_datagram(0x88) and is_data_datagram(0x8C), "data flags")
    _expect(not is_data_datagram(0xC0) and not is_data_datagram(0xA0), "ack/nak classified as data")
    frame, bitlen = _sample_frame()
    wrapped = _wrap(frame, bitlen, dgram_num=3, msg_num=4)
    burst = bytes([0x8C]) + wrapped[1:]
    _expect(datagram_number(burst) == 3, "datagram number")
    _expect(ack_datagram(3) == bytes.fromhex("c0000101030000"), ack_datagram(3).hex())
    tx = _tx()
    out = tx.translate_datagram("s2c", burst, peer=_peer(), now=0.0)[0]
    _expect(out[0] == 0x8C and out[1:4] == burst[1:4], "continuous-send flag was cleared")
    _expect(out != burst and out[14:][0] == 0x87, "0x8c construction was not rewritten")

    # The same flag on a split still reassembles. Both pieces use 0x8c.
    mid = max(1, len(frame) // 2)
    part0, part1 = frame[:mid], frame[mid:]
    d0 = _wrap(part0, mid * 8, 20, 8, flags=0x70, split=(2, 0x55, 0))
    d1 = _wrap(part1, bitlen - mid * 8, 21, 9, flags=0x70, split=(2, 0x55, 1))
    d0 = bytes([0x8C]) + d0[1:]
    d1 = bytes([0x8C]) + d1[1:]
    tx = _tx()
    _expect(tx.translate_datagram("s2c", d0, peer=_peer(), now=0.0) == [], "0x8c split forwarded early")
    outs = tx.translate_datagram("s2c", d1, peer=_peer(), now=0.2)
    _expect(len(outs) == 2 and outs[0][0] == 0x8C and outs[1][0] == 0x8C, "split flags")
    _expect(outs[0][1:4] == d0[1:4] and outs[1][1:4] == d1[1:4], "0x8c datagram numbers changed")
    c0 = walk_datagram(outs[0])[0]
    c1 = walk_datagram(outs[1])[0]
    translated = klei_to_vanilla_construction(frame, TranslatorConfig(translate_construction=True))
    _expect(c0.payload + c1.payload == translated, "0x8c split was not rewritten")
    _expect(c1.bitlen == (bitlen - mid * 8) - 12, f"0x8c tail bitlen {c1.bitlen}")


def test_split_drops_empty_tail() -> None:
    """Savings larger than the last piece must drop that piece and lower the split count.

    A zero tail inside the old dataBitLength is read as more serialize records.
    The kept piece keeps its datagram number, message number, and split index.
    """
    frame, bitlen = _sample_frame()
    encoded = _reencode_construction(frame, bitlen)
    _expect(encoded is not None and encoded[1] == bitlen - 12, "expected 12 bits saved")
    translated, new_bits = encoded
    part0, part1 = frame[:-1], frame[-1:]
    bits0 = (len(frame) - 1) * 8
    bits1 = bitlen - bits0
    _expect(0 < bits1 <= 8 and bits0 > new_bits, f"tail not smaller than the savings ({bits0}, {bits1}, {new_bits})")
    d0 = _wrap(part0, bits0, 40, 8, flags=0x70, split=(2, 0x77, 0))
    d1 = _wrap(part1, bits1, 41, 9, flags=0x70, split=(2, 0x77, 1))
    tx = _tx()
    _expect(tx.translate_datagram("s2c", d0, peer=_peer(), now=0.0) == [], "short tail forwarded early")
    outs = tx.translate_datagram("s2c", d1, peer=_peer(), now=0.1)
    _expect(len(outs) == 1 and outs[0][:4] == d0[:4], f"dropped tail emitted {len(outs)}")
    packet = walk_datagram(outs[0])[0]
    _expect(packet.bitlen == new_bits and packet.payload == translated, "dropped-tail payload")
    _expect(packet.split == (1, 0x77, 0), packet.split)
    header_len = len(d0) - len(part0)
    _expect(outs[0][header_len - 10:header_len - 6] == (1).to_bytes(4, "big"), "split count was not rewritten")
    _expect(outs[0][7:header_len - 10] == d0[7:header_len - 10], "message number changed when the tail was dropped")
    recs, _dests = _parse(packet.payload, 18)
    _expect(_rak_name(recs[0][2]) == b"evergreen" and _rak_name(recs[1][2]) == b"firepit", "dropped-tail names")


def _tile_region_payload(compressed: bool, extra_bits: int = 0) -> BitWriter:
    """Body of one tile-region serialize, aligned to its own bitstream."""
    w = BitWriter()
    if compressed:
        w.write_bit(1)
        w.write_le_bits(4, (256 - 1).bit_length())
        w.write_aligned_bytes(b"\x01\x00\x02\x00\x03\x00\x04\x00")
    else:
        w.write_bit(0)
        w.write_aligned_bytes(b"\x00\x00" * 256)
    if extra_bits:
        w.write_bits(0xA5, extra_bits)
    return w


def test_tile_region_serialize() -> None:
    """A 256-ushort RLE is a tile-region snapshot. Regions get the phone's id,
    x + 64*y instead of x + 128*y. The world frame's snapshot and later updates
    both go through, edge regions included. 16384, which the phone does not have,
    is dropped.

    A record that only starts with the RLE, and an entity record, stay as they are.
    """
    tile = _tile_region_payload(True)
    raw_tile = _tile_region_payload(False)
    kept = _payload_bits(40, 0x22)
    first = _payload_bits(5, 0x15)
    extra = _tile_region_payload(True, extra_bits=8)
    regions = [x + 128 * y for y in range(3) for x in range(3)]
    frame, bitlen = _server_frame_with_serialize(
        [(net_id, 0, BitWriter()) for net_id in regions + [16384]],
        [],
        [(net_id, 0, tile) for net_id in regions] + [(16384, 0, first), (16385, 0, kept), (258, 0, extra)],
    )
    encoded = _reencode_construction(frame, bitlen)
    _expect(encoded is not None, "tile frame was refused")
    _expect(_rewrite_serialize_records.tiles == 9, _rewrite_serialize_records.tiles)
    msg, recs, _dests, serial, left = _parse_limited(encoded[0], 18, encoded[1])
    _expect(msg == 0x87 and left == 0, (msg, left))
    _expect([r[0] for r in recs] == [x + 64 * y for y in range(3) for x in range(3)], [r[0] for r in recs])
    mobile = [x + 64 * y for y in range(3) for x in range(3)]
    _expect([(item[0], item[2].bit_len()) for item in serial]
            == [(net_id, tile.bit_len()) for net_id in mobile] + [(16385, 40), (258, extra.bit_len())], serial)
    _expect(serial[9][2].to_bytes() == kept.to_bytes(), "kept serialize payload changed")

    w = BitWriter()
    w.write_bits(0x88, 8)
    for net_id, body in [(129, tile), (0, raw_tile), (130, tile)]:
        w.write_le_bits(net_id, 24)
        w.write_bit(0)
        w.write_ranged(body.bit_len(), 0, 0x7FFF, allow_outside=False)
        r = BitReader(body.to_bytes())
        for _ in range(body.bit_len()):
            w.write_bit(r.read_bit())
    out = _reencode_serialize(w.to_bytes(), w.bit_len())
    _expect(out is not None, "tile update was refused")
    _expect(_rewrite_serialize_records.tiles == 3, _rewrite_serialize_records.tiles)
    r = BitReader(out[0])
    r.nbits = out[1]
    r.read_bits(8)
    ids = []
    for _ in range(3):
        ids.append(r.read_le_bits(18))
        r.read_bit()
        n = r.read_ranged(0, 0x7FFF, allow_outside=False)
        r.pos += n
    _expect(ids == [65, 0, 66], ids)


def test_destruction_message() -> None:
    """0x8b is net id + 64-bit tail records with no count; ids shrink to 18 bits."""
    w = BitWriter()
    w.write_bits(0x8B, 8)
    for net_id, tail in [(16385, 0x1122334455667788), (70191, 0)]:
        w.write_le_bits(net_id, 24)
        w.write_bits(tail, 64)
    out = _reencode_destruction(w.to_bytes(), w.bit_len())
    _expect(out is not None and out[1] == 8 + 2 * (18 + 64), out and out[1])
    r = BitReader(out[0])
    r.nbits = out[1]
    _expect(r.read_bits(8) == 0x8B, "message id")
    _expect(r.read_le_bits(18) == 16385 and r.read_bits(64) == 0x1122334455667788, "first record")
    _expect(r.read_le_bits(18) == 70191 and r.read_bits(64) == 0, "second record")
    _expect(_reencode_destruction(w.to_bytes()[:-2], w.bit_len() - 16) is None, "torn record accepted")


def test_split_retransmit_dropped() -> None:
    """After a shrink, a resent piece of the old count is dropped, not forwarded raw."""
    frame, bitlen = _sample_frame()
    encoded = _reencode_construction(frame, bitlen)
    _expect(encoded is not None and encoded[1] < bitlen, "sample did not shrink")
    part0, part1 = frame[:-1], frame[-1:]
    bits0 = (len(frame) - 1) * 8
    bits1 = bitlen - bits0
    _expect(bits0 > encoded[1], "tail piece is not the one the packer drops")
    d0 = _wrap(part0, bits0, 40, 8, flags=0x70, split=(2, 0x77, 0))
    d1 = _wrap(part1, bits1, 41, 9, flags=0x70, split=(2, 0x77, 1))
    peer = _peer()
    tx = _tx()
    _expect(tx.translate_datagram("s2c", d0, peer=peer, now=0.0) == [], "first piece forwarded")
    outs = tx.translate_datagram("s2c", d1, peer=peer, now=0.1)
    _expect(len(outs) == 1, f"rewrite emitted {len(outs)}")
    _expect(tx.translate_datagram("s2c", d1, peer=peer, now=1.0) == [], "retransmit was forwarded")
    _expect(tx.flush(now=1.0 + _SPLIT_TIMEOUT_S) == [], "timeout forwarded the dropped retransmit")
    # A later message reuses the split id but has a new datagram number.
    d2 = _wrap(part0, bits0, 50, 10, flags=0x70, split=(2, 0x77, 0))
    _expect(tx.translate_datagram("s2c", d2, peer=peer, now=2.0) == [], "new datagram was treated as a retransmit")
    _expect(tx.flush(now=2.0 + _SPLIT_TIMEOUT_S)[0][2] == d2, "new assembly was not held")


def test_split_tail_shares_datagram() -> None:
    """The last piece of a split travels with the messages sent after it.

    Seen live: the bridge forwarded such a datagram whole, the phone then assembled
    the untranslated split from the timed-out first piece and lost every replica.
    """
    frame, bitlen = _sample_frame()
    translated, new_bits = _reencode_construction(frame, bitlen)
    rider = _wrap(frame, bitlen, dgram_num=0, msg_num=11)[4:]
    peer = _peer()

    def riders(dgram: bytes) -> list:
        return [p for p in walk_datagram(dgram) if p.split is None]

    # Tail kept: both packets of the shared datagram are translated, under its number.
    mid = len(frame) // 2
    d0 = _wrap(frame[:mid], mid * 8, 20, 8, flags=0x70, split=(2, 0x4A, 0))
    d1 = _wrap(frame[mid:], bitlen - mid * 8, 21, 9, flags=0x70, split=(2, 0x4A, 1)) + rider
    tx = _tx()
    _expect(tx.translate_datagram("s2c", d0, peer=peer, now=0.0) == [], "first piece forwarded")
    outs = tx.translate_datagram("s2c", d1, peer=peer, now=0.1)
    _expect([o[:4] for o in outs] == [d0[:4], d1[:4]], "datagram numbers changed")
    pieces = [p for o in outs for p in walk_datagram(o) if p.split is not None]
    _expect(b"".join(p.payload for p in pieces) == translated, "split was not translated")
    _expect([(p.payload, p.bitlen) for p in riders(outs[1])] == [(translated, new_bits)], "rider not translated")

    # Tail dropped by the shrink: the rider still goes out under the tail's number.
    d0 = _wrap(frame[:-1], (len(frame) - 1) * 8, 40, 8, flags=0x70, split=(2, 0x77, 0))
    d1 = _wrap(frame[-1:], bitlen - (len(frame) - 1) * 8, 41, 9, flags=0x70, split=(2, 0x77, 1)) + rider
    tx = _tx()
    tx.translate_datagram("s2c", d0, peer=peer, now=0.0)
    outs = tx.translate_datagram("s2c", d1, peer=peer, now=0.1)
    _expect([o[:4] for o in outs] == [d0[:4], d1[:4]], f"dropped tail emitted {len(outs)}")
    _expect(walk_datagram(outs[0])[0].split == (1, 0x77, 0), "split count not lowered")
    only = walk_datagram(outs[1])
    _expect(len(only) == 1 and only[0].payload == translated, "rider lost with the dropped tail")

    # The server resends the tail (same message number, new datagram number) next to
    # a new message. Seen live: held as a new split, it froze the phone for 8 s.
    resend = _wrap(frame[-1:], bitlen - (len(frame) - 1) * 8, 45, 9, flags=0x70, split=(2, 0x77, 1)) + rider
    outs = tx.translate_datagram("s2c", resend, peer=peer, now=0.2)
    _expect(len(outs) == 1 and outs[0][:4] == resend[:4], "resent tail was held")
    only = walk_datagram(outs[0])
    _expect(len(only) == 1 and only[0].payload == translated, "rider of a resent tail")
    _expect(tx.flush(now=0.2 + _SPLIT_TIMEOUT_S) == [], "resent tail forwarded raw later")

    # Two resent pieces in one datagram (seen live): the kept one goes out rewritten.
    both = _wrap(frame[:-1], (len(frame) - 1) * 8, 46, 8, flags=0x70, split=(2, 0x77, 0)) + resend[4:]
    outs = tx.translate_datagram("s2c", both, peer=peer, now=0.3)
    got = walk_datagram(outs[0]) if len(outs) == 1 else []
    _expect([(p.split, p.payload) for p in got] == [((1, 0x77, 0), translated), (None, translated)], "two resent pieces")

    # Same resend while the first copy is still held: only the rider goes on.
    tx = _tx()
    _expect(tx.translate_datagram("s2c", d1, peer=peer, now=0.0) == [], "lone tail forwarded early")
    outs = tx.translate_datagram("s2c", resend, peer=peer, now=0.1)
    _expect(len(outs) == 1 and [p.payload for p in walk_datagram(outs[0])] == [translated], "rider of a held resend")

    # First piece never arrives: the piece goes on as it came, the rider translated.
    tx = _tx()
    _expect(tx.translate_datagram("s2c", d1, peer=peer, now=0.0) == [], "lone tail forwarded early")
    late = tx.flush(now=_SPLIT_TIMEOUT_S)
    _expect(len(late) == 1, f"timeout emitted {len(late)}")
    got = walk_datagram(late[0][2])
    _expect(got[0].payload == frame[-1:] and got[1].payload == translated, "timed-out tail")


def test_capture_identity() -> None:
    listing_path = os.path.join(CAPTURES, "real_pc_listing_0x86.bin")
    if not os.path.isfile(listing_path):
        print("PC listing 0x86 fixture absent; skip")
        return
    listing = open(listing_path, "rb").read()
    packets = walk_datagram(listing)
    _expect(packets is not None and len(packets) == 1, "listing did not walk")
    _expect(packets[0].reliability == 3 and packets[0].split is None, "listing reliability")
    _expect(packets[0].bitlen == 6056 and packets[0].payload[0] == 0x86, 
            f"listing bitlen/id {packets[0].bitlen} {packets[0].payload[:1].hex()}")
    _expect(len(packets[0].payload) == 757, f"listing payload {len(packets[0].payload)}")
    _expect(build_datagram(listing[:4], packets) == listing, "listing rebuild differs")
    tx = _tx()
    _expect(tx.translate_datagram("s2c", listing, peer=_peer(), now=0.0) == [listing], "listing rewritten")

    import listing_rewrite
    rewritten = listing_rewrite.rewrite_listing(listing)
    _expect(rewritten is not None and rewritten != listing, "listing_rewrite did not change the sample")
    _expect(tx.translate_datagram("s2c", rewritten, peer=_peer(), now=0.0) == [rewritten],
            "geyser touched a rewritten 0x86")

    pcap = os.path.join(CAPTURES, "join_20261106-120323.pcap0")
    payloads = list(_iter_udp_payloads(pcap))
    _expect(len(payloads) > 50, f"pcap yielded {len(payloads)} udp payloads")
    walk_fail = []
    data_count = 0
    for payload in payloads:
        if not payload or not is_data_datagram(payload[0]):
            continue
        data_count += 1
        walked = walk_datagram(payload)
        if walked is None or build_datagram(payload[:4], walked) != payload:
            walk_fail.append(payload[:24].hex())
    _expect(data_count > 0 and not walk_fail, f"walker failed {len(walk_fail)} of {data_count}: {walk_fail[:3]}")

    tx = _tx()
    emitted = []
    for payload in payloads:
        emitted.extend(tx.translate_datagram("s2c", payload, peer=_peer(), now=0.0))
    leftover = [item[2] for item in tx.flush(now=10.0)]
    _expect(not leftover, f"pcap left {len(leftover)} split pieces held")
    _expect(emitted == payloads, "handshake pcap was modified")
    print(f"capture identity: {len(payloads)} udp, {data_count} data datagrams, byte-identical")


def test_worn_item_unequip() -> None:
    """The phone's EQUIP on an item the server says is worn goes out as UNEQUIP."""
    from .netvars import EQUIPS_PREFIX, NetvarMapper, NetvarState
    from .rpc import CODE_BITS, ERPC_LUA, RpcMapper, read_args, read_signal, write_signal
    mob = {"rpc": ["ControllerUseItemOnSelfFromInvTile"], "action_ids": ["EQUIP", "UNEQUIP"]}
    pc = {"rpc": ["X", "ControllerUseItemOnSelfFromInvTile"], "action_ids": ["A", "EQUIP", "B", "UNEQUIP"]}
    mapper = RpcMapper(mob, pc)
    torch = 0x1122334455667788

    def use_on_self(action: int) -> tuple[int, list]:
        w = BitWriter()
        write_signal(w, ERPC_LUA)
        w.write_bit(0)
        w.write_bits(1, CODE_BITS)
        w.write_bits(4, 4)
        w.write_bits(action, 3)
        w.write_bits(15, 4)
        w.write_bits(torch, 64)
        out = mapper.translate(w.to_bytes(), w.bit_len(), {torch})
        _erpc, start = read_signal(out[0], out[1])
        r = BitReader(out[0])
        r.pos = start + 1
        return r.read_bits(CODE_BITS), read_args(r, out[1])

    code, args = use_on_self(1)  # EQUIP on the worn torch
    _expect(code == 2 and args[0][1] == 4 and args[1] == (15, torch), (code, args))
    code, args = use_on_self(2)  # UNEQUIP stays UNEQUIP
    _expect(args[0][1] == 4, args)

    # The worn set comes from the server's inventory_classified netvars.
    name = EQUIPS_PREFIX + "hands]"
    schema = {"inventory_classified": [(1, name, "net_entity")]}
    state = NetvarState(NetvarMapper(schema, schema, {"action_components": [], "action_pairs": []},
                                     {"action_components": [], "action_ids": []}))
    state.prefab_of[7] = "inventory_classified"
    chunk = BitWriter()
    chunk.write_bits(0, 6)  # no tag changes, visibility 0, parent and platform clean
    chunk.write_bit(1)
    chunk.write_bits(torch, 64)  # same raw bit order as the RPC arg
    w = BitWriter()
    w.write_bits(chunk.bit_len(), 16)
    w.write_aligned_bytes(chunk.to_bytes())
    r = BitReader(w.to_bytes())
    _expect(state.translate_payload(7, r, w.bit_len()) is not None, state.failed)
    _expect(state.equipped == {"hands": torch}, state.equipped)


def test_migration_info() -> None:
    """Cave migration: the phone's sub id and trailing u64, pointed at the target shard's bridge."""
    def lan_info(sub: int, port: int, tail: bool = False, ip: bytes = b"10.0.0.17", pw: bytes = b"") -> BitWriter:
        w = BitWriter()
        w.write_bits(0xA3, 8)
        w.write_bits(sub, 8)
        w.write_bits(len(ip), 16)
        w.write_aligned_bytes(ip)
        w.write_bits(port, 16)
        w.write_bits(len(pw), 16)
        if pw:
            w.write_aligned_bytes(pw)
        if tail:
            w.write_bits(0, 64)
        return w

    peer = _peer()
    tx = GeyserTranslator(TranslatorConfig(enabled=True, translate_construction=True, migrate_ports={11003: 11004}))
    for number, (port, want_port) in enumerate([(11003, 11004), (11005, 11005)]):  # the second shard has no bridge
        pc = lan_info(0x98, port)
        outs = tx.translate_datagram("s2c", _wrap(pc.to_bytes(), pc.bit_len(), number, number), peer=peer, now=0.1)
        want = lan_info(0x99, want_port, tail=True)
        packets = walk_datagram(outs[0])
        _expect(len(outs) == 1 and len(packets) == 1, outs)
        _expect((packets[0].payload, packets[0].bitlen) == (want.to_bytes(), want.bit_len()), packets[0].payload.hex())
    online = lan_info(0x97, 1)
    out = _wrap(online.to_bytes(), online.bit_len(), 7, 4)
    _expect(tx.translate_datagram("s2c", out, peer=peer, now=0.3) == [out], "online message changed without a host")
    # Online cluster: with the public host set, the online message becomes a LAN one at the Caves bridge.
    tx = GeyserTranslator(TranslatorConfig(enabled=True, translate_construction=True, migrate_ports={11003: 11004},
                                           migrate_host="dst.example.net", migrate_password=b"pw"))
    outs = tx.translate_datagram("s2c", _wrap(online.to_bytes(), online.bit_len(), 0, 0), peer=_peer(), now=0.1)
    packets = walk_datagram(outs[0])
    want = lan_info(0x99, 11004, tail=True, ip=b"dst.example.net", pw=b"pw")
    _expect((packets[0].payload, packets[0].bitlen) == (want.to_bytes(), want.bit_len()), packets[0].payload.hex())
    # Phone on EOS: either PC message becomes the phone's online one, looked up in the Mobile row.
    row = None
    tx = GeyserTranslator(TranslatorConfig(enabled=True, translate_construction=True, migrate_ports={11003: 11004},
                                           migrate_lobby=lambda: row, migrate_shard=2, migrate_password=b"pw"))
    lan = lan_info(0x98, 11003)
    outs = tx.translate_datagram("s2c", _wrap(lan.to_bytes(), lan.bit_len(), 0, 0), peer=_peer(), now=0.1)
    _expect(walk_datagram(outs[0])[0].payload[1] == 0x99, "no row file yet: LAN form expected")
    row = ("KU_TestRow^0000000000000000", "ap-southeast-1")

    def online_want(pw: bytes) -> BitWriter:
        w = BitWriter()
        w.write_bits(0xA3, 8)
        w.write_bits(0x98, 8)
        for text in (b"KU_TestRow^0000000000000000", b"ap-southeast-1", None, pw):
            if text is None:
                w.write_bits(2, 32)
                continue
            w.write_bits(len(text), 16)
            if text:
                w.write_aligned_bytes(text)
        w.write_bits(0, 64)
        return w

    pc_online = BitWriter()  # PC 0x97: two strings, u32, password
    pc_online.write_bits(0xA3, 8)
    pc_online.write_bits(0x97, 8)
    for text in (b"KU_pc^row", b"ap-southeast-1"):
        pc_online.write_bits(len(text), 16)
        pc_online.write_aligned_bytes(text)
    pc_online.write_bits(381056666, 32)
    pc_online.write_bits(7, 16)
    pc_online.write_aligned_bytes(b"shardpw")
    # The server's own password goes through; the cluster password only fills an empty one.
    cases = [(lan_info(0x98, 11003, pw=b"shardpw"), b"shardpw"), (lan_info(0x98, 11003), b"pw"),
             (pc_online, b"shardpw")]
    for number, (pc, pw) in enumerate(cases, start=1):
        outs = tx.translate_datagram("s2c", _wrap(pc.to_bytes(), pc.bit_len(), number, number), peer=_peer(), now=0.2)
        got = walk_datagram(outs[0])[0]
        want = online_want(pw)
        _expect((got.payload, got.bitlen) == (want.to_bytes(), want.bit_len()), got.payload.hex())


def test_world_network_schemas() -> None:
    """Both world network prefabs are known. The phone never asks to resume without one."""
    from .netvars import NetvarMapper, NetvarState
    mapper = NetvarMapper.from_dir()
    state = NetvarState(mapper)
    for i, prefab in enumerate(("forest_network", "cave_network")):
        _expect(prefab in mapper.pc, f"{prefab} missing from the PC schema")
        _expect(not state.hide(i, prefab), f"{prefab} would be hidden from the phone")
    pc = {name for _, name, _ in mapper.pc["cave_network"]}
    mob = {name for _, name, _ in mapper.mob["cave_network"]}
    _expect(pc <= mob, sorted(pc - mob))
    _expect(all(name.startswith("vault_floor_helper.") for name in mob - pc), sorted(mob - pc))


def test_empty_string_aligns() -> None:
    """A dirty empty net_string still aligns the stream: a pig built in mid chatter."""
    from .netvars import NetvarMapper
    tables = ({"action_components": [], "action_pairs": []}, {"action_components": [], "action_ids": []})
    pc = [(1, "talker.chatter.strid", "net_smallbyte"), (2, "talker.chatter.strtbl", "net_string"),
          (3, "named._name", "net_string"), (4, "combat._attackrange", "net_float")]
    mob = [(0, "damagehiteffect.health_data.damage", "net_float")] + pc  # the phone's extra var comes first
    mapper = NetvarMapper({"pigman": pc}, {"pigman": mob}, *tables)

    def chunk(schema_extra_clean: int) -> BitWriter:
        w = BitWriter()
        w.write_bits(0, 6)  # no tag changes, visibility 0, parent and platform clean
        for _ in range(schema_extra_clean):
            w.write_bit(0)
        w.write_bit(1); w.write_le_bits(2, 6)       # strid
        w.write_bit(1); w.write_bits(0, 16); w.align()  # strtbl: empty, yet aligned
        w.write_bit(1); w.write_bits(5, 16); w.write_aligned_bytes(b"Hamms")
        w.write_bit(1); w.write_le_bits(0x40400000, 32)
        return w

    src, want = chunk(0), chunk(1)
    dirty = {}
    out = mapper.translate_chunk("pigman", src.to_bytes(), src.bit_len(), dirty)
    _expect(dirty.get("named._name") == b"Hamms" and dirty.get("talker.chatter.strtbl") == b"", dirty)
    _expect(out == (want.to_bytes(), want.bit_len()), out)

    # Empty string last: the padding after it is part of the chunk.
    last = BitWriter()
    last.write_bits(0, 6)
    last.write_bit(0)
    last.write_bit(1); last.write_bits(0, 16); last.align()
    out = mapper.translate_chunk("pigman", last.to_bytes(), last.bit_len())
    want = BitWriter()
    want.write_bits(0, 6)
    want.write_bits(0, 2)
    want.write_bit(1); want.write_bits(0, 16); want.align()
    _expect(out == (want.to_bytes(), want.bit_len()), out)


def test_asset_fallback() -> None:
    """A PC-only anim build or animation reaches the phone as one it can draw."""
    from . import assets
    from .netvars import NetvarMapper, NetvarState

    def payload(build: str, anim: str, lead: int) -> BitWriter:
        w = BitWriter()
        w.write_bits(0, 16)      # no cEntity chunk
        w.write_bits(0, lead)    # the names sit at any bit offset
        w.write_bits(assets.name_hash(build), 32)
        w.write_bits(0b101, 3)
        w.write_bits(assets.name_hash(anim), 32)
        w.write_bits(0x5A, 8)
        return w

    def reader(w: BitWriter) -> BitReader:
        r = BitReader(w.to_bytes())
        r.nbits = w.bit_len()
        return r

    for lead in (0, 3, 7):
        src = payload("pig_frankenswine_build", "halloween_walk_loop", lead)
        want = payload("pig_build", "walk_loop", lead)
        out, swapped = assets.patch("pigman", reader(src))
        _expect((out.data, out.nbits) == (want.to_bytes(), want.bit_len()), f"lead {lead}")
        _expect(swapped == [("pig_frankenswine_build", "pig_build"), ("halloween_walk_loop", "walk_loop")], swapped)
        same = reader(src)
        _expect(assets.patch("spider", same) == (same, []), "another prefab was patched")
    plain = reader(payload("pig_build", "walk_loop", 5))
    _expect(assets.patch("pigman", plain) == (plain, []), "a pig the phone can draw was patched")

    # Through a 0x88 frame: the record keeps its size, an unknown net id is left alone.
    schema = {"pigman": []}
    tables = ({"action_components": [], "action_pairs": []}, {"action_components": [], "action_ids": []})
    state = NetvarState(NetvarMapper(schema, schema, *tables))
    state.prefab_of[4242] = "pigman"
    src = payload("pig_frankenswine_build", "halloween_idle_loop", 5)
    want = payload("pig_build", "idle_loop", 5)
    frame, bitlen = _serialize_frame([(4242, 0, src), (4243, 0, src)])
    encoded = _reencode_serialize(frame, bitlen, state)
    _expect(encoded is not None, "0x88 with a franken pig not translated")
    r = BitReader(encoded[0])
    r.nbits = encoded[1]
    r.read_bits(8)
    recs, left = _parse_serialize(r, 18)
    _expect(left == 0 and [rec[0] for rec in recs] == [4242, 4243], recs)
    _expect(recs[0][2].to_bytes() == want.to_bytes() and recs[0][2].bit_len() == want.bit_len(), "known pig")
    _expect(recs[1][2].to_bytes() == src.to_bytes(), "unknown net id changed")
    _expect(sorted(state.asset_fallbacks) == ["pigman: halloween_idle_loop -> idle_loop",
                                              "pigman: pig_frankenswine_build -> pig_build"], state.asset_fallbacks)


def test_recipe_rpc() -> None:
    """Craft RPCs: the recipe rpc_id is remapped by recipe name and skin_index is dropped."""
    from .rpc import CODE_BITS, ERPC_LUA, RpcMapper, encode_uint, write_signal
    mob = {"rpc": ["BufferBuild", "MakeRecipeFromMenu"], "action_ids": [],
           "recipes": ["axe=5", "torch=7"]}
    pc = {"rpc": ["BufferBuild", "Extra", "MakeRecipeFromMenu"], "action_ids": [],
          "recipes": ["axe=6", "torch=9", "witchbroom=7"]}
    mapper = RpcMapper(mob, pc)

    def lua_rpc(code: int, values: list[int]) -> BitWriter:
        w = BitWriter()
        write_signal(w, ERPC_LUA)
        w.write_bit(0)
        w.write_bits(code, CODE_BITS)
        for v in values:
            encode_uint(w, v)
        return w

    def decode(payload: bytes, nbits: int) -> tuple[int, list]:
        from .rpc import read_args, read_signal
        _erpc, start = read_signal(payload, nbits)
        r = BitReader(payload)
        r.pos = start + 1
        code = r.read_bits(CODE_BITS)
        return code, read_args(r, nbits)

    w = lua_rpc(2, [7, 3])  # MakeRecipeFromMenu(torch, skin_index 3)
    out = mapper.translate(w.to_bytes(), w.bit_len())
    _expect(out is not None, "craft rpc not translated")
    code, args = decode(out[0], out[1])
    _expect(code == 3 and args == [(6, 9), (0, 0)], (code, args))

    mapper.pc_code["DropItemFromInvTile"] = 4
    mapper.mob_names.append("DropActiveItem")
    w = BitWriter()
    write_signal(w, ERPC_LUA)
    w.write_bit(0)
    w.write_bits(3, CODE_BITS)  # DropActiveItem(entity)
    w.write_bits(15, 4)
    w.write_bits(0x1122334455667788, 64)
    out = mapper.translate(w.to_bytes(), w.bit_len())
    code, args = decode(out[0], out[1])
    _expect(code == 4 and args == [(15, 0x1122334455667788)], (code, args))

    w = lua_rpc(1, [5])  # BufferBuild(axe)
    out = mapper.translate(w.to_bytes(), w.bit_len())
    code, args = decode(out[0], out[1])
    _expect(code == 1 and args == [(4, 6)], (code, args))


def test_handshake_no_password_slot() -> None:
    """The phone handshake has no password slot and the bridge adds none in 0x91.

    The server checks the password in the 0x09 connection request (see
    test_conn_request_password); the 0x91 reader has no password slot, so the
    rewrite stays: id 0x91, version, net id none, name, user id, metrics."""
    from .rpc import (HANDSHAKE_CLIENT_INFO, NETID_NONE, NETID_PHONE_EOS, NETID_TYPE_BITS,
                      _read_rakstring, _write_rakstring, drop_phone_netid)

    def phone_handshake() -> BitWriter:
        w = BitWriter()
        w.write_bits(HANDSHAKE_CLIENT_INFO, 8)
        _write_rakstring(w, b"2.3.1")
        w.write_bits(NETID_PHONE_EOS, NETID_TYPE_BITS)
        _write_rakstring(w, b"e" * 32)          # EOS product user id
        _write_rakstring(w, b"Wilson")       # display name
        _write_rakstring(w, b"KU_userid")       # user id
        w.write_aligned_bytes(b"\x55" * 8)      # trailing metrics
        return w

    w = phone_handshake()
    out, nbits, note = drop_phone_netid(w.to_bytes(), w.bit_len())
    _expect(out is not None and note.startswith("handshake"), note)
    r = BitReader(out)
    r.nbits = nbits
    _expect(r.read_bits(8) == HANDSHAKE_CLIENT_INFO, "id changed")
    _expect(_read_rakstring(r) == b"2.3.1", "version")
    _expect(r.read_bits(NETID_TYPE_BITS) == NETID_NONE, "net id type")
    _expect(_read_rakstring(r) == b"Wilson", "name follows the net id (no password slot)")
    _expect(_read_rakstring(r) == b"KU_userid", "user id")
    r.align()
    _expect(r.read_aligned_bytes(r.remaining() // 8) == b"\x55" * 8, "metrics tail moved")


def test_conn_request_password() -> None:
    """The 0x09 connection request passes through the bridge UNCHANGED.

    The phone already appends the password it was prompted for to the tail of
    ID_CONNECTION_REQUEST (verified live: a join to a password server carries
    "...\\x00<password>" here, payload 192 bits incl. the 6-byte password). The PC
    server reads the password as the whole tail, so the bridge must NOT add it again;
    appending --server-password a second time doubles the field and the server rejects
    the join with ID_INVALID_PASSWORD ("Wrong Password", seen live 2026-11-13).
    """
    from .rpc import RpcMapper
    empty = {"rpc": [], "action_ids": [], "recipes": []}
    pay = b"\x09" + bytes(range(8)) + b"\x00" * 9
    datagram = bytes.fromhex("84000000") + b"\x40" + (len(pay) * 8).to_bytes(2, "big") + b"\x00\x00\x00" + pay

    # With a password configured, the 0x09 is still passed through unchanged.
    tx = GeyserTranslator(TranslatorConfig(enabled=True, rpc=RpcMapper(empty, empty, b"123456")))
    _expect(tx.translate_datagram("c2s", datagram, peer=_peer(), now=0.0) == [datagram],
            "0x09 with password configured changed")
    # Without a password the message also passes unchanged.
    tx2 = GeyserTranslator(TranslatorConfig(enabled=True, rpc=RpcMapper(empty, empty)))
    _expect(tx2.translate_datagram("c2s", datagram, peer=_peer(), now=0.0) == [datagram],
            "no-password 0x09 changed")
    # A split 0x09 (never seen in practice) is left alone.
    mid = len(datagram) // 2
    d0 = _wrap(datagram[:mid], mid * 8, 5, 5, flags=0x70, split=(2, 0x55, 0))
    d1 = _wrap(datagram[mid:], (len(datagram) - mid) * 8, 6, 6, flags=0x70, split=(2, 0x55, 1))
    tx3 = GeyserTranslator(TranslatorConfig(enabled=True, rpc=RpcMapper(empty, empty, b"123456")))
    _expect(tx3.translate_datagram("c2s", d0, peer=_peer(), now=0.0) == [d0], "split piece changed")
    _expect(tx3.translate_datagram("c2s", d1, peer=_peer(), now=0.0) == [d1], "split tail changed")


def main():
    test_le_layout()
    test_roundtrip()
    test_config_accepts_log()
    print("synthetic 24-bit -> 18-bit roundtrip: ok")
    test_datagram_rewrite()
    test_serialize_tail()
    test_serialize_message()
    test_live_frame87()
    test_split_rewrite()
    test_split_drops_empty_tail()
    test_tile_region_serialize()
    test_destruction_message()
    test_recipe_rpc()
    test_handshake_no_password_slot()
    test_conn_request_password()
    test_worn_item_unequip()
    test_migration_info()
    test_world_network_schemas()
    test_empty_string_aligns()
    test_asset_fallback()
    test_split_retransmit_dropped()
    test_split_tail_shares_datagram()
    test_split_listing()
    test_split_passthrough()
    test_continuous_send()
    test_capture_identity()
    print("datagram walker: ok")
    frame = open(SAMPLE, "rb").read()
    mid = frame[0] if frame else None
    print(f"sample frame: {len(frame)} bytes, msg id=0x{mid:02x}" if mid is not None else "empty sample")
    if mid == 0x2A:
        print("This buffer is ID_REPLICA_MANAGER_DOWNLOAD_STARTED (0x2a), not construction.")
        print("Prefab names are read from ID_DST_REPLICA_MANAGER_FRAME_CONSTRUCT_AND_SERIALIZE (0x87).")
        print("A raw-name scan of this buffer cannot confirm or reject Huffman. Capture an 0x87 frame.")
        return
    if mid != 0x87:
        print(f"unexpected message id 0x{mid:02x}; construction frames start with 0x87")
        return
    hits = scan(frame)
    if not hits:
        print("NO plausible RakString prefab name found by scan.")
        print(" => names may be GUID-only records first, or length encoding differs.")
        print("    Next: dump first 64 bits bit-by-bit and compare to mobile OnConstruction read order.")
        return
    print(f"found {len(hits)} candidate name position(s):")
    for p, n, name in hits[:20]:
        print(f"  bit {p:4d} (byte {p//8}.{p%8}): len={n:2d} name={name!r}")
    first = hits[0]
    print()
    print(f"FIRST plausible name at bit {first[0]} of the 0x87 body")
    print("   Compare that offset with: header + 18-bit id + flag + declared length.")


if __name__ == "__main__":
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    main()
