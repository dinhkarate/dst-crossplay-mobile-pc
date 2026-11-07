#!/usr/bin/env python3
"""Fix the PC->mobile handshake server-listing (0x86 message) so mobile accepts it.

Found via Unicorn emulation of the real mobile libDontStarve.so + live join tests.
The listing on the wire is
`[0x86][u32 ts][tServerListing]`, and tServerListing serializes as:

    [0006] [flags] [owner] [version u32] [platform u32] [0010 session16] [84 6X]
    [region] [name] [world-data ...]

PC (Steam) and mobile diverge ONLY in the FRONT: flags, the owner block, platform,
and the one tail byte after the session. Everything from the region onward (name +
world-data) is identical and passes through. The required rewrite:

  1. Replace the PC flags+owner block (Steam, ~26B: `0000 80 ... <12B compressed owner>`)
     with the mobile flags+owner block (EOS, ~76B: `0001 c0 ... 4008 00 <32-hex EOS
     product-user-id> 00 0b80 OU_<klei id>`). This is the byte-exact front of a real
     mobile pong/listing the phone's own Deserialize accepts.
     WITHOUT this, the mobile parser reads its ~60B EOS owner starting where the PC
     listing only has 12B, so every later field (incl. version @0x220) is read from the
     wrong offset -> it decodes a garbage version -> ID_DST_INCOMPATIBLE_PROTOCOL_VERSION
     (seen live on the phone 2026-11-13, even though the version VALUE was set correctly).
  2. version u32 -> 64020301 (0x03d0df4d) and platform u32 -> 64 (0x00000040, mobile).
  3. tail byte after the session: PC `84 61` -> mobile `84 65`.
  4. Append one trailing 0x00 byte: cNetworkManager::DeserializeHandShakeServerListing
     (@0x84927c) reads ONE MORE bool bit after tServerListing::Deserialize; PC omits it
     -> buffer overrun -> VERSION_HANDSHAKE_FAILED. The 0x00 gives bool=0 (success path).
  5. Fix the RakNet reliability-frame bitLength (u16 BE at byte offset 5).

The MOBILE_FRONT constant is lifted byte-for-byte from a replay-validated capture of a
mobile listing, with the owner's ids zeroed."""

# Mobile flags + EOS owner block from a validated mobile-format listing.
# (flags 0001 80 ... 4008 00 <32-hex EOS puid> 00 0b80 "OU_<account id>"; both zeroed here)
# The flag byte is 0x80 dedicated (struct +0x224) | 0x40 client-hosted (+0x225). The capture
# came from a phone-hosted game (0xc0); a dedicated server must clear 0x40, or the phone
# counts and lists the server's own [Host] entry as a player.
MOBILE_FRONT = bytes.fromhex(
    "0001800000003c0000000000000001"
    "4008003030303230303030303030303030303030303030303030303030303030303030"
    "000b80"
    "4f555f3030303030303030303030303030303030303030"
)

# PC version+platform markers (version u32 BE, platform u32 BE = 1/Steam) we rewrite.
PC_VER_PLATS = (
    bytes.fromhex("03d0df4d00000001"),  # patched server: version 64020301 + platform 1
    bytes.fromhex("000ba13c00000001"),  # stock server:   version 762172   + platform 1
)
MOB_VER_PLAT = bytes.fromhex("03d0df4d00000040")  # version 64020301 + platform 64 (mobile)


def rewrite_listing(pkt: bytes) -> bytes | None:
    """One unsplit 0x86 datagram. A listing too big for one datagram (a world with a
    Caves shard attached) arrives split; the geyser translator rewrites that one whole
    with rewrite_listing_payload."""
    if len(pkt) < 15 or pkt[0] != 0x84 or pkt[4] != 0x60:
        return None
    hdr = pkt[:14]
    new_payload = rewrite_listing_payload(pkt[14:])
    if new_payload is None:
        return None
    bitlen = len(new_payload) * 8
    header = bytearray(hdr)
    header[5] = (bitlen >> 8) & 0xff
    header[6] = bitlen & 0xff
    return bytes(header) + new_payload


def rewrite_listing_payload(payload: bytes) -> bytes | None:
    """The 0x86 message in mobile format, or None when it is not a PC listing."""
    if not payload or payload[0] != 0x86:
        return None
    # Locate the version+platform field (also tells us which server build this is).
    v = -1
    for cand in PC_VER_PLATS:
        j = payload.find(cand)
        if j >= 0:
            v = j
            break
    if v < 0:
        return None
    pre = payload[:7]            # [0x86][u32 ts][0006]  (keep)
    # payload[7:v] is the PC flags+owner block -> replaced by MOBILE_FRONT.
    after = payload[v + 8:]      # [0010 session16][84 6X][region+name+world-data]  (keep)
    sess, tailpair, rest = after[:18], after[18:20], after[20:]
    # Flip only the tail byte after the session: PC 0x61 -> mobile 0x65.
    tail = bytes([tailpair[0], 0x65]) if len(tailpair) == 2 and tailpair[0] == 0x84 else tailpair
    return pre + MOBILE_FRONT + MOB_VER_PLAT + sess + tail + rest + b"\x00"


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        d = open(sys.argv[1], "rb").read()
        out = rewrite_listing(d)
        print("in", len(d), "out", len(out) if out else None,
              "platform64", (MOB_VER_PLAT in out) if out else None,
              "OU_", (b"OU_" in out) if out else None,
              "newbits", hex((out[5] << 8) | out[6]) if out else None)
    else:
        print("usage: listing_rewrite.py <captured 0x86 datagram .bin>")
