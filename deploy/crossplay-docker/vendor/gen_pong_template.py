#!/usr/bin/env python3
"""Synthesize vendor/pong_mobile.hex from the known wire format.

A mobile DST server answers an unconnected RakNet ping with a pong whose payload is a
`tServerListing` (same class as the 0x86 handshake listing; see
proxy-bridge/listing_rewrite.py). The bridge (proxy-bridge/lan_bridge.py,
build_payload) only ever reads four things out of this template and overwrites the rest
live:

  * the EOS ProductUserId (32 hex, matches /0002[0-9a-f]{28}/) -> the relay's own PUID
  * the 16-hex session marker                                  -> a fresh random session
  * the region (2 bytes)                                       -> kept
  * the server name                                            -> --name

So nothing identifying needs to survive in the file. This generator emits the exact
byte layout with PLACEHOLDER values for the two account-bound fields (the EOS PUID and
the Klei owner id), which is why it does not need a packet captured from a live server
and ships no one's account id.

Layout (big-endian multi-byte), verified byte-for-byte against a real capture:

    0006                        listing header
    0001                        flags (high)
    80                          flag byte: 0x80 dedicated | 0x40 client-hosted
    0000003c                    u32 (constant in observed listings)
    0000000000000001            8 bytes (constant)
    4008 00                     owner block marker
    <32 ascii hex>              EOS ProductUserId  (placeholder; bridge overwrites)
    <len(owner) << 7, 3 bytes>  0 bit + u16 owner length + padding (000b80 for 23 chars)
    "OU_<digits>"               Klei owner id      (placeholder)
    03d0df4d                    version u32 = 64020301
    00000040                    platform u32 = 64 (mobile)
    0010                        session marker
    <16 ascii hex>              session            (placeholder; bridge overwrites)
    8524000000800100            8-byte tail (as captured; LAN-only bit clear, so phones use EOS)
    "US"                        region (2 bytes)
    <u16 len><name>             server name        (placeholder; bridge overwrites)
"""
import argparse
import struct
import sys

# Constant, non-identifying bytes of the layout.
HEADER      = bytes.fromhex("0006")
FLAGS_HIGH  = bytes.fromhex("0001")
FLAG_DED    = 0x80            # dedicated, client-hosted bit cleared
U32_CONST   = bytes.fromhex("0000003c")
EIGHT_CONST = bytes.fromhex("0000000000000001")
OWNER_MARK  = bytes.fromhex("400800")
VERSION     = bytes.fromhex("03d0df4d")   # 64020301
PLATFORM    = bytes.fromhex("00000040")   # 64 = mobile
SESS_MARK   = bytes.fromhex("0010")
TAIL8       = bytes.fromhex("8524000000800100")

# Placeholders. The PUID must match /0002[0-9a-f]{28}/ so build_payload can find and
# replace it; the session must be 16 hex chars. Neither value is anyone's real id.
PLACEHOLDER_PUID    = "0002" + "0" * 28
PLACEHOLDER_SESSION = "0" * 16
PLACEHOLDER_OWNER   = "OU_0000000000000000000"   # synthetic; not a real Klei account


def build_template(name: str, region: str, owner: str, flag: int = FLAG_DED) -> bytes:
    if len(region) != 2:
        raise ValueError("region must be exactly 2 characters, e.g. US")
    name_b = name.encode()
    # The owner block starts with a 0 bit, then the owner id's u16 length, then padding to
    # the next byte: 3 bytes holding len << 7. The phone rejects the pong if it is wrong.
    owner_mark = (len(owner) << 7).to_bytes(3, "big")
    return (
        HEADER + FLAGS_HIGH + bytes([flag]) + U32_CONST + EIGHT_CONST
        + OWNER_MARK + PLACEHOLDER_PUID.encode("ascii")
        + owner_mark + owner.encode("ascii")
        + VERSION + PLATFORM
        + SESS_MARK + PLACEHOLDER_SESSION.encode("ascii")
        + TAIL8 + region.encode("ascii")
        + struct.pack(">H", len(name_b)) + name_b
    )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-o", "--out", default="pong_mobile.hex",
                    help="output file (default: pong_mobile.hex in the current directory)")
    ap.add_argument("--name", default="crossplay",
                    help="placeholder server name; the bridge overwrites it with --name at runtime")
    ap.add_argument("--region", default="US", help="2-letter region shown in the listing (default US)")
    ap.add_argument("--owner", default=PLACEHOLDER_OWNER,
                    help="placeholder Klei owner id; keep the synthetic default unless you have a reason")
    ap.add_argument("--client-hosted", action="store_true",
                    help="set the client-hosted flag bit (0xc0) instead of dedicated (0x80); "
                         "only if a live test shows the phone rejects the dedicated pong")
    args = ap.parse_args()

    flag = 0xc0 if args.client_hosted else FLAG_DED
    tmpl = build_template(args.name, args.region, args.owner, flag)
    with open(args.out, "w") as f:
        f.write(tmpl.hex())
    print(f"wrote {args.out} ({len(tmpl)} bytes, {len(tmpl)*2} hex chars)")
    print("  EOS PUID + session are placeholders; the bridge fills them at runtime.")
    print("  No account id from any real server is embedded.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
