#!/usr/bin/env python3
"""Patch a stock DST dedicated server (build 762172) for crossplay.

    patch_server.py <dst-server-dir>          apply (safe to run twice)
    patch_server.py --check <dst-server-dir>  only report the state

Every site is checked first: a byte that is neither stock nor patched means this is a
different build, and nothing is written. The offsets only fit build 762172; the bridge's
translation tables are for that build too.

The version is left stock so direct PC clients still match (the bridge rewrites the
version the phone sees). The Floodgate pair lets an ONLINE cluster accept a bridged phone,
which cannot pass Klei's online session check, so the server self-registers on both the
Steam and the Mobile lobby while the phone still joins.
"""
import sys
from pathlib import Path

BUILD = 762172
BINARY = "bin64/dontstarve_dedicated_server_nullrenderer_x64"

# file offset, stock bytes, patched bytes
PATCHES = [
    # Accept the phone's longer network id.
    (0x27E46D, b"\x1f", b"\x20"),
    (0x27E493, b"\x01", b"\x00"),
    (0x27EB13, b"\x1f", b"\x3f"),
    # Take the "client sent no loadout" path for the inventory handshake (message 0x92):
    # the phone serializes its skins in a dialect this server cannot read. Players join
    # with default cosmetics.
    (0x263133, bytes.fromhex("7763"), bytes.fromhex("9090")),
    # Floodgate: trust a client that did not clear Klei's online session check, so a
    # bridged phone reaches "Client authenticated" on an online cluster. Gate#1 NOPs the
    # unauth reject; ROOT (je -> jmp) forces the offline-promote branch for every client.
    # Direct PC clients still authenticate through Steam/Klei as normal.
    (0x20CBA3, bytes.fromhex("0f84a7020000"), bytes.fromhex("909090909090")),
    (0x21A813, bytes.fromhex("0f84bc000000"), bytes.fromhex("e9bd00000090")),
]


def main():
    args = [a for a in sys.argv[1:] if a != "--check"]
    check = "--check" in sys.argv[1:]
    if len(args) != 1:
        sys.exit(__doc__)
    root = Path(args[0])
    version = (root / "version.txt").read_text().strip()
    if version != str(BUILD):
        sys.exit(f"{root} is build {version}; this patch set only fits build {BUILD}")
    path = root / BINARY
    data = bytearray(path.read_bytes())
    todo = 0
    for offset, stock, patched in PATCHES:
        current = bytes(data[offset:offset + len(stock)])
        if current == stock:
            todo += 1
            data[offset:offset + len(stock)] = patched
        elif current != patched:
            sys.exit(f"unexpected bytes {current.hex()} at {offset:#x}: not a stock {BUILD} binary")
    if check:
        print("patched" if todo == 0 else f"stock at {todo} of {len(PATCHES)} sites")
        return
    if todo:
        path.write_bytes(data)
    print(f"{path}: {todo} site(s) patched, {len(PATCHES) - todo} already done")


if __name__ == "__main__":
    main()
