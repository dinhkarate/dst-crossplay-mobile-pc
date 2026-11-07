# geyser/ — DST Crossplay RM3 dialect translator (Geyser-style)

Detachable protocol-translation layer for the LAN bridge, modeled on GeyserMC
(Minecraft Bedrock↔Java proxy). The mobile client and the PC dedicated server speak
**different RakNet ReplicaManager3 (RM3) dialects**; this module rewrites RM3 frames
on the wire so each side sees its own dialect — **without patching either binary**, so
a server/client update never hard-breaks the pipe (worst case: disable the module →
passthrough → re-verify).

## Files
- `bitstream.py` — RakNet BitStream primitives (MSB-first reader/writer): `ReadBit`,
  `ReadBits`, `ReadAlignedBytes`, `ReadBitsFromIntegerRange`, RakString raw (u16+bytes).
- `translator.py` — `GeyserTranslator` (pluggable adapter: `server_to_client` /
  `client_to_server`), the RM3 parse, and the Klei→vanilla transform. Passthrough when
  disabled or on any parse error (never corrupts the pipe).
- `selftest.py` — finalization tool: scans a captured 0x87 construction frame to pin the
  exact wire layout. The checked-in sample is 0x2a, so the tool refuses it. Run:
  `python3 -m geyser.selftest` from `proxy-bridge/`.
- `sample_construction_0x2a.bin` — a 246-byte server→client buffer kept from the
  2026-11-07 join. Its first byte is `0x2a` = `ID_REPLICA_MANAGER_DOWNLOAD_STARTED`,
  not the construction frame. Do not scan it for prefab names.

## Confirmed facts (2026-11-07, client log + disasm of both binaries)
- Mobile join reaches our server: listing rewrite OK (Platform 64, v64020301),
  session begins, then native assert:
  `cNetworkConnection::AllocReplica Failed to read prefab_name` (NetworkConnection.cpp:74)
  → 75× `RakNet detected a missing replica` → no CLIENT_READY → no spawn.
- `IsNetworkOrderInternal` returns 0 on both binaries (server `FUN_003ecf70`;
  mobile VA `0x8f5740` is `mov w0, wzr; ret`). Integer fields are little-endian
  `ReadBits`/`WriteBits` with `rightAligned=1`, and there is no byte swap.
- Both sides read the same `0x87` header and the same per-record declared-length
  field (`ReadBitsFromIntegerRange(0, 1023, allowOutside=1)`). Mobile does this
  at VA `0x9564d0`. The server log string is absent from the `.so`; the read is
  not. Do not strip that field.

## Message ids (both binaries, 2026-11-07)
`ReplicaManager3::OnReceive` compares the same immediates on the server (VA `0x30f670`)
and on mobile (VA `0x954108`). The packetNames table in the server (file `0x52f000`,
slot 0 = `ID_UNCONNECTED_PONG` = `0x1c`) gives the names:

| Id | Name | Handler |
|----|------|---------|
| `0x2a` | `ID_REPLICA_MANAGER_DOWNLOAD_STARTED` | not construction |
| `0x87` | `ID_DST_REPLICA_MANAGER_FRAME_CONSTRUCT_AND_SERIALIZE` | OnConstruction, reads prefab names |
| `0x88` | `ID_DST_REPLICA_MANAGER_FRAME_SERIALIZE` | OnSerialize |

The 246-byte buffer is `0x2a`. It has no prefab names because it is not a construction
frame. The earlier "no raw name anywhere, so Huffman" scan does not apply to `0x87`.

## What both readers do on `0x87`
Server `OnConstruction` (file VA `0x30e8e0`) and mobile `OnConstruction` (VA `0x956208`):

- 1 bit has-construction; if set, `ReadBitsFromIntegerRange(0, 1023, allowOutside=true)` count
- 1 bit has-destruction; if set, the same ranged count
- each construction record: network id, 1 flag bit, declared payload length (same
  ranged field), then exactly that many payload bits
- each destruction record: network id, then 64 bits. A missing object does
  `IgnoreBytes(8)`, which adds 64 to the bit cursor and does not realign

The width that differs is the network id. The server writes it (`FUN_0040c790`,
file `0x30c790`) and reads it (`0x30eb12`, destruction `0x30f181`) as **24 bits**,
`allowOutside=0`, max `0xffffff`. Mobile reads **18 bits** (`0x95635c` and
`0x956e00`, `ReadBits` count `0x12`, right-aligned). An id that does not fit in
18 bits must not be truncated; the frame stays as the server sent it.

`OnFramePacket` (server `FUN_0040f4b0`) does not stop at construction. On the
same bitstream, while more than 39 bits remain, it reads OnSerialize records:
network id, one flag bit, then a length (`0..32767` in 15 bits when the flag
is 0, `0..0x7fffffff` in 31 bits when the flag is 1), then that many payload
bits. `0x88` is that loop with no construction header. Mobile OnSerialize reads
the id as 18 bits at VA `0x957684`. The length field matches the server.

`klei_to_vanilla_construction` rewrites every 24-bit id in the `0x87`,
including the serialize tail, and copies the flag, the declared-length field,
and the payload/GUID bits. The same rewrite covers `0x88`. Huffman is not
established. A readable prefab name inside a live construction payload is still
unproven: flag 1 starts that payload with a 64-bit GUID.

`translate_datagram` walks a user datagram whose flag byte has IsValid set and
isACK/isNAK clear (`(b0 & 0xE0) == 0x80`, low two bits clear). isPacketPair,
isContinuousSend, and needsBAndAs stay in that byte. A world burst is `0x88`
(isContinuousSend) or `0x8c` (isContinuousSend and needsBAndAs), and those are
rewritten the same way as `0x84`. It rewrites an s2c internal payload when it
is `0x87` or `0x88` and every id fits in 18 bits. The uint16 BE `dataBitLength`
becomes the writer's exact bit length. The bits the phone's loop does not read
(39 or fewer after the last serialize record) are not copied. ACK (`0xC0`),
NAK (`0xA0`), `0x86`, `0x8b`, `0x2a`, `0x1b`, and `0x4b` are forwarded
unchanged. A split `0x87` or `0x88` is reassembled, then the rewritten bits are
packed into the front pieces. `dataBitLength` shrinks from the end so the sum
equals the rewritten length. Pieces that lose every bit are not sent, and the
uint32 BE split count on the pieces that remain is updated. Datagram numbers
and reliable message numbers of the pieces that remain stay put. A zero tail
inside the old length would be read as more serialize records. Parse failure,
a wide id, or a translated frame that would grow is the original datagram. A
split whose first piece is not `0x87` or `0x88` is forwarded as each piece
arrives. An incomplete `0x87`/`0x88` split is held 8s, then the originals are
forwarded. While a piece is held, the bridge ACKs that datagram to the server.

The join captured on 2026-11-07 had one `0x87` (construction ids 33919 and
16385, then the same two ids as serialize records, 1791 bits) and two `0x88`
packets (id 33919, 68 bits). All five ids fit in 18 bits. Replaying them
shrinks the `0x87` to 1767 bits and each `0x88` to 62 bits, and an 18-bit parse
returns the same payloads. The bridge that was running for that join refused
the `0x87` because of the serialize tail, so this replay is not a live play test.

## Wiring into the bridge
`lan_bridge.py --geyser` builds `TranslatorConfig(enabled=True, translate_construction=True, translate_serialize=True)`.
Listing rewrite still runs first. `translate_datagram` returns the datagrams to
send now (empty while a split is held). The bridge calls `flush` on each
`select` turn for the 8s timeout, and ACKs a held datagram on the upstream
socket. No `--geyser` flag is the same passthrough.
