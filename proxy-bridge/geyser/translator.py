"""DST Crossplay protocol translator — the "Geyser" layer.

Analogy to GeyserMC (Minecraft Bedrock<->Java proxy): the mobile client speaks one
RakNet ReplicaManager3 (RM3) dialect and the PC dedicated server speaks another.
Instead of patching either binary, this module sits in the LAN bridge and rewrites
the RM3 frames on the wire so each side sees its own dialect. Fully detachable:
if disabled (or if a frame isn't understood) it passes bytes through unchanged, so
a server/client update never hard-breaks the pipe — worst case you fall back to the
pre-translation behaviour and re-verify.

------------------------------------------------------------------------------
WIRE MISMATCH (disasm 2026-11-07, both binaries, IsNetworkOrderInternal == 0):
  0x87 = ID_DST_REPLICA_MANAGER_FRAME_CONSTRUCT_AND_SERIALIZE. Same header on
  both sides:
    1 bit has-construction; if set, ReadBitsFromIntegerRange(0, 1023, allowOutside)
    1 bit has-destruction; if set, the same ranged count
  Construction record:
    network id, 1 flag bit, declared payload length (same ranged 0..1023),
    then exactly that many payload bits.
  Destruction record in the same frame:
    network id, then 64 bits (GUID). IgnoreBytes(8) on a miss is +64 bits,
    not an align-then-skip.
  The same 0x87 bitstream then continues with OnSerialize records
  (OnFramePacket, FUN_0040f4b0) while more than 39 bits remain. A record is
  a network id, one flag bit, then a declared length: flag 0 is range
  0..32767 (15 bits), flag 1 is range 0..0x7fffffff (31 bits), then that
  many payload bits. 0x88 is the same serialize loop with no construction
  header. Mobile OnSerialize reads the id as 18 bits (VA 0x957684).

  The declared-length field is read by mobile OnConstruction at VA 0x9564d0.
  Do not strip it. The log string is absent on mobile; the read is not.

  Width that differs: server writes and reads the network id as 24 bits
  (receive file 0x30eb12 and 0x30f181; writer FUN_0040c790). Mobile reads 18
  bits (VA 0x95635c construction, 0x956e00 destruction), right-aligned, and
  does not byte-swap. Six extra bits per record shift the payload, which
  matches AllocReplica failing to read prefab_name.

  Translate server->client by rewriting each id 24 -> 18 and copying the flag,
  the declared-length field, and the payload/GUID bits. If any id does not fit
  in 18 bits, or the datagram does not parse, return the original bytes.
  Huffman is not established; it was inferred from a 0x2a download-started buffer.

  A readable prefab name from a live 0x87 is still unproven. The bridge turns
  the rewrite on only after the RakNet walker has isolated the message, and
  any doubt forwards the datagram unchanged.
------------------------------------------------------------------------------
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from .bitstream import BitReader, BitWriter
from .netvars import NetvarState, construction_prefab
from .rpc import _read_rakstring, _write_rakstring
from .raknet import (
    InternalPacket,
    build_datagram,
    datagram_number,
    nak_numbers,
    replace_payload,
    walk_datagram,
)

# Ids from the PC server packetNames table (file 0x52f000, index 0 = ID_UNCONNECTED_PONG
# = 0x1C) and from ReplicaManager3::OnReceive in BOTH binaries (server VA 0x30f670,
# mobile VA 0x954108). 0x1C + table index.
MSG_SERVER_LISTING = 0x86          # ID_DST_HANDSHAKE_SERVER_INFO (listing_rewrite.py)
MSG_FRAME_CONSTRUCT = 0x87         # ID_DST_REPLICA_MANAGER_FRAME_CONSTRUCT_AND_SERIALIZE
MSG_FRAME_SERIALIZE = 0x88         # ID_DST_REPLICA_MANAGER_FRAME_SERIALIZE
MSG_FRAME_DESTRUCTION = 0x8B       # ID_DST_REPLICA_MANAGER_DESTRUCTION
# Shard -> player. Same id on both builds (dispatch tables: PC server VA 0x452cf0, mobile
# VA 0x4469ea). The next byte is the shard sub id, where the phone's enum is one ahead
# (cShardManager::OnReceivedPacketFromMainServer, PC VA 0x2b2d30, mobile VA 0x8be44c).
MSG_SHARD_TO_PLAYER = 0xA3
PC_MIGRATION_INFO = 0x97           # ID_SHD_O2P_MIGRATION_INFO (online cluster: a lookup, no address)
PC_LAN_MIGRATION_INFO = 0x98       # ID_SHD_O2P_LAN_MIGRATION_INFO
MOBILE_LAN_MIGRATION_INFO = 0x99
MOBILE_MIGRATION_INFO = 0x98       # online: rowId, region, u32 shard id, password, u64 room id
# Messages that carry net ids. A split one is held until it can be rewritten whole.
_FRAME_MESSAGES = (MSG_FRAME_CONSTRUCT, MSG_FRAME_SERIALIZE, MSG_FRAME_DESTRUCTION)
# Handshake server listing. With a Caves shard attached it no longer fits one datagram,
# and lan_bridge only rewrites an unsplit one, so a split one is held and rewritten here.
MSG_SERVER_LISTING = 0x86
# Stock RakNet ids. 0x2A is download-started, not construction. The 246-byte
# sample_construction_0x2a.bin is this message and has no prefab names.
RM_SCOPE_CHANGE = 0x28             # ID_REPLICA_MANAGER_SCOPE_CHANGE
RM_DOWNLOAD_STARTED = 0x2A         # ID_REPLICA_MANAGER_DOWNLOAD_STARTED
RM_DOWNLOAD_COMPLETE = 0x2B        # ID_REPLICA_MANAGER_DOWNLOAD_COMPLETE


@dataclass
class TranslatorConfig:
    enabled: bool = False                 # master switch; passthrough when False
    translate_construction: bool = False  # 0x87 id width 24->18. lan_bridge --geyser sets this.
    translate_serialize: bool = False     # 0x88 and the serialize tail inside 0x87. Same 24->18 id width.
    netvars: object = None                # netvars.NetvarMapper: re-encode entity netvars PC -> mobile
    rpc: object = None                    # rpc.RpcMapper: remap phone Lua RPC codes and actions to PC
    migrate_ports: dict = field(default_factory=dict)  # shard server port -> port of the bridge in front of it
    migrate_host: str = ""                # address phones dial; turns the online 0x97 into a LAN 0x99
    migrate_password: bytes = b""         # cluster password carried in that 0x99
    listing: object = None                # callable(0x86 payload) -> mobile payload | None; for split listings
    migrate_lobby: object = None          # callable() -> (rowId, region) of the Mobile row | None
    migrate_shard: int = 0                # shard id the phone looks up in that row's secondaries
    log: object = None                    # optional callable(str); must be annotated or dataclass drops it


# Server write/read width vs mobile ReadBits width. Same for construction and
# the destruction records carried inside 0x87.
SERVER_NETID_BITS = 24
MOBILE_NETID_BITS = 18
MOBILE_NETID_MAX = (1 << MOBILE_NETID_BITS) - 1
COUNT_MIN = 0
COUNT_MAX = 0x3FF  # ReadBitsFromIntegerRange(0, 1023, allowOutside=1)
DESTRUCTION_TAIL_BITS = 64  # GUID, or IgnoreBytes(8) when the object is missing
# OnFramePacket reads another serialize record only while more than 0x27 bits remain.
SERIALIZE_STOP_BITS = 39
SERIALIZE_SHORT_MAX = 0x7FFF
SERIALIZE_LONG_MAX = 0x7FFFFFFF
# cNetworkTileRegion::Serialize is one RLE of exactly 256 ushorts, the same on
# both builds. Each client creates one region per 16x16 block of the map itself,
# with a fixed network id below the server range: x + 128*y on the PC (server ids
# start at 16384), x + 64*y on the phone (GetTileRegionNetworkID, mobile VA
# 0x83bebc; server ids start at 4096). Forwarding PC ids put the tiles in the
# wrong region and rebuilt rows outside the ocean colour buffer.
#
# Every region goes through, edge regions and the world-frame snapshot included.
# The client never loads tiles from the save: TileGrid starts as 0xFFFF and
# MapComponent::NetworkTileRegionDeserialized (mobile VA 0x6b3be0) builds the
# ground vertex buffers only after the first serialize of all regions (27x27 on a
# 425 map). Edge regions are safe: TileGrid allocates whole regions.
#
# The first server id, 16384, is an object the PC client already has (empty
# construction, 5-bit serialize). The phone has none, neither at 16384 nor at its
# own first server id 4096. On a missing replica it misreads every later record of
# the frame, so most regions never arrived. Its records are not forwarded.
_TILE_REGION_COUNT = 256
PC_TILE_REGION_STRIDE = 128
MOBILE_TILE_REGION_STRIDE = 64
PC_TILE_REGION_IDS = PC_TILE_REGION_STRIDE * PC_TILE_REGION_STRIDE
PC_ONLY_NETID = PC_TILE_REGION_IDS


def _pc_region_xy(net_id: int) -> tuple[int, int] | None:
    if net_id >= PC_TILE_REGION_IDS:
        return None
    x, y = net_id % PC_TILE_REGION_STRIDE, net_id // PC_TILE_REGION_STRIDE
    if x >= MOBILE_TILE_REGION_STRIDE or y >= MOBILE_TILE_REGION_STRIDE:
        return None
    return x, y


def _mobile_region_id(net_id: int) -> int:
    """Phone id of a PC tile region, or the id unchanged for anything else."""
    xy = _pc_region_xy(net_id)
    return net_id if xy is None else xy[0] + MOBILE_TILE_REGION_STRIDE * xy[1]


@dataclass
class ParseTrace:
    ok: bool = False
    desync_at_bit: int | None = None
    note: str = ""
    records: list = field(default_factory=list)


def parse_construction_stock(reader: BitReader) -> ParseTrace:
    """Legacy probe. This is NOT ReplicaManager3::OnConstruction.

    The confirmed outer record is network-id, one flag bit, a declared length,
    then that many payload bits (see klei_to_vanilla_construction). The prefab
    name, if present, sits inside those payload bits. This helper only tries to
    read a RakString at the reader's current position.
    """
    tr = ParseTrace()
    try:
        disc = reader.read_bit()
        if disc == 0:
            name = reader.read_rakstring()
            if not name or any(c < 0x20 or c >= 0x7F for c in name):
                tr.desync_at_bit = reader.pos
                tr.note = f"first entity name not printable: {name!r} -> header/guard offset wrong"
                return tr
            tr.records.append(("entity", name.decode("latin1")))
            tr.ok = True
            tr.note = f"first entity prefab = {name.decode('latin1')!r} (name read OK)"
        else:
            tr.records.append(("client-object", None))
            tr.ok = True
            tr.note = "first record is client-object (disc=1)"
    except EOFError as e:
        tr.desync_at_bit = reader.pos
        tr.note = f"EOF while reading first record: {e}"
    return tr


def _transfer_bits(src: BitReader, dst: BitWriter, n: int) -> None:
    """Copy n raw stream bits. read_bits/write_bits are inverses, so the
    little-endian integer layout inside the payload is preserved."""
    while n > 0:
        k = 32 if n >= 32 else n
        dst.write_bits(src.read_bits(k), k)
        n -= k


def _lift_bits(reader: BitReader, n: int) -> BitReader:
    """Consume n bits into a fresh reader. RM3 hands each payload to Deserialize as
    its own bitstream, so byte alignment inside it is relative to its first bit."""
    w = BitWriter()
    _transfer_bits(reader, w, n)
    out = BitReader(w.to_bytes())
    out.nbits = n
    return out


def _read_count(reader: BitReader) -> int:
    return reader.read_ranged(COUNT_MIN, COUNT_MAX, allow_outside=True)


def _write_count(writer: BitWriter, count: int) -> None:
    writer.write_ranged(count, COUNT_MIN, COUNT_MAX, allow_outside=True)


def klei_to_vanilla_construction(payload: bytes, cfg: TranslatorConfig) -> bytes:
    """Rewrite one 0x87 frame from 24-bit network ids to 18-bit network ids.

    Header, flag bit, declared-length field and payload/GUID bits are kept.
    Serialize records that follow in the same frame are rewritten the same way.
    Returns the original bytes when the frame is not 0x87, does not parse, or
    any id does not fit in 18 bits. Never returns a half-rewritten frame.
    """
    if not cfg.translate_construction:
        return payload
    try:
        rewritten = _reencode_construction(payload)
    except (EOFError, ValueError) as e:
        if cfg.log:
            cfg.log(f"[geyser] 0x87 passthrough ({e})")
        return payload
    if rewritten is None:
        if cfg.log:
            cfg.log("[geyser] 0x87 passthrough (network id does not fit in 18 bits, or trailing data)")
        return payload
    return rewritten[0]


def _online_migration(payload: bytes, bitlen: int, lobby, shard: int,
                      password: bytes) -> tuple[bytes, int, str] | None:
    """Either PC migration message -> the phone's online one, resolved through the lobby.

    A phone that came in over EOS must change shard over EOS too: the LAN message has no
    net id, and before a pong arrives its new connection pings the address over EOS to its
    own id. The online message makes it POST /lobby/read for `rowId` in `region` and take
    secondaries[str(shard)] -> {__addr, port, steamid}; steamid is the EOS id it connects
    to (cShardBroadcast::GetDestinationInfo / OnDestinationInfoResponse, mobile VA
    0x8c2214 / 0x8c26f4). lobby_announce --secondary puts the shard relays there.
    """
    if len(payload) < 2 or payload[1] not in (PC_MIGRATION_INFO, PC_LAN_MIGRATION_INFO):
        return None
    where = lobby() if lobby is not None else None
    if not where or not shard:
        return None
    row_id, region = where
    # The target shard checks the password carried by the server's own message (the
    # cluster join password was rejected live), so pass it on and fall back only when empty.
    r = _limit_reader(payload, bitlen)
    if r is None:
        return None
    r.read_bits(16)
    if payload[1] == PC_LAN_MIGRATION_INFO:
        _read_rakstring(r)
        r.read_bits(16)
    else:
        _read_rakstring(r)
        _read_rakstring(r)
        r.read_bits(32)
    password = _read_rakstring(r) or password
    w = BitWriter()
    w.write_bits(MSG_SHARD_TO_PLAYER, 8)
    w.write_bits(MOBILE_MIGRATION_INFO, 8)
    _write_rakstring(w, row_id.encode())
    _write_rakstring(w, region.encode())
    w.write_bits(shard, 32)
    _write_rakstring(w, password)
    w.write_bits(0, 64)
    return w.to_bytes(), w.bit_len(), f"0x{payload[1]:02x} -> online shard {shard} via row {row_id}"


def _reencode_migration(payload: bytes, bitlen: int, ports: dict, host: str = "",
                        host_password: bytes = b"") -> tuple[bytes, int, str] | None:
    """PC ID_SHD_O2P_LAN_MIGRATION_INFO -> the phone's, pointed at the bridge of the target shard.

    Both builds read RakString ip, u16 port, RakString password. The phone then reads a
    u64 it does not use (mobile VA 0x8be5c0) and drops the packet when it is missing.
    The ip is the address the client dialled to reach the server (seen live), so it is
    already this bridge's host. The port is the shard's own and is mapped to its bridge.

    An online cluster sends ID_SHD_O2P_MIGRATION_INFO instead: ids the client resolves
    through a lobby lookup, with no address. With `host` set and a single bridge in
    `ports`, it becomes the LAN message pointed at host:<that bridge>. The phone then
    dials UDP straight there, not EOS: the bridge's pong says LAN only (listing 0x286),
    and cPendingConnection::IsEosNetworkConnection (mobile VA 0x899234) is false for it.
    """
    if len(payload) < 2:
        return None
    if payload[1] == PC_MIGRATION_INFO:
        bridges = set(ports.values())
        if not host or len(bridges) != 1:
            return None
        ip, port, password, new_port = host.encode(), None, host_password, bridges.pop()
    elif payload[1] == PC_LAN_MIGRATION_INFO:
        r = _limit_reader(payload, bitlen)
        if r is None:
            return None
        r.read_bits(16)
        ip = _read_rakstring(r)
        port = r.read_bits(16)
        password = _read_rakstring(r)
        new_port = ports.get(port, port)
    else:
        return None
    w = BitWriter()
    w.write_bits(MSG_SHARD_TO_PLAYER, 8)
    w.write_bits(MOBILE_LAN_MIGRATION_INFO, 8)
    _write_rakstring(w, ip)
    w.write_bits(new_port, 16)
    _write_rakstring(w, password)
    w.write_bits(0, 64)
    if port is None:
        return w.to_bytes(), w.bit_len(), f"online -> LAN {host}:{new_port}"
    note = f"{ip.decode(errors='replace')}:{port} -> port {new_port}"
    if port not in ports:
        note += " (no bridge mapped for this shard)"
    return w.to_bytes(), w.bit_len(), note


def _limit_reader(payload: bytes, bitlen: int | None) -> BitReader | None:
    """Expose only the packet's dataBitLength. The last byte may contain pad bits."""
    reader = BitReader(payload)
    if bitlen is None:
        return reader
    if bitlen < 8 or bitlen > reader.nbits:
        return None
    reader.nbits = bitlen
    return reader


def _exact_tile_rle(sub: BitReader) -> bool:
    """True when `sub` is one 256-ushort RLE and then ends.

    OnSerialize copies the declared bits into a fresh bitstream (BitStream::Read
    at VA 0x95779c) before Deserialize. Alignment is therefore relative to the
    payload, not the outer frame.
    """
    try:
        compressed = sub.read_bit()
        if compressed:
            width = (_TILE_REGION_COUNT - 1).bit_length()
            encoded = sub.read_le_bits(width)
            if encoded <= 0 or encoded >= 0x401:
                return False
            sub.read_aligned_bytes(encoded * 2)
        else:
            sub.read_aligned_bytes(_TILE_REGION_COUNT * 2)
    except (EOFError, ValueError):
        return False
    return sub.remaining() == 0


def _is_tile_region(reader: BitReader, declared: int) -> bool:
    """True when the next `declared` bits are exactly one tile-region RLE. The cursor does not move."""
    if declared < 1 or declared > reader.remaining():
        return False
    start = reader.pos
    copied = BitWriter()
    try:
        left = declared
        while left:
            take = 32 if left >= 32 else left
            copied.write_bits(reader.read_bits(take), take)
            left -= take
    except EOFError:
        return False
    finally:
        reader.pos = start
    sub = BitReader(copied.to_bytes())
    sub.nbits = declared
    return _exact_tile_rle(sub)


def _rewrite_serialize_records(reader: BitReader, writer: BitWriter, nv: NetvarState | None = None) -> bool:
    """Rewrite OnSerialize records. False means the caller must passthrough the frame.

    Tile regions get the phone's region id; ``tiles`` counts them. PC_ONLY_NETID is dropped. With ``nv``, entity payloads
    are re-encoded for the mobile netvar schema.
    """
    tiles = 0
    while reader.remaining() > SERIALIZE_STOP_BITS:
        if reader.remaining() < SERVER_NETID_BITS + 1:
            return False
        net_id = reader.read_le_bits(SERVER_NETID_BITS)
        if net_id > MOBILE_NETID_MAX:
            return False
        flag = reader.read_bit()
        maximum = SERIALIZE_LONG_MAX if flag else SERIALIZE_SHORT_MAX
        declared = reader.read_ranged(0, maximum, allow_outside=False)
        if declared > reader.remaining():
            return False
        if _pc_region_xy(net_id) is not None and _is_tile_region(reader, declared):
            net_id = _mobile_region_id(net_id)
            tiles += 1
        elif net_id == PC_ONLY_NETID:
            reader.pos += declared
            continue
        elif nv is not None and net_id in nv.hidden:
            reader.pos += declared
            continue
        if nv is not None and net_id in nv.prefab_of:
            payload = nv.patch_assets(net_id, _lift_bits(reader, declared))
            translated = nv.translate_payload(net_id, payload, declared)
            if translated is not None:
                body = BitReader(translated.to_bytes())
                body.nbits = translated.bit_len()
                flag = 1 if body.nbits > SERIALIZE_SHORT_MAX else flag
                maximum = SERIALIZE_LONG_MAX if flag else SERIALIZE_SHORT_MAX
            else:
                payload.pos = 0
                body = payload
            writer.write_le_bits(net_id, MOBILE_NETID_BITS)
            writer.write_bit(flag)
            writer.write_ranged(body.nbits, 0, maximum, allow_outside=False)
            _transfer_bits(body, writer, body.nbits)
            continue
        writer.write_le_bits(net_id, MOBILE_NETID_BITS)
        writer.write_bit(flag)
        writer.write_ranged(declared, 0, maximum, allow_outside=False)
        _transfer_bits(reader, writer, declared)
    _rewrite_serialize_records.tiles = tiles
    return True


_rewrite_serialize_records.tiles = 0


def _reencode_serialize(payload: bytes, bitlen: int | None = None, nv: NetvarState | None = None) -> tuple[bytes, int] | None:
    """0x88: message id, then the same serialize records as the tail of 0x87."""
    if not payload or payload[0] != MSG_FRAME_SERIALIZE:
        return None
    reader = _limit_reader(payload, bitlen)
    if reader is None or reader.read_bits(8) != MSG_FRAME_SERIALIZE:
        return None
    writer = BitWriter()
    writer.write_bits(MSG_FRAME_SERIALIZE, 8)
    if not _rewrite_serialize_records(reader, writer, nv):
        return None
    if reader.remaining() > SERIALIZE_STOP_BITS:
        return None
    return writer.to_bytes(), writer.bit_len()


def _reencode_destruction(payload: bytes, bitlen: int | None = None, nv: NetvarState | None = None) -> tuple[bytes, int] | None:
    """0x8b: message id, then net id + 64-bit tail records with no count.

    ReplicaManager3::OnDestruction (mobile VA 0x9543ac) reads records while a
    byte remains, so 24-bit PC ids made the phone read past the buffer and crash.
    """
    if not payload or payload[0] != MSG_FRAME_DESTRUCTION:
        return None
    reader = _limit_reader(payload, bitlen)
    if reader is None or reader.read_bits(8) != MSG_FRAME_DESTRUCTION:
        return None
    writer = BitWriter()
    writer.write_bits(MSG_FRAME_DESTRUCTION, 8)
    while reader.remaining() >= SERVER_NETID_BITS + DESTRUCTION_TAIL_BITS:
        net_id = reader.read_le_bits(SERVER_NETID_BITS)
        if net_id > MOBILE_NETID_MAX:
            return None
        if net_id == PC_ONLY_NETID or (nv is not None and nv.forget(net_id)):
            reader.pos += DESTRUCTION_TAIL_BITS
            continue
        writer.write_le_bits(_mobile_region_id(net_id), MOBILE_NETID_BITS)
        _transfer_bits(reader, writer, DESTRUCTION_TAIL_BITS)
    if reader.remaining() >= 8:
        return None
    return writer.to_bytes(), writer.bit_len()


def _reencode_construction(payload: bytes, bitlen: int | None = None, nv: NetvarState | None = None) -> tuple[bytes, int] | None:
    if not payload or payload[0] != MSG_FRAME_CONSTRUCT:
        return None
    reader = _limit_reader(payload, bitlen)
    if reader is None or reader.read_bits(8) != MSG_FRAME_CONSTRUCT:
        return None
    writer = BitWriter()
    writer.write_bits(MSG_FRAME_CONSTRUCT, 8)

    has_c = reader.read_bit()
    c_count = _read_count(reader) if has_c else 0
    has_d = reader.read_bit()
    d_count = _read_count(reader) if has_d else 0

    # One bit per record is the smallest legal body. A huge count is a parse
    # miss, not a world with that many replicas in this buffer.
    if c_count > reader.remaining() or d_count > reader.remaining():
        return None

    # Records are buffered so the counts can drop entities the phone cannot spawn.
    records = BitWriter()
    kept_c = 0
    for _ in range(c_count):
        net_id = reader.read_le_bits(SERVER_NETID_BITS)
        if net_id > MOBILE_NETID_MAX:
            return None
        flag = reader.read_bit()
        declared = _read_count(reader)
        if declared > reader.remaining():
            return None
        if nv is not None and declared:
            body = _lift_bits(reader, declared)
            prefab = construction_prefab(body)
            if prefab is not None and nv.hide(net_id, prefab):
                continue
            body.pos = 0
        else:
            body = None
        if not declared:
            # Tile regions construct with an empty body; the phone already made its own.
            if net_id == PC_ONLY_NETID:
                continue
            net_id = _mobile_region_id(net_id)
        records.write_le_bits(net_id, MOBILE_NETID_BITS)
        records.write_bit(flag)
        _write_count(records, declared)
        _transfer_bits(body if body is not None else reader, records, declared)
        kept_c += 1

    kept_d = 0
    for _ in range(d_count):
        net_id = reader.read_le_bits(SERVER_NETID_BITS)
        if net_id > MOBILE_NETID_MAX:
            return None
        if reader.remaining() < DESTRUCTION_TAIL_BITS:
            return None
        if nv is not None and nv.forget(net_id):
            reader.pos += DESTRUCTION_TAIL_BITS
            continue
        records.write_le_bits(net_id, MOBILE_NETID_BITS)
        _transfer_bits(reader, records, DESTRUCTION_TAIL_BITS)
        kept_d += 1

    writer.write_bit(has_c)
    if has_c:
        _write_count(writer, kept_c)
    writer.write_bit(has_d)
    if has_d:
        _write_count(writer, kept_d)
    body = BitReader(records.to_bytes())
    body.nbits = records.bit_len()
    _transfer_bits(body, writer, body.nbits)

    # Construction is followed by zero or more serialize records. A tail the
    # serialize loop does not understand is left untouched by returning None.
    if not _rewrite_serialize_records(reader, writer, nv):
        return None
    if reader.remaining() > SERIALIZE_STOP_BITS:
        return None
    return writer.to_bytes(), writer.bit_len()


# A world construction burst on this LAN took about 3.3s (77 pieces). The hold
# has to outlast that, because the rewritten bytes cannot be released until the
# whole message is reassembled. The bridge ACKs the server for each held
# datagram so the resend timer does not stall the rest of the burst. Anything
# still incomplete at the timeout is forwarded unchanged. The cap is the sum of
# held original datagrams.
_SPLIT_TIMEOUT_S = 8.0
# Repacked split pieces reuse datagram numbers the bridge already ACKed to the
# server, so a NAK from the phone is answered from this cache instead.
_RESEND_KEEP_S = 30.0
# Netvar re-encoding can add a few bits (mobile-only vars, wider action arrays).
# The 24->18 id shrink usually pays for it; past this slack the frame is forwarded.
_GROW_SLACK_BYTES = 32
_LISTING_GROW_BYTES = 128
_SPLIT_HOLD_CAP = 2_000_000
_KEEP_PIECE = object()


def _message_number(packet: InternalPacket) -> int:
    """Reliable message number. Split pieces are always sent reliable."""
    return int.from_bytes(packet.header[3:6], "little")
_TIMESTAMP = 0x1B
_RPC_PLUGIN = 0x4A  # RakNet RPC4; engine RPC signals, see rpc.py


@dataclass
class _SplitGroup:
    count: int
    direction: str
    peer: object
    t0: float
    pieces: dict = field(default_factory=dict)  # index -> (raw datagram, InternalPacket)
    order: list = field(default_factory=list)  # indexes, first-seen order
    # A split whose first piece is not 0x87/0x88 is forwarded as it arrives.
    passthrough: bool = False
    seen: set = field(default_factory=set)
    # Last piece time. A passthrough group expires on idle, not on age: a slow
    # file transfer outlasts the timeout, and a group dropped mid-transfer would
    # hold (and ACK) the rest of the pieces.
    last: float = 0.0


class GeyserTranslator:
    """Pluggable RM3 dialect translator for the LAN bridge.

    ``translate_datagram`` returns the datagrams to send now. An empty list
    means a split piece is held. ``flush`` returns timed-out originals as
    ``(direction, peer, datagram)``. Anything that does not parse, or is not
    an s2c 0x87 or 0x88 whose ids fit in 18 bits, is the original bytes.
    """

    def __init__(self, cfg: TranslatorConfig | None = None):
        self.cfg = cfg or TranslatorConfig()
        # Split messages held until whole and rewritten; others pass piece by piece.
        self._held_messages = _FRAME_MESSAGES + ((MSG_SERVER_LISTING,) if self.cfg.listing is not None else ())
        self._groups: dict[tuple, _SplitGroup] = {}
        self._ready: list[tuple[str, object, bytes]] = []
        self._logged_timestamp = False
        # (peer, reliable message number) -> (rewritten piece or None when the
        # shrink dropped it, time). The server resends a piece under a new datagram
        # number but with the same message number. The raw piece must not reach the
        # phone after its split was rewritten. A later message has a new number.
        self._done: dict[tuple, tuple[InternalPacket | None, float]] = {}
        # (peer, datagram number) -> (repacked datagram, time sent)
        self._resend: dict[tuple, tuple[bytes, float]] = {}
        # One phone per bridge: net ids are unique per server connection, and a
        # reconnect re-sends every construction, so one map is enough.
        self._nv = NetvarState(self.cfg.netvars) if self.cfg.netvars is not None else None
        self._nv_failed_logged = 0
        self._nv_hidden_logged = 0
        self._nv_assets_logged = 0

    def _log(self, msg: str) -> None:
        if self.cfg.log:
            self.cfg.log(msg)

    def server_to_client(self, dst_payload: bytes) -> bytes:
        """dst_payload = the DST message (first byte = message id), after RakNet
        reliability-header stripping done by the caller. Returns translated bytes."""
        if not self.cfg.enabled or not dst_payload:
            return dst_payload
        mid = dst_payload[0]
        try:
            if mid == MSG_FRAME_CONSTRUCT and self.cfg.translate_construction:
                return klei_to_vanilla_construction(dst_payload, self.cfg)
            if mid == MSG_FRAME_SERIALIZE and (
                self.cfg.translate_serialize or self.cfg.translate_construction
            ):
                rewritten = _reencode_serialize(dst_payload)
                if rewritten is None:
                    self._log("[geyser] 0x88 passthrough (network id does not fit in 18 bits, or trailing data)")
                    return dst_payload
                return rewritten[0]
        except NotImplementedError:
            return dst_payload  # safe passthrough
        except Exception as e:  # never break the pipe on a translation bug
            self._log(f"[geyser] s->c translate error on 0x{mid:02x}: {e}; passthrough")
            return dst_payload
        return dst_payload

    def client_to_server(self, dst_payload: bytes) -> bytes:
        if not self.cfg.enabled or not dst_payload:
            return dst_payload
        # mobile sends little/no construction upstream; 18-bit ids stay as sent.
        return dst_payload

    def translate_datagram(self, direction: str, datagram: bytes, peer=None, now: float | None = None) -> list[bytes]:
        """Datagrams to send to ``peer`` now. Empty while a split group is incomplete."""
        if now is None:
            now = time.monotonic()
        try:
            self._expire(now)
            if direction == "c2s" and self._resend:
                for number in nak_numbers(datagram):
                    cached = self._resend.get((peer, number))
                    if cached is not None:
                        self._log(f"[geyser] resend repacked datagram {number} on NAK")
                        self._ready.append(("s2c", peer, cached[0]))
            if self.cfg.enabled and direction == "c2s" and self.cfg.rpc is not None:
                return self._translate_c2s(datagram)
            if not self.cfg.enabled or direction != "s2c" or not (
                self.cfg.translate_construction or self.cfg.translate_serialize
            ):
                return [datagram]
            return self._translate_s2c(datagram, peer, now)
        except Exception as e:
            self._log(f"[geyser] passthrough ({type(e).__name__}: {e})")
            return [datagram]

    def flush(self, now: float | None = None) -> list[tuple[str, object, bytes]]:
        """Timed-out split datagrams, original bytes, in receive order."""
        if now is None:
            now = time.monotonic()
        self._expire(now)
        ready = self._ready
        self._ready = []
        return ready

    def _translate_c2s(self, datagram: bytes) -> list[bytes]:
        """Phone Lua RPCs are one small unsplit frame each; anything else passes."""
        packets = walk_datagram(datagram)
        if not packets:
            return [datagram]
        rebuilt: list[InternalPacket] = []
        changed = False
        for packet in packets:
            out = None
            if packet.split is None and packet.payload and packet.payload[:1] == b"\x09":
                # ID_CONNECTION_REQUEST: the phone already appends the password it was
                # prompted for to the tail of this message (verified live: a join to a
                # password server carries "...\x00<password>" here). The PC server reads
                # the password as the whole tail, so the bridge must pass this through
                # UNCHANGED. Appending --server-password again doubles the field and the
                # server rejects the join with ID_INVALID_PASSWORD ("Wrong Password").
                rebuilt.append(packet)
                continue
            if out is None and packet.split is None:
                try:
                    equipped = self._nv.equipped.values() if self._nv is not None else ()
                    out = self.cfg.rpc.translate(packet.payload, packet.bitlen, set(equipped))
                except (EOFError, ValueError, KeyError) as e:
                    self._log(f"[geyser] rpc passthrough ({type(e).__name__}: {e})")
            if out is None:
                rebuilt.append(packet)
                continue
            body, bitlen, note = out
            self._log(f"[geyser] rpc {note} {packet.bitlen}->{bitlen} bits")
            rebuilt.append(replace_payload(packet, body, bitlen))
            changed = True
        if not changed:
            return [datagram]
        return [build_datagram(datagram[:4], rebuilt)]

    def _translate_s2c(self, datagram: bytes, peer, now: float) -> list[bytes]:
        packets = walk_datagram(datagram)
        if not packets:
            return [datagram]
        if any(packet.split is not None for packet in packets):
            # Resends of pieces that were already rewritten do not count.
            live = [
                packet for packet in packets
                if packet.split is not None and (peer, _message_number(packet)) not in self._done
            ]
            if not live:
                out = self._around_piece(peer, datagram)
                return [out] if out is not None else []
            if len(live) != 1:
                # Not seen: every piece but the last fills a datagram on its own.
                self._log(f"[geyser] datagram with {len(live)} split pieces forwarded whole")
                return [datagram]
            return self._hold_split(datagram, live[0], peer, now)
        rebuilt: list[InternalPacket] = []
        changed = False
        for packet in packets:
            updated = self._rewrite_packet(packet)
            if updated is None:
                rebuilt.append(packet)
            else:
                rebuilt.append(updated)
                changed = True
        if not changed:
            return [datagram]
        return [build_datagram(datagram[:4], rebuilt)]

    def _rewrite_packet(self, packet: InternalPacket) -> InternalPacket | None:
        rewritten = self._rewrite_message(packet.payload, packet.bitlen)
        if rewritten is None:
            return None
        body, bitlen = rewritten
        if body == packet.payload and bitlen == packet.bitlen:
            return None
        # The online move message carries the lobby row id and region; it is small either way.
        slack = _LISTING_GROW_BYTES if packet.payload[0] == MSG_SHARD_TO_PLAYER else _GROW_SLACK_BYTES
        if len(body) > len(packet.payload) + slack:
            self._log(f"[geyser] 0x{packet.payload[0]:02x} passthrough (translated frame grew)")
            return None
        self._log(
            f"[geyser] rewrote 0x{packet.payload[0]:02x} {packet.bitlen}->{bitlen} bits, "
            f"payload {len(packet.payload)}->{len(body)} bytes"
            + (f" tiles={_rewrite_serialize_records.tiles}" if _rewrite_serialize_records.tiles else "")
            + self._nv_note()
        )
        return replace_payload(packet, body, bitlen)

    def _nv_note(self) -> str:
        """Netvar counters for the rewrite log; each new failure kind is logged once."""
        if self._nv is None:
            return ""
        for key, n in list(self._nv.failed.items())[self._nv_failed_logged:]:
            self._log(f"[geyser] netvar passthrough {key} (x{n})")
        self._nv_failed_logged = len(self._nv.failed)
        for prefab in list(self._nv.hidden_prefabs)[self._nv_hidden_logged:]:
            self._log(f"[geyser] hidden {prefab} (not in the phone schema)")
        self._nv_hidden_logged = len(self._nv.hidden_prefabs)
        for key in list(self._nv.asset_fallbacks)[self._nv_assets_logged:]:
            self._log(f"[geyser] asset fallback {key}")
        self._nv_assets_logged = len(self._nv.asset_fallbacks)
        return f" netvars={self._nv.translated} entities={len(self._nv.prefab_of)} hidden={len(self._nv.hidden)}"

    def _rewrite_message(self, payload: bytes, bitlen: int) -> tuple[bytes, int] | None:
        if bitlen < 8 or not payload:
            return None
        if payload[0] == _TIMESTAMP:
            if not self._logged_timestamp:
                self._logged_timestamp = True
                self._log("[geyser] passthrough ID_TIMESTAMP 0x1b")
            return None
        if payload[0] == MSG_SERVER_LISTING and self.cfg.listing is not None:
            body = self.cfg.listing(payload)
            if body is None:
                return None
            self._log(f"[geyser] listing 0x86 rewritten {len(payload)}->{len(body)} bytes")
            return body, len(body) * 8
        if payload[0] == _RPC_PLUGIN and self.cfg.rpc is not None:
            out = self.cfg.rpc.translate_s2c(payload, bitlen)
            if out is None:
                return None
            self._log(f"[geyser] rpc s2c {out[2]}")
            return out[0], out[1]
        try:
            if payload[0] == MSG_SHARD_TO_PLAYER:
                out = _online_migration(payload, bitlen, self.cfg.migrate_lobby, self.cfg.migrate_shard,
                                        self.cfg.migrate_password)
                if out is None:
                    out = _reencode_migration(payload, bitlen, self.cfg.migrate_ports,
                                              self.cfg.migrate_host, self.cfg.migrate_password)
                if out is None:
                    self._log(f"[geyser] 0xa3 passthrough (shard sub id 0x{payload[1]:02x}, {bitlen} bits)")
                    return None
                self._log(f"[geyser] migration {out[2]}")
                return out[0], out[1]
            if payload[0] == MSG_FRAME_CONSTRUCT and self.cfg.translate_construction:
                return _reencode_construction(payload, bitlen, self._nv)
            if payload[0] == MSG_FRAME_SERIALIZE and (
                self.cfg.translate_serialize or self.cfg.translate_construction
            ):
                return _reencode_serialize(payload, bitlen, self._nv)
            if payload[0] == MSG_FRAME_DESTRUCTION and self.cfg.translate_construction:
                out = _reencode_destruction(payload, bitlen, self._nv)
                if out is None:
                    self._log(f"[geyser] 0x8b passthrough ({bitlen} bits do not fit 88-bit records)")
                return out
        except (EOFError, ValueError) as e:
            self._log(f"[geyser] 0x{payload[0]:02x} passthrough ({e})")
            return None
        return None

    def _around_piece(self, peer, raw: bytes, piece=_KEEP_PIECE) -> bytes | None:
        """``raw`` with everything beside its split piece translated.

        The server packs the last piece of a split with the messages that follow it,
        and resends unACKed pieces next to new messages. Forwarded whole, those
        messages reach the phone untranslated and a raw piece completes an
        untranslated copy of its split. ``piece`` replaces the split piece, None
        drops it. A resend of a rewritten piece becomes the rewritten piece again
        (the phone drops it if it has it). None when nothing is left to send; the
        caller then ACKs the server itself.
        """
        out = []
        for packet in walk_datagram(raw) or []:
            if packet.split is None:
                out.append(self._rewrite_packet(packet) or packet)
                continue
            done = self._done.get((peer, _message_number(packet)))
            if done is not None:
                packet = done[0]
            elif piece is not _KEEP_PIECE:
                packet = piece
            if packet is not None:
                out.append(packet)
        return build_datagram(raw[:4], out) if out else None

    def _hold_split(self, datagram: bytes, packet: InternalPacket, peer, now: float) -> list[bytes]:
        count, split_id, index = packet.split  # type: ignore[misc]
        key = ("s2c", peer, split_id)
        group = self._groups.get(key)
        if group is not None and group.count != count:
            self._queue_originals(key)
            group = None
        if group is None:
            group = _SplitGroup(count=count, direction="s2c", peer=peer, t0=now)
            self._groups[key] = group
        group.last = now
        if group.passthrough:
            if index in group.seen:
                # Server resend of a piece the client never ACKed. The bytes were
                # not changed, so a duplicate is harmless and a lost piece comes back.
                return [self._around_piece(peer, datagram)]
            group.seen.add(index)
            if len(group.seen) >= group.count:
                self._groups.pop(key, None)
            return [self._around_piece(peer, datagram)]
        if index in group.pieces:
            # Server retransmit of a piece we still hold. Forwarding the original
            # now would let the client assemble the untranslated copy and ignore
            # the later rewritten datagram number as a duplicate.
            out = self._around_piece(peer, datagram, None)
            return [out] if out is not None else []
        completes = len(group.pieces) + 1 == group.count
        if not completes and not self._can_hold(len(datagram)):
            self._log(f"[geyser] split 0x{split_id:04x} passthrough (hold cap)")
            self._queue_originals(key)
            return [self._around_piece(peer, datagram)]
        group.pieces[index] = (datagram, packet)
        group.order.append(index)
        if self._foreign_split(group):
            # File transfers and other split messages must not wait for a rewrite.
            group.passthrough = True
            group.seen.update(group.order)
            originals = [self._around_piece(peer, group.pieces[i][0]) for i in group.order]
            group.pieces.clear()
            group.order.clear()
            if len(group.seen) >= group.count:
                self._groups.pop(key, None)
            return originals
        if len(group.pieces) < group.count:
            return []
        return self._finish_split(key)

    def _foreign_split(self, group: _SplitGroup) -> bool:
        first = group.pieces.get(0)
        if first is None:
            return False
        payload = first[1].payload
        return not payload or payload[0] not in self._held_messages

    def _finish_split(self, key: tuple) -> list[bytes]:
        group = self._groups.pop(key)
        try:
            packed = self._try_rewrite_split(key, group)
        except Exception as e:
            self._log(f"[geyser] split passthrough ({type(e).__name__}: {e})")
            packed = None
        if packed is None:
            return [self._around_piece(group.peer, group.pieces[i][0]) for i in group.order]
        return packed

    def _try_rewrite_split(self, key: tuple, group: _SplitGroup) -> list[bytes] | None:
        """The rewritten datagrams, or None when the originals must go on."""
        if len(group.pieces) != group.count or any(i not in group.pieces for i in range(group.count)):
            return None
        ordered = [group.pieces[i][1] for i in range(group.count)]
        # RakNet splits on a byte boundary. A partial byte before the last piece
        # would not abut, so the original datagrams are forwarded.
        if any(piece.bitlen % 8 != 0 for piece in ordered[:-1]):
            self._log("[geyser] split passthrough (piece not byte-aligned)")
            return None
        total = b"".join(piece.payload for piece in ordered)
        sum_bits = sum(piece.bitlen for piece in ordered)
        if not total or len(total) * 8 - sum_bits >= 8:
            return None
        if total[0] not in self._held_messages:
            return None
        rewritten = self._rewrite_message(total, sum_bits)
        if rewritten is None:
            return None
        body, new_bits = rewritten
        # The mobile listing front is ~50 bytes longer; the last piece takes it.
        slack = _LISTING_GROW_BYTES if total[0] == MSG_SERVER_LISTING else _GROW_SLACK_BYTES
        if not body or new_bits <= 0 or new_bits > sum_bits + 8 * slack:
            self._log(
                f"[geyser] split 0x{total[0]:02x} passthrough (translated frame grew or empty)"
            )
            return None
        packed = self._pack_shrunk_split(group, ordered, body, new_bits)
        if packed is None:
            self._log(f"[geyser] split 0x{total[0]:02x} passthrough (could not repack)")
            return None
        self._log(
            f"[geyser] rewrote split 0x{total[0]:02x} id=0x{key[2]:04x} pieces={group.count}->{len(packed)} "
            f"payload {len(total)}->{len(body)} bytes"
            + (f" tiles={_rewrite_serialize_records.tiles}" if _rewrite_serialize_records.tiles else "")
            + self._nv_note()
        )
        now = time.monotonic()
        for dgram in packed:
            self._resend[(key[1], datagram_number(dgram))] = (dgram, now)
        return packed

    def _pack_shrunk_split(self, group: _SplitGroup, ordered: list, body: bytes, new_bits: int) -> list[bytes] | None:
        """Put the rewritten bits in the front pieces and drop the zero tail.

        A frame that grew puts the extra bits in the last piece.

        Each piece keeps its datagram number and reliable message number. dataBitLength
        shrinks from the end so the sum equals the rewritten length. A zero tail inside
        the old length would be read as more serialize records. Pieces that lose all
        of their bits are not sent, and the split count on the pieces that remain is
        updated. Indexes still start at 0.
        """
        chunks: list[tuple[int, bytes, int]] = []
        offset = 0
        for index, piece in enumerate(ordered):
            if offset >= new_bits:
                break
            if offset % 8 != 0:
                return None
            if index == len(ordered) - 1:
                take = new_bits - offset  # the last piece absorbs any growth
            else:
                take = piece.bitlen if offset + piece.bitlen <= new_bits else new_bits - offset
            if take <= 0:
                return None
            start = offset // 8
            size = (take + 7) // 8
            chunk = body[start:start + size]
            if len(chunk) != size:
                return None
            chunks.append((index, chunk, take))
            offset += take
        if offset != new_bits or not chunks:
            return None
        new_count = len(chunks)
        pieces: dict[int, InternalPacket | None] = {index: None for index in group.order}
        for index, chunk, take in chunks:
            piece = group.pieces[index][1]
            header = bytearray(piece.header)
            header[1] = (take >> 8) & 0xFF
            header[2] = take & 0xFF
            if new_count != group.count:
                if len(header) < 10:
                    return None
                header[-10:-6] = new_count.to_bytes(4, "big")
            pieces[index] = InternalPacket(bytes(header), take, chunk, piece.reliability, piece.split)
        now = time.monotonic()
        for index, piece in pieces.items():
            self._done[(group.peer, _message_number(group.pieces[index][1]))] = (piece, now)
        # A dropped piece still sends the messages that shared its datagram.
        packed = [self._around_piece(group.peer, group.pieces[index][0], pieces[index]) for index in group.order]
        return [dgram for dgram in packed if dgram is not None]

    def _can_hold(self, extra: int) -> bool:
        held = sum(len(raw) for group in self._groups.values() for raw, _packet in group.pieces.values())
        return held + extra <= _SPLIT_HOLD_CAP

    def _queue_originals(self, key: tuple) -> None:
        group = self._groups.pop(key, None)
        if group is None:
            return
        for index in group.order:
            self._ready.append((group.direction, group.peer, self._around_piece(group.peer, group.pieces[index][0])))

    def _expire(self, now: float) -> None:
        for cache in (self._resend, self._done):
            for k in [k for k, (_, t) in cache.items() if now - t >= _RESEND_KEEP_S]:
                del cache[k]
        late = [
            key for key, group in self._groups.items()
            if now - (group.last if group.passthrough else group.t0) >= _SPLIT_TIMEOUT_S
        ]
        for key in late:
            group = self._groups[key]
            if group.passthrough and not group.order:
                self._groups.pop(key, None)
                continue
            self._log(
                f"[geyser] split 0x{key[2]:04x} timeout, forwarding {len(group.order)}/{group.count} original"
            )
            self._queue_originals(key)
