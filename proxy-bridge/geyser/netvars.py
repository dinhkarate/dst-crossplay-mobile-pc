"""Netvar dialect translation for OnSerialize payloads (PC 762172 server -> mobile client).

Both sides run the same native serializer; only the Lua netvar set differs. An
entity's netvars live in a std::map keyed by hash(name), and DeserializeLuaState
reads one dirty bit per var in ascending hash order, then the value when dirty.
One var that exists on one side only shifts every later bit, so the payload is
decoded with the PC schema and re-encoded with the mobile one.

Serialize record payload (cNetworkComponent::Deserialize, mobile VA 0x6d6bfc):
  u16 L (big-endian), then ceil(L/8) bytes holding the cEntity chunk (L bits),
  then per native component a 16- or 32-bit big-endian length and that many
  bits, each chunk padded to a byte. Only the cEntity chunk is rewritten; the
  rest is byte-aligned and copied as is.

cEntity chunk (cEntity::Deserialize, mobile VA 0x75c298). Each step only runs
while bits remain:
  tags: bit hasAdds, bit clearAll, [6-bit n, n x 32] if hasAdds,
        then if not clearAll: bit hasRemoves, [6-bit n, n x 32] if hasRemoves
  1 bit visibility
  parent:   bit dirty, [bit has, [64 bits]]
  platform: bit dirty, [bit has, [64 bits]]
  Lua state: per var in hash order, 1 dirty bit, then the value if dirty.

Strings are a big-endian u16 length and byte-aligned raw bytes (measured on live
frames; BitReader.read_rakstring assumes little-endian and does not match).

Schemas come from tools/netvar_dump_mod run on a PC server and on the same
binary with the phone's scripts (schema/*.txt.gz). Value remaps:
  actioncomponents: PC component id -> mobile id by name (unknown ids dropped)
  inherentactions / inherentscene(alt)action: PC pairs(ACTIONS) position ->
  mobile action.code, widened from bytes to ushorts.
"""
from __future__ import annotations

import gzip
import os

from . import assets
from .bitstream import BitReader, BitWriter

SCHEMA_DIR = os.path.join(os.path.dirname(__file__), "schema")

SCALAR_BITS = {
    "net_bool": 1, "net_tinybyte": 3, "net_smallbyte": 6, "net_byte": 8,
    "net_shortint": 16, "net_ushortint": 16, "net_int": 32, "net_uint": 32,
    "net_float": 32, "net_hash": 32, "net_entity": 64,
}
ARRAY_ELEM_BITS = {"net_bytearray": 8, "net_smallbytearray": 6, "net_ushortarray": 16}
ARRAY_COUNT_BITS = 5
ARRAY_MAX = (1 << ARRAY_COUNT_BITS) - 1
TAG_COUNT_BITS = 6
GUID_BITS = 64

# inventory_classified netvar per equip slot: "inventory._equips[hands]".
EQUIPS_PREFIX = "inventory._equips["

# Every server mod adds one of these per entity; the phone runs without mods.
MOD_ACTION_PREFIX = "modactioncomponents"


def load_schema(path: str) -> dict[str, list[tuple[int, str, str]]]:
    """prefab -> [(hash, name, type)] in hash order, from a netvar dump."""
    opener = gzip.open if path.endswith(".gz") else open
    best: dict[str, tuple[int, list]] = {}
    with opener(path, "rt") as f:
        for line in f:
            prefab, count, fields = line.rstrip("\n").split("\t")
            vars_ = []
            for field in fields.split(",") if fields else []:
                name, typ, h = field.rsplit(":", 2)
                if not name.startswith(MOD_ACTION_PREFIX):
                    vars_.append((int(h), name, typ))
            vars_.sort()
            n = int(count)
            if prefab not in best or n > best[prefab][0]:
                best[prefab] = (n, vars_)
    return {p: v for p, (_, v) in best.items()}


def load_tables(path: str) -> dict[str, list[str]]:
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "rt") as f:
        return {k: v.split(",") if v else [] for k, v in
                (line.rstrip("\n").split("\t", 1) for line in f)}


def read_value(r: BitReader, typ: str):
    if typ in SCALAR_BITS:
        return r.read_le_bits(SCALAR_BITS[typ])
    if typ in ARRAY_ELEM_BITS:
        n = r.read_le_bits(ARRAY_COUNT_BITS)
        w = ARRAY_ELEM_BITS[typ]
        return [r.read_le_bits(w) for _ in range(n)]
    if typ == "net_string":
        # The stream is aligned after the length even when the string is empty.
        n = r.read_bits(16)
        return r.read_aligned_bytes(n)
    raise ValueError(f"unknown netvar type {typ}")


def write_value(w: BitWriter, typ: str, value) -> None:
    if typ in SCALAR_BITS:
        bits = SCALAR_BITS[typ]
        w.write_le_bits(value & ((1 << bits) - 1), bits)
    elif typ in ARRAY_ELEM_BITS:
        value = value[:ARRAY_MAX]
        w.write_le_bits(len(value), ARRAY_COUNT_BITS)
        bits = ARRAY_ELEM_BITS[typ]
        for v in value:
            w.write_le_bits(v & ((1 << bits) - 1), bits)
    elif typ == "net_string":
        w.write_bits(len(value), 16)
        w.write_aligned_bytes(value)
    else:
        raise ValueError(f"unknown netvar type {typ}")


def _copy(r: BitReader, w: BitWriter, n: int) -> None:
    while n:
        take = 32 if n >= 32 else n
        w.write_bits(r.read_bits(take), take)
        n -= take


def copy_entity_header(r: BitReader, w: BitWriter) -> None:
    """Copy tags, visibility, parent and platform bits. Stops where the stream ends."""
    if r.remaining() == 0:
        return
    has_adds = r.read_bit(); w.write_bit(has_adds)
    clear_all = r.read_bit(); w.write_bit(clear_all)
    if has_adds:
        n = r.read_bits(TAG_COUNT_BITS); w.write_bits(n, TAG_COUNT_BITS)
        _copy(r, w, 32 * n)
    if not clear_all:
        has_removes = r.read_bit(); w.write_bit(has_removes)
        if has_removes:
            n = r.read_bits(TAG_COUNT_BITS); w.write_bits(n, TAG_COUNT_BITS)
            _copy(r, w, 32 * n)
    if r.remaining() == 0:
        return
    w.write_bit(r.read_bit())  # visibility
    for _ in range(2):  # parent, platform
        if r.remaining() == 0:
            return
        dirty = r.read_bit(); w.write_bit(dirty)
        if dirty:
            has = r.read_bit(); w.write_bit(has)
            if has:
                _copy(r, w, GUID_BITS)


def read_lua_state(r: BitReader, schema: list[tuple[int, str, str]]) -> dict[str, object]:
    """Dirty vars by name. Raises EOFError/ValueError when the bits do not fit the schema."""
    dirty = {}
    for _, name, typ in schema:
        if r.remaining() <= 0:
            break
        if r.read_bit():
            dirty[name] = read_value(r, typ)
    if r.remaining() > 0:
        raise ValueError(f"{r.remaining()} bits left after Lua state")
    return dirty


class NetvarMapper:
    """Schemas and id tables for one PC server build and one phone build."""

    def __init__(self, pc_schema, mob_schema, pc_tables, mob_tables):
        self.pc = pc_schema
        self.mob = mob_schema
        mob_comp = {name: i + 1 for i, name in enumerate(mob_tables["action_components"])}
        self.comp_map = {i + 1: mob_comp.get(name) for i, name in enumerate(pc_tables["action_components"])}
        mob_code = {name: i + 1 for i, name in enumerate(mob_tables["action_ids"])}
        self.action_map = {i + 1: mob_code.get(name) for i, name in enumerate(pc_tables["action_pairs"])}

    @classmethod
    def from_dir(cls, path: str = SCHEMA_DIR) -> "NetvarMapper":
        j = lambda f: os.path.join(path, f)
        # extra_*.txt: prefabs the dump cannot cover. It runs on a forest world, where
        # cave_network cannot be spawned (world_network asserts TheWorld.net == nil).
        return cls({**load_schema(j("pc.txt.gz")), **load_schema(j("extra_pc.txt"))},
                   {**load_schema(j("mobile.txt.gz")), **load_schema(j("extra_mobile.txt"))},
                   load_tables(j("pc_tables.txt")), load_tables(j("mobile_tables.txt")))

    def convert(self, name: str, pc_type: str, mob_type: str, value):
        """Mobile value for one var, or None to leave it clean."""
        if name == "actioncomponents":
            return [m for m in (self.comp_map.get(v) for v in value) if m is not None]
        if name == "inherentactions":
            return sorted({m for m in (self.action_map.get(v) for v in value) if m is not None})
        if name in ("inherentsceneaction", "inherentscenealtaction"):
            return self.action_map.get(value) or 0 if value else 0
        if pc_type == mob_type:
            return value
        if pc_type in SCALAR_BITS and mob_type in SCALAR_BITS:
            return value
        if pc_type in ARRAY_ELEM_BITS and mob_type in ARRAY_ELEM_BITS:
            return value
        return None

    def translate_chunk(self, prefab: str, chunk: bytes, nbits: int,
                        dirty_out: dict | None = None) -> tuple[bytes, int] | None:
        """Re-encode one cEntity chunk. None when the prefab or the bits are not understood.

        dirty_out, when given, receives the PC values of the vars that were dirty.
        """
        pc_schema = self.pc.get(prefab)
        mob_schema = self.mob.get(prefab)
        if pc_schema is None or mob_schema is None:
            return None
        r = BitReader(chunk)
        r.nbits = nbits
        w = BitWriter()
        copy_entity_header(r, w)
        if r.remaining() == 0:
            return w.to_bytes(), w.bit_len()
        dirty = read_lua_state(r, pc_schema)
        if dirty_out is not None:
            dirty_out.update(dirty)
        pc_types = {name: typ for _, name, typ in pc_schema}
        out = []
        for _, name, typ in mob_schema:
            if name in dirty:
                v = self.convert(name, pc_types[name], typ, dirty[name])
                out.append((typ, v))
            else:
                out.append((typ, None))
        while out and out[-1][1] is None:
            out.pop()
        for typ, v in out:
            if v is None:
                w.write_bit(0)
            else:
                w.write_bit(1)
                write_value(w, typ, v)
        return w.to_bytes(), w.bit_len()


def split_payload(payload: BitReader, declared: int) -> tuple[int, bytes, int | None] | None:
    """(L, cEntity chunk bytes, tail bits) for one serialize payload, cursor at its start.

    tail is None when the chunk is the last thing written: then the payload ends
    right after its L bits, without padding.
    """
    if declared < 16:
        return None
    L = payload.read_bits(16)
    nbytes = (L + 7) // 8
    if 16 + 8 * nbytes <= declared:
        tail = declared - 16 - 8 * nbytes
    elif 16 + L == declared:
        tail = None
    else:
        return None
    chunk = payload.read_aligned_bytes(nbytes) if nbytes else b""
    return L, chunk, tail


def write_payload(w: BitWriter, L: int, chunk: bytes, padded: bool) -> None:
    """Inverse of split_payload for a fresh writer. The caller appends the tail."""
    w.write_bits(L, 16)
    if padded:
        if L:
            w.write_aligned_bytes(chunk[:(L + 7) // 8])
        return
    r = BitReader(chunk)
    r.nbits = L
    _copy(r, w, L)


# Construction payload (both builds): 64-bit creating-system GUID, 1-bit
# discriminator (0 entity, 1 client object), then for an entity the prefab name
# as a big-endian u16 length and byte-aligned bytes. Tile regions have no payload.
CONSTRUCTION_GUID_BITS = 64


def construction_prefab(payload: BitReader) -> str | None:
    """Prefab name of one construction payload read from a fresh reader, or None."""
    if payload.remaining() < CONSTRUCTION_GUID_BITS + 17:
        return None
    payload.pos += CONSTRUCTION_GUID_BITS
    if payload.read_bit():
        return None
    n = payload.read_bits(16)
    if n == 0 or n > 128:
        return None
    return payload.read_aligned_bytes(n).decode("latin1")


class NetvarState:
    """Per-connection net id -> prefab map plus the mapper. Counters feed the log."""

    def __init__(self, mapper: NetvarMapper):
        self.mapper = mapper
        self.prefab_of: dict[int, str] = {}
        # Entities whose prefab the phone does not have. Its AllocReplica fails on
        # them and the rest of the frame desyncs, so they never reach the phone.
        self.hidden: set[int] = set()
        self.hidden_prefabs: dict[str, int] = {}
        self.translated = 0
        self.failed: dict[str, int] = {}
        # "prefab: PC name -> phone name" for every asset fallback used, see assets.py.
        self.asset_fallbacks: dict[str, int] = {}
        # Equip slot -> entity the server says the phone player wears, from its
        # inventory_classified (only the owner receives it). The phone's own idea
        # can be wrong, see RpcMapper._convert.
        self.equipped: dict[str, int] = {}

    def hide(self, net_id: int, prefab: str) -> bool:
        """Record a construction. True when the phone must not see this entity."""
        if prefab in self.mapper.mob:
            self.prefab_of[net_id] = prefab
            self.hidden.discard(net_id)
            return False
        self.prefab_of.pop(net_id, None)
        self.hidden.add(net_id)
        self.hidden_prefabs[prefab] = self.hidden_prefabs.get(prefab, 0) + 1
        return True

    def forget(self, net_id: int) -> bool:
        """Record a destruction. True when the entity was hidden from the phone."""
        self.prefab_of.pop(net_id, None)
        if net_id in self.hidden:
            self.hidden.discard(net_id)
            return True
        return False

    def patch_assets(self, net_id: int, payload: BitReader) -> BitReader:
        """The payload with builds and animations the phone lacks swapped for ones it has."""
        prefab = self.prefab_of.get(net_id)
        if prefab is None:
            return payload
        payload, swapped = assets.patch(prefab, payload)
        for pc, mob in swapped:
            key = f"{prefab}: {pc} -> {mob}"
            self.asset_fallbacks[key] = self.asset_fallbacks.get(key, 0) + 1
        return payload

    def translate_payload(self, net_id: int, payload: BitReader, declared: int) -> BitWriter | None:
        """Mobile serialize payload for one record, or None to keep the original bits."""
        prefab = self.prefab_of.get(net_id)
        if prefab is None:
            return None
        try:
            parts = split_payload(payload, declared)
            if parts is None:
                raise ValueError("payload layout")
            L, chunk, tail = parts
            if L == 0:
                return None
            dirty = {} if prefab == "inventory_classified" else None
            out = self.mapper.translate_chunk(prefab, chunk, L, dirty)
            if out is None:
                raise ValueError("no schema")
            for name, value in (dirty or {}).items():
                if name.startswith(EQUIPS_PREFIX):
                    # read_value gives the GUID's bytes little-endian; RPC args keep raw bit order.
                    self.equipped[name[len(EQUIPS_PREFIX):-1]] = int.from_bytes(value.to_bytes(8, "little"), "big")
            new_chunk, new_L = out
            if new_L > 0xFFFF:
                raise ValueError("chunk too long")
            w = BitWriter()
            write_payload(w, new_L, new_chunk, padded=tail is not None)
            if tail:
                _copy(payload, w, tail)
        except (EOFError, ValueError) as e:
            key = f"{prefab}: {e}"
            self.failed[key] = self.failed.get(key, 0) + 1
            return None
        self.translated += 1
        return w
