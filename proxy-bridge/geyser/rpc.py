"""Client RPC translation between the phone and the PC 762172 server.

Every engine RPC is a RakNet RPC4 signal:
  4a 02 | name | pad to a byte | user bitstream
The name is RakString::SerializeCompressed of one character, chr(0x30 + eRPC)
(cNetworkRPCManager constructor, mobile VA 0x86e7d4): a 0 bit, a 32-bit
big-endian bit count, then StringCompressor Huffman bits padded to a byte.
The phone has one eRPC the PC lacks at 35, so its ids 36..41 are the PC's
35..40 (DisableLoadingProtection is 41 on the phone, 40 on the PC; the server
pause states the PC sends as 37/38 are 38/39 on the phone).

eRPC 0 carries a Lua RPC (SendLuaRPCToServer, mobile VA 0x875324): 1 flag bit,
7-bit RPC code, then args to the end. Each arg is a 4-bit tag and a value,
MSB-first, multi-byte values big-endian:
  0 nil/false, 1 true, 2 zero, 3 one, 4/5 +/- 3 bits, 6/7 +/- 6 bits,
  8/9 +/- 8 bits, 10 short, 11/12 -/+ 32 bits, 13 float, 14 string
  (u16 length + byte-aligned bytes), 15 entity GUID (64 bits).

RPC codes are the position in the sorted RPC name list, and the phone has two
handlers the PC lacks (DropActiveItem, UnequipItemFromInvTile), so most codes
are shifted. Action arguments use action.code, which is also shifted (PC has
CORRUPTNIGHTMARE and SWEEP). Both are remapped by name from schema/*_tables.txt.

Craft RPCs send recipe.rpc_id, which counts Recipe() calls in definition order:
786 of the phone's 1122 recipes have another id on the PC, which has 8 more.
They are remapped by recipe name. skin_index indexes PREFAB_SKINS[product],
whose lists also differ, so it is dropped and the item is built unskinned.
"""
from __future__ import annotations

import os

from .bitstream import BitReader, BitWriter
from .netvars import SCHEMA_DIR, load_tables

RPC4_SIGNAL = b"\x4a\x02"
NAME_LEN_BITS = 32
ERPC_NAME_BASE = 0x30
ERPC_LUA = 0
MOBILE_ONLY_ERPC = 35
SHIFTED_LAST = 41     # last phone eRPC with a PC counterpart
PC_UNUSED_ERPC = 41   # the PC registers 0..40; a signal to 41 is ignored

# Chat: the PC server sends Say as message + sender user id. The phone drops it
# when it is in offline mode (ParentalControls_BlockChat in Networking_Say), and
# it always is on a LAN server, so the bridge sends a system message instead.
ERPC_SAY = 21
ERPC_SYSTEM_MESSAGE = 23
OTHER_SENDER = b"PC"  # user ids the bridge has no name for (players not behind it)

CODE_BITS = 7
TAG_BITS = 4

TAG_NIL, TAG_TRUE, TAG_STRING = 0, 1, 14
TAG_VALUE_BITS = {0: 0, 1: 0, 2: 0, 3: 0, 4: 3, 5: 3, 6: 6, 7: 6, 8: 8, 9: 8,
                  10: 16, 11: 32, 12: 32, 13: 32, 15: 64}

# RPCs whose first argument is an action code (networkclientrpc.lua). A mod
# action carries mod_name and keeps its code, but the phone runs without mods.
ACTION_FIRST = {
    "LeftClick", "RightClick", "ActionButton", "ControllerActionButton",
    "ControllerActionButtonPoint", "ControllerAltActionButton",
    "ControllerAltActionButtonPoint", "DoWidgetButtonAction", "UseItemFromInvTile",
    "ControllerUseItemOnItemFromInvTile", "ControllerUseItemOnSelfFromInvTile",
    "ControllerUseItemOnSceneFromInvTile", "DoActionOnMap", "DoubleTapAction",
    "InteractionTarget",
}

DROP_ONE = 1  # DROP_MODES.ONE in the phone's widgets/inventorybar.lua

# The phone's equip slot menu sends its item self action, and on the bridge the
# phone can believe a worn item is not equipped (it offers Equip and sends EQUIP).
# The server builds UNEQUIP for a worn item and drops the mismatched code, so a
# worn item's EQUIP becomes UNEQUIP using the server's own equip slots.
SELF_USE = {"ControllerUseItemOnSelfFromInvTile"}

# Craft RPCs: (position of the recipe rpc_id, position of skin_index or None).
RECIPE_ARGS = {"MakeRecipeFromMenu": (0, 1), "MakeRecipeAtPoint": (0, 4), "BufferBuild": (0, None)}

# HANDSHAKE_CLIENT_INFO (PerformClientHandshaking, mobile VA 0x848990): id byte,
# RakString, cNetID2, display name, user id, then byte-aligned metrics. A cNetID2
# is a 3-bit type and its value; type 5 is an EOS product user id (32 hex chars)
# on the phone but an IOS id of at most 31 chars on the PC, so PC clients fail
# to build the phone's client object. The bridge sends no net id instead.
HANDSHAKE_CLIENT_INFO = 0x91
NETID_TYPE_BITS = 3
NETID_NONE = 0
NETID_PHONE_EOS = 5

# RakNet StringCompressor englishCharacterFrequencies (same table in both builds).
_FREQ = [0] * 256
_FREQ[10], _FREQ[13] = 722, 2
_FREQ[32:127] = [
    11084, 58, 63, 1, 0, 31, 0, 317, 64, 64, 44, 0, 695, 62, 980, 266, 69, 67, 56, 7, 73, 3, 14, 2,
    69, 1, 167, 9, 1, 2, 25, 94, 0, 195, 139, 34, 96, 48, 103, 56, 125, 653, 21, 5, 23, 64, 85, 44,
    34, 7, 92, 76, 147, 12, 14, 57, 15, 39, 15, 1, 1, 1, 2, 3, 0, 3611, 845, 1077, 1884, 5870, 841,
    1057, 2501, 3212, 164, 531, 2019, 1330, 3056, 4037, 848, 47, 2586, 2919, 4771, 1707, 535, 1106,
    152, 1243, 100, 0, 2, 0, 10,
]


def _huffman_codes(freq: list[int]) -> list[str]:
    """HuffmanEncodingTree::GenerateFromFrequencyTable, including its tie order."""
    def insert(nodes, node):
        for i, other in enumerate(nodes):
            if other[0] >= node[0]:
                nodes.insert(i, node)
                return
        nodes.append(node)

    parent: dict[int, tuple[int, str]] = {}
    nodes: list[tuple[int, int]] = []
    for c in range(256):
        insert(nodes, (freq[c] or 1, c))
    next_id = 256
    while len(nodes) > 1:
        (wa, a), (wb, b) = nodes.pop(0), nodes.pop(0)
        parent[a], parent[b] = (next_id, "0"), (next_id, "1")
        insert(nodes, (wa + wb, next_id))
        next_id += 1
    codes = []
    for c in range(256):
        path, node = [], c
        while node in parent:
            node, bit = parent[node]
            path.append(bit)
        codes.append("".join(reversed(path)))
    return codes


_CODES = _huffman_codes(_FREQ)


def _name_bits(erpc: int) -> str:
    """EncodeArray of the one-character slot name, padded to a byte."""
    bits = _CODES[ERPC_NAME_BASE + erpc]
    rem = -len(bits) % 8
    if rem:
        bits += next(code for code in _CODES if len(code) > rem)[:rem]
    return bits


_ERPC_OF_NAME = {_name_bits(i): i for i in range(64)}


def read_signal(payload: bytes, bitlen: int) -> tuple[int, int] | None:
    """(eRPC, bit offset of the user bitstream) of an RPC4 signal, else None."""
    if not payload.startswith(RPC4_SIGNAL) or bitlen < 16 + 1 + NAME_LEN_BITS:
        return None
    r = BitReader(payload)
    r.pos = 16
    if r.read_bit():
        return None
    n = r.read_bits(NAME_LEN_BITS)
    if r.pos + n > bitlen:
        return None
    erpc = _ERPC_OF_NAME.get(format(r.read_bits(n), f"0{n}b"))
    if erpc is None:
        return None
    return erpc, (r.pos + 7) & ~7


def write_signal(w: BitWriter, erpc: int) -> None:
    """Signal header up to the user bitstream, already byte-aligned."""
    bits = _name_bits(erpc)
    w.write_bits(RPC4_SIGNAL[0], 8)
    w.write_bits(RPC4_SIGNAL[1], 8)
    w.write_bit(0)
    w.write_bits(len(bits), NAME_LEN_BITS)
    w.write_bits(int(bits, 2), len(bits))
    w.align()


def retarget_signal(payload: bytes, bitlen: int, start: int, erpc: int) -> tuple[bytes, int]:
    w = BitWriter()
    write_signal(w, erpc)
    r = BitReader(payload)
    r.pos = start
    while bitlen - r.pos >= 32:
        w.write_bits(r.read_bits(32), 32)
    rest = bitlen - r.pos
    w.write_bits(r.read_bits(rest), rest)
    return w.to_bytes(), w.bit_len()


def phone_to_pc_erpc(erpc: int) -> int:
    if erpc == MOBILE_ONLY_ERPC or erpc > SHIFTED_LAST:
        return PC_UNUSED_ERPC
    return erpc - 1 if erpc > MOBILE_ONLY_ERPC else erpc


def pc_to_phone_erpc(erpc: int) -> int:
    return erpc + 1 if erpc >= MOBILE_ONLY_ERPC else erpc


def encode_uint(w: BitWriter, v: int) -> None:
    """Tag and value for a non-negative integer, as the phone's encoder picks them."""
    if v == 0:
        w.write_bits(2, TAG_BITS)
    elif v == 1:
        w.write_bits(3, TAG_BITS)
    elif v <= 7:
        w.write_bits(4, TAG_BITS)
        w.write_bits(v, 3)
    elif v <= 63:
        w.write_bits(6, TAG_BITS)
        w.write_bits(v, 6)
    elif v <= 255:
        w.write_bits(8, TAG_BITS)
        w.write_bits(v, 8)
    elif v < 1 << 15:
        w.write_bits(10, TAG_BITS)
        w.write_bits(v, 16)
    else:
        w.write_bits(12, TAG_BITS)
        w.write_bits(v, 32)


def uint_value(tag: int, raw: int) -> int | None:
    """The integer a positive tag carries, or None for other tags."""
    if tag == 2:
        return 0
    if tag == 3:
        return 1
    if tag in (4, 6, 8, 10, 12):
        return raw
    return None


def read_args(r: BitReader, end: int) -> list[tuple[int, object]]:
    """(tag, raw) per arg; a string's raw is its bytes. Raises on a short frame."""
    args: list[tuple[int, object]] = []
    while end - r.pos >= TAG_BITS:
        tag = r.read_bits(TAG_BITS)
        if tag == TAG_STRING:
            n = r.read_bits(16)
            r.align()
            args.append((tag, r.read_aligned_bytes(n)))
        else:
            args.append((tag, r.read_bits(TAG_VALUE_BITS[tag])))
    if r.pos > end or end - r.pos >= 8:
        raise ValueError(f"rpc args end at {r.pos}, frame has {end}")
    return args


def write_args(w: BitWriter, args: list[tuple[int, object]]) -> None:
    for tag, raw in args:
        if tag == "uint":
            encode_uint(w, raw)
            continue
        w.write_bits(tag, TAG_BITS)
        if tag == TAG_STRING:
            w.write_bits(len(raw), 16)
            w.align()
            w.write_aligned_bytes(raw)
        else:
            w.write_bits(raw, TAG_VALUE_BITS[tag])


def _read_rakstring(r: BitReader) -> bytes:
    n = r.read_bits(16)
    return r.read_aligned_bytes(n)


def _write_rakstring(w: BitWriter, s: bytes) -> None:
    w.write_bits(len(s), 16)
    w.write_aligned_bytes(s)


def read_handshake(payload: bytes) -> tuple[bytes, int, bytes, bytes, BitReader]:
    """HANDSHAKE_CLIENT_INFO fields: first string, net id type, name, user id, and a
    reader at the byte-aligned rest. Only the EOS net id (a string) is parsed."""
    r = BitReader(payload)
    r.pos = 8
    first = _read_rakstring(r)
    kind = r.read_bits(NETID_TYPE_BITS)
    if kind != NETID_PHONE_EOS:
        return first, kind, b"", b"", r
    _read_rakstring(r)
    name = _read_rakstring(r)
    userid = _read_rakstring(r)
    return first, kind, name, userid, r


def drop_phone_netid(payload: bytes, bitlen: int) -> tuple[bytes, int, str] | None:
    """HANDSHAKE_CLIENT_INFO with the phone's EOS net id replaced by none.

    The server's 0x91 reader has NO password slot (the password is checked in the
    0x09 connection request, where the translator appends it), so nothing else is
    inserted here: id, first string, net id, name, user id, then the aligned rest."""
    first, kind, name, userid, r = read_handshake(payload)
    if kind != NETID_PHONE_EOS:
        return None
    w = BitWriter()
    w.write_bits(HANDSHAKE_CLIENT_INFO, 8)
    _write_rakstring(w, first)
    w.write_bits(NETID_NONE, NETID_TYPE_BITS)
    _write_rakstring(w, name)
    _write_rakstring(w, userid)
    # The rest starts byte-aligned on both sides.
    while bitlen - r.pos >= 32:
        w.write_bits(r.read_bits(32), 32)
    rest = bitlen - r.pos
    w.write_bits(r.read_bits(rest), rest)
    return w.to_bytes(), w.bit_len(), "handshake net id EOS->none"


class RpcMapper:
    def __init__(self, mob_tables: dict, pc_tables: dict, password: bytes | None = None):
        self.password = password
        self.mob_names = mob_tables["rpc"]
        pc_rpc = {name: i + 1 for i, name in enumerate(pc_tables["rpc"])}
        self.pc_code = pc_rpc
        self.code_map = {i + 1: pc_rpc.get(name) for i, name in enumerate(self.mob_names)}
        pc_act = {name: i + 1 for i, name in enumerate(pc_tables["action_ids"])}
        self.pc_action = pc_act
        self.mob_action = {name: i + 1 for i, name in enumerate(mob_tables["action_ids"])}
        self.action_map = {i + 1: pc_act[name] for i, name in enumerate(mob_tables["action_ids"])
                           if name in pc_act}
        pc_recipe = dict(item.rsplit("=", 1) for item in pc_tables.get("recipes", []))
        self.recipe_map = {int(mob_id): int(pc_recipe[name])
                           for name, mob_id in (item.rsplit("=", 1) for item in mob_tables.get("recipes", []))
                           if name in pc_recipe}
        self.names: dict[bytes, bytes] = {}  # user id -> name, from phone handshakes

    @classmethod
    def from_dir(cls, path: str = SCHEMA_DIR, password: bytes | None = None) -> "RpcMapper":
        return cls(load_tables(os.path.join(path, "mobile_tables.txt")),
                   load_tables(os.path.join(path, "pc_tables.txt")), password)

    def name(self, mob_code: int) -> str:
        return self.mob_names[mob_code - 1] if 0 < mob_code <= len(self.mob_names) else f"#{mob_code}"

    def translate(self, payload: bytes, bitlen: int, equipped=()) -> tuple[bytes, int, str] | None:
        """Phone -> PC. (payload, bitlen, note) for an RPC4 signal or the handshake, else None.

        equipped: entity values the server says the phone player wears.
        """
        if payload[:1] == bytes([HANDSHAKE_CLIENT_INFO]):
            _, kind, name, userid, _ = read_handshake(payload)
            if userid:
                self.names[userid] = name
            return drop_phone_netid(payload, bitlen)
        sig = read_signal(payload, bitlen)
        if sig is None:
            return None
        erpc, start = sig
        if erpc != ERPC_LUA:
            pc = phone_to_pc_erpc(erpc)
            if pc == erpc:
                return None
            body, nbits = retarget_signal(payload, bitlen, start, pc)
            return body, nbits, f"eRPC {erpc}->{pc}"
        r = BitReader(payload)
        r.pos = start + 1
        mob = r.read_bits(CODE_BITS)
        args = read_args(r, bitlen)
        name = self.name(mob)
        args, name, note = self._convert(name, args, equipped)
        w = BitWriter()
        src = BitReader(payload)
        w.write_bits(src.read_bits(start + 1), start + 1)
        w.write_bits(self.pc_code[name], CODE_BITS)
        write_args(w, args)
        return w.to_bytes(), w.bit_len(), f"{self.name(mob)}->{name}{note}"

    def translate_s2c(self, payload: bytes, bitlen: int) -> tuple[bytes, int, str] | None:
        """PC -> phone: eRPC ids past the phone-only slot move, and chat becomes a system message."""
        sig = read_signal(payload, bitlen)
        if sig is None:
            return None
        erpc, start = sig
        if erpc == ERPC_SAY:
            return self._say_as_system_message(payload, bitlen, start)
        phone = pc_to_phone_erpc(erpc)
        if phone == erpc:
            return None
        body, nbits = retarget_signal(payload, bitlen, start, phone)
        return body, nbits, f"eRPC {erpc}->{phone}"

    def _say_as_system_message(self, payload: bytes, bitlen: int, start: int) -> tuple[bytes, int, str]:
        r = BitReader(payload)
        r.pos = start
        message = _read_rakstring(r)
        # Same rule as the phone's ReceiveSay: the sender's user id follows when 9+ bits remain.
        userid = _read_rakstring(r) if bitlen - r.pos >= 9 else b""
        name = self.names.get(userid, OTHER_SENDER) if userid else b""
        w = BitWriter()
        write_signal(w, ERPC_SYSTEM_MESSAGE)
        _write_rakstring(w, name + b": " + message if name else message)
        return w.to_bytes(), w.bit_len(), "Say->SystemMessage"

    def _convert(self, name: str, args: list, equipped=()) -> tuple[list, str, str]:
        if name in SELF_USE and len(args) >= 2 and uint_value(*args[0]) == self.mob_action.get("EQUIP"):
            if args[1][1] in equipped:
                return [("uint", self.pc_action["UNEQUIP"])] + args[1:], name, " EQUIP->UNEQUIP (worn)"
            note = f" EQUIP (item not worn, {len(equipped)} worn)"
            return [("uint", self.pc_action["EQUIP"])] + args[1:], name, note
        if name == "DropItemFromInvTile" and len(args) >= 2:
            # Phone: (item, mode) with DROP_MODES; PC: (item, single).
            single = uint_value(*args[1]) == DROP_ONE
            return [args[0], (TAG_TRUE if single else TAG_NIL, 0)] + args[2:], name, ""
        if name == "UnequipItemFromInvTile" and args:
            return [("uint", self.pc_action["UNEQUIP"]), args[0]], "UseItemFromInvTile", ""
        if name == "DropActiveItem" and args:
            # The cursor item is owned by the player's inventory, so the PC's
            # DropItemFromInvTile accepts it and drops the whole stack at the player.
            return [args[0]], "DropItemFromInvTile", ""
        if name in RECIPE_ARGS and args:
            recipe_at, skin_at = RECIPE_ARGS[name]
            code = uint_value(*args[recipe_at])
            mapped = self.recipe_map.get(code) if code is not None else None
            if mapped is None:
                return args, name, f" recipe {code} unmapped"
            args = list(args)
            args[recipe_at] = ("uint", mapped)
            if skin_at is not None and skin_at < len(args):
                args[skin_at] = (TAG_NIL, 0)
            return args, name, f" recipe {code}->{mapped}"
        if name in ACTION_FIRST and args:
            code = uint_value(*args[0])
            mapped = self.action_map.get(code) if code is not None else None
            if mapped is None:
                return args, name, f" action {code} unmapped"
            return [("uint", mapped)] + args[1:], name, ""
        return args, name, ""
