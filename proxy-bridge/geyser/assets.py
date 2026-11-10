"""Anim builds and animations only the PC build has, shown as the nearest thing the phone has.

The server names a build or an animation by the 32-bit hash of its name (the same
hash as a netvar name), written most significant bit first at any bit offset of
the entity's serialize payload. Measured on live frames: hash("pig_build") and
hash("pig_frankenswine_build") both appear that way in pigman records.

The phone has no asset for a PC-only name and draws nothing: a Hallowed Nights
franken pig is a hostile pig the phone player cannot see. Like GeyserMC mapping an
unknown block to a known one, the bridge swaps the hash for one the phone can draw.
The creature then looks like its everyday self but still behaves as the server says.

A 32-bit pattern matches by chance once in 2^32 bit positions, and only the prefabs
listed here are searched.
"""
from __future__ import annotations

from .bitstream import BitReader

# Hallowed Nights monsters (PC 762172) move with their own animations.
_HALLOWEEN_ANIMS = {
    "halloween_idle_loop": "idle_loop",
    "halloween_walk_pre": "walk_pre",
    "halloween_walk_loop": "walk_loop",
    "halloween_walk_pst": "walk_pst",
    "halloween_run_pre": "run_pre",
    "halloween_run_loop": "run_loop",
    "halloween_run_pst": "run_pst",
    "halloween_atk_pre": "atk",
    "halloween_atk": "idle_loop",
    "halloween_atk_pst": "idle_loop",
}

# prefab -> {PC-only name: name the phone has}
FALLBACK = {
    "pigman": {"pig_frankenswine_build": "pig_build", **_HALLOWEEN_ANIMS},
    "bunnyman": {"manrabbit_vampire_build": "manrabbit_build", **_HALLOWEEN_ANIMS},
    "merm": {"merm_mummy_build": "merm_build", **_HALLOWEEN_ANIMS},
    "bat": {"bat_acid_build": "bat_basic"},
    "rocky": {"rocky_acid_build": "rocky"},
}


def name_hash(name: str) -> int:
    v = 0
    for c in name.lower().encode():
        v = (c + (v << 6) + (v << 16) - v) & 0xFFFFFFFF
    return v


def _bits(name: str) -> str:
    return format(name_hash(name), "032b")


_PATTERNS = {prefab: [(_bits(pc), _bits(mob), pc, mob) for pc, mob in names.items()]
             for prefab, names in FALLBACK.items()}


def patch(prefab: str, payload: BitReader) -> tuple[BitReader, list[tuple[str, str]]]:
    """The payload with PC-only names swapped, and the (pc, phone) names that were swapped.

    The reader is returned untouched, at its current position, when nothing matches.
    """
    patterns = _PATTERNS.get(prefab)
    if not patterns or payload.nbits < 32:
        return payload, []
    n = payload.nbits
    nbytes = (n + 7) // 8
    bits = format(int.from_bytes(payload.data[:nbytes], "big") >> (8 * nbytes - n), f"0{n}b")
    swapped = []
    for pc, mob, pc_name, mob_name in patterns:
        if pc in bits:
            bits = bits.replace(pc, mob)
            swapped.append((pc_name, mob_name))
    if not swapped:
        return payload, []
    out = BitReader((int(bits, 2) << (8 * nbytes - n)).to_bytes(nbytes, "big"))
    out.nbits = n
    out.pos = payload.pos
    return out, swapped
