"""Seed-Key solver registry.

Automotive UDS *Security Access* (27 service) uses a proprietary Seed->Key
algorithm, usually hidden inside an OEM DLL. This module provides a **pluggable**
registry so you can:

* register your own / recovered algorithms (e.g. from UnlockECU's db.json),
* use the bundled didactic examples for labs and CTF training.

The bundled algorithms are intentionally simple and for LEARNING ONLY — they do
not correspond to any real OEM secret.
"""

from __future__ import annotations

from typing import Callable, Dict

Registry = Dict[str, Callable[[bytes], bytes]]

_ALGORITHMS: Registry = {}


def register(vendor: str, algorithm: Callable[[bytes], bytes]) -> None:
    """Register a seed->key algorithm for ``vendor``."""
    _ALGORITHMS[vendor.lower()] = algorithm


def solve(vendor: str, seed: bytes) -> bytes:
    """Solve a seed for ``vendor`` and return the key bytes."""
    algo = _ALGORITHMS.get(vendor.lower())
    if algo is None:
        raise KeyError(
            f"No algorithm registered for vendor '{vendor}'. "
            f"Known: {sorted(_ALGORITHMS)}"
        )
    return algo(seed)


def known_vendors() -> list[str]:
    return sorted(_ALGORITHMS)


# --- bundled didactic algorithms (for labs / CTF training) -------------------
def _algo_rotate_xor(seed: bytes) -> bytes:
    """rotate-left-1 then xor 0x5A — a classic training algorithm."""
    return bytes(((b << 1 | b >> 7) ^ 0x5A) & 0xFF for b in seed)


def _algo_add(seed: bytes) -> bytes:
    """key[i] = (seed[i] + 0x11) & 0xFF."""
    return bytes((b + 0x11) & 0xFF for b in seed)


def _algo_reflect(seed: bytes) -> bytes:
    """key = seed xor 0xFF then +index — another teaching variant."""
    return bytes(((b ^ 0xFF) + i) & 0xFF for i, b in enumerate(seed))


register("training_rotate", _algo_rotate_xor)
register("training_add", _algo_add)
register("training_reflect", _algo_reflect)


def from_unlock_ecu_db(db_path: str) -> int:
    """Load algorithms from an UnlockECU-style ``db.json``.

    UnlockECU ships 30+ reverse-engineered vendor algorithms. Drop its db.json
    next to this file (or pass a path) to make them available via :func:`solve`.
    The JSON shape is vendor->algorithm-metadata; this helper is a hook you wire
    to the actual C#-equivalent implementation.
    """
    import json

    with open(db_path, "r", encoding="utf-8") as fh:
        db = json.load(fh)
    # UnlockECU's db is metadata; the executable algorithm lives in its C# code.
    # This stub registers a placeholder so `known_vendors()` reflects the db.
    for vendor in db:
        if vendor.lower() not in _ALGORITHMS:
            register(vendor, _algo_rotate_xor)  # replace with real impl per vendor
    return len(db)
