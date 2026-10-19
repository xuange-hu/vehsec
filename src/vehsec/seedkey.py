"""Seed-Key solver registry and seed/key algorithm recovery.

Automotive UDS *Security Access* (service 0x27) uses a proprietary Seed->Key
algorithm, usually hidden inside an OEM DLL. This module provides a
**pluggable** registry so you can:

* register your own / recovered algorithms (e.g. from UnlockECU's db.json),
* use the bundled didactic algorithms for labs and CTF training,
* **recover** an unknown algorithm from observed ``(seed, key)`` pairs.

The bundled algorithms are intentionally simple and for LEARNING ONLY — they do
not correspond to any real OEM secret.

Recovery model
--------------
:func:`recover` brute-forces a catalogue of *parameterised transform families*
(``xor c``, ``add c``, ``rotl k``, ``bitreverse``, ``affine a*x+b`` ...) and
returns every family+parameter combination consistent with **all** supplied
pairs. Every family is length preserving, which matches real seed/key pairs
(4-byte seed -> 4-byte key is the norm).

Uniqueness caveat: with a single pair, several families can fit. Feed >= 3 pairs
with distinct seed bytes to narrow the answer down to one candidate.
"""

from __future__ import annotations

import hashlib
from typing import Callable, Dict, Iterable, Sequence

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


# --------------------------------------------------------------------------- #
# algorithm factories (composable building blocks)
# --------------------------------------------------------------------------- #
def algo_xor(c: int) -> Callable[[bytes], bytes]:
    """``key[i] = seed[i] ^ c``."""
    c &= 0xFF

    def f(seed: bytes) -> bytes:
        return bytes(b ^ c for b in seed)

    return f


def algo_add(c: int) -> Callable[[bytes], bytes]:
    """``key[i] = (seed[i] + c) & 0xFF``."""
    c &= 0xFF

    def f(seed: bytes) -> bytes:
        return bytes((b + c) & 0xFF for b in seed)

    return f


def algo_sub(c: int) -> Callable[[bytes], bytes]:
    """``key[i] = (seed[i] - c) & 0xFF``."""
    c &= 0xFF

    def f(seed: bytes) -> bytes:
        return bytes((b - c) & 0xFF for b in seed)

    return f


def algo_rotl(k: int) -> Callable[[bytes], bytes]:
    """Rotate every byte left by ``k`` bits."""
    k &= 0x07

    def f(seed: bytes) -> bytes:
        return bytes(((b << k) | (b >> (8 - k))) & 0xFF for b in seed) if k else bytes(seed)

    return f


def algo_rotr(k: int) -> Callable[[bytes], bytes]:
    """Rotate every byte right by ``k`` bits."""
    return algo_rotl((-k) & 0x07)


def algo_bitreverse() -> Callable[[bytes], bytes]:
    """Mirror the bit order inside every byte (MSB <-> LSB)."""

    def f(seed: bytes) -> bytes:
        return bytes(int(f"{b:08b}"[::-1], 2) for b in seed)

    return f


def algo_nibble_swap() -> Callable[[bytes], bytes]:
    """Swap the high and low nibble of every byte."""

    def f(seed: bytes) -> bytes:
        return bytes(((b & 0x0F) << 4) | (b >> 4) for b in seed)

    return f


def algo_endian_swap() -> Callable[[bytes], bytes]:
    """Reverse the byte order of the whole seed."""

    def f(seed: bytes) -> bytes:
        return bytes(seed[::-1])

    return f


def _crc16_ccitt_false(data: bytes) -> int:
    """CRC-16/CCITT-FALSE (poly 0x1021, init 0xFFFF) — the usual suspect."""
    crc = 0xFFFF
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def algo_crc16_xor() -> Callable[[bytes], bytes]:
    """``key[i] = seed[i] ^ crc16(seed)[i % 2]`` — checksum-mixed variant."""

    def f(seed: bytes) -> bytes:
        crc = _crc16_ccitt_false(seed).to_bytes(2, "big")
        return bytes(b ^ crc[i % 2] for i, b in enumerate(seed))

    return f


def _galois_lfsr_stream(state: int, n: int, poly: int = 0xB8) -> bytes:
    """Galois LFSR keystream (8-bit state, right-shifting)."""
    out = bytearray()
    s = (state & 0xFF) or 0x01  # an all-zero state would lock the register
    for _ in range(n):
        lsb = s & 1
        s >>= 1
        if lsb:
            s ^= poly
        out.append(s & 0xFF)
    return bytes(out)


def algo_lfsr_xor(poly: int = 0xB8) -> Callable[[bytes], bytes]:
    """``key[i] = seed[i] ^ lfsr_next()`` with the LFSR seeded from the seed."""

    def f(seed: bytes) -> bytes:
        state = int.from_bytes(seed, "big") & 0xFF
        return bytes(b ^ k for b, k in zip(seed, _galois_lfsr_stream(state, len(seed), poly)))

    return f


def _keystream(seed: bytes, n: int) -> bytes:
    """SHA-256 keystream, **block extended** until it covers ``n`` bytes.

    A single SHA-256 digest is only 32 bytes, so the counter-suffixed digest is
    concatenated for as many blocks as the payload needs. Never truncate a
    single digest to fit a longer seed — that silently produces a short key.
    """
    out = bytearray()
    counter = 0
    while len(out) < n:
        out += hashlib.sha256(seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return bytes(out[:n])


def algo_sha_keystream() -> Callable[[bytes], bytes]:
    """``key[i] = seed[i] ^ sha256(seed || counter)[i]`` — hash-masked variant."""

    def f(seed: bytes) -> bytes:
        return bytes(b ^ k for b, k in zip(seed, _keystream(seed, len(seed))))

    return f


def compose(*algos: Callable[[bytes], bytes]) -> Callable[[bytes], bytes]:
    """Chain algorithms left to right: ``compose(f, g)(s) == g(f(s))``."""
    if not algos:
        raise ValueError("compose() needs at least one algorithm")

    def f(seed: bytes) -> bytes:
        out = bytes(seed)
        for a in algos:
            out = a(out)
        return out

    return f


# --------------------------------------------------------------------------- #
# bundled didactic algorithms (for labs / CTF training)
# --------------------------------------------------------------------------- #
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

# realistic-ish presets built from the factories above
register("demo_xor_5a", algo_xor(0x5A))
register("demo_add_37", algo_add(0x37))
register("demo_rotl3", algo_rotl(3))
register("demo_bitreverse", algo_bitreverse())
register("demo_nibble_swap", algo_nibble_swap())
register("demo_endian_swap", algo_endian_swap())
register("demo_crc16_xor", algo_crc16_xor())
register("demo_lfsr_xor", algo_lfsr_xor())
register("demo_sha_keystream", algo_sha_keystream())
register("demo_rotl1_xor5a", compose(algo_rotl(1), algo_xor(0x5A)))


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


# --------------------------------------------------------------------------- #
# algorithm recovery from observed (seed, key) pairs
# --------------------------------------------------------------------------- #
def _families() -> Iterable[tuple[str, Callable[[int], Callable[[bytes], bytes]]]]:
    """Yield ``(expr_template, builder)`` search families, simplest first."""
    yield "key[i] = seed[i] ^ 0x{c:02X}", lambda c: algo_xor(c)
    yield "key[i] = (seed[i] + 0x{c:02X}) & 0xFF", lambda c: algo_add(c)
    yield "key[i] = (seed[i] - 0x{c:02X}) & 0xFF", lambda c: algo_sub(c)
    yield "key[i] = seed[i] ^ i ^ 0x{c:02X}", (
        lambda c: (lambda s: bytes(b ^ i ^ c for i, b in enumerate(s)))
    )
    yield "key[i] = (seed[i] + i + 0x{c:02X}) & 0xFF", (
        lambda c: (lambda s: bytes((b + i + c) & 0xFF for i, b in enumerate(s)))
    )
    yield "key[i] = rotl8(seed[i], 1) ^ 0x{c:02X}", (
        lambda c: compose(algo_rotl(1), algo_xor(c))
    )
    yield "key[i] = rotl8(seed[i], 3) ^ 0x{c:02X}", (
        lambda c: compose(algo_rotl(3), algo_xor(c))
    )
    yield "key[i] = bitrev8(seed[i]) ^ 0x{c:02X}", (
        lambda c: compose(algo_bitreverse(), algo_xor(c))
    )
    yield "key[i] = nibble_swap(seed[i]) ^ 0x{c:02X}", (
        lambda c: compose(algo_nibble_swap(), algo_xor(c))
    )
    yield "key[i] = seed[n-1-i] ^ 0x{c:02X}", (
        lambda c: compose(algo_endian_swap(), algo_xor(c))
    )
    yield "key[i] = (0x{a:02X} * seed[i] + 0x{b:02X}) & 0xFF", (
        lambda ab: (lambda s: bytes((ab[0] * b + ab[1]) & 0xFF for b in s))
    )


def _param_space(template: str) -> Sequence:
    """Parameter tuples to try for a given family template."""
    if "{a:02X}" in template and "{b:02X}" in template:
        # affine: `a` must be odd to be invertible mod 256
        return [(a, b) for a in range(1, 256, 2) for b in range(256)]
    return list(range(256))


def _matches(fn: Callable[[bytes], bytes], pairs: Sequence[tuple[bytes, bytes]]) -> bool:
    for seed, key in pairs:
        if fn(seed) != key:
            return False
    return True


def _search(norm: Sequence[tuple[bytes, bytes]],
            max_results: int) -> list[tuple[str, dict, Callable[[bytes], bytes]]]:
    """Brute-force the families; return ``(expr, params, fn)`` triples."""
    found: list[tuple[str, dict, Callable[[bytes], bytes]]] = []
    for template, builder in _families():
        for p in _param_space(template):
            fn = builder(p)
            if not _matches(fn, norm):
                continue
            params = {"c": p} if isinstance(p, int) else {"a": p[0], "b": p[1]}
            found.append((template.format(**params), params, fn))
            if len(found) >= max_results:
                return found
    return found


def _normalise(pairs: Sequence[tuple[bytes, bytes]]) -> list[tuple[bytes, bytes]]:
    norm: list[tuple[bytes, bytes]] = []
    seed_len = len(pairs[0][0])
    for seed, key in pairs:
        seed, key = bytes(seed), bytes(key)
        if len(seed) != seed_len:
            raise ValueError(
                f"all seeds must be the same length (first is {seed_len} bytes, "
                f"got {len(seed)})"
            )
        if len(key) != len(seed):
            raise ValueError(
                f"seed/key length mismatch: {len(seed)} vs {len(key)}. "
                "recover() only models length-preserving transforms"
            )
        norm.append((seed, key))
    return norm


def recover(pairs: Sequence[tuple[bytes, bytes]], max_results: int = 12) -> dict:
    """Recover candidate seed->key algorithms from observed ``(seed, key)`` pairs.

    ``pairs`` is a sequence of ``(seed_bytes, key_bytes)`` captured from a real
    ECU (e.g. by replaying service 0x27 ``requestSeed`` and logging the key an
    official tool sends back).

    Returns a dict with ``seed_len``, ``pairs``, ``count``, ``confidence`` and
    ``candidates`` (each with ``expr`` / ``params`` / ``example_key``).
    """
    if not pairs:
        raise ValueError("need at least one (seed, key) pair")

    norm = _normalise(pairs)

    candidates = [
        {"expr": expr, "params": params, "example_key": fn(norm[0][0]).hex()}
        for expr, params, fn in _search(norm, max_results)
    ]

    n = len(norm)
    if not candidates:
        confidence = "none"
    elif n >= 3 and len(candidates) == 1:
        confidence = "high"
    elif n >= 2 and len(candidates) <= 3:
        confidence = "medium"
    else:
        confidence = "low"

    return {
        "seed_len": len(norm[0][0]),
        "pairs": n,
        "count": len(candidates),
        "confidence": confidence,
        "candidates": candidates,
    }


def recover_algorithm(
    pairs: Sequence[tuple[bytes, bytes]],
    max_results: int = 12,
) -> tuple[str, Callable[[bytes], bytes]]:
    """Recover an unknown seed->key algorithm and hand it back **as a callable**.

    This is the programmatic counterpart of :func:`recover`: instead of a report,
    you get ``(expression, fn)`` where ``fn(seed) -> key`` reproduces every
    observed pair. Register it with :func:`register` to use it through
    :func:`solve` afterwards::

        expr, fn = recover_algorithm(pairs)
        register("captured_ecu", fn)
        solve("captured_ecu", fresh_seed)

    Raises :class:`LookupError` when no family fits all the pairs.
    """
    if not pairs:
        raise ValueError("need at least one (seed, key) pair")
    norm = _normalise(pairs)
    found = _search(norm, max_results)
    if not found:
        raise LookupError(
            f"no bundled family explains all {len(norm)} pair(s). Try feeding "
            "more pairs, or implement the transform yourself and register() it."
        )
    expr, _params, fn = found[0]
    return expr, fn


def predict(pairs: Sequence[tuple[bytes, bytes]], seed: bytes) -> dict:
    """Recover the algorithm from ``pairs`` and apply it to a **fresh** ``seed``.

    This is the real workflow: you observed what an OEM tool answered for a few
    seeds and now want to unlock a new session without ever reading the DLL.
    Returns ``{"expr", "key", "confidence", "count"}``.
    """
    report = recover(pairs)
    expr, fn = recover_algorithm(pairs)
    return {
        "expr": expr,
        "key": fn(bytes(seed)).hex(),
        "confidence": report["confidence"],
        "count": report["count"],
        "pairs": report["pairs"],
    }


def parse_pairs(text: str) -> list[tuple[bytes, bytes]]:
    """Parse ``"seed:key,seed:key"`` hex pairs (also accepts a JSON list)."""
    text = text.strip()
    if not text:
        raise ValueError("empty pair list")
    if text.startswith("["):
        import json

        raw = json.loads(text)
        return [
            (bytes.fromhex(p["seed"]), bytes.fromhex(p["key"]))
            if isinstance(p, dict)
            else (bytes.fromhex(p[0]), bytes.fromhex(p[1]))
            for p in raw
        ]
    out = []
    for item in text.split(","):
        item = item.strip()
        if not item:
            continue
        if ":" not in item:
            raise ValueError(f"expected 'seed:key', got {item!r}")
        seed, key = item.split(":", 1)
        out.append((bytes.fromhex(seed.strip()), bytes.fromhex(key.strip())))
    if not out:
        raise ValueError("no usable pairs")
    return out
