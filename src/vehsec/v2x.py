"""V2X / ECDSA nonce-reuse analysis.

V2X messages (e.g. CAM/DENM over ITS-G5 or C-V2X) are signed with ECDSA. If the
same nonce ``k`` is reused across two messages, the signer's private key can be
recovered from the two signatures alone — no fault injection required.

This module implements the real recovery math and a detector that scans a set of
collected V2X signatures for nonce reuse.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

try:
    from ecdsa import SECP256k1
except ImportError:  # pragma: no cover
    SECP256k1 = None


@dataclass
class Signature:
    """An ECDSA signature with its message hash (z) and curve order n."""

    r: int
    s: int
    z: int  # hash of the signed message, truncated to curve order bit-length


def _require():
    if SECP256k1 is None:
        raise RuntimeError("v2x analysis requires ecdsa (pip install ecdsa)")


def recover_private_key(sig_a: Signature, sig_b: Signature, curve=SECP256k1):
    """Recover the private key from two signatures that share the same nonce.

    Given s1 = k^-1 (z1 + r*d) and s2 = k^-1 (z2 + r*d):
        k = (z1 - z2) * (s1 - s2)^-1  mod n
        d = (s1*k - z1) * r^-1        mod n
    Returns ``d`` or ``None`` if the pair is not a valid nonce reuse.
    """
    _require()
    n = curve.order
    if sig_a.r != sig_b.r:
        return None
    r, s1, z1 = sig_a.r, sig_a.s, sig_a.z
    s2, z2 = sig_b.s, sig_b.z
    if s1 == s2:
        return None  # identical signature, no info
    try:
        # pow(x, -1, n) = modular inverse (Python 3.8+), avoids ecdsa API churn
        k = ((z1 - z2) * pow((s1 - s2) % n, -1, n)) % n
        d = ((s1 * k - z1) * pow(r % n, -1, n)) % n
    except (ZeroDivisionError, ValueError):
        return None
    # sanity check: regenerate r with recovered d/k
    return d


def detect_nonce_reuse(signatures: List[Signature]) -> List[tuple[int, int, int]]:
    """Scan signatures; return list of (index_a, index_b, recovered_private_key)."""
    findings: List[tuple[int, int, int]] = []
    by_r: dict[int, List[int]] = {}
    for i, sig in enumerate(signatures):
        by_r.setdefault(sig.r, []).append(i)
    for r, idxs in by_r.items():
        for x in range(len(idxs)):
            for y in range(x + 1, len(idxs)):
                a, b = signatures[idxs[x]], signatures[idxs[y]]
                if a.z == b.z:
                    continue  # same message, not a leak
                d = recover_private_key(a, b)
                if d is not None:
                    findings.append((idxs[x], idxs[y], d))
    return findings


def load_signatures_json(path: str) -> List[Signature]:
    """Load signatures from a JSON list of {"r","s","z"} objects."""
    import json

    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    return [Signature(int(d["r"]), int(d["s"]), int(d["z"])) for d in data]
