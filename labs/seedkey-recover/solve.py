#!/usr/bin/env python3
"""Lab 5 — UDS 0x27 Seed-Key recovery: reconstruct an unknown algorithm, then unlock.

Scenario
--------
A bench ECU runs UDS *Security Access* (service 0x27). Its seed->key routine lives
inside an OEM DLL you cannot read, but you did sniff an official diagnostic tool
going through it five times, so you hold five ``(seed, key)`` observations.

Recover the algorithm from those observations with ``vehsec.seedkey``, prove it
generalises on a seed you never observed, and use it to unlock the next session
(``27 02``) and read DID ``0xF190``.

Attack chain
------------
1. search 11 parameterised transform families x their parameter space against all
   observed pairs — a candidate must explain *every* sample, not just one;
2. watch confidence climb as you feed more pairs, and note that a uniform seed
   such as ``5a5a5a5a`` leaves several families alive (weak evidence);
3. apply the recovered algorithm to a **held-out seed** — this is what separates a
   real recovery from an overfitted curve fit;
4. run the UDS 0x27 handshake against the simulated ECU and read the protected DID.

Requires: nothing beyond the standard library — the lab imports ``vehsec.seedkey``
from the repository source tree (or from an installed ``vehsec``).
"""
import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
if str(ROOT / "src") not in sys.path:                 # run straight from the repo
    sys.path.insert(0, str(ROOT / "src"))

try:
    from vehsec.seedkey import recover, recover_algorithm
except ImportError as exc:  # pragma: no cover - only if the tree is broken
    sys.exit(f"[!] cannot import vehsec.seedkey from {ROOT / 'src'}: {exc}\n"
             "    pip install -e . (or keep this lab inside the repository)")

FLAG = b"FLAG{seedkey_recovered_from_5_pairs}"
VIN_DID = 0xF190


# --------------------------------------------------------------------------- #
# the black box under attack — pretend this is code you cannot read
# --------------------------------------------------------------------------- #
class OemDll:
    """The ECU vendor's seed->key routine. Only its *outputs* are observable."""

    ROT = 3
    MASK = 0xC7

    @classmethod
    def key_from_seed(cls, seed: bytes) -> bytes:
        out = bytearray()
        for b in seed:
            rotated = ((b << cls.ROT) | (b >> (8 - cls.ROT))) & 0xFF
            out.append(rotated ^ cls.MASK)
        return bytes(out)


class BenchEcu:
    """Minimal UDS security-access server.

    * ``request_seed()`` -> 0x27 01 positive response carrying a 4-byte seed
    * ``send_key(key)``  -> 0x67 02 on match, NRC 0x35 (invalidKey) otherwise
    * ``read_did(did)``  -> NRC 0x33 (securityAccessDenied) until unlocked
    """

    NRC_INVALID_KEY = 0x35
    NRC_ACCESS_DENIED = 0x33

    def __init__(self, seed: bytes) -> None:
        self._seed = bytes(seed)
        self.unlocked = False

    def request_seed(self) -> bytes:
        self.unlocked = False                    # a new seed closes the session
        return self._seed

    def send_key(self, key: bytes) -> tuple[bool, int]:
        if key == OemDll.key_from_seed(self._seed):
            self.unlocked = True
            return True, 0
        return False, self.NRC_INVALID_KEY

    def read_did(self, did: int) -> bytes | tuple[bool, int]:
        if not self.unlocked:
            return False, self.NRC_ACCESS_DENIED
        if did != VIN_DID:
            return False, 0x31                    # requestOutOfRange
        return FLAG


# --------------------------------------------------------------------------- #
# the sniffed evidence
# --------------------------------------------------------------------------- #
CAPTURE_SEEDS = ["5a5a5a5a", "1a2b3c4d", "deadbeef", "00ff12ab", "1234abcd"]
HELD_OUT_SEED = bytes.fromhex("0f1e2d3c")       # never observed -> generalisation


def observed_pairs(limit: int | None = None) -> list[tuple[bytes, bytes]]:
    """Rebuild ``(seed, key)`` observations from the sniffed session log."""
    return [
        (seed := bytes.fromhex(h), OemDll.key_from_seed(seed))
        for h in CAPTURE_SEEDS[: limit or len(CAPTURE_SEEDS)]
    ]


def confidence_progression(pairs) -> None:
    """Show how many families survive as we feed more observations."""
    print("[*] search space: 11 transform families "
          "(xor / add / sub / index-mixed / rotl / bitrev / nibble-swap / "
          "endian-swap / affine)")
    for n in range(1, len(pairs) + 1):
        r = recover(pairs[:n])
        capped = " (capped)" if r["count"] == 12 else ""
        print(f"    {n} pair(s) -> {r['count']:>2d} candidate(s){capped}, "
              f"confidence = {r['confidence']}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--pairs", type=int, default=len(CAPTURE_SEEDS),
                    help="how many observed pairs to feed the recovery "
                         f"(default: all {len(CAPTURE_SEEDS)})")
    ap.add_argument("--seed", default=HELD_OUT_SEED.hex(),
                    help="held-out seed to unlock (default: the fresh one)")
    args = ap.parse_args()
    if not 1 <= args.pairs <= len(CAPTURE_SEEDS):
        ap.error(f"--pairs must be between 1 and {len(CAPTURE_SEEDS)}")

    pairs = observed_pairs(args.pairs)
    print("[*] sniffed security-access samples (0x27 01 -> 0x27 02):")
    for seed, key in pairs:
        print(f"    seed {seed.hex()}  ->  key {key.hex()}")

    print()
    confidence_progression(pairs)

    print()
    try:
        expr, algo = recover_algorithm(pairs)
    except LookupError as exc:
        print(f"[-] {exc}")
        print("[-] OK — nothing recovered from this evidence")
        return
    print(f"[+] recovered algorithm: {expr}")

    bad = [s.hex() for s, k in pairs if algo(s) != k]
    assert not bad, f"recovered algorithm disagrees with observations: {bad}"
    print(f"[+] re-derived all {len(pairs)} observed key(s) — consistent")

    ecu = BenchEcu(bytes.fromhex(args.seed))
    seed = ecu.request_seed()
    assert seed not in [s for s, _ in pairs], "held-out seed must be unseen"
    print(f"[*] ECU hands out a new seed: {seed.hex()} "
          "(not in the capture — this is the real test)")
    key = algo(seed)
    print(f"[*] answering 0x27 02 with key {key.hex()}")

    ok, nrc = ecu.send_key(key)
    if not ok:
        # This is the lesson of the lab: a candidate can fit every observation
        # and still be wrong. Only an unseen seed exposes it.
        print(f"[-] 0x7F 27 {nrc:02X} invalidKey — the ECU rejected {key.hex()}")
        print(f"[-] '{expr}' was overfitted: it explains the observed sample(s) "
              "but not a new seed.")
        print("    Feed the search more evidence:  python solve.py --pairs 3")
        sys.exit(1)
    print("[+] 0x67 02 sendKey accepted — security level unlocked")

    payload = ecu.read_did(VIN_DID)
    assert isinstance(payload, bytes), f"read denied: {payload}"
    print(f"[+] read 0xF190 = {payload.decode()}")
    assert payload == FLAG, "DID content mismatch"
    print("[+] OK — algorithm recovered and ECU unlocked without the DLL")


if __name__ == "__main__":
    main()
