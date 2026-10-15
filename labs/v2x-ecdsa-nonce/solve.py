#!/usr/bin/env python3
"""Lab 3 — V2X ECDSA nonce-reuse: generate signatures and recover the private key.

Requires: ecdsa  (pip install ecdsa)
"""
import argparse
import hashlib
import json
import os

from ecdsa import SECP256k1, SigningKey
from ecdsa.util import sigencode_string


def z_of(msg: bytes) -> int:
    h = hashlib.sha256(msg).digest()
    z = int.from_bytes(h, "big")
    n = SECP256k1.order
    if z.bit_length() > n.bit_length():
        z >>= z.bit_length() - n.bit_length()
    return z


def gen_signatures(n: int, reuse: bool):
    sk = SigningKey.generate(curve=SECP256k1)
    priv = sk.privkey.secret_multiplier
    sigs = []
    reuse_k = int.from_bytes(os.urandom(32), "big") % SECP256k1.order if reuse else None
    for i in range(n):
        msg = f"v2x-message-{i}".encode()
        k = reuse_k if (reuse and i in (n // 3, n // 3 + 1)) else None
        sig = sk.sign(msg, k=k, hashfunc=hashlib.sha256, sigencode=sigencode_string)
        r = int.from_bytes(sig[:32], "big")
        s = int.from_bytes(sig[32:], "big")
        sigs.append({"r": r, "s": s, "z": z_of(msg)})
    return priv, sigs


def recover(sig_a, sig_b):
    n = SECP256k1.order
    r, s1, z1 = sig_a["r"], sig_a["s"], sig_a["z"]
    s2, z2 = sig_b["s"], sig_b["z"]
    if r != sig_b["r"] or s1 == s2 or z1 == z2:
        return None
    k = ((z1 - z2) * pow((s1 - s2) % n, -1, n)) % n
    d = ((s1 * k - z1) * pow(r % n, -1, n)) % n
    return d


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--gen", type=int, default=20, help="number of signatures")
    ap.add_argument("--reuse", action="store_true", help="force a nonce reuse")
    ap.add_argument("--out", default="signatures.json")
    args = ap.parse_args()

    priv, sigs = gen_signatures(args.gen, args.reuse)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(sigs, fh)

    print(f"[*] generated {len(sigs)} signatures -> {args.out}")
    print(f"[*] true private key = 0x{priv:X}")

    d = None
    by_r = {}
    for i, sg in enumerate(sigs):
        by_r.setdefault(sg["r"], []).append(i)
    for idxs in by_r.values():
        for x in range(len(idxs)):
            for y in range(x + 1, len(idxs)):
                d = recover(sigs[idxs[x]], sigs[idxs[y]])
                if d is not None:
                    break
            if d is not None:
                break
        if d is not None:
            break

    if d is None:
        print("[!] no nonce reuse found — rerun with --reuse")
        return
    print(f"[+] recovered private key = 0x{d:X}")
    print(f"[+] match = {d == priv}")
    assert d == priv, "recovered key does not match"
    print("[+] OK — private key recovered via nonce reuse")


if __name__ == "__main__":
    main()
