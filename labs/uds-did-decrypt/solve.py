#!/usr/bin/env python3
"""Lab 1 solver — UDS DID decrypt via XOR keystream derived from seed.

The ECU encrypted the DID with: ct = pt XOR sha256(seed)[:len].
Decryption is the same XOR (self-inverse).
"""
import hashlib
import os

# --- challenge data (normally captured from the ECU) -----------------------
SEED = bytes.fromhex("a1b2c3d4")               # UDS 27 01 response
FLAG = b"FLAG{UDS_DID_x0r_keystream_from_seed}"  # the secret DID (VIN)


def keystream(seed: bytes, length: int) -> bytes:
    """Extend a seed into a stream cipher key of arbitrary length (HKDF-style)."""
    out, ctr = b"", 0
    while len(out) < length:
        out += hashlib.sha256(seed + ctr.to_bytes(4, "big")).digest()
        ctr += 1
    return out[:length]


KEYSTREAM = keystream(SEED, len(FLAG))
CIPHERTEXT = bytes(p ^ k for p, k in zip(FLAG, KEYSTREAM))


def decrypt(ciphertext: bytes, seed: bytes) -> bytes:
    ks = keystream(seed, len(ciphertext))
    return bytes(c ^ k for c, k in zip(ciphertext, ks))


def main() -> None:
    pt = decrypt(CIPHERTEXT, SEED)
    print(f"[*] seed      = {SEED.hex()}")
    print(f"[*] ciphertext = {CIPHERTEXT.hex()}")
    print(f"[+] recovered DID (0xF190) = {pt.decode(errors='replace')}")
    assert pt == FLAG, "decryption mismatch"
    print("[+] OK — flag recovered")


if __name__ == "__main__":
    main()
