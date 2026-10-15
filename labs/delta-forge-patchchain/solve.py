#!/usr/bin/env python3
"""Lab 2 solver — recover a hidden payload from a firmware patch-chain diff.

Each patch applies buf[pos] ^= frag. So state[i] XOR state[i-1] == frag at the
patched position and 0 elsewhere. Collect non-zero diffs, sort by position.
"""
import os

FLAG = b"FLAG{delta_forge_patchchain_diff_reveals_payload}"
BASE_LEN = 64


def build_states():
    rng = os.urandom  # non-deterministic base is fine; recovery is position-based
    states = [bytearray(rng(BASE_LEN))]
    for i, b in enumerate(FLAG):
        s = bytearray(states[-1])
        s[i % BASE_LEN] ^= b            # patch = XOR with one flag byte
        states.append(s)
    return [bytes(s) for s in states]


def recover(states):
    slots = {}
    for a, b in zip(states, states[1:]):
        for pos in range(len(a)):
            d = a[pos] ^ b[pos]
            if d:
                slots[pos] = d
    out = bytearray()
    for pos in sorted(slots):
        out.append(slots[pos])
    return bytes(out)


def main():
    states = build_states()
    pt = recover(states)
    print(f"[*] snapshots        = {len(states)}")
    print(f"[+] recovered payload = {pt.decode(errors='replace')}")
    assert FLAG in pt, "payload not fully recovered"
    print("[+] OK — patch-chain differential reveals the flag")


if __name__ == "__main__":
    main()
