"""ICSim controller — drive the Instrument Cluster Simulator.

ICSim (zombieCraig/ICSim) is the de-facto free "virtual car" for CAN attack
demos. ``vehsec`` can send the same frames ICSim expects so you can script
tamper demos (speed spoofing, turn-signal injection, door unlock) without a car.

Frame IDs below match the public ICSim build; if you patched ICSim, adjust here.
"""

from __future__ import annotations

from .can_bus import CanBus, Frame

# ICSim CAN identifiers (public build)
ID_SPEED = 0x1A4
ID_DOOR = 0x19B
ID_TURN = 0x1B0
ID_BRAKE = 0x1C4


class IcsimController:
    """Send scripted frames to an ICSim instance on the configured bus."""

    def __init__(self, interface: str | None = None, channel: str | None = None):
        self.bus = CanBus(interface, channel)

    def set_speed(self, kmh: int) -> None:
        """Set displayed speed (0..65535 internal unit, ~km/h)."""
        v = max(0, min(65535, int(kmh)))
        self.bus.send_raw(ID_SPEED, bytes([v & 0xFF, (v >> 8) & 0xFF, 0x00]))

    def set_turn(self, direction: str) -> None:
        """direction: 'none' | 'left' | 'right'."""
        code = {"none": 0, "left": 1, "right": 2}.get(direction.lower(), 0)
        self.bus.send_raw(ID_TURN, bytes([code]))

    def set_door(self, door: str, locked: bool) -> None:
        """Toggle a door (front_left/back_left/front_right/back_right)."""
        bit = {
            "front_left": 0,
            "back_left": 1,
            "front_right": 4,
            "back_right": 5,
        }.get(door.lower(), 0)
        state = (1 if locked else 0) << bit
        self.bus.send_raw(ID_DOOR, bytes([state]))

    def set_brake(self, on: bool) -> None:
        self.bus.send_raw(ID_BRAKE, bytes([1 if on else 0]))

    def demo_tamper(self, kmh: int = 250) -> dict:
        """A one-shot tamper demo: jump speed, flash turn, lock doors."""
        self.set_speed(kmh)
        self.set_turn("left")
        for d in ("front_left", "back_left", "front_right", "back_right"):
            self.set_door(d, locked=True)
        return {"demo": "tamper", "speed": kmh, "doors": "locked", "turn": "left"}

    def shutdown(self) -> None:
        self.bus.shutdown()
