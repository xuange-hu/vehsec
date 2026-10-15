"""CAN bus helpers: send / receive / replay / fuzz.

Works on any python-can interface. Default is the cross-platform ``virtual``
bus so the toolkit runs without hardware. On Linux use ``socketcan`` with a
``vcan0`` interface; pair it with ICSim + UDSim for a full virtual lab.
"""

from __future__ import annotations

import os
import random
from dataclasses import dataclass, field
from typing import Iterable, Iterator, Optional

try:
    import can
except ImportError:  # pragma: no cover
    can = None


@dataclass
class Frame:
    """A minimal CAN frame."""

    arbitration_id: int
    data: bytes
    is_extended_id: bool = False
    timestamp: float = 0.0

    def to_message(self) -> "can.Message":
        if can is None:
            raise RuntimeError("python-can is not installed (pip install python-can)")
        return can.Message(
            arbitration_id=self.arbitration_id,
            data=self.data,
            is_extended_id=self.is_extended_id,
            timestamp=self.timestamp,
        )

    @classmethod
    def from_message(cls, msg: "can.Message") -> "Frame":
        return cls(
            arbitration_id=msg.arbitration_id,
            data=bytes(msg.data),
            is_extended_id=msg.is_extended_id,
            timestamp=getattr(msg, "timestamp", 0.0),
        )


def default_bus(interface: Optional[str] = None, channel: Optional[str] = None):
    """Return a python-can Bus using sane defaults for the current OS."""
    if can is None:
        raise RuntimeError("python-can is not installed (pip install python-can)")
    interface = interface or os.environ.get("VEHSEC_CAN_IFACE", "virtual")
    channel = channel or os.environ.get("VEHSEC_CAN_CHANNEL", "test")
    return can.Bus(channel=channel, interface=interface)


class CanBus:
    """Thin wrapper around python-can with capture / replay / fuzz helpers."""

    def __init__(self, interface: Optional[str] = None, channel: Optional[str] = None):
        self._bus = default_bus(interface, channel)

    def send(self, frame: Frame, timeout: float = 1.0) -> None:
        self._bus.send(frame.to_message(), timeout=timeout)

    def send_raw(self, arbitration_id: int, data: bytes, is_extended_id: bool = False) -> None:
        self.send(Frame(arbitration_id, bytes(data), is_extended_id))

    def recv(self, timeout: float = 1.0) -> Optional[Frame]:
        msg = self._bus.recv(timeout=timeout)
        return Frame.from_message(msg) if msg is not None else None

    def snapshot(self, count: int = 50, timeout: float = 0.2) -> list[Frame]:
        """Collect up to ``count`` frames (used to verify an attack landed)."""
        frames: list[Frame] = []
        while len(frames) < count:
            f = self.recv(timeout=timeout)
            if f is None:
                break
            frames.append(f)
        return frames

    def replay(self, frames: Iterable[Frame], interval: float = 0.0) -> int:
        """Replay captured frames onto the bus. Returns the number sent."""
        import time

        n = 0
        for f in frames:
            self.send(f)
            n += 1
            if interval:
                time.sleep(interval)
        return n

    def fuzz(
        self,
        ids: Iterable[int],
        payload_len: int = 8,
        rounds: int = 100,
        mutate: bool = True,
        seed: Optional[int] = None,
    ) -> Iterator[Frame]:
        """Yield mutated frames for fuzzing. If ``mutate`` is False, sends zeros."""
        rng = random.Random(seed)
        ids = list(ids)
        for _ in range(rounds):
            cid = rng.choice(ids)
            if mutate:
                payload = bytes(rng.getrandbits(8) for _ in range(payload_len))
            else:
                payload = bytes(payload_len)
            frame = Frame(cid, payload)
            self.send(frame)
            yield frame

    def shutdown(self) -> None:
        self._bus.shutdown()


def analyze(frames: Iterable[Frame]) -> dict:
    """Discover CAN IDs and their behaviour from a capture.

    For each arbitration id report:
      * count        - frames seen
      * unique       - distinct payloads (low => static/periodic, high => data)
      * changing     - byte positions that ever changed (candidate signal bytes)
      * first/last   - the boundary payloads seen

    This is the standard first step of reverse engineering an unknown vehicle:
    static IDs are usually status, changing ones carry the control signals.
    """
    stats: dict[int, dict] = {}
    for f in frames:
        s = stats.setdefault(
            f.arbitration_id,
            {"count": 0, "payloads": set(), "prev": None, "changing": set(),
             "first": None},
        )
        s["count"] += 1
        s["payloads"].add(f.data)
        if s["first"] is None:
            s["first"] = f.data
        s["last"] = f.data
        prev = s["prev"]
        if prev is not None and len(prev) == len(f.data):
            for i, (a, b) in enumerate(zip(prev, f.data)):
                if a != b:
                    s["changing"].add(i)
        s["prev"] = f.data

    out = {}
    for cid in sorted(stats, key=lambda k: -stats[k]["count"]):
        s = stats[cid]
        out[f"0x{cid:X}"] = {
            "count": s["count"],
            "unique": len(s["payloads"]),
            "changing": sorted(s["changing"]),
            "first": s["first"].hex(),
            "last": s["last"].hex(),
        }
    return out


def parse_candump(path: str) -> list[Frame]:
    """Parse a ``candump -l`` style log (``(t) iface ID#DATA``) into frames."""
    frames: list[Frame] = []
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            line = line.strip()
            if "#" not in line:
                continue
            try:
                token = line.split()[-1] if " " in line else line
                cid_str, data_str = token.split("#")
                cid = int(cid_str, 16)
                data = bytes.fromhex(data_str.replace("##", ""))
                frames.append(Frame(cid, data))
            except ValueError:
                continue
    return frames
