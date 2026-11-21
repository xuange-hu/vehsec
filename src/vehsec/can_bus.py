"""CAN bus helpers: send / receive / replay / fuzz.

Works on any python-can interface. Default is the cross-platform ``virtual``
bus so the toolkit runs without hardware. On Linux use ``socketcan`` with a
``vcan0`` interface; pair it with ICSim + UDSim for a full virtual lab.
"""

from __future__ import annotations

import os
import random
import sys
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


def parse_candump_report(path: str) -> tuple[list["Frame"], list[str]]:
    """Parse a ``candump -l`` log, returning ``(frames, skipped_reasons)``.

    Supported shapes, all of which appear in real ``candump`` output:

        123#1122334455667788            classic, 11-bit id
        1FDBFFF4x#DEADBEEF              extended, 29-bit id (note the ``x``)
        123##1CC1122...                 CAN FD, ``##`` then flags byte
        123#R                           remote frame, no payload

    The previous version did ``int(cid_str, 16)`` on the whole token and
    dropped anything it could not parse with a bare ``except ValueError``.
    That silently discarded **every extended frame and every CAN FD frame**:
    a 5-frame log came back as 2 frames, with no warning at all. For a tool
    whose job is replaying and analysing bus traffic, dropping frames is worse
    than a hard error — a replay with holes looks like a working replay.
    """
    frames: list[Frame] = []
    skipped: list[str] = []
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for lineno, raw in enumerate(fh, start=1):
            line = raw.strip()
            if not line or line.startswith("#") or "#" not in line:
                continue
            # candump formats: "(ts) iface ID#DATA" or "iface ID#DATA".
            token = line.split()[-1]
            try:
                frames.append(_frame_from_token(token))
            except ValueError as exc:
                skipped.append(f"line {lineno}: {exc}: {line}")
    return frames, skipped


def _frame_from_token(token: str) -> "Frame":
    """One ``ID#DATA`` token → Frame. Raises ValueError with a usable reason."""
    if "#" not in token:
        raise ValueError("no '#' separator")
    id_part, _, payload = token.partition("#")

    is_extended = id_part.endswith("x") or id_part.endswith("X")
    if is_extended:
        id_part = id_part[:-1]

    try:
        cid = int(id_part, 16)
    except ValueError:
        raise ValueError(f"arbitration id {id_part!r} is not hex") from None

    if cid < 0 or cid > 0x1FFFFFFF:
        raise ValueError(f"arbitration id 0x{cid:X} is outside 29 bits")

    # 11-bit ids never carry the 'x' suffix; anything above 0x7FF is extended
    # whether or not the writer marked it, because that is how the bus works.
    if cid > 0x7FF:
        is_extended = True
    if not is_extended and cid > 0x7FF:
        raise ValueError(f"11-bit frame claims id 0x{cid:X}")

    if payload.startswith("R") or payload.startswith("r"):
        # Remote frames carry no data; a zero-length frame is the honest shape.
        return Frame(cid, b"", is_extended_id=is_extended)

    is_fd = payload.startswith("#")
    if is_fd:
        # "##<flags><data>": the first byte after '##' is the FD flags byte.
        body = payload[1:]
        if len(body) < 2:
            raise ValueError("CAN FD frame is missing its flags byte")
        payload = body[1:]

    try:
        data = bytes.fromhex(payload)
    except ValueError:
        raise ValueError(f"payload {payload!r} is not valid hex") from None

    if not is_fd and len(data) > 8:
        # candump 在两个写法上都出现过：`ID##<flags><data>` 是显式 FD，
        # 而扩展帧直接写 12/24/64 字节也常见（socketcan 的 fd 帧省略了 flags）。
        # 判据看长度本身：经典 CAN 物理上不可能超过 8 字节，超了就是 FD。
        if is_extended:
            is_fd = True
        else:
            raise ValueError(f"classic CAN frame carries {len(data)} bytes (max 8)")

    return Frame(cid, data, is_extended_id=is_extended)


def parse_candump(path: str) -> list[Frame]:
    """Parse a ``candump`` log into frames.

    Malformed lines are reported on stderr instead of being swallowed: a
    replay that quietly loses frames is indistinguishable from a successful
    one, which is the failure mode this whole parser exists to avoid.
    """
    frames, skipped = parse_candump_report(path)
    if skipped:
        sample = "\n  ".join(skipped[:5])
        more = f"\n  ... and {len(skipped) - 5} more" if len(skipped) > 5 else ""
        sys.stderr.write(
            f"vehsec: skipped {len(skipped)} unparseable candump line(s):\n  {sample}{more}\n"
        )
    return frames
