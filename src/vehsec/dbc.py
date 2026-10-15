"""DBC (Vector CAN database) parser — pure standard library.

A DBC file is the Rosetta Stone of a CAN bus: without it a capture is just
``1A4#0A3F``, with it you get ``Speed = 41.5 km/h``. This module parses the
subset that matters for automotive work:

* ``BO_`` messages (frame id, name, DLC, transmitter)
* ``SG_`` signals, including **Intel (little-endian) and Motorola
  (big-endian) layouts**, signed values, factor/offset scaling, and
  multiplexed signals (``M`` / ``mN``)
* ``VAL_`` value tables so ``1`` renders as ``"On"``
* ``CM_`` comments on messages and signals

Deliberately *not* implemented: attributes (``BA_``), signal groups (``SIG_GROUP_``),
and extended multiplexing. Signals whose definitions are malformed are skipped
rather than aborting the parse — real OEM DBCs are messy.

Byte-order note (the part everyone gets wrong)
----------------------------------------------
DBC start bits use a "sawtooth" numbering that differs per byte order:

* ``@1`` Intel — ``start`` is the **LSB**, bits count upward.
* ``@0`` Motorola — ``start`` is the **MSB**; within the byte it is counted
  from the MSB, and consecutive bits walk *downward*, wrapping to the MSB of
  the next byte.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Union

__all__ = ["Signal", "Message", "Database", "DecodeError", "parse_file"]

_RE_BO = re.compile(r"^\s*BO_\s+(\d+)\s+([^:]+?):\s*(\d+)\s+(\S+)")
_RE_SG = re.compile(
    r"^\s*SG_\s+(?P<name>[A-Za-z0-9_]+)"
    r"(?:\s+(?P<mux>M|m\d+))?"
    r"\s*:\s*(?P<start>\d+)\|(?P<length>\d+)@(?P<order>[01])(?P<sign>[+-])"
    # factor/offset and [min|max] are optional: plenty of real files omit them.
    r"\s*(?:\(\s*(?P<factor>[-+0-9.eE]+)\s*,\s*(?P<offset>[-+0-9.eE]+)\s*\))?"
    r"\s*(?:\[\s*(?P<min>[-+0-9.eE]*)\s*\|\s*(?P<max>[-+0-9.eE]*)\s*\])?"
    r"\s*\"(?P<unit>[^\"]*)\"\s*(?P<rx>.*)$"
)
_RE_VAL = re.compile(r"^\s*VAL_\s+(\d+)\s+([A-Za-z0-9_]+)\s+(.*?);", re.DOTALL)
_RE_VAL_ITEM = re.compile(r"(-?\d+)\s+\"([^\"]*)\"")
_RE_CM_BO = re.compile(r"^\s*CM_\s+BO_\s+(\d+)\s+\"([^\"]*)\"\s*;")
_RE_CM_SG = re.compile(r"^\s*CM_\s+SG_\s+(\d+)\s+([A-Za-z0-9_]+)\s+\"([^\"]*)\"\s*;")


class DecodeError(ValueError):
    """Raised when a frame cannot be decoded against a message definition."""


def _num(text: str, default: float = 0.0) -> float:
    text = text.strip()
    if not text:
        return default
    try:
        return float(text)
    except ValueError:
        return default


def _bit_positions(start: int, length: int, big_endian: bool) -> List[int]:
    """Return LSB-indexed bit positions, most-significant bit first.

    LSB index 0 = bit 0 of byte 0 (least significant). The returned list is in
    signal order, so the first entry is the signal's MSB.
    """
    positions: List[int] = []
    if big_endian:
        # `start` is the MSB, counted from the MSB within its byte.
        pos = (start // 8) * 8 + (7 - (start % 8))
        for _ in range(length):
            positions.append(pos)
            if pos % 8 == 0:
                pos += 15  # wrap down to the MSB of the next byte
            else:
                pos -= 1
    else:
        # `start` is the LSB walking upward; reverse so MSB comes first.
        positions = [start + k for k in range(length)]
        positions.reverse()
    return positions


@dataclass
class Signal:
    """One signal inside a DBC message."""

    name: str
    start: int
    length: int
    byte_order: str  # "little_endian" | "big_endian"
    is_signed: bool
    factor: float = 1.0
    offset: float = 0.0
    minimum: float = 0.0
    maximum: float = 0.0
    unit: str = ""
    receivers: List[str] = field(default_factory=list)
    is_multiplexer: bool = False
    multiplexer_ids: Optional[List[int]] = None
    values: Dict[int, str] = field(default_factory=dict)
    comment: str = ""

    @property
    def is_big_endian(self) -> bool:
        return self.byte_order == "big_endian"

    def raw_value(self, data: bytes) -> int:
        """Extract the raw (unscaled) integer, honouring byte order and sign."""
        bits = _bit_positions(self.start, self.length, self.is_big_endian)
        value = 0
        for pos in bits:
            byte_index, bit_index = divmod(pos, 8)
            if byte_index >= len(data):
                raise DecodeError(
                    f"signal {self.name} needs byte {byte_index}, frame has {len(data)}"
                )
            value = (value << 1) | ((data[byte_index] >> bit_index) & 1)
        if self.is_signed and length_is_negative(value, self.length):
            value -= 1 << self.length
        return value

    def physical_value(self, data: bytes) -> float:
        return self.raw_value(data) * self.factor + self.offset

    def encode_raw(self, raw: int, data: Optional[bytearray] = None, dlc: int = 8) -> bytearray:
        """Write a raw integer into ``data`` (or a fresh zeroed frame)."""
        buf = data if data is not None else bytearray(dlc)
        if self.is_signed and raw < 0:
            raw += 1 << self.length
        if not 0 <= raw < (1 << self.length):
            raise DecodeError(f"raw value {raw} does not fit in {self.length} bits")
        bits = _bit_positions(self.start, self.length, self.is_big_endian)
        for shift, pos in enumerate(bits):
            byte_index, bit_index = divmod(pos, 8)
            if byte_index >= len(buf):
                raise DecodeError(f"signal {self.name} does not fit in a {len(buf)}-byte frame")
            bit = (raw >> (self.length - 1 - shift)) & 1
            if bit:
                buf[byte_index] |= 1 << bit_index
            else:
                buf[byte_index] &= ~(1 << bit_index) & 0xFF
        return buf

    def encode_physical(self, value: float, data: Optional[bytearray] = None, dlc: int = 8) -> bytearray:
        """Write a physical value (applies inverse factor/offset scaling)."""
        if self.factor == 0:
            raise DecodeError(f"signal {self.name} has factor 0; cannot scale")
        return self.encode_raw(int(round((value - self.offset) / self.factor)), data, dlc)

    def to_dict(self) -> Dict[str, object]:
        return {
            "name": self.name,
            "start": self.start,
            "length": self.length,
            "byte_order": self.byte_order,
            "signed": self.is_signed,
            "factor": self.factor,
            "offset": self.offset,
            "unit": self.unit,
            "receivers": self.receivers,
            "multiplexer": "M" if self.is_multiplexer else (
                ",".join(str(i) for i in self.multiplexer_ids) if self.multiplexer_ids else None
            ),
            "values": self.values,
            "comment": self.comment,
        }


def length_is_negative(value: int, length: int) -> bool:
    """True when the sign bit of a ``length``-bit two's-complement value is set."""
    return bool((value >> (length - 1)) & 1) if length else False


@dataclass
class Message:
    """A DBC message (CAN frame definition)."""

    frame_id: int
    name: str
    length: int  # DLC
    sender: str = ""
    signals: List[Signal] = field(default_factory=list)
    comment: str = ""

    @property
    def is_extended(self) -> bool:
        return self.frame_id > 0x7FF

    @property
    def multiplexer(self) -> Optional[Signal]:
        for s in self.signals:
            if s.is_multiplexer:
                return s
        return None

    def signal(self, name: str) -> Signal:
        for s in self.signals:
            if s.name == name:
                return s
        raise KeyError(f"no signal {name!r} in {self.name}")

    def decode(
        self, data: bytes, scaled: bool = True, apply_value_tables: bool = True
    ) -> Dict[str, Union[float, int, str]]:
        """Decode a frame into ``{signal_name: value}``.

        Multiplexed signals are only included when their multiplexer id matches
        the decoded multiplexer switch value.
        """
        if len(data) < self.length:
            raise DecodeError(f"{self.name} expects {self.length} bytes, got {len(data)}")
        mux = self.multiplexer
        active: Optional[int] = None
        if mux is not None:
            active = mux.physical_value(data) if scaled else mux.raw_value(data)
            active = int(active)

        out: Dict[str, Union[float, int, str]] = {}
        for s in self.signals:
            if s.multiplexer_ids is not None and active is not None:
                if active not in s.multiplexer_ids:
                    continue
            if scaled:
                value = s.physical_value(data)
                value = int(value) if float(value).is_integer() else round(value, 6)
            else:
                value = s.raw_value(data)
            if apply_value_tables and s.values:
                raw = s.raw_value(data)
                if raw in s.values:
                    out[s.name] = s.values[raw]
                    continue
            out[s.name] = value
        return out

    def encode(self, values: Dict[str, Union[float, int]]) -> bytes:
        """Encode ``{signal_name: physical_value}`` into a frame."""
        buf = bytearray(self.length or 8)
        for name, value in values.items():
            self.signal(name).encode_physical(float(value), buf, self.length or 8)
        return bytes(buf)

    def to_dict(self) -> Dict[str, object]:
        return {
            "id": f"0x{self.frame_id:X}",
            "name": self.name,
            "dlc": self.length,
            "sender": self.sender,
            "extended": self.is_extended,
            "comment": self.comment,
            "signals": [s.to_dict() for s in self.signals],
        }


@dataclass
class Database:
    """A parsed DBC file: a map of frame id -> :class:`Message`."""

    messages: Dict[int, Message] = field(default_factory=dict)
    source: str = ""

    # -- lookup ------------------------------------------------------------- #
    def __len__(self) -> int:
        return len(self.messages)

    def __iter__(self):
        return iter(self.messages.values())

    def message(self, key: Union[int, str]) -> Message:
        """Find a message by frame id (int or hex string) or by name."""
        if isinstance(key, int):
            if key in self.messages:
                return self.messages[key]
            raise KeyError(f"no message with id 0x{key:X}")
        text = key.strip()
        if text.lower().startswith("0x"):
            return self.message(int(text, 16))
        if text.isdigit():
            return self.message(int(text))
        for m in self.messages.values():
            if m.name == text:
                return m
        raise KeyError(f"no message named {key!r}")

    def search(self, needle: str) -> List[Message]:
        """Case-insensitive substring search over message and signal names."""
        needle = needle.lower()
        hits = []
        for m in self.messages.values():
            if needle in m.name.lower():
                hits.append(m)
                continue
            if any(needle in s.name.lower() for s in m.signals):
                hits.append(m)
        return hits

    # -- data --------------------------------------------------------------- #
    def decode(self, frame_id: int, data: bytes, **kwargs) -> Dict[str, Union[float, int, str]]:
        return self.message(frame_id).decode(data, **kwargs)

    def encode(self, key: Union[int, str], values: Dict[str, Union[float, int]]) -> bytes:
        return self.message(key).encode(values)

    # -- parsing ------------------------------------------------------------ #
    @classmethod
    def parse(cls, text: str, source: str = "") -> "Database":
        db = cls(source=source)
        current: Optional[Message] = None
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            m = _RE_BO.match(line)
            if m:
                current = Message(
                    frame_id=int(m.group(1)),
                    name=m.group(2).strip(),
                    length=int(m.group(3)),
                    sender=m.group(4).strip(),
                )
                db.messages[current.frame_id] = current
                continue

            m = _RE_SG.match(line)
            if m and current is not None:
                signal = _signal_from_match(m)
                if signal is not None:
                    current.signals.append(signal)
                continue

            m = _RE_VAL.match(line)
            if m:
                target = db.messages.get(int(m.group(1)))
                if target is None:
                    continue
                table = {int(k): v for k, v in _RE_VAL_ITEM.findall(m.group(3))}
                for s in target.signals:
                    if s.name == m.group(2):
                        s.values = table
                        break
                continue

            m = _RE_CM_BO.match(line)
            if m:
                target = db.messages.get(int(m.group(1)))
                if target is not None:
                    target.comment = m.group(2)
                continue

            m = _RE_CM_SG.match(line)
            if m:
                target = db.messages.get(int(m.group(1)))
                if target is None:
                    continue
                for s in target.signals:
                    if s.name == m.group(2):
                        s.comment = m.group(3)
                        break
                continue
        return db

    def summary(self) -> List[Dict[str, object]]:
        """A compact, JSON-safe summary used by the CLI and MCP server."""
        return [
            {
                "id": f"0x{m.frame_id:X}",
                "name": m.name,
                "dlc": m.length,
                "signals": len(m.signals),
            }
            for m in sorted(self.messages.values(), key=lambda x: x.frame_id)
        ]


def _signal_from_match(m: "re.Match[str]") -> Optional[Signal]:
    mux = m.group("mux")
    is_multiplexer = mux == "M"
    mux_ids: Optional[List[int]] = None
    if mux and mux.startswith("m") and mux[1:].isdigit():
        mux_ids = [int(mux[1:])]
    receivers = [r for r in re.split(r"[,\s]+", m.group("rx").strip()) if r]
    factor = m.group("factor")
    offset = m.group("offset")
    return Signal(
        name=m.group("name"),
        start=int(m.group("start")),
        length=int(m.group("length")),
        byte_order="big_endian" if m.group("order") == "0" else "little_endian",
        is_signed=m.group("sign") == "-",
        # Omitted (factor,offset) means the raw integer is the physical value.
        factor=float(factor) if factor is not None else 1.0,
        offset=float(offset) if offset is not None else 0.0,
        minimum=_num(m.group("min") or ""),
        maximum=_num(m.group("max") or ""),
        unit=m.group("unit"),
        receivers=receivers,
        is_multiplexer=is_multiplexer,
        multiplexer_ids=mux_ids,
    )


def parse_file(path: str) -> Database:
    """Parse a DBC file from disk."""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return Database.parse(fh.read(), source=path)
