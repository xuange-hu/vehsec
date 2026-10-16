"""ISO-TP (ISO 15765-2) — the transport layer that carries UDS over CAN.

Pure stdlib, no dependencies. Implements classic (8-byte) CAN segmentation:

    SF  single frame      PCI = 0x0 | length          (payload <= 7 bytes)
    FF  first frame       PCI = 0x1 | len_hi, len_lo  (payload 6 bytes, total <= 0xFFF)
    CF  consecutive frame PCI = 0x2 | seq             (payload 7 bytes, seq 1..15 then 0)
    FC  flow control      PCI = 0x3 | flow_status, block_size, st_min

This is the layer that lets you send a 200-byte UDS response over 8-byte CAN
frames. Useful on its own (sniffers, log analysis, crafting injections) and as
teaching material — it is what ``udsoncan``/``can-isotp`` do under the hood.
"""

from __future__ import annotations

SF, FF, CF, FC = 0, 1, 2, 3

MAX_SF = 7          # classic CAN: 8 bytes - 1 PCI byte
FF_DATA_BYTES = 6   # classic CAN: 8 - 2 PCI bytes
CF_DATA_BYTES = 7   # classic CAN: 8 - 1 PCI byte
MAX_TOTAL = 0xFFF   # 12-bit length field in the first frame

FLOW_CONTINUE, FLOW_WAIT, FLOW_OVERFLOW = 0, 1, 2


def encode_single_frame(data: bytes) -> bytes:
    """Single frame (SF): 0x0 | length, then up to 7 payload bytes."""
    data = bytes(data)
    if len(data) > MAX_SF:
        raise ValueError(f"single frame holds <= {MAX_SF} bytes, got {len(data)}")
    return bytes([(SF << 4) | len(data)]) + data


def encode_first_frame(data: bytes) -> bytes:
    """First frame (FF): 0x1 | len_hi, len_lo, then the first 6 payload bytes."""
    data = bytes(data)
    total = len(data)
    if total <= MAX_SF:
        raise ValueError("payload fits in a single frame; use encode_single_frame")
    if total > MAX_TOTAL:
        raise ValueError(f"ISO-TP classic supports <= {MAX_TOTAL} bytes, got {total}")
    pci = bytes([(FF << 4) | ((total >> 8) & 0x0F), total & 0xFF])
    return pci + data[:FF_DATA_BYTES]


def encode_consecutive_frame(chunk: bytes, seq: int) -> bytes:
    """Consecutive frame (CF): 0x2 | seq (1..15 then wrapping to 0)."""
    chunk = bytes(chunk)
    if len(chunk) > CF_DATA_BYTES:
        raise ValueError(f"consecutive frame holds <= {CF_DATA_BYTES} bytes")
    if not 0 <= seq <= 0x0F:
        raise ValueError("sequence number must fit in 4 bits")
    return bytes([(CF << 4) | (seq & 0x0F)]) + chunk


def encode_flow_control(flow_status: int = FLOW_CONTINUE,
                        block_size: int = 0, st_min: int = 0) -> bytes:
    """Flow control (FC): 0x3 | status, block size, separation time."""
    return bytes([(FC << 4) | (flow_status & 0x0F), block_size & 0xFF, st_min & 0xFF])


def decode(frame: bytes) -> dict:
    """Decode one ISO-TP frame into a dict (type, length/seq/flow fields, data)."""
    frame = bytes(frame)
    if not frame:
        raise ValueError("empty frame")
    pci = frame[0]
    ptype = pci >> 4

    if ptype == SF:
        length = pci & 0x0F
        return {"type": "SF", "length": length, "data": bytes(frame[1:1 + length])}
    if ptype == FF:
        if len(frame) < 2:
            raise ValueError("first frame needs 2 PCI bytes")
        total = ((pci & 0x0F) << 8) | frame[1]
        return {"type": "FF", "total": total, "data": bytes(frame[2:])}
    if ptype == CF:
        return {"type": "CF", "seq": pci & 0x0F, "data": bytes(frame[1:])}
    if ptype == FC:
        return {
            "type": "FC",
            "flow_status": pci & 0x0F,
            "block_size": frame[1] if len(frame) > 1 else 0,
            "st_min": frame[2] if len(frame) > 2 else 0,
        }
    raise ValueError(f"unknown PCI type 0x{ptype:X}")


def segment(data: bytes) -> list[bytes]:
    """Split a payload into ISO-TP frames (single frame, or FF + CFs)."""
    data = bytes(data)
    if len(data) <= MAX_SF:
        return [encode_single_frame(data)]
    frames = [encode_first_frame(data)]
    rest = data[FF_DATA_BYTES:]
    seq = 1
    for i in range(0, len(rest), CF_DATA_BYTES):
        frames.append(encode_consecutive_frame(rest[i:i + CF_DATA_BYTES], seq))
        seq = (seq + 1) & 0x0F
    return frames


def reassemble(frames: list[bytes]) -> bytes:
    """Reassemble a payload from ISO-TP frames, validating CF sequence numbers."""
    if not frames:
        raise ValueError("no frames to reassemble")
    first = decode(frames[0])
    if first["type"] == "SF":
        return first["data"]
    if first["type"] != "FF":
        raise ValueError("first frame must be SF or FF")

    total = first["total"]
    out = bytearray(first["data"])
    expected_seq = 1
    for raw in frames[1:]:
        d = decode(raw)
        if d["type"] == "FC":
            continue  # flow control carries no payload
        if d["type"] != "CF":
            raise ValueError(f"expected CF after FF, got {d['type']}")
        if d["seq"] != expected_seq:
            raise ValueError(
                f"CF sequence mismatch: expected {expected_seq}, got {d['seq']}"
            )
        out += d["data"]
        expected_seq = (expected_seq + 1) & 0x0F
        if len(out) >= total:
            break
    if len(out) < total:
        raise ValueError(f"incomplete: got {len(out)} of {total} bytes")
    return bytes(out[:total])


def describe(frames: list[bytes]) -> list[dict]:
    """Decode every frame of a capture into readable dicts (for log analysis)."""
    out = []
    for raw in frames:
        d = decode(raw)
        d["frame"] = bytes(raw).hex()
        out.append(d)
    return out
