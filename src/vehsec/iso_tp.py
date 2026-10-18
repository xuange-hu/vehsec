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


# --------------------------------------------------------------------------- #
# ASCII visualisation
# --------------------------------------------------------------------------- #
_FLOW_NAMES = {FLOW_CONTINUE: "CTS", FLOW_WAIT: "WAIT", FLOW_OVERFLOW: "OVFL"}
_FRAME_W = 8  # classic CAN data-field width

_PAD = "--"  # marker for bytes the frame does not use


def _hex_row(raw: bytes, width: int = _FRAME_W) -> str:
    cells = [f"{b:02X}" for b in raw[:width]]
    cells += [_PAD] * (width - len(cells))
    return " ".join(cells)


def _span(start: int, count: int) -> str:
    if count <= 0:
        return "-"
    return f"{start}..{start + count - 1}" if count > 1 else f"{start}"


def explain(frames: list[bytes], width: int = _FRAME_W) -> str:
    """Render an ISO-TP transfer as an ASCII diagram.

    This is the teaching asset: it shows, byte by byte, how a payload longer
    than 8 bytes is chopped into a First Frame plus Consecutive Frames, where
    the sequence numbers come from, and what the reassembled payload is.

    >>> print(explain(segment(bytes(range(20)))))
    """
    frames = [bytes(f) for f in frames]
    if not frames:
        raise ValueError("no frames to explain")

    rows: list[tuple[str, str, str, str]] = []   # idx, hexrow, kind, detail
    payload = bytearray()
    offset = 0
    total: int | None = None
    started = False

    for i, raw in enumerate(frames):
        d = decode(raw)
        kind = d["type"]
        if kind == "SF":
            data = d["data"]
            payload += data
            rows.append((str(i), _hex_row(raw, width), "SF",
                         f"len={d['length']} B — complete in one frame"))
            total = len(data)
            started = True
        elif kind == "FF":
            total = d["total"]
            data = d["data"]
            payload += data
            offset = len(data)
            rows.append((str(i), _hex_row(raw, width), "FF",
                         f"total={total} B, carries bytes {_span(0, len(data))}"))
            started = True
        elif kind == "CF":
            data = d["data"]
            payload += data
            rows.append((str(i), _hex_row(raw, width), "CF",
                         f"seq={d['seq']}, carries bytes {_span(offset, len(data))}"))
            offset += len(data)
        else:  # FC
            fs = d["flow_status"]
            rows.append((str(i), _hex_row(raw, width), "FC",
                         f"flow={_FLOW_NAMES.get(fs, fs)} block={d['block_size']} "
                         f"st_min={d['st_min']}"))

    n_payload = len(payload)
    title_total = total if total is not None else n_payload
    lines = [
        f"ISO-TP (ISO 15765-2) — {title_total}-byte payload "
        f"carried by {len(frames)} classic CAN frame(s)",
        "",
        f"  {'#':<3} {'frame bytes':<{width * 3 - 1}} PCI   kind  detail",
    ]
    for idx, hexrow, kind, detail in rows:
        pci = f"0x{int(hexrow.split()[0], 16):02X}" if not hexrow.startswith(_PAD) else "  -"
        lines.append(f"  {idx:<3} {hexrow:<{width * 3 - 1}} {pci:<5} {kind:<5} {detail}")

    lines.append("")
    if started and total is not None and n_payload >= total:
        body = payload[:total].hex().upper()
        # wrap the payload hex so long transfers stay readable
        per_line = width * 3
        chunks = [body[j:j + per_line] for j in range(0, len(body), per_line)] or ["(empty)"]
        lines.append("  reassembled payload:")
        for j, chunk in enumerate(chunks):
            prefix = "    " if j == 0 else "    "
            pretty = " ".join(chunk[k:k + 2] for k in range(0, len(chunk), 2))
            lines.append(f"{prefix}{pretty}")
        lines.append(f"    = {total} bytes")
    else:
        lines.append(
            f"  reassembled payload: INCOMPLETE — got {n_payload} of {total} bytes "
            "(missing consecutive frames?)"
        )
    return "\n".join(lines)


def explain_payload(data: bytes, width: int = _FRAME_W) -> str:
    """Segment ``data`` and render the resulting transfer as ASCII."""
    return explain(segment(data), width=width)
