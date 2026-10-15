"""J1939 — the heavy-duty vehicle protocol (trucks, buses, agriculture, marine).

Pure stdlib, no dependencies. Covers:

* 29-bit CAN identifier <-> PGN / priority / source address (PDU1 and PDU2),
* PGN label lookup for the common messages,
* NAME (64-bit) field decode (address-claimed / address-claim frames),
* DM1 (PGN 65226) diagnostic message decode into SPN/FMI/CM/OC,
* EEC1 (PGN 61444) engine speed decode.

Byte/bit layouts follow SAE J1939-21 (transport), J1939-71 (application) and
J1939-73 (diagnostics).
"""

from __future__ import annotations

# --- PGN labels: the ones you actually see in a capture ---------------------
PGN_LABELS = {
    0x0000: "Address Claimed / Cannot Claim (J1939-81)",
    0xE000: "Address Claimed (J1939-81)",
    0xEA00: "Request (J1939-21)",
    0xE800: "Acknowledgement (J1939-21)",
    0xEC00: "Transport Protocol - Connection Management (BAM/CTS)",
    0xEB00: "Transport Protocol - Data Transfer",
    0xF000: "Engine Temperature 1 (ET1)",
    0xF003: "Engine Fluid Level/Pressure 1 (EFL/P1)",
    0xF004: "Electronic Engine Controller 1 (EEC1)",
    0xF005: "Electronic Engine Controller 2 (EEC2)",
    0xFEF1: "Cruise Control/Vehicle Speed 1 (CCVS)",
    0xFEF2: "Fuel Consumption (LFC)",
    0xFEE5: "Engine Hours, Revolutions (HOURS)",
    0xFEE9: "Vehicle Distance (VD)",
    0xFECA: "Diagnostic Message 1 / DM1 (active DTCs)",
    0xFECB: "Diagnostic Message 2 / DM2 (previously active DTCs)",
    0xFECC: "Diagnostic Message 3 / DM3 (clear/reset)",
    0xFECD: "Diagnostic Message 4 / DM4 (freeze frame)",
    0xFEDF: "Electronic Brake Controller 1 (EBC1)",
    0xFE6C: "Torque/Speed Control 1 (TSC1)",
    0xFFFE: "Proprietary (PDU2 group extension used)",
}

PDU1_PF_MAX = 239  # PF < 240 => PDU1 (destination addressed)


def decode_id(can_id: int) -> dict:
    """Decode a 29-bit J1939 CAN identifier.

    Layout: priority(3) | PGN(18) | source address(8)
    For PDU1 (PF < 240) the low byte of the PGN field is the destination address;
    for PDU2 it is the group extension.
    """
    priority = (can_id >> 26) & 0x07
    pgn_field = (can_id >> 8) & 0x03FFFF
    sa = can_id & 0xFF
    pf = (pgn_field >> 8) & 0xFF
    ps = pgn_field & 0xFF

    if pf <= PDU1_PF_MAX:
        pdu = "PDU1"
        pgn = pgn_field & 0xFF00
        da = ps
        ge = None
    else:
        pdu = "PDU2"
        pgn = pgn_field
        da = 0xFF  # broadcast
        ge = ps

    return {
        "can_id": f"0x{can_id:08X}",
        "priority": priority,
        "pgn": pgn,
        "pgn_hex": f"0x{pgn:04X}",
        "pdu_format": pf,
        "pdu_type": pdu,
        "destination": da,
        "group_extension": ge,
        "source": sa,
        "label": PGN_LABELS.get(pgn, "unknown / proprietary"),
    }


def encode_id(pgn: int, source: int, priority: int = 6, destination: int = 0xFF) -> int:
    """Build a 29-bit J1939 CAN identifier.

    For PDU1 (PGN low byte == 0) ``destination`` is placed in the PS byte.
    """
    pf = (pgn >> 8) & 0xFF
    if pf <= PDU1_PF_MAX:
        ps = destination
        pgn_field = (pf << 8) | ps
    else:
        pgn_field = pgn  # low byte is the group extension
    return ((priority & 0x07) << 26) | ((pgn_field & 0x03FFFF) << 8) | (source & 0xFF)


def decode_name(name: int) -> dict:
    """Decode the 64-bit J1939 NAME (address-claim identity)."""
    return {
        "name_hex": f"0x{name:016X}",
        "identity_number": name & 0x1FFFFF,              # bits 0-20
        "manufacturer_code": (name >> 21) & 0x7FF,       # bits 21-31
        "ecu_instance": (name >> 32) & 0x07,             # bits 32-34
        "function_instance": (name >> 35) & 0x07,        # bits 35-37
        "function": (name >> 38) & 0x7F,                 # bits 38-44
        "vehicle_system": (name >> 46) & 0x07,           # bits 46-48
        "vehicle_system_instance": (name >> 49) & 0x07,  # bits 49-51
        "industry_group": (name >> 52) & 0x0F,           # bits 52-55
        "arbitrary_address_capable": bool((name >> 56) & 0x01),  # bit 56
    }


def decode_dtc(b0: int, b1: int, b2: int, b3: int) -> dict:
    """Decode one 4-byte J1939 DTC into SPN / FMI / CM / OC.

    Byte layout (J1939-73):
      b0,b1,b2[0:2] -> SPN (19 bits)
      b2[3:7]       -> FMI (5 bits)
      b3 bit 7      -> CM  (conversion method)
      b3[0:6]       -> OC  (occurrence count)
    """
    spn = b0 | (b1 << 8) | ((b2 & 0x07) << 16)
    fmi = (b2 >> 3) & 0x1F
    cm = (b3 >> 7) & 0x01
    oc = b3 & 0x7F
    return {"spn": spn, "fmi": fmi, "cm": cm, "oc": oc}


def decode_dm1(data: bytes) -> dict:
    """Decode a DM1 (PGN 65226) message: lamp status + active DTC list."""
    if len(data) < 2:
        raise ValueError("DM1 needs at least 2 bytes (lamp status)")
    lamp = data[0] | (data[1] << 8)
    lamps = {
        "malfunction_indicator": bool(lamp & (1 << 0)),
        "red_stop": bool(lamp & (1 << 1)),
        "amber_warning": bool(lamp & (1 << 2)),
        "protect": bool(lamp & (1 << 3)),
        "flash_malfunction": bool((lamp >> 8) & (1 << 0)),
        "flash_red_stop": bool((lamp >> 8) & (1 << 1)),
        "flash_amber": bool((lamp >> 8) & (1 << 2)),
        "flash_protect": bool((lamp >> 8) & (1 << 3)),
    }
    body = data[2:]
    dtcs = []
    for i in range(0, len(body) - 3, 4):
        dtcs.append(decode_dtc(*body[i:i + 4]))
    return {"lamps": lamps, "dtc_count": len(dtcs), "dtcs": dtcs}


def decode_engine_speed(data: bytes) -> float:
    """EEC1 (PGN 61444) engine speed: bytes 3-4, 0.125 rpm per bit."""
    if len(data) < 5:
        raise ValueError("EEC1 needs at least 5 bytes")
    raw = data[3] | (data[4] << 8)
    return raw * 0.125


def decode(can_id: int, data: bytes | None = None) -> dict:
    """Convenience: decode the id, and the payload when the PGN is known."""
    out = decode_id(can_id)
    if data is None:
        return out
    payload = bytes(data)
    out["data"] = payload.hex()
    try:
        if out["pgn"] == 0xF004:
            out["engine_speed_rpm"] = decode_engine_speed(payload)
        elif out["pgn"] in (0xFECA, 0xFECB):
            out["diagnostic"] = decode_dm1(payload)
        elif out["pgn"] in (0xEA00, 0xEE00):
            out["requested_pgn"] = f"0x{payload[0] | (payload[1] << 8) | (payload[2] << 16):06X}"
    except (ValueError, IndexError):
        pass
    return out
