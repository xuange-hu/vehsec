from vehsec import j1939


# --- 29-bit identifier ------------------------------------------------------ #
def test_decode_eec1_pdu2():
    d = j1939.decode_id(0x18F00400)
    assert d["priority"] == 6
    assert d["pgn"] == 0xF004
    assert d["pdu_type"] == "PDU2"          # PF = 0xF0 = 240 >= 240
    assert d["source"] == 0
    assert d["destination"] == 0xFF         # broadcast
    assert "EEC1" in d["label"]


def test_decode_request_pdu1():
    d = j1939.decode_id(0x18EA00F9)
    assert d["pgn"] == 0xEA00
    assert d["pdu_type"] == "PDU1"          # PF = 0xEA = 234 < 240
    assert d["destination"] == 0x00
    assert d["source"] == 0xF9
    assert "Request" in d["label"]


def test_encode_matches_known_ids():
    assert j1939.encode_id(0xF004, 0, priority=6) == 0x18F00400
    assert j1939.encode_id(0xEA00, 0xF9, priority=6, destination=0x00) == 0x18EA00F9


def test_encode_decode_roundtrip_pdu2():
    for pgn, sa, pri in ((0xF004, 0x00, 6), (0xFECA, 0x21, 7), (0xFEF1, 0x11, 3)):
        cid = j1939.encode_id(pgn, sa, priority=pri)
        d = j1939.decode_id(cid)
        assert d["pgn"] == pgn and d["source"] == sa and d["priority"] == pri


def test_encode_decode_roundtrip_pdu1():
    cid = j1939.encode_id(0xEA00, 0xF9, priority=6, destination=0x2B)
    d = j1939.decode_id(cid)
    assert d["pgn"] == 0xEA00
    assert d["destination"] == 0x2B
    assert d["source"] == 0xF9
    assert d["pdu_type"] == "PDU1"


def test_pgn_label_known_and_unknown():
    assert "DM1" in j1939.decode_id(0x18FECA00)["label"]
    assert j1939.decode_id(0x18F12300)["label"].startswith("unknown")


# --- NAME ------------------------------------------------------------------- #
def test_decode_name_fields():
    name = (
        0x12345                 # identity number (21 bits)
        | (0x1AB << 21)          # manufacturer code (11 bits, max 0x7FF)
        | (0x2 << 32)           # ECU instance (3)
        | (0x1 << 35)           # function instance (3)
        | (0x0F << 38)          # function (7)
        | (0x3 << 46)           # vehicle system (3)
        | (0x1 << 49)           # vehicle system instance (3)
        | (0x4 << 52)           # industry group (4)
        | (0x1 << 56)           # arbitrary address capable
    )
    d = j1939.decode_name(name)
    assert d["identity_number"] == 0x12345
    assert d["manufacturer_code"] == 0x1AB
    assert d["ecu_instance"] == 0x2
    assert d["function"] == 0x0F
    assert d["industry_group"] == 0x4
    assert d["arbitrary_address_capable"] is True


def test_manufacturer_code_is_eleven_bits():
    # the field is 11 bits wide; anything above 0x7FF cannot round-trip
    name = 0x7FF << 21
    assert j1939.decode_name(name)["manufacturer_code"] == 0x7FF


def test_decode_name_zero():
    d = j1939.decode_name(0)
    assert d["identity_number"] == 0
    assert d["arbitrary_address_capable"] is False
    assert d["name_hex"] == "0x0000000000000000"


# --- DTC / DM1 -------------------------------------------------------------- #
def test_decode_dtc_roundtrip():
    # spn 1234 (0x4D2), fmi 5, cm 1, oc 3
    b0 = 1234 & 0xFF                    # 0xD2
    b1 = (1234 >> 8) & 0xFF             # 0x04
    b2 = ((1234 >> 16) & 0x07) | (5 << 3)
    b3 = (1 << 7) | 3
    assert j1939.decode_dtc(b0, b1, b2, b3) == {"spn": 1234, "fmi": 5, "cm": 1, "oc": 3}


def test_decode_dm1_lamps_and_dtcs():
    data = bytes([0x02, 0x00, 0xD2, 0x04, 0x28, 0x83])
    res = j1939.decode_dm1(data)
    assert res["lamps"]["red_stop"] is True
    assert res["lamps"]["amber_warning"] is False
    assert res["dtc_count"] == 1
    assert res["dtcs"][0]["spn"] == 1234


def test_decode_dm1_no_dtcs():
    res = j1939.decode_dm1(bytes([0x00, 0x00]))
    assert res["dtc_count"] == 0
    assert not any(res["lamps"].values())


def test_decode_dm1_rejects_short_frame():
    import pytest

    with pytest.raises(ValueError):
        j1939.decode_dm1(bytes([0x00]))


# --- payload helpers -------------------------------------------------------- #
def test_engine_speed_scaling():
    # raw 0x1000 = 4096 -> 4096 * 0.125 = 512 rpm
    assert j1939.decode_engine_speed(bytes([0, 0, 0, 0x00, 0x10, 0, 0, 0])) == 512.0
    assert j1939.decode_engine_speed(bytes([0, 0, 0, 0, 0, 0, 0, 0])) == 0.0


def test_decode_with_payload_eec1():
    out = j1939.decode(0x18F00400, bytes([0xFF, 0xFF, 0xFF, 0x00, 0x10, 0xFF, 0xFF, 0xFF]))
    assert out["pgn"] == 0xF004
    assert out["engine_speed_rpm"] == 512.0


def test_decode_with_payload_dm1():
    out = j1939.decode(0x18FECA00, bytes([0x02, 0x00, 0xD2, 0x04, 0x28, 0x83]))
    assert out["diagnostic"]["dtc_count"] == 1


def test_decode_without_payload_has_no_payload_keys():
    out = j1939.decode(0x18F00400)
    assert "data" not in out and "engine_speed_rpm" not in out
