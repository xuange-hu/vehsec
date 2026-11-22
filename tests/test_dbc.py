from pathlib import Path

import pytest

from vehsec import dbc

DBC_PATH = Path(__file__).resolve().parent.parent / "examples" / "sample.dbc"

DBC_TEXT = DBC_PATH.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def db():
    return dbc.Database.parse(DBC_TEXT)


# --------------------------------------------------------------------------- #
# parsing
# --------------------------------------------------------------------------- #
def test_parses_all_messages(db):
    assert len(db) == 3
    assert {m.name for m in db} == {"VehicleSpeed", "EngineData", "BodyControl"}


def test_message_metadata(db):
    msg = db.message(0x100)
    assert msg.name == "VehicleSpeed"
    assert msg.frame_id == 0x100
    assert msg.length == 8
    assert msg.sender == "ECM"
    assert msg.is_extended is False


def test_lookup_by_name_and_hex_string(db):
    assert db.message("EngineData") is db.message(260)
    assert db.message("0x104") is db.message(260)


def test_unknown_message_raises_keyerror(db):
    with pytest.raises(KeyError):
        db.message(0xDEAD)


def test_signal_attributes(db):
    speed = db.message(0x100).signal("Speed")
    assert speed.start == 0 and speed.length == 16
    assert speed.byte_order == "little_endian"
    assert speed.factor == 0.1 and speed.offset == 0.0
    assert speed.unit == "km/h"
    assert speed.is_signed is False


def test_motorola_and_signed_flagged(db):
    torque = db.message(260).signal("Torque")
    assert torque.byte_order == "big_endian"
    assert torque.is_big_endian is True
    assert torque.is_signed is True


def test_value_tables_parsed(db):
    head = db.message(512).signal("Headlights")
    assert head.values == {0: "Off", 1: "Parking", 2: "LowBeam", 3: "HighBeam"}


def test_comments_parsed(db):
    assert "every 100 ms" in db.message(256).comment
    assert "not GPS" in db.message(256).signal("Speed").comment


def test_signal_without_factor_offset_defaults_to_identity():
    # Real-world DBCs often omit (factor,offset); raw integer must pass through.
    text = 'BO_ 1 Minimal: 2 ECU\n SG_ Raw : 0|8@1+ [0|255] ""  RX\n'
    sig = dbc.Database.parse(text).message(1).signal("Raw")
    assert sig.factor == 1.0 and sig.offset == 0.0
    assert sig.physical_value(b"\x2a") == 42


def test_signal_without_min_max_block():
    text = 'BO_ 2 NoRange: 1 ECU\n SG_ V : 0|8@1+ (2,0) ""  RX\n'
    sig = dbc.Database.parse(text).message(2).signal("V")
    assert sig.minimum == 0.0 and sig.maximum == 0.0
    assert sig.physical_value(b"\x03") == 6


def test_search_finds_by_signal_name(db):
    assert [m.name for m in db.search("wiper")] == ["BodyControl"]


def test_parse_file_helper():
    database = dbc.parse_file(str(DBC_PATH))
    assert len(database) == 3
    assert database.source == str(DBC_PATH)


# --------------------------------------------------------------------------- #
# decoding
# --------------------------------------------------------------------------- #
def test_decode_intel_16bit_and_scaling(db):
    # Speed raw 415 * 0.1 = 41.5 km/h ; Odometer raw 12345 * 0.1 = 1234.5 km
    data = bytes([0x9F, 0x01, 0x39, 0x30, 0x00, 0x01, 0x00, 0x00])
    values = db.decode(0x100, data)
    assert values["Speed"] == pytest.approx(41.5)
    assert values["Odometer"] == pytest.approx(1234.5)
    assert values["SpeedValid"] == 1


def test_decode_motorola_signed(db):
    # RPM 3000*0.25 = 750 rpm ; Torque raw 0xFF9C = -100 -> -10.0 Nm (Motorola)
    data = bytes([0xB8, 0x0B, 0x5A, 0x80, 0xFF, 0x9C, 0x00, 0x00])
    values = db.decode(260, data)
    assert values["RPM"] == pytest.approx(750.0)
    assert values["CoolantTemp"] == 50.0  # raw 90, offset -40
    assert values["Throttle"] == pytest.approx(50.196, abs=1e-2)
    assert values["Torque"] == pytest.approx(-10.0)


def test_decode_raw_skips_scaling(db):
    data = bytes([0x9F, 0x01, 0x39, 0x30, 0x00, 0x01, 0x00, 0x00])
    values = db.decode(0x100, data, scaled=False)
    assert values["Speed"] == 415
    assert values["Odometer"] == 12345


def test_value_table_renders_enum_as_text(db):
    data = bytes([0x51, 0x02, 0x00, 0x00])
    assert db.decode(512, data)["Headlights"] == "LowBeam"


def test_value_table_can_be_disabled(db):
    data = bytes([0x51, 0x02, 0x00, 0x00])
    assert db.decode(512, data, apply_value_tables=False)["Headlights"] == 2


def test_multiplexed_signals_are_selected_by_switch(db):
    # Mode == 1 -> only the m1 signal (WiperSpeed) is decoded
    values = db.decode(512, bytes([0x51, 0x02, 0x00, 0x00]),
                       scaled=False, apply_value_tables=False)
    assert values["Mode"] == 1
    assert values["WiperSpeed"] == 5
    assert "DoorsLocked" not in values


def test_multiplexer_switch_zero_selects_m0(db):
    values = db.decode(512, bytes([0x10, 0x00, 0x00, 0x00]),
                       scaled=False, apply_value_tables=False)
    assert values["Mode"] == 0
    assert values["DoorsLocked"] == 1
    assert "WiperSpeed" not in values


def test_multiplexer_switch_uses_its_value_table(db):
    values = db.decode(512, bytes([0x51, 0x02, 0x00, 0x00]))
    assert values["Mode"] == "Wiper"  # from VAL_ 512 Mode 1 "Wiper"


def test_short_frame_raises_decode_error(db):
    with pytest.raises(dbc.DecodeError):
        db.decode(260, b"\x01\x02")


# --------------------------------------------------------------------------- #
# encoding
# --------------------------------------------------------------------------- #
def test_encode_intel_signal(db):
    payload = db.message(0x100).encode({"Speed": 41.5})
    assert payload[:2] == bytes([0x9F, 0x01])


def test_encode_motorola_signed_signal(db):
    payload = db.message(260).encode({"Torque": -10.0})
    assert payload[4:6] == bytes([0xFF, 0x9C])


def test_encode_then_decode_roundtrip(db):
    payload = db.message(0x100).encode({"Speed": 88.8, "Odometer": 1234.5, "SpeedValid": 1})
    back = db.decode(0x100, payload)
    assert back["Speed"] == pytest.approx(88.8)
    assert back["Odometer"] == pytest.approx(1234.5)
    assert back["SpeedValid"] == 1


def test_encode_out_of_range_raises(db):
    with pytest.raises(dbc.DecodeError):
        db.message(512).signal("WiperSpeed").encode_raw(99)


def test_unknown_signal_raises(db):
    with pytest.raises(KeyError):
        db.message(0x100).signal("Nope")


# --------------------------------------------------------------------------- #
# bit-position correctness (the classic DBC footgun)
# --------------------------------------------------------------------------- #
def test_intel_positions_are_lsb_first_in_signal_order():
    from vehsec.dbc import _bit_positions

    # 16-bit Intel at start 0: MSB of the signal is bit 15, LSB is bit 0
    bits = _bit_positions(0, 16, big_endian=False)
    assert bits[0] == 15 and bits[-1] == 0


def test_motorola_positions_wrap_to_next_byte_msb():
    from vehsec.dbc import _bit_positions

    bits = _bit_positions(0, 16, big_endian=True)
    assert bits[0] == 7          # MSB of byte 0
    assert bits[8] == 15         # wraps to MSB of byte 1


def test_motorola_byte2_start():
    from vehsec.dbc import _bit_positions

    bits = _bit_positions(16, 16, big_endian=True)
    assert bits[0] == 23 and bits[8] == 31


def test_motorola_start_bit_matches_cantools_oracle():
    """Pin the sawtooth mapping against cantools' reference implementation.

    cantools' ``start_bit()`` (src/cantools/database/utils.py) is literally
    ``8 * (start // 8) + (7 - start % 8)`` for big_endian signals, and
    ``start`` unchanged for little-endian ones. A 2026-11-18 audit reported
    this mapping as "mirrored" and a CRITICAL on the strength of a hand-computed
    expectation; the oracle above says the shipped mapping is correct. Keeping
    the oracle in-tree stops that false positive from being "fixed" later.
    """
    from vehsec.dbc import _bit_positions

    for start in (0, 3, 7, 8, 16, 23, 32):
        oracle = 8 * (start // 8) + (7 - start % 8)
        assert _bit_positions(start, 1, big_endian=True)[0] == oracle
        assert _bit_positions(start, 1, big_endian=False)[0] == start


def test_motorola_zero_start_is_plain_big_endian():
    """``0|16@0+`` must be the big-endian integer in bytes 0-1."""
    from vehsec.dbc import Signal

    sig = Signal(name="be", start=0, length=16, byte_order="big_endian", is_signed=False)
    assert sig.raw_value(b"\x12\x3c") == 0x123C
    assert sig.raw_value(b"\xff\xfe") == 0xFFFE


def test_motorola_msb_anchored_seven_needs_third_byte():
    """``7|16@0+`` legitimately walks into byte 2 — that is not a bug.

    With the sawtooth numbering, start bit 7 is the *least* significant bit of
    byte 0, so a 16-bit Motorola signal from there ends in the MSB of byte 2.
    """
    from vehsec.dbc import DecodeError, Signal

    sig = Signal(name="be7", start=7, length=16, byte_order="big_endian", is_signed=False)
    with pytest.raises(DecodeError):
        sig.raw_value(b"\x12\x3c")
    # One more byte and the signal resolves: byte0 bit0, then byte1 MSB-first,
    # then byte2 bits 7..1 — i.e. 0b0_00111100_0000000 == 0x1E00.
    assert sig.raw_value(b"\x12\x3c\x00") == 0x1E00


def test_full_byte_is_endianness_agnostic():
    from vehsec.dbc import Signal

    data = b"\xAB"
    for order in ("little_endian", "big_endian"):
        s = Signal(name="x", start=0, length=8, byte_order=order, is_signed=False)
        assert s.raw_value(data) == 0xAB


def test_summary_is_json_serialisable(db):
    import json

    assert json.loads(json.dumps(db.summary()))[0]["id"] == "0x100"


# --------------------------------------------------------------------------- #
# attributes (BA_DEF_ / BA_DEF_DEF_ / BA_) and signal groups (SIG_GROUP_)
# --------------------------------------------------------------------------- #
ATTR_DBC = """
BO_ 260 EngineData: 8 ECM
 SG_ RPM : 0|16@1+ (1,0) [0|8000] "rpm" TCM
 SG_ Temp : 16|8@1+ (1,-40) [-40|215] "degC" TCM

BA_DEF_ BO_ "MsgCycleTime" INT 0 10000;
BA_DEF_ SG_ "GenSigStartValue" FLOAT 0 100000;
BA_DEF_ SG_ "GenSigSendType" ENUM "Cyclic","OnWrite","OnChange";
BA_DEF_ BU_ "NodeLayer" STRING;
BA_DEF_ "DBName" STRING;
BA_DEF_DEF_ "MsgCycleTime" 100;
BA_DEF_DEF_ "GenSigStartValue" 0;
BA_DEF_DEF_ "GenSigSendType" 0;
BA_DEF_DEF_ "DBName" "unnamed";
BA_ "MsgCycleTime" BO_ 260 20;
BA_ "GenSigStartValue" SG_ 260 RPM 800;
BA_ "GenSigSendType" SG_ 260 Temp 2;
BA_ "NodeLayer" BU_ ECM "ASAM-OFFSET";
BA_ "DBName" "Powertrain";
SIG_GROUP_ 260 PowerGroup 1 : RPM Temp;
"""


@pytest.fixture(scope="module")
def adb():
    return dbc.Database.parse(ATTR_DBC)


def test_ba_def_ranges(adb):
    cycle = adb.attribute_defs["MsgCycleTime"]
    assert cycle.value_type == "INT" and cycle.minimum == 0 and cycle.maximum == 10000
    assert cycle.object_type == "BO_"


def test_ba_def_enum_values(adb):
    send = adb.attribute_defs["GenSigSendType"]
    assert send.value_type == "ENUM"
    assert send.enum_values == ["Cyclic", "OnWrite", "OnChange"]


def test_ba_def_string_has_no_range(adb):
    name = adb.attribute_defs["DBName"]
    assert name.value_type == "STRING" and name.minimum is None and name.maximum is None


def test_ba_assignment_on_message(adb):
    assert adb.message(260).attributes["MsgCycleTime"] == 20
    assert adb.attribute("MsgCycleTime", "BO_", 260) == 20


def test_ba_assignment_on_signal(adb):
    rpm = adb.message(260).signal("RPM")
    assert rpm.attributes["GenSigStartValue"] == 800.0
    assert isinstance(rpm.attributes["GenSigStartValue"], float)


def test_ba_enum_index_resolved_to_name(adb):
    temp = adb.message(260).signal("Temp")
    assert temp.attributes["GenSigSendType"] == "OnChange"


def test_ba_assignment_on_node_and_network(adb):
    assert adb.node_attributes["ECM"]["NodeLayer"] == "ASAM-OFFSET"
    assert adb.network_attributes["DBName"] == "Powertrain"


def test_attribute_falls_back_to_default(adb):
    # No BA_ assignment for MsgCycleTime on message 0x42 -> BA_DEF_DEF_ value.
    assert adb.attribute("MsgCycleTime", "BO_", 0x42) == 100
    assert adb.attribute("GenSigSendType", "SG_", 260, "RPM") == "Cyclic"


def test_attribute_unknown_returns_none(adb):
    assert adb.attribute("NoSuchAttribute") is None


def test_ba_assignment_before_definition_is_order_independent():
    text = (
        'BA_ "MsgCycleTime" BO_ 260 20;\n'
        'BA_DEF_ BO_ "MsgCycleTime" INT 0 10000;\n'
        "BO_ 260 EngineData: 8 ECM\n"
    )
    parsed = dbc.Database.parse(text)
    assert parsed.message(260).attributes["MsgCycleTime"] == 20


def test_ba_int_and_hex_coercion():
    text = (
        'BA_DEF_ "Flags" HEX 0 255;\nBA_DEF_ "Count" INT 0 9;\n'
        'BA_ "Flags" 12;\nBA_ "Count" 3;\n'
    )
    parsed = dbc.Database.parse(text)
    assert parsed.network_attributes == {"Flags": 12, "Count": 3}


def test_unassigned_definition_is_kept(adb):
    text = ATTR_DBC + 'BA_DEF_ SG_ "Unused" INT 0 1;\n'
    parsed = dbc.Database.parse(text)
    assert parsed.attribute_defs["Unused"].value_type == "INT"
    assert parsed.attribute("Unused") is None


def test_sig_group_parsing(adb):
    groups = adb.groups_for_message(260)
    assert len(groups) == 1
    group = groups[0]
    assert group.name == "PowerGroup" and group.repetitions == 1
    assert group.signal_names == ["RPM", "Temp"]


def test_sig_group_attaches_to_message(adb):
    msg = adb.message(260)
    assert [g.name for g in msg.signal_groups] == ["PowerGroup"]
    assert msg.to_dict()["signal_groups"] == ["PowerGroup"]


def test_sig_group_resolves_by_name(adb):
    assert adb.groups_for_message("EngineData")[0].name == "PowerGroup"


def test_sig_group_on_unknown_message_is_kept():
    parsed = dbc.Database.parse("SIG_GROUP_ 999 Orphans 1 : A B;\n")
    assert parsed.signal_groups[0].message_id == 999
    assert parsed.signal_groups[0].signal_names == ["A", "B"]
