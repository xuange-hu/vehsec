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


def test_full_byte_is_endianness_agnostic():
    from vehsec.dbc import Signal

    data = b"\xAB"
    for order in ("little_endian", "big_endian"):
        s = Signal(name="x", start=0, length=8, byte_order=order, is_signed=False)
        assert s.raw_value(data) == 0xAB


def test_summary_is_json_serialisable(db):
    import json

    assert json.loads(json.dumps(db.summary()))[0]["id"] == "0x100"
