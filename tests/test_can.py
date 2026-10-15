from vehsec.can_bus import CanBus, Frame, analyze, parse_candump


def test_parse_candump_with_timestamp():
    from pathlib import Path

    p = Path(__file__).parent / "_tmp_candump.log"
    p.write_text(
        "(123.456789) vcan0 1A4#0102\n"
        "(124.000000) vcan0 19B#00FF\n"
        "garbage line without hash\n",
        encoding="utf-8",
    )
    frames = parse_candump(str(p))
    p.unlink()
    assert len(frames) == 2
    assert frames[0].arbitration_id == 0x1A4
    assert frames[0].data == b"\x01\x02"
    assert frames[1].arbitration_id == 0x19B
    assert frames[1].data == b"\x00\xff"


def test_frame_to_message_roundtrip():
    f = Frame(0x7E0, b"\x02\x10\x01", is_extended_id=False)
    msg = f.to_message()
    assert msg.arbitration_id == 0x7E0
    assert bytes(msg.data) == b"\x02\x10\x01"
    back = Frame.from_message(msg)
    assert back.arbitration_id == f.arbitration_id and back.data == f.data


def test_analyze_identifies_the_control_signal():
    # 0x1A4 changes every frame (candidate control/status signal); 0x19B is static
    frames = [Frame(0x1A4, bytes([i, 0x00])) for i in range(10)]
    frames += [Frame(0x19B, b"\x00\x00") for _ in range(10)]
    stats = analyze(frames)
    assert stats["0x1A4"]["count"] == 10
    assert stats["0x1A4"]["unique"] == 10
    assert 0 in stats["0x1A4"]["changing"], "byte 0 changes -> signal candidate"
    assert stats["0x19B"]["unique"] == 1
    assert stats["0x19B"]["changing"] == [], "static frame has no changing bytes"


def test_analyze_sorts_by_frequency():
    frames = [Frame(0x100, b"\x01")] + [Frame(0x200, b"\x02")] * 5
    assert list(analyze(frames))[0] == "0x200"


def test_fuzz_yields_requested_count():
    from vehsec.can_bus import CanBus

    bus = CanBus()  # virtual interface, no hardware needed
    frames = list(bus.fuzz([0x1A4], rounds=7, mutate=True, seed=42))
    bus.shutdown()
    assert len(frames) == 7
    assert all(f.arbitration_id == 0x1A4 and len(f.data) == 8 for f in frames)
