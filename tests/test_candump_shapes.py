"""candump 解析：扩展帧、CAN FD、远程帧一个都不能静默丢。

旧实现是 `int(cid_str, 16)` 包在 `except ValueError: continue` 里，于是：

    1FDBFFF4x#...   29 位 ID 带 `x` 后缀 → int() 抛错 → 整帧丢弃
    123##1CC...     FD 的 `##` 前缀      → fromhex 抛错 → 整帧丢弃

一份 5 帧的日志会读回 2 帧，而且不警告。对"重放/分析总线流量"这个
功能，缺帧比报错危险得多：带洞的重放看起来像成功的重放。
"""

from __future__ import annotations

from pathlib import Path

import pytest

from vehsec.can_bus import parse_candump, parse_candump_report


def _log(tmp_path: Path, body: str) -> str:
    p = tmp_path / "candump.log"
    p.write_text(body, encoding="utf-8")
    return str(p)


def test_extended_id_with_x_suffix_is_kept(tmp_path):
    path = _log(tmp_path, "(1.0) can0 1FDBFFF4x#DEADBEEF0102030405060708\n")
    frames, skipped = parse_candump_report(path)
    assert not skipped
    assert len(frames) == 1
    assert frames[0].arbitration_id == 0x1FDBFFF4
    assert frames[0].is_extended_id is True
    assert frames[0].data == bytes.fromhex("DEADBEEF0102030405060708")


def test_can_fd_double_hash_is_kept(tmp_path):
    # candump 用 `%X` 打印 socketcan 的 fd flags（CANFD_BRS/ESI），
    # 取值 0..3，所以 `##` 后面恰好一个十六进制字符。
    path = _log(tmp_path, "(1.0) can0 123##1112233445566778899AABBCCDD\n")
    frames, skipped = parse_candump_report(path)
    assert not skipped
    assert frames[0].arbitration_id == 0x123
    assert frames[0].data == bytes.fromhex("112233445566778899AABBCCDD")


def test_remote_frame_is_zero_length(tmp_path):
    path = _log(tmp_path, "(1.0) can0 123#R\n")
    frames, skipped = parse_candump_report(path)
    assert not skipped
    assert frames[0].data == b""


def test_all_five_real_shapes_round_trip(tmp_path):
    path = _log(
        tmp_path,
        "(1) can0 123#1122334455667788\n"
        "(2) can0 1FDBFFF4x#DEADBEEF0102030405060708\n"
        "(3) can0 18DAF110#0201FF00AA\n"
        "(4) can0 123##1112233445566778899AABBCCDD\n"
        "(5) can0 123#R\n",
    )
    frames, skipped = parse_candump_report(path)
    assert skipped == [], f"没有理由丢帧: {skipped}"
    assert len(frames) == 5
    assert [f.arbitration_id for f in frames] == [0x123, 0x1FDBFFF4, 0x18DAF110, 0x123, 0x123]
    assert [f.is_extended_id for f in frames] == [False, True, True, False, False]


def test_bad_line_is_reported_not_swallowed(tmp_path):
    path = _log(tmp_path, "(1) can0 123#ZZZ\n")
    frames, skipped = parse_candump_report(path)
    assert frames == []
    assert len(skipped) == 1
    assert "not valid hex" in skipped[0]


def test_classic_frame_over_eight_bytes_is_rejected(tmp_path):
    path = _log(tmp_path, "(1) can0 123#00112233445566778899\n")
    frames, skipped = parse_candump_report(path)
    assert frames == []
    assert any("max 8" in reason for reason in skipped)


def test_parse_candump_warns_on_stderr(tmp_path, capsys):
    """向后兼容的入口必须在丢行时说话，而不是安静返回。"""
    path = _log(tmp_path, "(1) can0 123#GG\n(2) can0 124#01\n")
    frames = parse_candump(path)
    assert len(frames) == 1
    assert "skipped 1" in capsys.readouterr().err


def test_id_outside_29_bits_is_rejected(tmp_path):
    path = _log(tmp_path, "(1) can0 3FFFFFFF#01\n")
    frames, skipped = parse_candump_report(path)
    assert frames == []
    assert any("29 bits" in reason for reason in skipped)