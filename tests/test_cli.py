import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("click", reason="click is required for CLI tests")

from click.testing import CliRunner  # noqa: E402

from vehsec.cli import cli  # noqa: E402


def test_help_lists_all_groups():
    r = CliRunner().invoke(cli, ["--help"])
    assert r.exit_code == 0, r.output
    for group in ("can", "uds", "seedkey", "v2x", "icsim", "j1939", "isotp", "mcp", "tui"):
        assert group in r.output, f"missing group {group}"


def test_isotp_segment_and_reassemble_commands():
    r = CliRunner().invoke(cli, ["isotp", "segment", "--data", "22F190"])
    assert r.exit_code == 0, r.output
    assert "0322F190" in r.output

    r = CliRunner().invoke(cli, ["isotp", "decode", "--frame", "0322F190"])
    assert r.exit_code == 0, r.output
    assert "SF" in r.output


def test_isotp_reassemble_command():
    # 20-byte payload: FF(total=0x14) + 6 bytes, then CF seq1(7) + CF seq2(7)
    frames = "1014000102030405,21060708090A0B0C,220D0E0F10111213"
    r = CliRunner().invoke(cli, ["isotp", "reassemble", "--frames", frames])
    assert r.exit_code == 0, r.output
    assert "000102030405060708090a0b0c0d0e0f10111213" in r.output.lower()


def test_j1939_decode_command():
    r = CliRunner().invoke(cli, ["j1939", "decode", "--id", "0x18F00400"])
    assert r.exit_code == 0, r.output
    assert "0xF004" in r.output and "EEC1" in r.output


def test_j1939_encode_command():
    r = CliRunner().invoke(cli, ["j1939", "encode", "--pgn", "0xF004", "--source", "0"])
    assert r.exit_code == 0, r.output
    assert "0x18F00400" in r.output


def test_j1939_dm1_command():
    r = CliRunner().invoke(cli, ["j1939", "dm1", "--data", "0200D2042883"])
    assert r.exit_code == 0, r.output
    assert "1234" in r.output


def test_seedkey_solve_command():
    r = CliRunner().invoke(cli, ["seedkey", "solve", "--vendor", "training_rotate", "--seed", "0102"])
    assert r.exit_code == 0, r.output
    assert "585e" in r.output


def test_seedkey_vendors_command():
    r = CliRunner().invoke(cli, ["seedkey", "vendors"])
    assert r.exit_code == 0, r.output
    assert "training_rotate" in r.output


def test_icsim_demo_runs_on_virtual_bus():
    r = CliRunner().invoke(cli, ["icsim", "demo", "--kmh", "250"])
    assert r.exit_code == 0, r.output
    assert "tamper" in r.output


def test_can_fuzz_runs_on_virtual_bus():
    r = CliRunner().invoke(cli, ["can", "fuzz", "--ids", "0x1A4", "--rounds", "3"])
    assert r.exit_code == 0, r.output
    assert "fuzzed" in r.output


def test_seedkey_predict_solves_an_unobserved_seed():
    """Recover from observations, then answer a fresh seed — the real workflow."""
    runner = CliRunner()
    r = runner.invoke(cli, ["seedkey", "predict",
                            "--pairs", "11223344:4B78691E,a5b6c7d8:FFEC9D82,"
                                       "deadbeeF:84F7E4B5",
                            "--seed", "00112233"])
    assert r.exit_code == 0, r.output
    assert "seed[i] ^ 0x5A" in r.output          # the recovered expression
    assert "5A4B7869" in r.output                # xor 0x5A applied to 00112233


def test_seedkey_predict_requires_exactly_one_source():
    runner = CliRunner()
    r = runner.invoke(cli, ["seedkey", "predict", "--seed", "00112233"])
    assert r.exit_code != 0
    assert "exactly one of --pairs or --file" in r.output
