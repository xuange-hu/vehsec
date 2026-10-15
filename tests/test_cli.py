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
    for group in ("can", "uds", "seedkey", "v2x", "icsim", "j1939", "mcp", "tui"):
        assert group in r.output, f"missing group {group}"


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
