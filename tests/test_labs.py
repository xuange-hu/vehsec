import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
LABS = {
    "uds-did-decrypt": [],
    "delta-forge-patchchain": [],
    "v2x-ecdsa-nonce": ["--gen", "20", "--reuse"],
    "sentinel2-can-statemachine": [],
}


def _run(name, *args):
    script = ROOT / "labs" / name / "solve.py"
    assert script.exists(), f"missing lab script: {script}"
    return subprocess.run(
        [sys.executable, str(script), *args],
        cwd=script.parent, capture_output=True, text=True,
    )


@pytest.mark.parametrize("name", sorted(LABS))
def test_lab_solver_runs_and_passes(name):
    proc = _run(name, *LABS[name])
    assert proc.returncode == 0, f"{name} failed:\n{proc.stderr}"
    assert "OK" in proc.stdout, f"{name} did not report OK:\n{proc.stdout}"


def test_v2x_lab_is_reusable_out_of_the_box(tmp_path):
    """A first-time visitor must see the attack succeed without extra flags."""
    out = str(tmp_path / "sigs.json")           # never litter the lab directory
    proc = _run("v2x-ecdsa-nonce", "--gen", "20", "--out", out)
    assert proc.returncode == 0, proc.stderr
    assert "recovered private key" in proc.stdout
    assert "rerun with" not in proc.stdout


def test_v2x_lab_contrast_branch_reports_no_reuse(tmp_path):
    out = str(tmp_path / "sigs.json")
    proc = _run("v2x-ecdsa-nonce", "--gen", "20", "--no-reuse", "--out", out)
    assert proc.returncode == 0, proc.stderr
    assert "no nonce reuse found" in proc.stdout
    assert "recovered private key" not in proc.stdout
