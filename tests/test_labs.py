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


@pytest.mark.parametrize("name", sorted(LABS))
def test_lab_solver_runs_and_passes(name):
    script = ROOT / "labs" / name / "solve.py"
    assert script.exists(), f"missing lab script: {script}"
    proc = subprocess.run(
        [sys.executable, str(script), *LABS[name]],
        cwd=script.parent, capture_output=True, text=True,
    )
    assert proc.returncode == 0, f"{name} failed:\n{proc.stderr}"
    assert "OK" in proc.stdout, f"{name} did not report OK:\n{proc.stdout}"
