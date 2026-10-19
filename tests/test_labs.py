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
    "seedkey-recover": [],
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


def test_seedkey_lab_unlocks_with_unseen_seed():
    """The recovered algorithm must generalise beyond the observed pairs."""
    proc = _run("seedkey-recover")
    assert proc.returncode == 0, proc.stderr
    assert "FLAG{seedkey_recovered_from_5_pairs}" in proc.stdout
    # the searched algorithm is printed, and every observed pair still holds
    assert "rotl8(seed[i], 3) ^ 0xC7" in proc.stdout


def test_seedkey_lab_rejects_an_overfitted_candidate():
    """One observation of a uniform seed leaves several families alive."""
    proc = _run("seedkey-recover", "--pairs", "1")
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "invalidKey" in proc.stdout
    assert "overfitted" in proc.stdout


def test_seedkey_lab_confidence_grows_with_evidence():
    proc = _run("seedkey-recover", "--pairs", "3")
    assert proc.returncode == 0, proc.stderr
    assert "confidence = high" in proc.stdout


def test_labs_directory_lists_every_lab():
    index = (ROOT / "labs" / "README.md").read_text(encoding="utf-8")
    for name in LABS:
        assert f"labs/{name}" in index or f"]({name})" in index, (
            f"{name} is missing from labs/README.md"
        )


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
