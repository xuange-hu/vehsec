import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_demo_script_runs_end_to_end():
    """The README demo must run clean on the virtual bus (it gets recorded)."""
    script = ROOT / "examples" / "demo.py"
    assert script.exists()
    proc = subprocess.run(
        [sys.executable, str(script)], cwd=ROOT, capture_output=True, text=True,
    )
    assert proc.returncode == 0, f"demo failed:\n{proc.stdout}\n{proc.stderr}"
    assert "OK" in proc.stdout
    # every stage should have produced output
    for stage in ("Step 1", "Step 3"):
        assert stage in proc.stdout
