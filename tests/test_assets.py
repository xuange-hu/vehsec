import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

# Everything a test, a README code block or a lab depends on at runtime.
ASSETS = [
    "examples/sample_candump.log",
    "examples/sample.dbc",
    "examples/demo.py",
    "examples/mcp-config.json",
    "examples/quickstart.md",
]


def _inside_work_tree() -> bool:
    probe = subprocess.run(
        ["git", "rev-parse", "--is-inside-work-tree"],
        capture_output=True, text=True, cwd=ROOT,
    )
    return probe.returncode == 0 and probe.stdout.strip() == "true"


@pytest.mark.skipif(not _inside_work_tree(), reason="not a git checkout")
def test_assets_are_committed_not_just_present():
    """A fixture exists on my disk and vanished in CI. Never again.

    `.gitignore` had `*.log`, so `examples/sample_candump.log` was never added:
    every local run passed, and every CI run died with FileNotFoundError. The
    only way to catch that class of bug is to ask git, not the filesystem --
    `Path.exists()` is true here and false on the runner.
    """
    for rel in ASSETS:
        assert (ROOT / rel).exists(), f"{rel} is referenced by the tests but missing locally"
        tracked = subprocess.run(
            ["git", "ls-files", "--error-unmatch", rel],
            capture_output=True, text=True, cwd=ROOT,
        )
        assert tracked.returncode == 0, (
            f"{rel} exists locally but git does not track it - it will be "
            f"absent from CI and from every fresh clone. Check .gitignore."
        )


def test_sample_candump_fixture_parses():
    from vehsec.can_bus import parse_candump

    frames = parse_candump(str(ROOT / "examples" / "sample_candump.log"))
    assert {f.arbitration_id for f in frames} == {0x1A4, 0x19B}
    assert len(frames) >= 40


def test_social_preview_renderer(tmp_path):
    """The GIF/social renderer must run headless (it also runs in CI/doc rebuilds)."""
    pytest.importorskip("PIL", reason="Pillow is required for the asset renderer")
    out = tmp_path / "social.png"
    r = subprocess.run(
        [sys.executable, str(ROOT / "examples" / "make_demo_gif.py"),
         "--social-only", "--social-out", str(out)],
        capture_output=True, text=True, cwd=ROOT,
    )
    assert r.returncode == 0, r.stderr
    assert out.exists() and out.stat().st_size > 1000

    from PIL import Image

    assert Image.open(out).size == (1280, 640)
