import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


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
