"""A fresh clone must be able to run `pytest` with nothing installed.

These repos use a ``src/`` layout, so on a contributor's machine the package
is not importable unless something puts ``src/`` on ``sys.path`` — that is
what the root ``conftest.py`` does. CI never catches it disappearing because
CI runs ``pip install -e .`` first: vehsec only worked here because it happened to be pip-installed,
which is exactly how the problem stays invisible.
"""

from __future__ import annotations

import os
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_root_conftest_bootstraps_src():
    path = os.path.join(REPO_ROOT, "conftest.py")
    assert os.path.isfile(path), "the root conftest.py is what makes plain `pytest` work after a clone"
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    assert "sys.path" in text and "src" in text


def test_pytest_collects_without_the_package_installed():
    # PYTHONPATH is the other way this can accidentally pass; strip it so the
    # check only exercises the conftest bootstrap.
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "tests", "--collect-only", "-q", "-o", "addopts="],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        check=False,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    out = proc.stdout + proc.stderr
    assert proc.returncode == 0, out
    assert "::" in proc.stdout, out
