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


# --------------------------------------------------------------------------- #
# curated list structure (awesome-vehicle-security.md)
# --------------------------------------------------------------------------- #
AWESOME = ROOT / "awesome-vehicle-security.md"


def test_awesome_list_anchor_links_resolve():
    """Every ``- [name](#anchor)`` in Contents must match a real heading.

    The list shipped with a Contents block that had drifted from the headings,
    so two anchors scrolled nowhere.
    """
    import re

    text = AWESOME.read_text(encoding="utf-8")
    headings = {
        re.sub(r"[^a-z0-9 -]", "", h.lower()).replace(" ", "-").strip("-")
        for h in re.findall(r"^##+ (.+)$", text, re.MULTILINE)
    }
    anchors = re.findall(r"^- \[[^\]]+\]\(#([^)]+)\)$", text, re.MULTILINE)
    assert anchors, "Contents block is missing"
    missing = [a for a in anchors if a not in headings]
    assert not missing, f"anchors with no heading: {missing}"


def test_awesome_list_sections_are_not_empty():
    """A section heading with no entries reads as an abandoned project."""
    import re

    text = AWESOME.read_text(encoding="utf-8")
    sections = re.split(r"^## ", text, flags=re.MULTILINE)[1:]
    thin = []
    for block in sections:
        title, _, body = block.partition("\n")
        entries = [ln for ln in body.splitlines() if ln.startswith("- ")]
        if len(entries) < 3:
            thin.append((title.strip(), len(entries)))
    assert not thin, f"sections with fewer than 3 entries: {thin}"


def test_awesome_list_entries_have_descriptions():
    """Every entry follows ``- [name](url) — description``.

    The optional ``(★)`` popularity marker sits between the link and the dash,
    and in-repo entries use relative paths, so both shapes are allowed.
    """
    import re

    text = AWESOME.read_text(encoding="utf-8")
    bad = []
    for line in text.splitlines():
        if not line.startswith("- [") or "](#" in line:
            continue
        link = r"\[[^\]]+\]\((?:https?://|labs/)[^)]*\)"
        if not re.match(rf"^- {link}(\s+\([^)]*★[^)]*\))?\s+—\s+\S", line):
            bad.append(line[:90])
    assert not bad, f"entries without a description: {bad}"


def test_awesome_list_has_no_dead_placeholders():
    """Catch the failure mode that actually bit: entries whose repo was deleted.

    The first draft carried ``EFeru/ICSim-docker``, ``IDontThinkLlama/ecu-toolkit``
    and ``uPwnLab/ecu-toolkit`` — three 404s, two of them belonging to accounts
    that no longer exist. Network checks live in ``scripts/check_links.py``
    (run by hand, since CI has no egress guarantees), so what can be pinned
    offline is the shape of the links themselves.
    """
    import re

    text = AWESOME.read_text(encoding="utf-8")
    urls = re.findall(r"\]\((https?://[^)]+)\)", text)
    for url in urls:
        assert " " not in url, f"URL contains a space: {url!r}"
        assert url.count("(") == url.count(")"), f"unbalanced parens in {url!r}"
    # A bare GitHub profile link is a smell: it usually replaced a dead repo.
    profiles = [u for u in urls if re.fullmatch(r"https://github\.com/[^/]+/?", u)]
    assert not profiles, f"entry points at a bare profile: {profiles}"


def test_awesome_list_covers_the_run_entry_point():
    """The list is a discovery surface for the toolkit; keep the link alive."""
    text = AWESOME.read_text(encoding="utf-8")
    assert "xuange-hu/vehsec" in text
    assert "labs/" in text
