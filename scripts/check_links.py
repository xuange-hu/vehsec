"""Check every external URL in a markdown file, in parallel, with retry.

Usage::

    python scripts/check_links.py awesome-vehicle-security.md

Exit code is 1 when any link returns a hard 4xx — i.e. the target is gone,
not merely slow or bot-blocked. ``403`` is reported separately because many
standards bodies block HEAD requests from scripts while serving browsers
normally; those are left to human review rather than failing the run.

Why this exists: the first version of the list carried three entries whose
repositories (and, in two cases, whole accounts) had been deleted. Dead links
are the fastest way to lose a visitor's trust, and eyeballing a list does not
catch them — a request does.
"""

from __future__ import annotations

import re
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

BOT_BLOCKED = (403, 405, 429)


def head(url: str, tries: int = 2) -> str:
    """Return an HTTP status as a string; '000' means no connection at all."""
    last = "000"
    for _ in range(tries):
        try:
            req = urllib.request.Request(
                url, method="HEAD", headers={"User-Agent": "Mozilla/5.0"}
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                return str(resp.status)
        except urllib.error.HTTPError as err:
            last = str(err.code)
            if err.code not in BOT_BLOCKED:
                return last
        except (urllib.error.URLError, TimeoutError, OSError):
            last = "000"
    return last


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2
    path = argv[1]
    text = open(path, encoding="utf-8").read()
    urls = sorted(set(re.findall(r"\((https?://[^)\s]+)\)", text)))

    with ThreadPoolExecutor(max_workers=10) as pool:
        results = list(pool.map(head, urls))

    ok = blocked = unreachable = dead = 0
    for url, code in zip(urls, results):
        if code.startswith(("2", "3")):
            ok += 1
            label = "ok"
        elif code == "000":
            unreachable += 1
            label = "unreachable"
        elif int(code) in BOT_BLOCKED:
            blocked += 1
            label = "bot-blocked"
        else:
            dead += 1
            label = "DEAD"
        print(f"{label:12s} {code:4s} {url}")

    print(
        f"\n{len(urls)} links: {ok} ok, {blocked} bot-blocked, "
        f"{unreachable} unreachable, {dead} dead"
    )
    return 1 if dead else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))