# Contributing

Thanks for helping improve `vehsec`. This project targets **authorized security
research and education** — please keep contributions within that scope.

## Dev setup

```bash
git clone https://github.com/xuange-hu/vehsec
cd vehsec
python -m venv .venv && source .venv/bin/activate
pip install -e ".[all]"        # core + CLI + TUI + MCP
pip install pytest ruff
```

## Run the checks (must pass before PR)

```bash
pytest -q                                    # 220 tests: core, CLI, MCP, all 5 labs
ruff check src tests --select=E9,F63,F7,F82  # syntax / undefined names
python labs/v2x-ecdsa-nonce/solve.py --gen 20 --reuse
```

## Code style

- Python 3.10+, `from __future__ import annotations` where helpful.
- Optional third-party imports (`isotp`, `udsoncan`, `ecdsa`, `mcp`, `textual`)
  must be **guarded** so `import vehsec` works without them.
- Every new MCP tool needs a docstring — agents read it to decide when to call.
- Every new capability should be exposed in **all three** surfaces: core lib,
  CLI, and MCP server (that's the project's whole point).

## Adding a lab

1. Create `labs/<name>/` with `README.md` (scenario + solution), `solve.py`
   (runnable, asserts success, prints `OK`), `Dockerfile`, `docker-compose.yml`.
2. Prefer stdlib-only; if you need a dep, install it in the Dockerfile.
3. Add it to `labs/README.md` and to `tests/test_labs.py` (it runs in CI).

## Adding a Seed-Key algorithm

```python
from vehsec import seedkey
seedkey.register("vendor_x", lambda s: bytes(b ^ 0x5A for b in s))
```

Only contribute algorithms you are legally allowed to publish. Do not contribute
code whose sole purpose is bypassing paid / geo-restricted content.

## Legal

All contributions must be for authorized research, teaching, or testing on
equipment you own. The MIT license applies; misuse is the user's responsibility.
