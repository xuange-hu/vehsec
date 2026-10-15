# Changelog

All notable changes to `vehsec` are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/); versioning follows SemVer.

## [Unreleased] — v0.2.0

### Added
- `doip` — **DoIP / ISO 13400-2**, diagnostics over Ethernet:
  - Wire codec: 8-byte header, vehicle announcement (VIN / EID / GID), routing
    activation request+response, diagnostic-message framing, negative ack handling.
  - `DoipClient` — TCP connect, routing activation, UDS request/response, alive-check
    answers, ack skipping.
  - `DoipSimulator` — an **in-process DoIP entity** (UDP discovery + TCP UDS) so the
    whole protocol can be exercised offline. Backs `vehsec doip simulate`.
  - CLI: `vehsec doip discover|simulate|probe`. MCP: `doip_simulate`, `doip_probe`.
- `dbc` — **DBC parser, pure standard library** (no `cantools` / `canmatrix` needed):
  - `BO_` messages, `SG_` signals, `VAL_` value tables, `CM_` comments.
  - **Intel (little-endian) and Motorola (big-endian)** layouts, signed values,
    factor/offset scaling, and multiplexed signals (`M` / `mN`).
  - `decode()` / `encode()` at signal level, `search()`, JSON-safe `summary()`.
  - CLI: `vehsec dbc info|decode|encode|watch`. MCP: `dbc_decode`, `dbc_info`.
  - `examples/sample.dbc` — a 3-message fixture covering Intel, Motorola, signed,
    scaling, enums and multiplexing.
- CLI: `doip` and `dbc` command groups; `dbc decode|encode` report bad input as a
  clean click error instead of a traceback.
- 55 new tests (`tests/test_doip.py`, `tests/test_dbc.py`): 25 → **80 passing**.
- MCP tool count 9 → **13**.

### Fixed
- Intel (little-endian) signal extraction was mirrored: bit positions were produced
  LSB-first while the extraction loop expects MSB-first, so every `@1` signal decoded
  bit-reversed. Motorola was unaffected, which is why it hid behind the passing tests.
  Bit positions are now MSB-first for both byte orders.
- DBC signal regex required `(factor,offset)` and `[min|max]`; real-world DBC files
  routinely omit them, which silently dropped every such signal. Both are now optional
  and default to identity scaling.

## [0.1.0] — 2026-10-15

Initial public release. One core library, three surfaces (CLI / TUI / MCP), four
runnable labs — all running on a virtual CAN bus with no hardware required.

### Added

**Core library** (`src/vehsec/`)
- `can_bus` — send / receive / replay / fuzz, `candump` log parsing, and CAN ID
  discovery (per-ID counts, unique payloads, changing byte positions).
- `uds` — UDS client over ISO-TP (`udsoncan` + `can-isotp`): session control,
  security access (27), DID read/write, routine control, ECU reset.
- `seedkey` — pluggable Seed→Key algorithm registry for the UDS 27 handshake.
- `v2x` — ECDSA nonce-reuse detection and **private-key recovery**:
  `k = (z1-z2)(s1-s2)^-1`, `d = (s1k-z1)r^-1 mod n`.
- `icsim` — script the ICSim virtual cluster (speed / doors / turn / brake).

**Surfaces**
- CLI (`vehsec`, click + rich): `can`, `uds`, `seedkey`, `v2x`, `icsim` groups.
- TUI (`vehsec tui`, textual): interactive command prompt + streaming log.
- MCP server (`vehsec mcp`): 9 tools over stdio for Claude Code / Cursor / Cline.

**Learning resources**
- `awesome-vehicle-security.md` — curated list (tools, hardware, standards, CTF, talks).
- 4 Docker labs: `uds-did-decrypt`, `delta-forge-patchchain`, `v2x-ecdsa-nonce`,
  `sentinel2-can-statemachine`.

**Docs & infrastructure**
- `docs/playbook.md` — attack playbook with an ISO/SAE 21434 TARA mapping table.
- `docs/promotion.md` — ready-to-post launch copy (Show HN / PH / Reddit / X).
- `docs/architecture.svg` — architecture diagram.
- `scripts/setup_vcan.sh` — one-shot Linux lab (vcan0 + ICSim + UDSim).
- `examples/demo.py` — 5-step recordable scripted demo.
- 25 tests + GitHub Actions CI on Python 3.11 / 3.12 / 3.13.

### Fixed
- ISO-TP dependency: PyPI package is `can-isotp` (import name `isotp`), not `isotp`.
- `ecdsa.numbertheory` has no `inverse` (it is `inverse_mod`); the failed import was
  silently disabling the whole `v2x` module. Now uses builtin `pow(x, -1, n)`.
- SHA-256 keystream is only 32 bytes; `zip()` truncated longer plaintexts. Keystream
  is now extended block-wise to any length.
- MCP SDK 2.x renames `FastMCP` → `MCPServer`; pinned `mcp<2` and added a compat import.
