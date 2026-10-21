# Changelog

All notable changes to `vehsec` are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/); versioning follows SemVer.

## [0.3.0] — 2026-10-21

### Added
- **DoIP over TLS (ISO 13400-2) and a certificate audit engine** — `src/vehsec/doip_tls.py`:
  - A **zero-dependency X.509 DER reader** plus a **pure-Python RSA PKCS#1 v1.5
    signature verifier**, so "self-signed" is *proven* by arithmetic rather than
    guessed from a `subject == issuer` string compare. Only *minting* key material
    needs `cryptography`; parsing and auditing never do.
  - `audit_certificate()` grades key size, signature hash, validity window,
    SAN/hostname match and CA chain into `critical/high/medium/low/info` findings
    with a 0–100 score; `probe_tls()` tests one TLS version at a time so a gateway
    that still answers TLS 1.0 is visible; `audit_endpoint()` also checks whether
    plaintext TCP 13400 still accepts a routing activation — if it does, the TLS
    listener is decorative.
  - CLI: `vehsec doip tls-simulate` / `tls-audit` / `tls-probe`.
    MCP: `doip_tls_simulate`, `doip_tls_audit`, `doip_tls_probe` (31 tools, up from 28).
- **Zero-friction MCP install** — `vehsec-mcp` is now a dedicated console script, so
  `uvx --from "vehsec[mcp]" vehsec-mcp` (or `pipx run`) needs no clone and no venv.
  Optional extras gained a `tls` extra; `[all]` pulls `cryptography>=42`.
- `vehsec mcp --check` prints the tool manifest an agent would receive and exits,
  without opening the stdio transport.

### Fixed
- Tests now pin the packaging surface: `tests/test_entrypoints.py` asserts the
  console-script targets resolve, that `@mcp.tool()` count equals the live manifest,
  and that `src/vehsec/__init__.py` and `pyproject.toml` agree on the version.

## [0.2.0] — 2026-10-19

### Added
- **`labs/seedkey-recover` — Lab 5, UDS 0x27 Seed-Key recovery** (zero third-party
  dependencies; stdlib + `vehsec.seedkey`):
  - Five sniffed `(seed, key)` pairs, a held-out seed that was never observed, a
    benchmark ECU implementing `0x27 01/02` plus a DID behind the security level.
  - `solve.py --pairs N` shows the search narrowing as evidence grows (1 pair →
    12 candidates / `low`, 2 → 1 / `medium`, 3+ → `high`), and `--pairs 1` ends in
    `0x7F 27 35 invalidKey` — the candidate fit the observation but failed the
    unlock, which is exactly the lesson.
  - Dockerfile / docker-compose included; `make labs` now runs all five.
- `seedkey` — **use the recovery result** instead of only reading it:
  - `recover_algorithm(pairs)` → `(expression, callable)`; the callable reproduces
    every observed pair and can be fed straight back through `register()` + `solve()`.
  - `predict(pairs, seed)` → the key for a **seed you never captured**, plus the
    recovered expression and the confidence rating.
  - CLI: `vehsec seedkey predict --pairs|--file --seed <hex>`.
    MCP: `seedkey_predict` (28 tools total, up from 27).
- `seedkey` — **algorithm recovery** (turn captured seed/key pairs into an algorithm):
  - `recover(pairs)` brute-forces a catalogue of parameterised transform families —
    `xor c`, `add c`, `sub c`, `xor i ^ c`, `add i + c`, `rotl 1/3 ^ c`,
    `bitrev ^ c`, `nibble-swap ^ c`, endian-swap, and the affine `a*seed[i]+b` —
    and returns every candidate consistent with **all** pairs, with a
    `high`/`medium`/`low` confidence rating (3+ pairs usually collapse to one).
  - Algorithm factories `algo_xor/add/sub/rotl/rotr/bitreverse/nibble_swap/
    endian_swap/crc16_xor/lfsr_xor/sha_keystream` + `compose()` for chaining, and
    10 new registered presets (`demo_*`).
  - `parse_pairs()` accepts `seed:key,seed:key` hex or a JSON list.
  - CLI: `vehsec seedkey recover --pairs|--file`, richer `vehsec seedkey vendors`.
    MCP: `seedkey_recover`, `seedkey_vendors` (27 tools total, up from 24).
- `iso_tp` — **ASCII visualisation** of a multi-frame transfer:
  - `explain(frames)` / `explain_payload(data)` render the frame list with PCI,
    kind (SF/FF/CF/FC), sequence numbers, the payload byte span each frame
    carries, `--` padding for unused bytes, and the reassembled payload.
    Incomplete transfers are reported as `INCOMPLETE — got N of M bytes`.
  - CLI: `vehsec isotp explain --data|--frames`. MCP: `isotp_explain`.
- `uds` — **diagnostic trouble codes (ISO 14229-1 services 0x19 / 0x14 / 0x28)**:
  - `decode_dtc()` / `encode_dtc()` convert between the 3-byte wire form and the
    SAE J2012 identifier (`C1 00 00` ↔ `U0100`); bits 7-6 of the high byte pick the
    system letter (P/C/B/U).
  - `decode_dtc_status()` expands the statusOfDTC byte into its flags
    (`confirmedDTC`, `pendingDTC`, `testFailed`, `warningIndicatorRequested`, ...).
  - `VirtualEcu` now stores DTCs and answers 0x19 sub-functions 0x01 (count),
    0x02 (by status mask) and 0x0A (supported), plus 0x14 clear (honouring the
    3-byte group mask) and 0x28 communication control.
  - `UdsClient.raw()` — an escape hatch that sends an arbitrary UDS payload and
    returns the response verbatim, so services `udsoncan` does not model (and
    vendor-specific ones) work without patching the library. Negative responses
    can be raised as a named `UdsError` or returned for the caller to inspect.
  - CLI: `vehsec uds dtc [--status|--count|--clear|--all]`, `vehsec uds comm`,
    `vehsec uds raw`. MCP: `uds_read_dtcs`, `uds_clear_dtcs`, `uds_decode_dtc`,
    `uds_raw` (24 tools total, up from 20).
- `labs/v2x-ecdsa-nonce` — **the nonce reuse is now the default**. The lab used to
  print "rerun with --reuse" and exit, which told a first-time visitor nothing.
  `--no-reuse` gives the contrast branch (a correct signer has nothing to exploit).

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
- `j1939` — **J1939 heavy-duty protocol (trucks, buses, agriculture), pure stdlib**:
  - 29-bit identifier decode/encode: priority, PGN, source address; **PDU1**
    (destination-addressed) vs **PDU2** (broadcast, group extension).
  - Label lookup for the common PGNs (EEC1, CCVS, DM1/DM2, TSC1, transport, ...).
  - 64-bit **NAME** decode: identity number, manufacturer code, function,
    industry group, arbitrary-address-capable.
  - **DM1** diagnostics: warning-lamp bits plus DTC list (SPN / FMI / CM / OC).
  - EEC1 engine-speed decoding (0.125 rpm per bit).
  - CLI: `vehsec j1939 decode|encode|name|dm1`.
  - MCP: `j1939_decode`, `j1939_encode`, `j1939_decode_name`, `j1939_decode_dm1`.
- CLI: `doip` and `dbc` command groups; `dbc decode|encode` report bad input as a
  clean click error instead of a traceback.
- 55 new tests (`tests/test_doip.py`, `tests/test_dbc.py`): 25 → **80 passing**.
- MCP tool count 9 → **13**.

- `iso_tp` — **ISO-TP / ISO 15765-2**, the transport layer that carries UDS over CAN,
  implemented from scratch with no dependencies:
  - SF/FF/CF/FC framing: SF `0x0|len`, FF `0x1|len_hi,len_lo`, CF `0x2|seq` (wrapping
    1..15 then 0), FC `0x3|status,BS,STmin`.
  - `segment()` / `reassemble()` round trip with consecutive-frame sequence validation
    and truncation to the first-frame declared length; flow-control frames skipped.
  - `decode()` / `describe()` for reading existing captures (sniffers, `candump` logs,
    crafted injections).
  - CLI: `vehsec isotp segment|decode|reassemble`. MCP: `isotp_segment`,
    `isotp_decode`, `isotp_reassemble`.
- **`VirtualEcu`** — an in-process UDS ECU answering on a `python-can` virtual bus:
  - Services 0x10 session, 0x11 reset, 0x22 read DID, 0x2E write DID, 0x27 security
    access, 0x31 routine control, 0x3E tester present; anything else gets a proper
    negative response (`0x7F svc 0x11`).
  - Answers multi-frame too (the 17-byte VIN spans FF + 2 CFs), honouring the
    receiver's block size and STmin.
  - Attached automatically on virtual buses, so `vehsec uds read --did 0xF190` works
    on a clean checkout with nothing plugged in. Use `auto_ecu=False` against metal.
- 38 new tests this round; MCP tool count 13 → **20** (17 with ISO-TP, 20 with J1939).

### Fixed
- **UDS was completely broken against current dependencies** — every `vehsec uds ...`
  command died on import or on connect. Two upstream renames had landed since the
  module was written:
  - `udsoncan` moved `Connection` out of `udsoncan.connection` into
    `udsoncan.connections` in 1.22 (now `PythonIsoTpConnection`), and both the `Client`
    class (`udsoncan.client.Client`) and the default config
    (`configs.default` → `configs.default_client_config`) moved as well. Imports now
    probe each shape.
  - `can-isotp` 2.x replaced `TransportLayer(bus, address)` with
    `TransportLayer(rxfn, txfn, address)`; the bus-carrying constructor is now
    `CanStack(bus, address=...)`. Since `pyproject.toml` pins only `can-isotp>=1.0`,
    a fresh install pulled 2.x and broke. Both layouts are now supported.
  - `CanStack(bus, address)` positionally raises "multiple values for argument
    'rxfn'" — `*args` are forwarded to the transport layer, so the address must be a
    keyword argument.
- Reading a DID that has no `data_identifiers` entry raised `ConfigError`. Rather than
  forcing callers to declare every DID up front (you usually don't know them before
  scanning), a pass-through codec is registered under `data_identifiers['default']`,
  signalling "read the rest of the payload" via `DidCodec.ReadAllRemainingData`.
- Seed bytes were computed from the raw response payload, which still carries the
  service/sub-function echo (`01 01 02 03 04` for a seed of `01 02 03 04`), so every
  derived key was wrong and the ECU answered `0x35 invalidKey`. The key is now derived
  through udsoncan's own `security_algo` hook, which hands over the parsed seed.
- Negative responses leaked an opaque third-party exception type; reads now surface a
  `UdsError` carrying the NRC name.
- The dependency error told users to `pip install isotp` — that is a *different*
  distribution. It now says `can-isotp` (which is the one that imports as `isotp`).
- Stopped tracking `labs/v2x-ecdsa-nonce/signatures.json`: `solve.py --out` rewrites it
  with fresh random keys on every run, so it only produced perpetual dirty diffs.
- `tests/test_uds.py` — the UDS module previously had **no** tests, which is how all of
  the above slipped through. 18 new tests (pure service dispatch + full round trips
  over the virtual bus). Suite: 120 → **138 passing**.
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
