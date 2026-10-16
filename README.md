# vehsec — Vehicle Security Toolkit

> CAN · UDS · Seed-Key · V2X · ICSim · **DoIP** · **DBC** — wrapped as a **CLI**,
> a **TUI**, and an **MCP server** so you (or an AI coding agent) can drive it.
> **No car required.**

[![CI](https://github.com/xuange-hu/vehsec/actions/workflows/ci.yml/badge.svg)](https://github.com/xuange-hu/vehsec/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/badge/tests-120%20passing-brightgreen.svg)](tests/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org)
[![MCP](https://img.shields.io/badge/MCP-2026%20standard-green.svg)](https://modelcontextprotocol.io)

[中文 README / Chinese version](README_CN.md) · [Attack playbook](docs/playbook.md) · [Launch copy](docs/promotion.md)

---

## Why

Vehicle / in-vehicle-network (IVN) security is one of the hottest areas in security
research — and one of the most fragmented. The classic tools (CANalyzat0r, UDSim,
CANToolz, ICSim, caringcaribou) are aging, Shell-heavy, and thinly documented, so
**a beginner cannot get started without a real car**.

`vehsec` folds those capabilities into one modern, documented, composable package:
one command, one TUI, or one sentence to an AI agent gets you a UDS handshake, a CAN
replay, a Seed-Key solve, a V2X signature analysis, or an instrument-cluster tamper
demo. Everything runs on a **virtual CAN bus** (`python-can virtual`, or `vcan0` +
ICSim on Linux) with Docker labs — nothing to brick.

## Architecture

<img src="docs/architecture.svg" alt="vehsec architecture" width="880"/>

One core library, three surfaces (CLI / TUI / MCP), one transport. The same
implementation is exposed to humans *and* to AI agents — that is the main difference
from the older tooling.

## Quick start

```bash
git clone https://github.com/xuange-hu/vehsec && cd vehsec
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e ".[all]"

vehsec --help             # CLI
vehsec tui                # interactive TUI
vehsec mcp                # MCP server (stdio) for AI agents
python examples/demo.py   # 5-step scripted demo, no hardware
```

## Let an AI agent drive it

Copy `examples/mcp-config.json` into your agent's MCP config
(`~/.workbuddy/mcp.json`, Cursor `~/.cursor/mcp.json`, or Claude Desktop's
`claude_desktop_config.json`) and trust the server. Then just ask:

> "Run a UDS security access on the virtual ECU and show me the seed and key."

Twenty tools are exposed: `can_send`, `can_fuzz`, `can_analyze`, `uds_security_access`,
`uds_read_did`, `seedkey_solve`, `v2x_analyze`, `icsim_set_speed`, `icsim_tamper_demo`,
`doip_simulate`, `doip_probe`, `dbc_decode`, `dbc_info`, `j1939_decode`, `j1939_encode`,
`j1939_decode_name`, `j1939_decode_dm1`, `isotp_segment`, `isotp_decode`,
`isotp_reassemble`.

## Capabilities

- **UDS diagnostics** — session control, security access (27), DID read/write, routine
  control, ECU reset, over ISO-TP (`udsoncan` + `can-isotp`).
- **CAN replay & fuzz** — replay `candump` logs, or mutate frames against a set of IDs.
- **CAN ID discovery** — per-ID counts, unique payloads, and *which bytes change*, to
  locate the control signal in an unknown vehicle.
- **Seed-Key solver** — pluggable algorithm registry for the UDS 27 handshake.
- **V2X / ECDSA** — detect nonce reuse and **recover the signer's private key**.
- **ICSim control** — script speed / doors / turn signals on the virtual cluster.
- **DoIP (ISO 13400)** — in-process virtual DoIP entity: vehicle discovery, routing
  activation, and UDS-over-Ethernet (read the VIN) with no hardware.
- **DBC parsing** — pure stdlib: Intel/Motorola endianness, signed values,
  factor/offset scaling, value tables, multiplexed signals.
- **J1939 (trucks/buses)** — 29-bit id ↔ PGN/priority/source (PDU1 & PDU2), NAME
  decode, DM1 diagnostics (SPN/FMI/CM/OC), EEC1 engine speed.
- **ISO-TP (ISO 15765-2)** — the UDS transport layer, from scratch: SF/FF/CF/FC
  framing, segmentation and reassembly with sequence validation.
- **DoIP (ISO 13400-2)** — diagnostics over Ethernet: vehicle discovery, routing
  activation and UDS over TCP/13400, plus an in-process simulated DoIP entity so you
  can learn the protocol with no vehicle and no hardware.
- **DBC decoding** — turn `1A4#1A02` into `Speed = 41.5 km/h`. Pure-stdlib DBC parser
  with Intel *and* Motorola byte order, signed values, scaling and multiplexed signals.

## Labs — 4 runnable Docker exercises

| Lab | Topic |
|-----|-------|
| [`labs/uds-did-decrypt`](labs/uds-did-decrypt) | UDS DID decryption: identify the cipher, recover the key |
| [`labs/delta-forge-patchchain`](labs/delta-forge-patchchain) | OTA patch-chain diff reveals a hidden payload |
| [`labs/v2x-ecdsa-nonce`](labs/v2x-ecdsa-nonce) | ECDSA nonce reuse → private-key recovery |
| [`labs/sentinel2-can-statemachine`](labs/sentinel2-can-statemachine) | CAN state-machine injection / missing auth guard |

```bash
python labs/v2x-ecdsa-nonce/solve.py --gen 20 --reuse
```

## DoIP & DBC in 30 seconds

```bash
vehsec doip simulate                       # spin up a fake DoIP ECU, read its VIN
vehsec dbc info    --file examples/sample.dbc
vehsec dbc decode  --file examples/sample.dbc --id 0x100 --data 9F01393000010000
#   Speed 41.5 km/h · Odometer 1234.5 km · SpeedValid 1
vehsec dbc encode  --file examples/sample.dbc --id 0x100 --set Speed=41.5
vehsec dbc watch   --file examples/sample.dbc --log capture.log   # decode a whole capture
```

## Docs

| Doc | What |
|-----|------|
| [Attack playbook](docs/playbook.md) | Recon → UDS → Seed-Key → replay → V2X, with an ISO/SAE 21434 TARA map |
| [Quickstart](examples/quickstart.md) | Install, CLI, TUI, MCP setup |
| [Roadmap](ROADMAP.md) | What's next |
| [Contributing](CONTRIBUTING.md) | Dev setup, tests, how to add a lab |
| [Security policy](SECURITY.md) | Reporting vulnerabilities in vehsec itself |
| [awesome-vehicle-security.md](awesome-vehicle-security.md) | Curated resource list |

## Tests

```bash
pip install -e ".[all]" && pip install pytest
pytest -q      # 80 passed: core, CLI, MCP registration, all 4 labs, demo script
```

CI runs ruff + pytest on Python 3.11 / 3.12 / 3.13.

## Legal & ethics

For **authorized security research, teaching, and testing on equipment you own only**.
Do not point this at vehicles or networks you are not authorized to test; comply with
your jurisdiction's laws. The authors accept no responsibility for misuse.

## License

MIT © xuange-hu
