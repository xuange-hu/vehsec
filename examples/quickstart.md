# Quickstart

## 1. Install

```bash
git clone https://github.com/xuange-hu/vehsec
cd vehsec
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[all]"
```

## 2. CLI

```bash
vehsec --help
vehsec can fuzz --ids 0x1A4,0x19B --rounds 50
vehsec seedkey solve --vendor training_rotate --seed 0102
vehsec icsim demo --kmh 250
```

## 3. TUI

```bash
vehsec tui
```

## 4. MCP (let an AI agent drive the tools)

Copy `examples/mcp-config.json` into your agent's MCP config
(`~/.workbuddy/mcp.json`, Cursor `~/.cursor/mcp.json`, or Claude Desktop
`claude_desktop_config.json`) and **trust** the server. Then ask the agent e.g.:

> "Use vehsec to run a UDS security-access on the virtual ECU and show me the seed/key."

If you installed via `uv`, use:

```json
{ "mcpServers": { "vehsec": { "command": "uvx", "args": ["vehsec", "mcp"] } } }
```

## 5. V2X nonce-reuse lab

```bash
python labs/v2x-ecdsa-nonce/solve.py --gen 20 --reuse
vehsec v2x analyze labs/v2x-ecdsa-nonce/signatures.json
```

See `labs/` for the four runnable CTF exercises.
