# 发布与传播文案（开箱即用）

> 目标：把 `vehsec` 推上 GitHub Trending，冲 1000 star。
> Trending 按「星增速」加权：24–48 小时内冲 50–200 星即可上榜，上榜后日增 300–1000。
> 所以：**发布要集中、演示要可视化、README 要 3 步跑通**。

## 1. 仓库基础信息

**Description（≤160 字符，放 GitHub 仓库描述）**
```
Vehicle security toolkit — CAN/UDS/Seed-Key/V2X/ICSim as a CLI, TUI and MCP server. No car required.
```

**Topics（GitHub 仓库标签，影响搜索与推荐）**
```
vehicle-security, car-hacking, can-bus, uds, isotp, doip, j1939, v2x, mcp-server, ctf, security-research, iso-21434, ecu, dbc, automotive
```

**社交预览图（提高分享点击率，一次性设置）**
`docs/social-preview.png`（1280×640）已生成 → 仓库 **Settings → General → Social preview**
手动上传一次即可，之后所有 Tweet/Reddit/IM 分享都会带这张卡片。

**一句话简介（中英通用）**
> `vehsec` 把散落的车联网安全工具收拢成一套现代工具链：CLI / TUI / MCP 三种入口，
> 全部跑在虚拟总线上，**不需要真车**就能做 UDS 诊断、CAN 重放与模糊、Seed-Key 求解、
> V2X 签名分析和仪表盘篡改演示。

## 1.5 核心钩子：一行命令（所有文案都要带这一句）

```
uvx --from "vehsec[mcp] @ git+https://github.com/xuange-hu/vehsec" vehsec-mcp
```

不用克隆、不用建虚拟环境、`uv` 首次启动自动拉取。加进 Claude Code / Cursor / Cline
的 MCP 配置即可。**这是转化率最高的一句话**——"要装环境"是访客流失的第一大原因，
所以每一条文案（Show HN、Reddit、X、掘金）都必须把它放在第二段：

```json
{ "mcpServers": { "vehsec": { "command": "uvx",
                              "args": ["--from", "vehsec[mcp] @ git+https://github.com/xuange-hu/vehsec",
                                       "vehsec-mcp"] } } }
```

> **2026-10-23 修正（别再退回旧写法）**：原先所有文案都写 `uvx --from "vehsec[mcp]"`，
> 但 vehsec **还没有发布到 PyPI**，这条命令对访客必然 404。必须用 `@ git+…` 形式。
> 等 PyPI 首发（`.github/workflows/publish.yml`，Trusted Publishing 一次性开通）
> 之后再统一改回短写法。

## 2. Show HN（发布当天 08:00–09:00 PT）

**标题**（Show HN 要求 `Show HN:` 前缀，≤80 字符）
```
Show HN: vehsec – car-hacking toolkit you can drive from Claude Code over MCP
```

**正文**
```
Hi HN — I build CTF challenges around in-vehicle networks and kept re-writing the
same glue code, so I packaged it.

vehsec wraps CAN/UDS/Seed-Key/V2X/ICSim/DoIP behind three interfaces: a CLI, a TUI,
and an MCP server. The MCP bit is the part I find interesting — you can literally
tell Claude Code or Cursor "run a UDS security access on the virtual ECU" and it
will drive the 27-service handshake and hand you the seed/key.

There is nothing to install:

    uvx --from "vehsec[mcp] @ git+https://github.com/xuange-hu/vehsec" vehsec-mcp

Everything runs on a virtual CAN bus (python-can 'virtual', or vcan0 + ICSim on
Linux), so there is no hardware in the loop and nothing to brick. Five Docker labs
cover: UDS DID decryption, an OTA patch-chain diff, recovering an ECDSA private key
from a reused V2X nonce, a CAN state-machine injection, and UDS 0x27 Seed-Key —
give it five sniffed (seed, key) pairs and it reconstructs the algorithm, then
unlocks the next session with a seed it never saw. That last one needs nothing but
the stdlib.

Two things I did not expect when I started: (1) the DoIP-over-TLS certificate audit
needs no crypto library — I wrote a DER reader and verified RSA PKCS#1 v1.5 signatures
in pure Python, so "self-signed" is computed rather than string-compared; and (2) the
single most useful check is whether the gateway's *plaintext* port 13400 still accepts
a routing activation. If it does, its TLS listener is decorative.

The V2X one is real math, not a toy: two signatures sharing a nonce give you
k = (z1-z2)(s1-s2)^-1 and d = (s1k-z1)r^-1 mod n.

Happy to answer questions about UDS, ISO-TP, or the MCP integration.
Code: https://github.com/xuange-hu/vehsec
```

## 3. Reddit r/carhacking

**标题**
```
vehsec — modern CAN/UDS/Seed-Key/V2X toolkit with an MCP server (no hardware needed)
```

**正文要点**
- 解决了什么：现有工具（CANalyzat0r / UDSim / CANToolz / ICSim）文档稀少、Shell 化严重
- 亮点：`vehsec mcp` 让 Agent 直接调用；5 个 Docker lab（含 Seed-Key 算法恢复）
- 声明：仅授权研究 / 教学
- 结尾问：想要 DoIP 还是 J1939 先做？

## 4. Product Hunt

**Tagline**：`Car-hacking toolkit for the AI-agent era`
**Description**
```
CAN, UDS, Seed-Key, V2X and ICSim in one modern toolkit. Use it from a CLI, a TUI,
or let Claude Code / Cursor drive it over MCP. Five Docker labs (including UDS 0x27 Seed-Key recovery), no car required.
```
**First comment**：放 30 秒 GIF（`python examples/demo.py` 录屏）+ 3 步跑通命令。

## 5. X / 推文串（6 条）

1. 车联网安全工具太散了。我把 CAN/UDS/Seed-Key/V2X/ICSim 收进了一个现代工具链 `vehsec`。👇
2. 三种入口：CLI（`vehsec`）、TUI（`vehsec tui`）、MCP（`vehsec mcp`）。第三种是重点。
3. `vehsec mcp` 之后，直接对 Claude Code 说"跑一次 UDS 安全访问"，它会自己走完 27 服务握手并把 seed/key 给你。
4. 5 个 Docker 实验全部不需要真车：UDS DID 解密、OTA 补丁链差分、V2X ECDSA nonce 复用恢复私钥、CAN 状态机注入、Seed-Key 算法恢复。
5. Seed-Key 那条是我最喜欢的：给 5 组嗅探到的 `(seed, key)`，它穷举 11 个变换族把算法反推出来，再拿一个**没见过的新 seed** 去走 `0x27 02` 解锁 ECU。 `--pairs 1` 的失败分支更有意思：算法拟合得上，但 ECU 回 `0x7F 27 35`。
6. V2X 那条是真数学：同一 nonce 下两条签名 → `k=(z1-z2)(s1-s2)^-1`，`d=(s1k-z1)r^-1 mod n`。🔗 github.com/xuange-hu/vehsec

## 6. Awesome 清单 PR 用的条目

```markdown
- [vehsec](https://github.com/xuange-hu/vehsec) — CAN/UDS/Seed-Key/V2X/DoIP-TLS toolkit
  with CLI, TUI and an MCP server (31 tools, one `uvx` line from the repo);
  runs on virtual CAN, 5 Docker CTF labs, no hardware required.
```
可提交的清单：`awesome-canbus`、`awesome-automotive-security`、`awesome-mcp-servers`、
`awesome-vehicle-security`（自建，见仓库根目录）。**一个 PR 只提一个清单**，措辞要贴合该清单风格。

## 7. 中文社区（掘金 / 知乎）

标题建议：《我写了一个能被 AI Agent 调用的车联网安全工具：vehsec》
结构：痛点 → 三种入口 → MCP 集成细节 → 5 个实验的技术点 → 踩坑（can-isotp 包名、
mcp 2.x 改名、sha256 密钥流截断、ecdsa.numbertheory 没有 inverse）→ 路线图。

## 8. 发布当天节奏

| 时间 | 动作 |
|------|------|
| 08:00 | Show HN + Product Hunt 同时发 |
| 09:00 | X 推文串 + 掘金/知乎 |
| 10:00 | r/carhacking、r/opensource、r/cybersecurity |
| 次日 | 逐个提交 Awesome 清单 PR（不要同一天全提） |
| 持续 | 每天回 issue/PR，保持 commit 活跃 |
