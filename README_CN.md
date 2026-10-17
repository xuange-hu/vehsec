# vehsec · 车联网安全工具集

> CAN · UDS · Seed-Key · V2X · ICSim —— 封装成 **CLI**、**TUI** 和 **MCP Server**
> 三种入口，让你（或 AI 编程 Agent）直接驱动。**不需要真车。**

[![CI](https://github.com/xuange-hu/vehsec/actions/workflows/ci.yml/badge.svg)](https://github.com/xuange-hu/vehsec/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/badge/tests-172%20passing-brightgreen.svg)](tests/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org)
[![MCP](https://img.shields.io/badge/MCP-2026%20标准-green.svg)](https://modelcontextprotocol.io)

[English README](README.md) · [攻击手册](docs/playbook.md) · [发布文案](docs/promotion.md)

<img src="docs/demo.gif" alt="vehsec 终端演示：CAN ID 发现、Seed-Key 求解、UDS 读 DID、J1939 解码、ICSim 篡改" width="880"/>

---

## 为什么做这个项目

车联网（IVN）安全是 2026 年最热、却工具最碎片化的方向之一。现有开源工具
（CANalyzat0r、UDSim、CANToolz、ICSim、caringcaribou）大多年久失修、文档稀少、
Shell 化严重，**新手很难在不动真车的前提下上手**。

`vehsec` 用一套**现代、文档完善、可组合**的代码把这些能力收拢起来：

- 一条命令 / 一个 TUI / 一句自然语言（经 MCP）就能完成 UDS 诊断、CAN 重放与模糊、
  Seed-Key 求解、V2X 签名分析、ICSim 仪表盘篡改演示。
- 全部实验**基于虚拟总线**（`python-can virtual`，或 Linux `vcan0` + ICSim），
  配 Docker Lab，**不需要真车，也不会刷坏 ECU**。
- 既是学习资源（精选清单 + 4 个 CTF 实验），也是可用的工具链。

## 三大支柱

| 支柱 | 说明 | 定位 |
|------|------|------|
| `vehsec` core + **CLI/TUI** | 现代化汽车安全工具包 | 安全工具，高热垂直 |
| **MCP Server**（`vehsec mcp`） | 封装为 MCP，供 Claude Code / Cursor / Cline 调用 | 蹭 2026 最大热点 AI Agent |
| **awesome-vehicle-security** + **labs/** | 精选清单 + 4 个可运行 CTF 实验 | 学习资源，易传播 |

## 架构

<img src="docs/architecture.svg" alt="vehsec architecture" width="880"/>

一层核心库，三种入口（CLI / TUI / MCP），统一走 `python-can` 虚拟总线或 Linux `vcan0`。
同一份实现同时暴露给人和 AI Agent——这是本项目与老工具最大的区别。

## 快速开始

```bash
git clone https://github.com/xuange-hu/vehsec && cd vehsec
python -m venv .venv && .venv\Scripts\activate        # Linux/macOS: source .venv/bin/activate
pip install -e ".[all]"

vehsec --help             # CLI
vehsec tui                # 交互式 TUI
vehsec mcp                # MCP stdio 服务（给 Agent 用）
python examples/demo.py   # 5 步演示，无需硬件
```

## 让 AI Agent 驱动

把 `examples/mcp-config.json` 加进 Agent 的 MCP 配置（`~/.workbuddy/mcp.json`、
Cursor 的 `~/.cursor/mcp.json`，或 Claude Desktop 的 `claude_desktop_config.json`）
并信任该 server，然后直接说：

> "对虚拟 ECU 跑一次 UDS 安全访问，把 seed 和 key 给我。"

共 24 个工具：`can_send`、`can_fuzz`、`can_analyze`、`uds_security_access`、
`uds_read_did`、`uds_read_dtcs`、`uds_clear_dtcs`、`uds_decode_dtc`、`uds_raw`、
`seedkey_solve`、`v2x_analyze`、`icsim_set_speed`、`icsim_tamper_demo`、
`doip_simulate`、`doip_probe`、`dbc_decode`、`dbc_info`、`j1939_decode`、`j1939_encode`、
`j1939_decode_name`、`j1939_decode_dm1`、`isotp_segment`、`isotp_decode`、`isotp_reassemble`。

## 能力一览

- **UDS 诊断**：会话控制、安全访问（27 服务）、DID 读写、例程控制、ECU 复位、
  **故障码读取/清除（19/14 服务）**、通信控制（28 服务）与**任意 raw 请求**，
  走 ISO-TP（`udsoncan` + `can-isotp`）。
- **CAN 重放 / 模糊**：重放 `candump` 日志，或对指定 ID 集合做变异模糊。
- **CAN ID 发现**：按 ID 统计帧数、唯一载荷数、**哪些字节在变化**，定位控制信号。
- **Seed-Key 求解**：可插拔算法注册表（含学习用示例算法与 UnlockECU 对接思路）。
- **V2X / ECDSA**：检测 nonce 复用并**恢复签名私钥**（真实验证过的数学）。
- **ICSim 控制**：脚本化发送车速 / 车门 / 转向帧，演示仪表盘篡改。
- **DoIP（ISO 13400）**：进程内虚拟 DoIP 实体，车辆发现、路由激活、以太网 UDS 读 VIN。
- **DBC 解析**：纯标准库实现，Intel/Motorola 字节序、有符号、缩放、枚举、多路复用。
- **J1939（商用车）**：29 位 ID ↔ PGN/优先级/源地址（PDU1/PDU2）、NAME 解码、
  DM1 故障诊断（SPN/FMI/CM/OC）、EEC1 发动机转速。
- **ISO-TP（ISO 15765-2）**：UDS 的传输层，纯实现 SF/FF/CF/FC 组帧、分段与重组
  （含 CF 序列号校验），不依赖第三方库。
- **DoIP（ISO 13400-2）**：以太网诊断——车辆发现、路由激活、UDS over TCP/13400；
  自带**进程内模拟器**，`vehsec doip simulate` 无车无硬件即可跑通全流程。
- **DBC 解析**：把 `1A4#1A02` 变成 `Speed = 41.5 km/h`。**纯标准库**实现，支持
  Intel / Motorola 字节序、有符号、缩放、VAL_ 枚举与多路复用信号。
- **故障码 DTC（SAE J2012 / ISO 14229-1）**：读取（19 服务的 01/02/0A 子功能）、
  清除（14 服务），并把 3 字节故障码解成 `U0100` 这样的 J2012 编号 + 状态位
  （confirmedDTC / pendingDTC / testFailed…）+ 简述。

## 故障码 DTC：30 秒上手

```console
$ vehsec uds dtc                       # 读故障码（19 服务 02 子功能）
         Diagnostic Trouble Codes (3)
┌───────┬────────┬─────────┬──────────────────────────┬──────────────────────┐
│ code  │ raw    │ status  │ flags                    │ description          │
├───────┼────────┼─────────┼──────────────────────────┼──────────────────────┤
│ P0100 │ 010000 │ 0x2C    │ pendingDTC,confirmedDTC… │ Mass or Volume Air … │
│ P0420 │ 042000 │ 0x0C    │ pendingDTC,confirmedDTC  │ Catalyst System Eff… │
│ U0100 │ C10000 │ 0x08    │ confirmedDTC             │ Lost Communication … │
└───────┴────────┴─────────┴──────────────────────────┴──────────────────────┘

$ vehsec uds dtc --status 0x08         # 只看已确认故障
$ vehsec uds dtc --count               # 只看数量
$ vehsec uds dtc --clear               # 清故障码（14 服务）
$ vehsec uds raw --data 1901FF         # 任意 UDS 请求，原样返回响应
590109000003
```

三条故障码记录共 15 字节，装不进单帧 CAN，因此这条响应走的是**首帧 + 连续帧**
的真实 ISO-TP 多帧路径——不是桩代码。

## 4 个可运行实验

| 实验 | 主题 |
|------|------|
| [`labs/uds-did-decrypt`](labs/uds-did-decrypt) | UDS DID 解密：算法识别与密钥恢复 |
| [`labs/delta-forge-patchchain`](labs/delta-forge-patchchain) | OTA 补丁链差分揭示隐藏载荷 |
| [`labs/v2x-ecdsa-nonce`](labs/v2x-ecdsa-nonce) | ECDSA nonce 复用 → 私钥恢复 |
| [`labs/sentinel2-can-statemachine`](labs/sentinel2-can-statemachine) | CAN 状态机注入（鉴权守卫缺失） |

```bash
python labs/v2x-ecdsa-nonce/solve.py --gen 20            # 默认即注入 nonce 复用，首跑就成功
python labs/v2x-ecdsa-nonce/solve.py --gen 20 --no-reuse # 对照组：正确实现，无可利用
```

## 文档

| 文档 | 内容 |
|------|------|
| [攻击手册](docs/playbook.md) | 侦察→UDS→Seed-Key→重放→V2X 全流程 + ISO/SAE 21434 TARA 映射 |
| [快速上手](examples/quickstart.md) | 安装、CLI、TUI、MCP 配置 |
| [路线图](ROADMAP.md) | 后续计划 |
| [贡献指南](CONTRIBUTING.md) | 开发环境、测试、如何新增实验 |
| [安全政策](SECURITY.md) | vehsec 自身漏洞的负责任披露 |
| [精选清单](awesome-vehicle-security.md) | 车联网安全资源汇总 |

## 测试

```bash
pip install -e ".[all]" && pip install pytest
pytest -q      # 172 passed：核心 / CLI / MCP 注册 / 4 个 lab / 演示脚本
```

CI 在 Python 3.11 / 3.12 / 3.13 上跑 ruff + pytest。

## 合规声明

**仅用于授权的安全研究、教学，以及你自己拥有的设备/车辆的测试。**
请勿对未授权的车辆或网络发起访问，遵守所在司法辖区法律。作者不对任何滥用负责。
详见 [SECURITY.md](SECURITY.md)。

## 许可

MIT © xuange-hu
