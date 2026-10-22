# vehsec · 车联网安全工具集

> CAN · UDS · Seed-Key · V2X · ICSim —— 封装成 **CLI**、**TUI** 和 **MCP Server**
> 三种入口，让你（或 AI 编程 Agent）直接驱动。**不需要真车。**

[![CI](https://github.com/xuange-hu/vehsec/actions/workflows/ci.yml/badge.svg)](https://github.com/xuange-hu/vehsec/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/badge/tests-277%20passing-brightgreen.svg)](tests/)
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
- 既是学习资源（精选清单 + 5 个 CTF 实验），也是可用的工具链。

## 三大支柱

| 支柱 | 说明 | 定位 |
|------|------|------|
| `vehsec` core + **CLI/TUI** | 现代化汽车安全工具包 | 安全工具，高热垂直 |
| **MCP Server**（`vehsec mcp`） | 封装为 MCP，供 Claude Code / Cursor / Cline 调用 | 蹭 2026 最大热点 AI Agent |
| **awesome-vehicle-security** + **labs/** | 精选清单 + 5 个可运行 CTF 实验 | 学习资源，易传播 |

## 架构

<img src="docs/architecture.svg" alt="vehsec architecture" width="880"/>

一层核心库，三种入口（CLI / TUI / MCP），统一走 `python-can` 虚拟总线或 Linux `vcan0`。
同一份实现同时暴露给人和 AI Agent——这是本项目与老工具最大的区别。

## 快速开始

**方式 A —— 一行命令，不用克隆、不用建虚拟环境**（最适合直接把 MCP 交给 Agent）：

```bash
uvx --from "vehsec[mcp] @ git+https://github.com/xuange-hu/vehsec" vehsec-mcp
uvx --from "vehsec @ git+https://github.com/xuange-hu/vehsec" vehsec --help
# 没有 uv？pipx run --spec "vehsec[mcp] @ git+https://github.com/xuange-hu/vehsec" vehsec-mcp
```

`@ git+…` 这种写法直接从本仓库安装，**今天就能用**。等项目发布到 PyPI 之后
会缩写成 `uvx --from "vehsec[mcp]" vehsec-mcp`；`.github/workflows/publish.yml`
会在每次 Release 时自动发布，只需在 PyPI 侧**一次性**开启 Trusted Publishing。

**方式 B —— 克隆下来改代码：**

```bash
git clone https://github.com/xuange-hu/vehsec && cd vehsec
python -m venv .venv && .venv\Scripts\activate        # Linux/macOS: source .venv/bin/activate
pip install -e ".[all]"

vehsec --help             # CLI
vehsec tui                # 交互式 TUI
vehsec mcp                # MCP stdio 服务（给 Agent 用）
vehsec mcp --check        # 列出 Agent 能拿到的 31 个工具后退出
python examples/demo.py   # 5 步演示，无需硬件
```

## 让 AI Agent 驱动

把下面这段加进 Agent 的 MCP 配置（`~/.workbuddy/mcp.json`、Cursor 的
`~/.cursor/mcp.json`、Cline，或 Claude Desktop 的 `claude_desktop_config.json`）
并信任该 server——**不用克隆、不用建虚拟环境**，`uv`/`uvx` 首次启动自动拉取：

```json
{
  "mcpServers": {
    "vehsec": {
      "command": "uvx",
      "args": ["--from", "vehsec[mcp] @ git+https://github.com/xuange-hu/vehsec", "vehsec-mcp"]
    }
  }
}
```

已经装过 `vehsec` 的话，等价写法是 `{ "command": "vehsec", "args": ["mcp"] }`
（`examples/mcp-config.json`）。然后直接说：

> "对虚拟 ECU 跑一次 UDS 安全访问，把 seed 和 key 给我。"

共 31 个工具：`can_send`、`can_fuzz`、`can_analyze`、`uds_security_access`、
`uds_read_did`、`uds_read_dtcs`、`uds_clear_dtcs`、`uds_decode_dtc`、`uds_raw`、
`seedkey_solve`、`seedkey_vendors`、`seedkey_recover`、`seedkey_predict`、
`v2x_analyze`、
`icsim_set_speed`、`icsim_tamper_demo`、
`doip_simulate`、`doip_probe`、`doip_tls_audit`、`doip_tls_probe`、`doip_tls_simulate`、
`dbc_decode`、`dbc_info`、`j1939_decode`、`j1939_encode`、
`j1939_decode_name`、`j1939_decode_dm1`、`isotp_segment`、`isotp_decode`、
`isotp_reassemble`、`isotp_explain`。

## 能力一览

- **UDS 诊断**：会话控制、安全访问（27 服务）、DID 读写、例程控制、ECU 复位、
  **故障码读取/清除（19/14 服务）**、通信控制（28 服务）与**任意 raw 请求**，
  走 ISO-TP（`udsoncan` + `can-isotp`）。
- **CAN 重放 / 模糊**：重放 `candump` 日志，或对指定 ID 集合做变异模糊。
- **CAN ID 发现**：按 ID 统计帧数、唯一载荷数、**哪些字节在变化**，定位控制信号。
- **Seed-Key 求解与算法恢复**：可插拔算法注册表（xor / add / rotate / 位反转 /
  半字节交换 / 大小端翻转 / CRC16 混合 / LFSR / SHA-256 密钥流），外加**算法恢复**——
  喂几组观测到的 `(seed, key)`，自动穷举变换族并解出参数；`seedkey predict` /
  `seedkey.predict()` 再把恢复出的算法套到一个**从未观测到的新 seed** 上，
  这就是"不读 DLL 也能解锁下一次会话"的那一步。
- **V2X / ECDSA**：检测 nonce 复用并**恢复签名私钥**（真实验证过的数学）。
- **ICSim 控制**：脚本化发送车速 / 车门 / 转向帧，演示仪表盘篡改。
- **DoIP（ISO 13400）**：进程内虚拟 DoIP 实体，车辆发现、路由激活、以太网 UDS 读 VIN。
- **DBC 解析**：纯标准库实现，Intel/Motorola 字节序、有符号、缩放、枚举、多路复用。
- **J1939（商用车）**：29 位 ID ↔ PGN/优先级/源地址（PDU1/PDU2）、NAME 解码、
  DM1 故障诊断（SPN/FMI/CM/OC）、EEC1 发动机转速。
- **ISO-TP（ISO 15765-2）**：UDS 的传输层，纯实现 SF/FF/CF/FC 组帧、分段与重组
  （含 CF 序列号校验），外加**多帧传输 ASCII 可视化**，不依赖第三方库。
- **DoIP（ISO 13400-2）**：以太网诊断——车辆发现、路由激活、UDS over TCP/13400；
  自带**进程内模拟器**，`vehsec doip simulate` 无车无硬件即可跑通全流程。
- **DBC 解析**：把 `1A4#1A02` 变成 `Speed = 41.5 km/h`。**纯标准库**实现，支持
  Intel / Motorola 字节序、有符号、缩放、VAL_ 枚举与多路复用信号。
- **DoIP over TLS（ISO 13400-2 安全诊断）**：TCP 3496 上的加密诊断通道，外加一套
  **证书审计引擎**——从零写的、零依赖 X.509 DER 解析器，并用纯 Python 验算
  RSA PKCS#1 v1.5 签名，所以"自签名"是**算出来的**，不是拿 subject==issuer 字符串
  猜的。对密钥长度、签名哈希、有效期、SAN/主机名、CA 链分级打分，
  还能探测网关实际接受哪些 TLS 版本。
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

## ISO-TP：30 秒上手

VIN 响应有 20 字节，装不进单帧，`vehsec isotp explain` 把多帧过程直接画出来：

```console
$ vehsec isotp explain --data 62F1904142434445464748494A4B4C4D4E4F5051
ISO-TP (ISO 15765-2) — 20-byte payload carried by 3 classic CAN frame(s)

  #   frame bytes             PCI   kind  detail
  0   10 14 62 F1 90 41 42 43 0x10  FF    total=20 B, carries bytes 0..5
  1   21 44 45 46 47 48 49 4A 0x21  CF    seq=1, carries bytes 6..12
  2   22 4B 4C 4D 4E 4F 50 51 0x22  CF    seq=2, carries bytes 13..19

  reassembled payload:
    62 F1 90 41 42 43 44 45 46 47 48 49
    4A 4B 4C 4D 4E 4F 50 51
    = 20 bytes
```

## Seed-Key 算法恢复：30 秒上手

真车的 seed→key 算法藏在 OEM 的 DLL 里。抓几组 `(seed, key)`（重放 `27 01`，
记录官方工具回的 key），交给 vehsec 反推：

```console
$ vehsec seedkey recover --pairs 11223344:4B78691E,a5b6c7d8:FFEC9D82,deadbeeF:84F7E4B5
    Recovered candidates (high confidence, 3 pair(s), 4-byte seed)
┌─────────────────────────┬────────────────────┐
│ algorithm               │ key for first seed │
├─────────────────────────┼────────────────────┤
│ key[i] = seed[i] ^ 0x5A │ 4B78691E           │
└─────────────────────────┴────────────────────┘
```

穷举覆盖 `xor c`、`add c`、`sub c`、`xor i ^ c`、`add i + c`、`rotl 1/3 ^ c`、
`bitrev ^ c`、半字节交换、大小端翻转，以及仿射族 `a*seed[i]+b`。候选解必须对
**所有**样本成立，因此 3 组以上样本通常收敛到唯一解。MCP 里同样可用：
`seedkey_recover(pairs="11223344:4B78691E,...")`。

**关键是泛化**：能拟合观测样本不等于恢复出了真算法，`seedkey predict`（MCP
`seedkey_predict` / 库函数 `vehsec.seedkey.predict()`）把结果套到从未见过的新
seed 上才算数：

```console
$ vehsec seedkey predict --pairs 11223344:4B78691E,a5b6c7d8:FFEC9D82,deadbeeF:84F7E4B5 \
                         --seed 00112233
algorithm key[i] = seed[i] ^ 0x5A
key      5A4B7869  (high confidence, 3 pair(s))
```

## DoIP over TLS：30 秒上手

```bash
# 1. 进程内起一个 TLS DoIP 网关：握手 → 路由激活 → UDS 读 VIN → 顺手审计证书
vehsec doip tls-simulate
#   协商出 TLSv1.3 / TLS_AES_256_GCM_SHA384
#   UDS 22 F190 -> 62f1905756575a5a5a314a5a5857303030303031
#   STRONG score 100/100

# 2. 审计抓到的证书（PEM 或 DER 都行）
vehsec doip tls-audit --file gateway.pem --ca oem-ca.pem --hostname gateway.local
#   REJECT score 10/100 grade F
#     [CRITICAL] RSA 密钥只有 1024 位
#     [HIGH    ] 用 SHA1 签名（sha1WithRSAEncryption）
#     [MEDIUM  ] 没有 subjectAltName 扩展，身份只剩 CN

# 3. 审计真实网关：支持哪些 TLS 版本、证书怎么样、明文 13400 是不是还开着
vehsec doip tls-probe --host 192.0.2.10
```

最有价值的发现通常来自第 3 条：**如果明文 13400 端口仍然接受路由激活，那它自己
的 TLS 监听就纯属摆设**——攻击者直接绕过就行。审计还会逐个 TLS 版本单独探测，
这正是"网关还在应答 TLS 1.0"这类问题的发现方式。

## 5 个可运行实验

| 实验 | 主题 |
|------|------|
| [`labs/uds-did-decrypt`](labs/uds-did-decrypt) | UDS DID 解密：算法识别与密钥恢复 |
| [`labs/delta-forge-patchchain`](labs/delta-forge-patchchain) | OTA 补丁链差分揭示隐藏载荷 |
| [`labs/v2x-ecdsa-nonce`](labs/v2x-ecdsa-nonce) | ECDSA nonce 复用 → 私钥恢复 |
| [`labs/sentinel2-can-statemachine`](labs/sentinel2-can-statemachine) | CAN 状态机注入（鉴权守卫缺失） |
| [`labs/seedkey-recover`](labs/seedkey-recover) | UDS 0x27 Seed-Key：5 组样本反推算法，再用未见过的 seed 解锁 ECU |

```bash
python labs/v2x-ecdsa-nonce/solve.py --gen 20            # 默认即注入 nonce 复用，首跑就成功
python labs/v2x-ecdsa-nonce/solve.py --gen 20 --no-reuse # 对照组：正确实现，无可利用

# Lab 5 零第三方依赖（标准库 + vehsec.seedkey），是最好上手的一个
python labs/seedkey-recover/solve.py            # 5 组样本 → 唯一解 → 解锁 → flag
python labs/seedkey-recover/solve.py --pairs 1  # 样本太少：拟合得上，解锁不了（NRC 0x35）
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
pytest -q      # 220 passed：核心 / CLI / MCP 注册 / 5 个 lab / 演示脚本
```

CI 在 Python 3.11 / 3.12 / 3.13 上跑 ruff + pytest。

## 合规声明

**仅用于授权的安全研究、教学，以及你自己拥有的设备/车辆的测试。**
请勿对未授权的车辆或网络发起访问，遵守所在司法辖区法律。作者不对任何滥用负责。
详见 [SECURITY.md](SECURITY.md)。

## 许可

MIT © xuange-hu
