# Roadmap — 目标 1000 star

## v0.1.0 ✅ 已完成（当前）
- [x] 核心库：CAN 收发/重放/模糊/candump 解析、UDS(isotp+udsoncan)、Seed-Key 注册表、
      V2X ECDSA nonce 复用恢复、ICSim 控制
- [x] CLI（click + rich）与 TUI（textual）
- [x] MCP Server：8 个工具，供 Claude Code / Cursor / Cline 调用
- [x] `awesome-vehicle-security.md` 精选清单
- [x] 4 个 Docker CTF Lab，全部通过断言
- [x] CAN 流量分析 / ID 发现（计数、唯一载荷、变化字节 → 定位控制信号）
- [x] 脚本化演示 `examples/demo.py`（5 步，可 asciinema/GIF 录屏，无需硬件）
- [x] 架构图 `docs/architecture.svg` 与发布文案 `docs/promotion.md`
- [x] 25 个测试 + GitHub Actions CI（3.11/3.12/3.13）

### v0.2.0 进度（2026-10-15）
- 测试 25 → **80**；MCP 工具 9 → **13**；新增 `doip.py` / `dbc.py` 两个模块。
- 踩坑记录：DBC 的 Intel 位序必须**反序**成 MSB-first 才能与 Motorola 共用同一套
  提取循环；`(factor,offset)` 与 `[min|max]` 在真实 DBC 中常省略，正则已改为可选。

### v0.2.0 进度（2026-10-15 夜间）
- 测试 80 → **100**；MCP 工具 13 → **17**；新增 `j1939.py` 模块（商用车协议）。
- 踩坑记录：J1939 NAME 的 manufacturer code 只有 **11 位**（上限 0x7FF），
  测试用例里用了 0xABC 会溢出被静默截断——不是模块 bug，是测试数据错。

### v0.2.0 进度（2026-10-16）
- 测试 100 → **138**；MCP 工具 17 → **20**；新增 `iso_tp.py`（ISO 15765-2）。
- **UDS 支柱修复**：此前任何 `vehsec uds ...` 命令在当前依赖下都直接崩溃，且该模块
  从未有测试。两个上游改名同时踩中：
  * `udsoncan` 1.22 起把 `Connection` 挪到 `udsoncan.connections`，且 `Client` 与默认
    配置（configs.default → configs.default_client_config）都换了位置；
  * `can-isotp` 2.x 把 `TransportLayer(bus, address)` 改成回调式，取而代之的是
    `CanStack(bus, address=...)`（**address 必须关键字传参**，否则撞 `rxfn`）。
  两条路径现均已做兼容。
- 新增 `VirtualEcu`：附加在虚拟总线上的进程内 UDS 应答器，支持 0x10/0x11/0x22/0x2E/
  0x27/0x31/0x3E，未知服务回 `7F xx 11`。至此三大支柱全部"零硬件可跑"。
- 踩坑记录：
  * Seed 的响应负载里含子功能回显（`01 01 02 03 04`），手工剥字节会随版本漂移，
    改用 udsoncan 自己的 `security_algo` 钩子拿解析后的 seed；
  * 未登记的 DID 读不了（ConfigError），在 `data_identifiers['default']` 挂一个
    `__len__` 抛 `ReadAllRemainingData` 的透传 codec 即可，不必预先声明每个 DID。
- 工程进展：仓库已在 GitHub 建立并推送（此前一直是纯本地仓库，从未公开）。

## v0.2.0 — 能力纵深（涨星主力）
- [x] **DTC 诊断故障码（19/14/28 服务）** `src/vehsec/uds.py`：SAE J2012 三字节
      编解码（`C10000` ↔ `U0100`）、statusOfDTC 位展开、常见故障码简述表；
      VirtualEcu 支持 0x19 的 01/02/0A 子功能、0x14 清除（按 group 掩码）、
      0x28 通信控制；新增 `UdsClient.raw()` 任意请求逃生舱。
      CLI `vehsec uds dtc|comm|raw`，MCP 新增 4 个工具（20 → 24）
- [x] TesterPresent(3E) / CommunicationControl(28) / DTC 读取(19) / 清除(14)
- [x] **DoIP（ISO 13400-2）** `src/vehsec/doip.py`：报文编解码、车辆声明/发现、
      路由激活、UDS over TCP，**带进程内模拟器**（`vehsec doip simulate` 无需硬件）
- [x] **DBC 解析与信号级编解码** `src/vehsec/dbc.py`：**纯标准库**（不依赖 canmatrix），
      支持 Intel/Motorola 字节序、有符号、缩放、VAL_ 枚举、多路复用信号；
      CLI 与 MCP 均已接入，`examples/sample.dbc` 为示例
- [ ] J1939 / ISO-TP 多帧与流控可视化
- [x] **J1939 商用车协议** `src/vehsec/j1939.py`：**纯标准库**，29 位 ID ↔
      PGN/优先级/源地址（PDU1 目标寻址 / PDU2 广播）、常见 PGN 名称表、
      64 位 NAME 解码、**DM1 故障诊断**（SPN/FMI/CM/OC + 告警灯位）、
      EEC1 发动机转速换算；CLI `vehsec j1939 decode|encode|name|dm1`
      与 MCP 4 个工具均已接入
- [ ] 更多 Seed-Key 算法 + UnlockECU db.json 适配器
- [ ] CAN 日志可视化（Web 或终端图表）

## v0.3.0 — 演示与传播（决定能否破千）
- [x] **README 顶部演示 GIF**：`examples/make_demo_gif.py` 用 Pillow 离线渲染
      真实 CLI 输出（无录屏、CI 可复现）→ `docs/demo.gif`；同脚本产出
      `docs/social-preview.png`（1280×640，Settings → Social preview 上传）
- [x] Linux vcan0 + ICSim + UDSim 一键脚本 `scripts/setup_vcan.sh`
- [x] 发布文案 `docs/promotion.md`（Show HN / PH / Reddit / X / Awesome PR 现成可发）
- [ ] 英文 README 与中英分栏
- [ ] 拆分为三个独立仓库（mcp / toolkit / awesome）分别冲 Trending

## 传播里程碑
- [ ] 提交到 `awesome-canbus`、`awesome-automotive-security` 等清单
- [ ] r/CarHacking、Show HN、Product Hunt 发布
- [ ] X / 掘金 / 知乎 技术串
- [ ] DEF CON Car Hacking Village 相关社群分享

### v0.2.0 进度（2026-10-17）
- 测试 140 → **172**；MCP 工具 20 → **24**。
- **DTC 支柱落地**：故障码是"扫描仪最该有的功能"，也是搜索量最大的 UDS 能力。
  新增 `decode_dtc`/`encode_dtc`/`decode_dtc_status` 三个纯函数 + NRC 名称表，
  VirtualEcu 增加 0x19/0x14/0x28 三个服务。
- **`UdsClient.raw()` 是关键设计决定**：`udsoncan` 只建模了部分服务，0x19 的
  DTC 解析需要它自己那一套 config。与其和上游 schema 纠缠，不如保留一个
  "payload 原样进、响应原样出"的通道，我们自己解析——版本漂移风险最小。
- 三条 DTC 记录 = 15 字节，超过经典 CAN 单帧 7 字节，因此这条响应**真实走
  首帧 + 连续帧**的多帧流程，顺带把 ISO-TP 路径又压测了一遍。
- 踩坑记录：
  * `argparse` **不支持** `--reuse/--no-reuse` 这种 click 风格的斜杠写法，
    要写成 `action=argparse.BooleanOptionalAction`（Python 3.9+）。
  * mcp 1.30 的 `list_tools()` 返回 pydantic `Tool`，**没有 `.fn`**；
    要调用工具得 `await mcp.call_tool(name, args)`，返回
    `(content_blocks, metadata)`，payload 在 `content[0].text`。
  * `groupOfDTC`（0x14 服务的 3 字节掩码）是 **AND 非零** 语义，不能用来表达
    "字母 == P"；测试里要用能真正区分的掩码（如 `0x00FF00` 命中中间字节）。
- **v2x lab 首跑体验修复**：默认即注入 nonce 复用，新访客第一次跑就能看到
  私钥被恢复出来；`--no-reuse` 才是对照组。

## 关键指标
GitHub Trending 按「星增速」加权：24–48 小时内冲 50–200 星即可上榜，上榜后日增
300–1000。因此发布要集中、演示要可视化、README 要 3 步跑通。
