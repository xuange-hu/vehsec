# Lab 4 · Sentinel-2 CAN 状态机（异常注入）

## 场景
Sentinel-2 网关用一段 CAN 报文序列驱动内部状态机：`LOCKED → AUTH → UNLOCKED →
DRIVE`。授权流程必须经过 `0x100` 鉴权帧才能进入 `AUTH`，再经 `0x200` 会话帧进入
`UNLOCKED`。但状态机实现存在缺陷：**`0x200` 会话帧的鉴权守卫缺失**，从 `LOCKED`
直接发 `0x200` + `0x55` 就能跳过鉴权直达 `UNLOCKED`（异常状态注入）。

## 文件
- `solve.py` — 状态机 + 正常日志 + 注入脚本（仅标准库）
- `Dockerfile` / `docker-compose.yml`

## 运行
```bash
docker compose up --build
# 或： python solve.py
```

## 解法要点
1. 抓正常报文序列，重建状态迁移条件。
2. 审计守卫：`0x200` 处理分支应要求 `state == AUTH`，却写成了 `state in (AUTH, LOCKED)`。
3. 构造注入帧 `(0x200, 0x55)` 在 `LOCKED` 下发送，绕过鉴权。

用 `vehsec` 复现：`vehsec can send --id 0x200 --data 55`（在虚拟总线上观察状态机）。
实际车端对应未授权诊断会话跳变 / 重放攻击，是 ISO 21434 威胁建模的典型条目。
