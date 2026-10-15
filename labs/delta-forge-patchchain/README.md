# Lab 2 · Delta Forge 补丁链（逻辑差异与绕过）

## 场景
一份固件以「补丁链」方式增量更新：每次 OTA 只是在上一版基础上叠加补丁。安全团队
只发布了每一「补丁等级」的完整固件快照（states），没有发布补丁本身。请通过分析
**相邻快照的差分**，在不运行任何补丁的情况下恢复被隐藏在补丁里的载荷（flag）。

## 文件
- `solve.py` — 生成快照 + 差分恢复（仅标准库）
- `Dockerfile` / `docker-compose.yml`

## 运行
```bash
docker compose up --build
# 或： python solve.py
```

## 解法要点
每个补丁对缓冲做 `buf[pos] ^= frag`（异或叠加）。因此相邻快照的差分
`state[i] XOR state[i-1]` 在补丁位置正好等于 `frag`，未改动位置差分为 0。
把非零差分按位置排序拼接，即可得到被隐藏的 payload——这就是「逻辑差异」分析，
也是某些 OTA 校验绕过（不重放补丁、只构造目标状态）的思路基础。
