# vehsec labs — 可运行汽车安全 CTF 实验

四个自带环境、打开即跑的实验，对应四个真实车端攻防场景。每个目录含
`README.md`（writeup）、`solve.py`（解题脚本，多数可独立运行）、`Dockerfile`
与 `docker-compose.yml`。

| Lab | 主题 | 覆盖能力 |
|-----|------|----------|
| [`uds-did-decrypt`](uds-did-decrypt) | UDS DID 解密：加密算法识别与密钥恢复 | UDS / 对称解密 |
| [`delta-forge-patchchain`](delta-forge-patchchain) | Delta Forge 补丁链：逻辑差异与绕过 | 固件补丁 / 差分 |
| [`v2x-ecdsa-nonce`](v2x-ecdsa-nonce) | V2X ECDSA nonce 复用：签名伪造 | ECDSA 数学校验 |
| [`sentinel2-can-statemachine`](sentinel2-can-statemachine) | Sentinel-2 CAN 状态机：异常注入 | CAN 状态机 / 注入 |

运行示例（Lab 3）：

```bash
cd labs/v2x-ecdsa-nonce
docker compose up --build
# 或本机： pip install ecdsa && python solve.py --gen 20 --reuse
```
