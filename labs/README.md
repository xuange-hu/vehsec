# vehsec labs — 可运行汽车安全 CTF 实验

五个自带环境、打开即跑的实验，对应五个真实车端攻防场景。每个目录含
`README.md`（writeup）、`solve.py`（解题脚本，多数可独立运行）、`Dockerfile`
与 `docker-compose.yml`。

| Lab | 主题 | 覆盖能力 |
|-----|------|----------|
| [`uds-did-decrypt`](uds-did-decrypt) | UDS DID 解密：加密算法识别与密钥恢复 | UDS / 对称解密 |
| [`delta-forge-patchchain`](delta-forge-patchchain) | Delta Forge 补丁链：逻辑差异与绕过 | 固件补丁 / 差分 |
| [`v2x-ecdsa-nonce`](v2x-ecdsa-nonce) | V2X ECDSA nonce 复用：签名伪造 | ECDSA 数学校验 |
| [`sentinel2-can-statemachine`](sentinel2-can-statemachine) | Sentinel-2 CAN 状态机：异常注入 | CAN 状态机 / 注入 |
| [`seedkey-recover`](seedkey-recover) | UDS 0x27 Seed-Key 算法恢复：观测反推 + 泛化解锁 | Seed-Key / 黑盒搜索 |

Lab 5 不需要任何额外依赖（只用标准库 + `vehsec.seedkey`），是五个里面最容易
上手的一个：把观测到的 `(seed, key)` 喂进去，它把算法反推出来，再拿一个
**从未见过的新 seed** 去解锁 ECU、读回受保护的 DID。

运行示例（Lab 5）：

```bash
cd labs/seedkey-recover
docker compose up --build
# 或本机： python solve.py
```

其它四个：

```bash
for lab in uds-did-decrypt delta-forge-patchchain sentinel2-can-statemachine; do
  (cd "labs/$lab" && python solve.py)
done
cd labs/v2x-ecdsa-nonce && python solve.py --gen 20 --reuse   # 需要 pip install ecdsa
```
