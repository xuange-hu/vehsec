# Lab 3 · V2X ECDSA nonce 复用（签名伪造与私钥恢复）

## 场景
V2X 广播消息（CAM/DENM）用 ECDSA 签名。某实现在生成签名时**复用了同一个随机数
k**（RFC 6979 未正确使用）。只要收集到两条用了相同 k 的签名，就能在不知道私钥的
情况下**恢复签名私钥**，进而伪造任意合法 V2X 消息（中间人链路）。

## 文件
- `solve.py` — 生成带/不带 nonce 复用的签名集，并恢复私钥（仅需 `ecdsa`）
- `signatures.json` — 生成的签名样本（也可被 `vehsec v2x analyze` 直接消费）
- `Dockerfile` / `docker-compose.yml`

## 运行
```bash
docker compose up --build
# 或： pip install ecdsa && python solve.py --gen 20
# 用 vehsec 分析： vehsec v2x analyze signatures.json
```

默认即注入 nonce 复用，所以**第一次跑就能看到私钥被恢复出来**（下面的对照分支
`--no-reuse` 演示的是正确实现：每条消息各自的 k，无可利用之处）。

## 解法要点（真实数学）
对两条签名 `(r, s1, z1)`、`(r, s2, z2)`（相同 r = 相同 k）：
```
k = (z1 - z2) * (s1 - s2)^-1  mod n
d = (s1*k - z1) * r^-1         mod n
```
恢复出的 `d` 即签名私钥。`vehsec.v2x` 模块实现了同样的恢复逻辑，可作为库调用。
