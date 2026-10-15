# Lab 1 · UDS DID 解密（加密算法识别与密钥恢复）

## 场景
实车 UDS 读取 `0xF190`（VIN）时，ECU 返回的是**加密后的 DID**。已知加密算法为
「以诊断会话 Seed 派生的密钥流做逐字节 XOR」，且密钥流 = `SHA256(seed)[:len]`。
你抓到了一段密文和对应的 seed，请恢复原始 DID（flag）。

## 文件
- `solve.py` — 解题脚本（仅用标准库，可独立运行）
- `Dockerfile` / `docker-compose.yml`

## 运行
```bash
docker compose up --build
# 或： python solve.py
```

## 解法要点
1. 加密：`ct = pt XOR keystream`，`keystream = sha256(seed)[:len(pt)]`。
2. 解密即再次 XOR：`pt = ct XOR keystream`（XOR 自逆）。
3. 关键在于**识别算法类型**（对称流密码 / XOR）与**恢复密钥材料**（seed 已知）。

## 延伸
真实车端 Seed-Key 是 27 服务的安全访问，算法藏在 OEM 私有 DLL 里，需用
[UnlockECU](https://github.com/jglim/UnlockECU) 的逆向实现。`vehsec` 的
`seedkey` 模块提供可插拔注册表，把逆向出的算法注册后即可自动求解。
