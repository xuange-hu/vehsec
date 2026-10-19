# Lab 5 · UDS 0x27 Seed-Key 算法恢复（黑盒逆向 + 泛化验证）

## 场景

台架 ECU 跑 UDS 安全访问（服务 `0x27`）。它的 seed→key 算法藏在 OEM 私有 DLL 里
（`solve.py` 里的 `OemDll`），你读不到源码，但你**嗅探**到了诊断仪走这个流程五次，
拿到了 5 组 `(seed, key)` 观测样本。

任务：**只凭观测样本反推算法**，然后用它去解锁**下一次会话**（一个你从未见过的新
seed），最后读受保护的 DID `0xF190`。

## 文件
- `solve.py` — 解题脚本（用 `vehsec.seedkey`，仓库内可直接跑）
- `Dockerfile` / `docker-compose.yml`

## 运行
```bash
docker compose up --build
# 或： python solve.py
```

## 攻击链

| 阶段 | 做了什么 |
|------|----------|
| ① 观测 | 5 组 `(seed, key)`，来自 `0x27 01` / `0x27 02` 抓包 |
| ② 搜索 | `vehsec.seedkey.recover()` 穷举 **11 个参数化变换族**（xor / add / sub / 下标混合 / rotl / bitrev / nibble-swap / endian-swap / 仿射 `a*x+b`），候选必须**对所有样本都成立** |
| ③ 定置信度 | 观察 `confidence` 随样本量上升：`low → medium → high` |
| ④ 泛化 | 用**未出现在样本里的新 seed** 算 key，发 `0x27 02` |
| ⑤ 取货 | ECU 回 `0x67 02` → 解锁 → 读 `0xF190` 得到 flag |

## 解法要点

1. **样本质量比数量更关键**。第一条样本是 `5a5a5a5a`——四个字节全相同，
   于是 `xor c` / `add c` / `rotl k` / `bitrev` / `nibble-swap` 等族都能解释它，
   一次跑出 12 个候选（上限截断）。**重复字节的 seed 是最弱的证据。**
2. 加入第 2 条不同字节的样本后，候选立刻收敛到 1 个；3 条以上置信度到 `high`。
   这就是为什么实车复现时要**多抓几次会话**。
3. **最关键的验证是未见过的新 seed**。只有它能区分"真的恢复了算法"和"过拟合"：

```bash
$ python solve.py --pairs 1       # 只用一条样本
[+] recovered algorithm: key[i] = seed[i] ^ 0x4F
[-] 0x7F 27 35 invalidKey — the ECU rejected 40516273
[-] 'key[i] = seed[i] ^ 0x4F' was overfitted ...
    Feed the search more evidence:  python solve.py --pairs 3
```

`xor 0x4F` 完美解释了那一条样本，但新 seed 一上就露馅——这就是 CTF 里最容易翻车的点。

## 与真实车端的对应关系

| 本题 | 实车 |
|------|------|
| `OemDll.key_from_seed()` | OEM 私有 DLL / `.so` 里的算法（或 UnlockECU 已逆向的 30+ 厂商） |
| `CAPTURE_SEEDS` 抓包 | 嗅探官方诊断仪走 `0x27` 的 bus log（或用 `vehsec can sniff`） |
| `BenchEcu` | 真实 ECU 的 `0x27 01/02` + `0x22 F190` |
| `recover()` 穷举 | 差分分析 / 已知算法族匹配（简单算法可自动解） |

真实 Seed-Key 常是 32/64 位、带 CRC、查表甚至 AES，穷举族会失效——那时正确的
做法是逆向 DLL。`vehsec.seedkey` 的定位是：**先把简单情况自动化掉**，逆向出来的
算法再 `register()` 回注册表复用。

## 延伸命令

```bash
# 观察到一样样本后，直接预测新 seed 的 key（不必知道算法）
vehsec seedkey predict --pairs 5a5a5a5a:15151515,1a2b3c4d:179e26ad --seed 0f1e2d3c
# 只看恢复报告
vehsec seedkey recover --pairs 5a5a5a5a:15151515,1a2b3c4d:179e26ad,deadbeef:31aa32b8
```
