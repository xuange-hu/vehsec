# Awesome Vehicle Security

> A curated list of resources for automotive / in-vehicle-network (IVN) security
> research: tools, hardware, learning material, CTF writeups, standards and talks.
> Companion to [`vehsec`](https://github.com/xuange-hu/vehsec) — a modern toolkit
> that wraps many of these capabilities behind a CLI, TUI and MCP server.
>
> Every link below was checked with an HTTP request before being added; star
> counts are the figures GitHub reported when the entry was last curated. Two
> larger general-purpose lists exist and are worth starring on their own —
> [`jaredthecoder/awesome-vehicle-security`](https://github.com/jaredthecoder/awesome-vehicle-security)
> (~4.8k★) and [`iDoka/awesome-canbus`](https://github.com/iDoka/awesome-canbus)
> (~3.6k★). This list stays deliberately narrower: it is the *runnable* subset,
> i.e. things you can clone and execute today against a virtual or bench setup.

Contributions welcome — open a PR (see bottom).

## Contents
- [Learning & Books](#learning--books)
- [Protocols & Standards](#protocols--standards)
- [CAN Tooling](#can-tooling)
- [UDS / Diagnostics](#uds--diagnostics)
- [Fuzzing & Attack Frameworks](#fuzzing--attack-frameworks)
- [Hardware](#hardware)
- [OBD-II Everyday Tools](#obd-ii-everyday-tools)
- [Simulation / Virtual Cars](#simulation--virtual-cars)
- [ECU & Firmware](#ecu--firmware)
- [J1939 / Heavy Vehicles](#j1939--heavy-vehicles)
- [V2X / Autonomous](#v2x--autonomous)
- [CTF Writeups & Practice Labs](#ctf-writeups--practice-labs)
- [Conferences & Talks](#conferences--talks)
- [Communities](#communities)

## Learning & Books

- [The Car Hacker's Handbook](https://archive.org/details/car-hackers-handbook-the-craig-smith) — Craig Smith's definitive intro; free to borrow.
- [CAN bus — Wikipedia](https://en.wikipedia.org/wiki/CAN_bus) — protocol fundamentals, arbitration and framing.
- [Unified Diagnostic Services — Wikipedia](https://en.wikipedia.org/wiki/Unified_Diagnostic_Services) — service/NRC reference.
- [ISO/SAE 21434](https://www.iso.org/standard/70918.html) — road-vehicle cybersecurity engineering (process, not code).
- [UNECE WP.29 R155](https://unece.org/transport/documents/2021/03/standards/un-regulation-no-155) — cyber-resilience regulation behind most 2024+ OEM security programmes.
- [`kentindell/canhack`](https://github.com/kentindell/canhack) — Canis Labs' "Yes We CAN" notes; the clearest explanation of CAN bit-level attacks.

## Protocols & Standards

The four documents that actually decide what a frame on the wire looks like:

- **ISO 11898-1** — CAN data link layer and arbitration.
- **ISO 15765-2** — ISO-TP: segmentation, flow control, the frame types `0x0`–`0x3`.
- **ISO 14229-1** — UDS: services, sub-functions, the `0x7F` negative-response codes.
- **ISO 13400-2** — DoIP: diagnostics over IP, the `0x1000`+ logical addresses.
- **SAE J1939** — heavy-vehicle CAN application layer (PGN/SPN, 29-bit IDs).

## CAN Tooling

- [`linux-can/can-utils`](https://github.com/linux-can/can-utils) — `candump`, `cansend`, `cangen`, `canbusload`; the floor everything else stands on.
- [`hardbyte/python-can`](https://github.com/hardbyte/python-can) — Python CAN library, including the `virtual` interface `vehsec` uses by default.
- [`collin80/SavvyCAN`](https://github.com/collin80/SavvyCAN) (~1.9k★) — cross-platform GUI: capture, DBC decode, sniffer and fuzz.
- [`MatthewKuKanich/CAN_Commander`](https://github.com/MatthewKuKanich/CAN_Commander) (~1.1k★) — reverse-engineering workbench for unknown CAN traffic.
- [`ebroecker/canmatrix`](https://github.com/ebroecker/canmatrix) — DBC/KCD/MAT/ARXML conversion; useful when a vendor ships the wrong format.
- [`julietkilo/CANBabel`](https://github.com/julietkilo/CANBabel) — multi-format CAN log conversion.
- [`GENIVI/CANdevStudio`](https://github.com/GENIVI/CANdevStudio) — GUI CAN simulation with scripted nodes.
- [`rbei-etas/busmaster`](https://github.com/rbei-etas/busmaster) (~1k★) — BUSMASTER: simulate, analyse and test bus systems (Windows-first).
- [`adamtheone/canDrive`](https://github.com/adamtheone/canDrive) — replay/adversarial tooling for drive-by-wire research.
- [`secdev/scapy`](https://github.com/secdev/scapy) — not CAN-specific, but the reference for hand-building arbitrary frames on any transport.

## UDS / Diagnostics

- [`pylessard/python-udsoncan`](https://github.com/pylessard/python-udsoncan) — Python UDS client used by `vehsec`; solid service definitions.
- [`pylessard/python-can-isotp`](https://github.com/pylessard/python-can-isotp) — ISO-TP over python-can (PyPI name `can-isotp`, import name `isotp`).
- [`hartkopp/can-isotp`](https://github.com/hartkopp/can-isotp) — the Linux kernel ISO-TP module; what SocketCAN users actually load.
- [`openxc/uds-c`](https://github.com/openxc/uds-c) (~800★) — C implementation of UDS + OBD-II, small enough to read end to end.
- [`mdabrowski1990/uds`](https://github.com/mdabrowski1990/uds) — independent Python UDS package; good second implementation to diff against.
- [`rnd-ash/OpenVehicleDiag`](https://github.com/rnd-ash/OpenVehicleDiag) (~1k★) — Rust cross-platform ECU diagnostics GUI (UDS over CAN and DoIP).
- [`rnd-ash/ecu_diagnostics`](https://github.com/rnd-ash/ecu_diagnostics) — the Rust crate underneath it, if you want a library rather than an app.
- [`zombieCraig/UDSim`](https://github.com/zombieCraig/UDSim) — UDS ECU simulator plus fuzzer; pairs with ICSim.
- [`lbenthins/ecu-simulator`](https://github.com/lbenthins/ecu-simulator) — scriptable diagnostic-service simulator, no hardware needed.
- [`jglim/UnlockECU`](https://github.com/jglim/UnlockECU) — 30+ reverse-engineered Seed-Key algorithms; the reference corpus behind `vehsec seedkey`.
- [`CaringCaribou/caringcaribou`](https://github.com/CaringCaribou/caringcaribou) (~1k★) — friendly discovery/fuzz/scan shell for bench work.

## Fuzzing & Attack Frameworks

- [`CANToolz/CANToolz`](https://github.com/CANToolz/CANToolz) — Python CAN MITM / replay / fuzz pipeline with a module graph.
- [`schutzwerk/CANalyzat0r`](https://github.com/schutzwerk/CANalyzat0r) (~800★) — security analysis toolkit for proprietary protocols.
- [`DanAurea/AutoFuze`](https://github.com/DanAurea/AutoFuze) — automotive-targeted fuzzing toolkit (small but purpose-built).
- [`infobyte/doggie`](https://github.com/infobyte/doggie) — Faraday's CAN attack/defence harness, incl. EvilDoggie.
- [`jgamblin/CarHackingTools`](https://github.com/jgamblin/CarHackingTools) (~1k★) — install recipes for the usual tool stack; saves an afternoon.
- [`Vu1nT0tal/Vehicle-Security-Toolkit`](https://github.com/Vu1nT0tal/Vehicle-Security-Toolkit) — 汽车/安卓/固件 安全测试工具集 (Chinese-language, firmware + Android focus).
- **[`xuange-hu/vehsec`](https://github.com/xuange-hu/vehsec)** — CLI/TUI/MCP toolkit (this list's companion): CAN/UDS/Seed-Key/V2X/DoIP/DBC/J1939 with evidence-bearing output.

## Hardware

- ELM327 / Veepeak — cheap OBD-II Bluetooth dongles; fine for logging, not for timing-sensitive attacks.
- [`linklayer/cantact`](https://github.com/linklayer/cantact) — open-source USB CAN interface (firmware + hardware).
- [`CANBus-Triple/CANBus-Triple`](https://github.com/CANBus-Triple/CANBus-Triple) — the classic three-bus car-hacking platform.
- [`MagnusThome/RejsaCAN-ESP32`](https://github.com/MagnusThome/RejsaCAN-ESP32) — ESP32 CAN board, Wi-Fi attached.
- [`Seeed-Studio/Seeed_Arduino_CAN`](https://github.com/Seeed-Studio/Seeed_Arduino_CAN) — cheap MCP2515-based Arduino CAN shield.
- [`newaetech/chipwhisperer`](https://github.com/newaetech/chipwhisperer) — side-channel and fault injection; the standard for ECU key extraction.

## OBD-II Everyday Tools

Where most people actually start, and what to reach for when you need a second opinion:

- [`barracuda-fsh/pyobd`](https://github.com/barracuda-fsh/pyobd) (~1.3k★) — OBD-II diagnostic tool in Python; the readable reference for PID handling.
- [`fr3ts0n/AndrOBD`](https://github.com/fr3ts0n/AndrOBD) (~2.2k★) — Android OBD app that works with any ELM327 adapter.
- [`cedricp/ddt4all`](https://github.com/cedricp/ddt4all) (~1.9k★) — Renault/Nissan diagnostic tool; useful for OEM-specific DID exploration.
- [`PowerBroker2/ELMduino`](https://github.com/PowerBroker2/ELMduino) (~1k★) — Arduino library for ELM327 modules; cheap logger builds.

## Simulation / Virtual Cars

- [`zombieCraig/ICSim`](https://github.com/zombieCraig/ICSim) — instrument-cluster simulator; the usual first bench, drives `vcan0`.
- [`zombieCraig/UDSim`](https://github.com/zombieCraig/UDSim) — the paired ECU simulator; realistic 0x27 seed/key and DTC responses.
- [`vehsec/labs`](labs/) — four self-contained labs that need neither hardware nor Docker: UDS DID decrypt, patch-chain diff, V2X nonce reuse, CAN state-machine injection.

## ECU & Firmware

- [`attify/firmware-analysis-toolkit`](https://github.com/attify/firmware-analysis-toolkit) — FIRMADYNE-derived extraction/emulation harness.
- [`openxc/openxc-python`](https://github.com/openxc/openxc-python) — reference parser for OBD-II / CAN trace formats; a good sanity check on your own decoder.
- [`newaetech/chipwhisperer`](https://github.com/newaetech/chipwhisperer) — see Hardware; the practical path to Seed-Key secrets.
- [`CR11CS/RollJam-315MHz-433MHz`](https://github.com/CR11CS/RollJam-315MHz-433MHz) — RF replay of rolling-code key fobs; the classic "amplify-and-replay" primitive.

## J1939 / Heavy Vehicles

- [`DanielMartensson/Open-SAE-J1939`](https://github.com/DanielMartensson/Open-SAE-J1939) (~650★) — portable J1939 stack (C/C++), PGN/SPN tables included.
- [`juergenH87/python-can-j1939`](https://github.com/juergenH87/python-can-j1939) — J1939 support for Python; ships a DBC-backed message set.
- [`nmfta-repo/pretty_j1939`](https://github.com/nmfta-repo/pretty_j1939) — pretty-print J1939 logs; useful for making sense of a truck capture.
- [`famez/J1939-Framework`](https://github.com/famez/J1939-Framework) — Java framework for J1939 frame handling.

## V2X / Autonomous

- [ETSI automotive & ITS](https://www.etsi.org/technologies/automotive-intelligent-transport) — the standards family (ITS-G5 and C-V2X).
- [`vehsec/labs/v2x-ecdsa-nonce`](labs/v2x-ecdsa-nonce) — recover a V2X signing key from a reused ECDSA nonce; the failure mode is real and recurring.
- [IEEE 1609](https://standards.ieee.org/ieee/1609.2/7190/) — WAVE security services: certificate formats and signing rules.

## CTF Writeups & Practice Labs

- **[`vehsec/labs`](labs/)** — four runnable labs by xuange-hu, no hardware required:
  - `uds-did-decrypt` — UDS DID 解密（加密算法识别与密钥恢复）
  - `delta-forge-patchchain` — Delta Forge 补丁链差异定位
  - `v2x-ecdsa-nonce` — V2X ECDSA nonce 复用签名伪造
  - `sentinel2-can-statemachine` — Sentinel-2 CAN 状态机注入
- [DEF CON Car Hacking Village challenges](https://carhackingvillage.com/) — past challenge archives are the best free corpus of real attack traffic.
- [`Bahieradan33/Automotive-Cybersecurity-Projects`](https://github.com/Bahieradan33/Automotive-Cybersecurity-Projects) — hands-on UDS/CAN exercises, each with a stated goal.
- [`zombieCraig/ICSim`](https://github.com/zombieCraig/ICSim) — spoof the instrument cluster; the classic first attack.
- [`zombieCraig/UDSim`](https://github.com/zombieCraig/UDSim) — then unlock the ECU; together they make a practice range.

## Conferences & Talks

- [CanSecWest](https://cansecwest.com/) — automotive track every spring.
- [Black Hat](https://www.blackhat.com/) — automotive briefings, usually August.
- [escar](https://escar.info/) — Embedded Security in Cars; the academic/industry crossover.

## Communities

- [r/CarHacking](https://www.reddit.com/r/CarHacking/) — the highest-signal public forum for bench questions.
- [`iDoka/awesome-canbus`](https://github.com/iDoka/awesome-canbus) — sister list, much broader on hardware.
- [`jaredthecoder/awesome-vehicle-security`](https://github.com/jaredthecoder/awesome-vehicle-security) — sister list, much broader on learning material and talks.

---

### Contributing

Fork → add your entry under the right heading (one line, `[name](url) — short desc`)
→ open a PR. Two rules, both enforced in review:

1. **The link must resolve.** Paste the URL you actually loaded; entries that 404
   or point at a different project than their label are removed on sight.
2. **Legal-research / education only.** No tooling whose purpose is to bypass
   paid services, immobilisers you do not own, or emissions testing.