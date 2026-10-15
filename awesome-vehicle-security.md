# Awesome Vehicle Security

> A curated list of resources for automotive / in-vehicle-network (IVN) security
> research: tools, hardware, learning material, CTF writeups, standards and talks.
> Companion to [`vehsec`](https://github.com/xuange-hu/vehsec) — a modern toolkit
> that wraps many of these capabilities behind a CLI, TUI and MCP server.

Contributions welcome — open a PR (see bottom).

## Contents
- [Learning & Books](#learning--books)
- [Protocols & Standards](#protocols--standards)
- [CAN Tooling](#can-tooling)
- [UDS / Diagnostics](#uds--diagnostics)
- [Fuzzing & Attack Frameworks](#fuzzing--attack-frameworks)
- [Hardware](#hardware)
- [Simulation / Virtual Cars](#simulation--virtual-cars)
- [ECU & Firmware](#ecu--firmware)
- [V2X / Autonomous](#v2x--autonomous)
- [CTF Writeups](#ctf-writeups)
- [Conferences & Talks](#conferences--talks)
- [Communities](#communities)

## Learning & Books
- [The Car Hacker's Handbook](https://archive.org/details/car-hackers-handbook-the-craig-smith) — Craig Smith's definitive intro.
- [CAN bus Wikipedia](https://en.wikipedia.org/wiki/CAN_bus) — protocol fundamentals.
- [UDS (ISO 14229) overview](https://en.wikipedia.org/wiki/Unified_Diagnostic_Services) — diagnostic service reference.
- [ISO/SAE 21434](https://www.iso.org/standard/70918.html) — road vehicles cybersecurity engineering.
- [UNECE WP.29 R155/R156](https://unece.org/transport/documents/2021/03/standards/un-regulation-no-155) — cyber resilience & SUMS regulation.

## Protocols & Standards
- ISO 11898 (CAN), ISO 15765 (ISO-TP / DoIP), ISO 14229 (UDS), ISO 21434, SAE J1939 (trucks/buses).

## CAN Tooling
- [linux-can/can-utils](https://github.com/linux-can/can-utils) — `candump`, `cansend`, `cangen`.
- [hardbyte/python-can](https://github.com/hardbyte/python-can) — Python CAN bus library (used by `vehsec`).
- [ebroecker/canmatrix](https://github.com/ebroecker/canmatrix) — DBC/KCD/MAT conversion.
- [julietkilo/CANBabel](https://github.com/julietkilo/CANBabel) — multi-format CAN conversion.
- [CANdevStudio](https://github.com/GENIVI/CANdevStudio) — GUI CAN simulation.

## UDS / Diagnostics
- [pylessard/python-udsoncan](https://github.com/pylessard/python-udsoncan) — Python UDS stack (used by `vehsec`).
- [christiansandberg/aioisotp](https://github.com/christiansandberg/aioisotp) — async ISO-TP.
- [zombieCraig/UDSim](https://github.com/zombieCraig/UDSim) — UDS simulator + fuzzer.
- [jglim/UnlockECU](https://github.com/jglim/UnlockECU) — 30+ reverse-engineered Seed-Key algorithms.
- [CaringCaribou/caringcaribou](https://github.com/CaringCaribou/caringcaribou) — friendly car-security exploration tool.

## Fuzzing & Attack Frameworks
- [CANToolz/CANToolz](https://github.com/CANToolz/CANToolz) — Python CAN MITM / replay / fuzz.
- [Schmidtisch/ICSim attacks](https://github.com/zombieCraig/ICSim) — demo scripts against ICSim.
- [CANalyzat0r](https://github.com/schutzwerk/CANalyzat0r) — security analysis toolkit.
- **[xuange-hu/vehsec](https://github.com/xuange-hu/vehsec)** — modern CLI/TUI/MCP toolkit (this list's companion).

## Hardware
- ELM327 / Veepeak — cheap OBD-II Bluetooth dongles (start here).
- [LinkLayer/cantact](https://github.com/linklayer/cantact) — open-source CAN interface.
- [MagnusThome/RejsaCAN-ESP32](https://github.com/MagnusThome/RejsaCAN-ESP32) — ESP32 CAN board.
- [greatscottgadgets/CC2531](https://github.com/greatscottgadgets/cc2531) — (related) RF analysis.
- [newaetech/chipwhisperer](https://github.com/newaetech/chipwhisperer) — side-channel / fault injection.

## Simulation / Virtual Cars
- [zombieCraig/ICSim](https://github.com/zombieCraig/ICSim) — instrument-cluster simulator for attack demos.
- [EFeru/ICSim-docker](https://github.com/EFeru/ICSim-docker) — one-command ICSim + savvycli.
- [revolvecake/ICSim-docker](https://github.com/revolvecake/ICSim-docker) — alternative compose setup.

## ECU & Firmware
- [FirmWare-Analysis-Toolkit (FAT)](https://github.com/attify/firmware-analysis-toolkit) — firmware extraction/analysis.
- [IDontThinkLlama/ecu-toolkit](https://github.com/IDontThinkLlama/ecu-toolkit) — ECU research tooling.
- [uPwnLab/ecu-toolkit](https://github.com/uPwnLab/ecu-toolkit) — additional ECU utilities.

## V2X / Autonomous
- [ETSI ITS / IEEE 1609](https://www.etsi.org/technologies/cellular-vehicle-to-everything) — V2X standards.
- [esnet/iCS-Optimus](https://github.com/esnet/iCS-Optimus) — related secure comms research.
- **V2X ECDSA nonce-reuse lab** in [`vehsec/labs/v2x-ecdsa-nonce`](labs/v2x-ecdsa-nonce) — recover a private key from reused nonces.

## CTF Writeups
- **[vehsec/labs](labs/)** — 4 runnable labs by xuange-hu:
  - `uds-did-decrypt` — UDS DID 解密 (加密算法识别与密钥恢复)
  - `delta-forge-patchchain` — Delta Forge patch chain 逻辑差异与绕过
  - `v2x-ecdsa-nonce` — V2X ECDSA nonce 复用签名伪造
  - `sentinel2-can-statemachine` — Sentinel-2 CAN 状态机注入

## Conferences & Talks
- [DEF CON Car Hacking Village](https://carhackingvillage.com/)
- [CanSecWest](https://cansecwest.com/) / [Black Hat](https://www.blackhat.com/) automotive tracks.
- [escar conference](https://www.escar.info/) — embedded security in cars.

## Communities
- [r/CarHacking](https://www.reddit.com/r/CarHacking/)
- [ipvm-community](https://github.com/iDoka/awesome-canbus) — Awesome CAN Bus (sister list).

---

### Contributing
Fork → add your entry under the right heading (one line, `[name](url) — short desc`)
→ open a PR. Keep it legal-research / education oriented.
