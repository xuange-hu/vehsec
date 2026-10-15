#!/usr/bin/env bash
# vehsec — Linux 虚拟车实验室一键环境 (vcan0 + can-utils + ICSim + UDSim)
# 用法: bash scripts/setup_vcan.sh          # 建 vcan0 并启动 ICSim
#       bash scripts/setup_vcan.sh stop     # 收尾清理
set -euo pipefail

IFACE="${VEHSEC_CAN_IFACE:-vcan0}"

log() { printf '\033[0;36m[vehsec]\033[0m %s\n' "$*"; }

stop() {
  log "停止 ICSim / UDSim 并移除 $IFACE"
  pkill -f icsim 2>/dev/null || true
  pkill -f udsim 2>/dev/null || true
  sudo ip link set "$IFACE" down 2>/dev/null || true
  sudo ip link del "$IFACE" 2>/dev/null || true
  log "已清理"
  exit 0
}
[ "${1:-}" = "stop" ] && stop

# 1) 虚拟 CAN 接口
log "加载 vcan 模块并创建 $IFACE"
sudo modprobe vcan
sudo ip link add dev "$IFACE" type vcan 2>/dev/null || log "$IFACE 已存在"
sudo ip link set up "$IFACE"
ip -details link show "$IFACE" | head -3

# 2) can-utils
if ! command -v candump >/dev/null 2>&1; then
  log "安装 can-utils"
  if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update -qq && sudo apt-get install -y can-utils
  elif command -v dnf >/dev/null 2>&1; then
    sudo dnf install -y can-utils
  else
    log "请手动安装 can-utils（需 candump / cansend / cangen）"
  fi
fi

# 3) ICSim（优先 Docker，无 Docker 则提示源码编译）
if command -v docker >/dev/null 2>&1; then
  log "用 Docker 启动 ICSim（EFeru/ICSim-docker）"
  docker run -d --name vehsec-icsim --network=host \
    -e DISPLAY="${DISPLAY:-:0}" -v /tmp/.X11-unix:/tmp/.X11-unix \
    eferu/icsim:latest >/dev/null 2>&1 \
    || log "Docker 镜像拉取失败，改用源码方式（见下）"
  log "若镜像不可用，源码方式："
else
  log "未检测到 Docker，使用源码方式："
fi
cat <<'SRC'
  git clone https://github.com/zombieCraig/ICSim /opt/ICSim
  cd /opt/ICSim && sudo apt-get install -y libsdl2-dev libsdl2-image-dev && make
  ./icsim vcan0 &      # 仪表盘窗口
  ./controls vcan0 &   # 油门/转向控制面板
SRC

# 4) UDSim（虚拟 ECU，可选）
cat <<'UDS'
  可选：git clone https://github.com/zombieCraig/UDSim && cd UDSim && cmake . && make
        ./udsim vcan0
UDS

# 5) 验证
log "抓包验证（Ctrl+C 停止）：candump $IFACE"
log "vehsec 演示："
cat <<'CMD'
  export VEHSEC_CAN_IFACE=socketcan VEHSEC_CAN_CHANNEL=vcan0
  vehsec icsim demo --kmh 250        # 车速篡改 + 车门锁定
  vehsec can fuzz --ids 0x1A4,0x19B --rounds 50
CMD
log "完成。用 bash scripts/setup_vcan.sh stop 清理。"
