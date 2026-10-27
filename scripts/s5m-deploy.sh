#!/usr/bin/env bash
# S5M Agent 一键部署（全新安装 / 重装；仅清理 S5M Agent 自身资源）
set -uo pipefail

IMAGE_NAME="s5m-agent-linux-amd64.tar"
IMAGE_SRC="s5m-agent:amd64-test"
IMAGE_LOCAL="s5m-agent:local"
CONTAINER="s5m-agent"
DATA_DIR="/opt/s5m-agent/data"
PORT_WEB=80
PORT_PROXY=7890

log()  { echo -e "\033[32m[+]\033[0m $*"; }
warn() { echo -e "\033[33m[!]\033[0m $*"; }
die()  { echo -e "\033[31m[x]\033[0m $*"; exit 1; }

# ---------- 自动探测镜像文件路径 ----------
find_image_tar() {
  local dirs=("$PWD" "$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)" /root /tmp)
  local d
  for d in "${dirs[@]}"; do
    [ -n "$d" ] && [ -f "$d/$IMAGE_NAME" ] && { echo "$d/$IMAGE_NAME"; return 0; }
  done
  return 1
}

if [ -z "${IMAGE_TAR:-}" ]; then
  IMAGE_TAR="$(find_image_tar)" || IMAGE_TAR=""
fi
[ -n "$IMAGE_TAR" ] && [ -f "$IMAGE_TAR" ] || \
  die "未找到 $IMAGE_NAME，已查找: PWD=$PWD、脚本目录、/root、/tmp。可手动指定: IMAGE_TAR=/path/to/$IMAGE_NAME $0"
log "使用镜像文件: $IMAGE_TAR"

[ "$(id -u)" -eq 0 ] || die "请用 root 运行"

# ---------- 1. 确保 Docker 可用 ----------
if ! command -v docker >/dev/null 2>&1 || ! docker version >/dev/null 2>&1; then
  log "未检测到可用 Docker，正在安装 docker.io ..."
  apt update || die "apt update 失败"
  apt install -y docker.io || die "docker.io 安装失败"
fi
systemctl enable --now docker >/dev/null 2>&1 || true

# ---------- 2. 仅清理 S5M Agent 自身资源 ----------
# 不删除其他应用的容器、镜像、卷或网络。
log "清理旧 S5M Agent 容器 ..."
docker rm -f "$CONTAINER" 2>/dev/null || true

log "清理 S5M Agent 相关镜像 ..."
while IFS= read -r image_id; do
  [ -n "$image_id" ] && docker rmi -f "$image_id" 2>/dev/null || true
done < <(docker images --format '{{.Repository}}:{{.Tag}} {{.ID}}' | awk '$1 ~ /^s5m-agent:/ {print $2}' | sort -u)

# ---------- 3. 删除 S5M Agent 数据目录（不保留应用数据） ----------
log "删除数据目录 /opt/s5m-agent ..."
rm -rf /opt/s5m-agent

# ---------- 4. 确保 Docker / containerd 服务运行 ----------
# 不清空 /var/lib/containerd，避免破坏宿主机上其他容器的数据。
log "检查并重启 containerd / Docker ..."
systemctl daemon-reload
systemctl restart containerd || die "containerd 启动失败"
sleep 2
systemctl restart docker || die "Docker 启动失败"
sleep 2

systemctl is-active --quiet containerd || die "containerd 启动失败"
systemctl is-active --quiet docker     || die "Docker 启动失败"

# ---------- 5. 加载镜像（失败自动重试 3 次） ----------
log "加载镜像 $IMAGE_TAR ..."
ok=0
for i in 1 2 3; do
  if docker load -i "$IMAGE_TAR"; then ok=1; break; fi
  warn "第 $i 次加载失败，重启 containerd/docker 后重试 ..."
  systemctl restart containerd docker
  sleep 3
done
if [ "$ok" -ne 1 ]; then
  warn "最近 containerd 日志："
  journalctl -u containerd -n 30 --no-pager
  die "docker load 失败，请检查磁盘空间 / 权限"
fi

docker tag "$IMAGE_SRC" "$IMAGE_LOCAL" 2>/dev/null || {
  src="$(docker images --format '{{.Repository}}:{{.Tag}}' | grep '^s5m-agent' | head -n1 || true)"
  [ -n "$src" ] && docker tag "$src" "$IMAGE_LOCAL" || die "找不到 s5m-agent 镜像"
}

# ---------- 6. 重建数据目录 ----------
log "重建数据目录 $DATA_DIR ..."
install -d -m 0700 "$DATA_DIR"

# ---------- 7. 启动容器 ----------
log "启动容器 $CONTAINER ..."
docker run -d \
  --name "$CONTAINER" \
  --restart unless-stopped \
  -p "${PORT_WEB}:80" \
  -p "${PORT_PROXY}:7890" \
  -v "$DATA_DIR":/data \
  "$IMAGE_LOCAL" || die "容器启动失败"

sleep 3

# ---------- 8. 验证 ----------
echo
log "===== 部署结果 ====="
docker ps --filter "name=$CONTAINER" --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
echo
log "容器日志（末 20 行）："
docker logs --tail 20 "$CONTAINER" 2>&1 || true
echo
log "machine-id："
curl -fsS "http://127.0.0.1:${PORT_WEB}/api/machine-id" || warn "API 暂无响应，稍等几秒再试"
echo
log "Web 探活："
curl -sI --max-time 5 "http://127.0.0.1:${PORT_WEB}" | head -n1 || warn "80 端口未响应"
echo
log "完成。浏览器访问： http://<服务器公网IP>"
warn "请确认安全组/防火墙按需放行 ${PORT_WEB} 和 ${PORT_PROXY}"

echo
log "进入实时日志模式：docker logs -f $CONTAINER"
warn "按 Ctrl+C 退出日志查看；这不会停止或删除容器。"
docker logs -f "$CONTAINER"
