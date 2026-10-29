#!/usr/bin/env bash
# S5M Agent 一键部署：仅替换本项目容器，保护其他 Docker 资源，支持 TUN 模式
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

# HTTP checks support curl, wget, or Python so minimal Ubuntu/Debian images work.
http_get() {
  local url="$1"
  if command -v curl >/dev/null 2>&1; then
    curl -fsS --max-time 5 "$url"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO- --timeout=5 "$url"
  elif command -v python3 >/dev/null 2>&1; then
    python3 - "$url" <<'PYHTTP'
import sys
from urllib.request import urlopen
try:
    with urlopen(sys.argv[1], timeout=5) as response:
        sys.stdout.buffer.write(response.read())
except Exception as exc:
    print(f"HTTP request failed: {exc}", file=sys.stderr)
    sys.exit(1)
PYHTTP
  else
    warn "无法执行 HTTP 检查：curl、wget、python3 均不可用"
    return 127
  fi
}

http_head() {
  local url="$1"
  if command -v curl >/dev/null 2>&1; then
    curl -sSI --max-time 5 "$url"
  elif command -v wget >/dev/null 2>&1; then
    wget --spider -S --timeout=5 "$url" 2>&1
  elif command -v python3 >/dev/null 2>&1; then
    python3 - "$url" <<'PYHTTP'
import sys
from urllib.request import Request, urlopen
try:
    with urlopen(Request(sys.argv[1], method="HEAD"), timeout=5) as response:
        print(f"HTTP/{response.version} {response.status} {response.reason}")
except Exception as exc:
    print(f"HTTP HEAD failed: {exc}", file=sys.stderr)
    sys.exit(1)
PYHTTP
  else
    warn "无法执行 HTTP 检查：curl、wget、python3 均不可用"
    return 127
  fi
}

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

# ---------- 2. 加载新镜像 ----------
# 不清理旧镜像、不删除卷、不重启 Docker/containerd。
log "加载镜像 $IMAGE_TAR ..."
ok=0
for i in 1 2 3; do
  if docker load -i "$IMAGE_TAR"; then ok=1; break; fi
  warn "第 $i 次加载失败，等待 3 秒后重试（不会重启 Docker 服务）..."
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

# ---------- 3. 保留持久化数据 ----------
# 不删除 /opt/s5m-agent；其中可能保存机器标识和配置。
log "确保持久化目录存在：$DATA_DIR"
install -d -m 0700 "$DATA_DIR"

# ---------- 4. 仅替换 S5M Agent 容器 ----------
log "仅移除旧 S5M Agent 容器（不删除数据目录）..."
docker rm -f "$CONTAINER" 2>/dev/null || true

# ---------- 5. 启动容器 ----------
log "启动容器 $CONTAINER ..."
docker run -d \
  --name "$CONTAINER" \
  --restart unless-stopped \
  --cap-add=NET_ADMIN \
  --device=/dev/net/tun:/dev/net/tun \
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
http_get "http://127.0.0.1:${PORT_WEB}/api/machine-id" || warn "API 暂无响应或缺少 HTTP 客户端；请检查容器日志和端口"
echo
log "Web 探活："
http_head "http://127.0.0.1:${PORT_WEB}" | head -n1 || warn "80 端口未响应或缺少 HTTP 客户端"
echo
log "完成。浏览器访问： http://<服务器公网IP>"
warn "请确认安全组/防火墙按需放行 ${PORT_WEB} 和 ${PORT_PROXY}"

echo
