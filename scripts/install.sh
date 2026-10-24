#!/usr/bin/env bash
set -Eeuo pipefail

APP="S5M-Server"
UNIT="s5m-server"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if [[ -f "$ROOT/source/main.go" ]]; then SRC="$ROOT/source"; elif [[ -f "$ROOT/main.go" ]]; then SRC="$ROOT"; else echo "❌ 源码目录不完整" >&2; exit 1; fi

ENV_FILE="/etc/s5m-server.env"
OLD_ENV_FILE="/etc/s5m-server/server.env"
DB_DIR="/var/lib/s5m-server"
BIN="/opt/S5M-Server/S5M-Server"

[[ $EUID -eq 0 ]] || { echo "请使用 sudo bash scripts/install.sh" >&2; exit 1; }

if systemctl is-active --quiet s5m-next 2>/dev/null || [[ -x /opt/s5m-next/bin/s5m-next ]]; then
  echo "检测到现有 S5M Next 部署。为防止覆盖数据库/服务，安装器已停止。" >&2
  exit 2
fi

for f in web/index.html web/app.js web/vendor/vue.global.prod.js web/vendor/element-plus.full.js web/vendor/element-plus.css; do
  if [[ ! -s "$SRC/$f" ]]; then echo "❌ 缺少前端资源: $SRC/$f" >&2; exit 1; fi
done

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq ca-certificates curl git build-essential golang-go sqlite3 libcap2-bin > /dev/null

# === 新增：智能处理端口占用 ===
PORT_TO_USE=$(grep -oP 'S5M_ADDR=:\K[0-9]+' "$ENV_FILE" 2>/dev/null || echo "80")
PORT_TO_USE=${PORT_TO_USE:-80}

if ss -lntp 2>/dev/null | grep -q ":${PORT_TO_USE} "; then
    echo "⚠️ 端口 ${PORT_TO_USE} 被占用，正在检查是否是旧的 s5m-server 进程..."
    OLD_PID=$(ss -lntp | grep ":${PORT_TO_USE} " | grep -oP 'pid=\K[0-9]+' | head -n1)
    OLD_CMD=$(ps -p "$OLD_PID" -o comm= 2>/dev/null || true)
    
    if [[ "$OLD_CMD" == *"S5M-Server"* ]]; then
        echo "🔄 检测到旧版 S5M-Server 正在运行 (PID: $OLD_PID)，自动停止以释放端口..."
        systemctl stop s5m-server || kill "$OLD_PID" || true
        sleep 1
    else
        echo "❌ 端口 ${PORT_TO_USE} 被其他程序 ($OLD_CMD, PID: $OLD_PID) 占用！" >&2
        echo "请手动停止该程序，或修改 $ENV_FILE 中的端口后重试。" >&2
        exit 1
    fi
fi
# ==============================

if ! getent passwd s5m-server >/dev/null; then useradd --system --home-dir "$DB_DIR" --shell /usr/sbin/nologin s5m-server; fi
install -d -o s5m-server -g s5m-server -m 0750 "$DB_DIR" "$DB_DIR/backups"
install -d -m 0755 /opt/S5M-Server /opt/S5M-Server/source
chown -R s5m-server:s5m-server "$DB_DIR"
chmod -R go-rwx "$DB_DIR"

STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP="/var/backups/s5m-server-install-$STAMP"
install -d -m 0700 "$BACKUP"
[[ -f "$DB_DIR/s5m.db" ]] && sqlite3 "$DB_DIR/s5m.db" ".backup '$BACKUP/s5m.db'"
[[ -f "$BIN" ]] && cp -a "$BIN" "$BACKUP/S5M-Server.bin"

if [[ -f "$OLD_ENV_FILE" && ! -f "$ENV_FILE" ]]; then mv "$OLD_ENV_FILE" "$ENV_FILE"
elif [[ -f "$OLD_ENV_FILE" && -f "$ENV_FILE" ]]; then mv "$OLD_ENV_FILE" "$OLD_ENV_FILE.unused.$STAMP"; fi

if [[ ! -f "$ENV_FILE" ]]; then
  ADMIN_PASS="$(tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 32)"
  cat > "$ENV_FILE" <<ENVEOF
S5M_ADDR=:80
S5M_DB=$DB_DIR/s5m.db
S5M_CONFIG=$DB_DIR/config.yaml
S5M_BACKUP=$DB_DIR/backups
S5M_ADMIN_USER=admin
S5M_ADMIN_PASSWORD=$ADMIN_PASS
S5M_JWT_SECRET=$(openssl rand -hex 32)
MIHOMO_API=http://127.0.0.1:8088
MIHOMO_SECRET=$(openssl rand -hex 24)
MIHOMO_CONFIG_PATH=$DB_DIR/config.yaml
ENVEOF
  chmod 0600 "$ENV_FILE"
  printf '用户名: admin\n密码: %s\n' "$ADMIN_PASS" > /root/S5M-Server-credentials.txt
  chmod 0600 /root/S5M-Server-credentials.txt
fi

rm -rf /opt/S5M-Server/source
install -d -m 0755 /opt/S5M-Server/source
cp -a "$SRC/." /opt/S5M-Server/source/

cd /opt/S5M-Server/source
go mod download
go test ./... || { echo "❌ go test 失败，可用 SKIP_TEST=1 bash scripts/install.sh 跳过" >&2; exit 1; }
go build -trimpath -ldflags='-s -w' -o /opt/S5M-Server/S5M-Server.new .
install -o root -g root -m 0755 /opt/S5M-Server/S5M-Server.new "$BIN"
rm -f /opt/S5M-Server/S5M-Server.new
setcap cap_net_bind_service=+ep "$BIN" || true

cat > /etc/systemd/system/s5m-server.service <<SERVICEEOF
[Unit]
Description=S5M-Server Control Panel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=s5m-server
Group=s5m-server
EnvironmentFile=$ENV_FILE
ExecStart=$BIN
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$DB_DIR
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
LockPersonality=true
RestrictSUIDSGID=true

[Install]
WantedBy=multi-user.target
SERVICEEOF

systemctl daemon-reload
systemctl enable "$UNIT"
systemctl restart "$UNIT"

ADDR="$(grep -E '^S5M_ADDR=' "$ENV_FILE" | cut -d= -f2-)"
PORT="${ADDR##*:}"
[[ -z "$PORT" ]] && PORT=80

HEALTH_OK=0
for _ in $(seq 1 20); do
  if curl -fsS --max-time 2 "http://127.0.0.1:${PORT}/api/v1/health" >/tmp/s5m-server-health.json 2>/dev/null; then HEALTH_OK=1; break; fi
  sleep 1
done

if [[ "$HEALTH_OK" -ne 1 ]] || ! grep -q '"status":"ok"' /tmp/s5m-server-health.json 2>/dev/null; then
  echo "❌ 健康检查失败（端口 $PORT），正在回滚二进制..." >&2
  systemctl stop "$UNIT" || true
  if [[ -f "$BACKUP/S5M-Server.bin" ]]; then
    install -o root -g root -m 0755 "$BACKUP/S5M-Server.bin" "$BIN"
    setcap cap_net_bind_service=+ep "$BIN" 2>/dev/null || true
    systemctl start "$UNIT"
  fi
  exit 1
fi

echo "✅ S5M-Server 安装成功"
echo "   服务: $UNIT（端口 $PORT）"
echo "   健康: $(cat /tmp/s5m-server-health.json)"
