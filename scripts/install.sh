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
apt-get install -y -qq ca-certificates curl git build-essential golang-go sqlite3 libcap2-bin openssl python3 gzip > /dev/null

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

# Ensure the main-controller Mihomo binary exists before installing the panel.
# An already working installation is preserved; this bootstrap never overwrites it.
MIHOMO_DIR="/opt/mihomo"
MIHOMO_BIN="$MIHOMO_DIR/mihomo"
ensure_mihomo() {
  if [[ -e "$MIHOMO_BIN" ]]; then
    if [[ -x "$MIHOMO_BIN" ]] && "$MIHOMO_BIN" -v >/tmp/s5m-mihomo-version.txt 2>&1; then
      echo "✅ 检测到主控 Mihomo 已安装：$(head -n 1 /tmp/s5m-mihomo-version.txt)"
      echo "   按要求跳过内核下载与替换。"
      return 0
    fi
    echo "❌ 检测到 $MIHOMO_BIN 已存在，但无法成功执行版本检查。" >&2
    echo "   为避免覆盖现有内核，安装器不会自动替换；请先检查文件和权限。" >&2
    return 1
  fi

  local arch asset_url release_tag tmpdir archive candidate
  case "$(uname -m)" in
    x86_64|amd64) arch="amd64" ;;
    aarch64|arm64) arch="arm64" ;;
    *)
      echo "❌ 当前架构 $(uname -m) 暂不支持自动安装 Mihomo（仅支持 amd64/arm64）。" >&2
      return 1
      ;;
  esac

  echo "ℹ️ 未检测到主控 Mihomo，正在查询 GitHub 最新稳定版..."
  local release_json
  release_json="$(curl -fsSL --retry 3 --connect-timeout 10 --max-time 60 \
    -H 'Accept: application/vnd.github+json' \
    -H 'X-GitHub-Api-Version: 2022-11-28' \
    https://api.github.com/repos/MetaCubeX/mihomo/releases/latest)" || {
      echo "❌ 无法读取 Mihomo 最新稳定版发布信息。" >&2
      return 1
    }

  read -r release_tag asset_url < <(python3 -c '
import json, re, sys
d=json.load(sys.stdin)
tag=d.get("tag_name", "")
assets=d.get("assets", [])
arch=sys.argv[1]
# Release naming differs by architecture. amd64 has explicit CPU baseline variants;
# select the portable x86-64-v1 build. arm64 uses the unqualified asset name.
if arch == "amd64":
    expected = f"mihomo-linux-amd64-v1-{tag}.gz" if tag else ""
elif arch == "arm64":
    expected = f"mihomo-linux-arm64-{tag}.gz" if tag else ""
else:
    expected = ""
matches=[a.get("browser_download_url", "") for a in assets
         if a.get("name", "") == expected and a.get("browser_download_url", "").startswith("https://github.com/")]
if not tag or not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", tag) or len(matches) != 1:
    print("", "")
else:
    print(tag, matches[0])
' "$arch" <<<"$release_json")

  if [[ -z "$release_tag" || -z "$asset_url" ]]; then
    echo "❌ 最新稳定版中未找到名称与发行标签严格匹配的 Linux $arch 二进制包。" >&2
    echo "   请检查 GitHub Releases 资产命名；为避免下载错误架构或变体，安装器不会猜测资产。" >&2
    python3 -c '
import json, sys
d=json.load(sys.stdin)
print("   发行标签:", d.get("tag_name", "(缺失)"))
print("   可用 Linux 资产:")
for a in d.get("assets", []):
    n=a.get("name", "")
    if n.startswith("mihomo-linux-"):
        print("    -", n)
' <<<"$release_json" >&2
    return 1
  fi

  tmpdir="$(mktemp -d)"
  trap 'rm -rf "${tmpdir:-}"' RETURN
  archive="$tmpdir/mihomo.gz"
  candidate="$tmpdir/mihomo"
  echo "⬇️ 正在下载 Mihomo $release_tag（linux/$arch）..."
  if ! curl -fL --retry 3 --connect-timeout 10 --max-time 180 "$asset_url" -o "$archive"; then
    echo "❌ Mihomo 下载失败。" >&2
    return 1
  fi
  if ! gzip -t "$archive" || ! gzip -dc "$archive" > "$candidate"; then
    echo "❌ Mihomo 压缩包校验或解压失败。" >&2
    return 1
  fi
  chmod 0755 "$candidate"
  if ! "$candidate" -v >/tmp/s5m-mihomo-candidate-version.txt 2>&1; then
    echo "❌ 下载的 Mihomo 二进制无法运行，拒绝安装。" >&2
    cat /tmp/s5m-mihomo-candidate-version.txt >&2 || true
    return 1
  fi

  install -d -o root -g root -m 0755 "$MIHOMO_DIR"
  install -o root -g root -m 0755 "$candidate" "$MIHOMO_BIN"
  if ! "$MIHOMO_BIN" -v >/tmp/s5m-mihomo-version.txt 2>&1; then
    echo "❌ Mihomo 安装后版本检查失败。" >&2
    rm -f "$MIHOMO_BIN"
    return 1
  fi
  echo "✅ 已安装主控 Mihomo：$(head -n 1 /tmp/s5m-mihomo-version.txt)"
}
ensure_mihomo

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
  ADMIN_PASS="$(openssl rand -hex 24)"
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

# Backfill required S5M paths/address for older environment files as well.
# Keep existing user choices intact; missing values use the native-install defaults.
for entry in \
  "S5M_ADDR=:80" \
  "S5M_DB=$DB_DIR/s5m.db" \
  "S5M_CONFIG=$DB_DIR/config.yaml" \
  "S5M_BACKUP=$DB_DIR/backups" \
  "S5M_ADMIN_USER=admin"; do
  key="${entry%%=*}"
  if ! grep -qE "^${key}=" "$ENV_FILE"; then
    printf '%s\n' "$entry" >> "$ENV_FILE"
  fi
done
chmod 0600 "$ENV_FILE"

# Keep the main Mihomo controller API and its systemd service aligned with the
# environment used by S5M-Server. Preserve existing values, but backfill keys that
# may be absent from older installations before reading them under `set -e`.
if ! grep -qE '^MIHOMO_API=' "$ENV_FILE"; then
  printf '\nMIHOMO_API=http://127.0.0.1:8088\n' >> "$ENV_FILE"
fi
if ! grep -qE '^MIHOMO_SECRET=' "$ENV_FILE"; then
  printf '\nMIHOMO_SECRET=%s\n' "$(openssl rand -hex 24)" >> "$ENV_FILE"
fi
chmod 0600 "$ENV_FILE"
MIHOMO_API_URL="$(awk -F= '/^MIHOMO_API=/ { sub(/^[^=]*=/, ""); value=$0 } END { print value }' "$ENV_FILE")"
MIHOMO_PORT="$(printf '%s' "$MIHOMO_API_URL" | sed -nE 's#^https?://[^/:]+:([0-9]+)(/.*)?$#\1#p')"
MIHOMO_PORT="${MIHOMO_PORT:-8088}"
MIHOMO_SECRET_VALUE="$(awk -F= '/^MIHOMO_SECRET=/ { sub(/^[^=]*=/, ""); value=$0 } END { print value }' "$ENV_FILE")"
if [[ ! -s "$DB_DIR/config.yaml" ]]; then
  install -d -o root -g root -m 0750 "$DB_DIR"
  cat > "$DB_DIR/config.yaml" <<MIHOMO_CONFIG_EOF
mode: rule
mixed-port: 8080
log-level: info
external-controller: 127.0.0.1:${MIHOMO_PORT}
secret: "${MIHOMO_SECRET_VALUE}"
allow-lan: true
find-process-mode: "off"
proxies: []
rules:
  - MATCH,DIRECT
MIHOMO_CONFIG_EOF
  chmod 0600 "$DB_DIR/config.yaml"
fi
# The S5M service runs as s5m-server and must read/replace the active config
# during publish/rollback. Keep it private while granting ownership to that service.
chown s5m-server:s5m-server "$DB_DIR/config.yaml"
chmod 0600 "$DB_DIR/config.yaml"

cat > /etc/systemd/system/mihomo.service <<MIHOMO_SERVICE_EOF
[Unit]
Description=Mihomo Proxy Core (S5M main controller)
After=network-online.target
Wants=network-online.target
ConditionPathExists=$MIHOMO_BIN
ConditionPathExists=$DB_DIR/config.yaml

[Service]
Type=simple
User=root
Group=root
ExecStart=$MIHOMO_BIN -d $DB_DIR -f $DB_DIR/config.yaml
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ReadWritePaths=$DB_DIR
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE
LockPersonality=true
RestrictSUIDSGID=true

[Install]
WantedBy=multi-user.target
MIHOMO_SERVICE_EOF

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
SupplementaryGroups=systemd-journal
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
systemctl enable mihomo
if ! systemctl restart mihomo; then
  echo "❌ 主控 Mihomo 服务启动失败。请检查：journalctl -u mihomo -n 100 --no-pager" >&2
  systemctl status mihomo --no-pager -l >&2 || true
  exit 1
fi
systemctl enable "$UNIT"
if ! systemctl restart "$UNIT"; then
  echo "❌ S5M-Server 服务启动失败。请检查：journalctl -u $UNIT -n 100 --no-pager" >&2
  systemctl status "$UNIT" --no-pager -l >&2 || true
  exit 1
fi

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
