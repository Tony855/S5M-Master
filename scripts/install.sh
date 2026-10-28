#!/usr/bin/env bash
set -Eeuo pipefail

APP="S5M-Server"
UNIT="s5m-server"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if [[ -f "$ROOT/source/main.go" ]]; then SRC="$ROOT/source"; elif [[ -f "$ROOT/main.go" ]]; then SRC="$ROOT"; else echo "❌ 源码目录不完整" >&2; exit 1; fi

ENV_FILE="/etc/s5m-server.env"
OLD_ENV_FILE="/etc/s5m-server/server.env"
DB_DIR="/var/lib/s5m-server"
# HTTPS is checked before prompting: preserve a working certificate and virtual host.
S5M_DOMAIN="${S5M_DOMAIN:-}"
S5M_EMAIL="${S5M_EMAIL:-}"
HTTPS_ALREADY_CONFIGURED=0
NGINX_SITE="/etc/nginx/sites-available/s5m-server"
NGINX_ENABLED="/etc/nginx/sites-enabled/s5m-server"
if [[ -n "${1:-}" && -z "$S5M_DOMAIN" ]]; then S5M_DOMAIN="$1"; fi

[[ $EUID -eq 0 ]] || { echo "请使用 sudo bash scripts/install.sh" >&2; exit 1; }

# Reuse a working TLS virtual host and certificate without rewriting or reissuing them.
if [[ -f "$NGINX_SITE" ]] &&
   grep -Eq 'listen[[:space:]]+443[[:space:]]+ssl' "$NGINX_SITE"; then
  detected_domain="$(awk '/^[[:space:]]*server_name[[:space:]]/ { for (i=2;i<=NF;i++) if ($i !~ /;/) {gsub(/;/,"",$i); if ($i != "_" && $i !~ /^\$/) {print $i; exit}} }' "$NGINX_SITE")"
  cert_path="$(sed -nE 's/^[[:space:]]*ssl_certificate[[:space:]]+([^;]+);.*/\1/p' "$NGINX_SITE" | head -n1)"
  key_path="$(sed -nE 's/^[[:space:]]*ssl_certificate_key[[:space:]]+([^;]+);.*/\1/p' "$NGINX_SITE" | head -n1)"
  if [[ -n "$detected_domain" && -s "$cert_path" && -s "$key_path" ]] &&
     command -v nginx >/dev/null 2>&1 && nginx -t >/dev/null 2>&1 &&
     { [[ -z "$S5M_DOMAIN" ]] || [[ "$S5M_DOMAIN" == "$detected_domain" ]]; }; then
    S5M_DOMAIN="$detected_domain"
    HTTPS_ALREADY_CONFIGURED=1
    echo "🔐 检测到现有 HTTPS 配置和证书：$S5M_DOMAIN，跳过重复配置。"
  fi
fi

# Ask interactively only when HTTPS is not already configured. Blank domain keeps HTTP-only mode.
if [[ -z "$S5M_DOMAIN" && "$HTTPS_ALREADY_CONFIGURED" -eq 0 && -t 0 ]]; then
  echo "尚未检测到可用的 S5M HTTPS 配置。"
  read -r -p "请输入面板域名（留空则暂不配置 HTTPS）: " S5M_DOMAIN
  if [[ -n "$S5M_DOMAIN" ]]; then
    read -r -p "Let's Encrypt 邮箱 [v2wallid@gmail.com]: " S5M_EMAIL
    S5M_EMAIL="${S5M_EMAIL:-v2wallid@gmail.com}"
  fi
fi

if [[ -n "$S5M_DOMAIN" && ! "$S5M_DOMAIN" =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$ ]]; then
  echo "❌ S5M_DOMAIN 格式无效：$S5M_DOMAIN" >&2
  exit 1
fi
if [[ -n "$S5M_DOMAIN" && "$HTTPS_ALREADY_CONFIGURED" -eq 0 && -z "$S5M_EMAIL" ]]; then
  S5M_EMAIL="v2wallid@gmail.com"
fi
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
apt_packages=(ca-certificates curl git build-essential golang-go sqlite3 libcap2-bin openssl python3 gzip)
if [[ -n "$S5M_DOMAIN" ]]; then apt_packages+=(nginx certbot python3-certbot-nginx); fi
apt-get install -y -qq "${apt_packages[@]}" > /dev/null

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
    elif [[ -n "$S5M_DOMAIN" && "$OLD_CMD" == *"nginx"* ]]; then
        echo "ℹ️ 检测到现有 Nginx，保留其服务并添加 S5M 域名虚拟主机。"
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
# Snapshot mutable files before any migration or generated defaults are written.
# Marker files let rollback distinguish absent files from files that were backed up.
if [[ -e "$ENV_FILE" ]]; then cp -a "$ENV_FILE" "$BACKUP/s5m-server.env"; else : > "$BACKUP/env-file-absent"; fi
if [[ -e "$OLD_ENV_FILE" ]]; then cp -a "$OLD_ENV_FILE" "$BACKUP/legacy-server.env"; else : > "$BACKUP/legacy-env-absent"; fi
if [[ -e "$DB_DIR/config.yaml" ]]; then cp -a "$DB_DIR/config.yaml" "$BACKUP/config.yaml"; else : > "$BACKUP/config-file-absent"; fi
if [[ -f "$BIN" ]]; then cp -a "$BIN" "$BACKUP/S5M-Server.bin"; else : > "$BACKUP/server-bin-absent"; fi
if [[ -f /etc/systemd/system/s5m-server.service ]]; then
  cp -a /etc/systemd/system/s5m-server.service "$BACKUP/s5m-server.service"
else
  : > "$BACKUP/server-service-absent"
fi
if [[ -f /etc/systemd/system/mihomo.service ]]; then
  cp -a /etc/systemd/system/mihomo.service "$BACKUP/mihomo.service"
else
  : > "$BACKUP/mihomo-service-absent"
fi

# When HTTPS is requested, snapshot both the Nginx site file and its enabled
# symlink before any changes. A failed Certbot run can otherwise leave a broken
# or partially TLS-configured virtual host behind after the application rolls back.
if [[ -n "$S5M_DOMAIN" && "$HTTPS_ALREADY_CONFIGURED" -eq 0 ]]; then
  if [[ -e "$NGINX_SITE" || -L "$NGINX_SITE" ]]; then
    cp -a "$NGINX_SITE" "$BACKUP/nginx-s5m-server.conf"
  else
    : > "$BACKUP/nginx-site-absent"
  fi
  if [[ -e "$NGINX_ENABLED" || -L "$NGINX_ENABLED" ]]; then
    cp -a "$NGINX_ENABLED" "$BACKUP/nginx-s5m-server.enabled"
  else
    : > "$BACKUP/nginx-enabled-absent"
  fi
fi

# Shared rollback for failures after the snapshot has been created. The database
# backup is deliberately not copied over a live DB; preserve it for controlled recovery.
rollback_install() {
  local reason="${1:-unknown failure}"
  echo "❌ 安装失败：${reason}，正在恢复安装前的文件和服务配置..." >&2
  systemctl stop "$UNIT" 2>/dev/null || true
  if [[ -f "$BACKUP/S5M-Server.bin" ]]; then
    install -o root -g root -m 0755 "$BACKUP/S5M-Server.bin" "$BIN"
    setcap cap_net_bind_service=+ep "$BIN" 2>/dev/null || true
  elif [[ -f "$BACKUP/server-bin-absent" ]]; then
    rm -f "$BIN"
  fi
  if [[ -f "$BACKUP/s5m-server.service" ]]; then
    cp -a "$BACKUP/s5m-server.service" /etc/systemd/system/s5m-server.service
  elif [[ -f "$BACKUP/server-service-absent" ]]; then
    rm -f /etc/systemd/system/s5m-server.service
  fi
  if [[ -f "$BACKUP/mihomo.service" ]]; then
    cp -a "$BACKUP/mihomo.service" /etc/systemd/system/mihomo.service
  elif [[ -f "$BACKUP/mihomo-service-absent" ]]; then
    rm -f /etc/systemd/system/mihomo.service
  fi
  if [[ -f "$BACKUP/s5m-server.env" ]]; then cp -a "$BACKUP/s5m-server.env" "$ENV_FILE"; elif [[ -f "$BACKUP/env-file-absent" ]]; then rm -f "$ENV_FILE"; fi
  if [[ -f "$BACKUP/legacy-server.env" ]]; then install -d -m 0750 "$(dirname "$OLD_ENV_FILE")"; cp -a "$BACKUP/legacy-server.env" "$OLD_ENV_FILE"; elif [[ -f "$BACKUP/legacy-env-absent" ]]; then rm -f "$OLD_ENV_FILE"; fi
  if [[ -f "$BACKUP/config.yaml" ]]; then cp -a "$BACKUP/config.yaml" "$DB_DIR/config.yaml"; elif [[ -f "$BACKUP/config-file-absent" ]]; then rm -f "$DB_DIR/config.yaml"; fi
  if [[ -n "$S5M_DOMAIN" ]]; then
    if [[ -f "$BACKUP/nginx-s5m-server.conf" ]]; then
      rm -f "$NGINX_SITE"
      cp -a "$BACKUP/nginx-s5m-server.conf" "$NGINX_SITE"
    elif [[ -f "$BACKUP/nginx-site-absent" ]]; then
      rm -f "$NGINX_SITE"
    fi
    if [[ -e "$BACKUP/nginx-s5m-server.enabled" || -L "$BACKUP/nginx-s5m-server.enabled" ]]; then
      rm -f "$NGINX_ENABLED"
      cp -a "$BACKUP/nginx-s5m-server.enabled" "$NGINX_ENABLED"
    elif [[ -f "$BACKUP/nginx-enabled-absent" ]]; then
      rm -f "$NGINX_ENABLED"
    fi
    if command -v nginx >/dev/null 2>&1 && nginx -t; then
      systemctl reload nginx 2>/dev/null || true
    fi
  fi
  systemctl daemon-reload
  if [[ -f "$BACKUP/mihomo.service" ]]; then
    systemctl restart mihomo || echo "❌ Mihomo 回滚启动失败，请检查 journalctl -u mihomo" >&2
  else
    systemctl stop mihomo 2>/dev/null || true
  fi
  if [[ -f "$BACKUP/S5M-Server.bin" ]]; then
    systemctl start "$UNIT" || echo "❌ 旧版 S5M-Server 启动失败，请检查 journalctl -u $UNIT" >&2
  else
    systemctl stop "$UNIT" 2>/dev/null || true
  fi
}

if [[ -f "$OLD_ENV_FILE" && ! -f "$ENV_FILE" ]]; then mv "$OLD_ENV_FILE" "$ENV_FILE"
elif [[ -f "$OLD_ENV_FILE" && -f "$ENV_FILE" ]]; then mv "$OLD_ENV_FILE" "$OLD_ENV_FILE.unused.$STAMP"; fi

if [[ ! -f "$ENV_FILE" ]]; then
  ADMIN_PASS="$(openssl rand -hex 24)"
  cat > "$ENV_FILE" <<ENVEOF
S5M_ADDR=$([[ -n "$S5M_DOMAIN" ]] && echo "127.0.0.1:8080" || echo ":80")
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
# Keep existing user choices intact except when HTTPS reverse proxy is explicitly enabled.
if [[ -n "$S5M_DOMAIN" ]]; then
  if grep -qE '^S5M_ADDR=' "$ENV_FILE"; then
    sed -i 's#^S5M_ADDR=.*#S5M_ADDR=127.0.0.1:8080#' "$ENV_FILE"
  else
    printf '\nS5M_ADDR=127.0.0.1:8080\n' >> "$ENV_FILE"
  fi
fi
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

# Keep the main Mihomo API settings aligned with an existing config when
# upgrading older installations. Otherwise a newly generated env secret or a
# hard-coded port can make a previously working API unreachable.
EXISTING_MIHOMO_SECRET=""
EXISTING_MIHOMO_CONTROLLER=""
if [[ -s "$DB_DIR/config.yaml" ]]; then
  EXISTING_MIHOMO_SECRET="$(sed -nE 's/^secret:[[:space:]]*["'\''"]?([^"'\''"[:space:]]+)["'\''"]?[[:space:]]*$/\1/p' "$DB_DIR/config.yaml" | head -n1)"
  EXISTING_MIHOMO_CONTROLLER="$(sed -nE 's/^external-controller:[[:space:]]*["'\''"]?([^"'\''"[:space:]]+)["'\''"]?[[:space:]]*$/\1/p' "$DB_DIR/config.yaml" | head -n1)"
fi
if ! grep -qE '^MIHOMO_API=' "$ENV_FILE"; then
  if [[ -n "$EXISTING_MIHOMO_CONTROLLER" ]]; then
    case "$EXISTING_MIHOMO_CONTROLLER" in
      http://*|https://*) API_DEFAULT="$EXISTING_MIHOMO_CONTROLLER" ;;
      *) API_DEFAULT="http://$EXISTING_MIHOMO_CONTROLLER" ;;
    esac
  else
    API_DEFAULT="http://127.0.0.1:8088"
  fi
  printf '\nMIHOMO_API=%s\n' "$API_DEFAULT" >> "$ENV_FILE"
fi
if ! grep -qE '^MIHOMO_SECRET=' "$ENV_FILE"; then
  if [[ -n "$EXISTING_MIHOMO_SECRET" ]]; then
    SECRET_DEFAULT="$EXISTING_MIHOMO_SECRET"
  else
    SECRET_DEFAULT="$(openssl rand -hex 24)"
  fi
  printf '\nMIHOMO_SECRET=%s\n' "$SECRET_DEFAULT" >> "$ENV_FILE"
fi
chmod 0600 "$ENV_FILE"
MIHOMO_API_URL="$(awk -F= '/^MIHOMO_API=/ { sub(/^[^=]*=/, ""); value=$0 } END { print value }' "$ENV_FILE")"
MIHOMO_PORT="$(printf '%s' "$MIHOMO_API_URL" | sed -nE 's#^https?://[^/:]+:([0-9]+)(/.*)?$#\1#p')"
MIHOMO_PORT="${MIHOMO_PORT:-8088}"
MIHOMO_SECRET_VALUE="$(awk -F= '/^MIHOMO_SECRET=/ { sub(/^[^=]*=/, ""); value=$0 } END { print value }' "$ENV_FILE")"
if [[ ! -s "$DB_DIR/config.yaml" ]]; then
  cat > "$DB_DIR/config.yaml" <<MIHOMO_CONFIG_EOF
mode: rule
mixed-port: 8080
log-level: info
allow-lan: true
find-process-mode: "off"
proxies: []
rules:
  - MATCH,DIRECT
MIHOMO_CONFIG_EOF
fi

# Existing user configs must also receive the controller endpoint and API secret.
# Without these keys Mihomo starts successfully, but S5M cannot query /version,
# monitor traffic, or publish/reload configs. Bind the API to loopback only.
if ! grep -qE '^external-controller[[:space:]]*:' "$DB_DIR/config.yaml"; then
  printf '\nexternal-controller: "127.0.0.1:%s"\n' "$MIHOMO_PORT" >> "$DB_DIR/config.yaml"
fi
if ! grep -qE '^secret[[:space:]]*:' "$DB_DIR/config.yaml"; then
  printf 'secret: "%s"\n' "$MIHOMO_SECRET_VALUE" >> "$DB_DIR/config.yaml"
fi

# Keep the config private and readable by both services. S5M owns it so config
# publish/rollback can replace it; Mihomo runs as root under a restricted
# capability set and needs CAP_DAC_OVERRIDE to traverse the private state dir.
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
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_DAC_OVERRIDE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_DAC_OVERRIDE
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
  rollback_install "主控 Mihomo 启动失败"
  exit 1
fi
systemctl enable "$UNIT"
if ! systemctl restart "$UNIT"; then
  echo "❌ S5M-Server 服务启动失败。请检查：journalctl -u $UNIT -n 100 --no-pager" >&2
  systemctl status "$UNIT" --no-pager -l >&2 || true
  rollback_install "S5M-Server 启动失败"
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
  echo "❌ 健康检查失败（端口 $PORT），正在恢复安装前状态..." >&2
  rollback_install "健康检查失败（端口 $PORT）"
  exit 1
fi

if [[ -n "$S5M_DOMAIN" && "$HTTPS_ALREADY_CONFIGURED" -eq 0 ]]; then
  
  cat > "$NGINX_SITE" <<NGINXEOF
server {
    listen 80;
    listen [::]:80;
    server_name $S5M_DOMAIN;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 3600s;
    }
}
NGINXEOF
  ln -sfn "$NGINX_SITE" "$NGINX_ENABLED"
  # Keep any existing default site intact; the S5M virtual host is selected by server_name.
  if ! nginx -t || ! systemctl enable --now nginx; then
    rollback_install "Nginx HTTPS 反向代理配置失败"
    exit 1
  fi
  if ! certbot --nginx --non-interactive --agree-tos --redirect --email "$S5M_EMAIL" -d "$S5M_DOMAIN"; then
    echo "❌ Let's Encrypt 证书签发失败。请确认域名 DNS 已指向本机，且 TCP 80/443 可从公网访问。" >&2
    rollback_install "HTTPS 证书签发失败"
    exit 1
  fi
  if ! curl -fsS --max-time 10 "https://$S5M_DOMAIN/api/v1/health" >/tmp/s5m-server-https-health.json; then
    rollback_install "HTTPS 端点健康检查失败"
    exit 1
  fi
  echo "🔐 HTTPS 证书已签发并配置自动续期： https://$S5M_DOMAIN"
elif [[ -n "$S5M_DOMAIN" && "$HTTPS_ALREADY_CONFIGURED" -eq 1 ]]; then
  if ! curl -fsS --max-time 10 "https://$S5M_DOMAIN/api/v1/health" >/tmp/s5m-server-https-health.json; then
    echo "❌ 检测到现有 HTTPS 配置，但 HTTPS 健康检查失败；为避免覆盖现有配置，安装器停止。请检查 Nginx/证书/服务状态。" >&2
    exit 1
  fi
  echo "✅ 复用现有 HTTPS 配置，不重新签发证书： https://$S5M_DOMAIN"
fi

echo "✅ S5M-Server 安装成功"
echo "   服务: $UNIT（端口 $PORT）"
echo "   健康: $(cat /tmp/s5m-server-health.json)"
if [[ -n "$S5M_DOMAIN" ]]; then echo "   HTTPS: https://$S5M_DOMAIN"; else echo "   HTTPS: 未配置（设置 S5M_DOMAIN 与 S5M_EMAIL 可启用 Let's Encrypt）"; fi
