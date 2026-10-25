#!/bin/sh
set -eu

MIHOMO_HOME="${MIHOMO_HOME:-/data}"
CONFIG_PATH="${MIHOMO_HOME}/config.yaml"
mkdir -p "$MIHOMO_HOME" /data

# An interrupted kernel upgrade leaves the previous binary in place.
# Restore it before starting Mihomo; successful upgrades remove this backup
# only after the running API confirms the requested version.
MIHOMO_BIN="/usr/local/bin/mihomo"
MIHOMO_BACKUP="${MIHOMO_BIN}.previous"
if [ -e "$MIHOMO_BACKUP" ]; then
  echo "检测到未完成的 Mihomo 内核升级，优先恢复旧内核"
  if [ -x "$MIHOMO_BACKUP" ]; then
    rm -f "$MIHOMO_BIN"
    mv "$MIHOMO_BACKUP" "$MIHOMO_BIN"
    chmod 0755 "$MIHOMO_BIN"
    echo "已在启动前恢复旧 Mihomo 内核"
  else
    echo "旧 Mihomo 内核备份不存在或不可执行，拒绝自动覆盖当前内核" >&2
    exit 1
  fi
fi

# One-time migration from the retired directory; never overwrite the new config.
LEGACY_CONFIG="/data/s5m-next/config.yaml"
if [ ! -s "$CONFIG_PATH" ] && [ -s "$LEGACY_CONFIG" ]; then
  cp "$LEGACY_CONFIG" "$CONFIG_PATH"
  chmod 0600 "$CONFIG_PATH"
  echo "已将旧 Mihomo 配置迁移到 $CONFIG_PATH"
fi

if [ ! -s "$CONFIG_PATH" ]; then
  cp /app/default-config.yaml "$CONFIG_PATH"
  chmod 0600 "$CONFIG_PATH"
fi

# Replace only known public placeholders; preserve any already-configured secret.
if grep -Eq '^secret:[[:space:]]*"?(__S5M_GENERATED_SECRET__|__S5M_MIHOMO_SECRET__|change-this-secret)"?[[:space:]]*$' "$CONFIG_PATH"; then
  secret="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d '[:space:]')"
  [ "${#secret}" -eq 64 ] || { echo "无法生成 Mihomo API secret" >&2; exit 1; }
  sed -i "s|^secret:.*|secret: \"$secret\"|" "$CONFIG_PATH"
  chmod 0600 "$CONFIG_PATH"
fi

/usr/local/bin/mihomo -d "$MIHOMO_HOME" -f "$CONFIG_PATH" &
MIHOMO_PID=$!

/app/s5m-agent &
AGENT_PID=$!

shutdown() {
  kill "$AGENT_PID" "$MIHOMO_PID" 2>/dev/null || true
  wait "$AGENT_PID" "$MIHOMO_PID" 2>/dev/null || true
}

trap shutdown INT TERM HUP

# BusyBox ps (Alpine) does not support the procps-style -p PID option.
# Enumerate PID and state instead, so live children are not misdetected as dead.
process_alive() {
  pid="$1"
  kill -0 "$pid" 2>/dev/null || return 1
  state="$(ps -o pid,stat 2>/dev/null | awk -v pid="$pid" '$1 == pid { print $2; found=1; exit } END { if (!found) exit 1 }' | tr -d '[:space:]' || true)"
  case "$state" in
    ""|Z*|X*) return 1 ;;
  esac
  return 0
}

# Stop the container if either essential process exits; Docker can then restart it.
while process_alive "$MIHOMO_PID" && process_alive "$AGENT_PID"; do
  sleep 2
done

shutdown
exit 1
