#!/bin/sh
set -eu

MIHOMO_HOME="${MIHOMO_HOME:-/data/s5m-next}"
CONFIG_PATH="${MIHOMO_HOME}/config.yaml"
mkdir -p "$MIHOMO_HOME" /data

if [ ! -s "$CONFIG_PATH" ]; then
  cp /opt/s5m/default-config.yaml "$CONFIG_PATH"
  chmod 0600 "$CONFIG_PATH"
fi

# Migrate the old public placeholder and initialize a unique local API secret.
if grep -Eq '^secret:[[:space:]]*(__S5M_GENERATED_SECRET__|change-this-secret)?[[:space:]]*$' "$CONFIG_PATH"; then
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

# kill -0 alone also succeeds for zombie processes; check the process state too.
process_alive() {
  pid="$1"
  kill -0 "$pid" 2>/dev/null || return 1
  state="$(ps -o stat= -p "$pid" 2>/dev/null | tr -d '[:space:]' || true)"
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
 "$CONFIG_PATH"; then
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

# kill -0 alone also succeeds for zombie processes; check the process state too.
process_alive() {
  pid="$1"
  kill -0 "$pid" 2>/dev/null || return 1
  state="$(ps -o stat= -p "$pid" 2>/dev/null | tr -d '[:space:]' || true)"
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
