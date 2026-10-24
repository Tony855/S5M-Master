#!/bin/sh
set -eu

MIHOMO_HOME="${MIHOMO_HOME:-/data/s5m-next}"
CONFIG_PATH="${MIHOMO_HOME}/config.yaml"
mkdir -p "$MIHOMO_HOME" /data

if [ ! -s "$CONFIG_PATH" ]; then
  cp /opt/s5m/default-config.yaml "$CONFIG_PATH"
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
trap shutdown INT TERM

# Stop the container if either essential process exits.
while kill -0 "$MIHOMO_PID" 2>/dev/null && kill -0 "$AGENT_PID" 2>/dev/null; do
  sleep 2
done
shutdown
exit 1
