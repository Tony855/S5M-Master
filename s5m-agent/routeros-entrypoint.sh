#!/bin/sh
set -eu

MIHOMO_HOME="${MIHOMO_HOME:-/data}"
CONFIG_PATH="${MIHOMO_HOME}/config.yaml"
MIHOMO_BIN="${MIHOMO_HOME}/bin/mihomo"
mkdir -p "${MIHOMO_HOME}/bin" "${MIHOMO_HOME}/etc"

# Keep the kernel in the persistent mount so an image/container recreation does
# not silently discard an Agent-driven kernel update.
if [ ! -x "${MIHOMO_BIN}" ]; then
  cp /usr/local/bin/mihomo.initial "${MIHOMO_BIN}.tmp"
  chmod 0755 "${MIHOMO_BIN}.tmp"
  mv "${MIHOMO_BIN}.tmp" "${MIHOMO_BIN}"
fi

# Recover an interrupted update before launching services.
if [ -x "${MIHOMO_BIN}.previous" ]; then
  mv -f "${MIHOMO_BIN}.previous" "${MIHOMO_BIN}"
fi

if [ ! -s "${CONFIG_PATH}" ]; then
  cp /app/default-config.yaml "${CONFIG_PATH}"
  chmod 0600 "${CONFIG_PATH}"
fi
if grep -Eq '^secret:[[:space:]]*"?(__S5M_GENERATED_SECRET__|__S5M_MIHOMO_SECRET__|change-this-secret)"?[[:space:]]*$' "${CONFIG_PATH}"; then
  secret="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d '[:space:]')"
  [ "${#secret}" -eq 64 ] || { echo "无法生成 Mihomo API secret" >&2; exit 1; }
  sed -i "s|^secret:.*|secret: \"${secret}\"|" "${CONFIG_PATH}"
  chmod 0600 "${CONFIG_PATH}"
fi

run_mihomo() {
  while :; do
    echo "启动 Mihomo: ${MIHOMO_BIN}"
    "${MIHOMO_BIN}" -d "${MIHOMO_HOME}" -f "${CONFIG_PATH}" || true
    echo "Mihomo 已退出，2 秒后重试"
    sleep 2
  done
}
run_agent() {
  while :; do
    /app/s5m-agent || true
    echo "S5M Agent 已退出，2 秒后重试"
    sleep 2
  done
}
run_mihomo &
mihomo_pid=$!
run_agent &
agent_pid=$!
cleanup() {
  kill "$mihomo_pid" "$agent_pid" 2>/dev/null || true
  wait "$mihomo_pid" "$agent_pid" 2>/dev/null || true
}
trap cleanup INT TERM EXIT
wait "$agent_pid"
