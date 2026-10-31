#!/bin/sh
# Real-process SmartDNS rollback integration test.
# Runs against the SmartDNS binary inside the combined Agent image and uses
# isolated loopback ports so it cannot disturb the container's live resolver.
set -eu

SMARTDNS_BIN="${SMARTDNS_BIN:-/usr/sbin/smartdns}"
DIG_BIN="${DIG_BIN:-dig}"
TEST_DIR="$(mktemp -d /tmp/smartdns-rollback.XXXXXX)"
CONFIG="$TEST_DIR/smartdns.conf"
BACKUP="$TEST_DIR/smartdns.conf.previous"
PID_FILE="$TEST_DIR/smartdns.pid"
LOG_FILE="$TEST_DIR/smartdns.log"
PID=""

cleanup() {
  if [ -n "$PID" ]; then
    kill "$PID" >/dev/null 2>&1 || true
    wait "$PID" >/dev/null 2>&1 || true
  fi
  rm -rf "$TEST_DIR"
}
trap cleanup EXIT INT TERM

command -v "$SMARTDNS_BIN" >/dev/null 2>&1 || {
  echo "SmartDNS binary not found: $SMARTDNS_BIN" >&2
  exit 2
}
command -v "$DIG_BIN" >/dev/null 2>&1 || {
  echo "dig is required" >&2
  exit 2
}

write_old_config() {
  cat > "$CONFIG" <<'EOF'
bind 127.0.0.1:16053
bind-tcp 127.0.0.1:16053
server 223.5.5.5
server 119.29.29.29
cache-size 1024
log-level error
log-console yes
log-syslog no
EOF
}

write_unhealthy_candidate() {
  cat > "$CONFIG" <<'EOF'
bind 127.0.0.1:16053
bind-tcp 127.0.0.1:16053
server 127.0.0.1:9
cache-size 1024
log-level error
log-console yes
log-syslog no
EOF
}

start_smartdns() {
  "$SMARTDNS_BIN" -f -x -p "$PID_FILE" -c "$CONFIG" >>"$LOG_FILE" 2>&1 &
  PID=$!
}

stop_smartdns() {
  if [ -n "$PID" ]; then
    kill "$PID" >/dev/null 2>&1 || true
    wait "$PID" >/dev/null 2>&1 || true
    PID=""
  fi
}

query_has_answer() {
  "$DIG_BIN" +time=2 +tries=1 +short @127.0.0.1 -p 16053 example.com A 2>/dev/null |
    grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'
}

wait_for_answer() {
  attempts=0
  while [ "$attempts" -lt 30 ]; do
    if query_has_answer && "$DIG_BIN" +tcp +time=2 +tries=1 +short @127.0.0.1 -p 16053 example.com A 2>/dev/null |
      grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
      return 0
    fi
    if [ -n "$PID" ] && ! kill -0 "$PID" 2>/dev/null; then
      return 1
    fi
    attempts=$((attempts + 1))
    sleep 1
  done
  return 1
}

write_old_config
cp "$CONFIG" "$BACKUP"
start_smartdns
if ! wait_for_answer; then
  cat "$LOG_FILE" >&2
  echo "Initial SmartDNS process did not answer UDP and TCP DNS" >&2
  exit 1
fi
stop_smartdns

# Apply a syntactically valid candidate whose only upstream is deliberately
# unreachable. The daemon can start, but a real DNS query must fail.
write_unhealthy_candidate
start_smartdns
sleep 2
if [ -n "$PID" ] && ! kill -0 "$PID" 2>/dev/null; then
  cat "$LOG_FILE" >&2
  echo "Unhealthy candidate unexpectedly failed to start; test did not reach DNS rollback" >&2
  exit 1
fi
if query_has_answer; then
  echo "Unhealthy candidate unexpectedly answered DNS; test upstream assumption is invalid" >&2
  exit 1
fi
stop_smartdns

# Exercise the same essential rollback contract as the Agent: restore exact
# backup bytes, restart the real SmartDNS process, then prove UDP and TCP work.
cp "$BACKUP" "$CONFIG"
cmp -s "$CONFIG" "$BACKUP"
start_smartdns
if ! wait_for_answer; then
  cat "$LOG_FILE" >&2
  echo "Restored SmartDNS process failed UDP/TCP DNS verification" >&2
  exit 1
fi

if find "$TEST_DIR" -maxdepth 1 -type f -name '.smartdns-*.conf' | grep -q .; then
  echo "Temporary SmartDNS config files were left behind" >&2
  exit 1
fi

echo "PASS: real SmartDNS process recovered from an unhealthy candidate; restored config answered UDP and TCP DNS."
