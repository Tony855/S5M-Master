#!/bin/sh
set -eu

SCRIPT="${SMARTDNS_RECOVERY_SCRIPT:-/etc/cont-init.d/15-smartdns-recovery}"
TEST_DIR="$(mktemp -d /tmp/smartdns-startup-recovery.XXXXXX)"
trap 'rm -rf "$TEST_DIR"' EXIT INT TERM
LIVE="$TEST_DIR/smartdns.conf"
BACKUP="$LIVE.previous"
PENDING="$LIVE.recovery-pending"

printf 'candidate-config\n' > "$LIVE"
printf 'known-good-config\n' > "$BACKUP"
S5M_DATA_DIR="$TEST_DIR" SMARTDNS_CONFIG_PATH="$LIVE" "$SCRIPT"

cmp -s "$LIVE" "$PENDING"
grep -qx 'known-good-config' "$LIVE"
[ ! -e "$BACKUP" ]

# If another update is interrupted before health verification, its newer backup
# must supersede the older pending recovery copy.
printf 'newer-known-good-config\n' > "$BACKUP"
printf 'broken-after-restart\n' > "$LIVE"
S5M_DATA_DIR="$TEST_DIR" SMARTDNS_CONFIG_PATH="$LIVE" "$SCRIPT"
grep -qx 'newer-known-good-config' "$LIVE"
grep -qx 'newer-known-good-config' "$PENDING"
[ ! -e "$BACKUP" ]

# A second startup before DNS becomes healthy must retry the latest recovery.
printf 'broken-after-second-restart\n' > "$LIVE"
S5M_DATA_DIR="$TEST_DIR" SMARTDNS_CONFIG_PATH="$LIVE" "$SCRIPT"
grep -qx 'newer-known-good-config' "$LIVE"
[ -f "$PENDING" ]

# No pending backup means a normal startup must leave the current config alone.
rm -f "$PENDING"
printf 'current-good-config\n' > "$LIVE"
S5M_DATA_DIR="$TEST_DIR" SMARTDNS_CONFIG_PATH="$LIVE" "$SCRIPT"
grep -qx 'current-good-config' "$LIVE"

echo 'PASS: interrupted SmartDNS update restores the previous config on startup and retries until health verification.'
