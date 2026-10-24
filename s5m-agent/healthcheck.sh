#!/bin/sh
set -eu

MIHOMO_HOME="${MIHOMO_HOME:-/data}"
CONFIG_PATH="${MIHOMO_HOME}/config.yaml"

# Check the Agent HTTP API first.
wget -q -T 3 -O /dev/null http://127.0.0.1:81/api/config

# Check Mihomo's authenticated controller API using the secret in its active config.
[ -r "$CONFIG_PATH" ]
secret="$(awk -F: '$1 == "secret" { sub(/^[^:]*:[[:space:]]*/, ""); gsub(/["\047]/, ""); print; exit }' "$CONFIG_PATH")"
[ -n "$secret" ]
wget -q -T 3 -O /dev/null --header="Authorization: Bearer ${secret}" http://127.0.0.1:8088/version
