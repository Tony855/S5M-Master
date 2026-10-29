#!/bin/sh
set -eu

wget -q -T 3 -O /dev/null http://127.0.0.1:80/api/config
pidof mihomo >/dev/null 2>&1
pidof smartdns >/dev/null 2>&1
