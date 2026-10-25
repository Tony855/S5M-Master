#!/bin/sh
set -eu

# The Agent API must respond. Do not use the on-disk Mihomo secret as a
# container-liveness probe: a credential mismatch must not make the container
# unhealthy or trigger an orchestrator restart that interrupts proxy traffic.
wget -q -T 3 -O /dev/null http://127.0.0.1:81/api/config

# Confirm S6 still supervises the Mihomo service, without forcing an API
# authentication check that could fail while the proxy dataplane is healthy.
[ "$(s6-svstat -o up /run/service/mihomo 2>/dev/null || true)" = "true" ]
