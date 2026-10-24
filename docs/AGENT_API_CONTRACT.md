# S5M Agent API contract (current implementation)

This document records the currently implemented controller/Agent contract. It is intentionally explicit about gaps; it does not claim that remote monitoring or remote upgrades are implemented.

## Authentication and registration

- Controller UI API uses `Authorization: Bearer <user JWT>`.
- `POST /api/v1/agent/register` is the Agent registration endpoint.
- `GET /api/v1/agent/config` is called by the Agent using its machine-specific credential. The controller records `agent_lastseen_<machine_code>` when a valid config request is processed.
- `GET /api/v1/agents` is an authenticated controller endpoint. It returns a map keyed by machine code. Each value contains `authorized` (boolean) and `last_seen` (Unix seconds). It must not return raw Agent credentials.

## Current limitations

- A recent `last_seen` value reflects a successful config pull, not a separately verified Agent process health report.
- The Agent downloads and applies the complete node-specific Mihomo YAML, including TUN, DNS, ports, proxies and rules. The controller stores a desired-config SHA-256; the Agent reports the hash of its local config so the UI can show whether the desired configuration has been applied.
- A node without a saved custom YAML receives a generated full configuration when its editor is first opened.
- During a config change, the Agent authenticates the reload request with the currently running Mihomo secret from the previous config when available. This permits the new YAML to rotate the secret without locking out the reload request.
- Controller overview/traffic and controller-side Mihomo update handlers still operate on the controller host's local Mihomo. Per-Agent kernel upgrades use the authenticated command/acknowledgement workflow described below.
- Agent status is based on authenticated heartbeats and local Mihomo API probes; a recently received heartbeat alone does not prove all subsystems are healthy.

## Unified data/config directory

- Agent uses `MIHOMO_HOME` as the single Mihomo data directory; it defaults to `/data`, and the main config is always `${MIHOMO_HOME}/config.yaml`.
- Controller uses `S5M_DATA_DIR` as its unified data directory; it defaults to `/data`, with `s5m.db`, `config.yaml`, and `backups/` under that directory. `S5M_DB`, `S5M_CONFIG`, and `S5M_BACKUP` remain optional explicit overrides.
- `/data/s5m-next/config.yaml` is not an active default path. The Agent entrypoint only checks it for a one-time migration when the new `/data/config.yaml` does not exist.

## UI behavior

The machine-code page uses the existing `s5m_next_token` browser storage key and sends the Bearer token to the authenticated endpoint. It displays an Agent as online when its last config pull was within 90 seconds; this is a UI heuristic, not a health check.


## Complete per-Agent Mihomo configuration and kernel update workflow

- `GET/PUT /api/v1/nodes/{code}/config` stores and retrieves a complete node-specific Mihomo YAML. The editor exposes the full YAML plus quick controls for `tun.enable`, `dns.enable`, and `dns.nameserver`.
- Agent pulls the full YAML and replaces its local configuration only after YAML checks, required `secret`/`tun`/`dns` checks, and local Mihomo `-t` validation. It retains the previous file and attempts rollback if reload fails.
- Routine proxy edits update the `proxies` and `rules` sections of existing node YAML while preserving other custom settings and the node secret.
- An administrator can queue a per-Agent Mihomo update with a version tag and SHA-256 of the matching official GitHub release `.gz` asset. Agent downloads only from the official MetaCubeX/Mihomo release URL, verifies the supplied digest, tests the binary and current config, replaces the binary, requests Mihomo restart, and reports success/failure.
- The SHA-256 is for the compressed release asset and must match the Agent architecture: amd64 uses `mihomo-linux-amd64-compatible-<version>.gz`; arm64 uses `mihomo-linux-arm64-<version>.gz`. Never use a checksum for another architecture or asset.
- Kernel update commands require a dedicated Agent JWT and an authenticated controller administrator. Pending commands are acknowledged and retained as the latest result in the controller's Agent list.
