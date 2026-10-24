# S5M Agent API contract (current implementation)

This document records the currently implemented controller/Agent contract. It is intentionally explicit about gaps; it does not claim that remote monitoring or remote upgrades are implemented.

## Authentication and registration

- Controller UI API uses `Authorization: Bearer <user JWT>`.
- `POST /api/v1/agent/register` is the Agent registration endpoint.
- `GET /api/v1/agent/config` is called by the Agent using its machine-specific credential. The controller records `agent_lastseen_<machine_code>` when a valid config request is processed.
- `GET /api/v1/agents` is an authenticated controller endpoint. It returns a map keyed by machine code. Each value contains `authorized` (boolean) and `last_seen` (Unix seconds). It must not return raw Agent credentials.

## Current limitations

- A recent `last_seen` value reflects a successful config pull, not a separately verified Agent process health report.
- The Agent currently synchronizes proxy and rule sections from the controller config. Other Mihomo settings are not guaranteed to synchronize.
- Controller overview/traffic and Mihomo update handlers currently operate on the controller host's local Mihomo, not on a selected remote Agent.
- There is no complete end-to-end remote command/acknowledgement protocol yet for per-Agent status, configuration apply results, restart, log retrieval, or upgrades. Do not interpret the online badge as proof that every Agent subsystem is healthy.

## UI behavior

The machine-code page uses the existing `s5m_next_token` browser storage key and sends the Bearer token to the authenticated endpoint. It displays an Agent as online when its last config pull was within 90 seconds; this is a UI heuristic, not a health check.


## Complete per-Agent Mihomo configuration and kernel update workflow

- `GET/PUT /api/v1/nodes/{code}/config` stores and retrieves a complete node-specific Mihomo YAML. The editor exposes the full YAML plus quick controls for `tun.enable`, `dns.enable`, and `dns.nameserver`.
- Agent pulls the full YAML and replaces its local configuration only after YAML checks, required `secret`/`tun`/`dns` checks, and local Mihomo `-t` validation. It retains the previous file and attempts rollback if reload fails.
- Routine proxy edits update the `proxies` and `rules` sections of existing node YAML while preserving other custom settings and the node secret.
- An administrator can queue a per-Agent Mihomo update with a version tag and SHA-256 of the matching official GitHub release `.gz` asset. Agent downloads only from the official MetaCubeX/Mihomo release URL, verifies the supplied digest, tests the binary and current config, replaces the binary, requests Mihomo restart, and reports success/failure.
- The SHA-256 is for the compressed release asset and must match the Agent architecture: amd64 uses `mihomo-linux-amd64-compatible-<version>.gz`; arm64 uses `mihomo-linux-arm64-<version>.gz`. Never use a checksum for another architecture or asset.
- Kernel update commands require a dedicated Agent JWT and an authenticated controller administrator. Pending commands are acknowledged and retained as the latest result in the controller's Agent list.
