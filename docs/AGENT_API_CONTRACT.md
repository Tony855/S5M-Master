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
