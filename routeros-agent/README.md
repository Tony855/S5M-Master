# S5M RouterOS Native Container Agent

Dedicated RouterOS /container management. This agent does not invoke Linux Docker commands. It connects outbound to S5M over HTTPS and connects to RouterOS API-SSL with certificate validation enabled.

## Supported actions (initial increment)

- routeros.container.list — /container/print
- routeros.container.start — /container/start
- routeros.container.stop — /container/stop
- routeros.container.restart — stop, then start

Only RouterOS internal IDs such as *1 are accepted. Arbitrary CLI text is never accepted or executed.

## Environment

- S5M_CENTRAL_URL: S5M base URL; HTTPS required except localhost development.
- S5M_MACHINE_CODE: machine code pre-created in S5M.
- S5M_AGENT_SECRET: dedicated token assigned to that machine in S5M (not the global registration token).
- ROUTEROS_API_ADDR: RouterOS API-SSL host:port, e.g. 192.168.88.1:8729.
- ROUTEROS_API_USERNAME, ROUTEROS_API_PASSWORD: dedicated RouterOS account with minimum required permissions.
- ROUTEROS_TLS_SERVER_NAME: optional certificate DNS name; defaults to host from address.
- ROUTEROS_CA_FILE: optional PEM CA bundle for private RouterOS certificates.

TLS verification must not be disabled. For a self-signed/private certificate, configure a trusted CA chain and a matching server name. Enable RouterOS API-SSL and firewall it to the intended management network only.

## RouterOS Container deployment notes

For an agent running inside RouterOS Container, point ROUTEROS_API_ADDR at a RouterOS host/interface address reachable from the container network, not the container's own address. RouterOS veth addressing, routing, firewall rules, and API service access must be configured explicitly; a container does not automatically inherit host RouterOS permissions.

The agent must reach the S5M HTTPS endpoint outbound. Dynamic public IPv4 and CGNAT are supported because S5M does not initiate a connection to the router. If deployed on a nearby Linux gateway, use a LAN or VPN address for the RouterOS API.

## Build and test

Run go test -race ./..., go vet ./..., and go build -trimpath -o s5m-routeros-agent . from this directory.

The agent uses the existing S5M task queue. Assign a dedicated machine code/token; do not run this and the Docker/Mihomo agent concurrently with the same machine code.
