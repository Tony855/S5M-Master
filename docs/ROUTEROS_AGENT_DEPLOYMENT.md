# S5M RouterOS Agent deployment guide

This implementation uses S5M per-machine registration and the shared Agent command queue (`GET /api/v1/agent/command`, `POST /api/v1/agent/command/ack`). RouterOS container commands are queued by an administrator through `POST /api/v1/agents/routeros-command`; the API accepts only `list`, `start`, `stop`, and `restart`, validates RouterOS internal IDs, requires a dedicated authorized machine code, and refuses targets that have not reported `os=routeros`. The RouterOS agent initiates HTTPS requests to S5M; S5M never needs the router's current public IP. It is suitable for changing public IPv4 and CGNAT when outbound HTTPS is allowed.

Official references:
- RouterOS Container: https://help.mikrotik.com/docs/spaces/ROS/pages/84901929/Container
- RouterOS API: https://help.mikrotik.com/docs/spaces/ROS/pages/47579160/API
- RouterOS Services: https://help.mikrotik.com/docs/spaces/ROS/pages/103841820/Services

## 1. S5M registration

1. In S5M, generate a dedicated Agent token for a new machine code, reserved for one RouterOS device.
2. Do not reuse the machine code currently used by a Docker/Mihomo agent. The command queue is scoped to machine code.
3. Keep the generated token private. It becomes S5M_AGENT_SECRET for the RouterOS agent and is exchanged for the per-device Agent JWT at startup.

## 2. Prepare RouterOS API-SSL

Enable and configure API-SSL with a certificate whose SAN matches the TLS server name used by the agent. Do not expose API-SSL to the public Internet. Restrict the service address and firewall to the container veth source IP or a trusted management subnet.

Example only; replace the certificate name and address with your own validated values:

~~~routeros
/ip service set api-ssl disabled=no certificate=s5m-api-ssl address=172.31.255.2/32
~~~

Create a dedicated RouterOS user for this agent. RouterOS user-group permissions are relatively coarse; grant only the policies needed for reading and operating containers, and protect the API service with firewall rules. Do not use the full administrator account. If your version or policy layout cannot safely restrict this account, deploy the agent on a management Linux host and use a dedicated management VPN instead.

## 3. Container network example

The following is an example isolated veth subnet. Check that 172.31.255.0/29 does not overlap any local or VPN subnet before applying. Add an input firewall accept rule for TCP 8729 from 172.31.255.2 to the router before any general input drop rule. Configure outbound NAT according to your existing WAN interface/list.

~~~routeros
/interface bridge add name=s5m-agent-bridge
/ip address add address=172.31.255.1/29 interface=s5m-agent-bridge
/interface veth add name=veth-s5m-agent address=172.31.255.2/29 gateway=172.31.255.1
/interface bridge port add bridge=s5m-agent-bridge interface=veth-s5m-agent
/ip firewall filter add chain=input action=accept protocol=tcp src-address=172.31.255.2 dst-port=8729 comment="S5M RouterOS Agent API-SSL"
/ip firewall nat add chain=srcnat action=masquerade src-address=172.31.255.0/29 out-interface-list=WAN comment="S5M agent outbound network"
~~~

The input firewall rule must be placed before the rule that drops other input traffic. If your RouterOS does not use an interface list named WAN, replace the NAT rule with the correct existing WAN interface/list. Do not blindly paste this sample into a production router without checking the current firewall and addressing.

## 4. Configure the Agent container

Create a RouterOS environment list. Values below are placeholders; use the exact S5M base URL, machine code, per-device token, RouterOS username/password and TLS certificate name. Store the CA certificate on RouterOS storage and mount it read-only if supported by your setup.

~~~routeros
/container/envs/add list=S5M_ROUTEROS key=S5M_CENTRAL_URL value="https://s5m.example.com"
/container/envs/add list=S5M_ROUTEROS key=S5M_MACHINE_CODE value="routeros-site-001"
/container/envs/add list=S5M_ROUTEROS key=S5M_AGENT_SECRET value="REPLACE_WITH_PER_DEVICE_TOKEN"
/container/envs/add list=S5M_ROUTEROS key=ROUTEROS_API_ADDR value="172.31.255.1:8729"
/container/envs/add list=S5M_ROUTEROS key=ROUTEROS_API_USERNAME value="s5m-agent"
/container/envs/add list=S5M_ROUTEROS key=ROUTEROS_API_PASSWORD value="REPLACE_WITH_ROUTEROS_PASSWORD"
/container/envs/add list=S5M_ROUTEROS key=ROUTEROS_TLS_SERVER_NAME value="routeros-site-001.example.net"
/container/envs/add list=S5M_ROUTEROS key=ROUTEROS_CA_FILE value="/etc/s5m/routeros-ca.pem"
~~~

If a CA file is used, create a directory on RouterOS storage such as disk1/s5m/certs and place routeros-ca.pem in it. Create a mount list for that directory and attach it to the container as shown below. The file must contain the trusted CA certificate chain. The API certificate must include the DNS name in ROUTEROS_TLS_SERVER_NAME. TLS verification is enabled and is not bypassed.

Set the container registry according to your image source, then create the container. Use external storage for root-dir; RouterOS containers can consume substantial disk space.

~~~routeros
/container/mounts/add list=S5M_ROUTEROS_CA src=disk1/s5m/certs dst=/etc/s5m
/container/config/set registry-url=https://ghcr.io tmpdir=disk1/tmp
/container/add remote-image=ghcr.io/tony855/s5m-routeros-agent:dev interface=veth-s5m-agent root-dir=disk1/s5m-routeros-agent envlist=S5M_ROUTEROS mountlists=S5M_ROUTEROS_CA name=s5m-routeros-agent start-on-boot=yes logging=yes
/container/print
/container/start [find where name="s5m-routeros-agent"]
~~~

The GHCR package must be accessible to the router. If it is private, configure registry credentials using the supported RouterOS registry settings or import an image archive instead. Do not store a broad GitHub personal access token on the router.

## 5. Linux sidecar deployment alternative

The same binary can run on a Linux management host or in the supplied Docker image. Set the same environment variables, but set ROUTEROS_API_ADDR to the router's private LAN or VPN address and make sure the Linux host trusts the API-SSL CA. This is usually preferable where RouterOS Container support, CPU architecture, storage, or host API reachability is constrained.

## 6. Verify

1. Confirm the agent container is running and its logs do not show registration, TLS, or API login errors.
2. In S5M, confirm the dedicated machine code is online and reports OS routeros.
3. Open Docker/RouterOS container navigation, select the RouterOS Agent, and read the container list.
4. Test stop/start only on a non-critical container first.
5. Confirm task history includes the action, task ID, result and any RouterOS error.

## Scope and limitations

This increment supports list, start, stop and restart only. It does not yet implement image update/repull, add/remove/edit container, logs, or a per-device RouterOS credential vault in S5M. RouterOS credentials stay in the Agent's environment/configuration and must be protected as secrets. No live hardware integration test is claimed by CI; CI covers Go tests, static analysis, builds and container-image smoke testing.
