# OpenWrt native runtime files

This directory contains the initial native OpenWrt service integration. It does not use Docker, RouterOS Container, s6-overlay, or a container network namespace.

## Current files

- `etc/init.d/s5m-agent`: procd supervises Mihomo and S5M Agent as separate processes.
- `etc/config/s5m-agent`: initial UCI defaults for the future package integration.

## Initial manual deployment (development only)

1. Build `s5m-agent` for the device's verified Go target and install it as `/usr/bin/s5m-agent`.
2. Install a matching, verified Mihomo binary as `/usr/bin/mihomo`.
3. Install the Agent web asset as `/usr/share/s5m-agent/index.html`.
4. Install the repository's default Mihomo YAML as `/usr/share/s5m-agent/default-config.yaml`.
5. Copy the init script to `/etc/init.d/s5m-agent`, make it executable, and copy the UCI defaults to `/etc/config/s5m-agent`.
6. Review the default YAML. Keep TUN disabled and keep `external-controller` bound to loopback.
7. Run `/etc/init.d/s5m-agent enable` and `/etc/init.d/s5m-agent start`.

This is not yet a distributable IPK/APK package. Package metadata, target-specific cross-compilation, UCI option wiring, upgrade/rollback scripts, and hardware validation remain outstanding. The current init script uses conservative fixed paths; the UCI values are defaults/documentation until the service is fully wired to UCI.

## Important limitations

- Agent currently listens on TCP/80. Do not expose it on WAN; restrict access to a trusted management LAN.
- No firewall, LAN/WAN, DHCP, DNS, route, or TUN changes are applied automatically.
- TUN remains disabled until the exact router model, kernel modules, device access, and management-path rollback are validated.
- The persistent data directory currently defaults to `/etc/s5m-agent`; ensure the device has writable persistent overlay/extroot space.
- Do not use this development init script on production routers before CI and device testing.
