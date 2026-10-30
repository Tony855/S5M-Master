# S5M OpenWrt full firmware

This branch builds a minimal native OpenWrt image with S5M Agent and Mihomo installed directly on the router. It does not use Docker, RouterOS containers, s6-overlay, or LuCI.

## Build targets

- OpenWrt 25.12.6 stable series.
- x86/64 ImageBuilder profile generic (x86_64).
- armsr/armv8 ImageBuilder profile generic (generic ARMv8 system image; not universal for every ARM router board).
- S5M Agent is cross-compiled as static Go binaries for linux/amd64 and linux/arm64.
- Mihomo v1.19.31 official release assets are pinned and SHA-256 verified before inclusion.

## Firmware contents

The selected OpenWrt profile retains its kernel, device support, network drivers, firmware, base system, netifd, dnsmasq, odhcpd, firewall4/nftables, Dropbear SSH, procd, UCI and BusyBox. The build adds kmod-tun, ip-full, CA certificates, S5M Agent and Mihomo. LuCI and unrelated server packages are not added.

Agent and Mihomo run as separate native processes supervised by procd. Agent registration UI is installed at /usr/share/s5m-agent/index.html; persistent Agent/Mihomo data and YAML live under /etc/s5m-agent.

## Network and safety defaults

- No automatic edits to LAN/WAN interfaces, IP addresses, DHCP pools, firewall zones, default routes or SSH settings.
- OpenWrt's default firewall policy remains responsible for WAN isolation; the Agent registration endpoint listens on TCP/80 and must only be reached from a trusted management LAN.
- Mihomo TUN is disabled in the shipped default YAML. The firmware includes kmod-tun but does not enable TUN or install routes.
- Mihomo controller remains bound to 127.0.0.1:8088 in the shipped default configuration.
- First boot creates a per-device Mihomo API secret. Existing /etc/s5m-agent/config.yaml and Agent binding data are not overwritten on service restart.
- Agent and Mihomo binaries are separate from the OpenWrt base system; the Agent updater must not overwrite kernel, bootloader, /etc/init.d, or network configuration files.

## CI build

.github/workflows/openwrt-firmware.yml builds both targets on pushes to s5m-agent-openwrt and manual dispatch. It validates the ImageBuilder profile, compiles Agent, verifies the Mihomo archive checksum, assembles firmware, checks the resulting manifest and emits SHA-256 checksums. Firmware is uploaded as a workflow artifact.

CI does not create a GitHub Release or merge this branch into dev/main. Release is a separate step after successful CI and hardware smoke tests.

## Important ARM limitation

armsr/armv8 generic is an ARMv8 system target, not a board-specific image. Wi-Fi radios, switch PHYs, LEDs, reset buttons, storage layout and bootloader integration are board-specific. Do not flash it to a consumer router unless that exact device is listed as supported by this target/profile. Add board-specific profiles only after identifying and testing the hardware model.

## First boot

1. Connect by the OpenWrt default LAN address and SSH.
2. Confirm LAN/WAN and SSH access before binding the Agent.
3. Open the Agent registration page from the trusted LAN at http://<router-lan-ip>/.
4. Bind the device to S5M Master.
5. Keep TUN disabled until exact hardware, kernel module and management-route rollback are validated.

This branch currently produces full firmware images, not standalone APK/IPK packages. A separately installable package can be added later if required; it is not needed for the selected full-firmware delivery.
