# S5M OpenWrt 原生 Agent 与固件交付说明

## 当前交付范围

本分支交付的是 **OpenWrt 完整固件镜像**，不是独立 IPK/APK 软件包。固件由 OpenWrt ImageBuilder 生成，包含 S5M Agent、Mihomo、procd 服务脚本和默认配置。

本分支只承载 OpenWrt 适配，不直接修改 main、dev、S5M-SmartDNS 或 RouterOS 专用实现。

## 运行架构与已实现功能

- Agent 与 Mihomo 分别由独立 procd 服务管理，支持开机启动、崩溃 respawn、启动/停止/重启和系统日志。
- Agent 使用现有 S5M 主控注册、专属 Token 授权、心跳、WebSocket 命令通道、节点 YAML 同步和诊断协议。
- Agent 与 Mihomo 数据默认保存在 `/etc/s5m-agent`。procd 通过 `MIHOMO_HOME` 指定数据目录、`MIHOMO_BINARY` 指定 Mihomo 二进制、`S5M_WEB_INDEX` 指定注册页面；未设置时保留容器/其他平台原有默认路径。
- 机器码优先读取 `/etc/machine-id`；系统机器标识不可用时，在 `MIHOMO_HOME/machine-id` 原子持久化备用机器码。
- Mihomo API 默认只绑定 `127.0.0.1:8088`，不向 LAN/WAN 暴露控制接口。
- 主控 OpenWrt 面板提供设备型号、系统运行时间、内存、磁盘、网络接口、Agent/Mihomo 进程状态、PID、系统日志和脱敏后的 UCI network/dhcp/firewall 只读快照。
- 系统日志只读取最近 80 行，发送前进行敏感字段脱敏并限制遥测包大小。
- 远程操作只接受固定白名单：Mihomo start/stop/restart、Agent restart、OpenWrt router reboot。操作要求授权设备、有效心跳和管理员确认；不执行调用方提供的任意 shell 命令。
- 路由器重启和 Agent 重启均有服务端持久化跟踪：命令 ACK 不是重启成功；必须观察旧 WebSocket 断开、新连接认证和新连接有效心跳。超时显示未确认。主控进程重启会把旧连接证据标记为中断，不会误报成功。
- Mihomo 内核更新执行版本格式和 SHA-256 校验、原子替换、重启、API 健康验证及失败回滚；OpenWrt 使用独立 procd Mihomo 服务。

## 构建目标

| OpenWrt target | Go 架构 | 交付说明 |
| --- | --- | --- |
| x86/64 | amd64 | ImageBuilder generic 固件 |
| armsr/armv8 | arm64 | ImageBuilder generic ARMv8 固件，不代表兼容所有 ARM 路由器 |

ARMv8 generic 镜像不是特定消费级路由器的板级固件。Wi-Fi、交换芯片、PHY、LED、按键、存储布局和 bootloader 均可能不同。不得仅凭 CPU 架构判断设备兼容性。

MIPS、ARMv7 等其他架构当前不属于本分支首批固件构建目标；不得假定 Mihomo 官方二进制或当前构建流程支持它们。

## 网络与 TUN 安全说明

- 固件默认配置当前将 Mihomo TUN 设置为启用，包含 auto-route、auto-redirect；strict-route 关闭，并排除常见私网、CGNAT、loopback 和 link-local 网段。
- 该配置并不能保证所有设备的 SSH、LAN 管理和 WAN 路由都不受影响。首次部署前应通过本地控制台或可靠回滚通道操作；若未在目标设备验证管理链路，先将 `tun.enable` 设为 `false` 再部署。
- Agent 不自动修改 OpenWrt WAN/LAN、默认路由、DNS、DHCP、防火墙规则或 SSH 配置。
- UCI network/dhcp/firewall 页面目前为只读快照；不提供远程网络配置写入，避免误操作导致路由器失联。
- 默认代理监听配置和规则由用户管理的 Mihomo YAML 决定；Agent 不自动开放防火墙端口。

## 构建与 CI

`.github/workflows/openwrt-firmware.yml` 当前构建两个目标：
- x86/64 amd64
- armsr/armv8 arm64

工作流会编译并测试 Agent、校验 Mihomo 官方压缩包 SHA-256、校验 ImageBuilder SHA-256、组装固件、检查固件清单并生成 SHA256SUMS。构建产物作为 GitHub Actions artifact 上传，不自动创建 Release，也不自动合并分支。

**CI 成功只证明构建和自动化检查通过，不等于真实路由器兼容性或网络稳定性已经验证。**

本分支当前不生成独立 IPK/APK 包；若未来需要在现有 OpenWrt 系统上单独安装/升级 Agent，应另行实现并验证 OpenWrt package Makefile、依赖、升级脚本和卸载保留策略。当前完整固件交付不依赖该包流程。

## 安装前检查

1. 确认设备的准确型号、OpenWrt target/subtarget、闪存布局和恢复方式。
2. 确认设备有可写 overlay/extroot 空间，能保存 `/etc/s5m-agent`。
3. 备份当前配置和固件，确认串口/恢复模式或其他可靠救援通道。
4. 先验证 LAN、WAN、DNS、SSH，再决定是否启用 TUN。
5. 注册 Agent 时使用 HTTPS 主控地址；仅可信内网且显式设置安全开关时才允许 HTTP。
6. 不要把 armsr/armv8 generic 镜像直接刷入未确认兼容的消费级路由器。

## 当前验收状态

| 验收项 | 当前状态 |
| --- | --- |
| x86/64 固件自动构建 | CI 构建通过；仍需真实设备刷机验证 |
| armsr/armv8 固件自动构建 | CI 构建通过；仍需真实设备刷机验证 |
| Agent/Mihomo 独立 procd 脚本与静态检查 | 已实现并纳入 CI |
| Agent 注册、Token 授权、心跳、WebSocket 命令处理 | 有自动化测试；仍需真实设备联调 |
| OpenWrt 遥测、日志和只读 UCI 快照 | 已实现并有单元测试 |
| Mihomo 更新 SHA-256、健康检查与回滚 | 已实现并有自动化测试；仍需设备升级回归 |
| 路由器/Agent 重启的断线、新连接、心跳确认 | 已实现持久化状态和回归测试；仍需真实设备重启测试 |
| 主控重启后的跟踪恢复 | 恢复为“验证中断”，不误报成功；有自动化测试 |
| TUN、DNS、SSH 管理链路 | 未完成各具体硬件的专项实测 |
| 独立 IPK/APK 包 | 当前不在完整固件交付范围内 |

## 明确不在当前范围内

- 远程写入 UCI、修改 WAN/LAN、DHCP、DNS、防火墙、默认路由或 SSH。
- LuCI 管理页面。
- MIPS/ARMv7 等未纳入构建矩阵的架构。
- 独立 IPK/APK 包安装流程。
- 未经真实硬件验证的通用 ARM 路由器兼容性承诺。
