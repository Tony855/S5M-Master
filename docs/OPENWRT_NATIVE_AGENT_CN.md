# S5M OpenWrt 原生 Agent 集成方案

## 目标

在 OpenWrt 路由器系统中原生运行 S5M Agent 与 Mihomo，不依赖 Docker、RouterOS Container 或 s6-overlay。Agent 继续使用现有 S5M 主控注册、Token 授权、心跳、WebSocket 控制通道、节点 YAML 同步和诊断协议。

本分支只承载 OpenWrt 适配，不直接修改 main、dev、S5M-SmartDNS 或 RouterOS 专用实现。

## 运行架构

- OpenWrt init：使用 procd 管理独立的 s5m-agent 与 mihomo 服务，支持开机启动、崩溃重启、日志和服务状态。
- 配置管理：优先使用 UCI 配置文件管理 OpenWrt 服务参数；Agent 的授权数据与节点 Mihomo YAML 独立存放，避免 UCI reload 覆盖主控下发配置。
- 持久化目录：默认使用 /etc/s5m-agent 保存设备授权与配置；/usr/bin/s5m-agent 和 /usr/bin/mihomo 保存可执行文件。需要可写 overlay 或 extroot；安装前检查剩余空间。
- 网络：不自动改写 LAN/WAN、默认路由、DNS、DHCP 或防火墙规则。首次安装只提供 Agent Web 注册入口；代理端口由用户显式启用和配置。
- TUN：默认关闭。仅在设备内核具备 tun 设备、所需内核模块与权限时才允许启用；必须先验证 SSH/LAN 管理可达性和路由回滚方案。
- API：Mihomo controller 只绑定 127.0.0.1；禁止默认暴露 controller API 到 LAN/WAN。

## 首批支持目标

先完成并验证以下通用目标，再按实际设备扩展：

| OpenWrt target | Go 架构 | 说明 |
| --- | --- | --- |
| x86_64 | amd64 | 首批目标 |
| aarch64_generic | arm64 | 首批目标 |
| aarch64_cortex-a53 | arm64 | 首批目标 |
| aarch64_cortex-a72 | arm64 | 首批目标 |
| mipsel / mips_24kc | mips / mipsle | 暂不承诺 Mihomo 官方二进制可用 |
| arm_cortex-a7 | arm | 暂不承诺 Mihomo 官方二进制可用 |

OpenWrt target/subtarget 与 Go GOARCH/GOARM 的映射必须通过设备的 `ubus call system board`、`opkg print-architecture` 或 `apk --print-arch` 结果确定，不能只根据 CPU 型号推断。首批发布只包含经过构建和运行测试的架构。

## 包与服务设计

计划提供：
- OpenWrt package Makefile，生成 ipk（兼容 apk 的 OpenWrt 版本另行验证）。
- procd init 脚本：分别管理 Agent 与 Mihomo，提供 respawn、stdout/stderr 日志和 enable/disable。
- 服务控制：Mihomo 使用独立的 `/etc/init.d/s5m-mihomo`，Agent 使用 `/etc/init.d/s5m-agent`；主控通过 Agent WebSocket 下发白名单操作。Mihomo 支持 start/stop/restart，Agent 仅支持 restart，避免远程停止后失去管理通道。
- 内核更新：Agent 更新 Mihomo 二进制后，在 OpenWrt 上通过 `/etc/init.d/s5m-mihomo restart` 请求 procd 重启，并等待本机 API 返回目标版本；其他 s6 部署仍使用原来的 s6-svc 路径。
- 旧版迁移：Agent init 脚本使用一次性标记检查旧版复合服务；若 Mihomo 尚未由独立 procd 服务托管，则启用并启动新服务，不覆盖现有 YAML。
- 操作保护：仅接受固定服务名与动作，不拼接 shell 命令；要求 OpenWrt 平台、授权 Agent、有效心跳和管理员二次确认；每个 Agent 同时只允许一个待执行命令。
- UCI 默认配置：主控 URL、Agent 监听地址/端口、Mihomo API、代理监听端口及 TUN 开关。
- 安装/升级/卸载脚本：升级保留授权、机器码、节点 YAML 和 Mihomo 数据；卸载默认保留数据，明确确认后才允许清理。
- 构建矩阵：先 x86_64、aarch64；对每个架构生成包、SHA-256、版本元数据和 CI smoke test。

## 必须完成的代码适配

1. 将 Agent 当前硬编码的 /data 持久化路径抽象为 S5M_DATA_DIR，并保持容器环境默认值 /data，确保现有 RouterOS 与 Docker 行为不变。
2. 让 Agent 的机器码、注册配置、运行配置和 Mihomo 更新路径全部使用统一数据目录。
3. 为 OpenWrt 提供明确的 Mihomo 二进制路径配置；禁止更新流程覆盖系统其他路径。
4. 把容器专用启动、健康检查和文件路径逻辑与 OpenWrt procd 运行方式隔离。
5. 增加单元测试，验证自定义数据目录、目录权限、机器码持久化、配置升级保留和内核回滚。
6. 增加 OpenWrt package 构建和静态检查；CI 通过不等同于真实路由器验证。

## 安全与兼容性要求

- 不使用 host 网络、Docker 或容器能力。
- Agent 注册必须使用 HTTPS；明文 HTTP 仅允许沿用现有显式内网 opt-in 安全开关。
- Token、密码和 Mihomo secret 不得写入普通日志。
- 默认不开放代理端口；不自动修改防火墙。
- 不自动启用 TUN，不自动添加全局策略路由，不允许升级过程改变 SSH 管理路径。
- 不覆盖用户现有 Mihomo 配置；写入前备份，校验失败必须回滚。
- 设备空间不足、架构不支持或依赖缺失时必须安全失败，不破坏现有网络。

## 验收标准

- [ ] x86_64 OpenWrt 包构建成功并在真实设备安装。
- [ ] aarch64 OpenWrt 包构建成功并在真实设备安装。
- [ ] procd 能独立启动、停止、重启 Agent 与 Mihomo，重启路由器后自动恢复。
- [ ] 主控注册、授权、心跳、WebSocket 和节点 YAML 同步正常。
- [ ] 设备重启、软件升级后机器码、Token 和配置保持不变。
- [ ] Mihomo 内核更新具备 SHA-256 校验、运行验证和失败回滚。
- [ ] 不修改默认路由、WAN/LAN、DNS、DHCP、防火墙和 SSH 管理链路。
- [ ] TUN 默认关闭；仅在真实设备专项验证后启用。
- [ ] 卸载不会误删持久化数据。

## 开发顺序

阶段 1：Agent 数据目录与二进制路径抽象、单元测试。
阶段 2：OpenWrt procd 服务、UCI 配置和 package Makefile。
阶段 3：x86_64/aarch64 构建、包校验和 CI。
阶段 4：真实设备注册、心跳、配置同步、内核升级与回滚。
阶段 5：按设备型号验证 TUN、DNS 和代理接入；通过后再考虑正式发布。
