# S5M 主控与 Agent 安装、配置和编译部署指南

本文对应仓库 `Tony855/S5M-Master` 的 `main` 分支。主控服务在 Debian/Ubuntu 上原生安装；Agent 可作为 Docker 容器部署。请先固定使用同一发布版本/提交，避免主控与 Agent API 不匹配。

## 1. 架构与端口

- **主控（S5M-Server）**：Web/API、节点管理、Agent 注册与授权、配置下发。原生安装到 `/opt/S5M-Server`，systemd 服务名 `s5m-server`。
- **主控 Mihomo**：运行在主控机上，服务名 `mihomo`；安装脚本不会覆盖一个已存在且能正常运行的 `/opt/mihomo/mihomo`。
- **Agent**：运行在每个受管节点上；提供绑定页面/API（容器内 81），运行 Mihomo（混合代理端口 7890，控制 API 8088）。`/data` 必须使用持久化卷，里面有 `config.yaml` 和绑定凭据 `agent.json`。
- **网络方向**：Agent 必须能访问主控 HTTP(S) 地址；主控不应直接暴露 Agent 的 Mihomo 控制端口 8088。8088 默认只供容器内部本机使用。

| 组件 | 默认端口 | 说明 |
| --- | ---: | --- |
| 主控 Web/API | 80/tcp | 可在 `/etc/s5m-server.env` 的 `S5M_ADDR` 中修改 |
| Agent 绑定页面 | 81/tcp | 建议只向管理网开放；首次绑定后仍需保护 |
| Agent Mihomo 代理 | 7890/tcp | 按节点代理用途和防火墙策略开放 |
| Agent Mihomo API | 8088/tcp | 仅容器内部使用，不要发布到公网 |

## 2. 主控端：Debian/Ubuntu 原生安装

推荐全新 Debian/Ubuntu 服务器，具有 sudo/root 权限、可访问 GitHub，建议先配置 DNS、系统时间和安全组。安装脚本会安装 Go、SQLite、systemd 相关依赖并构建服务。

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl git
git clone https://github.com/Tony855/S5M-Master.git
cd S5M-Master
sudo bash scripts/install.sh
```

脚本成功后检查服务、端口、健康接口：

```bash
sudo systemctl status s5m-server --no-pager -l
sudo systemctl status mihomo --no-pager -l
sudo journalctl -u s5m-server -n 100 --no-pager
sudo journalctl -u mihomo -n 100 --no-pager
curl -fsS http://127.0.0.1/api/v1/health
sudo ss -lntp
```

健康接口应返回含 `"status":"ok"` 的 JSON。若修改过 `S5M_ADDR`，请把上面的 curl 端口替换成配置端口。首次安装生成的管理员凭据保存在 root 专用文件 `/root/S5M-Server-credentials.txt`（仅首次生成新环境配置时创建）；请立即登录并修改密码，不要将该文件发给他人。

### 主控配置文件与服务

- 环境变量：`/etc/s5m-server.env`，权限应为 `0600`。
- 数据库、主控 Mihomo 配置和备份目录：默认位于 `/var/lib/s5m-server/`。
- 主控程序：`/opt/S5M-Server/S5M-Server`。
- systemd 单元：`s5m-server.service`、`mihomo.service`。

查看配置时不要把 JWT、管理员密码、Agent 授权密钥或 Mihomo secret 粘贴到公开 issue/日志中：

```bash
sudo stat -c '%a %U:%G %n' /etc/s5m-server.env /var/lib/s5m-server/config.yaml
sudo systemctl is-enabled s5m-server mihomo
```

### 防火墙建议

只开放业务确实需要的端口。至少不要把主控 Mihomo API（默认 loopback 地址）或 Agent Mihomo API 8088 暴露到公网。若 Agent 绑定页面只供管理员使用，应限制 81/tcp 的来源地址；代理端口 7890 是否开放应按实际业务决定。

## 3. Agent 节点部署

**完整的镜像包下载、SHA256 校验、Ubuntu/Debian Docker 导入运行、RouterOS 容器导入、网络配置、升级回滚和故障排查步骤，请看专门教程：**

[《S5M Agent 详细部署教程（Ubuntu/Debian 与 MikroTik RouterOS）》](DEPLOYMENT_GUIDE_CN.md)

当前 GitHub Actions 工作流导出 `linux/amd64` 和 `linux/arm64` 两种完整容器镜像 tar 包，并作为 Actions Artifacts 提供下载；它不要求从 GHCR 拉取镜像。请先确认对应运行记录中的两个架构构建及 smoke test 均成功，再下载匹配架构的产物。不要把 amd64 镜像用于 ARM64 设备，或把 arm64 镜像用于 x86_64 设备。

镜像包含 Agent、Mihomo 内核及运行所需文件。容器内 Agent 目录为 `/app`，Mihomo 可执行文件为 `/usr/local/bin/mihomo`，必须将 `/data` 持久化挂载；不要将 Mihomo API 8088 端口映射到公网。

## 4. Agent 与主控绑定

1. 登录主控 Web 管理界面，进入 Agent/节点管理，创建或查看该节点的注册授权密钥。授权密钥是敏感信息，只在受信任的管理通道中传递。
2. 在浏览器打开 `http://节点IP:81/`。如果 Agent 页面无法访问，先检查容器状态、宿主机端口映射和防火墙。
3. 在绑定页面填入主控完整地址，例如 `http://主控IP` 或已配置 TLS 的 `https://主控域名`，以及该节点的授权密钥，然后提交。
4. 页面应提示绑定成功；返回主控节点列表确认节点状态。
5. 等待一个心跳周期（约 30 秒），检查 Agent 日志和主控节点状态。绑定成功代表凭据已保存；后续心跳、配置下发和状态上报成功才代表实际通信正常。

主控地址不要包含用户名/密码、查询参数或 URL fragment。跨公网部署应优先使用 HTTPS 或 VPN/管理网，避免明文传输授权密钥。

## 5. Agent 本地编译与交叉编译

仓库中的 Agent 是独立 Go 模块：`s5m-agent/go.mod`。**不要在仓库根目录执行 `go build .`**；主控和 Agent 是不同模块。当前 CI 使用 Go 1.22 进行 Agent 测试和静态检查，容器构建阶段使用 Go 1.23 Alpine builder。

安装 Go 后，从仓库根目录运行：

```bash
cd S5M-Master/s5m-agent
go mod download
gofmt -w .
go test -race -count=1 ./...
go vet ./...
go build -trimpath -o ./s5m-agent .
./s5m-agent
```

最后一步会启动 Agent 常驻进程并尝试访问本地 `/data`，只建议在测试环境运行；日常只需执行前面的测试和编译命令。生成的本地二进制可删除，不需要提交到 Git。

### 构建 Linux amd64 / arm64

在仓库根目录执行：

```bash
cd S5M-Master/s5m-agent
go mod download
go test ./...
go vet ./...
mkdir -p ../dist
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o ../dist/s5m-agent-linux-amd64 .
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags='-s -w' -o ../dist/s5m-agent-linux-arm64 .
sha256sum ../dist/s5m-agent-linux-* > ../dist/SHA256SUMS
file ../dist/s5m-agent-linux-*
```

说明：
- `GOOS=linux` 指定目标系统；`GOARCH=amd64/arm64` 指定 CPU 架构。
- `CGO_ENABLED=0` 生成不依赖目标机 C 运行库的 Go Agent 二进制。
- 交叉编译只证明编译器能生成目标架构文件；需要在相应架构设备或模拟环境做运行/集成测试。
- Agent 二进制本身不包含 Mihomo 内核、HTML 页面或启动脚本。生产部署优先使用完整容器镜像；单独复制二进制不能替代完整镜像。
- Docker 镜像中的 Mihomo 资产会按架构下载并校验 SHA-256。不要关闭校验或用不明来源的二进制替换。

## 6. Agent Docker 镜像构建与验证

在安装了 Docker Buildx 的构建机上，从仓库根目录执行：

```bash
docker buildx build \
  --platform linux/amd64 \
  --file s5m-agent/Dockerfile \
  --tag s5m-agent:local-amd64 \
  --load .

docker run --rm --entrypoint /bin/sh s5m-agent:local-amd64 -c \
  'test -x /app/s5m-agent && test -x /usr/local/bin/mihomo && test -x /healthcheck.sh && /usr/local/bin/mihomo -v'
```

ARM64 镜像可以用支持 QEMU 的 Buildx 构建机验证：

```bash
docker buildx build \
  --platform linux/arm64 \
  --file s5m-agent/Dockerfile \
  --tag s5m-agent:local-arm64 \
  --load .
docker run --rm --platform linux/arm64 --entrypoint /bin/sh s5m-agent:local-arm64 -c \
  'test -x /app/s5m-agent && test -x /usr/local/bin/mihomo && /usr/local/bin/mihomo -v'
```

构建需要访问 Go module 下载源和 Mihomo GitHub Releases；网络或上游资产变更可能导致构建失败。失败时先检查日志中的具体下载 URL、资产名称和 SHA-256，不要直接删除校验步骤。

## 7. GitHub Actions 编译流程

`S5M CI` 工作流负责脚本语法、Go 格式、依赖、测试、静态检查和 amd64/arm64 交叉编译。

`S5M Agent multi-arch images` 工作流负责构建完整 Alpine 镜像、验证 Agent/Mihomo/tini/健康检查脚本，并导出两个架构的镜像 tar 归档和 SHA256 文件。**当前工作流把归档作为 GitHub Actions Artifacts 上传，不再推送 GHCR。** 在 GitHub 仓库的 [Actions 页面](https://github.com/Tony855/S5M-Master/actions/workflows/agent-images.yml)选择对应运行记录，确认两个架构 job 成功后再下载 Artifacts。详细操作见 [部署教程](DEPLOYMENT_GUIDE_CN.md)。

稳定发布通过 `s5m-agent-vX.Y.Z` 标签或 Actions 手动触发并填写语义化版本号（`X.Y.Z`）进行。只有确认 CI、两个架构镜像构建和 smoke test 全部通过后，才应将发布包用于生产环境。

## 8. 升级、备份与恢复

升级前备份主控数据库、环境文件和 Mihomo 配置；Agent 侧备份持久化数据目录。示例：

```bash
sudo install -d -m 0700 /var/backups/s5m-manual
sudo sqlite3 /var/lib/s5m-server/s5m.db \
  '.backup /var/backups/s5m-manual/s5m.db'
sudo cp -a /etc/s5m-server.env /var/backups/s5m-manual/
sudo cp -a /var/lib/s5m-server/config.yaml /var/backups/s5m-manual/
sudo tar -C /opt/s5m-agent -czf /var/backups/s5m-manual/agent-data.tgz data
```

升级后执行健康检查、查看服务日志，并确认 Agent 在主控中在线。不要删除旧数据库或 Agent 的 `/data` 卷来解决普通升级问题；其中包含注册状态与本地配置。

## 9. 故障排查清单

- **主控安装失败**：检查 `sudo journalctl -u s5m-server -n 150 --no-pager`、Go 下载是否成功，以及 `/var/lib/s5m-server` 权限。
- **主控 Mihomo 版本/状态不可见**：检查 `sudo systemctl status mihomo`、`sudo journalctl -u mihomo -n 150 --no-pager`、配置中的 `external-controller` 是否为 loopback 地址、`secret` 是否与环境配置一致。
- **Agent 容器不断重启**：`docker logs --tail 200 s5m-agent`；检查 Mihomo 配置是否能通过启动校验、持久化目录是否可写、容器架构是否正确。
- **Agent 页面打开但节点不在线**：检查主控地址、授权密钥、主控健康接口、两端网络/时间和 Agent 日志；绑定页显示凭据存在并不能单独证明连接正常。
- **Docker 构建失败**：确认构建上下文是仓库根目录 `.`，并使用 `-f s5m-agent/Dockerfile`；检查 `s5m-agent/go.mod`、`s5m-agent/go.sum` 是否存在、Go modules 与 Mihomo release 是否可下载。
- **架构错误**：`uname -m` 查看设备架构；常见映射为 `x86_64 → amd64`、`aarch64 → arm64`。不要在未验证的 CPU 架构上复用另一架构的二进制。


## 10. Ubuntu 24.04：从本地 tar 镜像完整重装 Agent（清除旧 Agent 数据）

本节适用于已下载完整镜像包到 `/root/s5m-agent-linux-amd64.tar` 的 Ubuntu/Debian x86_64 节点。**这是破坏性重装流程**：会删除旧的 `s5m-agent` 容器、旧 Agent 专用目录 `/opt/s5m-agent` 和旧的同名测试镜像；不会清空 Docker 全局目录，也不会删除其他项目的容器、镜像或卷。执行前确认目标容器名称和目录确实只供 S5M Agent 使用。

### 10.1 确认系统、镜像包和 Docker 正常

逐段复制执行，不要把多条命令拆开后漏掉反斜杠：

```bash
uname -m
# 本教程 amd64 镜像预期输出 x86_64

ls -lh /root/s5m-agent-linux-amd64.tar
file /root/s5m-agent-linux-amd64.tar
tar -tf /root/s5m-agent-linux-amd64.tar >/dev/null \
  && echo "镜像归档结构正常" \
  || { echo "镜像包损坏或不是 tar 文件，停止操作"; exit 1; }

systemctl is-active docker
systemctl is-active containerd
docker info
```

如果系统不是 `x86_64`、Docker/containerd 未运行，或 `docker info` 报错，请先处理对应问题，不要继续清理。若镜像包旁有 GitHub Actions 提供的 SHA256 文件，应先用 `sha256sum -c 文件名.sha256` 校验；校验文件必须与该镜像包来自同一次构建产物。

### 10.2 删除旧 Agent（不保留旧数据）

```bash
docker rm -f s5m-agent 2>/dev/null || true
docker image rm s5m-agent:amd64-test 2>/dev/null || true
docker image rm s5m-agent:local 2>/dev/null || true
rm -rf -- /opt/s5m-agent
install -d -m 0750 /opt/s5m-agent/data
```

以上会清除旧 Agent 的本地绑定凭据和配置。重装后通常需要在主控重新核对/生成节点授权并重新绑定。**不要执行** `rm -rf /var/lib/docker`、`rm -rf /var/lib/containerd` 或清理全局 Docker 资源的命令；这些目录可能包含其他业务数据，而且删除它们会破坏容器运行时。

### 10.3 导入镜像并确认实际标签

```bash
docker load -i /root/s5m-agent-linux-amd64.tar
docker image ls
```

从输出确认刚导入的镜像名称和标签。GitHub Actions 导出的 amd64 测试镜像通常标记为 `s5m-agent:amd64-test`。如果实际输出不是这个标签，后面的启动命令必须把镜像名替换成实际值，不能猜标签。

### 10.4 启动容器（Agent 管理端口 + Mihomo 代理端口）

若导入结果确实是 `s5m-agent:amd64-test`，执行下面**完整的一条命令**。请从 `docker run` 开始一次性复制到最后一行：

```bash
docker run -d \
  --name s5m-agent \
  --restart unless-stopped \
  -p 81:80 \
  -p 7890:7890 \
  -v /opt/s5m-agent/data:/data \
  -v /etc/machine-id:/etc/machine-id:ro \
  s5m-agent:amd64-test
```

端口说明：

- `81:80`：宿主机 TCP/81 转发到容器内 Agent 页面/API TCP/80。
- `7890:7890`：将 Mihomo mixed-port 发布到宿主机 TCP/7890，供其他设备使用代理时需要。若只在本机测试，建议改为 `-p 127.0.0.1:7890:7890`；若要让局域网/公网客户端连接，必须先确认 Mihomo 监听地址、配置认证/访问策略，并在云安全组和主机防火墙中仅放行可信来源。**不要把未受保护的 7890 直接暴露到整个公网，避免形成开放代理。**
- `/data`：Agent 配置与绑定凭据存储位置。本流程先删除旧数据再创建新目录。
- `/etc/machine-id:ro`：只读提供宿主机稳定机器标识；请勿在重装时随意生成新机器标识。
- 不要映射 Mihomo 控制 API TCP/8088；它只应供容器内部 Agent 使用。
- 不要添加 `--init`；当前镜像入口由 `/init` 管理。

### 10.5 检查容器、日志、端口和接口

```bash
docker ps -a --filter 'name=^/s5m-agent$'
docker inspect s5m-agent --format '状态={{.State.Status}} 重启次数={{.RestartCount}}'
docker logs --tail 150 s5m-agent
docker port s5m-agent
ss -lntp | grep -E ':(81|7890)\b' || true

curl -i --max-time 10 http://127.0.0.1:81/api/config
curl -i --max-time 10 http://127.0.0.1:81/api/machine-id
```

HTTP 接口需要有响应；具体状态码和响应内容应结合该版本接口实现判断。再检查主控中节点的绑定状态、最后心跳和日志。容器启动成功不等于已经完成主控注册；需要确认绑定、心跳和配置同步都正常。

如容器启动失败：

```bash
docker logs --tail 200 s5m-agent
docker inspect s5m-agent --format '{{json .State}}'
journalctl -u docker -u containerd -n 100 --no-pager
```

若 `docker load` 报 containerd content/ingest 目录不存在，停止重复删除/重装；先检查 `systemctl status containerd docker`、`docker info` 和日志，修复运行时后再导入。不要靠删除 `/var/lib/containerd` 来尝试解决。

### 10.6 命令换行常见错误

正确写法是每一行（最后的镜像名除外）都以反斜杠 `\` 结尾。例如 `-p 7890:7890 \` 后面才可以继续下一行。如果第一行在 `-p 7890:7890` 后没有反斜杠，shell 会立刻执行一个缺少镜像名的 `docker run`，随后把 `-v` 当成独立命令并报 `-bash: -v: command not found`。出现这种情况时，不要继续输入剩余行；请从完整的 `docker run` 命令重新复制执行。
