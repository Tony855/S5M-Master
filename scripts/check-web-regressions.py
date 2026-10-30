#!/usr/bin/env python3
"""Guard against regressions in the embedded S5M control-center UI."""
from pathlib import Path

html = Path("source/web/index.html").read_text(encoding="utf-8")
instance_card_start = html.index('v-for="item in filteredAgentEntries"')
instance_card_end = html.index("page === 'config'", instance_card_start)
instance_card_section = html[instance_card_start:instance_card_end]
app_js = Path("source/web/app.js").read_text(encoding="utf-8")
configgen = Path("source/internal/app/configgen.go").read_text(encoding="utf-8")
handlers = Path("source/internal/app/handlers.go").read_text(encoding="utf-8")
handlers_test = Path("source/internal/app/handlers_test.go").read_text(encoding="utf-8")
template_source = Path("source/internal/app/template.go").read_text(encoding="utf-8")
router = Path("source/internal/app/router.go").read_text(encoding="utf-8")
import_handler = handlers[handlers.index("func (a *App) handleImportProxies"):handlers.index("func (a *App) handleAgentRegister")]
rollback_impl = configgen[configgen.index("func (a *App) Rollback"):configgen.index("func (a *App) Rollback")+5000]
ui = html + "\n" + app_js

checks = {
    "Linux Agent deployment explicitly isolates TUN routes in Docker bridge network to protect host SSH": (
        '--network bridge' in Path("scripts/s5m-deploy.sh").read_text(encoding="utf-8").split("docker run -d", 1)[1].split('|| die "容器启动失败"', 1)[0]
        and '--network host' not in Path("scripts/s5m-deploy.sh").read_text(encoding="utf-8").split("docker run -d", 1)[1].split('|| die "容器启动失败"', 1)[0]
        and "Keep Mihomo TUN routes inside the Agent container's network namespace" in Path("scripts/s5m-deploy.sh").read_text(encoding="utf-8")
        and 'if [ "$network_mode" != "bridge" ]; then' in Path("scripts/s5m-deploy.sh").read_text(encoding="utf-8")
    ),
    "Mihomo template version deletion has a protected current-version and node-binding guard": "handleDeleteMihomoTemplateVersion" in template_source and "不能删除当前发布版本" in template_source and "FROM node_template_bindings WHERE source='template' AND template_version=?" in template_source and '"DELETE /api/v1/mihomo/template/{version}"' in router,
    "Mihomo template history UI exposes guarded deletion with confirmation": "deleteMihomoTemplateVersion" in app_js and "ElMessageBox.confirm" in app_js and "scope.row.version === templateCurrentVersion" in html,

    "Agent runtime status explains missing telemetry and reports last_error": "let runtimeMessage" in app_js and "runtimeMessage = last > 0" in app_js and "runtimeMessage" in html and "Agent 状态/错误信息：" in html and "有认证通信记录，但没有有效运行状态" in app_js,
    "browser realtime WebSocket requires an authenticated one-time short-lived ticket": "POST /api/v1/events/ticket" in Path("source/internal/app/router.go").read_text(encoding="utf-8") and "GET /api/v1/events/ws" in Path("source/internal/app/router.go").read_text(encoding="utf-8") and "ExpiresAt: now.Add(30 * time.Second)" in handlers and "delete(a.browserTickets, ticket)" in Path("source/internal/app/agent_websocket.go").read_text(encoding="utf-8"),
    "browser realtime WebSocket validates same-origin and current enabled admin account": "browserEventsUpgrader" in Path("source/internal/app/agent_websocket.go").read_text(encoding="utf-8") and "strings.EqualFold(parsed.Host, r.Host)" in Path("source/internal/app/agent_websocket.go").read_text(encoding="utf-8") and 'u.Role != "admin"' in Path("source/internal/app/agent_websocket.go").read_text(encoding="utf-8"),
    "Agent heartbeats and command ACKs publish browser events only after persistence": '"type": "agent.status.updated"' in Path("source/internal/app/agent_websocket.go").read_text(encoding="utf-8") and '"type": "agent.command.updated"' in Path("source/internal/app/agent_websocket.go").read_text(encoding="utf-8") and "a.publishBrowserEvent" in Path("source/internal/app/agent_websocket.go").read_text(encoding="utf-8"),
    "browser realtime client requests a ticket, reconnects, and locally expires stale Agent status": "api('/api/v1/events/ticket', { method: 'POST' })" in app_js and "new WebSocket(" in app_js and "browserEventsRetryTimer" in app_js and "age >= 90" in app_js and "realtimeStatus" in html,
    "Agent online state rejects future heartbeat timestamps without container runtime API": "const ageSeconds = now - last;" in app_js and "const online = last > 0 && ageSeconds >= 0 && ageSeconds < 90;" in app_js and "/api/v1/container/" not in app_js and "dockerTask" not in app_js and "routerOSCommand" not in app_js,
    "container-management routes, handlers, and Agent task polling remain removed": not Path("source/internal/app/container_handlers.go").exists() and not Path("source/internal/app/container_auth.go").exists() and "/api/v1/container/" not in Path("source/internal/app/router.go").read_text(encoding="utf-8") and "processContainerTask" not in Path("s5m-agent/main.go").read_text(encoding="utf-8") and "reportContainerStatus" not in Path("s5m-agent/main.go").read_text(encoding="utf-8"),
    "mobile instance grid rule is not duplicated": Path("source/web/app.css").read_text(encoding="utf-8").count(".instance-list{grid-template-columns:minmax(0,1fr)}") == 1,
    "installer rolls back prior config and service files when Mihomo or server startup fails": 'rollback_install "主控 Mihomo 启动失败"' in Path("scripts/install.sh").read_text(encoding="utf-8") and 'rollback_install "S5M-Server 启动失败"' in Path("scripts/install.sh").read_text(encoding="utf-8") and "rollback_install()" in Path("scripts/install.sh").read_text(encoding="utf-8"),
    "installer snapshots and restores env and node Mihomo YAML during failed health-check rollback": 'cp -a "$ENV_FILE" "$BACKUP/s5m-server.env"' in Path("scripts/install.sh").read_text(encoding="utf-8") and 'cp -a "$BACKUP/s5m-server.env" "$ENV_FILE"' in Path("scripts/install.sh").read_text(encoding="utf-8") and 'cp -a "$DB_DIR/config.yaml" "$BACKUP/config.yaml"' in Path("scripts/install.sh").read_text(encoding="utf-8") and 'cp -a "$BACKUP/config.yaml" "$DB_DIR/config.yaml"' in Path("scripts/install.sh").read_text(encoding="utf-8"),
    "installer rollback removes newly created binaries/units when no previous install existed": 'elif [[ -f "$BACKUP/server-bin-absent" ]]; then' in Path("scripts/install.sh").read_text(encoding="utf-8") and 'elif [[ -f "$BACKUP/server-service-absent" ]]; then' in Path("scripts/install.sh").read_text(encoding="utf-8") and 'elif [[ -f "$BACKUP/mihomo-service-absent" ]]; then' in Path("scripts/install.sh").read_text(encoding="utf-8"),
    "installer rollback restarts restored Mihomo and uses one shared health-check rollback path": 'systemctl restart mihomo || echo "❌ Mihomo 回滚启动失败' in Path("scripts/install.sh").read_text(encoding="utf-8") and 'rollback_install "健康检查失败（端口 $PORT）"' in Path("scripts/install.sh").read_text(encoding="utf-8") and '正在回滚二进制...' not in Path("scripts/install.sh").read_text(encoding="utf-8"),
    "Mihomo API settings are detected only at YAML top level and controller stays loopback-only": "s/^secret:[[:space:]]*" in Path("scripts/install.sh").read_text(encoding="utf-8") and "s/^external-controller:[[:space:]]*" in Path("scripts/install.sh").read_text(encoding="utf-8") and "grep -qE '^secret[[:space:]]*:'" in Path("scripts/install.sh").read_text(encoding="utf-8") and "grep -qE '^external-controller[[:space:]]*:'" in Path("scripts/install.sh").read_text(encoding="utf-8") and "127.0.0.1:%s" in Path("scripts/install.sh").read_text(encoding="utf-8"),
    "Mihomo systemd unit includes required config-file DAC capability": "CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_DAC_OVERRIDE" in Path("scripts/install.sh").read_text(encoding="utf-8") and "AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_DAC_OVERRIDE" in Path("scripts/install.sh").read_text(encoding="utf-8"),
    "legacy unused frontend helpers remain removed": all(not __import__("re").search(r"\b" + name + r"\b", app_js) for name in ("parseProxyLine", "loadConfig", "saveConfig", "publishConfig")),
    "system logs query current and legacy service units and report journal read errors": 'exec.Command("journalctl", "-u", "s5m-server", "-u", "s5m-next"' in handlers and "读取 S5M systemd 日志失败" in handlers and "SupplementaryGroups=systemd-journal" in Path("scripts/install.sh").read_text(encoding="utf-8"),
    "shared JSON decoder bounds request bodies and rejects trailing JSON values": "const maxJSONRequestBody = 2 << 20" in handlers and "func decodeLimited(r *http.Request, maxBytes int64, sizeLabel string, v any) error" in handlers and "io.LimitReader(r.Body, maxBytes+1)" in handlers and "decodeLimited(r, maxJSONRequestBody, \"2 MiB\", v)" in handlers and "TestDecodeBoundsJSONRequestBody" in handlers_test,
    "bulk proxy import bounds request body and uses validated structured parser": "http.MaxBytesReader(w, r.Body, 1<<20)" in handlers and "parseProxyImportContent(in.Content)" in import_handler and "func parseProxyImportContent(content string)" in handlers,
    "proxy validation rejects unsupported protocols and normalizes supported protocol": "代理类型无效" in handlers and '"socks5", "http", "ss", "vmess", "vless", "trojan"' in handlers and "TestValidateProxyRejectsUnsupportedProtocol" in handlers_test,
    "instance creation trims and validates name, machine code, and HTTP API URL": "func validateInstance(in *Instance) string" in handlers and "url.ParseRequestURI(in.APIURL)" in handlers and "TestValidateInstance" in handlers_test,
    "Agent registration trims and bounds machine code and secret": "func validateAgentRegistrationInput(machineCode, secret string)" in handlers and "TestValidateAgentRegistrationInput" in handlers_test,
    "proxy validation rejects unknown modes and out-of-range ports": '"运行模式无效' in handlers and '"代理端口必须在 1-65535 之间"' in handlers and 'case "proxy", "china", "global", "split", "return", "game":' in handlers,
    "unbound proxies are explicitly labeled and never described as global sync entries": "留空为未绑定；选择全局节点可同步到所有已授权节点" in html and "未关联节点实例，不会同步到节点配置" in html and "全局节点（同步到所有已授权节点）" in html and "选择“全局节点”会同步到所有已授权节点" in html,
    "node config generation excludes unbound proxies from every registered node": 'p.MachineCode == "__GLOBAL__"' in Path("source/internal/app/configgen.go").read_text(encoding="utf-8") and "TestBuildConfigSupportsExplicitGlobalAndUnboundProxies" in Path("source/internal/app/configgen_test.go").read_text(encoding="utf-8"),
    "proxy form retains mode and complete extra JSON": "extra_json: '{}'" in ui and "row.mode] || row.mode || 'return'" in ui and "extra_json: JSON.stringify(extra, null, 2)" in ui,
    "proxy save sends mode and parsed extra": "name: proxyForm.name, mode: proxyForm.mode || 'return'" in ui and "extra: extra" in ui and "extra = JSON.parse(proxyForm.extra_json || '{}')" in ui,
    "proxy editor rejects invalid/non-object JSON": "高级参数 JSON 格式无效" in ui and "高级参数必须是 JSON 对象" in ui,
    "proxy sync failure is reported as partial success": "代理数据已保存，但节点配置同步失败" in ui and "同步失败" in ui,
    "proxy deletion sync failure refreshes list and offers retry": "if (message.includes('代理已删除'))" in app_js and "await loadProxies();" in app_js and "立即重试同步所有节点" in app_js,
    "bulk proxy import synchronizes authorized node configs and exposes partial failure": "if successCount > 0" in import_handler and "syncAuthorizedNodeConfigs()" in import_handler and '"sync_failed": syncFailed' in import_handler and "data.sync_failed" in app_js and "代理导入已完成" in app_js,
    "JSON proxy import inherits the top-level protocol without silently defaulting to SOCKS5": "parsedJSON.protocol || parsedJSON.type || parsedJSON.scheme" in app_js and "item.type || item.protocol || item.scheme || inheritedProtocol || ''" in app_js and "item.type || item.protocol || 'socks5'" not in app_js,
    "JSON proxy import preserves direct VMess links and protocol-specific VMess/SS options": "item.uri || item.url || item.link || item.proxy || item.vmess_link || item.vmessLink" in app_js and "if (type === 'vmess')" in app_js and "if (type === 'ss')" in app_js,
    "system operations page exposes protected logs and Mihomo update": 'index="system">系统运维</el-menu-item>' in ui and "loadSystemLogs" in ui and "type: 'system.logs.get'" in app_js and "/api/v1/logs" not in app_js and "/api/v1/mihomo/update" in app_js and ("type: 'mihomo.status.get'" in app_js or "/api/v1/mihomo/status" in app_js),
    "master Mihomo update is distinguished from Agent updates and requires confirmation": "主控服务器 Mihomo 内核" in html and "当前 Mihomo 版本" in html and "systemd 服务状态" in html and "不会更新各个 Agent 节点" in html and "确认更新主控 Mihomo" in app_js and "ElementPlus.ElMessageBox.confirm" in app_js[app_js.index("const updateKernel ="):app_js.index("const loadSystemLogs")],
    "master Mihomo status distinguishes disk binary, systemd service, and live API version": '"api_version"' in handlers and '"api_online"' in handlers and '"version_mismatch"' in handlers and "runningMihomoAPIVersion" in handlers and "运行中 API 版本" in html and "mainMihomoStatus.api_error" in html,
    "system operations page is reachable through page navigation allowlist": "const PAGES = ['dashboard','proxies','instances','config','system']" in app_js and "if (v === 'system') { loadSystemLogs(); loadMainMihomoStatus(); }" in app_js,
    "backup download uses Authorization header and restore has destructive confirmation": "fetch('/api/v1/backup', { headers: authHeaders() })" in ui and "/api/v1/backup?token=" not in ui and "/api/v1/restore" in ui and "128 MiB" in ui and "确认恢复数据库" in ui,
    "client subscription link is displayed after the per-node YAML editor at the bottom of the config page": html.index("客户端订阅链接") > html.index("保存当前节点配置") and html.index("客户端订阅链接") > html.index("节点独立配置 (YAML)"),
    "administrator account control is compact and hides role label from the main status bar": 'class="admin-menu-trigger"' in html and 'class="admin-user-text"' not in html and 'class="admin-avatar"' in html and 'class="admin-chevron"' in html and '管理员菜单' in html,
    "subscription URL trims blank settings and always initializes a usable absolute fallback": "const fallback = new URL('/api/v1/subscribe', window.location.href).toString();" in app_js and "String(s.subscribe_url || s.sub_url || '').trim()" in app_js and "subUrl.value = configured || fallback;" in app_js,
    "Agent binding button requires a non-empty token and hides backend diagnostics from end users": '<button id="btn" onclick="save()" disabled>' in Path("s5m-agent/index.html").read_text(encoding="utf-8") and 'oninput="updateBindButton()"' in Path("s5m-agent/index.html").read_text(encoding="utf-8") and "bindingInProgress || !secret" in Path("s5m-agent/index.html").read_text(encoding="utf-8") and "主控地址或授权密钥无效" not in Path("s5m-agent/index.html").read_text(encoding="utf-8") and "S5M_ALLOW_INSECURE_HTTP" not in Path("s5m-agent/index.html").read_text(encoding="utf-8") and "/data 挂载" not in Path("s5m-agent/index.html").read_text(encoding="utf-8") and "请检查 Agent 日志" not in Path("s5m-agent/index.html").read_text(encoding="utf-8"),
    "Mihomo template page provides a safe starter with empty proxy sections and baseline rules": "defaultMihomoTemplate" in Path("source/internal/app/template.go").read_text(encoding="utf-8") and "draft = defaultMihomoTemplate" in Path("source/internal/app/template.go").read_text(encoding="utf-8") and "REPLACE_WITH_A_UNIQUE_RANDOM_SECRET" in Path("source/internal/app/template.go").read_text(encoding="utf-8") and "YOUR_PROXY_SERVER" not in Path("source/internal/app/template.go").read_text(encoding="utf-8") and "221111cdn" not in Path("source/internal/app/template.go").read_text(encoding="utf-8"),
    "generated Mihomo defaults use loopback DNS, Fake-IP filters, and controller direct routing": "listen: 127.0.0.1:5353" in configgen and "'+.v2net.cc'" in configgen and "DOMAIN-SUFFIX,v2net.cc,DIRECT" in configgen and "tun:\n    enable: false" in configgen,
    "configuration UI focuses on per-node YAML and removes unused global draft panel": "selectedConfigNode" in ui and "节点独立配置 (YAML)" in html and "全局配置与版本发布" not in html and "globalConfigYaml" not in app_js,
    "global config draft endpoint bounds request size and validates YAML before persistence": "decodeLimited(r, 2<<20, \"2 MiB\", &in)" in handlers and "全局 YAML 语法错误" in handlers and "全局 YAML 必须是非空对象" in handlers,
    "global config save response does not falsely claim Agent rollout": "尚未发布" in handlers and "不会自动更新节点独立 YAML" in handlers and "Agent 将在 30 秒内拉取更新" not in handlers,
    "global config version APIs remain backend-only for compatibility": "/api/v1/config/versions" in Path("source/internal/app/router.go").read_text(encoding="utf-8") and "/api/v1/config/rollback" in Path("source/internal/app/router.go").read_text(encoding="utf-8") and "确认回滚配置" not in ui,
    "backend rollback still syncs the saved global draft": 'UpdateSettings(map[string]string{"config_yaml": yml})' in configgen and "回滚已完成，但全局配置草稿同步失败" in configgen,
    "backend rollback keeps current database-managed proxy/rule sections": "BuildConfigForMachine(\"\")" in rollback_impl and "mergeManagedProxySections(yml, managedYAML)" in rollback_impl,
    "node config sync has an authenticated retry action": "type: 'nodes.config-sync.retry'" in app_js and "/api/v1/nodes/config-sync" not in app_js and "retryNodeConfigSync" in ui and "立即重试同步所有节点" in ui,
    "primary UI loads the extracted application bundle": 'src="/app.js"' in html and Path("source/web/app.js").is_file() and Path("source/web/app.js").stat().st_size > 10000,
    "main UI stylesheet is external and present": '<link rel="stylesheet" href="/app.css">' in html and "<style>" not in html and Path("source/web/app.css").is_file() and Path("source/web/app.css").stat().st_size > 1000,
    "per-agent Mihomo update automatically fetches official stable release metadata over authenticated WebSocket RPC and queues verified checksum": "openAgentKernelUpdate(item.code)" in ui and "type: 'agent.mihomo.update-info'" in app_js and "/api/v1/agents/kernel-update-info?machine_code=" not in app_js and "latest_version" in ui and "kernelUpdateInfo.arch" in ui and "handleAgentMihomoUpdateInfo" in handlers and "一键更新" in ui,
    "Agent Mihomo update exposes pending and final results without a stale hardcoded default": "pending_command" in handlers and "command_result" in handlers and "item.pendingCommand.type === 'update_mihomo'" in html and "item.commandResult.type === 'update_mihomo'" in html and "kernelUpdateVersion.value = ''" in app_js and "kernelUpdateVersion.value = 'v1.19.31'" not in app_js,
    "Agent Mihomo update validates semantic version using literal dots and digit classes": r"if (!/^v\d+\.\d+\.\d+$/.test(version))" in app_js and r"if (!/^v\\d+\\.\\d+\\.\\d+$/.test(version))" not in app_js,
    "global Mihomo update validates candidate binary and confirms the live version before reporting success": "candidateVersion != release.TagName" in handlers and "copyFileAtomic(binaryPath, backupPath)" in handlers and "waitForMihomoAPIVersion(candidateVersion, 30*time.Second)" in handlers and "已更新并确认运行版本为 " in handlers,
    "global Mihomo update checks HTTP status and service recovery paths": "resp.StatusCode < 200 || resp.StatusCode >= 300" in handlers and "自动恢复旧二进制失败" in handlers and "systemctl" in handlers,
    "Mihomo update falls back from proxy error pages to direct gzip download": "isGzipHeader(header[:n])" in handlers and "if err := download(\"https://ghproxy.net/\" + assetURL); err != nil" in handlers and "func TestIsGzipHeader" in Path("source/internal/app/mihomo_update_test.go").read_text(encoding="utf-8"),
}
# Every simple event handler used in the main Vue template must be exposed by setup().
event_names = set()
for match in __import__("re").finditer(r'@(click|change|input|keyup|submit|selection-change|current-change|size-change|close|confirm|upload|remove|preview|success|error|clear|visible-change|command)\s*=\s*["\']([A-Za-z_$][\w$]*)["\']', html):
    event_names.add(match.group(2))
return_start = app_js.rfind("return {")
return_end = app_js.find("\n    };", return_start)
returned = app_js[return_start:return_end] if return_start >= 0 and return_end >= 0 else ""
missing_handlers = sorted(name for name in event_names if not __import__("re").search(r"\b" + __import__("re").escape(name) + r"\b", returned))
checks["simple template event handlers are exposed by Vue setup"] = not missing_handlers
if missing_handlers:
    print("Missing setup return handlers: " + ", ".join(missing_handlers))


# Keep frontend API calls and backend route declarations in sync. This catches
# accidental path/method drift when either the Vue UI or Go router is refactored.
template_source = Path("source/internal/app/template.go").read_text(encoding="utf-8")
router_source = Path("source/internal/app/router.go").read_text(encoding="utf-8")
route_patterns = set(
    (method, path)
    for method, path in __import__("re").findall(
        r'"(GET|POST|PUT|DELETE|PATCH) (/api/v1/[^"]+)"\s*:', router_source
    )
)
route_patterns.update(
    __import__("re").findall(
        r'mux\.HandleFunc\("(GET|POST|PUT|DELETE|PATCH) (/api/v1/[^"]+)"\s*,',
        router_source,
    )
)

def normalize_route(path):
    path = path.split("?", 1)[0].rstrip("/")
    return __import__("re").sub(r"\{[^/]+\}", "{param}", path)

ui_api_calls = []
for match in __import__("re").finditer(
    r"""\bapi\(\s*(['"])(/api/v1/[^'"]+)\1\s*(?:,\s*\{\s*method:\s*(['"])(GET|POST|PUT|DELETE|PATCH)\3)?""",
    app_js,
):
    method = match.group(4) or "GET"
    path = match.group(2).split("?", 1)[0]
    ui_api_calls.append((method, path))

missing_api_routes = []
for method, path in sorted(set(ui_api_calls)):
    normalized = normalize_route(path)
    exact_match = any(
        route_method == method and normalize_route(route_path) == normalized
        for route_method, route_path in route_patterns
    )
    # A trailing slash literal indicates that the UI appends a path parameter
    # using string concatenation (for example, /proxies/ + id).
    prefix_match = path.endswith("/") and any(
        route_method == method and normalize_route(route_path).startswith(normalized + "/")
        for route_method, route_path in route_patterns
    )
    if not exact_match and not prefix_match:
        missing_api_routes.append(f"{method} {path}")

checks["frontend API calls resolve to backend routes"] = not missing_api_routes
if missing_api_routes:
    print("Frontend API routes without backend declarations: " + ", ".join(missing_api_routes))



# Responsive instance-card styling and safety invariants. These checks keep the
# visual refinement from silently regressing in future frontend changes.
css = Path("source/web/app.css").read_text(encoding="utf-8")
instance_card_checks = {
    "instance cards use a two-column desktop grid and three columns on wide screens": "grid-template-columns: repeat(2, minmax(0, 1fr));" in css and "@media (min-width: 1500px)" in css and ".instance-panel .instance-list { grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 18px; }" in css,
    "instance grid collapses to one column at medium and mobile widths": "@media (max-width: 1050px)" in css and ".instance-panel .instance-list { grid-template-columns: minmax(0, 1fr); }" in css and "@media (max-width: 760px)" in css,
    "instance action buttons become a two-column grid on mobile": ".instance-row .instance-actions { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px; }" in css,
    "instance card header groups machine code and copy action, aligns status chips, and presents host metadata as a compact row": "instance-identity-top" in html and "instance-copy-button" in html and "safeCopy(item.code)" in html and "instance-statuses" in html and "instance-host-label" in html and "主机与系统" in html and "instance-host-system" in html and "instance-summary-mihomo" in html and "instance-summary-update" in html and ".instance-identity-top" in css and ".instance-statuses" in css and "grid-template-areas: \"identity statuses\" \"host host\"" in css and "grid-template-areas: \"identity\" \"statuses\" \"host\"" in css and ".instance-host-system strong" in css,
    "Mihomo versions normalize repeated v/V prefixes before the UI display prefix": "const normalizeMihomoVersion = (value) => {" in app_js and "replace(/^(?:v)+/i, '')" in app_js and "normalizeMihomoVersion(status.mihomo_version)" in app_js and "item.online ? 'v' : '最后上报 v'" in html,
    "offline Agent never presents cached Mihomo health as currently running": "mihomoRunning: online && status.mihomo_healthy === true" in app_js and "状态未知（Agent 离线）" in html and "最后上报 v" in html and "!item.online ? 'is-unknown'" in html,
    "Mihomo version normalization regression covers plain, single-prefix, and repeated-prefix values": "vv1.19.33" in Path("scripts/check-web-regressions.py").read_text(encoding="utf-8") and "1.19.33" in Path("scripts/check-web-regressions.py").read_text(encoding="utf-8"),
    "instance cards show last-report timestamp once in the compact summary with no removed details panel": instance_card_section.count("最后上报：") == 1 and "状态更新时间" not in instance_card_section and "instance-detail-label" not in instance_card_section and "instance-summary-updated" not in instance_card_section,
    "scheme A shows the full machine-code copy label and preserves the four original actions": "复制机器码" in instance_card_section and "safeCopy(item.code)" in instance_card_section and all(handler in instance_card_section for handler in ("openProxiesForMachine(item.code)", "openNodeConfigForMachine(item.code)", "openAgentKernelUpdate(item.code)", "deleteAgent(item.code)")),
    "scheme A combines Mihomo runtime state and version on one row, with update result on the next row": "Mihomo 运行状态" in instance_card_section and "instance-mihomo-runtime" in instance_card_section and "instance-summary-mihomo" in instance_card_section and "instance-mihomo-version" in instance_card_section and "instance-update-row" in instance_card_section and "instance-summary-update" in instance_card_section and "Mihomo：" not in instance_card_section and "Mihomo 更新：" not in instance_card_section,
    "scheme A keeps host, authorization, Agent state, and live telemetry visible": "instance-host-system" in instance_card_section and "item.authorized" in instance_card_section and "item.online" in instance_card_section and "item.connections" in instance_card_section and "item.uploadSpeed" in instance_card_section and "item.downloadSpeed" in instance_card_section and "item.updated_at" in instance_card_section and "proxyCountForMachine(item.code)" in instance_card_section,
    "instance list refresh is manual and silent, with no 10-second polling timer": "const agentRefreshing = ref(false);" in app_js and "if (agentLoading.value || agentRefreshing.value) return;" in app_js and "静默刷新实例失败，保留现有列表" in app_js and "instanceRefreshTimer" not in app_js and ' :loading="agentLoading || agentRefreshing"' in html,
    "silent instance refresh keeps stable card identity and does not reset search/filter state": 'v-for="item in filteredAgentEntries" :key="item.code"' in html and "const agentSearch = ref('');" in app_js and "const agentStatusFilter = ref('all');" in app_js and "const loadAgentsData = async () => {" in app_js and "agentSearch.value =" not in app_js[app_js.index("const loadAgentsData = async () => {"):app_js.index("const loadAgentsData = async () => {") + 9000] and "agentStatusFilter.value =" not in app_js[app_js.index("const loadAgentsData = async () => {"):app_js.index("const loadAgentsData = async () => {") + 9000],
    "instance cards use tighter padding and restrained action-button colors": ".instance-row { padding: 13px; border-radius: 12px;" in css and "--el-button-bg-color: #f0f6ff" in css and "--el-button-bg-color: #fff8ed" in css,
    "runtime status palette includes online, offline, warning, and unknown states": all(token in css for token in (".status-badge.status-online", ".status-badge.status-offline", ".status-badge.status-warning", ".status-badge.status-unknown")),
    "instance list does not expose token plaintext and keeps all four management actions": "{{ item.token }}" not in html and "item.token" not in html and all(handler in html for handler in ("openProxiesForMachine(item.code)", "openNodeConfigForMachine(item.code)", "openAgentKernelUpdate(item.code)", "deleteAgent(item.code)")),
    "instance card layout prevents long machine identifiers from forcing overflow": ".instance-row {\n  min-width: 0;" in css and ".instance-row .agent-code {\n  min-width: 0;" in css and "overflow-wrap: anywhere;" in css,
}
checks.update(instance_card_checks)


checks.update({
    "Mihomo DNS/TUN quick toggles read only top-level YAML sections and normalize boolean values": (
        "const start = lines.findIndex(line => new RegExp('^' + section" in app_js
        and "const isYamlEnabled = value => /^(?:true|yes|on)$/i.test" in app_js
        and "configDnsEnabled.value = isYamlEnabled(readYamlScalar(configYaml.value, 'dns', 'enable'))" in app_js
    ),
    "desktop proxy list displays the persisted source IP CIDR": 'prop="source_cidr" label="源 IP (CIDR)"' in html,
    "mobile proxy cards display the persisted source IP CIDR with legacy fallback": 'proxy-mobile-label">源 IP (CIDR)' in html and "item.source_cidr ||" in html,
    "desktop proxy association label handles global sentinel before generic machine code": (
        'v-if="scope.row.machine_code === \'__GLOBAL__\'"' in html
        and html.index('v-if="scope.row.machine_code === \'__GLOBAL__\'"')
        < html.index('v-else-if="scope.row.machine_code"')
        and "同步至所有已授权节点" in html
    ),
    "mobile proxy association label handles global sentinel before generic machine code": (
        'v-if="item.machine_code === \'__GLOBAL__\'"' in html
        and html.index('v-if="item.machine_code === \'__GLOBAL__\'"')
        < html.index('v-else-if="item.machine_code"')
        and "未关联节点实例，不会同步到节点配置" in html
    ),
})

# WebSocket-first control-plane regression guards. These checks make sure live
# node operations and command lifecycle updates cannot silently fall back to polling.
browser_ws_source = Path("source/internal/app/agent_websocket.go").read_text(encoding="utf-8")
browser_ws_tests = Path("source/internal/app/agent_websocket_test.go").read_text(encoding="utf-8")
checks.update({
    "Agent Mihomo update UI uses browser WebSocket control instead of the legacy HTTP command endpoint": "sendBrowserWSControl({" in app_js and "type: 'agent.mihomo.update'" in app_js and "/api/v1/agents/kernel-update'" not in app_js and "/api/v1/agents/kernel-update\"" not in app_js,
    "browser WebSocket correlates request results and enforces a bounded request timeout": "browserWSRequests.set(requestId" in app_js and "request.result" in app_js and "15000" in app_js and "clearTimeout" in app_js,
    "Agent status and command lifecycle are delivered as browser WebSocket events": '"type": "agent.status.updated"' in browser_ws_source and '"type": "agent.command.queued"' in browser_ws_source and '"type": "agent.command.updated"' in browser_ws_source and "publishBrowserEvent" in browser_ws_source,
    "dashboard overview and traffic are not driven by a periodic HTTP polling timer": "setInterval(() => loadOverview" not in app_js and "setInterval(loadOverview" not in app_js and "setInterval(() => loadTraffic" not in app_js and "setInterval(loadTraffic" not in app_js,
    "dashboard overview and traffic snapshots use authenticated WebSocket RPC with no HTTP fallback": "type: 'monitor.overview.get'" in app_js and "type: 'monitor.traffic.get'" in app_js and "api('/api/v1/monitor/overview" not in app_js and "api('/api/v1/monitor/traffic" not in app_js and 'case "monitor.overview.get":' in browser_ws_source and 'case "monitor.traffic.get":' in browser_ws_source and "Revalidate the administrator session for every browser RPC" in browser_ws_source,
    "Proxy deletion preserves committed-delete sync failure recovery": (
        "message.includes('代理已删除')" in app_js
        and "立即重试同步所有节点" in app_js
        and "type: 'proxy.delete'" in app_js
    ),
    "Proxy deletion uses authenticated WebSocket RPC with validated numeric ID": (
        "type: 'proxy.delete'" in app_js
        and "api('/api/v1/proxies/' + encodeURIComponent(row.id)" not in app_js
        and 'case "proxy.delete":' in browser_ws_source
        and 'ProxyID         string `json:"proxy_id"`' in browser_ws_source
        and 'req.SetPathValue("id", strconv.FormatInt(id, 10))' in browser_ws_source
        and "a.handleDeleteProxy" in browser_ws_source
        and "Revalidate the administrator session for every browser RPC" in browser_ws_source
    ),
    "Agent and proxy list snapshots use WebSocket RPC and preserve nested response data": "type: 'agents.list.get'" in app_js and "type: 'proxies.list.get'" in app_js and "api('/api/v1/agents?t=" not in app_js and "api('/api/v1/proxies?t=" not in app_js and 'case "agents.list.get":' in browser_ws_source and 'case "proxies.list.get":' in browser_ws_source and 'reply["data"] = payload' in browser_ws_source,
    "live traffic values update directly from Agent WebSocket telemetry without an HTTP polling fallback": "Live telemetry is authoritative while WebSocket is connected." in app_js and "Number(status.upload_speed)" in app_js and "Number(status.download_speed)" in app_js and "Number(status.connections)" in app_js,
    "Agent WebSocket control keeps auth-revocation, session ACK, and long-command TTL regressions covered": "TestAgentWebSocketCannotPersistHeartbeatAfterAuthorizationRevocation" in browser_ws_tests and "TestAgentWebSocketDeliversAndAcknowledgesPendingCommand" in browser_ws_tests and "TestAgentWebSocketHeartbeatTTLAllowsLongKernelUpdate" in browser_ws_tests,
})


# Agent enrollment and authorization state must not depend on a forced browser reload.
agent_registration_html = Path("s5m-agent/index.html").read_text(encoding="utf-8")
agent_registration_main = Path("s5m-agent/main.go").read_text(encoding="utf-8")
checks.update({
    "Agent authorization changes are broadcast and handled by the primary management UI": (
        '"type": "agent.binding.revoked"' in handlers
        and '"type": "agent.binding.updated"' in handlers
        and "agent.binding.revoked" in app_js
        and "agent.binding.updated" in app_js
    ),
    "primary console WebSocket RPC covers agent list and node config read/save": (
        "type: 'agents.list.get'" in app_js and "type: 'node.config.get'" in app_js
        and "type: 'node.config.save'" in app_js
        and 'case "agents.list.get":' in browser_ws_source
        and 'case "node.config.get":' in browser_ws_source
        and 'case "node.config.save":' in browser_ws_source
    ),
    "primary instance cards show authorization, copy and per-node telemetry": (
        "item.authorized" in html and "safeCopy(item.code)" in html
        and "item.connections" in html and "item.uploadSpeed" in html
        and "item.downloadSpeed" in html and "item.updated_at" in html
        and "Number(status.upload_speed)" in app_js
        and "Number(status.download_speed)" in app_js
        and "Number(status.connections)" in app_js
    ),
    "existing YAML editor provides TUN/DNS shortcuts on the same YAML model": (
        "configTunEnabled" in html and "configDnsEnabled" in html
        and 'v-model="configTunEnabled" @change="applyConfigQuickSettings"' in html
        and 'v-model="configDnsEnabled" @change="applyConfigQuickSettings"' in html
        and "configDnsNameservers" in html and "applyConfigQuickSettings" in html
        and "setYamlScalar" in app_js
        and "yamlChildIndent" in app_js and "findYamlChild" in app_js
        and "yamlIndent(line)" in app_js
    ),
    "node config save and read-back verification use WebSocket only": (
        "type: 'node.config.save'" in app_js and "type: 'node.config.get'" in app_js
        and "/api/v1/nodes/" not in app_js[app_js.index("const saveNodeConfig = async () => {"):app_js.index("const safeCopy = async")]
    ),
    "retired standalone agent management page is removed": not Path("source/web/agents.html").exists(),
})

# Read-only control-plane snapshots continue migrating to the authenticated
# WebSocket RPC channel; writes remain on their existing validated endpoints.
checks.update({
    "main Mihomo status snapshot uses WebSocket RPC without HTTP polling fallback": (
        "type: 'mihomo.status.get'" in app_js
        and "api('/api/v1/mihomo/status?t=" not in app_js
        and 'case "mihomo.status.get":' in browser_ws_source
        and "a.handleMihomoStatus" in browser_ws_source
    ),
    "Mihomo template and per-node template status snapshots use WebSocket RPC": (
        "type: 'mihomo.template.get'" in app_js
        and "type: 'mihomo.template.nodes.get'" in app_js
        and "api('/api/v1/mihomo/template?t=" not in app_js
        and "api('/api/v1/mihomo/template/nodes?t=" not in app_js
        and 'case "mihomo.template.get":' in browser_ws_source
        and 'case "mihomo.template.nodes.get":' in browser_ws_source
    ),
    "settings read uses WebSocket RPC while existing settings update endpoint stays available": (
        "type: 'settings.get'" in app_js
        and "api('/api/v1/settings?t=" not in app_js
        and 'case "settings.get":' in browser_ws_source
        and "a.handleGetSettings" in browser_ws_source
        and '"PUT /api/v1/settings"' in router_source
    ),
    "read-only WebSocket snapshot RPCs remain explicitly allowlisted and admin-session checked": (
        "Revalidate the administrator session for every browser RPC" in browser_ws_source
        and 'case "settings.get":' in browser_ws_source
        and 'case "mihomo.status.get":' in browser_ws_source
        and 'case "mihomo.template.get":' in browser_ws_source
        and 'case "mihomo.template.nodes.get":' in browser_ws_source
        and 'default:' in browser_ws_source
    ),
})

checks["system logs snapshot uses allowlisted admin WebSocket RPC without HTTP fallback"] = (
    "type: 'system.logs.get'" in app_js
    and "api('/api/v1/logs?t=" not in app_js
    and 'case "system.logs.get":' in browser_ws_source
    and "a.handleGetLogs" in browser_ws_source
    and "Revalidate the administrator session for every browser RPC" in browser_ws_source
)


checks["Mihomo template publish/apply/rollback/delete mutations use explicit authenticated WebSocket RPC"] = (
    "type: 'mihomo.template.publish'" in app_js
    and "type: 'mihomo.template.apply'" in app_js
    and 'TemplateVersion int    `json:"template_version"`' in browser_ws_source
    and '"version": message.TemplateVersion' in browser_ws_source
    and "template_version: version" in app_js
    and "type: 'mihomo.template.rollback'" in app_js
    and "type: 'mihomo.template.delete'" in app_js
    and "api('/api/v1/mihomo/template/publish'" not in app_js
    and "api('/api/v1/mihomo/template/apply'" not in app_js
    and "api('/api/v1/mihomo/template/rollback'" not in app_js
    and "api('/api/v1/mihomo/template/' + target" not in app_js
    and 'case "mihomo.template.publish":' in browser_ws_source
    and 'case "mihomo.template.apply":' in browser_ws_source
    and 'case "mihomo.template.rollback":' in browser_ws_source
    and 'case "mihomo.template.delete":' in browser_ws_source
    and "a.handlePublishMihomoTemplate" in browser_ws_source
    and "a.handleApplyMihomoTemplate" in browser_ws_source
    and "a.handleRollbackNodeTemplate" in browser_ws_source
    and "a.handleDeleteMihomoTemplateVersion" in browser_ws_source
    and 'req.SetPathValue("version", strconv.Itoa(version))' in browser_ws_source
    and "Revalidate the administrator session for every browser RPC" in browser_ws_source
)


checks["Agent token generation uses authenticated WebSocket RPC and preserves admin context"] = (
    "type: 'agent.binding.generate'" in app_js
    and "api('/api/v1/agents/generate'" not in app_js
    and 'case "agent.binding.generate":' in browser_ws_source
    and 'context.WithValue(req.Context(), userKey, u)' in browser_ws_source
    and "a.handleGenerateAgentToken" in browser_ws_source
    and "Revalidate the administrator session for every browser RPC" in browser_ws_source
)


checks["Agent kernel release lookup and binding revocation use authenticated WebSocket RPC"] = (
    "type: 'agent.mihomo.update-info'" in app_js
    and "type: 'agent.binding.revoke'" in app_js
    and "api('/api/v1/agents/kernel-update-info?" not in app_js
    and "api('/api/v1/agents?code='" not in app_js
    and 'case "agent.mihomo.update-info":' in browser_ws_source
    and 'case "agent.binding.revoke":' in browser_ws_source
    and "a.handleAgentMihomoUpdateInfo" in browser_ws_source
    and "a.handleDeleteAgent" in browser_ws_source
    and "Revalidate the administrator session for every browser RPC" in browser_ws_source
)

checks["administrator password change uses authenticated WebSocket RPC, not HTTP"] = (
    "type: 'auth.password.change'" in app_js
    and "api('/api/v1/auth/password'" not in app_js
    and 'case "auth.password.change":' in browser_ws_source
    and 'PasswordOld     string `json:"old"`' in browser_ws_source
    and 'PasswordNew     string `json:"new"`' in browser_ws_source
    and 'context.WithValue(req.Context(), userKey, u)' in browser_ws_source
    and "a.handlePassword" in browser_ws_source
    and "Revalidate the administrator session for every browser RPC" in browser_ws_source
)


checks["node config sync retry mutation uses explicit authenticated WebSocket RPC"] = (
    "type: 'nodes.config-sync.retry'" in app_js
    and "api('/api/v1/nodes/config-sync'" not in app_js
    and 'case "nodes.config-sync.retry":' in browser_ws_source
    and "a.handleRetryNodeConfigSync" in browser_ws_source
    and "Revalidate the administrator session for every browser RPC" in browser_ws_source
)

# Pending browser RPC promises must settle immediately when their socket closes.
# Do not wait for the generic 15-second timeout; the remote write may already have run.
checks["browser WebSocket close rejects pending RPCs immediately and marks write outcomes as unknown"] = (
    "const rejectPendingBrowserWSRequests = (message) => {" in app_js
    and "rejectPendingBrowserWSRequests('实时通道已断开，请重新连接后重试')" in app_js
    and "rejectPendingBrowserWSRequests('实时通道已断开，操作结果未确认；请刷新状态后再决定是否重试')" in app_js
    and "const wasCurrentSocket = browserEventsSocket === socket;" in app_js
    and "pending.reject(new Error(message))" in app_js
)

checks["main browser WebSocket ignores stale ticket responses and stale socket events across logout/reconnect"] = (
    "let browserEventsConnecting = false;" in app_js
    and "let browserEventsGeneration = 0;" in app_js
    and "browserEventsGeneration++;" in app_js
    and "const generation = ++browserEventsGeneration;" in app_js
    and "if (generation !== browserEventsGeneration || browserEventsStopped || !token.value) return;" in app_js
    and "if (generation !== browserEventsGeneration || browserEventsStopped || !token.value || browserEventsSocket !== socket) return;" in app_js
    and "const wasCurrentSocket = browserEventsSocket === socket;" in app_js
    and "if (!wasCurrentSocket || browserEventsStopped || !token.value) return;" in app_js
)

checks["Primary console rejects pending WebSocket RPCs on disconnect and stops stale socket reconnects"] = (
    "const rejectPendingBrowserWSRequests = (message) => {" in app_js
    and "rejectPendingBrowserWSRequests('实时通道已断开，操作结果未确认；请刷新状态后再决定是否重试')" in app_js
    and "let browserEventsStopped = false;" in app_js
    and "browserEventsStopped = true;" in app_js
    and "if (!wasCurrentSocket || browserEventsStopped || !token.value) return;" in app_js
)
checks["Primary console loads Agent list over authenticated WebSocket RPC"] = (
    "sendBrowserWSControl({ type: 'agents.list.get' })" in app_js
    and "api('/api/v1/agents'" not in app_js
    and "const connectBrowserEvents = async () => {" in app_js
    and "socket.onopen" in app_js
)


checks["Agent binding updates and revocations invalidate in-flight snapshots and force an authoritative list reload"] = (
    "let agentBindingRevision = 0;" in app_js
    and app_js.count("agentBindingRevision++;") >= 2
    and "const revocationRevision = agentBindingRevision;" in app_js
    and "if (revocationRevision !== agentBindingRevision)" in app_js
    and "retryAfterRevocation = true;" in app_js
    and "Promise.resolve().then(() => loadAgentsData());" in app_js
)

failed = [name for name, ok in checks.items() if not ok]
for name, ok in checks.items():
    print(("PASS" if ok else "FAIL") + ": " + name)
if failed:
    raise SystemExit(1)
