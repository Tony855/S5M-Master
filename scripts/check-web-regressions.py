#!/usr/bin/env python3
"""Guard against regressions in the embedded S5M control-center UI."""
from pathlib import Path

html = Path("source/web/index.html").read_text(encoding="utf-8")
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
    "Mihomo template version deletion has a protected current-version and node-binding guard": "handleDeleteMihomoTemplateVersion" in template_source and "不能删除当前发布版本" in template_source and "FROM node_template_bindings WHERE source='template' AND template_version=?" in template_source and '"DELETE /api/v1/mihomo/template/{version}"' in router,
    "Mihomo template history UI exposes guarded deletion with confirmation": "deleteMihomoTemplateVersion" in app_js and "ElMessageBox.confirm" in app_js and "scope.row.version === templateCurrentVersion" in html,

    "Agent runtime status explains missing telemetry and reports last_error": "let runtimeMessage" in app_js and "runtimeMessage = last > 0" in app_js and "item.runtimeMessage" in html and "Agent 状态/错误信息：" in html and "有认证通信记录，但没有有效运行状态" in app_js,
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
    "proxy validation rejects unknown modes and out-of-range ports": '"运行模式无效' in handlers and '"代理端口必须在 1-65535 之间"' in handlers and 'case "proxy", "china", "game":' in handlers,
    "proxy form retains mode and complete extra JSON": "extra_json: '{}'" in ui and "mode: row.mode || 'proxy'" in ui and "extra_json: JSON.stringify(extra, null, 2)" in ui,
    "proxy save sends mode and parsed extra": "name: proxyForm.name, mode: proxyForm.mode || 'proxy'" in ui and "extra: extra" in ui and "extra = JSON.parse(proxyForm.extra_json || '{}')" in ui,
    "proxy editor rejects invalid/non-object JSON": "高级参数 JSON 格式无效" in ui and "高级参数必须是 JSON 对象" in ui,
    "proxy sync failure is reported as partial success": "代理数据已保存，但节点配置同步失败" in ui and "同步失败" in ui,
    "proxy deletion sync failure refreshes list and offers retry": "if (message.includes('代理已删除'))" in app_js and "await loadProxies();" in app_js and "立即重试同步所有节点" in app_js,
    "bulk proxy import synchronizes authorized node configs and exposes partial failure": "if successCount > 0" in import_handler and "syncAuthorizedNodeConfigs()" in import_handler and '"sync_failed": syncFailed' in import_handler and "data.sync_failed" in app_js and "代理导入已完成" in app_js,
    "system operations page exposes protected logs and Mihomo update": 'index="system">系统运维</el-menu-item>' in ui and "loadSystemLogs" in ui and "/api/v1/logs" in ui and "/api/v1/mihomo/update" in ui and "/api/v1/mihomo/status" in ui,
    "master Mihomo update is distinguished from Agent updates and requires confirmation": "主控服务器 Mihomo 内核" in html and "当前 Mihomo 版本" in html and "systemd 服务状态" in html and "不会更新各个 Agent 节点" in html and "确认更新主控 Mihomo" in app_js and "ElementPlus.ElMessageBox.confirm" in app_js[app_js.index("const updateKernel ="):app_js.index("const loadSystemLogs")],
    "master Mihomo status distinguishes disk binary, systemd service, and live API version": '"api_version"' in handlers and '"api_online"' in handlers and '"version_mismatch"' in handlers and "runningMihomoAPIVersion" in handlers and "运行中 API 版本" in html and "mainMihomoStatus.api_error" in html,
    "system operations page is reachable through page navigation allowlist": "const PAGES = ['dashboard','proxies','instances','config','system']" in app_js and "if (v === 'system') { loadSystemLogs(); loadMainMihomoStatus(); }" in app_js,
    "backup download uses Authorization header and restore has destructive confirmation": "fetch('/api/v1/backup', { headers: authHeaders() })" in ui and "/api/v1/backup?token=" not in ui and "/api/v1/restore" in ui and "128 MiB" in ui and "确认恢复数据库" in ui,
    "client subscription link is displayed after the per-node YAML editor at the bottom of the config page": html.index("客户端订阅链接") > html.index("保存当前节点配置") and html.index("客户端订阅链接") > html.index("节点独立配置 (YAML)"),
    "administrator account control is compact and hides role label from the main status bar": 'class="admin-menu-trigger"' in html and 'class="admin-user-text"' not in html and 'class="admin-avatar"' in html and 'class="admin-chevron"' in html and '管理员菜单' in html,
    "subscription URL trims blank settings and always initializes a usable absolute fallback": "const fallback = new URL('/api/v1/subscribe', window.location.href).toString();" in app_js and "String(s.subscribe_url || s.sub_url || '').trim()" in app_js and "subUrl.value = configured || fallback;" in app_js,
    "Mihomo template page provides a safe starter without fake proxy/rule sections": "defaultMihomoTemplate" in Path("source/internal/app/template.go").read_text(encoding="utf-8") and "draft = defaultMihomoTemplate" in Path("source/internal/app/template.go").read_text(encoding="utf-8") and "REPLACE_WITH_A_UNIQUE_RANDOM_SECRET" in Path("source/internal/app/template.go").read_text(encoding="utf-8") and "YOUR_PROXY_SERVER" not in Path("source/internal/app/template.go").read_text(encoding="utf-8") and "221111cdn" not in Path("source/internal/app/template.go").read_text(encoding="utf-8"),
    "generated Mihomo DNS follows routing rules and uses a bootstrap resolver to avoid DNS/proxy loops": "respect-rules: true" in configgen and "proxy-server-nameserver:" in configgen and "DOMAIN-SUFFIX,%s,%s" in configgen and "dns.alidns.com" in configgen and "doh.pub" in configgen,
    "configuration UI focuses on per-node YAML and removes unused global draft panel": "selectedConfigNode" in ui and "节点独立配置 (YAML)" in html and "全局配置与版本发布" not in html and "globalConfigYaml" not in app_js,
    "global config draft endpoint bounds request size and validates YAML before persistence": "decodeLimited(r, 2<<20, \"2 MiB\", &in)" in handlers and "全局 YAML 语法错误" in handlers and "全局 YAML 必须是非空对象" in handlers,
    "global config save response does not falsely claim Agent rollout": "尚未发布" in handlers and "不会自动更新节点独立 YAML" in handlers and "Agent 将在 30 秒内拉取更新" not in handlers,
    "global config version APIs remain backend-only for compatibility": "/api/v1/config/versions" in Path("source/internal/app/router.go").read_text(encoding="utf-8") and "/api/v1/config/rollback" in Path("source/internal/app/router.go").read_text(encoding="utf-8") and "确认回滚配置" not in ui,
    "backend rollback still syncs the saved global draft": 'UpdateSettings(map[string]string{"config_yaml": yml})' in configgen and "回滚已完成，但全局配置草稿同步失败" in configgen,
    "backend rollback keeps current database-managed proxy/rule sections": "BuildConfigForMachine(\"\")" in rollback_impl and "mergeManagedProxySections(yml, managedYAML)" in rollback_impl,
    "node config sync has an authenticated retry action": "/api/v1/nodes/config-sync" in ui and "retryNodeConfigSync" in ui and "立即重试同步所有节点" in ui,
    "primary UI loads the extracted application bundle": 'src="/app.js"' in html and Path("source/web/app.js").is_file() and Path("source/web/app.js").stat().st_size > 10000,
    "main UI stylesheet is external and present": '<link rel="stylesheet" href="/app.css">' in html and "<style>" not in html and Path("source/web/app.css").is_file() and Path("source/web/app.css").stat().st_size > 1000,
    "per-agent Mihomo update automatically fetches official stable release metadata and queues verified checksum": "openAgentKernelUpdate(item.code)" in ui and "/api/v1/agents/kernel-update-info?machine_code=" in ui and "latest_version" in ui and "kernelUpdateInfo.arch" in ui and "handleAgentMihomoUpdateInfo" in handlers and "一键更新" in ui,
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
    "instance details are collapsed by default and support expanded content": '<details class="instance-details">' in html and "<summary>展开详细状态</summary>" in html and ".instance-details[open] > summary" in css,
    "instance cards show the status timestamp only in expanded details, not twice in the summary": "instance-detail-label\">状态更新时间" in html and "instance-summary-updated" not in html,
    "instance list refresh is manual and silent, with no 10-second polling timer": "const agentRefreshing = ref(false);" in app_js and "if (agentLoading.value || agentRefreshing.value) return;" in app_js and "静默刷新实例失败，保留现有列表" in app_js and "instanceRefreshTimer" not in app_js and ' :loading="agentLoading || agentRefreshing"' in html,
    "silent instance refresh keeps stable card identity and does not reset search/filter state": 'v-for="item in filteredAgentEntries" :key="item.code"' in html and "const agentSearch = ref('');" in app_js and "const agentStatusFilter = ref('all');" in app_js and "const loadAgentsData = async () => {" in app_js and "agentSearch.value =" not in app_js[app_js.index("const loadAgentsData = async () => {"):app_js.index("const loadAgentsData = async () => {") + 9000] and "agentStatusFilter.value =" not in app_js[app_js.index("const loadAgentsData = async () => {"):app_js.index("const loadAgentsData = async () => {") + 9000],
    "instance cards use tighter padding and restrained action-button colors": ".instance-row { padding: 13px; border-radius: 12px;" in css and "--el-button-bg-color: #f0f6ff" in css and "--el-button-bg-color: #fff8ed" in css,
    "runtime status palette includes online, offline, warning, and unknown states": all(token in css for token in (".status-badge.status-online", ".status-badge.status-offline", ".status-badge.status-warning", ".status-badge.status-unknown")),
    "instance list does not expose token plaintext and keeps all four management actions": "列表不显示明文" in html and "{{ item.token }}" not in html and all(handler in html for handler in ("openProxiesForMachine(item.code)", "openNodeConfigForMachine(item.code)", "openAgentKernelUpdate(item.code)", "deleteAgent(item.code)")),
    "instance card layout prevents long machine identifiers from forcing overflow": ".instance-row {\n  min-width: 0;" in css and ".instance-row .agent-code {\n  min-width: 0;" in css and "overflow-wrap: anywhere;" in css,
}
checks.update(instance_card_checks)

failed = [name for name, ok in checks.items() if not ok]
for name, ok in checks.items():
    print(("PASS" if ok else "FAIL") + ": " + name)
if failed:
    raise SystemExit(1)
