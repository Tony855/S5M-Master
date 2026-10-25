#!/usr/bin/env python3
"""Guard against regressions in the embedded S5M control-center UI."""
from pathlib import Path

html = Path("source/web/index.html").read_text(encoding="utf-8")
app_js = Path("source/web/app.js").read_text(encoding="utf-8")
configgen = Path("source/internal/app/configgen.go").read_text(encoding="utf-8")
handlers = Path("source/internal/app/handlers.go").read_text(encoding="utf-8")
import_handler = handlers[handlers.index("func (a *App) handleImportProxies"):handlers.index("func (a *App) handleAgentRegister")]
rollback_impl = configgen[configgen.index("func (a *App) Rollback"):configgen.index("func (a *App) Rollback")+5000]
ui = html + "\n" + app_js

checks = {
    "proxy form retains mode and complete extra JSON": "extra_json: '{}'" in ui and "mode: row.mode || 'proxy'" in ui and "extra_json: JSON.stringify(extra, null, 2)" in ui,
    "proxy save sends mode and parsed extra": "name: proxyForm.name, mode: proxyForm.mode || 'proxy'" in ui and "extra: extra" in ui and "extra = JSON.parse(proxyForm.extra_json || '{}')" in ui,
    "proxy editor rejects invalid/non-object JSON": "高级参数 JSON 格式无效" in ui and "高级参数必须是 JSON 对象" in ui,
    "proxy sync failure is reported as partial success": "代理数据已保存，但节点配置同步失败" in ui and "同步失败" in ui,
    "proxy deletion sync failure refreshes list and offers retry": "if (message.includes('代理已删除'))" in app_js and "await loadProxies();" in app_js and "立即重试同步所有节点" in app_js,
    "bulk proxy import synchronizes authorized node configs and exposes partial failure": "if successCount > 0" in import_handler and "syncAuthorizedNodeConfigs()" in import_handler and '"sync_failed": syncFailed' in import_handler and "data.sync_failed" in app_js and "代理导入已完成" in app_js,
    "Docker selector and task execution reject RouterOS agents": "v-for=\"item in dockerAgentEntries\"" in ui and "所选机器码不是可用的 Docker Agent" in ui,
    "RouterOS list/action reject non-RouterOS agents": "所选机器码不是 RouterOS Agent" in ui and "当前选择不是 RouterOS Agent" in ui,
    "system operations page exposes protected logs and Mihomo update": 'index="system">系统运维</el-menu-item>' in ui and "loadSystemLogs" in ui and "/api/v1/logs" in ui and "/api/v1/mihomo/update" in ui,
    "master Mihomo update is distinguished from Agent updates and requires confirmation": "主控服务器 Mihomo 内核" in html and "不会更新各个 Agent 节点" in html and "确认更新主控 Mihomo" in app_js and "ElementPlus.ElMessageBox.confirm" in app_js[app_js.index("const updateKernel ="):app_js.index("const loadSystemLogs")],
    "system operations page is reachable through page navigation allowlist": "const PAGES = ['dashboard','proxies','instances','docker','routeros-containers','config','system']" in app_js and "if (v === 'system') loadSystemLogs();" in app_js,
    "backup download uses Authorization header and restore has destructive confirmation": "fetch('/api/v1/backup', { headers: authHeaders() })" in ui and "/api/v1/backup?token=" not in ui and "/api/v1/restore" in ui and "128 MiB" in ui and "确认恢复数据库" in ui,
    "global config draft save and publish are separate from node YAML": "globalConfigYaml" in ui and "/api/v1/config/save" in ui and "/api/v1/config/publish" in ui and "selectedConfigNode" in ui,
    "global config draft endpoint bounds request size and validates YAML before persistence": "maxConfigBody = int64(2 << 20)" in handlers and "全局 YAML 语法错误" in handlers and "全局 YAML 必须是非空对象" in handlers,
    "global config save response does not falsely claim Agent rollout": "尚未发布" in handlers and "不会自动更新节点独立 YAML" in handlers and "Agent 将在 30 秒内拉取更新" not in handlers,
    "configuration history supports version listing and guarded rollback": "/api/v1/config/versions" in ui and "/api/v1/config/rollback" in ui and "确认回滚配置" in ui,
    "successful rollback syncs the editable global config draft": 'UpdateSettings(map[string]string{"config_yaml": yml})' in configgen and "回滚已完成，但全局配置草稿同步失败" in configgen and "回滚已完成，但全局配置草稿同步失败" in app_js,
    "rollback keeps current database-managed proxy/rule sections": "BuildConfigForMachine(\"\")" in rollback_impl and "mergeManagedProxySections(yml, managedYAML)" in rollback_impl and "代理列表和路由规则始终以当前代理数据库为准" in html,
    "node config sync has an authenticated retry action": "/api/v1/nodes/config-sync" in ui and "retryNodeConfigSync" in ui and "立即重试同步所有节点" in ui,
    "primary UI loads the extracted application bundle": 'src="/app.js"' in html and Path("source/web/app.js").is_file() and Path("source/web/app.js").stat().st_size > 10000,
    "main UI stylesheet is external and present": '<link rel="stylesheet" href="/app.css">' in html and "<style>" not in html and Path("source/web/app.css").is_file() and Path("source/web/app.css").stat().st_size > 1000,
    "Docker and RouterOS pages are grouped under container management": '<el-sub-menu index="containers">' in ui and "default-openeds=\"['containers']\"" in ui and 'index="docker">Docker 容器' in ui and 'index="routeros-containers">RouterOS 容器' in ui,
    "per-agent Mihomo update validates version and SHA-256 before queueing": "openAgentKernelUpdate(item.code)" in ui and "/api/v1/agents/kernel-update" in ui and r"/^v\d+\.\d+\.\d+$/" in ui and r"/^[a-f0-9]{64}$/" in ui,
    "global Mihomo update validates candidate binary before replacing live binary": "candidateVersion != release.TagName" in handlers and "copyFileAtomic(binaryPath, backupPath)" in handlers and "已成功更新至 " in handlers,
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


failed = [name for name, ok in checks.items() if not ok]
for name, ok in checks.items():
    print(("PASS" if ok else "FAIL") + ": " + name)
if failed:
    raise SystemExit(1)
