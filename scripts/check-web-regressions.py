#!/usr/bin/env python3
"""Guard against regressions in the embedded S5M control-center UI."""
from pathlib import Path

html = Path("source/web/index.html").read_text(encoding="utf-8")

checks = {
    "proxy form retains mode and complete extra JSON": "extra_json: '{}'" in html and "mode: row.mode || 'proxy'" in html and "extra_json: JSON.stringify(extra, null, 2)" in html,
    "proxy save sends mode and parsed extra": "name: proxyForm.name, mode: proxyForm.mode || 'proxy'" in html and "extra: extra" in html and "extra = JSON.parse(proxyForm.extra_json || '{}')" in html,
    "proxy editor rejects invalid/non-object JSON": "高级参数 JSON 格式无效" in html and "高级参数必须是 JSON 对象" in html,
    "proxy sync failure is reported as partial success": "代理数据已保存，但节点配置同步失败" in html and "同步失败" in html,
    "Docker selector and task execution reject RouterOS agents": "v-for=\"item in dockerAgentEntries\"" in html and "所选机器码不是可用的 Docker Agent" in html,
    "RouterOS list/action reject non-RouterOS agents": "所选机器码不是 RouterOS Agent" in html and "当前选择不是 RouterOS Agent" in html,
    "system operations page exposes protected logs and Mihomo update": 'index="system">系统运维</el-menu-item>' in html and "loadSystemLogs" in html and "/api/v1/logs" in html and "/api/v1/mihomo/update" in html,
    "backup restore has size checks and explicit destructive confirmation": "/api/v1/backup?token=" in html and "/api/v1/restore" in html and "128 MiB" in html and "确认恢复数据库" in html,
    "global config draft save and publish are separate from node YAML": "globalConfigYaml" in html and "/api/v1/config/save" in html and "/api/v1/config/publish" in html and "selectedConfigNode" in html,
    "configuration history supports version listing and guarded rollback": "/api/v1/config/versions" in html and "/api/v1/config/rollback" in html and "确认回滚配置" in html,
    "primary UI does not load the legacy standalone app.js": 'src="/app.js"' not in html and 'src="./app.js"' not in html,
}
failed = [name for name, ok in checks.items() if not ok]
for name, ok in checks.items():
    print(("PASS" if ok else "FAIL") + ": " + name)
if failed:
    raise SystemExit(1)
