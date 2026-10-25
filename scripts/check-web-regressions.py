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
}
failed = [name for name, ok in checks.items() if not ok]
for name, ok in checks.items():
    print(("PASS" if ok else "FAIL") + ": " + name)
if failed:
    raise SystemExit(1)
