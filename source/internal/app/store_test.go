package app

import (
	"path/filepath"
	"testing"
)

func TestSaveNodeConfigIfEmptyPreservesExistingYAML(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "node-config-test.db")
	store, err := OpenStore(dbPath)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	_, err = store.db.Exec(`CREATE TABLE IF NOT EXISTS node_configs(
                machine_code TEXT PRIMARY KEY,
                yaml_text TEXT NOT NULL DEFAULT '',
                updated_at TEXT NOT NULL
        )`)
	if err != nil {
		t.Fatalf("创建测试表: %v", err)
	}

	original := "proxies:\n  - name: custom-node\n    type: socks5\n"
	generated := "proxies:\n  - name: generated-node\n    type: socks5\n"

	if err := store.SaveNodeConfigIfEmpty("machine-test", original); err != nil {
		t.Fatalf("首次初始化: %v", err)
	}

	if err := store.SaveNodeConfigIfEmpty("machine-test", generated); err != nil {
		t.Fatalf("重复初始化: %v", err)
	}

	got, err := store.GetNodeConfig("machine-test")
	if err != nil {
		t.Fatalf("读取配置: %v", err)
	}
	if got == nil || got.YAML != original {
		t.Fatalf("已有配置被覆盖：期望原始 YAML，实际 %#v", got)
	}

	if err := store.SaveNodeConfig("machine-empty", ""); err != nil {
		t.Fatalf("建立空配置: %v", err)
	}
	if err := store.SaveNodeConfigIfEmpty("machine-empty", generated); err != nil {
		t.Fatalf("初始化空配置: %v", err)
	}

	got, err = store.GetNodeConfig("machine-empty")
	if err != nil {
		t.Fatalf("读取初始化配置: %v", err)
	}
	if got == nil || got.YAML != generated {
		t.Fatalf("空配置未被初始化：实际 %#v", got)
	}
}

func TestDeleteAgentBindingRevokesAndFailsOutstandingTasks(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "agent-delete-test.db")
	store, err := OpenStore(dbPath)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	if err := store.UpdateSettings(map[string]string{
		"agent_machine_node_123":  "s5m-secret",
		"agent_lastseen_node_123": "1792750000",
	}); err != nil {
		t.Fatalf("设置测试授权: %v", err)
	}
	_, err = store.db.Exec(`INSERT INTO agent_status(machine_code,updated_at) VALUES(?,?)`, "node_123", "2026-10-23T00:00:00Z")
	if err != nil {
		t.Fatalf("插入状态: %v", err)
	}
	for _, status := range []string{"pending", "running", "succeeded"} {
		_, err = store.db.Exec(`INSERT INTO agent_tasks(machine_code,action,status,created_at,updated_at,claimed_at) VALUES(?,?,?,?,?,?)`, "node_123", "docker.list", status, "2026-10-23T00:00:00Z", "2026-10-23T00:00:00Z", "2026-10-23T00:00:00Z")
		if err != nil {
			t.Fatalf("插入任务 %s: %v", status, err)
		}
	}
	if err := store.DeleteAgentBinding("node_123"); err != nil {
		t.Fatalf("DeleteAgentBinding: %v", err)
	}
	for _, key := range []string{"agent_machine_node_123", "agent_lastseen_node_123"} {
		if _, err := store.GetSetting(key); err == nil {
			t.Fatalf("授权设置 %s 未删除", key)
		}
	}
	var n int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM agent_status WHERE machine_code=?`, "node_123").Scan(&n); err != nil || n != 0 {
		t.Fatalf("节点状态仍存在: n=%d err=%v", n, err)
	}
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM agent_tasks WHERE machine_code=? AND status IN ('pending','running')`, "node_123").Scan(&n); err != nil || n != 0 {
		t.Fatalf("仍有未完成任务: n=%d err=%v", n, err)
	}
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM agent_tasks WHERE machine_code=? AND status='succeeded'`, "node_123").Scan(&n); err != nil || n != 1 {
		t.Fatalf("已完成任务历史未保留: n=%d err=%v", n, err)
	}
}
