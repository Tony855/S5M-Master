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

func TestSaveNodeConfigsRollsBackWholeBatchOnFailure(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "atomic-node-config-test.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	if err := store.SaveNodeConfigs(map[string]string{
		"node-a": "proxies: [old-a]",
		"node-b": "proxies: [old-b]",
	}); err != nil {
		t.Fatalf("seed node configs: %v", err)
	}
	if _, err := store.db.Exec(`CREATE TRIGGER fail_node_b_update BEFORE UPDATE ON node_configs
		WHEN OLD.machine_code = 'node-b'
		BEGIN SELECT RAISE(ABORT, 'simulated write failure'); END`); err != nil {
		t.Fatalf("create failure trigger: %v", err)
	}

	err = store.SaveNodeConfigs(map[string]string{
		"node-a": "proxies: [new-a]",
		"node-b": "proxies: [new-b]",
	})
	if err == nil {
		t.Fatal("SaveNodeConfigs() expected simulated write failure")
	}

	for machineCode, want := range map[string]string{
		"node-a": "proxies: [old-a]",
		"node-b": "proxies: [old-b]",
	} {
		got, err := store.GetNodeConfig(machineCode)
		if err != nil {
			t.Fatalf("GetNodeConfig(%q): %v", machineCode, err)
		}
		if got == nil || got.YAML != want {
			t.Errorf("node %q YAML = %#v, want %q; batch should roll back completely", machineCode, got, want)
		}
	}
}

func TestSaveNodeConfigsRejectsBlankMachineCode(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "blank-machine-config-test.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	if err := store.SaveNodeConfigs(map[string]string{"  ": "proxies: []"}); err == nil {
		t.Fatal("SaveNodeConfigs() should reject a blank machine code")
	}
}

func TestCreateSettingIfAbsentDoesNotOverwritePendingCommand(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "atomic-setting-test.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	created, err := store.CreateSettingIfAbsent("agent_command_node-a", `{"id":"first","type":"update_mihomo"}`)
	if err != nil || !created {
		t.Fatalf("first CreateSettingIfAbsent() = %v, %v; want true, nil", created, err)
	}
	created, err = store.CreateSettingIfAbsent("agent_command_node-a", `{"id":"second","type":"update_mihomo"}`)
	if err != nil {
		t.Fatalf("second CreateSettingIfAbsent() error = %v", err)
	}
	if created {
		t.Fatal("second CreateSettingIfAbsent() overwrote an existing pending command")
	}
	value, err := store.GetSetting("agent_command_node-a")
	if err != nil {
		t.Fatalf("GetSetting(): %v", err)
	}
	if value != `{"id":"first","type":"update_mihomo"}` {
		t.Fatalf("pending command = %q, want the original command", value)
	}
}

func TestGetSettingsReturnsAllStoredValues(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "get-settings-test.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	want := map[string]string{
		"agent_token": "token-value",
		"mihomo_api":  "http://127.0.0.1:9090",
	}
	if err := store.UpdateSettings(want); err != nil {
		t.Fatalf("UpdateSettings: %v", err)
	}
	got, err := store.GetSettings()
	if err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	for key, value := range want {
		if got[key] != value {
			t.Errorf("GetSettings()[%q] = %q, want %q", key, got[key], value)
		}
	}
}


func TestFreshStoreDoesNotCreateLegacyAgentTasksTable(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "fresh-store.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	var count int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'agent_tasks'`).Scan(&count); err != nil {
		t.Fatalf("check legacy table: %v", err)
	}
	if count != 0 {
		t.Fatal("fresh database unexpectedly created retired agent_tasks table")
	}
}

func TestStoreMigrationPreservesExistingLegacyAgentTasksTable(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "legacy-store.db")
	store, err := OpenStore(dbPath)
	if err != nil {
		t.Fatalf("initial OpenStore: %v", err)
	}
	if _, err := store.db.Exec(`CREATE TABLE agent_tasks (id TEXT PRIMARY KEY, status TEXT NOT NULL DEFAULT 'pending')`); err != nil {
		store.db.Close()
		t.Fatalf("create legacy table fixture: %v", err)
	}
	if err := store.db.Close(); err != nil {
		t.Fatalf("close initial store: %v", err)
	}

	reopened, err := OpenStore(dbPath)
	if err != nil {
		t.Fatalf("reopen legacy database: %v", err)
	}
	defer reopened.db.Close()

	var count int
	if err := reopened.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'agent_tasks'`).Scan(&count); err != nil {
		t.Fatalf("check legacy table after migration: %v", err)
	}
	if count != 1 {
		t.Fatal("migration removed the existing legacy agent_tasks table")
	}
}
