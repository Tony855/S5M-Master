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
		"agent_machine_node_123":        "s5m-secret",
		"agent_lastseen_node_123":       "1792750000",
		"agent_status_node_123":         `{"stale":true}`,
		"agent_command_node_123":        `{"id":"pending"}`,
		"agent_command_result_node_123": `{"status":"old"}`,
		"agent_secret_node_123":         "old-secret",
		"agent_mihomo_secret_node_123":  "old-mihomo-secret",
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
	for _, key := range []string{"agent_machine_node_123", "agent_lastseen_node_123", "agent_status_node_123", "agent_command_node_123", "agent_command_result_node_123", "agent_secret_node_123", "agent_mihomo_secret_node_123"} {
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

func TestCancelPendingAgentTaskOnlyCancelsUnclaimedTasks(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "tasks.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()
	pendingID, err := store.CreateAgentTask("node-1", "docker.list", `{}`)
	if err != nil {
		t.Fatalf("CreateAgentTask pending: %v", err)
	}
	changed, err := store.CancelPendingAgentTask(pendingID)
	if err != nil || changed != 1 {
		t.Fatalf("cancel pending: changed=%d err=%v", changed, err)
	}
	var status string
	if err := store.db.QueryRow("SELECT status FROM agent_tasks WHERE id=?", pendingID).Scan(&status); err != nil {
		t.Fatalf("read cancelled status: %v", err)
	}
	if status != "cancelled" {
		t.Fatalf("status = %q, want cancelled", status)
	}
	changed, err = store.CancelPendingAgentTask(pendingID)
	if err != nil || changed != 0 {
		t.Fatalf("cancel already-cancelled task: changed=%d err=%v", changed, err)
	}
	runningID, err := store.CreateAgentTask("node-1", "docker.list", `{}`)
	if err != nil {
		t.Fatalf("CreateAgentTask running: %v", err)
	}
	if _, err := store.db.Exec("UPDATE agent_tasks SET status='running' WHERE id=?", runningID); err != nil {
		t.Fatalf("mark task running: %v", err)
	}
	changed, err = store.CancelPendingAgentTask(runningID)
	if err != nil || changed != 0 {
		t.Fatalf("cancel running task: changed=%d err=%v", changed, err)
	}
}

func TestFailStaleAgentTasksDoesNotRequeueOrTouchOtherTasks(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "stale-tasks.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	staleBefore := "2026-10-24T12:00:00Z"
	staleID, err := store.CreateAgentTask("node-1", "docker.restart", `{"container_id":"proxy-1"}`)
	if err != nil {
		t.Fatalf("Create stale task: %v", err)
	}
	freshID, err := store.CreateAgentTask("node-1", "docker.list", `{}`)
	if err != nil {
		t.Fatalf("Create fresh task: %v", err)
	}
	otherNodeID, err := store.CreateAgentTask("node-2", "docker.stop", `{"container_id":"proxy-2"}`)
	if err != nil {
		t.Fatalf("Create other-node task: %v", err)
	}
	if _, err := store.db.Exec(`UPDATE agent_tasks SET status='running', claimed_at=?, updated_at=? WHERE id=?`, "2026-10-24T11:57:00Z", "2026-10-24T11:57:00Z", staleID); err != nil {
		t.Fatalf("Mark stale task running: %v", err)
	}
	if _, err := store.db.Exec(`UPDATE agent_tasks SET status='running', claimed_at=?, updated_at=? WHERE id=?`, "2026-10-24T12:00:30Z", "2026-10-24T12:00:30Z", freshID); err != nil {
		t.Fatalf("Mark fresh task running: %v", err)
	}
	if _, err := store.db.Exec(`UPDATE agent_tasks SET status='running', claimed_at=?, updated_at=? WHERE id=?`, "2026-10-24T11:57:00Z", "2026-10-24T11:57:00Z", otherNodeID); err != nil {
		t.Fatalf("Mark other-node task running: %v", err)
	}

	changed, err := store.FailStaleAgentTasks("node-1", staleBefore)
	if err != nil || changed != 1 {
		t.Fatalf("FailStaleAgentTasks: changed=%d err=%v, want 1", changed, err)
	}

	var status, errorText, finishedAt string
	if err := store.db.QueryRow(`SELECT status,error_text,finished_at FROM agent_tasks WHERE id=?`, staleID).Scan(&status, &errorText, &finishedAt); err != nil {
		t.Fatalf("Read stale task: %v", err)
	}
	if status != "failed" || errorText == "" || finishedAt == "" {
		t.Fatalf("stale task status=%q error=%q finished_at=%q; expected failed with diagnostic and finish time", status, errorText, finishedAt)
	}
	for _, id := range []int64{freshID, otherNodeID} {
		if err := store.db.QueryRow(`SELECT status FROM agent_tasks WHERE id=?`, id).Scan(&status); err != nil {
			t.Fatalf("Read unaffected task %d: %v", id, err)
		}
		if status != "running" {
			t.Fatalf("unaffected task %d status=%q, want running", id, status)
		}
	}
	changed, err = store.FailStaleAgentTasks("node-1", staleBefore)
	if err != nil || changed != 0 {
		t.Fatalf("repeat stale-task cleanup: changed=%d err=%v, want 0", changed, err)
	}
}

func TestRenewAgentTaskLeaseOnlyTouchesRunningOwnedTask(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "renew-task-lease.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	runningID, err := store.CreateAgentTask("node-1", "docker.logs", `{}`)
	if err != nil {
		t.Fatalf("Create running task: %v", err)
	}
	pendingID, err := store.CreateAgentTask("node-1", "docker.list", `{}`)
	if err != nil {
		t.Fatalf("Create pending task: %v", err)
	}
	if _, err := store.db.Exec(`UPDATE agent_tasks SET status='running', updated_at=? WHERE id=?`, "2020-01-01T00:00:00Z", runningID); err != nil {
		t.Fatalf("Set old lease: %v", err)
	}

	changed, err := store.RenewAgentTaskLease(runningID, "node-1")
	if err != nil || changed != 1 {
		t.Fatalf("RenewAgentTaskLease owned running task: changed=%d err=%v, want 1", changed, err)
	}
	var updated string
	if err := store.db.QueryRow(`SELECT updated_at FROM agent_tasks WHERE id=?`, runningID).Scan(&updated); err != nil {
		t.Fatalf("Read renewed lease: %v", err)
	}
	if updated == "2020-01-01T00:00:00Z" {
		t.Fatal("lease timestamp was not refreshed")
	}

	for _, tc := range []struct {
		name string
		id   int64
		code string
	}{
		{name: "wrong machine", id: runningID, code: "node-2"},
		{name: "pending task", id: pendingID, code: "node-1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed, err := store.RenewAgentTaskLease(tc.id, tc.code)
			if err != nil || changed != 0 {
				t.Fatalf("RenewAgentTaskLease: changed=%d err=%v, want 0", changed, err)
			}
		})
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
