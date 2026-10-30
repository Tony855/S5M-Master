package app

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestAckAgentCommandRejectsOldIDWhenReplacementIsPending(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "ack-replacement.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	const machineCode = "ack_node"
	const oldResult = `{"id":"cmd-old","type":"update_mihomo","status":"success"}`
	const replacement = `{"id":"cmd-new","type":"update_mihomo","version":"v1.2.3"}`
	if err := store.UpdateSettings(map[string]string{
		"agent_command_result_" + machineCode: oldResult,
		"agent_command_" + machineCode:        replacement,
	}); err != nil {
		t.Fatalf("seed command state: %v", err)
	}

	duplicate, matched, err := store.AckAgentCommand(machineCode, "cmd-old", "success", "stale retry", 100)
	if err != nil {
		t.Fatalf("AckAgentCommand: %v", err)
	}
	if duplicate || matched {
		t.Fatalf("stale ACK = duplicate %v, matched %v; want both false while replacement is pending", duplicate, matched)
	}

	settings, err := store.GetSettings()
	if err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	if settings["agent_command_"+machineCode] != replacement {
		t.Fatalf("replacement command changed: %q", settings["agent_command_"+machineCode])
	}
	if settings["agent_command_result_"+machineCode] != oldResult {
		t.Fatalf("previous result changed: %q", settings["agent_command_result_"+machineCode])
	}
}

func TestAckAgentCommandTreatsSameCompletedIDAsDuplicateOnlyWithoutPendingCommand(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "ack-duplicate.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	const machineCode = "ack_node"
	const result = `{"id":"cmd-done","type":"update_mihomo","status":"success"}`
	if err := store.UpdateSettings(map[string]string{
		"agent_command_result_" + machineCode: result,
	}); err != nil {
		t.Fatalf("seed command result: %v", err)
	}

	duplicate, matched, err := store.AckAgentCommand(machineCode, "cmd-done", "success", "retry", 200)
	if err != nil {
		t.Fatalf("AckAgentCommand duplicate retry: %v", err)
	}
	if !duplicate || !matched {
		t.Fatalf("duplicate retry = duplicate %v, matched %v; want both true", duplicate, matched)
	}

	settings, err := store.GetSettings()
	if err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	if settings["agent_command_result_"+machineCode] != result {
		t.Fatalf("duplicate retry should not rewrite original result: %q", settings["agent_command_result_"+machineCode])
	}
}

func TestAckAgentCommandDoesNotAcceptDuplicateWhenPendingRecordIsMalformed(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "ack-malformed-pending.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	const machineCode = "ack_node"
	const malformed = `{"id":`
	const oldResult = `{"id":"cmd-done","status":"success"}`
	if err := store.UpdateSettings(map[string]string{
		"agent_command_" + machineCode:        malformed,
		"agent_command_result_" + machineCode: oldResult,
	}); err != nil {
		t.Fatalf("seed command state: %v", err)
	}

	duplicate, matched, err := store.AckAgentCommand(machineCode, "cmd-done", "success", "retry", 300)
	if err != nil {
		t.Fatalf("AckAgentCommand: %v", err)
	}
	if duplicate || matched {
		t.Fatalf("ACK with malformed pending record = duplicate %v, matched %v; want both false", duplicate, matched)
	}
}
func TestAckAgentCommandPreservesOpenWrtServiceActionMetadata(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "ack-openwrt-action.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	const machineCode = "ack_openwrt"
	const pending = `{"id":"cmd-agent-restart","type":"openwrt_service_action","service":"agent","action":"restart"}`
	if err := store.UpdateSettings(map[string]string{
		"agent_command_" + machineCode: pending,
	}); err != nil {
		t.Fatalf("seed pending command: %v", err)
	}

	duplicate, matched, err := store.AckAgentCommand(machineCode, "cmd-agent-restart", "success", "restart scheduled", 400)
	if err != nil || duplicate || !matched {
		t.Fatalf("AckAgentCommand = duplicate %v matched %v err %v; want false, true, nil", duplicate, matched, err)
	}

	settings, err := store.GetSettings()
	if err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	var result map[string]any
	if err := json.Unmarshal([]byte(settings["agent_command_result_"+machineCode]), &result); err != nil {
		t.Fatalf("decode command result: %v", err)
	}
	if result["service"] != "agent" || result["action"] != "restart" {
		t.Fatalf("OpenWrt action metadata was not retained: %#v", result)
	}
}

func TestCreateAgentCommandWithTrackingIsAtomicOnPendingConflict(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "reboot-queue.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	const machineCode = "atomic_reboot_node"
	if err := store.UpdateSettings(map[string]string{
		"agent_command_" + machineCode:         `{"id":"existing","type":"reboot_openwrt"}`,
		"agent_reboot_tracking_" + machineCode: `{"command_id":"existing","status":"queued"}`,
	}); err != nil {
		t.Fatal(err)
	}
	created, err := store.CreateAgentCommandWithTracking(
		machineCode,
		`{"id":"replacement","type":"reboot_openwrt"}`,
		`{"command_id":"replacement","status":"queued"}`,
	)
	if err != nil || created {
		t.Fatalf("conflicting queue = created %v err %v; want false, nil", created, err)
	}
	settings, err := store.GetSettings()
	if err != nil {
		t.Fatal(err)
	}
	if settings["agent_command_"+machineCode] != `{"id":"existing","type":"reboot_openwrt"}` ||
		settings["agent_reboot_tracking_"+machineCode] != `{"command_id":"existing","status":"queued"}` {
		t.Fatalf("conflicting transaction changed existing command/tracking: %#v", settings)
	}
}

func TestDeleteAgentBindingAlsoRemovesRebootTracking(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "revoke-reboot.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()
	const code = "revoke_reboot_node"
	if err := store.UpdateSettings(map[string]string{
		"agent_machine_" + code:         "dedicated-token",
		"agent_reboot_tracking_" + code: `{"command_id":"reboot-1","status":"waiting_reconnect"}`,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteAgentBinding(code); err != nil {
		t.Fatalf("DeleteAgentBinding: %v", err)
	}
	settings, err := store.GetSettings()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := settings["agent_reboot_tracking_"+code]; ok {
		t.Fatalf("reboot tracking survived Agent revocation: %#v", settings)
	}
}
