package app

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestValidateAgentInstanceCommandPayloadAllowlist(t *testing.T) {
	valid := json.RawMessage(`{"id":"update-1","type":"update_mihomo","version":"v1.2.3","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`)
	if err := validateAgentInstanceCommandPayload("mihomo", "update-1", valid); err != nil {
		t.Fatalf("valid Mihomo update rejected: %v", err)
	}
	if err := validateAgentInstanceCommandPayload("wireguard", "update-1", valid); err == nil {
		t.Fatal("WireGuard command accepted before runtime support exists")
	}
	unsupported := json.RawMessage(`{"id":"update-1","type":"restart","version":"v1.2.3","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`)
	if err := validateAgentInstanceCommandPayload("mihomo", "update-1", unsupported); err == nil {
		t.Fatal("unsupported command type accepted")
	}
	extra := json.RawMessage(`{"id":"update-1","type":"update_mihomo","version":"v1.2.3","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","shell":"touch /tmp/pwned"}`)
	if err := validateAgentInstanceCommandPayload("mihomo", "update-1", extra); err == nil {
		t.Fatal("unexpected command field accepted")
	}
	if err := validateAgentInstanceCommandPayload("mihomo", "other-id", valid); err == nil {
		t.Fatal("mismatched command ID accepted")
	}
}

func TestAgentInstanceCommandRedeliveryAndAckReplaySurviveStoreRestart(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "agent-command-recovery.db")
	store, err := OpenStore(dbPath)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	if err := store.ProvisionAgentInstance("recovery-node", "mihomo", "default", "recovery-secret-0123456789abcdef"); err != nil {
		t.Fatal(err)
	}
	command := json.RawMessage(`{"id":"recover-1","type":"update_mihomo","version":"v1.2.3","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`)
	if err := store.QueueAgentInstanceCommand("recovery-node", "mihomo", "default", "recover-1", command); err != nil {
		t.Fatalf("queue command: %v", err)
	}
	first, err := store.GetPendingAgentInstanceCommand("recovery-node", "mihomo", "default")
	if err != nil || first == nil || first.CommandID != "recover-1" {
		t.Fatalf("first delivery lookup: %#v err=%v", first, err)
	}
	second, err := store.GetPendingAgentInstanceCommand("recovery-node", "mihomo", "default")
	if err != nil || second == nil || second.CommandID != first.CommandID {
		t.Fatalf("redelivery did not return same pending command: %#v err=%v", second, err)
	}
	if err := store.db.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = OpenStore(dbPath)
	if err != nil {
		t.Fatalf("reopen Store after master restart: %v", err)
	}
	defer store.db.Close()
	recovered, err := store.GetPendingAgentInstanceCommand("recovery-node", "mihomo", "default")
	if err != nil || recovered == nil || recovered.CommandID != "recover-1" {
		t.Fatalf("pending command not recovered: %#v err=%v", recovered, err)
	}
	if err := store.AckAgentInstanceCommandIdempotent("recovery-node", "mihomo", "default", "recover-1", "success", "installed"); err != nil {
		t.Fatalf("first ACK: %v", err)
	}
	if err := store.AckAgentInstanceCommandIdempotent("recovery-node", "mihomo", "default", "recover-1", "success", "installed"); err != nil {
		t.Fatalf("identical ACK replay should succeed: %v", err)
	}
	if err := store.AckAgentInstanceCommandIdempotent("recovery-node", "mihomo", "default", "recover-1", "failed", "conflicting result"); err == nil {
		t.Fatal("conflicting ACK replay unexpectedly accepted")
	}
	if pending, err := store.GetPendingAgentInstanceCommand("recovery-node", "mihomo", "default"); err != nil || pending != nil {
		t.Fatalf("ACK did not clear pending command: %#v err=%v", pending, err)
	}
	latest, err := store.GetLatestAgentInstanceCommand("recovery-node", "mihomo", "default")
	if err != nil || latest == nil || latest.Status != "success" || latest.Result != "installed" {
		t.Fatalf("durable ACK result changed: %#v err=%v", latest, err)
	}
}
