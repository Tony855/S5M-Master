package app

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestAgentInstanceLatestCommandUsesCompositeOrderingIndex(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "agent-index.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.db.Close()
	if err := store.ProvisionAgentInstance("index-node", "wireguard", "routeros-1", "index-secret-0123456789abcdef-0123456789"); err != nil {
		t.Fatal(err)
	}
	first := json.RawMessage(`{"id":"first","type":"wireguard_status","interface":"wg0"}`)
	if err := store.QueueAgentInstanceCommand("index-node", "wireguard", "routeros-1", "first", first); err != nil {
		t.Fatal(err)
	}
	if err := store.AckAgentInstanceCommandIdempotent("index-node", "wireguard", "routeros-1", "first", "success", "ok"); err != nil {
		t.Fatal(err)
	}
	second := json.RawMessage(`{"id":"second","type":"wireguard_status","interface":"wg0"}`)
	if err := store.QueueAgentInstanceCommand("index-node", "wireguard", "routeros-1", "second", second); err != nil {
		t.Fatal(err)
	}

	rows, err := store.db.Query(`EXPLAIN QUERY PLAN SELECT machine_code, agent_type, instance_id, command_id, command_json,
		status, result_message, created_at, updated_at FROM agent_instance_commands
		WHERE machine_code=? AND agent_type=? AND instance_id=?
		ORDER BY updated_at DESC, created_at DESC, command_id DESC LIMIT 1`,
		"index-node", "wireguard", "routeros-1")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var details []string
	for rows.Next() {
		var id, parent, notUsed int
		var detail string
		if err := rows.Scan(&id, &parent, &notUsed, &detail); err != nil {
			t.Fatal(err)
		}
		details = append(details, detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(details, "\n")
	if !strings.Contains(joined, "idx_agent_instance_command_latest") {
		t.Fatalf("latest command query did not use composite ordering index: %s", joined)
	}
	latest, err := store.GetLatestAgentInstanceCommand("index-node", "wireguard", "routeros-1")
	if err != nil || latest == nil || latest.CommandID != "second" {
		t.Fatalf("latest command = %#v, err=%v", latest, err)
	}
}
