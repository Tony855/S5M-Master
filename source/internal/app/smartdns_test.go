package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateControllerSmartDNSConfig(t *testing.T) {
	if err := validateControllerSmartDNSConfig(defaultAgentSmartDNSConfig); err != nil {
		t.Fatalf("default SmartDNS config rejected: %v", err)
	}
	for _, config := range []string{
		"",
		"include /etc/passwd\n",
		"exec /bin/sh\n",
		"bind 0.0.0.0:6053 extra\n",
		strings.Repeat("x", 9<<10),
	} {
		if err := validateControllerSmartDNSConfig(config); err == nil {
			t.Errorf("invalid SmartDNS config unexpectedly accepted: %q", config[:min(len(config), 40)])
		}
	}
}

func TestQueueAgentSmartDNSConfigRequiresDedicatedAuthorizedAgent(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "smartdns-command.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()
	const code = "node_smartdns_01"
	if err := store.UpdateSettings(map[string]string{
		"agent_token":           "global-token",
		"agent_machine_" + code:         "dedicated-token",
	}); err != nil {
		t.Fatalf("UpdateSettings: %v", err)
	}
	a := &App{store: store}
	if err := a.queueAgentSmartDNSConfig(code, defaultAgentSmartDNSConfig); err != nil {
		t.Fatalf("queue valid SmartDNS config: %v", err)
	}
	settings, err := store.GetSettings()
	if err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	var command map[string]string
	if err := json.Unmarshal([]byte(settings["agent_command_"+code]), &command); err != nil {
		t.Fatalf("decode pending command: %v", err)
	}
	if command["type"] != "configure_smartdns" || command["config"] != defaultAgentSmartDNSConfig {
		t.Fatalf("unexpected command payload: %#v", command)
	}
	if settings["agent_smartdns_config_"+code] != defaultAgentSmartDNSConfig {
		t.Fatal("desired SmartDNS config was not persisted")
	}
	if err := a.queueAgentSmartDNSConfig(code, defaultAgentSmartDNSConfig); err == nil || !strings.Contains(err.Error(), "待执行命令") {
		t.Fatalf("second pending command error = %v, want conflict", err)
	}
	if err := a.queueAgentSmartDNSConfig("not_bound", defaultAgentSmartDNSConfig); err == nil || !strings.Contains(err.Error(), "未授权") {
		t.Fatalf("unbound Agent error = %v, want unauthorized", err)
	}
}

func TestGetAgentSmartDNSConfigReturnsDesiredConfigAndReportedStatus(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "smartdns-get.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()
	const code = "node_smartdns_02"
	if err := store.UpdateSettings(map[string]string{
		"agent_token": "global-token",
		"agent_machine_" + code: "dedicated-token",
		"agent_status_" + code:          `{"smartdns_available":true,"smartdns_running":true,"smartdns_version":"SmartDNS test","smartdns_config_sha256":"abc"}`,
		"agent_smartdns_config_" + code: defaultAgentSmartDNSConfig,
	}); err != nil {
		t.Fatalf("UpdateSettings: %v", err)
	}
	a := &App{store: store}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents/smartdns/config?machine_code="+code, nil)
	a.handleGetAgentSmartDNSConfig(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var result map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if result["config"] != defaultAgentSmartDNSConfig || result["running"] != true || result["version"] != "SmartDNS test" {
		t.Fatalf("unexpected SmartDNS config/status response: %#v", result)
	}
}
