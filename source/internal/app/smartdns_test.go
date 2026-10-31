package app

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"strconv"
	"time"
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
		"agent_machine_" + code: "dedicated-token",
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

func TestQueueAgentSmartDNSConfigRollsBackCommandWhenDesiredConfigWriteFails(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "smartdns-atomic.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()
	const code = "node_smartdns_03"
	if err := store.UpdateSettings(map[string]string{
		"agent_token":           "global-token",
		"agent_machine_" + code: "dedicated-token",
	}); err != nil {
		t.Fatalf("UpdateSettings: %v", err)
	}
	if _, err := store.db.Exec(`CREATE TRIGGER fail_smartdns_desired_config
		BEFORE INSERT ON settings
		WHEN NEW.key = 'agent_smartdns_config_node_smartdns_03'
		BEGIN SELECT RAISE(ABORT, 'simulated desired config write failure'); END`); err != nil {
		t.Fatalf("create failure trigger: %v", err)
	}
	a := &App{store: store}
	if err := a.queueAgentSmartDNSConfig(code, defaultAgentSmartDNSConfig); err == nil || !strings.Contains(err.Error(), "期望配置") {
		t.Fatalf("queue error = %v, want desired-config persistence failure", err)
	}
	settings, err := store.GetSettings()
	if err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	if _, exists := settings["agent_command_"+code]; exists {
		t.Fatalf("pending command was left behind after transaction failure: %q", settings["agent_command_"+code])
	}
	if _, exists := settings["agent_smartdns_config_"+code]; exists {
		t.Fatalf("desired config unexpectedly persisted despite trigger failure")
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
		"agent_token":                   "global-token",
		"agent_machine_" + code:         "dedicated-token",
		"agent_lastseen_" + code:        strconv.FormatInt(time.Now().Unix(), 10),
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
	if result["desired_config_sha256"] != hashSmartDNSConfig(defaultAgentSmartDNSConfig) {
		t.Fatalf("desired_config_sha256 = %v, want %s", result["desired_config_sha256"], hashSmartDNSConfig(defaultAgentSmartDNSConfig))
	}
	if hashSmartDNSConfig("server 223.5.5.5\n") != hashSmartDNSConfig("server 223.5.5.5") {
		t.Fatal("SmartDNS desired hash must ignore trailing whitespace, matching Agent runtime hashing")
	}
	if result["reported_config_sha256"] != "abc" {
		t.Fatalf("reported_config_sha256 = %v, want the Agent-reported value", result["reported_config_sha256"])
	}
}

func TestQueueAgentSmartDNSConfigConcurrentRequestsKeepCommandAndDesiredConfigConsistent(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "smartdns-concurrent.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	const code = "node_smartdns_concurrent"
	if err := store.UpdateSettings(map[string]string{
		"agent_token":           "global-token",
		"agent_machine_" + code: "dedicated-token",
	}); err != nil {
		t.Fatalf("UpdateSettings: %v", err)
	}
	a := &App{store: store}

	const contenders = 12
	start := make(chan struct{})
	results := make(chan error, contenders)
	var wg sync.WaitGroup
	for i := 0; i < contenders; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			config := defaultAgentSmartDNSConfig + fmt.Sprintf("\n# contender %d\n", i)
			<-start
			results <- a.queueAgentSmartDNSConfig(code, config)
		}(i)
	}
	close(start)
	wg.Wait()
	close(results)

	successes := 0
	for err := range results {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("successful queue requests = %d, want exactly 1", successes)
	}

	settings, err := store.GetSettings()
	if err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	var command map[string]string
	if err := json.Unmarshal([]byte(settings["agent_command_"+code]), &command); err != nil {
		t.Fatalf("decode pending command: %v", err)
	}
	desired := settings["agent_smartdns_config_"+code]
	if command["type"] != "configure_smartdns" || command["config"] == "" {
		t.Fatalf("invalid pending command: %#v", command)
	}
	if command["config"] != desired {
		t.Fatalf("pending command config differs from desired config")
	}
}


func TestSmartDNSStatusExpiresOldAndMissingHeartbeats(t *testing.T) {
	const code = "node_smartdns_stale"
	base := map[string]string{
		"agent_status_" + code:  `{"smartdns_available":true,"smartdns_running":true,"smartdns_dns_healthy":true,"smartdns_version":"old"}`,
		"agent_lastseen_" + code: strconv.FormatInt(time.Now().Add(-5*time.Minute).Unix(), 10),
	}
	status := smartDNSStatusFromSettings(base, code)
	if status["online"] != false || status["telemetry_received"] != false ||
		status["smartdns_running"] != false || status["smartdns_dns_healthy"] != false {
		t.Fatalf("stale status was treated as live: %#v", status)
	}
	delete(base, "agent_lastseen_"+code)
	status = smartDNSStatusFromSettings(base, code)
	if status["online"] != false || status["smartdns_last_error"] != "Agent 尚未上报心跳" {
		t.Fatalf("missing heartbeat was not classified correctly: %#v", status)
	}
}

func TestSmartDNSStatusRecognizesFreshLegacyAgentWithoutTelemetry(t *testing.T) {
	const code = "node_smartdns_legacy"
	settings := map[string]string{
		"agent_lastseen_" + code: strconv.FormatInt(time.Now().Unix(), 10),
		"agent_status_" + code:  `{"mihomo_healthy":true}`,
	}
	status := smartDNSStatusFromSettings(settings, code)
	if status["online"] != true || status["telemetry_received"] != false ||
		status["smartdns_last_error"] != "当前 Agent 版本尚未上报 SmartDNS 状态" {
		t.Fatalf("legacy Agent telemetry was misclassified: %#v", status)
	}
}
