package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestMihomoSecretCandidates(t *testing.T) {
	dir := t.TempDir()
	configPath := dir + "/config.yaml"
	previousPath := configPath + ".previous"

	if err := os.WriteFile(previousPath, []byte("secret: old-secret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte("secret: \"new-secret\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := mihomoSecretCandidates(configPath)
	if err != nil {
		t.Fatalf("mihomoSecretCandidates() error = %v", err)
	}
	if len(got) != 2 || got[0] != "old-secret" || got[1] != "new-secret" {
		t.Fatalf("secret candidates = %#v, want previous then current", got)
	}

	if err := os.WriteFile(previousPath, []byte("secret: same-secret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte("secret: same-secret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err = mihomoSecretCandidates(configPath)
	if err != nil {
		t.Fatalf("deduplicated candidates returned error: %v", err)
	}
	if len(got) != 1 || got[0] != "same-secret" {
		t.Fatalf("duplicate secret candidates = %#v, want one unique secret", got)
	}

	if err := os.WriteFile(configPath, []byte("secret: \"\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(previousPath); err != nil {
		t.Fatal(err)
	}
	if _, err := mihomoSecretCandidates(configPath); err == nil {
		t.Fatal("expected error when no valid secret exists")
	}
}

func TestHostnameHandler(t *testing.T) {
	t.Setenv("S5M_HOSTNAME", "edge-node-01")
	req := httptest.NewRequest(http.MethodGet, "/api/hostname", nil)
	rec := httptest.NewRecorder()
	hostnameHandler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/hostname status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var payload map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode hostname response: %v", err)
	}
	if payload["hostname"] != "edge-node-01" {
		t.Fatalf("hostname = %q, want configured host hostname", payload["hostname"])
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}

	post := httptest.NewRequest(http.MethodPost, "/api/hostname", nil)
	postRec := httptest.NewRecorder()
	hostnameHandler(postRec, post)
	if postRec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /api/hostname status = %d, want %d", postRec.Code, http.StatusMethodNotAllowed)
	}
	if got := postRec.Header().Get("Allow"); got != http.MethodGet {
		t.Fatalf("Allow = %q, want GET", got)
	}
}

func TestValidateCentralURL(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
		ok   bool
	}{
		{name: "https", in: " https://controller.example.com/ ", want: "https://controller.example.com", ok: true},
		{name: "http local network", in: "http://192.0.2.10:8080", want: "http://192.0.2.10:8080", ok: true},
		{name: "missing scheme", in: "controller.example.com", ok: false},
		{name: "unsupported scheme", in: "ftp://controller.example.com", ok: false},
		{name: "missing host", in: "https://", ok: false},
		{name: "userinfo", in: "https://user:pass@controller.example.com", ok: false},
		{name: "query", in: "https://controller.example.com?token=x", ok: false},
		{name: "fragment", in: "https://controller.example.com#fragment", ok: false},
		{name: "newline", in: "https://controller.example.com\r\nX-Injected: yes", ok: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := validateCentralURL(tt.in)
			if tt.ok {
				if err != nil {
					t.Fatalf("expected valid URL, got error: %v", err)
				}
				if got != tt.want {
					t.Fatalf("URL = %q, want %q", got, tt.want)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected invalid URL %q to be rejected; got %q", tt.in, got)
			}
		})
	}
}

func TestValidateKernelUpdateCommand(t *testing.T) {
	tests := []struct {
		name    string
		version string
		sha256  string
		wantErr bool
	}{
		{name: "valid", version: "v1.19.31", sha256: strings.Repeat("a", 64)},
		{name: "missing v prefix", version: "1.19.31", sha256: strings.Repeat("a", 64), wantErr: true},
		{name: "version injection", version: "v1.19.31/../../latest", sha256: strings.Repeat("a", 64), wantErr: true},
		{name: "prerelease unsupported", version: "v1.19.31-rc.1", sha256: strings.Repeat("a", 64), wantErr: true},
		{name: "short checksum", version: "v1.19.31", sha256: "abcd", wantErr: true},
		{name: "non hex checksum", version: "v1.19.31", sha256: strings.Repeat("z", 64), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateKernelUpdateCommand(agentCommand{Version: tt.version, SHA256: tt.sha256})
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateKernelUpdateCommand() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateMihomoConfigYAML(t *testing.T) {
	valid := []byte("mixed-port: 7890\nsecret: test-secret\ntun:\n  enable: false\ndns:\n  enable: true\n  nameserver:\n    - 1.1.1.1\n")
	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{name: "valid full config", data: valid},
		{name: "empty", data: []byte(""), wantErr: true},
		{name: "malformed yaml", data: []byte("tun: ["), wantErr: true},
		{name: "empty document", data: []byte("---\n"), wantErr: true},
		{name: "missing secret", data: []byte("tun: {}\ndns: {}\n"), wantErr: true},
		{name: "blank secret", data: []byte("secret: '  '\ntun: {}\ndns: {}\n"), wantErr: true},
		{name: "missing tun", data: []byte("secret: test\ndns: {}\n"), wantErr: true},
		{name: "tun wrong type", data: []byte("secret: test\ntun: false\ndns: {}\n"), wantErr: true},
		{name: "missing dns", data: []byte("secret: test\ntun: {}\n"), wantErr: true},
		{name: "dns wrong type", data: []byte("secret: test\ntun: {}\ndns: true\n"), wantErr: true},
		{name: "over size limit", data: append(valid, []byte(strings.Repeat(" ", 2*1024*1024))...), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := validateMihomoConfigYAML(tt.data)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateMihomoConfigYAML() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNewMihomoRestartRequest(t *testing.T) {
	req, err := newMihomoRestartRequest("test-secret")
	if err != nil {
		t.Fatalf("newMihomoRestartRequest() error = %v", err)
	}
	if req.Method != http.MethodPost {
		t.Fatalf("restart method = %q, want %q", req.Method, http.MethodPost)
	}
	if req.URL.String() != "http://127.0.0.1:8088/restart" {
		t.Fatalf("restart URL = %q", req.URL.String())
	}
	if got := req.Header.Get("Authorization"); got != "Bearer test-secret" {
		t.Fatalf("Authorization = %q, want bearer secret", got)
	}
}

func TestMihomoVersionMatches(t *testing.T) {
	tests := []struct {
		name, actual, expected string
		want                   bool
	}{
		{name: "exact", actual: "1.19.31", expected: "1.19.31", want: true},
		{name: "prefix v", actual: "v1.19.31", expected: "1.19.31", want: true},
		{name: "both prefix v", actual: "v1.19.31", expected: "v1.19.31", want: true},
		{name: "different version", actual: "1.19.30", expected: "1.19.31"},
		{name: "empty actual", actual: "", expected: "1.19.31"},
		{name: "empty expected", actual: "1.19.31", expected: ""},
		{name: "suffix mismatch", actual: "1.19.31-dev", expected: "1.19.31"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := mihomoVersionMatches(tt.actual, tt.expected); got != tt.want {
				t.Fatalf("mihomoVersionMatches(%q, %q) = %v, want %v", tt.actual, tt.expected, got, tt.want)
			}
		})
	}
}

func TestVerifyKernelUpgrade(t *testing.T) {
	restartFailure := errors.New("restart connection closed")
	healthFailure := errors.New("version health check timed out")
	rollbackFailure := errors.New("restore failed")

	tests := []struct {
		name         string
		restartErr   error
		healthErr    error
		rollbackErr  error
		wantErr      bool
		wantRollback bool
		wantErrParts []string
	}{
		{
			name:       "restart transport error but new version healthy",
			restartErr: restartFailure,
		},
		{
			name:         "health check fails and rollback succeeds",
			healthErr:    healthFailure,
			wantErr:      true,
			wantRollback: true,
			wantErrParts: []string{"健康检查失败", "已恢复旧内核"},
		},
		{
			name:         "health and rollback both fail",
			healthErr:    healthFailure,
			rollbackErr:  rollbackFailure,
			wantErr:      true,
			wantRollback: true,
			wantErrParts: []string{"健康检查失败", "恢复旧内核失败", "restore failed"},
		},
		{
			name:         "restart and health fail but rollback succeeds",
			restartErr:   restartFailure,
			healthErr:    healthFailure,
			wantErr:      true,
			wantRollback: true,
			wantErrParts: []string{"重启请求返回错误", "健康检查", "已恢复旧内核"},
		},
		{
			name:         "restart fails and rollback fails",
			restartErr:   restartFailure,
			healthErr:    healthFailure,
			rollbackErr:  rollbackFailure,
			wantErr:      true,
			wantRollback: true,
			wantErrParts: []string{"重启请求返回错误", "健康检查失败", "恢复旧内核失败"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rollbackCalled := false
			err := verifyKernelUpgrade(
				func() error { return tt.restartErr },
				func() error { return tt.healthErr },
				func() error {
					rollbackCalled = true
					return tt.rollbackErr
				},
			)
			if (err != nil) != tt.wantErr {
				t.Fatalf("verifyKernelUpgrade() error = %v, wantErr %v", err, tt.wantErr)
			}
			if rollbackCalled != tt.wantRollback {
				t.Fatalf("rollback called = %v, want %v", rollbackCalled, tt.wantRollback)
			}
			if !tt.wantErr && rollbackCalled {
				t.Fatal("successful health check must not trigger rollback")
			}
			if err != nil {
				for _, part := range tt.wantErrParts {
					if !strings.Contains(err.Error(), part) {
						t.Errorf("error %q does not contain %q", err, part)
					}
				}
			}
		})
	}
}

func TestCalculateMihomoSpeeds(t *testing.T) {
	mihomoSpeedMu.Lock()
	mihomoSpeedLastTime = time.Time{}
	mihomoSpeedLastUpload = 0
	mihomoSpeedLastDownload = 0
	mihomoSpeedMu.Unlock()

	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	up, down := calculateMihomoSpeeds(100, 200, start)
	if up != 0 || down != 0 {
		t.Fatalf("first sample should have zero speed, got up=%d down=%d", up, down)
	}
	up, down = calculateMihomoSpeeds(500, 800, start.Add(2*time.Second))
	if up != 200 || down != 300 {
		t.Fatalf("speed = up:%d down:%d, want up:200 down:300", up, down)
	}
	up, down = calculateMihomoSpeeds(10, 20, start.Add(4*time.Second))
	if up != 0 || down != 0 {
		t.Fatalf("counter reset should not report negative speed, got up=%d down=%d", up, down)
	}
}

func TestTrafficCounter(t *testing.T) {
	if got, ok := trafficCounter(float64(123)); !ok || got != 123 {
		t.Fatalf("trafficCounter(float64(123)) = %d, %v", got, ok)
	}
	if _, ok := trafficCounter("123"); ok {
		t.Fatal("trafficCounter should reject string counters")
	}
}
func TestPreserveMihomoSecret(t *testing.T) {
	incoming := map[string]interface{}{"secret": "controller-supplied", "mode": "rule"}
	current := map[string]interface{}{"secret": "local-secret"}
	if err := preserveMihomoSecret(current, incoming); err != nil {
		t.Fatalf("preserveMihomoSecret() error = %v", err)
	}
	if incoming["secret"] != "local-secret" {
		t.Fatalf("incoming secret = %#v, want local secret", incoming["secret"])
	}

	for name, config := range map[string]map[string]interface{}{
		"missing":    {},
		"blank":      {"secret": "  "},
		"wrong type": {"secret": true},
	} {
		t.Run(name, func(t *testing.T) {
			if err := preserveMihomoSecret(config, map[string]interface{}{}); err == nil {
				t.Fatal("missing or invalid local secret should be rejected")
			}
		})
	}
}

func TestNormalizeMachineID(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{name: "valid id", data: []byte("0123456789abcdef0123456789abcdef\n"), want: "0123456789a"},
		{name: "valid legacy id", data: []byte("abc123def456"), want: "abc123def45"},
		{name: "empty", data: []byte(""), want: ""},
		{name: "too short", data: []byte("abc123"), want: ""},
		{name: "invalid characters", data: []byte("0123456789gabcdef0123456789abcde"), want: ""},
		{name: "all zero", data: []byte("00000000000000000000000000000000"), want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeMachineID(tt.data)
			if len(got) > 11 {
				got = got[:11]
			}
			if got != tt.want {
				t.Fatalf("normalizeMachineID() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestReadSystemMachineID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "machine-id")
	if _, err := readSystemMachineID(path); err == nil {
		t.Fatal("missing file should fail")
	}
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readSystemMachineID(path); err == nil {
		t.Fatal("empty file should fail")
	}
	if err := os.WriteFile(path, []byte("fedcba9876543210fedcba9876543210\n"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := readSystemMachineID(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != "fedcba98765" {
		t.Fatalf("readSystemMachineID() = %q", got)
	}
}

func TestLoadOrCreateMachineIDFallbackIsStableAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	systemPath := filepath.Join(dir, "missing-machine-id")
	storagePath := filepath.Join(dir, "persistent-data", "machine-id")
	first, err := loadOrCreateMachineID(systemPath, storagePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 11 {
		t.Fatalf("machine ID length = %d, want 11", len(first))
	}
	info, err := os.Stat(storagePath)
	if err != nil {
		t.Fatalf("fallback was not persisted: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("fallback permissions = %o, want 600", info.Mode().Perm())
	}
	// A second invocation simulates restart while /data stays mounted.
	second, err := loadOrCreateMachineID(systemPath, storagePath)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("machine ID changed after restart: %q != %q", first, second)
	}
}

func TestLoadOrCreateMachineIDReplacesEmptyPersistedFallback(t *testing.T) {
	dir := t.TempDir()
	systemPath := filepath.Join(dir, "missing-machine-id")
	storagePath := filepath.Join(dir, "data", "machine-id")
	if err := os.MkdirAll(filepath.Dir(storagePath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(storagePath, nil, 0600); err != nil {
		t.Fatal(err)
	}
	id, err := loadOrCreateMachineID(systemPath, storagePath)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(storagePath)
	if err != nil {
		t.Fatal(err)
	}
	if validStoredFallbackMachineID(data) == "" {
		t.Fatal("empty persisted fallback was not replaced by a valid ID")
	}
	if id != string(data[:11]) {
		t.Fatalf("returned machine ID %q does not match persisted ID", id)
	}
}

func TestLoadOrCreateMachineIDRejectsUnwritableStorage(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "not-a-directory")
	if err := os.WriteFile(blocker, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := loadOrCreateMachineID(filepath.Join(dir, "missing"), filepath.Join(blocker, "machine-id"))
	if err == nil {
		t.Fatal("expected a clear storage error")
	}
}

func TestMachineIDHandler(t *testing.T) {
	t.Setenv("MIHOMO_HOME", t.TempDir())
	req := httptest.NewRequest(http.MethodGet, "/api/machine-id", nil)
	rec := httptest.NewRecorder()
	machineIDHandler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var result map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result["machine_id"]) != 11 {
		t.Fatalf("unexpected response: %#v", result)
	}
	req = httptest.NewRequest(http.MethodPost, "/api/machine-id", nil)
	rec = httptest.NewRecorder()
	machineIDHandler(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status = %d, want 405", rec.Code)
	}
}

func TestMihomoBinaryPathForRouterOS(t *testing.T) {
	t.Setenv("S5M_ROUTEROS", "1")
	t.Setenv("MIHOMO_HOME", "/routeros-persist")
	if got, want := mihomoBinaryPath(), "/routeros-persist/bin/mihomo"; got != want {
		t.Fatalf("RouterOS mihomoBinaryPath() = %q, want %q", got, want)
	}
	t.Setenv("S5M_ROUTEROS", "0")
	if got, want := mihomoBinaryPath(), "/usr/local/bin/mihomo"; got != want {
		t.Fatalf("default mihomoBinaryPath() = %q, want %q", got, want)
	}
}

func TestReportHeartbeatWebSocketSuccess(t *testing.T) {
	t.Setenv("S5M_AGENT_WEBSOCKET", "1")
	var httpFallbackCalled bool
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/agent/ws":
			if r.Header.Get("Authorization") != "Bearer test-token" {
				t.Errorf("WebSocket Authorization header = %q", r.Header.Get("Authorization"))
			}
			conn, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				t.Errorf("upgrade websocket: %v", err)
				return
			}
			defer conn.Close()
			if err := conn.WriteJSON(map[string]any{"type": "welcome"}); err != nil {
				t.Errorf("write welcome: %v", err)
				return
			}
			var msg struct {
				Type   string         `json:"type"`
				ID     string         `json:"id"`
				Status map[string]any `json:"status"`
			}
			if err := conn.ReadJSON(&msg); err != nil {
				t.Errorf("read heartbeat: %v", err)
				return
			}
			if msg.Type != "heartbeat" || msg.ID == "" || msg.Status["mihomo_version"] != "test-version" {
				t.Errorf("unexpected heartbeat payload: %#v", msg)
				return
			}
			if err := conn.WriteJSON(map[string]any{"type": "heartbeat.ack", "id": msg.ID, "ok": true}); err != nil {
				t.Errorf("write ack: %v", err)
			}
		case "/api/v1/agent/heartbeat":
			httpFallbackCalled = true
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	err := reportHeartbeat(Config{CentralURL: server.URL, Token: "test-token"}, map[string]any{"mihomo_version": "test-version"})
	if err != nil {
		t.Fatalf("reportHeartbeat() error = %v", err)
	}
	if httpFallbackCalled {
		t.Fatal("HTTP fallback was called even though WebSocket heartbeat succeeded")
	}
}

func TestReportHeartbeatFallsBackToHTTPWhenWebSocketFails(t *testing.T) {
	t.Setenv("S5M_AGENT_WEBSOCKET", "1")
	var httpCalled bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/agent/heartbeat" {
			http.NotFound(w, r)
			return
		}
		httpCalled = true
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("HTTP Authorization header = %q", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	err := reportHeartbeat(Config{CentralURL: server.URL, Token: "test-token"}, map[string]any{"mihomo_version": "test-version"})
	if err != nil {
		t.Fatalf("reportHeartbeat() fallback error = %v", err)
	}
	if !httpCalled {
		t.Fatal("HTTP fallback was not called after WebSocket handshake failure")
	}
}

func TestReportHeartbeatFallsBackWhenWebSocketAckIDDoesNotMatch(t *testing.T) {
	t.Setenv("S5M_AGENT_WEBSOCKET", "1")
	var httpCalled bool
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/agent/ws":
			conn, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				t.Errorf("upgrade websocket: %v", err)
				return
			}
			defer conn.Close()
			if err := conn.WriteJSON(map[string]any{"type": "welcome"}); err != nil {
				t.Errorf("write welcome: %v", err)
				return
			}
			var msg map[string]any
			if err := conn.ReadJSON(&msg); err != nil {
				t.Errorf("read heartbeat: %v", err)
				return
			}
			if err := conn.WriteJSON(map[string]any{"type": "heartbeat.ack", "id": "wrong-id", "ok": true}); err != nil {
				t.Errorf("write ack: %v", err)
			}
		case "/api/v1/agent/heartbeat":
			httpCalled = true
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	err := reportHeartbeat(Config{CentralURL: server.URL, Token: "test-token"}, map[string]any{"mihomo_version": "test-version"})
	if err != nil {
		t.Fatalf("reportHeartbeat() fallback error = %v", err)
	}
	if !httpCalled {
		t.Fatal("HTTP fallback was not called after mismatched WebSocket ACK ID")
	}
}

func TestReportHeartbeatWebSocketPreservesCentralBasePath(t *testing.T) {
	t.Setenv("S5M_AGENT_WEBSOCKET", "1")
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/gateway/api/v1/agent/ws" {
			http.NotFound(w, r)
			return
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade websocket: %v", err)
			return
		}
		defer conn.Close()
		if err := conn.WriteJSON(map[string]any{"type": "welcome"}); err != nil {
			t.Errorf("write welcome: %v", err)
			return
		}
		var msg struct {
			Type string `json:"type"`
			ID   string `json:"id"`
		}
		if err := conn.ReadJSON(&msg); err != nil {
			t.Errorf("read heartbeat: %v", err)
			return
		}
		if err := conn.WriteJSON(map[string]any{"type": "heartbeat.ack", "id": msg.ID, "ok": true}); err != nil {
			t.Errorf("write ack: %v", err)
		}
	}))
	defer server.Close()

	cfg := Config{CentralURL: server.URL + "/gateway", Token: "test-token"}
	if err := reportHeartbeatWebSocket(cfg, map[string]any{"mihomo_version": "test-version"}); err != nil {
		t.Fatalf("reportHeartbeatWebSocket() error = %v", err)
	}
}
