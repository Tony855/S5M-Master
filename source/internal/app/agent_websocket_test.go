package app

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
)

func websocketTestApp(t *testing.T) (*App, string, string) {
	t.Helper()
	store, err := OpenStore(filepath.Join(t.TempDir(), "agent-ws.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = store.db.Close() })

	const code = "ws_node_01"
	const secret = "ws-dedicated-secret"
	app := &App{store: store, jwtKey: []byte("test-ws-signing-key")}
	if err := store.UpdateSettings(map[string]string{
		"agent_token":           "global-secret",
		"agent_machine_" + code: secret,
	}); err != nil {
		t.Fatalf("UpdateSettings: %v", err)
	}
	sum := sha256.Sum256([]byte(secret))
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": code, "role": "agent", "ver": hex.EncodeToString(sum[:]),
	}).SignedString(app.jwtKey)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return app, code, token
}

func TestAgentWebSocketRejectsUnauthorizedHandshake(t *testing.T) {
	app, _, _ := websocketTestApp(t)
	server := httptest.NewServer(http.HandlerFunc(app.handleAgentWebSocket))
	defer server.Close()

	_, response, err := websocket.DefaultDialer.Dial("ws"+server.URL[len("http"):], nil)
	if err == nil {
		t.Fatal("unauthorized WebSocket handshake unexpectedly succeeded")
	}
	if response == nil || response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("handshake response = %#v, want HTTP 401", response)
	}
}

func TestAgentWebSocketAcceptsHeartbeatAndPersistsStatus(t *testing.T) {
	app, code, token := websocketTestApp(t)
	server := httptest.NewServer(http.HandlerFunc(app.handleAgentWebSocket))
	defer server.Close()

	header := http.Header{}
	header.Set("Authorization", "Bearer "+token)
	conn, _, err := websocket.DefaultDialer.Dial("ws"+server.URL[len("http"):], header)
	if err != nil {
		t.Fatalf("dial authenticated WebSocket: %v", err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	var welcome map[string]any
	if err := conn.ReadJSON(&welcome); err != nil {
		t.Fatalf("read welcome: %v", err)
	}
	if welcome["type"] != "welcome" {
		t.Fatalf("welcome type = %#v", welcome["type"])
	}

	status := map[string]any{
		"mihomo_version": "v1.19.3",
		"mihomo_healthy": true,
		"upload_total":   12,
		"download_total": 34,
		"upload_speed":   1,
		"download_speed": 2,
		"connections":    3,
		"config_sha256":  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"last_error":     "",
	}
	if err := conn.WriteJSON(map[string]any{"type": "heartbeat", "id": "hb-1", "status": status}); err != nil {
		t.Fatalf("send heartbeat: %v", err)
	}
	var ack map[string]any
	if err := conn.ReadJSON(&ack); err != nil {
		t.Fatalf("read heartbeat ACK: %v", err)
	}
	if ack["type"] != "heartbeat.ack" || ack["id"] != "hb-1" || ack["ok"] != true {
		t.Fatalf("unexpected ACK: %#v", ack)
	}

	settings, err := app.store.GetSettings()
	if err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	var saved map[string]any
	if err := json.Unmarshal([]byte(settings["agent_status_"+code]), &saved); err != nil {
		t.Fatalf("decode persisted status: %v", err)
	}
	if saved["mihomo_version"] != "v1.19.3" || saved["received_at"] == nil {
		t.Fatalf("unexpected persisted status: %#v", saved)
	}
	if settings["agent_lastseen_"+code] == "" {
		t.Fatal("heartbeat did not persist last-seen timestamp")
	}
}

func TestAgentWebSocketSupersededConnectionCannotOverwriteStatus(t *testing.T) {
	app, code, token := websocketTestApp(t)
	server := httptest.NewServer(http.HandlerFunc(app.handleAgentWebSocket))
	defer server.Close()

	header := http.Header{}
	header.Set("Authorization", "Bearer "+token)
	dial := func() *websocket.Conn {
		t.Helper()
		conn, _, err := websocket.DefaultDialer.Dial("ws"+server.URL[len("http"):], header)
		if err != nil {
			t.Fatalf("dial authenticated WebSocket: %v", err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		var welcome map[string]any
		if err := conn.ReadJSON(&welcome); err != nil {
			conn.Close()
			t.Fatalf("read welcome: %v", err)
		}
		if welcome["type"] != "welcome" {
			conn.Close()
			t.Fatalf("welcome type = %#v", welcome["type"])
		}
		return conn
	}

	oldConn := dial()
	defer oldConn.Close()
	newConn := dial()
	defer newConn.Close()

	status := map[string]any{
		"mihomo_version": "stale-connection",
		"mihomo_healthy": true,
		"upload_total":   float64(12),
		"download_total": float64(34),
		"upload_speed":   float64(1),
		"download_speed": float64(2),
		"connections":    float64(3),
		"config_sha256":  strings.Repeat("a", 64),
		"last_error":     "",
	}
	if err := oldConn.WriteJSON(map[string]any{"type": "heartbeat", "id": "hb-old", "status": status}); err != nil {
		t.Fatalf("send heartbeat on superseded connection: %v", err)
	}
	var response map[string]any
	if err := oldConn.ReadJSON(&response); err != nil {
		t.Fatalf("read superseded connection response: %v", err)
	}
	if response["type"] != "error" || !strings.Contains(response["message"].(string), "取代") {
		t.Fatalf("unexpected superseded connection response: %#v", response)
	}

	settings, err := app.store.GetSettings()
	if err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	if settings["agent_status_"+code] != "" || settings["agent_lastseen_"+code] != "" {
		t.Fatalf("superseded connection persisted status: %#v", settings)
	}

	freshStatus := map[string]any{}
	for k, v := range status {
		freshStatus[k] = v
	}
	freshStatus["mihomo_version"] = "current-connection"
	if err := newConn.WriteJSON(map[string]any{"type": "heartbeat", "id": "hb-new", "status": freshStatus}); err != nil {
		t.Fatalf("send heartbeat on current connection: %v", err)
	}
	if err := newConn.ReadJSON(&response); err != nil {
		t.Fatalf("read current connection ACK: %v", err)
	}
	if response["type"] != "heartbeat.ack" || response["id"] != "hb-new" {
		t.Fatalf("unexpected current connection response: %#v", response)
	}
	settings, err = app.store.GetSettings()
	if err != nil {
		t.Fatalf("GetSettings after current heartbeat: %v", err)
	}
	var saved map[string]any
	if err := json.Unmarshal([]byte(settings["agent_status_"+code]), &saved); err != nil {
		t.Fatalf("decode current status: %v", err)
	}
	if saved["mihomo_version"] != "current-connection" {
		t.Fatalf("status overwritten by stale connection: %#v", saved)
	}
}

func TestAgentWebSocketGenerationDoesNotResetAfterDisconnect(t *testing.T) {
	app, _, token := websocketTestApp(t)
	server := httptest.NewServer(http.HandlerFunc(app.handleAgentWebSocket))
	defer server.Close()

	header := http.Header{}
	header.Set("Authorization", "Bearer "+token)
	dial := func() *websocket.Conn {
		t.Helper()
		conn, _, err := websocket.DefaultDialer.Dial("ws"+server.URL[len("http"):], header)
		if err != nil {
			t.Fatalf("dial authenticated WebSocket: %v", err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		var welcome map[string]any
		if err := conn.ReadJSON(&welcome); err != nil {
			conn.Close()
			t.Fatalf("read welcome: %v", err)
		}
		return conn
	}

	oldConn := dial()
	defer oldConn.Close()
	middleConn := dial()
	middleConn.Close()
	latestConn := dial()
	defer latestConn.Close()

	status := map[string]any{
		"mihomo_version": "stale-connection",
		"mihomo_healthy": true,
		"upload_total":   float64(12),
		"download_total": float64(34),
		"upload_speed":   float64(1),
		"download_speed": float64(2),
		"connections":    float64(3),
		"config_sha256":  strings.Repeat("a", 64),
		"last_error":     "",
	}
	if err := oldConn.WriteJSON(map[string]any{"type": "heartbeat", "id": "hb-aba", "status": status}); err != nil {
		t.Fatalf("send heartbeat on stale connection: %v", err)
	}
	var response map[string]any
	if err := oldConn.ReadJSON(&response); err != nil {
		t.Fatalf("read stale connection response: %v", err)
	}
	if response["type"] != "error" {
		t.Fatalf("stale connection was re-authorized after reconnect: %#v", response)
	}
}

func TestHTTPAgentHeartbeatRejectsInvalidTelemetry(t *testing.T) {
	app, code, token := websocketTestApp(t)
	status := map[string]any{
		"mihomo_version": "v1.19.3",
		"mihomo_healthy": true,
		"upload_total":   float64(-1),
		"download_total": float64(34),
		"upload_speed":   float64(1),
		"download_speed": float64(2),
		"connections":    float64(3),
		"config_sha256":  strings.Repeat("a", 64),
		"last_error":     "",
	}
	body, err := json.Marshal(status)
	if err != nil {
		t.Fatalf("marshal status: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/heartbeat", strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	app.handleAgentHeartbeat(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	settings, err := app.store.GetSettings()
	if err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	if settings["agent_status_"+code] != "" || settings["agent_lastseen_"+code] != "" {
		t.Fatal("invalid HTTP heartbeat must not be persisted")
	}
}

func TestAgentWebSocketRejectsHeartbeatMissingRequiredFields(t *testing.T) {
	app, _, token := websocketTestApp(t)
	server := httptest.NewServer(http.HandlerFunc(app.handleAgentWebSocket))
	defer server.Close()

	header := http.Header{}
	header.Set("Authorization", "Bearer "+token)
	conn, _, err := websocket.DefaultDialer.Dial("ws"+server.URL[len("http"):], header)
	if err != nil {
		t.Fatalf("dial authenticated WebSocket: %v", err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var welcome map[string]any
	if err := conn.ReadJSON(&welcome); err != nil {
		t.Fatalf("read welcome: %v", err)
	}
	if err := conn.WriteJSON(map[string]any{
		"type": "heartbeat", "id": "hb-bad", "status": map[string]any{"mihomo_version": "v1.0.0"},
	}); err != nil {
		t.Fatalf("send invalid heartbeat: %v", err)
	}
	var response map[string]any
	if err := conn.ReadJSON(&response); err != nil {
		t.Fatalf("read validation response: %v", err)
	}
	if response["type"] != "error" || response["id"] != "hb-bad" {
		t.Fatalf("unexpected validation response: %#v", response)
	}
}

func TestValidateAgentWSStatusRejectsInvalidValues(t *testing.T) {
	valid := func() map[string]any {
		return map[string]any{
			"mihomo_version": "v1.19.3",
			"mihomo_healthy": true,
			"upload_total":   float64(12),
			"download_total": float64(34),
			"upload_speed":   float64(1),
			"download_speed": float64(2),
			"connections":    float64(3),
			"config_sha256":  strings.Repeat("a", 64),
			"last_error":     "",
		}
	}
	tests := []struct {
		name    string
		mutate  func(map[string]any)
		wantErr bool
	}{
		{name: "valid", mutate: func(map[string]any) {}},
		{name: "empty hash allowed", mutate: func(s map[string]any) { s["config_sha256"] = "" }},
		{name: "healthy without version", mutate: func(s map[string]any) { s["mihomo_version"] = "" }, wantErr: true},
		{name: "wrong healthy type", mutate: func(s map[string]any) { s["mihomo_healthy"] = "true" }, wantErr: true},
		{name: "negative counter", mutate: func(s map[string]any) { s["upload_total"] = float64(-1) }, wantErr: true},
		{name: "fractional counter", mutate: func(s map[string]any) { s["download_total"] = float64(1.5) }, wantErr: true},
		{name: "wrong connections type", mutate: func(s map[string]any) { s["connections"] = "many" }, wantErr: true},
		{name: "invalid hash", mutate: func(s map[string]any) { s["config_sha256"] = "abc" }, wantErr: true},
		{name: "oversized error", mutate: func(s map[string]any) { s["last_error"] = strings.Repeat("x", agentWSMaxErrorBytes+1) }, wantErr: true},
		{name: "missing field", mutate: func(s map[string]any) { delete(s, "connections") }, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status := valid()
			tt.mutate(status)
			err := validateAgentWSStatus(status)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateAgentWSStatus() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAgentWebSocketDoesNotPersistInvalidStatus(t *testing.T) {
	app, code, token := websocketTestApp(t)
	server := httptest.NewServer(http.HandlerFunc(app.handleAgentWebSocket))
	defer server.Close()

	header := http.Header{}
	header.Set("Authorization", "Bearer "+token)
	conn, _, err := websocket.DefaultDialer.Dial("ws"+server.URL[len("http"):], header)
	if err != nil {
		t.Fatalf("dial authenticated WebSocket: %v", err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var welcome map[string]any
	if err := conn.ReadJSON(&welcome); err != nil {
		t.Fatalf("read welcome: %v", err)
	}
	status := map[string]any{
		"mihomo_version": "v1.19.3",
		"mihomo_healthy": true,
		"upload_total":   float64(12),
		"download_total": float64(34),
		"upload_speed":   float64(1),
		"download_speed": float64(2),
		"connections":    "many",
		"config_sha256":  strings.Repeat("a", 64),
		"last_error":     "",
	}
	if err := conn.WriteJSON(map[string]any{"type": "heartbeat", "id": "hb-invalid", "status": status}); err != nil {
		t.Fatalf("send invalid heartbeat: %v", err)
	}
	var response map[string]any
	if err := conn.ReadJSON(&response); err != nil {
		t.Fatalf("read validation response: %v", err)
	}
	if response["type"] != "error" || response["id"] != "hb-invalid" {
		t.Fatalf("unexpected validation response: %#v", response)
	}
	settings, err := app.store.GetSettings()
	if err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	if settings["agent_status_"+code] != "" || settings["agent_lastseen_"+code] != "" {
		t.Fatal("invalid heartbeat must not be persisted")
	}
}
