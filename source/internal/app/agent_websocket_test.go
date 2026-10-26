package app

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
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
		"agent_token": "global-secret",
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
		"upload_total": 12,
		"download_total": 34,
		"upload_speed": 1,
		"download_speed": 2,
		"connections": 3,
		"config_sha256": "abc",
		"last_error": "",
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
