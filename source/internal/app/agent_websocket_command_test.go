package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func dialAgentWebSocketForCommandTest(t *testing.T, app *App, token string) (*websocket.Conn, func()) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(app.handleAgentWebSocket))
	header := http.Header{}
	header.Set("Authorization", "Bearer "+token)
	conn, response, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), header)
	if err != nil {
		server.Close()
		t.Fatalf("dial authenticated WebSocket: err=%v response=%v", err, response)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var welcome map[string]any
	if err := conn.ReadJSON(&welcome); err != nil {
		conn.Close()
		server.Close()
		t.Fatalf("read welcome: %v", err)
	}
	if welcome["type"] != "welcome" {
		conn.Close()
		server.Close()
		t.Fatalf("welcome type = %#v", welcome["type"])
	}
	return conn, func() {
		_ = conn.Close()
		server.Close()
	}
}

func TestAgentWebSocketDeliversPendingCommandAndPersistsAck(t *testing.T) {
	app, code, token := websocketTestApp(t)
	const command = `{"id":"ws-cmd-200","type":"update_mihomo","version":"v1.2.3"}`
	if err := app.store.UpdateSettings(map[string]string{
		"agent_command_" + code: command,
	}); err != nil {
		t.Fatalf("seed pending command: %v", err)
	}
	conn, cleanup := dialAgentWebSocketForCommandTest(t, app, token)
	defer cleanup()

	if err := conn.WriteJSON(map[string]any{"type": "command.request", "id": "poll-200"}); err != nil {
		t.Fatalf("request command: %v", err)
	}
	var delivered map[string]any
	if err := conn.ReadJSON(&delivered); err != nil {
		t.Fatalf("read command delivery: %v", err)
	}
	if delivered["type"] != "command.deliver" || delivered["id"] != "poll-200" {
		t.Fatalf("unexpected delivery envelope: %#v", delivered)
	}
	commandBody, ok := delivered["command"].(map[string]any)
	if !ok || commandBody["id"] != "ws-cmd-200" || commandBody["type"] != "update_mihomo" {
		t.Fatalf("unexpected delivered command: %#v", delivered["command"])
	}

	if err := conn.WriteJSON(map[string]any{
		"type": "command.ack", "id": "ws-cmd-200",
		"command_status": "success", "message": "updated",
	}); err != nil {
		t.Fatalf("send command ACK: %v", err)
	}
	var ack map[string]any
	if err := conn.ReadJSON(&ack); err != nil {
		t.Fatalf("read command ACK confirmation: %v", err)
	}
	if ack["type"] != "command.acknowledged" || ack["id"] != "ws-cmd-200" || ack["ok"] != true {
		t.Fatalf("unexpected ACK confirmation: %#v", ack)
	}

	settings, err := app.store.GetSettings()
	if err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	if settings["agent_command_"+code] != "" {
		t.Fatalf("pending command remains after ACK: %q", settings["agent_command_"+code])
	}
	var result map[string]any
	if err := json.Unmarshal([]byte(settings["agent_command_result_"+code]), &result); err != nil {
		t.Fatalf("decode persisted command result: %v", err)
	}
	if result["id"] != "ws-cmd-200" || result["type"] != "update_mihomo" ||
		result["status"] != "success" || result["message"] != "updated" {
		t.Fatalf("unexpected persisted command result: %#v", result)
	}
}

func TestAgentWebSocketRejectsMismatchedCommandAckAndKeepsPendingCommand(t *testing.T) {
	app, code, token := websocketTestApp(t)
	const pending = `{"id":"ws-cmd-201","type":"update_mihomo","version":"v1.2.3"}`
	if err := app.store.UpdateSettings(map[string]string{
		"agent_command_" + code: pending,
	}); err != nil {
		t.Fatalf("seed pending command: %v", err)
	}
	conn, cleanup := dialAgentWebSocketForCommandTest(t, app, token)
	defer cleanup()

	if err := conn.WriteJSON(map[string]any{
		"type": "command.ack", "id": "not-current",
		"command_status": "success", "message": "should not be accepted",
	}); err != nil {
		t.Fatalf("send mismatched ACK: %v", err)
	}
	var response map[string]any
	if err := conn.ReadJSON(&response); err != nil {
		t.Fatalf("read mismatched ACK response: %v", err)
	}
	if response["type"] != "error" {
		t.Fatalf("mismatched ACK response = %#v, want error", response)
	}
	settings, err := app.store.GetSettings()
	if err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	if settings["agent_command_"+code] != pending {
		t.Fatalf("mismatched ACK mutated pending command: %q", settings["agent_command_"+code])
	}
	if settings["agent_command_result_"+code] != "" {
		t.Fatalf("mismatched ACK created a result: %q", settings["agent_command_result_"+code])
	}
}

func TestAgentWebSocketDuplicateCommandAckIsIdempotent(t *testing.T) {
	app, code, token := websocketTestApp(t)
	if err := app.store.UpdateSettings(map[string]string{
		"agent_command_result_" + code: `{"id":"ws-cmd-202","type":"update_mihomo","status":"success"}`,
	}); err != nil {
		t.Fatalf("seed prior result: %v", err)
	}
	conn, cleanup := dialAgentWebSocketForCommandTest(t, app, token)
	defer cleanup()

	if err := conn.WriteJSON(map[string]any{
		"type": "command.ack", "id": "ws-cmd-202",
		"command_status": "success", "message": "retry",
	}); err != nil {
		t.Fatalf("send duplicate ACK: %v", err)
	}
	var response map[string]any
	if err := conn.ReadJSON(&response); err != nil {
		t.Fatalf("read duplicate ACK response: %v", err)
	}
	if response["type"] != "command.acknowledged" || response["id"] != "ws-cmd-202" || response["ok"] != true {
		t.Fatalf("duplicate ACK response = %#v", response)
	}
	settings, err := app.store.GetSettings()
	if err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	if settings["agent_command_result_"+code] != `{"id":"ws-cmd-202","type":"update_mihomo","status":"success"}` {
		t.Fatalf("duplicate ACK mutated prior result: %q", settings["agent_command_result_"+code])
	}
}
