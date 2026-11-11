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

func registerInstanceWebSocketTestToken(t *testing.T, app *App, machineCode, agentType, instanceID, secret string) string {
	t.Helper()
	body, err := json.Marshal(map[string]string{
		"machine_code": machineCode,
		"agent_type":   agentType,
		"instance_id":  instanceID,
		"secret":       secret,
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/register", strings.NewReader(string(body)))
	req.RemoteAddr = "198.51.100.20:1234"
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	app.handleAgentRegister(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("register instance status=%d body=%s", rec.Code, rec.Body.String())
	}
	var response struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil || response.Token == "" {
		t.Fatalf("decode instance token=%q err=%v", response.Token, err)
	}
	return response.Token
}

func dialInstanceWebSocketTest(t *testing.T, serverURL, token string) *websocket.Conn {
	t.Helper()
	header := http.Header{}
	header.Set("Authorization", "Bearer "+token)
	conn, response, err := websocket.DefaultDialer.Dial("ws"+serverURL[len("http"):], header)
	if err != nil {
		if response != nil {
			t.Fatalf("dial instance WebSocket: %v (HTTP %d)", err, response.StatusCode)
		}
		t.Fatalf("dial instance WebSocket: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var welcome map[string]any
	if err := conn.ReadJSON(&welcome); err != nil {
		_ = conn.Close()
		t.Fatalf("read instance welcome: %v", err)
	}
	if welcome["type"] != "welcome" || welcome["protocol"] != float64(1) {
		_ = conn.Close()
		t.Fatalf("unexpected instance welcome: %#v", welcome)
	}
	return conn
}

func requestInstanceCommand(t *testing.T, conn *websocket.Conn, requestID, wantCommandID string) {
	t.Helper()
	if err := conn.WriteJSON(map[string]any{"type": "command.request", "id": requestID}); err != nil {
		t.Fatalf("request pending instance command: %v", err)
	}
	var delivered map[string]any
	if err := conn.ReadJSON(&delivered); err != nil {
		t.Fatalf("read pending instance command: %v", err)
	}
	command, ok := delivered["command"].(map[string]any)
	if delivered["type"] != "command.deliver" || delivered["id"] != requestID ||
		!ok || command["id"] != wantCommandID {
		t.Fatalf("unexpected redelivered instance command: %#v", delivered)
	}
}

func TestAgentInstanceCommandRedeliversAfterDisconnectAndAcceptsAckReplay(t *testing.T) {
	app, machineCode, _ := websocketTestApp(t)
	const agentType = "mihomo"
	const instanceID = "default"
	const secret = "instance-reconnect-secret-123456789"
	if err := app.store.ProvisionAgentInstance(machineCode, agentType, instanceID, secret); err != nil {
		t.Fatalf("provision Agent instance: %v", err)
	}
	token := registerInstanceWebSocketTestToken(t, app, machineCode, agentType, instanceID, secret)

	const commandID = "reconnect-command-1"
	command := json.RawMessage(`{"id":"reconnect-command-1","type":"update_mihomo","version":"v1.2.3","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`)
	if err := app.store.QueueAgentInstanceCommand(machineCode, agentType, instanceID, commandID, command); err != nil {
		t.Fatalf("queue Agent instance command: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(app.handleAgentWebSocket))
	defer server.Close()

	// The first connection receives the command and disconnects before ACK.
	first := dialInstanceWebSocketTest(t, server.URL, token)
	requestInstanceCommand(t, first, "poll-before-disconnect", commandID)
	if err := first.Close(); err != nil {
		t.Fatalf("close first Agent connection: %v", err)
	}

	// A fresh authenticated connection must receive the same durable command.
	second := dialInstanceWebSocketTest(t, server.URL, token)
	requestInstanceCommand(t, second, "poll-after-reconnect", commandID)

	// Persist the ACK, then close without reading command.acknowledged to model
	// a lost ACK response. The controller must tolerate the Agent replaying it.
	if err := second.WriteJSON(map[string]any{
		"type": "command.ack", "id": commandID,
		"command_status": "success", "message": "installed",
	}); err != nil {
		t.Fatalf("send first command ACK: %v", err)
	}
	_ = second.Close()

	deadline := time.Now().Add(2 * time.Second)
	for {
		latest, err := app.store.GetLatestAgentInstanceCommand(machineCode, agentType, instanceID)
		if err != nil {
			t.Fatalf("read persisted command result: %v", err)
		}
		if latest != nil && latest.CommandID == commandID && latest.Status == "success" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("first ACK was not durably committed before timeout: %#v", latest)
		}
		time.Sleep(10 * time.Millisecond)
	}

	third := dialInstanceWebSocketTest(t, server.URL, token)
	defer third.Close()
	if err := third.WriteJSON(map[string]any{
		"type": "command.ack", "id": commandID,
		"command_status": "success", "message": "installed",
	}); err != nil {
		t.Fatalf("replay command ACK after reconnect: %v", err)
	}
	var confirmation map[string]any
	if err := third.ReadJSON(&confirmation); err != nil {
		t.Fatalf("read replayed ACK confirmation: %v", err)
	}
	if confirmation["type"] != "command.acknowledged" ||
		confirmation["id"] != commandID || confirmation["ok"] != true {
		t.Fatalf("exact duplicate ACK was not accepted: %#v", confirmation)
	}

	pending, err := app.store.GetPendingAgentInstanceCommand(machineCode, agentType, instanceID)
	if err != nil {
		t.Fatalf("read pending command after ACK replay: %v", err)
	}
	if pending != nil {
		t.Fatalf("acknowledged command remains pending: %#v", pending)
	}
	latest, err := app.store.GetLatestAgentInstanceCommand(machineCode, agentType, instanceID)
	if err != nil {
		t.Fatalf("read final command result: %v", err)
	}
	if latest == nil || latest.CommandID != commandID || latest.Status != "success" || latest.Result != "installed" {
		t.Fatalf("final command result changed after ACK replay: %#v", latest)
	}
}
