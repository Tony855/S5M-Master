package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestAgentInstanceNewWebSocketSupersedesOldSessionBeforeCommandAck(t *testing.T) {
	app, machineCode, _ := websocketTestApp(t)
	const agentType = "mihomo"
	const instanceID = "default"
	const secret = "instance-session-replacement-secret-123456"
	if err := app.store.ProvisionAgentInstance(machineCode, agentType, instanceID, secret); err != nil {
		t.Fatalf("provision Agent instance: %v", err)
	}
	token := registerInstanceWebSocketTestToken(t, app, machineCode, agentType, instanceID, secret)

	const commandID = "session-replacement-command"
	command := json.RawMessage(`{"id":"session-replacement-command","type":"update_mihomo","version":"v1.2.3","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}`)
	if err := app.store.QueueAgentInstanceCommand(machineCode, agentType, instanceID, commandID, command); err != nil {
		t.Fatalf("queue Agent instance command: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(app.handleAgentWebSocket))
	defer server.Close()

	oldConn := dialInstanceWebSocketTest(t, server.URL, token)
	newConn := dialInstanceWebSocketTest(t, server.URL, token)
	defer newConn.Close()

	// The server must actively close the superseded socket, not leave it alive
	// until its next heartbeat or command poll.
	_ = oldConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _, err := oldConn.ReadMessage()
	if err == nil {
		_ = oldConn.Close()
		t.Fatal("superseded Agent WebSocket remained readable")
	}
	if closeErr, ok := err.(*websocket.CloseError); ok && closeErr.Code != websocket.CloseNormalClosure {
		t.Fatalf("superseded socket closed with unexpected code: %#v", closeErr)
	}
	_ = oldConn.Close()

	// The replacement connection retains command ownership and can complete
	// the pending operation; the stale connection cannot consume its ACK.
	requestInstanceCommand(t, newConn, "poll-on-replacement", commandID)
	if err := newConn.WriteJSON(map[string]any{
		"type": "command.ack", "id": commandID,
		"command_status": "success", "message": "replacement-session-complete",
	}); err != nil {
		t.Fatalf("ACK from replacement session: %v", err)
	}
	var ack map[string]any
	if err := newConn.ReadJSON(&ack); err != nil {
		t.Fatalf("read replacement session ACK confirmation: %v", err)
	}
	if ack["type"] != "command.acknowledged" || ack["id"] != commandID || ack["ok"] != true {
		t.Fatalf("replacement session ACK not accepted: %#v", ack)
	}

	latest, err := app.store.GetLatestAgentInstanceCommand(machineCode, agentType, instanceID)
	if err != nil {
		t.Fatalf("read latest command result: %v", err)
	}
	if latest == nil || latest.CommandID != commandID || latest.Status != "success" || latest.Result != "replacement-session-complete" {
		t.Fatalf("replacement session did not persist expected ACK: %#v", latest)
	}
}
