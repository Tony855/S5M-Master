package app

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)


// TestAgentWebSocketRevocationBlocksCommandPolling verifies an established socket
// cannot keep reading commands after its machine authorization is revoked.
func TestAgentWebSocketRevocationBlocksCommandPolling(t *testing.T) {
	app, code, token := websocketTestApp(t)
	if err := app.store.UpdateSettings(map[string]string{
		"agent_command_" + code: `{"id":"revoked-cmd","type":"update_mihomo"}`,
	}); err != nil {
		t.Fatalf("seed pending command: %v", err)
	}
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

	revokeReq := httptest.NewRequest(http.MethodDelete, "/api/v1/agents?code="+code, nil)
	revokeRec := httptest.NewRecorder()
	app.handleDeleteAgent(revokeRec, revokeReq)
	if revokeRec.Code != http.StatusOK {
		t.Fatalf("revoke status = %d, want 200; body=%s", revokeRec.Code, revokeRec.Body.String())
	}

	if err := conn.WriteJSON(map[string]any{"type": "command.request", "id": "revoked-poll"}); err != nil {
		t.Fatalf("send command request after revocation: %v", err)
	}
	var response map[string]any
	if err := conn.ReadJSON(&response); err != nil {
		t.Fatalf("read revoked socket response: %v", err)
	}
	if response["type"] != "error" || !strings.Contains(response["message"].(string), "授权已失效") {
		t.Fatalf("revoked socket response = %#v, want authorization error", response)
	}
	settings, err := app.store.GetSettings()
	if err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	if settings["agent_command_"+code] == "" {
		t.Fatal("revoked socket should not consume the pending command")
	}
}
