package app

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// TestAgentWebSocketRevocationBlocksOperations verifies that an established
// socket cannot perform any runtime operation after its authorization is revoked.
func TestAgentWebSocketRevocationBlocksOperations(t *testing.T) {
	tests := []struct {
		name    string
		message map[string]any
	}{
		{name: "command polling", message: map[string]any{"type": "command.request", "id": "revoked-command"}},
		{name: "configuration sync", message: map[string]any{"type": "config.request", "id": "revoked-config"}},
		{name: "heartbeat", message: map[string]any{"type": "heartbeat", "id": "revoked-heartbeat", "status": map[string]any{}}},
		{name: "command acknowledgement", message: map[string]any{"type": "command.ack", "id": "revoked-ack", "command_status": "success"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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

			revokeReq := httptest.NewRequest(http.MethodDelete, "/api/v1/agents?code="+code, nil)
			revokeRec := httptest.NewRecorder()
			app.handleDeleteAgent(revokeRec, revokeReq)
			if revokeRec.Code != http.StatusOK {
				t.Fatalf("revoke status = %d, want 200; body=%s", revokeRec.Code, revokeRec.Body.String())
			}

			if err := conn.WriteJSON(tt.message); err != nil {
				t.Fatalf("send message after revocation: %v", err)
			}
			var response map[string]any
			if err := conn.ReadJSON(&response); err != nil {
				t.Fatalf("read revoked socket response: %v", err)
			}
			message, _ := response["message"].(string)
			if response["type"] != "error" || !strings.Contains(message, "授权已失效") {
				t.Fatalf("revoked socket response = %#v, want authorization error", response)
			}
		})
	}
}
