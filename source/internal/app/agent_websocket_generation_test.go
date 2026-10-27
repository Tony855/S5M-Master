package app

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// TestAgentWebSocketSupersededConnectionCannotOperate ensures reconnecting the
// same Agent invalidates the previous socket for all runtime operations.
func TestAgentWebSocketSupersededConnectionCannotOperate(t *testing.T) {
	tests := []struct {
		name    string
		message map[string]any
	}{
		{name: "command polling", message: map[string]any{"type": "command.request", "id": "old-command"}},
		{name: "configuration sync", message: map[string]any{"type": "config.request", "id": "old-config"}},
		{name: "heartbeat", message: map[string]any{"type": "heartbeat", "id": "old-heartbeat", "status": map[string]any{}}},
		{name: "command acknowledgement", message: map[string]any{"type": "command.ack", "id": "old-ack", "command_status": "success"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app, _, token := websocketTestApp(t)
			server := httptest.NewServer(http.HandlerFunc(app.handleAgentWebSocket))
			defer server.Close()

			header := http.Header{}
			header.Set("Authorization", "Bearer "+token)
			wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
			oldConn, _, err := websocket.DefaultDialer.Dial(wsURL, header)
			if err != nil {
				t.Fatalf("dial first WebSocket: %v", err)
			}
			defer oldConn.Close()
			_ = oldConn.SetReadDeadline(time.Now().Add(2 * time.Second))
			var welcome map[string]any
			if err := oldConn.ReadJSON(&welcome); err != nil {
				t.Fatalf("read first welcome: %v", err)
			}

			newConn, _, err := websocket.DefaultDialer.Dial(wsURL, header)
			if err != nil {
				t.Fatalf("dial replacement WebSocket: %v", err)
			}
			defer newConn.Close()
			_ = newConn.SetReadDeadline(time.Now().Add(2 * time.Second))
			if err := newConn.ReadJSON(&welcome); err != nil {
				t.Fatalf("read replacement welcome: %v", err)
			}

			if err := oldConn.WriteJSON(tt.message); err != nil {
				t.Fatalf("send operation through superseded socket: %v", err)
			}
			var response map[string]any
			if err := oldConn.ReadJSON(&response); err != nil {
				t.Fatalf("read superseded socket response: %v", err)
			}
			message, _ := response["message"].(string)
			if response["type"] != "error" || !strings.Contains(message, "被更新连接取代") {
				t.Fatalf("superseded socket response = %#v, want replacement-connection error", response)
			}
		})
	}
}
