package app

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestAgentInstanceConcurrentWebSocketCommandIsolation(t *testing.T) {
	app, machineCode, _ := websocketTestApp(t)
	count := 24
	if configured := strings.TrimSpace(os.Getenv("S5M_AGENT_WS_LOAD_INSTANCES")); configured != "" {
		parsed, err := strconv.Atoi(configured)
		if err != nil || parsed < 1 || parsed > 500 {
			t.Fatalf("S5M_AGENT_WS_LOAD_INSTANCES must be an integer from 1 to 500, got %q", configured)
		}
		count = parsed
	}
	type fixture struct {
		id, token, commandID string
	}
	fixtures := make([]fixture, count)
	for i := range fixtures {
		id := fmt.Sprintf("parallel-%02d", i)
		secret := fmt.Sprintf("parallel-instance-secret-%02d-0123456789abcdef", i)
		if err := app.store.ProvisionAgentInstance(machineCode, "mihomo", id, secret); err != nil {
			t.Fatalf("provision %s: %v", id, err)
		}
		body, _ := json.Marshal(map[string]string{"machine_code": machineCode, "agent_type": "mihomo", "instance_id": id, "secret": secret})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/register", strings.NewReader(string(body)))
		req.RemoteAddr = fmt.Sprintf("198.18.%d.%d:1234", i/250, i%250+1)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		app.handleAgentRegister(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("register %s status=%d body=%s", id, rec.Code, rec.Body.String())
		}
		var registered struct {
			Token string `json:"token"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &registered); err != nil || registered.Token == "" {
			t.Fatalf("decode %s token: token=%q err=%v", id, registered.Token, err)
		}
		commandID := fmt.Sprintf("parallel-command-%02d", i)
		payload := json.RawMessage(fmt.Sprintf(`{"id":%q,"type":"update_mihomo","version":"v1.2.3","sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}`, commandID))
		if err := app.store.QueueAgentInstanceCommand(machineCode, "mihomo", id, commandID, payload); err != nil {
			t.Fatalf("queue %s: %v", id, err)
		}
		fixtures[i] = fixture{id: id, token: registered.Token, commandID: commandID}
	}

	server := httptest.NewServer(http.HandlerFunc(app.handleAgentWebSocket))
	defer server.Close()
	var wg sync.WaitGroup
	errs := make(chan error, count)
	for _, f := range fixtures {
		f := f
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, _, err := websocket.DefaultDialer.Dial("ws"+server.URL[len("http"):], instanceConcurrencyAuthHeader(f.token))
			if err != nil {
				errs <- fmt.Errorf("%s dial: %w", f.id, err)
				return
			}
			defer conn.Close()
			_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
			var welcome map[string]any
			if err := conn.ReadJSON(&welcome); err != nil || welcome["type"] != "welcome" {
				errs <- fmt.Errorf("%s welcome invalid: %#v (%v)", f.id, welcome, err)
				return
			}
			requestID := "poll-" + f.id
			if err := conn.WriteJSON(map[string]any{"type": "command.request", "id": requestID}); err != nil {
				errs <- fmt.Errorf("%s request: %w", f.id, err)
				return
			}
			var delivered map[string]any
			if err := conn.ReadJSON(&delivered); err != nil {
				errs <- fmt.Errorf("%s delivery: %w", f.id, err)
				return
			}
			cmd, ok := delivered["command"].(map[string]any)
			if delivered["type"] != "command.deliver" || delivered["id"] != requestID || !ok || cmd["id"] != f.commandID {
				errs <- fmt.Errorf("%s received another instance command: %#v", f.id, delivered)
				return
			}
			if err := conn.WriteJSON(map[string]any{"type": "command.ack", "id": f.commandID, "command_status": "success", "message": "ok"}); err != nil {
				errs <- fmt.Errorf("%s ack: %w", f.id, err)
				return
			}
			var ack map[string]any
			if err := conn.ReadJSON(&ack); err != nil || ack["type"] != "command.acknowledged" || ack["id"] != f.commandID || ack["ok"] != true {
				errs <- fmt.Errorf("%s ack confirmation invalid: %#v (%v)", f.id, ack, err)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	for _, f := range fixtures {
		pending, err := app.store.GetPendingAgentInstanceCommand(machineCode, "mihomo", f.id)
		if err != nil {
			t.Errorf("%s pending: %v", f.id, err)
		} else if pending != nil {
			t.Errorf("%s still pending: %#v", f.id, pending)
		}
		result, err := app.store.GetLatestAgentInstanceCommand(machineCode, "mihomo", f.id)
		if err != nil {
			t.Errorf("%s result: %v", f.id, err)
		} else if result == nil || result.CommandID != f.commandID || result.Status != "success" {
			t.Errorf("%s result mismatch: %#v", f.id, result)
		}
	}
}

func instanceConcurrencyAuthHeader(token string) http.Header {
	header := http.Header{}
	header.Set("Authorization", "Bearer "+token)
	return header
}
