package app

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

const (
	agentWSMaxMessageBytes = 16 << 10
	agentWSHeartbeatTTL    = 75 * time.Second
	agentWSMaxVersionBytes = 128
	agentWSMaxErrorBytes   = 2048
)

var agentWSUpgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	// Agent clients do not need browser Origin headers. Reject browser-originated
	// connections rather than accepting arbitrary cross-site WebSocket requests.
	CheckOrigin: func(r *http.Request) bool {
		return strings.TrimSpace(r.Header.Get("Origin")) == ""
	},
}

type agentWSMessage struct {
	Type   string         `json:"type"`
	ID     string         `json:"id,omitempty"`
	Status map[string]any `json:"status,omitempty"`
}

// validateAgentWSStatus rejects malformed telemetry before it reaches persistent
// node status. JSON numbers decode as float64, so integer counters are bounded
// to the exact-integer range supported by float64.
func validateAgentWSStatus(status map[string]any) error {
	required := []string{
		"mihomo_version", "mihomo_healthy", "upload_total",
		"download_total", "upload_speed", "download_speed",
		"connections", "config_sha256", "last_error",
	}
	for _, key := range required {
		if _, ok := status[key]; !ok {
			return fmt.Errorf("心跳缺少必需字段: %s", key)
		}
	}

	version, ok := status["mihomo_version"].(string)
	if !ok || len(version) > agentWSMaxVersionBytes {
		return fmt.Errorf("mihomo_version 必须是长度不超过 %d 字节的字符串", agentWSMaxVersionBytes)
	}
	if healthy, ok := status["mihomo_healthy"].(bool); !ok {
		return fmt.Errorf("mihomo_healthy 必须是布尔值")
	} else if healthy && strings.TrimSpace(version) == "" {
		return fmt.Errorf("mihomo_healthy 为 true 时 mihomo_version 不能为空")
	}

	for _, key := range []string{"upload_total", "download_total", "upload_speed", "download_speed"} {
		value, ok := status[key].(float64)
		if !ok || math.IsNaN(value) || math.IsInf(value, 0) || value < 0 || value > 9.0e15 {
			return fmt.Errorf("%s 必须是有限的非负数且不超过 9e15", key)
		}
		if strings.HasSuffix(key, "_total") && math.Trunc(value) != value {
			return fmt.Errorf("%s 必须是整数", key)
		}
	}
	connections, ok := status["connections"].(float64)
	if !ok || math.IsNaN(connections) || math.IsInf(connections, 0) ||
		connections < 0 || connections > 9.0e15 || math.Trunc(connections) != connections {
		return fmt.Errorf("connections 必须是有限的非负整数且不超过 9e15")
	}

	configHash, ok := status["config_sha256"].(string)
	if !ok {
		return fmt.Errorf("config_sha256 必须是字符串")
	}
	if configHash != "" {
		decoded, err := hex.DecodeString(configHash)
		if err != nil || len(decoded) != 32 {
			return fmt.Errorf("config_sha256 必须为空或 64 位十六进制 SHA-256")
		}
	}
	lastError, ok := status["last_error"].(string)
	if !ok || len(lastError) > agentWSMaxErrorBytes {
		return fmt.Errorf("last_error 必须是长度不超过 %d 字节的字符串", agentWSMaxErrorBytes)
	}
	return nil
}

func (a *App) handleAgentWebSocket(w http.ResponseWriter, r *http.Request) {
	machineCode, err := a.agentMachineFromRequest(r)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, err.Error())
		return
	}

	conn, err := agentWSUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return // The upgrader has already written the HTTP error response.
	}
	defer conn.Close()

	// A newly authenticated connection supersedes any older connection for the
	// same Agent. Older sockets may still be blocked in ReadJSON, so every
	// heartbeat must verify its generation before it can mutate persisted state.
	a.agentWSMu.Lock()
	if a.agentWSGeneration == nil {
		a.agentWSGeneration = make(map[string]uint64)
	}
	a.agentWSGeneration[machineCode]++
	generation := a.agentWSGeneration[machineCode]
	a.agentWSMu.Unlock()
	defer func() {
		a.agentWSMu.Lock()
		if a.agentWSGeneration[machineCode] == generation {
			delete(a.agentWSGeneration, machineCode)
		}
		a.agentWSMu.Unlock()
	}()

	conn.SetReadLimit(agentWSMaxMessageBytes)
	_ = conn.SetReadDeadline(time.Now().Add(agentWSHeartbeatTTL))
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(agentWSHeartbeatTTL))
	})

	if err := conn.WriteJSON(map[string]any{
		"type":                   "welcome",
		"protocol":               1,
		"heartbeat_interval_sec": 30,
	}); err != nil {
		return
	}

	for {
		var msg agentWSMessage
		if err := conn.ReadJSON(&msg); err != nil {
			return
		}
		if msg.Type != "heartbeat" || msg.Status == nil {
			_ = conn.WriteJSON(map[string]string{
				"type":    "error",
				"message": "当前 WebSocket 阶段仅接受 heartbeat 消息",
			})
			continue
		}
		if err := validateAgentWSStatus(msg.Status); err != nil {
			_ = conn.WriteJSON(map[string]string{
				"type":    "error",
				"id":      msg.ID,
				"message": err.Error(),
			})
			continue
		}
		msg.Status["received_at"] = time.Now().Unix()
		payload, marshalErr := json.Marshal(msg.Status)
		if marshalErr != nil {
			return
		}
		now := strconv.FormatInt(time.Now().Unix(), 10)
		a.agentWSMu.Lock()
		if a.agentWSGeneration[machineCode] != generation {
			a.agentWSMu.Unlock()
			_ = conn.WriteJSON(map[string]string{
				"type":    "error",
				"id":      msg.ID,
				"message": "Agent WebSocket 连接已被更新连接取代",
			})
			return
		}
		if err := a.store.UpdateSettings(map[string]string{
			"agent_lastseen_" + machineCode: now,
			"agent_status_" + machineCode:   string(payload),
		}); err != nil {
			a.agentWSMu.Unlock()
			_ = conn.WriteJSON(map[string]string{
				"type":    "error",
				"id":      msg.ID,
				"message": "保存 Agent 心跳失败",
			})
			continue
		}
		a.agentWSMu.Unlock()
		_ = conn.SetReadDeadline(time.Now().Add(agentWSHeartbeatTTL))
		if err := conn.WriteJSON(map[string]any{
			"type": "heartbeat.ack",
			"id":   msg.ID,
			"ok":   true,
		}); err != nil {
			return
		}
	}
}
