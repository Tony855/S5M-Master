package app

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

const (
	agentWSMaxMessageBytes = 16 << 10
	agentWSHeartbeatTTL    = 75 * time.Second
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
		for _, key := range []string{
			"mihomo_version", "mihomo_healthy", "upload_total",
			"download_total", "upload_speed", "download_speed",
			"connections", "config_sha256", "last_error",
		} {
			if _, ok := msg.Status[key]; !ok {
				_ = conn.WriteJSON(map[string]string{
					"type":    "error",
					"id":      msg.ID,
					"message": "心跳缺少必需字段: " + key,
				})
				continue
			}
		}
		msg.Status["received_at"] = time.Now().Unix()
		payload, marshalErr := json.Marshal(msg.Status)
		if marshalErr != nil {
			return
		}
		now := strconv.FormatInt(time.Now().Unix(), 10)
		if err := a.store.UpdateSettings(map[string]string{
			"agent_lastseen_" + machineCode: now,
			"agent_status_" + machineCode:   string(payload),
		}); err != nil {
			_ = conn.WriteJSON(map[string]string{
				"type":    "error",
				"id":      msg.ID,
				"message": "保存 Agent 心跳失败",
			})
			continue
		}
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
