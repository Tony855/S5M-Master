package app

import (
	"crypto/sha256"
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
	Type          string         `json:"type"`
	ID            string         `json:"id,omitempty"`
	Status        map[string]any `json:"status,omitempty"`
	ConfigHash    string         `json:"config_sha256,omitempty"`
	CommandStatus string         `json:"command_status,omitempty"`
	Message       string         `json:"message,omitempty"`
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
	// Serialize generation changes only with operations for this Agent. Other
	// Agents remain independent and are not blocked by a slow config/store call.
	operationMu := a.agentWSOperationLock(machineCode)
	operationMu.Lock()
	a.agentWSMu.Lock()
	if a.agentWSGeneration == nil {
		a.agentWSGeneration = make(map[string]uint64)
	}
	a.agentWSGeneration[machineCode]++
	generation := a.agentWSGeneration[machineCode]
	a.agentWSMu.Unlock()
	operationMu.Unlock()
	// Keep the generation counter after disconnect. Deleting it would let a
	// later reconnect reuse generation 1 and accidentally re-authorize an old
	// still-open socket (an ABA problem).

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
		// Authorization can be revoked after the handshake. Revalidate the
		// original bearer token before every operation, not only before heartbeats.
		currentMachineCode, authErr := a.agentMachineFromRequest(r)
		if authErr != nil || currentMachineCode != machineCode {
			_ = conn.WriteJSON(map[string]string{
				"type": "error", "id": msg.ID, "message": "Agent 授权已失效，请重新注册",
			})
			return
		}
		// A reconnect supersedes the previous socket for every operation, not
		// only heartbeat writes. Otherwise an old socket could still poll
		// commands, fetch config, or acknowledge a command after replacement.
		a.agentWSMu.Lock()
		isCurrentGeneration := a.agentWSGeneration[machineCode] == generation
		a.agentWSMu.Unlock()
		if !isCurrentGeneration {
			_ = conn.WriteJSON(map[string]string{
				"type": "error", "id": msg.ID, "message": "Agent WebSocket 连接已被更新连接取代",
			})
			return
		}
		// Serialize non-heartbeat operations with connection replacement. The
		// generation check and the operation's side effects must share one lock;
		// checking then unlocking here would leave a TOCTOU window.
		if msg.Type == "config.request" || msg.Type == "command.request" || msg.Type == "command.ack" {
			operationMu.Lock()
			a.agentWSMu.Lock()
			isCurrentGeneration = a.agentWSGeneration[machineCode] == generation
			a.agentWSMu.Unlock()
			if !isCurrentGeneration {
				operationMu.Unlock()
				_ = conn.WriteJSON(map[string]string{
					"type": "error", "id": msg.ID, "message": "Agent WebSocket 连接已被更新连接取代",
				})
				return
			}
			switch msg.Type {
			case "config.request":
				if err := a.sendAgentWSConfig(conn, machineCode, msg.ID, msg.ConfigHash); err != nil {
					operationMu.Unlock()
					_ = conn.WriteJSON(map[string]string{"type": "error", "id": msg.ID, "message": "读取节点配置失败"})
					continue
				}
			case "command.request":
				if err := a.sendAgentWSCommand(conn, machineCode, msg.ID); err != nil {
					operationMu.Unlock()
					_ = conn.WriteJSON(map[string]string{"type": "error", "id": msg.ID, "message": "读取待执行命令失败"})
					continue
				}
			case "command.ack":
				if err := a.ackAgentWSCommand(machineCode, msg.ID, msg.CommandStatus, msg.Message); err != nil {
					operationMu.Unlock()
					_ = conn.WriteJSON(map[string]string{"type": "error", "id": msg.ID, "message": err.Error()})
					continue
				}
				if err := conn.WriteJSON(map[string]any{"type": "command.acknowledged", "id": msg.ID, "ok": true}); err != nil {
					operationMu.Unlock()
					return
				}
			}
			operationMu.Unlock()
			continue
		}
		if msg.Type != "heartbeat" || msg.Status == nil {
			_ = conn.WriteJSON(map[string]string{"type": "error", "id": msg.ID, "message": "不支持的 WebSocket 消息类型"})
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
		receivedAt := time.Now()
		msg.Status["received_at"] = receivedAt.Unix()
		payload, marshalErr := json.Marshal(msg.Status)
		if marshalErr != nil {
			return
		}
		now := strconv.FormatInt(receivedAt.Unix(), 10)
		// Heartbeats use the same per-Agent operation lock as reconnects. This
		// prevents a superseded socket from committing telemetry without holding
		// the global generation mutex during a database write.
		operationMu.Lock()
		a.agentWSMu.Lock()
		isCurrentGeneration = a.agentWSGeneration[machineCode] == generation
		if a.agentHeartbeatAt == nil {
			a.agentHeartbeatAt = make(map[string]int64)
		}
		isNewerHeartbeat := receivedAt.UnixNano() >= a.agentHeartbeatAt[machineCode]
		a.agentWSMu.Unlock()
		if !isCurrentGeneration {
			operationMu.Unlock()
			_ = conn.WriteJSON(map[string]string{
				"type":    "error",
				"id":      msg.ID,
				"message": "Agent WebSocket 连接已被更新连接取代",
			})
			return
		}
		if !isNewerHeartbeat {
			operationMu.Unlock()
			_ = conn.WriteJSON(map[string]string{
				"type":    "error",
				"id":      msg.ID,
				"message": "已忽略较旧的 Agent 心跳",
			})
			continue
		}
		if err := a.store.UpdateSettings(map[string]string{
			"agent_lastseen_" + machineCode: now,
			"agent_status_" + machineCode:   string(payload),
		}); err != nil {
			operationMu.Unlock()
			_ = conn.WriteJSON(map[string]string{
				"type":    "error",
				"id":      msg.ID,
				"message": "保存 Agent 心跳失败",
			})
			continue
		}
		a.agentWSMu.Lock()
		a.agentHeartbeatAt[machineCode] = receivedAt.UnixNano()
		a.agentWSMu.Unlock()
		operationMu.Unlock()
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

// sendAgentWSConfig returns only the configuration assigned to the authenticated machine.
func (a *App) sendAgentWSConfig(conn *websocket.Conn, machineCode, requestID, clientHash string) error {
	nodeConfig, err := a.store.GetNodeConfig(machineCode)
	if err != nil {
		return err
	}
	yml := ""
	if nodeConfig != nil {
		yml = strings.TrimSpace(nodeConfig.YAML)
	}
	if yml == "" {
		yml, err = a.BuildConfigForMachine(machineCode)
		if err != nil {
			return err
		}
		if err := a.store.SaveNodeConfig(machineCode, yml); err != nil {
			return err
		}
	}
	sum := sha256.Sum256([]byte(yml))
	hash := hex.EncodeToString(sum[:])
	if err := a.store.UpdateSettings(map[string]string{"agent_lastseen_" + machineCode: strconv.FormatInt(time.Now().Unix(), 10)}); err != nil {
		return err
	}
	if clientHash == hash {
		return conn.WriteJSON(map[string]any{"type": "config.unchanged", "id": requestID, "sha256": hash})
	}
	return conn.WriteJSON(map[string]any{"type": "config.sync", "id": requestID, "sha256": hash, "yaml": yml})
}

// sendAgentWSCommand redelivers the persisted pending command until an ACK is stored.
func (a *App) sendAgentWSCommand(conn *websocket.Conn, machineCode, requestID string) error {
	settings, err := a.store.GetSettings()
	if err != nil {
		return err
	}
	raw := strings.TrimSpace(settings["agent_command_"+machineCode])
	if raw == "" {
		return conn.WriteJSON(map[string]any{"type": "command.none", "id": requestID})
	}
	var command map[string]any
	if err := json.Unmarshal([]byte(raw), &command); err != nil {
		return fmt.Errorf("解析待执行命令失败: %w", err)
	}
	return conn.WriteJSON(map[string]any{"type": "command.deliver", "id": requestID, "command": command})
}

// ackAgentWSCommand persists an ACK only for the currently pending command.
// Duplicate ACKs are accepted only when the prior result has the same command ID.
func (a *App) ackAgentWSCommand(machineCode, commandID, status, message string) error {
	if strings.TrimSpace(commandID) == "" || (status != "success" && status != "failed") || len(message) > 2048 {
		return fmt.Errorf("命令 ID、状态或结果消息无效")
	}
	settings, err := a.store.GetSettings()
	if err != nil {
		return fmt.Errorf("读取待执行命令失败: %w", err)
	}
	var pending map[string]string
	if json.Unmarshal([]byte(settings["agent_command_"+machineCode]), &pending) != nil || pending["id"] != commandID {
		var previous map[string]any
		if json.Unmarshal([]byte(settings["agent_command_result_"+machineCode]), &previous) == nil && previous["id"] == commandID {
			return nil
		}
		return fmt.Errorf("命令已被替换或不存在")
	}
	result, err := json.Marshal(map[string]any{"id": commandID, "type": pending["type"], "status": status, "message": message, "updated_at": time.Now().Unix()})
	if err != nil {
		return fmt.Errorf("编码命令结果失败: %w", err)
	}
	// Commit the result and remove the pending command in one SQLite transaction.
	// Otherwise a failed delete could leave a completed command queued for rerun.
	if err := a.store.CompleteAgentCommand(machineCode, commandID, string(result)); err != nil {
		return fmt.Errorf("原子确认 Agent 命令失败: %w", err)
	}
	return nil
}
