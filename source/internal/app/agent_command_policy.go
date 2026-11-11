package app

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// validateAgentInstanceCommandPayload accepts only the command currently implemented by the Mihomo Agent.
// WireGuard remote commands remain disabled until its Agent runtime implements a matching dispatcher.
func validateAgentInstanceCommandPayload(agentType, commandID string, raw json.RawMessage) error {
	if agentType != "mihomo" {
		return fmt.Errorf("当前 Agent 类型暂不支持远程命令")
	}
	var payload struct {
		ID string `json:"id"`
		Type string `json:"type"`
		Version string `json:"version"`
		SHA256 string `json:"sha256"`
	}
	if len(raw) == 0 || !json.Valid(raw) || json.Unmarshal(raw, &payload) != nil {
		return fmt.Errorf("Agent 命令 JSON 无效")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || len(fields) != 4 {
		return fmt.Errorf("Mihomo 更新命令字段不符合协议")
	}
	for key := range fields {
		if key != "id" && key != "type" && key != "version" && key != "sha256" {
			return fmt.Errorf("Mihomo 更新命令包含不支持的字段")
		}
	}
	if payload.ID != commandID || payload.Type != "update_mihomo" {
		return fmt.Errorf("Mihomo 命令 ID 或类型无效")
	}
	if !regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`).MatchString(strings.TrimSpace(payload.Version)) ||
		!regexp.MustCompile(`^[a-fA-F0-9]{64}$`).MatchString(strings.TrimSpace(payload.SHA256)) {
		return fmt.Errorf("Mihomo 更新版本或 SHA-256 无效")
	}
	return nil
}

// AckAgentInstanceCommandIdempotent accepts an exact duplicate ACK after a lost response.
// Conflicting replays and ACKs for replaced/nonexistent commands remain rejected.
func (s *Store) AckAgentInstanceCommandIdempotent(machineCode, agentType, instanceID, commandID, status, resultMessage string) error {
	if err := validateAgentIdentity(machineCode, agentType, instanceID); err != nil {
		return err
	}
	if !regexp.MustCompile(`^[A-Za-z0-9_-]{1,96}$`).MatchString(commandID) || (status != "success" && status != "failed") || len(resultMessage) > 2048 {
		return fmt.Errorf("Agent 实例命令 ACK 参数无效")
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := s.db.Exec(`UPDATE agent_instance_commands SET status=?, result_message=?, updated_at=?
		WHERE machine_code=? AND agent_type=? AND instance_id=? AND command_id=? AND status='pending'`,
		status, resultMessage, now, machineCode, agentType, instanceID, commandID)
	if err != nil { return err }
	n, err := res.RowsAffected()
	if err != nil { return err }
	if n == 1 { return nil }
	var existingStatus, existingMessage string
	err = s.db.QueryRow(`SELECT status, result_message FROM agent_instance_commands
		WHERE machine_code=? AND agent_type=? AND instance_id=? AND command_id=?`,
		machineCode, agentType, instanceID, commandID).Scan(&existingStatus, &existingMessage)
	if err == nil && existingStatus == status && existingMessage == resultMessage { return nil }
	if err != nil && err != sql.ErrNoRows { return err }
	return sql.ErrNoRows
}
