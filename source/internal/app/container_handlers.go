package app

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func (a *App) handleContainerAgentStatus(w http.ResponseWriter, r *http.Request) {
	code, ok := a.agentMachineCode(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "Agent 身份验证失败")
		return
	}
	var in struct {
		Hostname        string          `json:"hostname"`
		OS              string          `json:"os"`
		Arch            string          `json:"arch"`
		DockerAvailable bool            `json:"docker_available"`
		MihomoRunning   bool            `json:"mihomo_running"`
		MihomoVersion   string          `json:"mihomo_version"`
		Status          json.RawMessage `json:"status_json"`
	}
	if err := decodeLimited(r, 32<<10, "32 KiB", &in); err != nil {
		writeErr(w, decodeErrorStatus(err), "状态数据格式错误")
		return
	}
	if len(in.Hostname) > 255 || len(in.OS) > 100 || len(in.Arch) > 100 || len(in.MihomoVersion) > 255 {
		writeErr(w, http.StatusBadRequest, "状态字段过长")
		return
	}
	status := string(in.Status)
	if len(in.Status) == 0 || !json.Valid(in.Status) {
		status = "{}"
	}
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := a.store.db.Exec(`INSERT INTO agent_status
        (machine_code,hostname,os,arch,docker_available,mihomo_running,mihomo_version,status_json,updated_at)
        VALUES(?,?,?,?,?,?,?,?,?)
        ON CONFLICT(machine_code) DO UPDATE SET hostname=excluded.hostname,os=excluded.os,
        arch=excluded.arch,docker_available=excluded.docker_available,
        mihomo_running=excluded.mihomo_running,mihomo_version=excluded.mihomo_version,
        status_json=excluded.status_json,updated_at=excluded.updated_at`,
		code, in.Hostname, in.OS, in.Arch, in.DockerAvailable, in.MihomoRunning, in.MihomoVersion, status, now)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "保存节点状态失败")
		return
	}
	// Container agents also refresh the shared Agent last-seen timestamp. The
	// RouterOS-only agent does not download Mihomo configuration, so this status
	// endpoint is its authoritative online heartbeat.
	if err := a.store.UpdateSettings(map[string]string{
		"agent_lastseen_" + code: strconv.FormatInt(time.Now().Unix(), 10),
	}); err != nil {
		writeErr(w, http.StatusInternalServerError, "更新 Agent 心跳失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *App) handleQueueRouterOSCommand(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	if u == nil || u.Role != "admin" {
		writeErr(w, http.StatusForbidden, "仅管理员可以操作 RouterOS 容器")
		return
	}
	var in struct {
		MachineCode string `json:"machine_code"`
		Action string `json:"action"`
		ContainerID string `json:"container_id"`
	}
	if err := decodeLimited(r, 8<<10, "8 KiB", &in); err != nil {
		writeErr(w, decodeErrorStatus(err), "请求 JSON 无效")
		return
	}
	in.MachineCode = strings.TrimSpace(in.MachineCode)
	in.Action = strings.TrimSpace(in.Action)
	in.ContainerID = strings.TrimSpace(in.ContainerID)
	if !regexp.MustCompile("^[A-Za-z0-9_-]{1,64}$").MatchString(in.MachineCode) {
		writeErr(w, http.StatusBadRequest, "机器码格式无效")
		return
	}
	commandType := map[string]string{
		"list": "routeros_container_list",
		"start": "routeros_container_start",
		"stop": "routeros_container_stop",
		"restart": "routeros_container_restart",
	}[in.Action]
	if commandType == "" {
		writeErr(w, http.StatusBadRequest, "仅支持 list/start/stop/restart")
		return
	}
	if in.Action == "list" {
		in.ContainerID = ""
	} else if !regexp.MustCompile("^\\*[0-9A-Fa-f]{1,31}$").MatchString(in.ContainerID) {
		writeErr(w, http.StatusBadRequest, "RouterOS 容器内部 ID 无效")
		return
	}
	settings, err := a.store.GetSettings()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "读取 Agent 授权失败")
		return
	}
	token := settings["agent_machine_"+in.MachineCode]
	if token == "" || token == settings["agent_token"] {
		writeErr(w, http.StatusNotFound, "目标 Agent 未授权")
		return
	}
	var osName string
	err = a.store.db.QueryRow("SELECT os FROM agent_status WHERE machine_code=?", in.MachineCode).Scan(&osName)
	if err != nil || strings.ToLower(strings.TrimSpace(osName)) != "routeros" {
		writeErr(w, http.StatusBadRequest, "目标 Agent 未报告为 RouterOS 节点")
		return
	}
	command := map[string]string{
		"id": fmt.Sprintf("%d", time.Now().UnixNano()),
		"type": commandType,
	}
	if in.ContainerID != "" {
		command["container_id"] = in.ContainerID
	}
	payload, err := json.Marshal(command)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "生成 RouterOS 命令失败")
		return
	}
	created, err := a.store.CreateSettingIfAbsent("agent_command_"+in.MachineCode, string(payload))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "保存 RouterOS 命令失败")
		return
	}
	if !created {
		writeErr(w, http.StatusConflict, "该 Agent 已有待执行命令，请等待完成后重试")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{
		"message": "RouterOS 命令已排队；节点在线时将执行并回传结果",
		"command_id": command["id"],
	})
}
func (a *App) handleRouterOSCommandResult(w http.ResponseWriter, r *http.Request) {
	code := strings.TrimSpace(r.URL.Query().Get("machine_code"))
	if !regexp.MustCompile("^[A-Za-z0-9_-]{1,64}$").MatchString(code) { writeErr(w, http.StatusBadRequest, "机器码格式无效"); return }
	settings, err := a.store.GetSettings()
	if err != nil { writeErr(w, http.StatusInternalServerError, "读取命令结果失败"); return }
	raw := settings["agent_command_result_"+code]
	if raw == "" { writeJSON(w, http.StatusOK, map[string]any{"result": nil}); return }
	var result map[string]any
	if err := json.Unmarshal([]byte(raw), &result); err != nil { writeErr(w, http.StatusInternalServerError, "命令结果数据损坏"); return }
	writeJSON(w, http.StatusOK, map[string]any{"result": result})
}
func (a *App) handleContainerNodes(w http.ResponseWriter, r *http.Request) {
	if !a.requireContainerAdmin(w, r) {
		return
	}
	rows, err := a.store.db.Query(`SELECT machine_code,hostname,os,arch,docker_available,
        mihomo_running,mihomo_version,status_json,updated_at FROM agent_status ORDER BY machine_code`)
	if err != nil {
		writeErr(w, 500, "读取节点状态失败")
		return
	}
	defer rows.Close()
	nodes := make([]map[string]any, 0)
	for rows.Next() {
		var code, host, osName, arch, version, status, updated string
		var docker, mihomo bool
		if err = rows.Scan(&code, &host, &osName, &arch, &docker, &mihomo, &version, &status, &updated); err != nil {
			writeErr(w, 500, "读取节点数据失败")
			return
		}
		var detail any
		if json.Unmarshal([]byte(status), &detail) != nil {
			detail = map[string]any{}
		}
		nodes = append(nodes, map[string]any{
			"machine_code": code, "hostname": host, "os": osName, "arch": arch,
			"docker_available": docker, "mihomo_running": mihomo,
			"mihomo_version": version, "status_json": detail, "updated_at": updated,
			"online": agentStatusIsOnline(updated, time.Now().UTC()),
		})
	}
	if err = rows.Err(); err != nil {
		writeErr(w, 500, "遍历节点数据失败")
		return
	}
	writeJSON(w, 200, map[string]any{"nodes": nodes})
}

func agentStatusIsOnline(updatedAt string, now time.Time) bool {
	t, err := time.Parse(time.RFC3339, updatedAt)
	if err != nil || t.After(now.Add(30*time.Second)) {
		return false
	}
	return now.Sub(t) <= 90*time.Second
}
