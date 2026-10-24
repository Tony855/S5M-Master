package app

import (
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
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
	r.Body = http.MaxBytesReader(w, r.Body, 32768)
	var in struct {
		Hostname        string          `json:"hostname"`
		OS              string          `json:"os"`
		Arch            string          `json:"arch"`
		DockerAvailable bool            `json:"docker_available"`
		MihomoRunning   bool            `json:"mihomo_running"`
		MihomoVersion   string          `json:"mihomo_version"`
		Status          json.RawMessage `json:"status_json"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "状态数据格式错误")
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
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *App) handleContainerAgentNextTask(w http.ResponseWriter, r *http.Request) {
	code, ok := a.agentMachineCode(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "Agent 身份验证失败")
		return
	}
	nowTime := time.Now().UTC()
	now := nowTime.Format(time.RFC3339)
	// Requeue a task left running by a crashed/disconnected Agent. Docker commands
	// have a 15-second execution timeout; a 2-minute lease safely exceeds normal work.
	staleBefore := nowTime.Add(-2 * time.Minute).Format(time.RFC3339)
	if _, err := a.store.db.Exec(`UPDATE agent_tasks SET status='pending', claimed_at='', updated_at=? WHERE machine_code=? AND status='running' AND claimed_at<>'' AND claimed_at < ?`, now, code, staleBefore); err != nil {
		writeErr(w, http.StatusInternalServerError, "恢复超时任务失败")
		return
	}
	var t struct {
		ID        int64           `json:"id"`
		Action    string          `json:"action"`
		Params    string          `json:"-"`
		CreatedAt string          `json:"created_at"`
	}
	err := a.store.db.QueryRow(`UPDATE agent_tasks
        SET status='running',claimed_at=?,updated_at=?
        WHERE id=(SELECT id FROM agent_tasks WHERE machine_code=? AND status='pending' ORDER BY id LIMIT 1)
        AND machine_code=? AND status='pending'
        RETURNING id,action,params_json,created_at`, now, now, code, code).
		Scan(&t.ID, &t.Action, &t.Params, &t.CreatedAt)
	if err == sql.ErrNoRows {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err != nil {
		slog.Error("领取容器任务失败", "machine_code", code, "error", err)
		writeErr(w, http.StatusInternalServerError, "领取任务失败")
		return
	}
	params := json.RawMessage(t.Params)
	if len(params) == 0 || !json.Valid(params) {
		params = json.RawMessage("{}")
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": t.ID, "action": t.Action, "params": params, "created_at": t.CreatedAt})
}

func (a *App) handleContainerAgentTaskResult(w http.ResponseWriter, r *http.Request) {
	code, ok := a.agentMachineCode(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "Agent 身份验证失败")
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, http.StatusBadRequest, "任务 ID 无效")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 256<<10)
	var in struct {
		Status string          `json:"status"`
		Result json.RawMessage `json:"result"`
		Error  string          `json:"error"`
	}
	if err = json.NewDecoder(r.Body).Decode(&in); err != nil && err != io.EOF {
		writeErr(w, http.StatusBadRequest, "结果数据格式错误")
		return
	}
	if in.Status != "succeeded" && in.Status != "failed" {
		writeErr(w, http.StatusBadRequest, "任务状态无效")
		return
	}
	result := string(in.Result)
	if len(in.Result) == 0 || !json.Valid(in.Result) {
		result = "{}"
	}
	if len(in.Error) > 4096 {
		in.Error = in.Error[:4096]
	}
	n, err := a.store.UpdateAgentTaskResult(id, code, in.Status, result, in.Error)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "保存任务结果失败")
		return
	}
	if n == 0 {
		writeErr(w, http.StatusConflict, "任务不存在、不属于此节点或已结束")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func validContainerID(s string) bool {
	if s == "" || len(s) > 128 || strings.HasPrefix(s, "-") {
		return false
	}
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return true
}

func validContainerAction(s string) bool {
	switch strings.TrimSpace(s) {
	case "docker.list", "docker.inspect", "docker.logs", "docker.start", "docker.stop", "docker.restart",
		"mihomo.status", "mihomo.restart":
		return true
	}
	return false
}

func agentStatusIsOnline(updatedAt string, now time.Time) bool {
	t, err := time.Parse(time.RFC3339, updatedAt)
	if err != nil || t.After(now.Add(30*time.Second)) {
		return false
	}
	return now.Sub(t) <= 90*time.Second
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

func (a *App) handleCreateContainerTask(w http.ResponseWriter, r *http.Request) {
	if !a.requireContainerAdmin(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16384)
	var in struct {
		MachineCode string          `json:"machine_code"`
		Action      string          `json:"action"`
		Params      json.RawMessage `json:"params"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, 400, "任务数据格式错误")
		return
	}
	if strings.TrimSpace(in.MachineCode) == "" || len(in.MachineCode) > 200 {
		writeErr(w, 400, "机器码无效")
		return
	}
	if !validContainerAction(in.Action) {
		writeErr(w, 400, "不允许的任务动作")
		return
	}
	settings, err := a.store.GetSettings()
	if err != nil {
		writeErr(w, 500, "读取机器配置失败")
		return
	}
	secret := settings["agent_machine_"+in.MachineCode]
	if secret == "" || secret == settings["agent_token"] {
		writeErr(w, 400, "该机器尚未配置专属 Agent Token")
		return
	}
	params := in.Params
	if len(params) == 0 {
		params = json.RawMessage("{}")
	}
	if !json.Valid(params) || string(params) == "null" {
		writeErr(w, 400, "params 必须是有效 JSON")
		return
	}
	var obj map[string]json.RawMessage
	if err = json.Unmarshal(params, &obj); err != nil || obj == nil {
		writeErr(w, 400, "params 必须是 JSON 对象")
		return
	}
	for k := range obj {
		if k != "container_id" && k != "tail" {
			writeErr(w, 400, "params 包含不支持的字段: "+k)
			return
		}
	}
	if v, ok := obj["container_id"]; ok {
		var id string
		if json.Unmarshal(v, &id) != nil || !validContainerID(strings.TrimSpace(id)) {
			writeErr(w, 400, "container_id 无效")
			return
		}
	}
	if v, ok := obj["tail"]; ok {
		var n int
		if json.Unmarshal(v, &n) != nil || n < 1 || n > 1000 {
			writeErr(w, 400, "tail 必须在 1 到 1000 之间")
			return
		}
	}
	if (in.Action == "docker.inspect" || in.Action == "docker.logs" ||
		in.Action == "docker.start" || in.Action == "docker.stop" || in.Action == "docker.restart") &&
		len(obj["container_id"]) == 0 {
		writeErr(w, 400, "该动作必须提供 container_id")
		return
	}
	if in.Action == "docker.logs" && len(obj["tail"]) == 0 {
		obj["tail"] = json.RawMessage("100")
		params, _ = json.Marshal(obj)
	}
	id, err := a.store.CreateAgentTask(in.MachineCode, in.Action, string(params))
	if err != nil {
		writeErr(w, 500, "创建任务失败")
		return
	}
	writeJSON(w, 201, map[string]any{"id": id, "status": "pending"})
}

func (a *App) handleListContainerTasks(w http.ResponseWriter, r *http.Request) {
	if !a.requireContainerAdmin(w, r) {
		return
	}
	limit := 100
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 100 {
			writeErr(w, 400, "limit 必须在 1 到 100 之间")
			return
		}
		limit = n
	}
	rows, err := a.store.db.Query(`SELECT id,machine_code,action,params_json,status,
        result_json,error_text,created_at,updated_at,claimed_at,finished_at
        FROM agent_tasks ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		writeErr(w, 500, "读取任务记录失败")
		return
	}
	defer rows.Close()
	tasks := make([]map[string]any, 0)
	for rows.Next() {
		var id int64
		var machine, action, params, status, result, errText, created, updated, claimed, finished string
		if err = rows.Scan(&id, &machine, &action, &params, &status, &result, &errText, &created, &updated, &claimed, &finished); err != nil {
			writeErr(w, 500, "读取任务数据失败")
			return
		}
		var p any
		if json.Unmarshal([]byte(params), &p) != nil {
			p = map[string]any{}
		}
		var res any
		if result != "" && json.Unmarshal([]byte(result), &res) != nil {
			res = result
		}
		tasks = append(tasks, map[string]any{
			"id": id, "machine_code": machine, "action": action, "params": p, "status": status,
			"result": res, "error": errText, "created_at": created, "updated_at": updated,
			"claimed_at": claimed, "finished_at": finished,
		})
	}
	if err = rows.Err(); err != nil {
		writeErr(w, 500, "遍历任务数据失败")
		return
	}
	writeJSON(w, 200, map[string]any{"tasks": tasks})
}

func (a *App) handleCancelContainerTask(w http.ResponseWriter, r *http.Request) {
	if !a.requireContainerAdmin(w, r) {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, http.StatusBadRequest, "任务 ID 无效")
		return
	}
	n, err := a.store.CancelPendingAgentTask(id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "取消任务失败")
		return
	}
	if n == 0 {
		writeErr(w, http.StatusConflict, "任务不存在或已被领取/结束，无法取消")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "id": id, "status": "cancelled"})
}
