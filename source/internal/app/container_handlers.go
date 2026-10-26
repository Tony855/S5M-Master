package app

import (
	"encoding/json"
	"net/http"
	"strconv"
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
