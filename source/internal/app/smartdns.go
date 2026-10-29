package app

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"
)

const defaultAgentSmartDNSConfig = `# Managed by S5M. The config is persisted at /data/smartdns.conf.
bind 127.0.0.1:6053
bind-tcp 127.0.0.1:6053
server 223.5.5.5
server 119.29.29.29
cache-size 16384
prefetch-domain yes
serve-expired yes
log-level info
log-console yes
log-syslog no
`

var smartDNSMachineCodePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
var smartDNSConfigControlChars = regexp.MustCompile("[\\x00-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f]")
var smartDNSAllowedDirectives = map[string]bool{
	"bind": true, "bind-tcp": true,
	"server": true, "server-tcp": true, "server-tls": true,
	"server-https": true, "server-quic": true,
	"cache-size": true, "prefetch-domain": true, "serve-expired": true,
	"log-level": true, "log-console": true, "log-syslog": true,
	"dualstack-ip-selection": true, "rr-ttl": true, "rr-ttl-min": true,
	"rr-ttl-max": true, "force-AAAA-SOA": true, "force-qtype-SOA": true,
	"speed-check-mode": true, "response-mode": true,
}

func validateControllerSmartDNSConfig(config string) error {
	if strings.TrimSpace(config) == "" || len(config) > 8<<10 {
		return fmt.Errorf("SmartDNS 配置不能为空且不得超过 8 KiB")
	}
	if smartDNSConfigControlChars.MatchString(config) {
		return fmt.Errorf("SmartDNS 配置包含非法控制字符")
	}
	usable := 0
	bindUDP, bindTCP := false, false
	for i, raw := range strings.Split(strings.ReplaceAll(config, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || !smartDNSAllowedDirectives[fields[0]] {
			return fmt.Errorf("第 %d 行配置指令无效或不允许: %q", i+1, firstSmartDNSField(fields))
		}
		if strings.ContainsAny(line, "`$") || strings.Contains(strings.ToLower(line), "include") {
			return fmt.Errorf("第 %d 行包含不允许的特殊内容", i+1)
		}
		if (fields[0] == "bind" || fields[0] == "bind-tcp") {
			if len(fields) != 2 || fields[1] != "127.0.0.1:6053" {
				return fmt.Errorf("第 %d 行监听地址必须保持在容器回环地址 127.0.0.1:6053", i+1)
			}
			if fields[0] == "bind" { bindUDP = true } else { bindTCP = true }
		}
		usable++
	}
	if usable == 0 {
		return fmt.Errorf("SmartDNS 配置没有有效指令")
	}
	if !bindUDP || !bindTCP {
		return fmt.Errorf("必须同时配置 bind 127.0.0.1:6053 和 bind-tcp 127.0.0.1:6053")
	}
	return nil
}

func firstSmartDNSField(fields []string) string {
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

func (a *App) queueAgentSmartDNSConfig(machineCode, config string) error {
	machineCode = strings.TrimSpace(machineCode)
	if !smartDNSMachineCodePattern.MatchString(machineCode) {
		return fmt.Errorf("机器码格式无效")
	}
	if err := validateControllerSmartDNSConfig(config); err != nil {
		return err
	}
	settings, err := a.store.GetSettings()
	if err != nil {
		return fmt.Errorf("读取 Agent 授权失败")
	}
	token := strings.TrimSpace(settings["agent_machine_"+machineCode])
	if token == "" || token == strings.TrimSpace(settings["agent_token"]) {
		return fmt.Errorf("目标 Agent 未授权")
	}
	command := map[string]string{
		"id": fmt.Sprintf("%d", time.Now().UnixNano()),
		"type": "configure_smartdns",
		"config": config,
	}
	payload, err := json.Marshal(command)
	if err != nil {
		return fmt.Errorf("生成 SmartDNS 配置命令失败")
	}
	created, err := a.store.CreateSettingIfAbsent("agent_command_"+machineCode, string(payload))
	if err != nil {
		return fmt.Errorf("保存 SmartDNS 配置命令失败")
	}
	if !created {
		return fmt.Errorf("该 Agent 已有待执行命令，请等待完成后重试")
	}
	if err := a.store.UpdateSettings(map[string]string{"agent_smartdns_config_" + machineCode: config}); err != nil {
		return fmt.Errorf("SmartDNS 命令已排队，但保存期望配置失败: %w", err)
	}
	a.publishBrowserEvent(map[string]any{
		"type": "agent.command.queued", "machine_code": machineCode,
		"command_id": command["id"], "command_type": command["type"], "at": time.Now().Unix(),
	})
	return nil
}

func (a *App) handleGetAgentSmartDNSConfig(w http.ResponseWriter, r *http.Request) {
	code := strings.TrimSpace(r.URL.Query().Get("machine_code"))
	if !smartDNSMachineCodePattern.MatchString(code) {
		writeErr(w, http.StatusBadRequest, "机器码格式无效")
		return
	}
	settings, err := a.store.GetSettings()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "读取 SmartDNS 配置失败")
		return
	}
	if token := strings.TrimSpace(settings["agent_machine_"+code]); token == "" || token == strings.TrimSpace(settings["agent_token"]) {
		writeErr(w, http.StatusNotFound, "目标 Agent 未授权")
		return
	}
	config := settings["agent_smartdns_config_"+code]
	if strings.TrimSpace(config) == "" {
		config = defaultAgentSmartDNSConfig
	}
	status := map[string]any{}
	if raw := strings.TrimSpace(settings["agent_status_"+code]); raw != "" {
		_ = json.Unmarshal([]byte(raw), &status)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"machine_code": code,
		"config": config,
		"desired_config_sha256": hashConfig(config),
		"reported_config_sha256": status["smartdns_config_sha256"],
		"available": status["smartdns_available"] == true,
		"running": status["smartdns_running"] == true,
		"version": status["smartdns_version"],
		"last_error": status["smartdns_last_error"],
		"last_seen": settings["agent_lastseen_"+code],
	})
}

func (a *App) handleQueueAgentSmartDNSConfig(w http.ResponseWriter, r *http.Request) {
	var in struct {
		MachineCode string `json:"machine_code"`
		Config string `json:"config"`
	}
	if err := decodeLimited(r, 10<<10, "10 KiB", &in); err != nil {
		writeErr(w, decodeErrorStatus(err), "SmartDNS 配置请求无效")
		return
	}
	if err := a.queueAgentSmartDNSConfig(in.MachineCode, in.Config); err != nil {
		status := http.StatusBadRequest
		if strings.Contains(err.Error(), "待执行命令") {
			status = http.StatusConflict
		} else if strings.Contains(err.Error(), "读取 Agent 授权") || strings.Contains(err.Error(), "保存 SmartDNS") {
			status = http.StatusInternalServerError
		} else if strings.Contains(err.Error(), "未授权") {
			status = http.StatusNotFound
		}
		writeErr(w, status, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{
		"ok": true,
		"message": "SmartDNS 配置命令已排队；Agent 会通过 WebSocket 执行并回报结果",
	})
}
