package app

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	slog.Error("API 报错", "code", code, "msg", msg)
	writeJSON(w, code, map[string]string{"error": msg})
}

func decode(r *http.Request, v any) error { return json.NewDecoder(r.Body).Decode(v) }

func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decode(r, &in); err != nil {
		writeErr(w, 400, "参数错误")
		return
	}
	u, err := a.store.UserByUsername(in.Username)
	if err != nil || !u.Enabled || bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(in.Password)) != nil {
		writeErr(w, 401, "账号或密码错误")
		return
	}
	tok, _ := a.signToken(u)
	writeJSON(w, 200, map[string]any{"token": tok, "user": u})
}

func (a *App) handleMe(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, currentUser(r)) }

func (a *App) handlePassword(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Old string `json:"old"`
		New string `json:"new"`
	}
	if err := decode(r, &in); err != nil || len(in.New) < 6 {
		writeErr(w, 400, "新密码至少 6 位")
		return
	}
	cu := currentUser(r)
	u, err := a.store.UserByUsername(cu.Username)
	if err != nil || bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(in.Old)) != nil {
		writeErr(w, 401, "原密码错误")
		return
	}
	h, _ := bcrypt.GenerateFromPassword([]byte(in.New), bcrypt.DefaultCost)
	a.store.UpdatePassword(u.ID, string(h))
	writeJSON(w, 200, map[string]string{"message": "密码已更新"})
}

func (a *App) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	s, _ := a.store.GetSettings()
	writeJSON(w, 200, s)
}
func (a *App) handleUpdateSettings(w http.ResponseWriter, r *http.Request) {
	var in map[string]string
	if err := decode(r, &in); err != nil {
		writeErr(w, 400, "参数错误")
		return
	}
	a.store.UpdateSettings(in)
	writeJSON(w, 200, map[string]string{"message": "设置已保存"})
}

func (a *App) handleListInstances(w http.ResponseWriter, r *http.Request) {
	list, _ := a.store.ListInstances()
	writeJSON(w, 200, list)
}
func (a *App) handleCreateInstance(w http.ResponseWriter, r *http.Request) {
	var in Instance
	if err := decode(r, &in); err != nil || in.Name == "" {
		writeErr(w, 400, "参数错误")
		return
	}
	if err := a.store.CreateInstance(&in); err != nil {
		writeErr(w, 409, err.Error())
		return
	}
	writeJSON(w, 200, in)
}
func (a *App) handleDeleteInstance(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	a.store.DeleteInstance(id)
	writeJSON(w, 200, map[string]string{"message": "已删除"})
}

func (a *App) handleListProxies(w http.ResponseWriter, r *http.Request) {
	list, _ := a.store.ListProxies()
	writeJSON(w, 200, list)
}

func (a *App) validateProxy(p *Proxy) string {
	if p.Name == "" {
		return "名称不能为空"
	}
	if p.Mode == "" {
		p.Mode = "proxy"
	}
	if p.Mode == "proxy" || p.Mode == "china" || p.Mode == "game" {
		if p.Type == "" || p.Server == "" || p.Port <= 0 {
			return "代理必须填写类型、服务器和端口"
		}
	}
	if p.SourceCIDR == "" {
		p.SourceCIDR = "0.0.0.0/0"
	}
	if _, _, err := net.ParseCIDR(p.SourceCIDR); err != nil {
		return "源 IP 必须是合法 CIDR"
	}
	return ""
}

func (a *App) handleCreateProxy(w http.ResponseWriter, r *http.Request) {
	var p Proxy
	if err := decode(r, &p); err != nil {
		writeErr(w, 400, "参数错误")
		return
	}
	if msg := a.validateProxy(&p); msg != "" {
		writeErr(w, 400, msg)
		return
	}
	if p.Extra == nil {
		p.Extra = map[string]any{}
	}
	if err := a.store.CreateProxy(&p); err != nil {
		writeErr(w, 409, err.Error())
		return
	}
	writeJSON(w, 200, p)
}

func (a *App) handleUpdateProxy(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	var p Proxy
	if err := decode(r, &p); err != nil {
		writeErr(w, 400, "参数错误")
		return
	}
	p.ID = id
	if msg := a.validateProxy(&p); msg != "" {
		writeErr(w, 400, msg)
		return
	}
	if p.Extra == nil {
		p.Extra = map[string]any{}
	}
	if err := a.store.UpdateProxy(&p); err != nil {
		writeErr(w, 409, err.Error())
		return
	}
	writeJSON(w, 200, p)
}

func (a *App) handleDeleteProxy(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	a.store.DeleteProxy(id)
	writeJSON(w, 200, map[string]string{"message": "已删除"})
}

func (a *App) handlePreview(w http.ResponseWriter, r *http.Request) {
	yml, _ := a.BuildConfig()
	writeJSON(w, 200, map[string]string{"yaml": yml})
}
func (a *App) handlePublish(w http.ResponseWriter, r *http.Request) {
	cv, err := a.Publish()
	if err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "message": err.Error(), "version": cv})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "message": "发布成功", "version": cv})
}
func (a *App) handleVersions(w http.ResponseWriter, r *http.Request) {
	list, _ := a.store.ListVersions(30)
	writeJSON(w, 200, list)
}
func (a *App) handleRollback(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Version int `json:"version"`
	}
	if err := decode(r, &in); err != nil || in.Version <= 0 {
		writeErr(w, 400, "无效")
		return
	}
	cv, err := a.Rollback(in.Version)
	if err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "message": err.Error(), "version": cv})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "message": "回滚成功", "version": cv})
}
func (a *App) handleOverview(w http.ResponseWriter, r *http.Request) {
	list, _ := a.store.ListProxies()
	enabled := 0
	for _, p := range list {
		if p.Enabled {
			enabled++
		}
	}
	writeJSON(w, 200, map[string]any{"mihomo": a.MihomoInfo(), "proxy_total": len(list), "proxy_enabled": enabled})
}

var lastUp, lastDown uint64
var lastTime time.Time

func (a *App) handleMonitorTraffic(w http.ResponseWriter, r *http.Request) {
	resp, err := a.mihomoReq(http.MethodGet, "/connections", nil)
	if err != nil {
		writeJSON(w, 200, map[string]any{"up": 0, "down": 0, "conns": 0})
		return
	}
	defer resp.Body.Close()
	var data struct {
		DownloadTotal uint64 `json:"downloadTotal"`
		UploadTotal   uint64 `json:"uploadTotal"`
		Connections   []any  `json:"connections"`
	}
	json.NewDecoder(resp.Body).Decode(&data)
	now := time.Now()
	upSpeed, downSpeed := uint64(0), uint64(0)
	if !lastTime.IsZero() {
		diff := now.Sub(lastTime).Seconds()
		if diff > 0 {
			if data.UploadTotal >= lastUp {
				upSpeed = uint64(float64(data.UploadTotal-lastUp) / diff)
			}
			if data.DownloadTotal >= lastDown {
				downSpeed = uint64(float64(data.DownloadTotal-lastDown) / diff)
			}
		}
	}
	lastUp, lastDown, lastTime = data.UploadTotal, data.DownloadTotal, now
	writeJSON(w, 200, map[string]any{"up": upSpeed, "down": downSpeed, "conns": len(data.Connections)})
}

func (a *App) handleUpdateMihomo(w http.ResponseWriter, r *http.Request) {
	out, _ := exec.Command("/opt/mihomo/mihomo", "-v").Output()
	re := regexp.MustCompile(`Mihomo Meta (v[0-9]+\.[0-9]+\.[0-9]+)`)
	matches := re.FindStringSubmatch(string(out))
	currentVersion := "unknown"
	if len(matches) > 1 {
		currentVersion = matches[1]
	}
	client := &http.Client{Timeout: 10 * time.Second}
	req, _ := http.NewRequest("GET", "https://api.github.com/repos/MetaCubeX/mihomo/releases/latest", nil)
	req.Header.Set("User-Agent", "S5M-Next")
	resp, err := client.Do(req)
	if err != nil {
		writeErr(w, 500, "检查更新失败")
		return
	}
	defer resp.Body.Close()
	var release struct {
		TagName string `json:"tag_name"`
		Assets  []struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
		} `json:"assets"`
	}
	json.NewDecoder(resp.Body).Decode(&release)
	latestVersion := release.TagName
	if currentVersion == latestVersion {
		writeJSON(w, 200, map[string]string{"message": "当前已是最新版本", "status": "latest"})
		return
	}
	var downloadURL string
	for _, asset := range release.Assets {
		if strings.Contains(asset.Name, "linux-amd64-compatible") && strings.HasSuffix(asset.Name, ".gz") {
			downloadURL = "https://ghproxy.net/" + asset.BrowserDownloadURL
			break
		}
	}
	if downloadURL == "" {
		writeErr(w, 500, "未找到适配包")
		return
	}
	tmp := "/tmp/mihomo_update.gz"
	if err := exec.Command("curl", "-fL", "-o", tmp, downloadURL).Run(); err != nil {
		writeErr(w, 500, "下载失败")
		return
	}
	exec.Command("systemctl", "stop", "mihomo").Run()
	exec.Command("cp", "/opt/mihomo/mihomo", "/opt/mihomo/mihomo.bak").Run()
	data, _ := exec.Command("gunzip", "-c", tmp).Output()
	os.WriteFile("/opt/mihomo/mihomo", data, 0755)
	exec.Command("systemctl", "start", "mihomo").Run()
	writeJSON(w, 200, map[string]string{"message": "已成功更新至 " + latestVersion, "status": "updated"})
}

func (a *App) handleGetLogs(w http.ResponseWriter, r *http.Request) {
	cmd := exec.Command("journalctl", "-u", "s5m-next", "-n", "100", "--no-pager", "-o", "short-iso")
	output, _ := cmd.CombinedOutput()
	lines := strings.Split(string(output), "\n")
	var result []string
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		line = regexp.MustCompile(`\s+[a-zA-Z0-9.-]+\.bytevirt\.com\s+`).ReplaceAllString(line, " ")
		line = strings.ReplaceAll(line, " systemd[1]: ", " ")
		line = strings.ReplaceAll(line, "s5m-next.service:", "S5M:")
		line = regexp.MustCompile(`time=\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z?\s*`).ReplaceAllString(line, "")
		if len(line) >= 25 && line[10] == 'T' {
			line = strings.Replace(line[:19], "T", " ", 1) + " " + strings.TrimSpace(line[25:])
		}
		result = append(result, line)
	}
	writeJSON(w, 200, map[string]string{"logs": strings.Join(result, "\n")})
}

func (a *App) handleDownloadBackup(w http.ResponseWriter, r *http.Request) {
	t, err := jwt.Parse(r.URL.Query().Get("token"), func(t *jwt.Token) (any, error) { return a.jwtKey, nil }, jwt.WithValidMethods([]string{"HS256"}))
	if err != nil || !t.Valid {
		writeErr(w, 401, "登录已失效")
		return
	}
	w.Header().Set("Content-Disposition", "attachment; filename=s5m_backup.db")
	http.ServeFile(w, r, a.cfg.DBPath)
}

func (a *App) handleRestoreBackup(w http.ResponseWriter, r *http.Request) {
	file, _, err := r.FormFile("file")
	if err != nil {
		writeErr(w, 400, "上传失败")
		return
	}
	defer file.Close()
	tmp := "/tmp/restore.db"
	out, _ := os.Create(tmp)
	defer out.Close()
	io.Copy(out, file)
	a.store.db.Close()
	os.Rename(tmp, a.cfg.DBPath)
	writeJSON(w, 200, map[string]string{"message": "已覆盖，请重启面板"})
}

func (a *App) handleSubscribe(w http.ResponseWriter, r *http.Request) {
	s, _ := a.store.GetSettings()
	if s["sub_token"] == "" || r.URL.Query().Get("token") != s["sub_token"] {
		writeErr(w, 403, "无效 token")
		return
	}
	proxies, _ := a.store.ListProxies()
	var outs []proxyOut
	for _, p := range proxies {
		if !p.Enabled || p.Mode == "direct" || p.Mode == "reject" {
			continue
		}
		ex := map[string]any{}
		for k, v := range p.Extra {
			switch k {
			case "name", "type", "server", "port":
				continue
			}
			ex[k] = v
		}
		outs = append(outs, proxyOut{Name: p.Name, Type: p.Type, Server: p.Server, Port: p.Port, Extra: ex})
	}
	b, _ := yaml.Marshal(map[string]any{"proxies": outs, "rules": []string{"MATCH,DIRECT"}})
	w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
	w.Write(b)
}

func parseProxyLine(line string) (*Proxy, error) {
	p := &Proxy{Mode: "proxy", SourceCIDR: "0.0.0.0/0", Enabled: true, Extra: map[string]any{}}
	if idx := strings.Index(line, "#"); idx != -1 {
		p.Name = line[idx+1:]
		line = line[:idx]
	}
	schemeIdx := strings.Index(line, "://")
	if schemeIdx == -1 {
		return nil, fmt.Errorf("缺协议")
	}
	p.Type = line[:schemeIdx]
	line = line[schemeIdx+3:]
	var hostport string
	if atIdx := strings.LastIndex(line, "@"); atIdx != -1 {
		auth, hostp := line[:atIdx], line[atIdx+1:]
		hostport = hostp
		if auth != ":" && auth != "" {
			parts := strings.SplitN(auth, ":", 2)
			if len(parts) > 0 {
				p.Extra["username"] = parts[0]
			}
			if len(parts) > 1 {
				p.Extra["password"] = parts[1]
			}
		}
	} else {
		hostport = line
	}
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		if lc := strings.LastIndex(hostport, ":"); lc != -1 {
			host, portStr = hostport[:lc], hostport[lc+1:]
		} else {
			return nil, err
		}
	}
	p.Server = host
	p.Port, _ = strconv.Atoi(portStr)
	if p.Name == "" {
		p.Name = fmt.Sprintf("%s-%s:%d", p.Type, p.Server, p.Port)
	}
	if p.Type == "vless" || p.Type == "vmess" || p.Type == "trojan" || p.Type == "socks5" {
		p.Extra["udp"] = true
	}
	return p, nil
}

func (a *App) handleImportProxies(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Content string `json:"content"`
	}
	if err := decode(r, &in); err != nil {
		writeErr(w, 400, "参数错误")
		return
	}
	successCount := 0
	var failReasons []string
	lines := strings.Split(strings.ReplaceAll(strings.TrimSpace(in.Content), "\r\n", "\n"), "\n")
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		p, err := parseProxyLine(line)
		if err != nil {
			failReasons = append(failReasons, fmt.Sprintf("第 %d 行失败", i+1))
			continue
		}
		if err := a.store.CreateProxy(p); err != nil {
			p.Name = p.Name + "-" + strconv.FormatInt(time.Now().UnixNano(), 36)
			if err := a.store.CreateProxy(p); err != nil {
				failReasons = append(failReasons, fmt.Sprintf("存入失败"))
				continue
			}
		}
		successCount++
	}
	msg := "导入完成"
	if len(failReasons) > 0 {
		msg = strings.Join(failReasons, "; ")
	}
	writeJSON(w, 200, map[string]any{"success": successCount, "fail": len(failReasons), "message": msg})
}

func (a *App) handleAgentRegister(w http.ResponseWriter, r *http.Request) {
	var in struct {
		MachineCode string `json:"machine_code"`
		Secret      string `json:"secret"`
	}
	if err := decode(r, &in); err != nil || in.MachineCode == "" || in.Secret == "" {
		writeErr(w, 400, "机器码和密钥不能为空")
		return
	}
	settings, _ := a.store.GetSettings()
	expectedSecret := settings["agent_token"]
	if expectedSecret == "" {
		writeErr(w, 500, "主控台未初始化全局 Token")
		return
	}

	// 校验：必须等于全局 Token，或者等于该机器码的专属 Token
	machineToken := settings["agent_machine_"+in.MachineCode]
	if in.Secret != expectedSecret && (machineToken == "" || in.Secret != machineToken) {
		writeErr(w, 403, "密钥错误")
		return
	}

	// 核心修复：如果数据库里没有该机器码，自动用其输入的密钥写入记录，避免心跳被 401 拦截
	if machineToken == "" {
		a.store.UpdateSettings(map[string]string{"agent_machine_" + in.MachineCode: in.Secret})
	}

	claims := jwt.MapClaims{"sub": in.MachineCode, "role": "agent"}
	token, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(a.jwtKey)
	writeJSON(w, 200, map[string]string{"message": "注册成功", "token": token})
}

func (a *App) handleAgentConfig(w http.ResponseWriter, r *http.Request) {
	machineCode := ""
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
		token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
			return a.jwtKey, nil
		})
		if err == nil && token.Valid {
			if claims, ok := token.Claims.(jwt.MapClaims); ok {
				if mc, ok := claims["sub"].(string); ok && mc != "" {
					machineCode = mc
				}
			}
		}
	}
	if machineCode == "" {
		writeErr(w, 401, "无效的 Agent Token")
		return
	}

	// 记录最后在线时间
	now := fmt.Sprintf("%d", time.Now().Unix())
	a.store.UpdateSettings(map[string]string{"agent_lastseen_" + machineCode: now})

	// 复用 configgen 生成完整配置（含 SRC-IP-CIDR 分流规则、REJECT 防泄漏规则）
	yml, err := a.BuildConfigForMachine(machineCode)
	if err != nil {
		writeErr(w, 500, "生成配置失败: "+err.Error())
		return
	}

	w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(yml))
}

// 删除指定的机器码
func (a *App) handleDeleteAgent(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		writeErr(w, 400, "机器码和密钥不能为空")
		return
	}
	// 彻底从数据库删除机器码的 Token 和心跳记录
	err := a.store.DeleteSettings([]string{"agent_machine_" + code, "agent_lastseen_" + code})
	if err != nil {
		writeErr(w, 500, "删除失败: "+err.Error())
		return
	}
	writeJSON(w, 200, map[string]string{"message": "已删除"})
}

// 返回所有已注册的机器码 -> Token 映射
// 依赖 store 里 settings 表的 agent_machine_<code> 键
func (a *App) handleGetAgents(w http.ResponseWriter, r *http.Request) {
	settings, err := a.store.GetSettings()
	if err != nil {
		writeErr(w, 500, "读取设置失败: "+err.Error())
		return
	}
	type AgentInfo struct {
		Token    string `json:"token"`
		LastSeen int64  `json:"last_seen"`
	}
	result := make(map[string]AgentInfo)

	// 1. 收集所有出现过的机器码（来自 agent_machine_ 或 agent_lastseen_）
	codes := make(map[string]bool)
	for k := range settings {
		if strings.HasPrefix(k, "agent_machine_") {
			codes[strings.TrimPrefix(k, "agent_machine_")] = true
		}
		if strings.HasPrefix(k, "agent_lastseen_") {
			codes[strings.TrimPrefix(k, "agent_lastseen_")] = true
		}
	}

	globalToken := settings["agent_token"]

	// 2. 组装信息
	for code := range codes {
		token := settings["agent_machine_"+code]
		// 如果机器专属 token 为空，前端用全局 token 顶替展示（或者留空，取决于前端逻辑）
		if token == "" {
			token = globalToken
		}

		var lastSeen int64
		if tsStr := settings["agent_lastseen_"+code]; tsStr != "" {
			lastSeen, _ = strconv.ParseInt(tsStr, 10, 64)
		}

		result[code] = AgentInfo{Token: token, LastSeen: lastSeen}
	}

	writeJSON(w, 200, result)
}

// 为特定机器码生成专属短 Token
func (a *App) handleGenerateAgentToken(w http.ResponseWriter, r *http.Request) {
	var in struct {
		MachineCode string `json:"machine_code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.MachineCode == "" {
		writeErr(w, 400, "参数错误，缺少机器码")
		return
	}

	// 生成一个随机短 token (例如 s5m-mc-xxxx)
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		writeErr(w, 500, "生成随机 Token 失败")
		return
	}
	token := fmt.Sprintf("s5m-%x", buf)

	// 存入数据库：agent_machine_<机器码> = token
	err := a.store.UpdateSettings(map[string]string{
		"agent_machine_" + in.MachineCode: token,
	})
	if err != nil {
		writeErr(w, 500, "保存 Token 失败: "+err.Error())
		return
	}

	writeJSON(w, 200, map[string]string{
		"message": "生成成功",
		"token":   token,
	})
}

// 保存全局配置并下发给 Agent
func (a *App) handleSaveConfig(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ConfigYaml string `json:"config_yaml"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, 400, "参数错误")
		return
	}
	err := a.store.UpdateSettings(map[string]string{"config_yaml": in.ConfigYaml})
	if err != nil {
		writeErr(w, 500, "保存配置失败")
		return
	}
	writeJSON(w, 200, map[string]string{"message": "配置已保存，Agent 将在 30 秒内拉取更新"})
}
