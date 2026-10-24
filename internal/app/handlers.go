package app

import (
	"crypto/rand"
	"crypto/sha256"
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
	"sync"
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

	if err := decode(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "参数错误")
		return
	}
	if len(in.New) < 6 {
		writeErr(w, http.StatusBadRequest, "新密码至少 6 位")
		return
	}

	cu := currentUser(r)
	if cu == nil {
		writeErr(w, http.StatusUnauthorized, "未登录")
		return
	}

	u, err := a.store.UserByUsername(cu.Username)
	if err != nil || u == nil || !u.Enabled {
		writeErr(w, http.StatusUnauthorized, "账号不存在或已禁用，请重新登录")
		return
	}

	if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(in.Old)) != nil {
		writeErr(w, http.StatusUnauthorized, "原密码错误")
		return
	}

	h, err := bcrypt.GenerateFromPassword([]byte(in.New), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "密码处理失败")
		return
	}

	if err := a.store.UpdatePassword(u.ID, string(h)); err != nil {
		writeErr(w, http.StatusInternalServerError, "密码保存失败")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "密码已更新"})
}

func (a *App) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	settings, err := a.store.GetSettings()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "读取设置失败")
		return
	}
	writeJSON(w, http.StatusOK, settings)
}
func (a *App) handleUpdateSettings(w http.ResponseWriter, r *http.Request) {
	var in map[string]string
	if err := decode(r, &in); err != nil || in == nil {
		writeErr(w, http.StatusBadRequest, "参数错误")
		return
	}

	if err := a.store.UpdateSettings(in); err != nil {
		writeErr(w, http.StatusInternalServerError, "设置保存失败")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "设置已保存"})
}

func (a *App) handleListInstances(w http.ResponseWriter, r *http.Request) {
	list, err := a.store.ListInstances()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "读取实例列表失败")
		return
	}
	writeJSON(w, http.StatusOK, list)
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
	rawID := strings.TrimSpace(r.PathValue("id"))
	id, err := strconv.ParseInt(rawID, 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, http.StatusBadRequest, "实例 ID 无效")
		return
	}

	if err := a.store.DeleteInstance(id); err != nil {
		writeErr(w, http.StatusInternalServerError, "删除实例失败")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "已删除"})
}

func (a *App) handleListProxies(w http.ResponseWriter, r *http.Request) {
	list, err := a.store.ListProxies()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "读取代理列表失败")
		return
	}
	writeJSON(w, http.StatusOK, list)
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
	if err := a.syncAuthorizedNodeConfigs(); err != nil {
		writeErr(w, http.StatusInternalServerError, "代理已保存，但节点配置同步失败: "+err.Error())
		return
	}
	writeJSON(w, 200, p)
}

func (a *App) handleUpdateProxy(w http.ResponseWriter, r *http.Request) {
	rawID := strings.TrimSpace(r.PathValue("id"))
	id, err := strconv.ParseInt(rawID, 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, http.StatusBadRequest, "代理 ID 无效")
		return
	}
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
	if err := a.syncAuthorizedNodeConfigs(); err != nil {
		writeErr(w, http.StatusInternalServerError, "代理已更新，但节点配置同步失败: "+err.Error())
		return
	}
	writeJSON(w, 200, p)
}

func (a *App) handleDeleteProxy(w http.ResponseWriter, r *http.Request) {
	rawID := strings.TrimSpace(r.PathValue("id"))
	id, err := strconv.ParseInt(rawID, 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, http.StatusBadRequest, "代理 ID 无效")
		return
	}

	if err := a.store.DeleteProxy(id); err != nil {
		writeErr(w, http.StatusInternalServerError, "删除代理失败")
		return
	}
	if err := a.syncAuthorizedNodeConfigs(); err != nil {
		writeErr(w, http.StatusInternalServerError, "代理已删除，但节点配置同步失败: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "已删除"})
}

func (a *App) handlePreview(w http.ResponseWriter, r *http.Request) {
	yml, err := a.BuildConfig()
	if err != nil {
		writeErr(w, 500, "生成配置失败: "+err.Error())
		return
	}
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
	list, err := a.store.ListVersions(30)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "读取配置版本失败")
		return
	}
	writeJSON(w, http.StatusOK, list)
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
	list, err := a.store.ListProxies()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "读取代理概览失败")
		return
	}

	enabled := 0
	for _, p := range list {
		if p.Enabled {
			enabled++
		}
	}

	// 先获取内核状态；内核异常时仍返回仪表盘数据。
	mihomo := a.MihomoInfo()

	var downloadTotal uint64
	var uploadTotal uint64
	var connections []any

	resp, monitorErr := a.mihomoReq(http.MethodGet, "/connections", nil)
	if monitorErr == nil {
		defer resp.Body.Close()
		if resp.StatusCode < 300 {
			var data struct {
				DownloadTotal uint64 `json:"downloadTotal"`
				UploadTotal   uint64 `json:"uploadTotal"`
				Connections   []any  `json:"connections"`
			}
			if json.NewDecoder(resp.Body).Decode(&data) == nil {
				downloadTotal = data.DownloadTotal
				uploadTotal = data.UploadTotal
				connections = data.Connections
			}
		}
	}

	if connections == nil {
		connections = []any{}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"mihomo":        mihomo,
		"total":         len(list),
		"enabled":       enabled,
		"proxy_total":   len(list),
		"proxy_enabled": enabled,
		"downloadTotal": downloadTotal,
		"uploadTotal":   uploadTotal,
		"connections":   connections,
	})
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
	s, err := a.store.GetSettings()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "读取订阅设置失败")
		return
	}
	if s["sub_token"] == "" || r.URL.Query().Get("token") != s["sub_token"] {
		writeErr(w, 403, "无效 token")
		return
	}
	proxies, err := a.store.ListProxies()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "读取订阅代理失败")
		return
	}
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
	settings, err := a.store.GetSettings()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "读取 Agent 注册配置失败")
		return
	}
	expectedSecret := settings["agent_token"]
	if expectedSecret == "" {
		writeErr(w, 500, "主控台未初始化全局 Token")
		return
	}

	// 只允许预先分配的专属 Token 注册对应机器码。
	machineToken := settings["agent_machine_"+in.MachineCode]
	if machineToken == "" ||
		machineToken == expectedSecret ||
		in.Secret == expectedSecret ||
		in.Secret != machineToken {
		writeErr(w, 403, "机器码或专属 Token 不匹配")
		return
	}

	version := fmt.Sprintf("%x", sha256.Sum256([]byte(machineToken)))
	claims := jwt.MapClaims{"sub": in.MachineCode, "role": "agent", "ver": version}
	token, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(a.jwtKey)
	writeJSON(w, 200, map[string]string{"message": "注册成功", "token": token})
}

func (a *App) handleAgentConfig(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		writeErr(w, 401, "缺少 Agent Token")
		return
	}

	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, fmt.Errorf("不支持的 JWT 签名算法")
		}
		return a.jwtKey, nil
	})
	if err != nil || token == nil || !token.Valid {
		writeErr(w, 401, "无效或已过期的 Agent Token")
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		writeErr(w, 401, "无效的 Agent Token")
		return
	}
	machineCode, ok := claims["sub"].(string)
	role, roleOK := claims["role"].(string)
	if !ok || machineCode == "" || !roleOK || role != "agent" {
		writeErr(w, 401, "Agent 身份或机器码无效")
		return
	}

	settings, err := a.store.GetSettings()
	if err != nil {
		writeErr(w, 500, "读取设备授权状态失败")
		return
	}

	// 已删除、未授权，或仍沿用全局 Token 的旧记录一律拒绝。
	machineToken := settings["agent_machine_"+machineCode]
	if machineToken == "" || machineToken == settings["agent_token"] {
		writeErr(w, 401, "设备未授权或已解绑")
		return
	}

	// JWT 必须绑定当前专属 Token；更换 Token 后旧 JWT 立即失效。
	version, versionOK := claims["ver"].(string)
	currentVersion := fmt.Sprintf("%x", sha256.Sum256([]byte(machineToken)))
	if !versionOK || version == "" || version != currentVersion {
		writeErr(w, 401, "Agent 授权版本已失效，请重新绑定")
		return
	}

	now := fmt.Sprintf("%d", time.Now().Unix())
	if err := a.store.UpdateSettings(map[string]string{
		"agent_lastseen_" + machineCode: now,
	}); err != nil {
		writeErr(w, 500, "更新设备心跳失败")
		return
	}

	nodeConfig, err := a.store.GetNodeConfig(machineCode)
	if err != nil {
		slog.Error("读取节点配置失败", "machine_code", machineCode, "error", err)
		writeErr(w, http.StatusInternalServerError, "读取节点配置失败")
		return
	}
	yml := ""
	if nodeConfig != nil {
		yml = strings.TrimSpace(nodeConfig.YAML)
	}
	if yml == "" {
		yml, err = a.BuildConfigForMachine(machineCode)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "生成节点配置失败: "+err.Error())
			return
		}
		if err := a.store.SaveNodeConfig(machineCode, yml); err != nil {
			writeErr(w, http.StatusInternalServerError, "保存节点配置失败")
			return
		}
	}
	w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(yml))
}


// agentMachineFromRequest validates the per-machine JWT and confirms its dedicated token is still active.
func (a *App) agentMachineFromRequest(r *http.Request) (string, error) {
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, "Bearer ") {
		return "", fmt.Errorf("缺少 Agent Token")
	}
	token, err := jwt.Parse(strings.TrimPrefix(header, "Bearer "), func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, fmt.Errorf("不支持的 JWT 签名算法")
		}
		return a.jwtKey, nil
	})
	if err != nil || token == nil || !token.Valid {
		return "", fmt.Errorf("无效或已过期的 Agent Token")
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", fmt.Errorf("Agent Token claims 无效")
	}
	code, codeOK := claims["sub"].(string)
	role, roleOK := claims["role"].(string)
	version, versionOK := claims["ver"].(string)
	if !codeOK || code == "" || !roleOK || role != "agent" || !versionOK || version == "" {
		return "", fmt.Errorf("Agent 身份无效")
	}
	settings, err := a.store.GetSettings()
	if err != nil {
		return "", fmt.Errorf("读取 Agent 授权失败: %w", err)
	}
	machineToken := settings["agent_machine_"+code]
	if machineToken == "" || machineToken == settings["agent_token"] ||
		version != fmt.Sprintf("%x", sha256.Sum256([]byte(machineToken))) {
		return "", fmt.Errorf("Agent 未授权或授权已失效")
	}
	return code, nil
}

func (a *App) handleQueueMihomoUpdate(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	if u == nil || u.Role != "admin" {
		writeErr(w, http.StatusForbidden, "仅管理员可以更新 Agent Mihomo 内核")
		return
	}
	var in struct {
		MachineCode string `json:"machine_code"`
		Version     string `json:"version"`
		SHA256      string `json:"sha256"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "请求 JSON 无效")
		return
	}
	in.MachineCode = strings.TrimSpace(in.MachineCode)
	in.Version = strings.TrimSpace(in.Version)
	in.SHA256 = strings.ToLower(strings.TrimSpace(in.SHA256))
	if !regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`).MatchString(in.MachineCode) ||
		!regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`).MatchString(in.Version) ||
		!regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(in.SHA256) {
		writeErr(w, http.StatusBadRequest, "机器码、版本号或 SHA-256 格式无效")
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
	if settings["agent_command_"+in.MachineCode] != "" {
		writeErr(w, http.StatusConflict, "该 Agent 已有待执行命令，请等待完成后重试")
		return
	}
	command := map[string]string{
		"id": fmt.Sprintf("%d", time.Now().UnixNano()), "type": "update_mihomo",
		"version": in.Version, "sha256": in.SHA256,
	}
	payload, err := json.Marshal(command)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "生成内核更新命令失败")
		return
	}
	if err := a.store.UpdateSettings(map[string]string{"agent_command_"+in.MachineCode: string(payload)}); err != nil {
		writeErr(w, http.StatusInternalServerError, "保存内核更新命令失败")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"message": "更新命令已排队；Agent 在线时会下载、校验并应用指定内核版本", "command_id": command["id"]})
}

func (a *App) handleAgentCommand(w http.ResponseWriter, r *http.Request) {
	code, err := a.agentMachineFromRequest(r)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, err.Error())
		return
	}
	settings, err := a.store.GetSettings()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "读取 Agent 命令失败")
		return
	}
	if raw := settings["agent_command_"+code]; raw != "" {
		var command map[string]string
		if err := json.Unmarshal([]byte(raw), &command); err != nil {
			writeErr(w, http.StatusInternalServerError, "待执行命令数据损坏")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"command": command})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"command": nil})
}

func (a *App) handleAgentCommandAck(w http.ResponseWriter, r *http.Request) {
	code, err := a.agentMachineFromRequest(r)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, err.Error())
		return
	}
	var in struct {
		ID      string `json:"id"`
		Status  string `json:"status"`
		Message string `json:"message"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "命令结果 JSON 无效")
		return
	}
	if in.ID == "" || (in.Status != "success" && in.Status != "failed") {
		writeErr(w, http.StatusBadRequest, "命令 ID 或状态无效")
		return
	}
	settings, err := a.store.GetSettings()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "读取待执行命令失败")
		return
	}
	var pending map[string]string
	if json.Unmarshal([]byte(settings["agent_command_"+code]), &pending) != nil || pending["id"] != in.ID {
		writeErr(w, http.StatusConflict, "命令已被替换或不存在")
		return
	}
	result, _ := json.Marshal(map[string]any{"id": in.ID, "type": pending["type"], "status": in.Status, "message": in.Message, "updated_at": time.Now().Unix()})
	if err := a.store.UpdateSettings(map[string]string{"agent_command_result_"+code: string(result)}); err != nil {
		writeErr(w, http.StatusInternalServerError, "保存命令结果失败")
		return
	}
	if err := a.store.DeleteSettings([]string{"agent_command_" + code}); err != nil {
		writeErr(w, http.StatusInternalServerError, "清除已执行命令失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// handleAgentHeartbeat stores authenticated per-Agent runtime telemetry.
func (a *App) handleAgentHeartbeat(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	var in map[string]any
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in == nil {
		writeErr(w, http.StatusBadRequest, "心跳 JSON 格式错误")
		return
	}
	for _, key := range []string{"mihomo_version", "mihomo_healthy", "upload_total", "download_total", "upload_speed", "download_speed", "connections", "config_sha256", "last_error"} {
		if _, ok := in[key]; !ok {
			writeErr(w, http.StatusBadRequest, "缺少心跳字段: "+key)
			return
		}
	}
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		writeErr(w, http.StatusUnauthorized, "缺少 Agent Token")
		return
	}
	token, err := jwt.Parse(strings.TrimPrefix(authHeader, "Bearer "), func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, fmt.Errorf("不支持的 JWT 签名算法")
		}
		return a.jwtKey, nil
	})
	if err != nil || token == nil || !token.Valid {
		writeErr(w, http.StatusUnauthorized, "无效或已过期的 Agent Token")
		return
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "无效的 Agent Token")
		return
	}
	code, codeOK := claims["sub"].(string)
	role, roleOK := claims["role"].(string)
	version, versionOK := claims["ver"].(string)
	if !codeOK || code == "" || !roleOK || role != "agent" || !versionOK || version == "" {
		writeErr(w, http.StatusUnauthorized, "Agent 身份无效")
		return
	}
	settings, err := a.store.GetSettings()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "读取设备授权失败")
		return
	}
	machineToken := settings["agent_machine_"+code]
	currentVersion := fmt.Sprintf("%x", sha256.Sum256([]byte(machineToken)))
	if machineToken == "" || machineToken == settings["agent_token"] || version != currentVersion {
		writeErr(w, http.StatusUnauthorized, "设备未授权或授权已失效")
		return
	}
	in["received_at"] = time.Now().Unix()
	payload, err := json.Marshal(in)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "心跳字段无法序列化")
		return
	}
	if err := a.store.UpdateSettings(map[string]string{
		"agent_lastseen_"+code: strconv.FormatInt(time.Now().Unix(), 10),
		"agent_status_"+code: string(payload),
	}); err != nil {
		writeErr(w, http.StatusInternalServerError, "保存心跳数据失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "received_at": time.Now().Unix()})
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
		Authorized bool           `json:"authorized"`
		LastSeen   int64          `json:"last_seen"`
		Status        map[string]any `json:"status,omitempty"`
		CommandResult map[string]any `json:"command_result,omitempty"`
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

	// 2. 仅返回具有有效专属 Token 的设备。
	// 不使用全局 Token 回退，也不展示只有心跳记录的未授权设备。
	for code := range codes {
		token := settings["agent_machine_"+code]
		if token == "" || token == settings["agent_token"] {
			continue
		}

		var lastSeen int64
		if tsStr := settings["agent_lastseen_"+code]; tsStr != "" {
			lastSeen, _ = strconv.ParseInt(tsStr, 10, 64)
		}

		var status map[string]any
		if raw := settings["agent_status_"+code]; raw != "" {
			_ = json.Unmarshal([]byte(raw), &status)
		}
		var commandResult map[string]any
		if raw := settings["agent_command_result_"+code]; raw != "" {
			_ = json.Unmarshal([]byte(raw), &commandResult)
		}
		result[code] = AgentInfo{Authorized: true, LastSeen: lastSeen, Status: status, CommandResult: commandResult}
	}

	writeJSON(w, 200, result)
}

// agentTokenGenerateMu 防止同一进程内并发请求重复分配同一机器码。
var agentTokenGenerateMu sync.Mutex

// 为指定机器码分配专属 Token。
// 已存在的 Token 不会被覆盖；需要更换时应走单独、明确授权的轮换流程。
func (a *App) handleGenerateAgentToken(w http.ResponseWriter, r *http.Request) {
	// 额外检查管理员角色，不能只依赖登录认证。
	u := currentUser(r)
	if u == nil || u.Role != "admin" {
		writeErr(w, http.StatusForbidden, "仅管理员可以生成机器 Token")
		return
	}

	var in struct {
		MachineCode string `json:"machine_code"`
	}

	// 限制请求体大小，避免异常大请求占用资源。
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "JSON 参数错误")
		return
	}

	in.MachineCode = strings.TrimSpace(in.MachineCode)

	// 保留旧机器码兼容性，同时禁止将任意内容拼接进 settings 键名。
	// 新节点仍应使用 11 位十六进制机器码。
	if len(in.MachineCode) < 1 || len(in.MachineCode) > 64 ||
		!regexp.MustCompile(`^[A-Za-z0-9_-]+$`).MatchString(in.MachineCode) {
		writeErr(w, http.StatusBadRequest, "机器码格式错误")
		return
	}

	agentTokenGenerateMu.Lock()
	defer agentTokenGenerateMu.Unlock()

	settings, err := a.store.GetSettings()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "读取机器码配置失败")
		return
	}

	globalToken := strings.TrimSpace(settings["agent_token"])
	key := "agent_machine_" + in.MachineCode

	// 不允许用生成接口覆盖已有绑定凭证。
	if existing := strings.TrimSpace(settings[key]); existing != "" {
		writeJSON(w, http.StatusConflict, map[string]string{
			"error":        "该机器码已经分配专属 Token，未进行覆盖",
			"machine_code": in.MachineCode,
		})
		return
	}

	// 防止生成结果与全局 Token 相同。
	var token string
	for attempt := 0; attempt < 3; attempt++ {
		buf := make([]byte, 16)
		if _, err := rand.Read(buf); err != nil {
			writeErr(w, http.StatusInternalServerError, "生成随机 Token 失败")
			return
		}
		token = fmt.Sprintf("s5m-%x", buf)
		if token != globalToken {
			break
		}
		token = ""
	}
	if token == "" {
		writeErr(w, http.StatusInternalServerError, "无法生成有效的专属 Token")
		return
	}

	// 原子创建绑定，绝不覆盖已存在的 Token。
	created, err := a.store.CreateSettingIfAbsent(key, token)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "保存 Token 失败")
		return
	}
	if !created {
		writeJSON(w, http.StatusConflict, map[string]string{
			"error":        "该机器码已经分配专属 Token，未进行覆盖",
			"machine_code": in.MachineCode,
		})
		return
	}

	// 回读验证，避免把未成功保存的凭证返回给调用方。
	saved, err := a.store.GetSettings()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "Token 已提交保存，但回读验证失败")
		return
	}
	if saved[key] != token {
		writeErr(w, http.StatusInternalServerError, "Token 保存校验失败")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"message":      "生成成功",
		"machine_code": in.MachineCode,
		"token":        token,
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

func (a *App) handleGetNodeConfig(w http.ResponseWriter, r *http.Request) {
	code := strings.TrimSpace(r.PathValue("code"))
	if code == "" {
		writeErr(w, 400, "机器码不能为空")
		return
	}
	settings, err := a.store.GetSettings()
	if err != nil {
		writeErr(w, 500, "读取授权状态失败")
		return
	}
	mt := settings["agent_machine_"+code]
	if mt == "" || mt == settings["agent_token"] {
		writeErr(w, 404, "节点未授权")
		return
	}
	cfg, err := a.store.GetNodeConfig(code)
	if err != nil {
		writeErr(w, 404, "该节点尚未保存独立 YAML 配置")
		return
	}
	writeJSON(w, 200, cfg)
}

func (a *App) handleSaveNodeConfig(w http.ResponseWriter, r *http.Request) {
	code := strings.TrimSpace(r.PathValue("code"))
	if code == "" {
		writeErr(w, 400, "机器码不能为空")
		return
	}
	settings, err := a.store.GetSettings()
	if err != nil {
		writeErr(w, 500, "读取授权状态失败")
		return
	}
	mt := settings["agent_machine_"+code]
	if mt == "" || mt == settings["agent_token"] {
		writeErr(w, 404, "节点未授权")
		return
	}
	var in struct {
		YAML string `json:"config_yaml"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2<<20)).Decode(&in); err != nil {
		writeErr(w, 400, "请求 JSON 无效")
		return
	}
	if strings.TrimSpace(in.YAML) == "" {
		writeErr(w, 400, "YAML 不能为空")
		return
	}
	var cfg map[string]any
	if err := yaml.Unmarshal([]byte(in.YAML), &cfg); err != nil || len(cfg) == 0 {
		writeErr(w, 400, "Mihomo YAML 格式错误或配置为空")
		return
	}
	secret, _ := cfg["secret"].(string)
	if strings.TrimSpace(secret) == "" {
		writeErr(w, 400, "完整配置必须包含非空 secret")
		return
	}
	if _, ok := cfg["tun"]; !ok {
		writeErr(w, 400, "完整配置缺少 tun 配置块；关闭 TUN 时也应设置 tun.enable: false")
		return
	}
	if _, ok := cfg["dns"]; !ok {
		writeErr(w, 400, "完整配置缺少 dns 配置块")
		return
	}
	if err := a.store.SaveNodeConfig(code, in.YAML); err != nil {
		writeErr(w, 500, "保存节点配置失败")
		return
	}
	writeJSON(w, 200, map[string]string{"message": "完整节点配置已保存；Agent 将在下一次拉取时应用"})
}
