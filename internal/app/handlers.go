package app

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
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

func decode(r *http.Request, v any) error {
	return json.NewDecoder(r.Body).Decode(v)
}

// ================= 认证相关 =================
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
		writeErr(w, 401, "用户名或密码错误")
		return
	}
	tok, _ := a.signToken(u)
	writeJSON(w, 200, map[string]any{"token": tok, "user": u})
}

func (a *App) handleMe(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, currentUser(r))
}

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

// ================= 设置与节点 =================
func (a *App) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	settings, _ := a.store.GetSettings()
	writeJSON(w, 200, settings)
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
			return "代理模式必须填写类型、服务器和端口"
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

// ================= 配置版本 =================
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

// ================= 监控与内核 =================
func (a *App) handleOverview(w http.ResponseWriter, r *http.Request) {
	list, _ := a.store.ListProxies()
	enabled := 0
	for _, p := range list {
		if p.Enabled { enabled++ }
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
	upSpeed := uint64(0)
	downSpeed := uint64(0)

	if !lastTime.IsZero() {
		diff := now.Sub(lastTime).Seconds()
		if diff > 0 {
			if data.UploadTotal >= lastUp { upSpeed = uint64(float64(data.UploadTotal-lastUp) / diff) }
			if data.DownloadTotal >= lastDown { downSpeed = uint64(float64(data.DownloadTotal-lastDown) / diff) }
		}
	}
	lastUp = data.UploadTotal
	lastDown = data.DownloadTotal
	lastTime = now

	writeJSON(w, 200, map[string]any{"up": upSpeed, "down": downSpeed, "conns": len(data.Connections)})
}

func (a *App) handleUpdateMihomo(w http.ResponseWriter, r *http.Request) {
	out, _ := exec.Command("/opt/mihomo/mihomo", "-v").Output()
	re := regexp.MustCompile(`Mihomo Meta (v[0-9]+\.[0-9]+\.[0-9]+)`)
	matches := re.FindStringSubmatch(string(out))
	currentVersion := "unknown"
	if len(matches) > 1 { currentVersion = matches[1] }

	client := &http.Client{Timeout: 10 * time.Second}
	req, _ := http.NewRequest("GET", "https://api.github.com/repos/MetaCubeX/mihomo/releases/latest", nil)
	req.Header.Set("User-Agent", "S5M-Next")

	resp, err := client.Do(req)
	if err != nil { writeErr(w, 500, "检查更新失败(网络异常): "+err.Error()); return }
	defer resp.Body.Close()

	var release struct {
		TagName string `json:"tag_name"`
		Assets  []struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil { writeErr(w, 500, "解析 GitHub 版本信息失败"); return }
	latestVersion := release.TagName

	if currentVersion == latestVersion {
		writeJSON(w, 200, map[string]string{"message": "当前已是最新版本 " + latestVersion + "，无需更新", "status": "latest"})
		return
	}

	var downloadURL string
	for _, asset := range release.Assets {
		if strings.Contains(asset.Name, "linux-amd64-compatible") && strings.HasSuffix(asset.Name, ".gz") {
			downloadURL = "https://ghproxy.net/" + asset.BrowserDownloadURL
			break
		}
	}
	if downloadURL == "" { writeErr(w, 500, "未找到适配的 linux-amd64 安装包"); return }

	tmp := "/tmp/mihomo_update.gz"
	if err := exec.Command("curl", "-fL", "-o", tmp, downloadURL).Run(); err != nil { writeErr(w, 500, "下载更新包失败，可能网络被阻断"); return }

	exec.Command("systemctl", "stop", "mihomo").Run()
	exec.Command("cp", "/opt/mihomo/mihomo", "/opt/mihomo/mihomo.bak").Run()
	data, _ := exec.Command("gunzip", "-c", tmp).Output()
	os.WriteFile("/opt/mihomo/mihomo", data, 0755)
	exec.Command("systemctl", "start", "mihomo").Run()

	writeJSON(w, 200, map[string]string{"message": "已成功更新至最新版本 " + latestVersion, "status": "updated"})
}

// ================= 日志与备份 =================
func (a *App) handleGetLogs(w http.ResponseWriter, r *http.Request) {
	cmd := exec.Command("journalctl", "-u", "s5m-next", "-n", "100", "--no-pager", "-o", "short-iso")
	output, _ := cmd.CombinedOutput()

	lines := strings.Split(string(output), "\n")
	var result []string
	for _, line := range lines {
		if strings.TrimSpace(line) == "" { continue }
		reHost := regexp.MustCompile(`\s+[a-zA-Z0-9.-]+\.bytevirt\.com\s+`)
		line = reHost.ReplaceAllString(line, " ")
		line = strings.ReplaceAll(line, " systemd[1]: ", " ")
		line = strings.ReplaceAll(line, "s5m-next.service:", "S5M:")
		reTime := regexp.MustCompile(`time=\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z?\s*`)
		line = reTime.ReplaceAllString(line, "")
		if len(line) >= 25 && line[10] == 'T' {
			timeStr := strings.Replace(line[:19], "T", " ", 1)
			line = timeStr + " " + strings.TrimSpace(line[25:])
		}
		result = append(result, line)
	}
	writeJSON(w, 200, map[string]string{"logs": strings.Join(result, "\n")})
}

func (a *App) handleDownloadBackup(w http.ResponseWriter, r *http.Request) {
	tokenStr := r.URL.Query().Get("token")
	if tokenStr == "" { writeErr(w, 401, "未登录"); return }
	t, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) { return a.jwtKey, nil }, jwt.WithValidMethods([]string{"HS256"}))
	if err != nil || !t.Valid { writeErr(w, 401, "登录已失效"); return }

	w.Header().Set("Content-Disposition", "attachment; filename=s5m_backup.db")
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeFile(w, r, a.cfg.DBPath)
}

func (a *App) handleRestoreBackup(w http.ResponseWriter, r *http.Request) {
	file, _, err := r.FormFile("file")
	if err != nil { writeErr(w, 400, "上传文件失败: "+err.Error()); return }
	defer file.Close()

	tmp := "/tmp/restore.db"
	out, err := os.Create(tmp)
	if err != nil { writeErr(w, 500, "创建临时文件失败"); return }
	defer out.Close()
	io.Copy(out, file)

	a.store.db.Close()
	if err := os.Rename(tmp, a.cfg.DBPath); err != nil { writeErr(w, 500, "覆盖数据库失败，请检查权限"); return }

	writeJSON(w, 200, map[string]string{"message": "数据库已成功覆盖，请手动重启 S5M 服务以生效！"})
}

// ================= 客户端订阅 =================
func (a *App) handleSubscribe(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	settings, _ := a.store.GetSettings()
	expectedToken := settings["sub_token"]

	if expectedToken == "" || token != expectedToken { writeErr(w, 403, "无效的订阅 token"); return }

	proxies, err := a.store.ListProxies()
	if err != nil { writeErr(w, 500, "获取节点失败"); return }

	var outs []proxyOut
	for _, p := range proxies {
		if !p.Enabled || p.Mode == "direct" || p.Mode == "reject" { continue }
		ex := map[string]any{}
		for k, v := range p.Extra {
			switch k {
			case "name", "type", "server", "port": continue
			}
			ex[k] = v
		}
		outs = append(outs, proxyOut{Name: p.Name, Type: p.Type, Server: p.Server, Port: p.Port, Extra: ex})
	}

	res := map[string]any{
		"proxies": outs,
		"rules":   []string{"MATCH,DIRECT"},
	}
	b, _ := yaml.Marshal(res)
	w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
	w.WriteHeader(200)
	w.Write(b)
}

// ================= 代理导入 =================
func parseProxyLine(line string) (*Proxy, error) {
	p := &Proxy{Mode: "proxy", SourceCIDR: "0.0.0.0/0", Enabled: true, Extra: map[string]any{}}
	if idx := strings.Index(line, "#"); idx != -1 {
		if unescaped, err := url.QueryUnescape(line[idx+1:]); err == nil { p.Name = unescaped } else { p.Name = line[idx+1:] }
		line = line[:idx]
	}
	schemeIdx := strings.Index(line, "://")
	if schemeIdx == -1 { return nil, fmt.Errorf("缺少协议前缀") }
	p.Type = line[:schemeIdx]
	line = line[schemeIdx+3:]

	var hostport string
	if atIdx := strings.LastIndex(line, "@"); atIdx != -1 {
		auth := line[:atIdx]
		hostport = line[atIdx+1:]
		if auth != ":" && auth != "" {
			parts := strings.SplitN(auth, ":", 2)
			if len(parts) > 0 && parts[0] != "" { p.Extra["username"] = parts[0] }
			if len(parts) > 1 && parts[1] != "" { p.Extra["password"] = parts[1] }
		}
	} else { hostport = line }

	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		if lastColon := strings.LastIndex(hostport, ":"); lastColon != -1 {
			host = hostport[:lastColon]
			portStr = hostport[lastColon+1:]
		} else { return nil, fmt.Errorf("无法解析主机和端口: %s", err) }
	}

	p.Server = host
	p.Port, err = strconv.Atoi(portStr)
	if err != nil { return nil, fmt.Errorf("端口不合法: %s", portStr) }
	if p.Name == "" { p.Name = fmt.Sprintf("%s-%s:%d", p.Type, p.Server, p.Port) }
	if p.Type == "vless" || p.Type == "vmess" || p.Type == "trojan" || p.Type == "socks5" { p.Extra["udp"] = true }
	return p, nil
}

func (a *App) handleImportProxies(w http.ResponseWriter, r *http.Request) {
	var in struct { Content string `json:"content"` }
	if err := decode(r, &in); err != nil { writeErr(w, 400, "参数错误"); return }

	successCount := 0
	var failReasons []string
	content := strings.TrimSpace(in.Content)

	type jsonImportServer struct {
		Server   string `json:"server"`
		Port     int    `json:"port"`
		Username string `json:"username"`
		Password string `json:"password"`
		UDP      bool   `json:"udp"`
	}
	type jsonImportConfig struct {
		Protocol string             `json:"protocol"`
		Servers  []jsonImportServer `json:"servers"`
	}
	var jsonCfg jsonImportConfig

	if err := json.Unmarshal([]byte(content), &jsonCfg); err == nil && len(jsonCfg.Servers) > 0 {
		for _, s := range jsonCfg.Servers {
			p := Proxy{Name: fmt.Sprintf("%s-%d", s.Server, s.Port), Mode: "proxy", Type: "socks5", Server: s.Server, Port: s.Port, SourceCIDR: "0.0.0.0/0", Enabled: true, Extra: map[string]any{"udp": s.UDP}}
			if s.Username != "" { p.Extra["username"] = s.Username }
			if s.Password != "" { p.Extra["password"] = s.Password }
			if err := a.store.CreateProxy(&p); err != nil {
				p.Name = fmt.Sprintf("%s-%d-%d", s.Server, s.Port, time.Now().UnixNano())
				if err := a.store.CreateProxy(&p); err != nil { failReasons = append(failReasons, fmt.Sprintf("节点 %s 存入失败: %v", p.Name, err)); continue }
			}
			successCount++
		}
	} else {
		lines := strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n")
		for i, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "//") { continue }
			p, err := parseProxyLine(line)
			if err != nil { failReasons = append(failReasons, fmt.Sprintf("第 %d 行解析失败: %v", i+1, err)); continue }
			if err := a.store.CreateProxy(p); err != nil {
				p.Name = p.Name + "-" + strconv.FormatInt(time.Now().UnixNano(), 36)
				if err := a.store.CreateProxy(p); err != nil { failReasons = append(failReasons, fmt.Sprintf("节点 %s 存入失败: %v", p.Name, err)); continue }
			}
			successCount++
		}
	}

	msg := "导入完成"
	if len(failReasons) > 0 { msg = strings.Join(failReasons, "; ") }
	writeJSON(w, 200, map[string]any{"success": successCount, "fail": len(failReasons), "message": msg})
}

// ================= Agent 自动注册 =================
func (a *App) handleAgentRegister(w http.ResponseWriter, r *http.Request) {
	var in struct {
		MachineCode string `json:"machine_code"`
		Secret      string `json:"secret"`
	}
	if err := decode(r, &in); err != nil || in.MachineCode == "" {
		writeErr(w, 400, "机器码不能为空")
		return
	}

	settings, _ := a.store.GetSettings()
	expectedSecret := settings["agent_token"]
	if expectedSecret == "" || in.Secret != expectedSecret {
		writeErr(w, 403, "注册密钥错误，拒绝接入！")
		return
	}

	claims := jwt.MapClaims{
		"sub":  in.MachineCode,
		"role": "agent",
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(a.jwtKey)
	if err != nil {
		writeErr(w, 500, "生成 Token 失败")
		return
	}

	a.store.UpdateSettings(map[string]string{
		"agent_machine_" + in.MachineCode: token,
	})

	writeJSON(w, 200, map[string]string{
		"message": "注册成功",
		"token":   token,
	})
}
