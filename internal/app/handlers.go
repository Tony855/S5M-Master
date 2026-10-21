package app

import (
"encoding/json"
"fmt"
"net"
"net/http"
"net/url"
"strconv"
"strings"
"time"

"golang.org/x/crypto/bcrypt"
)

func writeJSON(w http.ResponseWriter, code int, v any) {
w.Header().Set("Content-Type", "application/json; charset=utf-8")
w.WriteHeader(code)
_ = json.NewEncoder(w).Encode(v)
}
func writeErr(w http.ResponseWriter, code int, msg string) { writeJSON(w, code, map[string]string{"error": msg}) }
func decode(r *http.Request, v any) error { return json.NewDecoder(r.Body).Decode(v) }

func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
var in struct { Username string `json:"username"`; Password string `json:"password"` }
if err := decode(r, &in); err != nil { writeErr(w, 400, "参数错误"); return }
u, err := a.store.UserByUsername(in.Username)
if err != nil || !u.Enabled || bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(in.Password)) != nil { writeErr(w, 401, "用户名或密码错误"); return }
tok, _ := a.signToken(u)
writeJSON(w, 200, map[string]any{"token": tok, "user": u})
}

func (a *App) handleMe(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, currentUser(r)) }

func (a *App) handlePassword(w http.ResponseWriter, r *http.Request) {
var in struct { Old string `json:"old"`; New string `json:"new"` }
if err := decode(r, &in); err != nil || len(in.New) < 6 { writeErr(w, 400, "新密码至少 6 位"); return }
cu := currentUser(r)
u, err := a.store.UserByUsername(cu.Username)
if err != nil || bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(in.Old)) != nil { writeErr(w, 401, "原密码错误"); return }
h, _ := bcrypt.GenerateFromPassword([]byte(in.New), bcrypt.DefaultCost)
a.store.UpdatePassword(u.ID, string(h))
writeJSON(w, 200, map[string]string{"message": "密码已更新"})
}

func (a *App) handleGetSettings(w http.ResponseWriter, r *http.Request) { settings, _ := a.store.GetSettings(); writeJSON(w, 200, settings) }
func (a *App) handleUpdateSettings(w http.ResponseWriter, r *http.Request) {
var in map[string]string
if err := decode(r, &in); err != nil { writeErr(w, 400, "参数错误"); return }
a.store.UpdateSettings(in)
writeJSON(w, 200, map[string]string{"message": "设置已保存"})
}

func (a *App) handleListProxies(w http.ResponseWriter, r *http.Request) { list, _ := a.store.ListProxies(); writeJSON(w, 200, list) }

func (a *App) validateProxy(p *Proxy) string {
if p.Name == "" { return "名称不能为空" }
if p.Mode == "" { p.Mode = "proxy" }
if p.Mode == "proxy" || p.Mode == "china" || p.Mode == "game" {
if p.Type == "" || p.Server == "" || p.Port <= 0 { return "代理模式必须填写类型、服务器和端口" }
}
if p.SourceCIDR == "" { p.SourceCIDR = "0.0.0.0/0" }
if _, _, err := net.ParseCIDR(p.SourceCIDR); err != nil { return "源 IP 必须是合法 CIDR" }
return ""
}

func (a *App) handleCreateProxy(w http.ResponseWriter, r *http.Request) {
var p Proxy
if err := decode(r, &p); err != nil { writeErr(w, 400, "参数错误"); return }
if msg := a.validateProxy(&p); msg != "" { writeErr(w, 400, msg); return }
if p.Extra == nil { p.Extra = map[string]any{} }
if err := a.store.CreateProxy(&p); err != nil { writeErr(w, 409, err.Error()); return }
writeJSON(w, 200, p)
}

func (a *App) handleUpdateProxy(w http.ResponseWriter, r *http.Request) {
id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
var p Proxy
if err := decode(r, &p); err != nil { writeErr(w, 400, "参数错误"); return }
p.ID = id
if msg := a.validateProxy(&p); msg != "" { writeErr(w, 400, msg); return }
if p.Extra == nil { p.Extra = map[string]any{} }
if err := a.store.UpdateProxy(&p); err != nil { writeErr(w, 409, err.Error()); return }
writeJSON(w, 200, p)
}

func (a *App) handleDeleteProxy(w http.ResponseWriter, r *http.Request) {
id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
a.store.DeleteProxy(id)
writeJSON(w, 200, map[string]string{"message": "已删除"})
}

func (a *App) handlePreview(w http.ResponseWriter, r *http.Request) { yml, _ := a.BuildConfig(); writeJSON(w, 200, map[string]string{"yaml": yml}) }
func (a *App) handlePublish(w http.ResponseWriter, r *http.Request) {
cv, err := a.Publish()
if err != nil { writeJSON(w, 200, map[string]any{"ok": false, "message": err.Error(), "version": cv}); return }
writeJSON(w, 200, map[string]any{"ok": true, "message": "发布成功", "version": cv})
}
func (a *App) handleVersions(w http.ResponseWriter, r *http.Request) { list, _ := a.store.ListVersions(30); writeJSON(w, 200, list) }
func (a *App) handleRollback(w http.ResponseWriter, r *http.Request) {
var in struct { Version int `json:"version"` }
if err := decode(r, &in); err != nil || in.Version <= 0 { writeErr(w, 400, "无效"); return }
cv, err := a.Rollback(in.Version)
if err != nil { writeJSON(w, 200, map[string]any{"ok": false, "message": err.Error(), "version": cv}); return }
writeJSON(w, 200, map[string]any{"ok": true, "message": "回滚成功", "version": cv})
}
func (a *App) handleOverview(w http.ResponseWriter, r *http.Request) {
list, _ := a.store.ListProxies()
enabled := 0
for _, p := range list { if p.Enabled { enabled++ } }
writeJSON(w, 200, map[string]any{"mihomo": a.MihomoInfo(), "proxy_total": len(list), "proxy_enabled": enabled})
}

// ================= 极致的宽容解析器 =================
func parseProxyLine(line string) (*Proxy, error) {
p := &Proxy{ Mode: "proxy", SourceCIDR: "0.0.0.0/0", Enabled: true, Extra: map[string]any{} }

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
} else {
hostport = line
}

host, portStr, err := net.SplitHostPort(hostport)
if err != nil {
// 如果是没有中括号的 IPv6，兜底处理
if lastColon := strings.LastIndex(hostport, ":"); lastColon != -1 {
host = hostport[:lastColon]
portStr = hostport[lastColon+1:]
} else {
return nil, fmt.Errorf("无法解析主机和端口: %s", err)
}
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

type jsonImportServer struct { Server string `json:"server"`; Port int `json:"port"`; Username string `json:"username"`; Password string `json:"password"`; UDP bool `json:"udp"` }
type jsonImportConfig struct { Protocol string `json:"protocol"`; Servers []jsonImportServer `json:"servers"` }
var jsonCfg jsonImportConfig

if err := json.Unmarshal([]byte(content), &jsonCfg); err == nil && len(jsonCfg.Servers) > 0 {
for _, s := range jsonCfg.Servers {
p := Proxy{ Name: fmt.Sprintf("%s-%d", s.Server, s.Port), Mode: "proxy", Type: "socks5", Server: s.Server, Port: s.Port, SourceCIDR: "0.0.0.0/0", Enabled: true, Extra: map[string]any{"udp": s.UDP} }
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
writeJSON(w, 200, map[string]any{ "success": successCount, "fail": len(failReasons), "message": msg })
}
