package app

import (
	"encoding/json"
	"net"
	"net/http"
	"strconv"

	"golang.org/x/crypto/bcrypt"
)

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func decode(r *http.Request, v any) error {
	return json.NewDecoder(r.Body).Decode(v)
}

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
	tok, err := a.signToken(u)
	if err != nil {
		writeErr(w, 500, "签发令牌失败")
		return
	}
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
	if err := a.store.UpdatePassword(u.ID, string(h)); err != nil {
		writeErr(w, 500, "更新失败")
		return
	}
	writeJSON(w, 200, map[string]string{"message": "密码已更新"})
}

func (a *App) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	settings, err := a.store.GetSettings()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, settings)
}

func (a *App) handleUpdateSettings(w http.ResponseWriter, r *http.Request) {
	var in map[string]string
	if err := decode(r, &in); err != nil {
		writeErr(w, 400, "参数错误")
		return
	}
	if err := a.store.UpdateSettings(in); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]string{"message": "设置已保存"})
}

func (a *App) handleListProxies(w http.ResponseWriter, r *http.Request) {
	list, err := a.store.ListProxies()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, list)
}

func (a *App) validateProxy(p *Proxy) string {
	if p.Name == "" || p.Type == "" || p.Server == "" || p.Port <= 0 || p.Port > 65535 {
		return "名称/类型/服务器/端口 必填且端口合法"
	}
	if p.SourceCIDR == "" {
		p.SourceCIDR = "0.0.0.0/0"
	}
	if _, _, err := net.ParseCIDR(p.SourceCIDR); err != nil {
		return "源 IP 必须是合法 CIDR，例如 192.168.1.10/32"
	}
	switch p.Type {
	case "socks5", "ss", "vmess", "vless", "trojan":
	default:
		return "不支持的协议类型"
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
		writeErr(w, 409, "创建失败: "+err.Error())
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
		writeErr(w, 409, "更新失败: "+err.Error())
		return
	}
	writeJSON(w, 200, p)
}

func (a *App) handleDeleteProxy(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err := a.store.DeleteProxy(id); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]string{"message": "已删除"})
}

func (a *App) handlePreview(w http.ResponseWriter, r *http.Request) {
	yml, err := a.BuildConfig()
	if err != nil {
		writeErr(w, 500, err.Error())
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
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, list)
}

func (a *App) handleRollback(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Version int `json:"version"`
	}
	if err := decode(r, &in); err != nil || in.Version <= 0 {
		writeErr(w, 400, "版本号无效")
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
	writeJSON(w, 200, map[string]any{
		"mihomo":        a.MihomoInfo(),
		"proxy_total":   len(list),
		"proxy_enabled": enabled,
	})
}
