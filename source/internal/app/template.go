package app

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type mihomoTemplateVersion struct {
	Version int    `json:"version"`
	SHA256 string `json:"sha256"`
	Note string `json:"note"`
	CreatedAt string `json:"created_at"`
}

func (a *App) ensureTemplateSchema() error {
	_, err := a.store.db.Exec(`
CREATE TABLE IF NOT EXISTS mihomo_template_versions (
 version INTEGER PRIMARY KEY,
 yaml_text TEXT NOT NULL,
 sha256 TEXT NOT NULL,
 note TEXT NOT NULL DEFAULT '',
 created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS node_template_bindings (
 machine_code TEXT PRIMARY KEY,
 template_version INTEGER NOT NULL DEFAULT 0,
 config_sha256 TEXT NOT NULL DEFAULT '',
 source TEXT NOT NULL DEFAULT 'independent',
 updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS node_template_history (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 machine_code TEXT NOT NULL,
 previous_yaml TEXT NOT NULL,
 previous_template_version INTEGER NOT NULL DEFAULT 0,
 previous_source TEXT NOT NULL DEFAULT 'independent',
 created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_node_template_history_machine ON node_template_history(machine_code, id DESC);
`)
	return err
}

func validateMihomoTemplate(yml string) error {
	if strings.TrimSpace(yml) == "" { return fmt.Errorf("模板 YAML 不能为空") }
	var cfg map[string]any
	if err := yaml.Unmarshal([]byte(yml), &cfg); err != nil { return fmt.Errorf("YAML 语法错误: %w", err) }
	if len(cfg) == 0 { return fmt.Errorf("模板配置不能为空") }
	if secret, ok := cfg["secret"]; ok {
		if value, ok := secret.(string); !ok || strings.TrimSpace(value) == "" { return fmt.Errorf("secret 必须是非空字符串") }
	}
	if tun, ok := cfg["tun"]; ok {
		if _, ok := tun.(map[string]any); !ok { return fmt.Errorf("tun 必须是 YAML 配置块") }
	}
	if dns, ok := cfg["dns"]; ok {
		if _, ok := dns.(map[string]any); !ok { return fmt.Errorf("dns 必须是 YAML 配置块") }
	}
	return nil
}

func hashConfig(yml string) string {
	sum := sha256.Sum256([]byte(yml))
	return hex.EncodeToString(sum[:])
}

func (a *App) handleGetMihomoTemplate(w http.ResponseWriter, r *http.Request) {
	draft, _ := a.store.GetSetting("mihomo_template_draft")
	currentRaw, _ := a.store.GetSetting("mihomo_template_current_version")
	current := 0
	fmt.Sscanf(currentRaw, "%d", &current)
	rows, err := a.store.db.Query("SELECT version, sha256, note, created_at FROM mihomo_template_versions ORDER BY version DESC")
	if err != nil { writeErr(w, 500, "读取模板版本失败"); return }
	defer rows.Close()
	versions := make([]mihomoTemplateVersion, 0)
	for rows.Next() {
		var v mihomoTemplateVersion
		if err := rows.Scan(&v.Version, &v.SHA256, &v.Note, &v.CreatedAt); err != nil { writeErr(w, 500, "读取模板版本失败"); return }
		versions = append(versions, v)
	}
	if err := rows.Err(); err != nil { writeErr(w, 500, "读取模板版本失败"); return }
	writeJSON(w, 200, map[string]any{"draft_yaml": draft, "current_version": current, "versions": versions})
}

func (a *App) handleSaveMihomoTemplateDraft(w http.ResponseWriter, r *http.Request) {
	var in struct { YAML string `json:"yaml"` }
	if err := decodeLimited(r, 2<<20, "2 MiB", &in); err != nil { writeErr(w, 400, "请求 JSON 无效或超过 2 MiB"); return }
	if err := validateMihomoTemplate(in.YAML); err != nil { writeErr(w, 400, err.Error()); return }
	if err := a.store.UpdateSettings(map[string]string{"mihomo_template_draft": in.YAML}); err != nil { writeErr(w, 500, "保存模板草稿失败"); return }
	writeJSON(w, 200, map[string]string{"message":"模板草稿已保存；尚未发布，也不会覆盖任何节点"})
}

func (a *App) handlePublishMihomoTemplate(w http.ResponseWriter, r *http.Request) {
	var in struct { Note string `json:"note"` }
	if r.Body != nil { _ = decodeLimited(r, 16<<10, "16 KiB", &in) }
	draft, err := a.store.GetSetting("mihomo_template_draft")
	if err != nil || strings.TrimSpace(draft) == "" { writeErr(w, 400, "请先保存模板草稿"); return }
	if err := validateMihomoTemplate(draft); err != nil { writeErr(w, 400, err.Error()); return }
	tx, err := a.store.db.Begin()
	if err != nil { writeErr(w, 500, "创建模板版本失败"); return }
	defer tx.Rollback()
	var current int
	_ = tx.QueryRow("SELECT COALESCE(MAX(version),0) FROM mihomo_template_versions").Scan(&current)
	next := current + 1
	created := time.Now().UTC().Format(time.RFC3339)
	if _, err = tx.Exec("INSERT INTO mihomo_template_versions(version,yaml_text,sha256,note,created_at) VALUES(?,?,?,?,?)", next, draft, hashConfig(draft), strings.TrimSpace(in.Note), created); err != nil {
		writeErr(w, 500, "发布模板版本失败"); return
	}
	if _, err = tx.Exec("INSERT INTO settings(key,value) VALUES('mihomo_template_current_version',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", fmt.Sprint(next)); err != nil {
		writeErr(w, 500, "更新当前模板版本失败"); return
	}
	if err = tx.Commit(); err != nil { writeErr(w, 500, "提交模板版本失败"); return }
	writeJSON(w, 200, map[string]any{"message":"模板已发布；已有节点不会自动更新", "version":next, "sha256":hashConfig(draft)})
}

func (a *App) handleGetNodeTemplateStatus(w http.ResponseWriter, r *http.Request) {
	settings, err := a.store.GetSettings()
	if err != nil { writeErr(w, 500, "读取节点授权状态失败"); return }
	current := 0
	fmt.Sscanf(settings["mihomo_template_current_version"], "%d", &current)
	rows, err := a.store.db.Query("SELECT machine_code, template_version, config_sha256, source, updated_at FROM node_template_bindings")
	if err != nil { writeErr(w, 500, "读取节点模板状态失败"); return }
	defer rows.Close()
	type state struct {
		MachineCode string `json:"machine_code"`
		TemplateVersion int `json:"template_version"`
		LatestVersion int `json:"latest_version"`
		ConfigSHA256 string `json:"config_sha256"`
		Source string `json:"source"`
		Status string `json:"status"`
		UpdatedAt string `json:"updated_at"`
	}
	bindings := map[string]state{}
	for rows.Next() {
		var s state
		if err := rows.Scan(&s.MachineCode, &s.TemplateVersion, &s.ConfigSHA256, &s.Source, &s.UpdatedAt); err != nil { writeErr(w, 500, "读取节点模板状态失败"); return }
		s.LatestVersion = current
		if s.Source == "independent" { s.Status = "independent" } else if s.TemplateVersion < current { s.Status = "outdated" } else { s.Status = "current" }
		bindings[s.MachineCode] = s
	}
	codes := make([]string,0)
	for key, value := range settings { if strings.HasPrefix(key,"agent_machine_") && value != "" && value != settings["agent_token"] { codes = append(codes, strings.TrimPrefix(key,"agent_machine_")) } }
	sort.Strings(codes)
	out := make([]state,0,len(codes))
	for _, code := range codes {
		s, ok := bindings[code]
		if !ok { s = state{MachineCode:code, LatestVersion:current, Source:"untracked", Status:"untracked"} }
		// Compare the stored configuration hash to identify manual edits after template application.
		if s.Source != "untracked" && s.Source != "independent" {
			if cfg, e := a.store.GetNodeConfig(code); e == nil && cfg != nil && hashConfig(cfg.YAML) != s.ConfigSHA256 { s.Status = "drifted" }
		}
		out = append(out,s)
	}
	writeJSON(w,200,map[string]any{"current_version":current,"nodes":out})
}

func (a *App) handleApplyMihomoTemplate(w http.ResponseWriter, r *http.Request) {
	var in struct {
		MachineCode string `json:"machine_code"`
		Version int `json:"version"`
		Confirm bool `json:"confirm"`
	}
	if err := decodeLimited(r, 16<<10, "16 KiB", &in); err != nil { writeErr(w,400,"请求 JSON 无效"); return }
	code := strings.TrimSpace(in.MachineCode)
	if code == "" || in.Version < 1 { writeErr(w,400,"必须选择节点和有效模板版本"); return }
	if !in.Confirm { writeErr(w,400,"必须明确确认覆盖所选节点配置"); return }
	settings, err := a.store.GetSettings()
	if err != nil { writeErr(w,500,"读取节点授权状态失败"); return }
	mt := settings["agent_machine_"+code]
	if mt == "" || mt == settings["agent_token"] { writeErr(w,404,"节点未授权"); return }
	var template string
	if err := a.store.db.QueryRow("SELECT yaml_text FROM mihomo_template_versions WHERE version=?",in.Version).Scan(&template); err != nil {
		if err == sql.ErrNoRows { writeErr(w,404,"模板版本不存在") } else { writeErr(w,500,"读取模板版本失败") }; return
	}
	// Reuse the node config validator so invalid or incomplete configs cannot be applied.
	if err := validateMihomoTemplate(template); err != nil { writeErr(w,400,"模板不能应用: "+err.Error()); return }
	var cfg map[string]any
	if err := yaml.Unmarshal([]byte(template), &cfg); err != nil { writeErr(w,400,"模板 YAML 无效"); return }
	if secret, ok := cfg["secret"].(string); !ok || strings.TrimSpace(secret)=="" { writeErr(w,400,"应用到节点的完整配置必须包含非空 secret"); return }
	if _, ok := cfg["tun"]; !ok { writeErr(w,400,"应用到节点的完整配置必须包含 tun 配置块"); return }
	if _, ok := cfg["dns"]; !ok { writeErr(w,400,"应用到节点的完整配置必须包含 dns 配置块"); return }
	tx, err := a.store.db.Begin()
	if err != nil { writeErr(w,500,"开始应用模板事务失败"); return }
	defer tx.Rollback()
	var oldYAML string
	_ = tx.QueryRow("SELECT yaml_text FROM node_configs WHERE machine_code=?",code).Scan(&oldYAML)
	var oldVersion int
	var oldSource string
	_ = tx.QueryRow("SELECT template_version,source FROM node_template_bindings WHERE machine_code=?",code).Scan(&oldVersion,&oldSource)
	if oldSource == "" { oldSource = "independent" }
	if strings.TrimSpace(oldYAML)!="" {
		if _,err=tx.Exec("INSERT INTO node_template_history(machine_code,previous_yaml,previous_template_version,previous_source,created_at) VALUES(?,?,?,?,?)",code,oldYAML,oldVersion,oldSource,time.Now().UTC().Format(time.RFC3339)); err!=nil { writeErr(w,500,"备份原节点配置失败"); return }
	}
	now:=time.Now().UTC().Format(time.RFC3339)
	if _,err=tx.Exec("INSERT INTO node_configs(machine_code,yaml_text,updated_at) VALUES(?,?,?) ON CONFLICT(machine_code) DO UPDATE SET yaml_text=excluded.yaml_text,updated_at=excluded.updated_at",code,template,now); err!=nil { writeErr(w,500,"保存节点配置失败"); return }
	if _,err=tx.Exec("INSERT INTO node_template_bindings(machine_code,template_version,config_sha256,source,updated_at) VALUES(?,?,?,?,?) ON CONFLICT(machine_code) DO UPDATE SET template_version=excluded.template_version,config_sha256=excluded.config_sha256,source=excluded.source,updated_at=excluded.updated_at",code,in.Version,hashConfig(template),"template",now); err!=nil { writeErr(w,500,"保存节点模板版本信息失败"); return }
	if err=tx.Commit(); err!=nil { writeErr(w,500,"提交节点模板配置失败"); return }
	writeJSON(w,200,map[string]any{"message":"模板已应用到所选节点；原配置已备份，Agent 将在下一次拉取时获取配置","machine_code":code,"template_version":in.Version})
}

// Ensure the file's JSON contract stays explicit for future API evolution.
var _ = json.Valid
