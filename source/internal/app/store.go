package app

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct{ db *sql.DB }

type User struct {
	ID           int64  `json:"id"`
	Username     string `json:"username"`
	PasswordHash string `json:"-"`
	Role         string `json:"role"`
	Enabled      bool   `json:"enabled"`
}

type Instance struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	MachineCode string `json:"machine_code"`
	APIURL      string `json:"api_url"`
}

type Proxy struct {
	ID          int64          `json:"id"`
	Name        string         `json:"name"`
	Mode        string         `json:"mode"`
	Type        string         `json:"type"`
	Server      string         `json:"server"`
	Port        int            `json:"port"`
	SourceCIDR  string         `json:"source_cidr"`
	MachineCode string         `json:"machine_code"`
	Extra       map[string]any `json:"extra"`
	Enabled     bool           `json:"enabled"`
}

type ConfigVersion struct {
	ID        int64  `json:"id"`
	Version   int    `json:"version"`
	SHA256    string `json:"sha256"`
	Status    string `json:"status"`
	CreatedAt string `json:"created_at"`
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func OpenStore(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) migrate() error {
	schema := `
CREATE TABLE IF NOT EXISTS users(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 username TEXT NOT NULL UNIQUE,
 password_hash TEXT NOT NULL,
 role TEXT NOT NULL DEFAULT 'admin',
 enabled INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS instances(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL UNIQUE,
 machine_code TEXT NOT NULL DEFAULT '',
 api_url TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS proxies(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL UNIQUE,
 mode TEXT NOT NULL DEFAULT 'proxy',
 type TEXT NOT NULL,
 server TEXT NOT NULL,
 port INTEGER NOT NULL,
 source_cidr TEXT NOT NULL DEFAULT '0.0.0.0/0',
 machine_code TEXT NOT NULL DEFAULT '',
 config_json TEXT NOT NULL DEFAULT '{}',
 enabled INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS config_versions(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 version INTEGER NOT NULL UNIQUE,
 sha256 TEXT NOT NULL,
 yaml_text TEXT NOT NULL,
 status TEXT NOT NULL,
 created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS node_configs(
    machine_code TEXT PRIMARY KEY,
    yaml_text TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS settings(
 key TEXT PRIMARY KEY,
 value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS agent_instances(
 machine_code TEXT NOT NULL,
 agent_type TEXT NOT NULL CHECK(agent_type IN ('mihomo','wireguard')),
 instance_id TEXT NOT NULL,
 credential_sha256 TEXT NOT NULL,
 status_json TEXT NOT NULL DEFAULT '{}',
 last_seen INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL,
 PRIMARY KEY(machine_code, agent_type, instance_id)
);
CREATE TABLE IF NOT EXISTS agent_instance_configs(
 machine_code TEXT NOT NULL,
 agent_type TEXT NOT NULL,
 instance_id TEXT NOT NULL,
 yaml_text TEXT NOT NULL,
 sha256 TEXT NOT NULL,
 updated_at TEXT NOT NULL,
 PRIMARY KEY(machine_code, agent_type, instance_id),
 FOREIGN KEY(machine_code, agent_type, instance_id)
   REFERENCES agent_instances(machine_code, agent_type, instance_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS agent_instance_commands(
 machine_code TEXT NOT NULL,
 agent_type TEXT NOT NULL,
 instance_id TEXT NOT NULL,
 command_id TEXT NOT NULL,
 command_json TEXT NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('pending','success','failed')),
 result_message TEXT NOT NULL DEFAULT '',
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL,
 PRIMARY KEY(machine_code, agent_type, instance_id, command_id),
 FOREIGN KEY(machine_code, agent_type, instance_id)
   REFERENCES agent_instances(machine_code, agent_type, instance_id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_instance_one_pending_command
 ON agent_instance_commands(machine_code, agent_type, instance_id) WHERE status='pending';
CREATE INDEX IF NOT EXISTS idx_agent_instance_command_latest
 ON agent_instance_commands(machine_code, agent_type, instance_id, updated_at DESC, created_at DESC, command_id DESC);
CREATE INDEX IF NOT EXISTS idx_agent_instances_machine ON agent_instances(machine_code);
CREATE INDEX IF NOT EXISTS idx_cv_version ON config_versions(version DESC);
`
	_, err := s.db.Exec(schema)
	if err != nil {
		return err
	}
	// Remove the obsolete table used only by the deleted container-management telemetry.
	if _, err := s.db.Exec(`DROP TABLE IF EXISTS agent_status`); err != nil {
		return fmt.Errorf("清理已废弃的 Agent 状态表失败: %w", err)
	}
	// 安全补全旧表字段
	var count int
	s.db.QueryRow("SELECT count(*) FROM pragma_table_info('proxies') WHERE name='machine_code'").Scan(&count)
	if count == 0 {
		s.db.Exec("ALTER TABLE proxies ADD COLUMN machine_code TEXT NOT NULL DEFAULT ''")
	}

	if err := s.migrateLegacyAgentInstances(); err != nil {
		return fmt.Errorf("迁移旧 Agent 身份到实例表失败: %w", err)
	}

	// TUN is disabled by default for new installations. Preserve an existing explicit operator choice.
	s.db.Exec(`INSERT OR IGNORE INTO settings (key, value) VALUES ('tun_enable', 'false')`)
	// 首次启动时自动生成随机 Agent 注册密钥（不再硬编码默认值）
	var atCount int
	s.db.QueryRow(`SELECT COUNT(*) FROM settings WHERE key='agent_token' AND value != ''`).Scan(&atCount)
	if atCount == 0 {
		buf := make([]byte, 16)
		if _, err := rand.Read(buf); err == nil {
			token := fmt.Sprintf("s5m-%x", buf)
			s.db.Exec(`INSERT OR REPLACE INTO settings (key, value) VALUES ('agent_token', ?)`, token)
		}
	}
	return nil
}

// migrateLegacyAgentInstances copies legacy machine-scoped credentials and telemetry
// into the instance table as the default Mihomo instance. Legacy settings remain
// untouched during this compatibility phase, so existing Agents keep authenticating.
func (s *Store) migrateLegacyAgentInstances() error {
	rows, err := s.db.Query(`SELECT key, value FROM settings WHERE substr(key, 1, 14) = 'agent_machine_'`)
	if err != nil {
		return err
	}
	type legacyAgent struct {
		machineCode string
		secret      string
	}
	var agents []legacyAgent
	for rows.Next() {
		var key, secret string
		if err := rows.Scan(&key, &secret); err != nil {
			rows.Close()
			return err
		}
		code := strings.TrimPrefix(key, "agent_machine_")
		if len(code) == 0 || len(code) > 64 || strings.TrimSpace(secret) == "" {
			continue
		}
		valid := true
		for _, ch := range code {
			if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
				(ch >= '0' && ch <= '9') || ch == '_' || ch == '-') {
				valid = false
				break
			}
		}
		if valid {
			agents = append(agents, legacyAgent{machineCode: code, secret: secret})
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if len(agents) == 0 {
		return nil
	}

	settings, err := s.GetSettings()
	if err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for _, agent := range agents {
		sum := sha256.Sum256([]byte(agent.secret))
		status := settings["agent_status_"+agent.machineCode]
		agentType := "mihomo"
		if !json.Valid([]byte(status)) {
			status = "{}"
		} else {
			var telemetry map[string]any
			if json.Unmarshal([]byte(status), &telemetry) == nil {
				if reportedType, ok := telemetry["agent_type"].(string); ok && reportedType == "wireguard" {
					agentType = "wireguard"
				}
			}
		}
		lastSeen, parseErr := strconv.ParseInt(strings.TrimSpace(settings["agent_lastseen_"+agent.machineCode]), 10, 64)
		if parseErr != nil || lastSeen < 0 {
			lastSeen = 0
		}
		_, err := tx.Exec(`INSERT INTO agent_instances(
			machine_code, agent_type, instance_id, credential_sha256,
			status_json, last_seen, created_at, updated_at
		) VALUES(?, ?, 'default', ?, ?, ?, ?, ?)
		ON CONFLICT(machine_code, agent_type, instance_id) DO NOTHING`,
			agent.machineCode, agentType, hex.EncodeToString(sum[:]), status, lastSeen, now, now)
		if err != nil {
			return fmt.Errorf("迁移机器 %q 的旧 Agent 身份失败: %w", agent.machineCode, err)
		}
	}
	return tx.Commit()
}

func (s *Store) GetSetting(key string) (string, error) {
	var value string
	err := s.db.QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&value)
	return value, err
}

func (s *Store) GetSettings() (map[string]string, error) {
	rows, err := s.db.Query(`SELECT key, value FROM settings`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	res := make(map[string]string)
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, fmt.Errorf("读取设置行失败: %w", err)
		}
		res[k] = v
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("遍历设置记录失败: %w", err)
	}
	return res, nil
}

// CreateSettingIfAbsent 原子创建配置项；若 key 已存在，不覆盖已有值。
func (s *Store) CreateSettingIfAbsent(key, value string) (bool, error) {
	result, err := s.db.Exec(
		`INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO NOTHING`,
		key, value,
	)
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

func (s *Store) UpdateSettings(updates map[string]string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for k, v := range updates {
		if _, err := tx.Exec(
			`INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
			k, v,
		); err != nil {
			return fmt.Errorf("update setting %q: %w", k, err)
		}
	}

	return tx.Commit()
}

// AckAgentCommand atomically commits a command result and removes only the matching
// pending command. A retry is accepted only when the persisted result has the same ID.
// matched=false means the command was replaced or no longer exists.
func (s *Store) AckAgentCommand(machineCode, commandID, status, message string, updatedAt int64) (duplicate bool, matched bool, err error) {
	tx, err := s.db.Begin()
	if err != nil {
		return false, false, err
	}
	defer tx.Rollback()

	pendingKey := "agent_command_" + machineCode
	resultKey := "agent_command_result_" + machineCode
	var raw string
	err = tx.QueryRow(`SELECT value FROM settings WHERE key=?`, pendingKey).Scan(&raw)
	pendingExists := err == nil
	if err == sql.ErrNoRows {
		raw = ""
	} else if err != nil {
		return false, false, err
	}
	var pending map[string]string
	if raw != "" && json.Unmarshal([]byte(raw), &pending) == nil && pending["id"] == commandID {
		result, marshalErr := json.Marshal(map[string]any{
			"id": commandID, "type": pending["type"], "status": status,
			"message": message, "updated_at": updatedAt,
		})
		if marshalErr != nil {
			return false, false, marshalErr
		}
		if _, err := tx.Exec(`INSERT INTO settings(key,value) VALUES(?,?)
			ON CONFLICT(key) DO UPDATE SET value=excluded.value`, resultKey, string(result)); err != nil {
			return false, false, err
		}
		if _, err := tx.Exec(`DELETE FROM settings WHERE key=? AND value=?`, pendingKey, raw); err != nil {
			return false, false, err
		}
		if err := tx.Commit(); err != nil {
			return false, false, err
		}
		return false, true, nil
	}

	// A different or malformed pending command takes precedence over an old
	// result: an ACK for that old ID must not be accepted as a duplicate while
	// a replacement command is waiting for acknowledgement.
	if pendingExists {
		return false, false, nil
	}

	var previous string
	err = tx.QueryRow(`SELECT value FROM settings WHERE key=?`, resultKey).Scan(&previous)
	if err != nil && err != sql.ErrNoRows {
		return false, false, err
	}
	var previousResult map[string]any
	if err == nil && json.Unmarshal([]byte(previous), &previousResult) == nil && previousResult["id"] == commandID {
		return true, true, nil
	}
	return false, false, nil
}

func (s *Store) CountUsers() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

func (s *Store) CreateUser(username, hash, role string) error {
	_, err := s.db.Exec(`INSERT INTO users(username,password_hash,role) VALUES(?,?,?)`, username, hash, role)
	return err
}

func (s *Store) UserByUsername(name string) (*User, error) {
	u := &User{}
	var en int
	err := s.db.QueryRow(`SELECT id,username,password_hash,role,enabled FROM users WHERE username=?`, name).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &en)
	if err != nil {
		return nil, err
	}
	u.Enabled = en == 1
	return u, nil
}

func (s *Store) UpdatePassword(id int64, hash string) error {
	_, err := s.db.Exec(`UPDATE users SET password_hash=? WHERE id=?`, hash, id)
	return err
}

func (s *Store) ListInstances() ([]Instance, error) {
	rows, err := s.db.Query(`SELECT id,name,machine_code,api_url FROM instances ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Instance
	for rows.Next() {
		var i Instance
		if err := rows.Scan(&i.ID, &i.Name, &i.MachineCode, &i.APIURL); err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, nil
}

func (s *Store) CreateInstance(i *Instance) error {
	res, err := s.db.Exec(`INSERT INTO instances(name,machine_code,api_url) VALUES(?,?,?)`, i.Name, i.MachineCode, i.APIURL)
	if err != nil {
		return err
	}
	i.ID, _ = res.LastInsertId()
	return nil
}

func (s *Store) DeleteInstance(id int64) error {
	_, err := s.db.Exec(`DELETE FROM instances WHERE id=?`, id)
	return err
}

func (s *Store) ListProxies() ([]Proxy, error) {
	rows, err := s.db.Query(`SELECT id,name,mode,type,server,port,source_cidr,machine_code,config_json,enabled FROM proxies ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Proxy
	for rows.Next() {
		var p Proxy
		var extra string
		var en int
		if err := rows.Scan(&p.ID, &p.Name, &p.Mode, &p.Type, &p.Server, &p.Port, &p.SourceCIDR, &p.MachineCode, &extra, &en); err != nil {
			return nil, err
		}
		p.Enabled = en == 1
		p.Extra = map[string]any{}
		_ = json.Unmarshal([]byte(extra), &p.Extra)
		out = append(out, p)
	}
	return out, nil
}

func (s *Store) GetProxy(id int64) (*Proxy, error) {
	var p Proxy
	var extra string
	var en int
	err := s.db.QueryRow(`SELECT id,name,mode,type,server,port,source_cidr,machine_code,config_json,enabled FROM proxies WHERE id=?`, id).
		Scan(&p.ID, &p.Name, &p.Mode, &p.Type, &p.Server, &p.Port, &p.SourceCIDR, &p.MachineCode, &extra, &en)
	if err != nil {
		return nil, err
	}
	p.Enabled = en == 1
	p.Extra = map[string]any{}
	_ = json.Unmarshal([]byte(extra), &p.Extra)
	return &p, nil
}

func (s *Store) CreateProxy(p *Proxy) error {
	extra, _ := json.Marshal(p.Extra)
	res, err := s.db.Exec(`INSERT INTO proxies(name,mode,type,server,port,source_cidr,machine_code,config_json,enabled) VALUES(?,?,?,?,?,?,?,?,?)`, p.Name, p.Mode, p.Type, p.Server, p.Port, p.SourceCIDR, p.MachineCode, string(extra), b2i(p.Enabled))
	if err != nil {
		return err
	}
	p.ID, _ = res.LastInsertId()
	return nil
}

func (s *Store) UpdateProxy(p *Proxy) error {
	extra, _ := json.Marshal(p.Extra)
	_, err := s.db.Exec(`UPDATE proxies SET name=?,mode=?,type=?,server=?,port=?,source_cidr=?,machine_code=?,config_json=?,enabled=? WHERE id=?`, p.Name, p.Mode, p.Type, p.Server, p.Port, p.SourceCIDR, p.MachineCode, string(extra), b2i(p.Enabled), p.ID)
	return err
}

func (s *Store) DeleteProxy(id int64) error {
	_, err := s.db.Exec(`DELETE FROM proxies WHERE id=?`, id)
	return err
}

func (s *Store) NextVersion() (int, error) {
	var v int
	err := s.db.QueryRow(`SELECT COALESCE(MAX(version),0)+1 FROM config_versions`).Scan(&v)
	return v, err
}

func (s *Store) InsertVersion(v int, sha, yml, status string) error {
	_, err := s.db.Exec(`INSERT INTO config_versions(version,sha256,yaml_text,status,created_at) VALUES(?,?,?,?,?)`, v, sha, yml, status, time.Now().Format(time.RFC3339))
	return err
}

func (s *Store) UpdateVersionStatus(version int, status string) error {
	_, err := s.db.Exec(
		`UPDATE config_versions SET status=? WHERE version=?`,
		status, version,
	)
	if err != nil {
		return err
	}
	return nil
}

func (s *Store) ListVersions(limit int) ([]ConfigVersion, error) {
	rows, err := s.db.Query(`SELECT id,version,sha256,status,created_at FROM config_versions ORDER BY version DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ConfigVersion
	for rows.Next() {
		var v ConfigVersion
		if err := rows.Scan(&v.ID, &v.Version, &v.SHA256, &v.Status, &v.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func (s *Store) VersionYAML(version int) (string, error) {
	var y string
	err := s.db.QueryRow(`SELECT yaml_text FROM config_versions WHERE version=?`, version).Scan(&y)
	return y, err
}

func (s *Store) DeleteSettings(keys []string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, k := range keys {
		if _, err := tx.Exec("DELETE FROM settings WHERE key=?", k); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// DeleteAgentBinding atomically revokes a machine credential and clears live node status.
// The node's YAML is retained for audit/re-registration.
func (s *Store) DeleteAgentBinding(machineCode string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, key := range []string{"agent_machine_" + machineCode, "agent_lastseen_" + machineCode, "agent_status_" + machineCode, "agent_command_" + machineCode, "agent_command_result_" + machineCode, "agent_secret_" + machineCode, "agent_mihomo_secret_" + machineCode} {
		if _, err := tx.Exec(`DELETE FROM settings WHERE key=?`, key); err != nil {
			return err
		}
	}
	// Revoke every composite Agent identity for this machine in the same
	// transaction. Configs and command queues cascade with their parent identity.
	if _, err := tx.Exec(`DELETE FROM agent_instances WHERE machine_code=?`, machineCode); err != nil {
		return err
	}
	// Remove the live template binding in the same transaction as revoking the
	// machine credential. Keep node_configs and node_template_history for audit
	// and possible re-registration; only the active binding must disappear.
	var hasTemplateBindings int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='node_template_bindings'`).Scan(&hasTemplateBindings); err != nil {
		return err
	}
	if hasTemplateBindings > 0 {
		if _, err := tx.Exec(`DELETE FROM node_template_bindings WHERE machine_code=?`, machineCode); err != nil {
			return err
		}
	}
	return tx.Commit()
}

type NodeConfig struct {
	MachineCode string `json:"machine_code"`
	YAML        string `json:"config_yaml"`
	UpdatedAt   string `json:"updated_at"`
}

func (s *Store) GetNodeConfig(machineCode string) (*NodeConfig, error) {
	c := &NodeConfig{}
	err := s.db.QueryRow(
		`SELECT machine_code, yaml_text, updated_at
         FROM node_configs WHERE machine_code=?`,
		machineCode,
	).Scan(&c.MachineCode, &c.YAML, &c.UpdatedAt)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return c, nil
}

func (s *Store) SaveNodeConfig(machineCode, yamlText string) error {
	_, err := s.db.Exec(`INSERT INTO node_configs(machine_code,yaml_text,updated_at) VALUES(?,?,?) ON CONFLICT(machine_code) DO UPDATE SET yaml_text=excluded.yaml_text, updated_at=excluded.updated_at`, machineCode, yamlText, time.Now().Format(time.RFC3339))
	return err
}

// SaveNodeConfigIfUnchanged performs an optimistic write. It updates an existing
// row only when the YAML still matches the caller's snapshot; an absent row may
// be initialized only when expectedYAML is empty. This prevents background
// normalization from overwriting a newer manual edit.
func (s *Store) SaveNodeConfigIfUnchanged(machineCode, expectedYAML, yamlText string) (bool, error) {
	result, err := s.db.Exec(`INSERT INTO node_configs(machine_code,yaml_text,updated_at) VALUES(?,?,?)
		ON CONFLICT(machine_code) DO UPDATE SET yaml_text=excluded.yaml_text, updated_at=excluded.updated_at
		WHERE node_configs.yaml_text=?`,
		machineCode, yamlText, time.Now().Format(time.RFC3339), expectedYAML)
	if err != nil {
		return false, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	return affected == 1, nil
}

// SaveNodeConfigIfEmpty 只初始化不存在或内容为空的节点配置。
// 已存在的非空 YAML 不会被自动同步覆盖。
// SaveNodeConfigs atomically replaces a batch of node configurations.
// If any write fails, the transaction rolls back so nodes cannot be left on a
// partially synchronized generation.
func (s *Store) SaveNodeConfigs(configs map[string]string) error {
	if len(configs) == 0 {
		return nil
	}
	keys := make([]string, 0, len(configs))
	for machineCode := range configs {
		if strings.TrimSpace(machineCode) == "" {
			return fmt.Errorf("机器码不能为空")
		}
		keys = append(keys, machineCode)
	}
	sort.Strings(keys)

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`INSERT INTO node_configs(machine_code,yaml_text,updated_at) VALUES(?,?,?) ON CONFLICT(machine_code) DO UPDATE SET yaml_text=excluded.yaml_text, updated_at=excluded.updated_at`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	now := time.Now().Format(time.RFC3339)
	for _, machineCode := range keys {
		if _, err := stmt.Exec(machineCode, configs[machineCode], now); err != nil {
			return fmt.Errorf("保存机器 %s 的配置失败: %w", machineCode, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return nil
}

func (s *Store) SaveNodeConfigIfEmpty(machineCode, yamlText string) error {
	_, err := s.db.Exec(`INSERT INTO node_configs(machine_code,yaml_text,updated_at)
                VALUES(?,?,?)
                ON CONFLICT(machine_code) DO UPDATE SET
                        yaml_text=excluded.yaml_text,
                        updated_at=excluded.updated_at
                WHERE trim(node_configs.yaml_text) = ''`,
		machineCode, yamlText, time.Now().Format(time.RFC3339))
	return err
}

// AgentIdentity is the stable identity of one Agent runtime on a physical machine.
type AgentIdentity struct {
	MachineCode      string          `json:"machine_code"`
	AgentType        string          `json:"agent_type"`
	InstanceID       string          `json:"instance_id"`
	CredentialSHA256 string          `json:"-"`
	StatusJSON       json.RawMessage `json:"status"`
	LastSeen         int64           `json:"last_seen"`
	CreatedAt        string          `json:"created_at"`
	UpdatedAt        string          `json:"updated_at"`
}

func validateAgentIdentity(machineCode, agentType, instanceID string) error {
	if !regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`).MatchString(machineCode) {
		return fmt.Errorf("机器码格式无效")
	}
	if agentType != "mihomo" && agentType != "wireguard" {
		return fmt.Errorf("Agent 类型无效")
	}
	if !regexp.MustCompile(`^[A-Za-z0-9_.-]{1,96}$`).MatchString(instanceID) {
		return fmt.Errorf("Agent 实例 ID 格式无效")
	}
	return nil
}

// ProvisionAgentInstance stores only a SHA-256 fingerprint of the dedicated
// credential. Rotating a credential deliberately preserves status and last_seen.
func (s *Store) ProvisionAgentInstance(machineCode, agentType, instanceID, secret string) error {
	if err := validateAgentIdentity(machineCode, agentType, instanceID); err != nil {
		return err
	}
	if len(secret) < 32 || len(secret) > 256 || strings.TrimSpace(secret) != secret {
		return fmt.Errorf("Agent 专属凭据长度或格式无效")
	}
	sum := sha256.Sum256([]byte(secret))
	hash := hex.EncodeToString(sum[:])
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.db.Exec(`INSERT INTO agent_instances(
		machine_code, agent_type, instance_id, credential_sha256, status_json,
		last_seen, created_at, updated_at
	) VALUES(?, ?, ?, ?, '{}', 0, ?, ?)
	ON CONFLICT(machine_code, agent_type, instance_id) DO UPDATE SET
		credential_sha256=excluded.credential_sha256,
		updated_at=excluded.updated_at`,
		machineCode, agentType, instanceID, hash, now, now)
	return err
}

// AgentInstanceCredentialHash returns the stored credential fingerprint for
// constant-time comparison by the authentication layer.
func (s *Store) AgentInstanceCredentialHash(machineCode, agentType, instanceID string) (string, error) {
	if err := validateAgentIdentity(machineCode, agentType, instanceID); err != nil {
		return "", err
	}
	var hash string
	err := s.db.QueryRow(`SELECT credential_sha256 FROM agent_instances
		WHERE machine_code=? AND agent_type=? AND instance_id=?`,
		machineCode, agentType, instanceID).Scan(&hash)
	return hash, err
}

// UpdateAgentInstanceStatus atomically updates telemetry for exactly one Agent
// instance; it never writes to the legacy machine-scoped settings keys.
func (s *Store) UpdateAgentInstanceStatus(machineCode, agentType, instanceID string, status json.RawMessage, lastSeen int64) error {
	if err := validateAgentIdentity(machineCode, agentType, instanceID); err != nil {
		return err
	}
	if lastSeen < 0 || len(status) == 0 || len(status) > 64<<10 || !json.Valid(status) {
		return fmt.Errorf("Agent 实例状态数据无效")
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	result, err := s.db.Exec(`UPDATE agent_instances SET status_json=?, last_seen=?, updated_at=?
		WHERE machine_code=? AND agent_type=? AND instance_id=?`,
		string(status), lastSeen, now, machineCode, agentType, instanceID)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Store) GetAgentInstance(machineCode, agentType, instanceID string) (*AgentIdentity, error) {
	if err := validateAgentIdentity(machineCode, agentType, instanceID); err != nil {
		return nil, err
	}
	item := &AgentIdentity{}
	var statusJSON []byte
	err := s.db.QueryRow(`SELECT machine_code, agent_type, instance_id, credential_sha256,
		status_json, last_seen, created_at, updated_at FROM agent_instances
		WHERE machine_code=? AND agent_type=? AND instance_id=?`,
		machineCode, agentType, instanceID).Scan(
		&item.MachineCode, &item.AgentType, &item.InstanceID, &item.CredentialSHA256,
		&statusJSON, &item.LastSeen, &item.CreatedAt, &item.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	item.StatusJSON = json.RawMessage(statusJSON)
	return item, nil
}

func (s *Store) ListAgentInstances(machineCode string) ([]AgentIdentity, error) {
	if !regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`).MatchString(machineCode) {
		return nil, fmt.Errorf("机器码格式无效")
	}
	rows, err := s.db.Query(`SELECT machine_code, agent_type, instance_id, status_json,
		last_seen, created_at, updated_at FROM agent_instances
		WHERE machine_code=? ORDER BY agent_type, instance_id`, machineCode)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AgentIdentity
	for rows.Next() {
		var item AgentIdentity
		var statusJSON []byte
		if err := rows.Scan(&item.MachineCode, &item.AgentType, &item.InstanceID,
			&statusJSON, &item.LastSeen, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		item.StatusJSON = json.RawMessage(statusJSON)
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// ListAllAgentInstances returns every composite Agent identity for the shared control panel.
func (s *Store) ListAllAgentInstances() ([]AgentIdentity, error) {
	rows, err := s.db.Query(`SELECT machine_code, agent_type, instance_id, status_json,
		last_seen, created_at, updated_at FROM agent_instances
		ORDER BY machine_code, agent_type, instance_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AgentIdentity
	for rows.Next() {
		var item AgentIdentity
		var statusJSON []byte
		if err := rows.Scan(&item.MachineCode, &item.AgentType, &item.InstanceID,
			&statusJSON, &item.LastSeen, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		item.StatusJSON = json.RawMessage(statusJSON)
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) DeleteAgentInstance(machineCode, agentType, instanceID string) error {
	if err := validateAgentIdentity(machineCode, agentType, instanceID); err != nil {
		return err
	}
	_, err := s.db.Exec(`DELETE FROM agent_instances
		WHERE machine_code=? AND agent_type=? AND instance_id=?`,
		machineCode, agentType, instanceID)
	return err
}

// AgentInstanceConfig is the desired configuration for one independent Agent runtime.
type AgentInstanceConfig struct {
	MachineCode string `json:"machine_code"`
	AgentType   string `json:"agent_type"`
	InstanceID  string `json:"instance_id"`
	YAML        string `json:"config_yaml"`
	SHA256      string `json:"sha256"`
	UpdatedAt   string `json:"updated_at"`
}

// AgentInstanceCommand is a command scoped to one Agent runtime.
type AgentInstanceCommand struct {
	MachineCode string          `json:"machine_code"`
	AgentType   string          `json:"agent_type"`
	InstanceID  string          `json:"instance_id"`
	CommandID   string          `json:"command_id"`
	CommandJSON json.RawMessage `json:"command"`
	Status      string          `json:"status"`
	Result      string          `json:"result,omitempty"`
	CreatedAt   string          `json:"created_at"`
	UpdatedAt   string          `json:"updated_at"`
}

const agentInstanceConfigMaxBytes = 2 << 20
const agentInstanceCommandMaxBytes = 64 << 10

// SaveAgentInstanceConfig stores the exact YAML bytes and their SHA-256 for one
// composite identity. It never reads or writes the legacy machine-wide config.
func (s *Store) SaveAgentInstanceConfig(machineCode, agentType, instanceID, yamlText string) error {
	if err := validateAgentIdentity(machineCode, agentType, instanceID); err != nil {
		return err
	}
	if strings.TrimSpace(yamlText) == "" || len(yamlText) > agentInstanceConfigMaxBytes {
		return fmt.Errorf("Agent 实例配置为空或超过 2 MiB")
	}
	sum := sha256.Sum256([]byte(yamlText))
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.db.Exec(`INSERT INTO agent_instance_configs(
		machine_code, agent_type, instance_id, yaml_text, sha256, updated_at
	) VALUES(?, ?, ?, ?, ?, ?)
	ON CONFLICT(machine_code, agent_type, instance_id) DO UPDATE SET
		yaml_text=excluded.yaml_text, sha256=excluded.sha256, updated_at=excluded.updated_at`,
		machineCode, agentType, instanceID, yamlText, hex.EncodeToString(sum[:]), now)
	return err
}

// GetAgentInstanceConfig returns nil when the instance has no assigned config.
func (s *Store) GetAgentInstanceConfig(machineCode, agentType, instanceID string) (*AgentInstanceConfig, error) {
	if err := validateAgentIdentity(machineCode, agentType, instanceID); err != nil {
		return nil, err
	}
	item := &AgentInstanceConfig{}
	err := s.db.QueryRow(`SELECT machine_code, agent_type, instance_id, yaml_text, sha256, updated_at
		FROM agent_instance_configs WHERE machine_code=? AND agent_type=? AND instance_id=?`,
		machineCode, agentType, instanceID).Scan(
		&item.MachineCode, &item.AgentType, &item.InstanceID, &item.YAML, &item.SHA256, &item.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return item, nil
}

// QueueAgentInstanceCommand allows at most one pending command per Agent instance.
func (s *Store) QueueAgentInstanceCommand(machineCode, agentType, instanceID, commandID string, command json.RawMessage) error {
	if err := validateAgentIdentity(machineCode, agentType, instanceID); err != nil {
		return err
	}
	if !regexp.MustCompile(`^[A-Za-z0-9_-]{1,96}$`).MatchString(commandID) ||
		len(command) == 0 || len(command) > agentInstanceCommandMaxBytes || !json.Valid(command) {
		return fmt.Errorf("Agent 实例命令 ID 或 JSON 数据无效")
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(command, &payload); err != nil || payload == nil {
		return fmt.Errorf("Agent 实例命令必须是 JSON 对象")
	}
	var payloadID string
	if raw := payload["id"]; len(raw) > 0 {
		_ = json.Unmarshal(raw, &payloadID)
	}
	if payloadID != commandID {
		return fmt.Errorf("Agent 实例命令 ID 与载荷不匹配")
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.db.Exec(`INSERT INTO agent_instance_commands(
		machine_code, agent_type, instance_id, command_id, command_json, status, result_message, created_at, updated_at
	) VALUES(?, ?, ?, ?, ?, 'pending', '', ?, ?)`,
		machineCode, agentType, instanceID, commandID, string(command), now, now)
	if err != nil {
		return fmt.Errorf("写入 Agent 实例命令失败: %w", err)
	}
	return nil
}

// GetPendingAgentInstanceCommand returns only the pending command for this exact instance.
func (s *Store) GetPendingAgentInstanceCommand(machineCode, agentType, instanceID string) (*AgentInstanceCommand, error) {
	if err := validateAgentIdentity(machineCode, agentType, instanceID); err != nil {
		return nil, err
	}
	item := &AgentInstanceCommand{}
	var commandJSON []byte
	err := s.db.QueryRow(`SELECT machine_code, agent_type, instance_id, command_id, command_json,
		status, result_message, created_at, updated_at FROM agent_instance_commands
		WHERE machine_code=? AND agent_type=? AND instance_id=? AND status='pending'`,
		machineCode, agentType, instanceID).Scan(
		&item.MachineCode, &item.AgentType, &item.InstanceID, &item.CommandID, &commandJSON,
		&item.Status, &item.Result, &item.CreatedAt, &item.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	item.CommandJSON = json.RawMessage(commandJSON)
	return item, nil
}

// GetLatestAgentInstanceCommand returns the most recent command state for one exact instance.
func (s *Store) GetLatestAgentInstanceCommand(machineCode, agentType, instanceID string) (*AgentInstanceCommand, error) {
	if err := validateAgentIdentity(machineCode, agentType, instanceID); err != nil {
		return nil, err
	}
	item := &AgentInstanceCommand{}
	var commandJSON []byte
	err := s.db.QueryRow(`SELECT machine_code, agent_type, instance_id, command_id, command_json,
		status, result_message, created_at, updated_at FROM agent_instance_commands
		WHERE machine_code=? AND agent_type=? AND instance_id=?
		ORDER BY updated_at DESC, created_at DESC, command_id DESC LIMIT 1`,
		machineCode, agentType, instanceID).Scan(
		&item.MachineCode, &item.AgentType, &item.InstanceID, &item.CommandID, &commandJSON,
		&item.Status, &item.Result, &item.CreatedAt, &item.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	item.CommandJSON = json.RawMessage(commandJSON)
	return item, nil
}

// AckAgentInstanceCommand atomically acknowledges exactly one pending command.
func (s *Store) AckAgentInstanceCommand(machineCode, agentType, instanceID, commandID, status, resultMessage string) error {
	if err := validateAgentIdentity(machineCode, agentType, instanceID); err != nil {
		return err
	}
	if !regexp.MustCompile(`^[A-Za-z0-9_-]{1,96}$`).MatchString(commandID) ||
		(status != "success" && status != "failed") || len(resultMessage) > 2048 {
		return fmt.Errorf("Agent 实例命令 ACK 参数无效")
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := s.db.Exec(`UPDATE agent_instance_commands SET status=?, result_message=?, updated_at=?
		WHERE machine_code=? AND agent_type=? AND instance_id=? AND command_id=? AND status='pending'`,
		status, resultMessage, now, machineCode, agentType, instanceID, commandID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return sql.ErrNoRows
	}
	return nil
}
