package app

import (
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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
CREATE TABLE IF NOT EXISTS agent_status(
 machine_code TEXT PRIMARY KEY,
 hostname TEXT NOT NULL DEFAULT '',
 os TEXT NOT NULL DEFAULT '',
 arch TEXT NOT NULL DEFAULT '',
 docker_available INTEGER NOT NULL DEFAULT 0,
 mihomo_running INTEGER NOT NULL DEFAULT 0,
 mihomo_version TEXT NOT NULL DEFAULT '',
 status_json TEXT NOT NULL DEFAULT '{}',
 updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS agent_tasks(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 machine_code TEXT NOT NULL,
 action TEXT NOT NULL,
 params_json TEXT NOT NULL DEFAULT '{}',
 status TEXT NOT NULL DEFAULT 'pending',
 result_json TEXT NOT NULL DEFAULT '',
 error_text TEXT NOT NULL DEFAULT '',
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL,
 claimed_at TEXT NOT NULL DEFAULT '',
 finished_at TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_agent_tasks_machine_status
 ON agent_tasks(machine_code, status, id);
CREATE INDEX IF NOT EXISTS idx_agent_tasks_created
 ON agent_tasks(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_cv_version ON config_versions(version DESC);
`
	_, err := s.db.Exec(schema)
	if err != nil {
		return err
	}
	// 安全补全旧表字段
	var count int
	s.db.QueryRow("SELECT count(*) FROM pragma_table_info('proxies') WHERE name='machine_code'").Scan(&count)
	if count == 0 {
		s.db.Exec("ALTER TABLE proxies ADD COLUMN machine_code TEXT NOT NULL DEFAULT ''")
	}

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
		if err := rows.Scan(&k, &v); err == nil {
			res[k] = v
		}
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

// DeleteAgentBinding atomically revokes a machine credential and invalidates its live work.
// Completed task history and the node's YAML are retained for audit/re-registration.
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
	if _, err := tx.Exec(`DELETE FROM agent_status WHERE machine_code=?`, machineCode); err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := tx.Exec(`UPDATE agent_tasks SET status='failed', error_text='Agent binding removed', updated_at=?, finished_at=? WHERE machine_code=? AND status IN ('pending','running')`, now, now, machineCode); err != nil {
		return err
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

// SaveNodeConfigIfEmpty 只初始化不存在或内容为空的节点配置。
// 已存在的非空 YAML 不会被自动同步覆盖。
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

// CreateAgentTask 创建一个等待 Agent 领取的任务。
func (s *Store) CreateAgentTask(machineCode, action, paramsJSON string) (int64, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := s.db.Exec(`
        INSERT INTO agent_tasks
            (machine_code, action, params_json, status, created_at, updated_at)
        VALUES (?, ?, ?, 'pending', ?, ?)`,
		machineCode, action, paramsJSON, now, now)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// CancelPendingAgentTask cancels only tasks that have not been claimed by an Agent.
func (s *Store) CancelPendingAgentTask(id int64) (int64, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := s.db.Exec(`UPDATE agent_tasks
		SET status='cancelled', error_text='Cancelled by administrator', updated_at=?, finished_at=?
		WHERE id=? AND status='pending'`, now, now, id)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
// UpdateAgentTaskResult 仅允许更新属于指定机器且仍在执行中的任务。
func (s *Store) UpdateAgentTaskResult(id int64, machineCode, status, resultJSON, errorText string) (int64, error) {
	if status != "succeeded" && status != "failed" {
		return 0, fmt.Errorf("invalid task status")
	}
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := s.db.Exec(`
        UPDATE agent_tasks
        SET status=?, result_json=?, error_text=?, updated_at=?, finished_at=?
        WHERE id=? AND machine_code=? AND status='running'`,
		status, resultJSON, errorText, now, now, id, machineCode)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
