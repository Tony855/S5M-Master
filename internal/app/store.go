package app

import (
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
ID     int64  `json:"id"`
Name   string `json:"name"`
APIURL string `json:"api_url"`
Secret string `json:"secret"`
}

type Proxy struct {
ID         int64          `json:"id"`
	InstanceID int64          `json:"instance_id"`
Name       string         `json:"name"`
Mode       string         `json:"mode"`
Type       string         `json:"type"`
Server     string         `json:"server"`
Port       int            `json:"port"`
SourceCIDR string         `json:"source_cidr"`
Extra      map[string]any `json:"extra"`
Enabled    bool           `json:"enabled"`
}

type ConfigVersion struct {
ID        int64  `json:"id"`
Version   int    `json:"version"`
SHA256    string `json:"sha256"`
Status    string `json:"status"`
CreatedAt string `json:"created_at"`
}

func b2i(b bool) int {
if b { return 1 }
return 0
}

func OpenStore(path string) (*Store, error) {
if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil { return nil, err }
dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"
db, err := sql.Open("sqlite", dsn)
if err != nil { return nil, err }
db.SetMaxOpenConns(1)
s := &Store{db: db}
if err := s.migrate(); err != nil { return nil, err }
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
 api_url TEXT NOT NULL,
 secret TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS proxies(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL UNIQUE,
 mode TEXT NOT NULL DEFAULT 'proxy',
 type TEXT NOT NULL,
 server TEXT NOT NULL,
 port INTEGER NOT NULL,
 source_cidr TEXT NOT NULL DEFAULT '0.0.0.0/0',
	instance_id INTEGER NOT NULL DEFAULT 0,
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
CREATE TABLE IF NOT EXISTS settings(
 key TEXT PRIMARY KEY,
 value TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cv_version ON config_versions(version DESC);
`
_, err := s.db.Exec(schema)
if err != nil { return err }

// 自动升级旧表：如果 mode 列不存在，则补充
var count int
s.db.QueryRow("SELECT count(*) FROM pragma_table_info('proxies') WHERE name='mode'").Scan(&count)
if count == 0 {
_, err = s.db.Exec("ALTER TABLE proxies ADD COLUMN mode TEXT NOT NULL DEFAULT 'proxy'")
if err != nil { return fmt.Errorf("failed to add mode column: %w", err) }
}

s.db.Exec(`INSERT OR IGNORE INTO settings (key, value) VALUES ('tun_enable', 'false')`)
	s.db.Exec(`INSERT OR IGNORE INTO settings (key, value) VALUES ('agent_token', 's5m-agent-secret')`)
return nil
}

func (s *Store) GetSettings() (map[string]string, error) {
rows, err := s.db.Query(`SELECT key, value FROM settings`)
if err != nil { return nil, err }
defer rows.Close()
res := make(map[string]string)
for rows.Next() {
var k, v string
if err := rows.Scan(&k, &v); err == nil { res[k] = v }
}
return res, nil
}

func (s *Store) UpdateSettings(updates map[string]string) error {
tx, err := s.db.Begin()
if err != nil { return err }
for k, v := range updates {
tx.Exec(`INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, k, v)
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
if err != nil { return nil, err }
u.Enabled = en == 1
return u, nil
}

func (s *Store) UpdatePassword(id int64, hash string) error {
_, err := s.db.Exec(`UPDATE users SET password_hash=? WHERE id=?`, hash, id)
return err
}

func (s *Store) ListProxies() ([]Proxy, error) {
rows, err := s.db.Query(`SELECT id,instance_id,name,mode,type,server,port,source_cidr,config_json,enabled FROM proxies ORDER BY id`)
if err != nil { return nil, err }
defer rows.Close()
var out []Proxy
for rows.Next() {
var p Proxy
var extra string
var en int
if err := rows.Scan(&p.ID, &p.InstanceID, &p.Name, &p.Mode, &p.Type, &p.Server, &p.Port, &p.SourceCIDR, &extra, &en); err != nil { return nil, err }
p.Enabled = en == 1
p.Extra = map[string]any{}
_ = json.Unmarshal([]byte(extra), &p.Extra)
out = append(out, p)
}
return out, nil
}

func (s *Store) CreateProxy(p *Proxy) error {
extra, _ := json.Marshal(p.Extra)
res, err := s.db.Exec(`INSERT INTO proxies(instance_id,name,mode,type,server,port,source_cidr,config_json,enabled) VALUES(?,?,?,?,?,?,?,?,?)`, p.InstanceID, p.Name, p.Mode, p.Type, p.Server, p.Port, p.SourceCIDR, string(extra), b2i(p.Enabled))
if err != nil { return err }
p.ID, _ = res.LastInsertId()
return nil
}

func (s *Store) UpdateProxy(p *Proxy) error {
extra, _ := json.Marshal(p.Extra)
_, err := s.db.Exec(`UPDATE proxies SET instance_id=?,name=?,mode=?,type=?,server=?,port=?,source_cidr=?,config_json=?,enabled=? WHERE id=?`, p.InstanceID, p.Name, p.Mode, p.Type, p.Server, p.Port, p.SourceCIDR, string(extra), b2i(p.Enabled), p.ID)
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

func (s *Store) ListVersions(limit int) ([]ConfigVersion, error) {
rows, err := s.db.Query(`SELECT id,version,sha256,status,created_at FROM config_versions ORDER BY version DESC LIMIT ?`, limit)
if err != nil { return nil, err }
defer rows.Close()
var out []ConfigVersion
for rows.Next() {
var v ConfigVersion
if err := rows.Scan(&v.ID, &v.Version, &v.SHA256, &v.Status, &v.CreatedAt); err != nil { return nil, err }
out = append(out, v)
}
return out, nil
}

func (s *Store) VersionYAML(version int) (string, error) {
var y string
err := s.db.QueryRow(`SELECT yaml_text FROM config_versions WHERE version=?`, version).Scan(&y)
return y, err
}

func (s *Store) ListInstances() ([]Instance, error) {
rows, err := s.db.Query(`SELECT id,name,api_url,secret FROM instances ORDER BY id`)
if err != nil { return nil, err }
defer rows.Close()
var out []Instance
for rows.Next() {
var i Instance
if err := rows.Scan(&i.ID, &i.Name, &i.APIURL, &i.Secret); err != nil { return nil, err }
out = append(out, i)
}
return out, nil
}

func (s *Store) CreateInstance(i *Instance) error {
res, err := s.db.Exec(`INSERT INTO instances(name,api_url,secret) VALUES(?,?,?)`, i.Name, i.APIURL, i.Secret)
if err != nil { return err }
i.ID, _ = res.LastInsertId()
return nil
}

func (s *Store) DeleteInstance(id int64) error {
_, err := s.db.Exec(`DELETE FROM instances WHERE id=?`, id)
return err
}
