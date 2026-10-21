package app

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const baseTemplate = `log-level: info
external-controller: 127.0.0.1:8088
secret: "change-this-secret"
allow-lan: true
find-process-mode: "off"
tcp-concurrent: true
ipv6: false
sniffer:
    enable: false
    sniff:
        HTTP:
            ports:
                - 80
            override-destination: true
        TLS:
            ports:
                - 443
        QUIC:
            ports:
                - 443
            override-destination: true
tun:
    enable: __TUN_ENABLE__
    tcp-concurrent: true
    bind-address: '*'
    stack: mixed
    dns-hijack:
        - any:53
        - tcp://any:53
    auto-detect-interface: true
    auto-route: true
dns:
    enable: true
    listen: 0.0.0.0:5353
    nameserver:
        - https://doh.opendns.com/dns-query
        - https://dns.google/dns-query
        - https://dns.alidns.com/dns-query
    fallback:
        - 223.5.5.5
        - 8.8.8.8
proxies:__PROXIES__
rules:__RULES__
`

type proxyOut struct {
	Name   string         `yaml:"name"`
	Type   string         `yaml:"type"`
	Server string         `yaml:"server"`
	Port   int            `yaml:"port"`
	Extra  map[string]any `yaml:",inline"`
}

func indent(s, prefix string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, l := range lines {
		lines[i] = prefix + l
	}
	return strings.Join(lines, "\n") + "\n"
}

func (a *App) BuildConfig() (string, error) {
	proxies, err := a.store.ListProxies()
	if err != nil {
		return "", err
	}

	settings, _ := a.store.GetSettings()
	tunEnable := settings["tun_enable"]
	if tunEnable != "true" {
		tunEnable = "false"
	}

	var outs []proxyOut
	for _, p := range proxies {
		if !p.Enabled {
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
		outs = append(outs, proxyOut{
			Name: p.Name, Type: p.Type, Server: p.Server, Port: p.Port, Extra: ex,
		})
	}

	proxiesYAML := " []"
	if len(outs) > 0 {
		b, err := yaml.Marshal(outs)
		if err != nil {
			return "", err
		}
		proxiesYAML = "\n" + indent(string(b), "    ")
	}

	rules := []string{
		"DOMAIN-KEYWORD,221111cdn,REJECT",
		"DOMAIN-SUFFIX,221111cdn,REJECT",
		"DOMAIN-REGEX,^abc.*2222com,REJECT",
	}
	for _, p := range proxies {
		if !p.Enabled {
			continue
		}
		cidr := p.SourceCIDR
		if cidr == "" {
			cidr = "0.0.0.0/0"
		}
		rules = append(rules, fmt.Sprintf("SRC-IP-CIDR,%s,%s", cidr, p.Name))
	}
	rules = append(rules, "NETWORK,UDP,DIRECT", "MATCH,REJECT")

	rb, err := yaml.Marshal(rules)
	if err != nil {
		return "", err
	}
	rulesYAML := "\n" + indent(string(rb), "    ")

	out := strings.Replace(baseTemplate, "__PROXIES__", proxiesYAML, 1)
	out = strings.Replace(out, "__RULES__", rulesYAML, 1)
	out = strings.Replace(out, "__TUN_ENABLE__", tunEnable, 1)
	return out, nil
}

func (a *App) Publish() (*ConfigVersion, error) {
	yml, err := a.BuildConfig()
	if err != nil {
		return nil, err
	}
	var chk any
	if err := yaml.Unmarshal([]byte(yml), &chk); err != nil {
		return nil, fmt.Errorf("YAML 语法错误: %w", err)
	}
	sum := sha256.Sum256([]byte(yml))
	sha := hex.EncodeToString(sum[:])

	_ = os.MkdirAll(a.cfg.BackupDir, 0o700)
	_ = os.MkdirAll(filepath.Dir(a.cfg.ConfigPath), 0o700)

	if _, err := os.Stat(a.cfg.ConfigPath); err == nil {
		if b, e := os.ReadFile(a.cfg.ConfigPath); e == nil {
			_ = os.WriteFile(filepath.Join(a.cfg.BackupDir,
				time.Now().Format("20060102-150405")+".yaml"), b, 0o600)
		}
	}

	tmp := a.cfg.ConfigPath + ".tmp"
	if err := os.WriteFile(tmp, []byte(yml), 0o600); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp, a.cfg.ConfigPath); err != nil {
		return nil, err
	}

	v, _ := a.store.NextVersion()
	if err := a.store.InsertVersion(v, sha, yml, "published"); err != nil {
		return nil, err
	}

	cv := &ConfigVersion{Version: v, SHA256: sha, Status: "published"}
	if err := a.ReloadMihomo(); err != nil {
		cv.Status = "published_reload_failed"
		return cv, fmt.Errorf("配置已写入，但 Mihomo 重载失败: %w", err)
	}
	return cv, nil
}

func (a *App) Rollback(version int) (*ConfigVersion, error) {
	yml, err := a.store.VersionYAML(version)
	if err != nil {
		return nil, fmt.Errorf("版本不存在: %w", err)
	}
	var chk any
	if err := yaml.Unmarshal([]byte(yml), &chk); err != nil {
		return nil, fmt.Errorf("历史 YAML 损坏: %w", err)
	}
	_ = os.MkdirAll(a.cfg.BackupDir, 0o700)
	if b, e := os.ReadFile(a.cfg.ConfigPath); e == nil {
		_ = os.WriteFile(filepath.Join(a.cfg.BackupDir,
			"before-rollback-"+time.Now().Format("20060102-150405")+".yaml"), b, 0o600)
	}
	tmp := a.cfg.ConfigPath + ".tmp"
	if err := os.WriteFile(tmp, []byte(yml), 0o600); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp, a.cfg.ConfigPath); err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(yml))
	if err := a.ReloadMihomo(); err != nil {
		return &ConfigVersion{Version: version, SHA256: hex.EncodeToString(sum[:]), Status: "rolled_back_reload_failed"}, err
	}
	return &ConfigVersion{Version: version, SHA256: hex.EncodeToString(sum[:]), Status: "rolled_back"}, nil
}
