package app

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const baseTemplate = `mode: rule
mixed-port: 8080
log-level: info
external-controller: 127.0.0.1:8088
secret: "__S5M_MIHOMO_SECRET__"
allow-lan: true
find-process-mode: "off"
tcp-concurrent: true
ipv6: false
unified-delay: true
tcp-fast-open: true

sniffer:
    enable: true
    sniff:
        HTTP:
            ports: [80]
            override-destination: true
        TLS:
            ports: [443]
        QUIC:
            ports: [443]
            override-destination: true
tun:
    enable: true
    tcp-concurrent: true
    bind-address: '*'
    stack: mixed
    dns-hijack:
        - 'any:53'
        - 'tcp://any:53'
    auto-detect-interface: true
    auto-route: true
    strict-route: true
dns:
    enable: true
    listen: 0.0.0.0:5353
    enhanced-mode: fake-ip
    fake-ip-range: 198.18.0.1/16
    fake-ip-filter:
        - '*.lan'
        - '*.local'
        - '*.msftconnecttest.com'
        - '*.msftncsi.com'
    default-nameserver:
        - 223.5.5.5
        - 119.29.29.29
    nameserver:
        - https://dns.alidns.com/dns-query
        - https://doh.pub/dns-query
    fallback:
        - https://dns.cloudflare.com/dns-query
        - https://dns.google/dns-query
    fallback-filter:
        geoip: true
        geoip-code: CN
        ipcidr:
            - 240.0.0.0/4

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

func (a *App) BuildConfigForMachine(machineCode string) (string, error) {
	proxies, err := a.store.ListProxies()
	if err != nil {
		return "", err
	}
	secretKey := "mihomo_secret_controller"
	if machineCode != "" {
		secretKey = "agent_mihomo_secret_" + machineCode
	}
	secret, err := a.getOrCreateMihomoSecret(secretKey)
	if err != nil {
		return "", err
	}
	yml, err := buildConfigFromProxies(proxies, machineCode, secret)
	if err != nil {
		return "", err
	}
	// The controller's TUN switch controls generated defaults. A saved per-node
	// YAML remains authoritative and is preserved by syncAuthorizedNodeConfigs.
	settings, err := a.store.GetSettings()
	if err != nil {
		return "", fmt.Errorf("读取 TUN 开关失败: %w", err)
	}
	if settings["tun_enable"] != "true" {
		yml = strings.Replace(yml, "tun:\n    enable: true", "tun:\n    enable: false", 1)
	}
	return yml, nil
}

// getOrCreateMihomoSecret creates a cryptographically random API secret once per controller/Agent.
func (a *App) getOrCreateMihomoSecret(key string) (string, error) {
	settings, err := a.store.GetSettings()
	if err != nil {
		return "", fmt.Errorf("读取 Mihomo 密钥失败: %w", err)
	}
	if secret := strings.TrimSpace(settings[key]); secret != "" {
		return secret, nil
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("生成 Mihomo 随机密钥失败: %w", err)
	}
	secret := hex.EncodeToString(buf)
	created, err := a.store.CreateSettingIfAbsent(key, secret)
	if err != nil {
		return "", fmt.Errorf("保存 Mihomo 密钥失败: %w", err)
	}
	if created {
		return secret, nil
	}
	settings, err = a.store.GetSettings()
	if err != nil {
		return "", fmt.Errorf("回读 Mihomo 密钥失败: %w", err)
	}
	if secret = strings.TrimSpace(settings[key]); secret == "" {
		return "", fmt.Errorf("Mihomo 密钥保存后仍不存在")
	}
	return secret, nil
}

// syncAuthorizedNodeConfigs refreshes cached YAML for machines with dedicated tokens.
// It does not publish or reload the controller's own Mihomo configuration.
func (a *App) syncAuthorizedNodeConfigs() error {
	settings, err := a.store.GetSettings()
	if err != nil {
		return fmt.Errorf("读取机器授权失败: %w", err)
	}
	const prefix = "agent_machine_"
	configs := make(map[string]string)
	for key, token := range settings {
		if !strings.HasPrefix(key, prefix) || strings.TrimSpace(token) == "" {
			continue
		}
		machineCode := strings.TrimSpace(strings.TrimPrefix(key, prefix))
		if machineCode == "" {
			continue
		}
		generated, err := a.BuildConfigForMachine(machineCode)
		if err != nil {
			return fmt.Errorf("为机器 %s 生成配置失败: %w", machineCode, err)
		}
		// Existing complete per-node YAML is authoritative for TUN, DNS, ports and other settings.
		// Proxy edits refresh only generated proxies/rules and preserve the node's secret.
		existing, err := a.store.GetNodeConfig(machineCode)
		if err != nil {
			return fmt.Errorf("读取机器 %s 的独立配置失败: %w", machineCode, err)
		}
		if existing != nil && strings.TrimSpace(existing.YAML) != "" {
			var currentDoc, generatedDoc map[string]any
			if err := yaml.Unmarshal([]byte(existing.YAML), &currentDoc); err != nil {
				return fmt.Errorf("机器 %s 的独立 YAML 无效: %w", machineCode, err)
			}
			if err := yaml.Unmarshal([]byte(generated), &generatedDoc); err != nil {
				return fmt.Errorf("机器 %s 的生成 YAML 无效: %w", machineCode, err)
			}
			for _, section := range []string{"proxies", "rules"} {
				if value, ok := generatedDoc[section]; ok {
					currentDoc[section] = value
				}
			}
			generated, err = yaml.Marshal(currentDoc)
			if err != nil {
				return fmt.Errorf("序列化机器 %s 的独立配置失败: %w", machineCode, err)
			}
		}
		var doc map[string]any
		if err := yaml.Unmarshal([]byte(generated), &doc); err != nil {
			return fmt.Errorf("机器 %s 的 YAML 校验失败: %w", machineCode, err)
		}
		if len(doc) == 0 {
			return fmt.Errorf("机器 %s 的 YAML 内容为空", machineCode)
		}
		configs[machineCode] = generated
	}
	for machineCode, yml := range configs {
		if err := a.store.SaveNodeConfig(machineCode, yml); err != nil {
			return fmt.Errorf("保存机器 %s 的配置失败: %w", machineCode, err)
		}
	}
	return nil
}

func buildConfigFromProxies(proxies []Proxy, machineCode, secret string) (string, error) {
	matchesMachine := func(p Proxy) bool {
		return machineCode == "" || p.MachineCode == "" || p.MachineCode == machineCode
	}
	eligible := func(p Proxy) bool {
		return p.Enabled && p.Mode != "direct" && p.Mode != "reject" && matchesMachine(p)
	}
	endpointKey := func(p Proxy) string {
		return strings.ToLower(strings.TrimSpace(p.Type)) + "|" +
			strings.Trim(strings.TrimSpace(p.Server), "[]") + "|" +
			fmt.Sprint(p.Port)
	}

	var outs []proxyOut
	emittedNames := map[string]bool{}
	activeByEndpoint := map[string][]Proxy{}

	for _, p := range proxies {
		if !eligible(p) {
			continue
		}
		if emittedNames[p.Name] {
			return "", fmt.Errorf("代理名称重复：%q", p.Name)
		}
		emittedNames[p.Name] = true
		key := endpointKey(p)
		activeByEndpoint[key] = append(activeByEndpoint[key], p)

		ex := map[string]any{}
		for k, v := range p.Extra {
			switch k {
			case "name", "type", "server", "port":
				continue
			}
			ex[k] = v
		}
		outs = append(outs, proxyOut{
			Name: p.Name, Type: p.Type, Server: p.Server,
			Port: p.Port, Extra: ex,
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
	seenCIDR := map[string]string{}

	for _, p := range proxies {
		if !matchesMachine(p) || p.Mode == "direct" || p.Mode == "reject" {
			continue
		}

		target := ""
		if eligible(p) {
			target = p.Name
		} else if !p.Enabled {
			// 禁用记录只能作为映射元数据，不能成为实际出口。
			candidates := activeByEndpoint[endpointKey(p)]
			if len(candidates) == 1 {
				target = candidates[0].Name
			} else {
				continue
			}
		} else {
			continue
		}

		cidr := strings.TrimSpace(p.SourceCIDR)
		if cidr == "" {
			continue
		}

		_, network, parseErr := net.ParseCIDR(cidr)
		if parseErr != nil {
			return "", fmt.Errorf("代理 %q 的 SourceCIDR 无效 %q: %w", p.Name, cidr, parseErr)
		}
		ones, bits := network.Mask.Size()
		if ones == 0 && (bits == 32 || bits == 128) {
			continue
		}

		canonical := network.String()
		if previous, exists := seenCIDR[canonical]; exists {
			return "", fmt.Errorf("客户端网段 %q 重复映射到 %q 和 %q", canonical, previous, target)
		}
		if !emittedNames[target] {
			return "", fmt.Errorf("客户端网段 %q 的目标代理 %q 未生成", canonical, target)
		}

		seenCIDR[canonical] = target
		rules = append(rules, fmt.Sprintf("SRC-IP-CIDR,%s,%s", canonical, target))
	}

	rules = append(rules, "MATCH,DIRECT")
	rb, err := yaml.Marshal(rules)
	if err != nil {
		return "", err
	}
	rulesYAML := "\n" + indent(string(rb), "    ")

	if strings.TrimSpace(secret) == "" {
		return "", fmt.Errorf("Mihomo API 密钥不能为空")
	}
	out := strings.Replace(baseTemplate, "__S5M_MIHOMO_SECRET__", secret, 1)
	out = strings.Replace(out, "__PROXIES__", proxiesYAML, 1)
	out = strings.Replace(out, "__RULES__", rulesYAML, 1)
	return out, nil
}

func (a *App) BuildConfig() (string, error) { return a.BuildConfigForMachine("") }

func (a *App) Publish() (*ConfigVersion, error) {
	yml, err := a.BuildConfig()
	if err != nil {
		return nil, err
	}

	var chk any
	if err := yaml.Unmarshal([]byte(yml), &chk); err != nil {
		return nil, fmt.Errorf("YAML 语法错误: %w", err)
	}

	configDir := filepath.Dir(a.cfg.ConfigPath)
	if err := os.MkdirAll(a.cfg.BackupDir, 0o700); err != nil {
		return nil, fmt.Errorf("创建备份目录失败: %w", err)
	}
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		return nil, fmt.Errorf("创建配置目录失败: %w", err)
	}

	candidate := a.cfg.ConfigPath + ".candidate"
	if err := os.WriteFile(candidate, []byte(yml), 0o600); err != nil {
		return nil, fmt.Errorf("写入候选配置失败: %w", err)
	}
	defer os.Remove(candidate)

	check := exec.Command("/opt/mihomo/mihomo", "-t", "-d", configDir, "-f", candidate)
	if output, err := check.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("Mihomo 候选配置校验失败: %w; 输出: %s", err, strings.TrimSpace(string(output)))
	}

	v, err := a.store.NextVersion()
	if err != nil {
		return nil, fmt.Errorf("获取配置版本失败: %w", err)
	}

	oldConfig, readErr := os.ReadFile(a.cfg.ConfigPath)
	if readErr != nil && !os.IsNotExist(readErr) {
		return nil, fmt.Errorf("读取当前配置失败: %w", readErr)
	}
	hadOld := readErr == nil

	if hadOld {
		backupPath := filepath.Join(a.cfg.BackupDir, time.Now().Format("20060102-150405.000000")+".yaml")
		if err := os.WriteFile(backupPath, oldConfig, 0o600); err != nil {
			return nil, fmt.Errorf("备份当前配置失败，未发布: %w", err)
		}
	}

	sum := sha256.Sum256([]byte(yml))
	sha := hex.EncodeToString(sum[:])

	restoreOld := func() error {
		if !hadOld {
			return os.Remove(a.cfg.ConfigPath)
		}
		tmpRestore := a.cfg.ConfigPath + ".restore"
		if err := os.WriteFile(tmpRestore, oldConfig, 0o600); err != nil {
			return err
		}
		return os.Rename(tmpRestore, a.cfg.ConfigPath)
	}

	if err := os.Rename(candidate, a.cfg.ConfigPath); err != nil {
		return nil, fmt.Errorf("替换配置文件失败: %w", err)
	}

	if err := a.store.InsertVersion(v, sha, yml, "published"); err != nil {
		if restoreErr := restoreOld(); restoreErr != nil {
			return nil, fmt.Errorf("记录版本失败: %v；恢复旧配置也失败: %w", err, restoreErr)
		}
		return nil, fmt.Errorf("记录配置版本失败，已恢复旧配置: %w", err)
	}

	cv := &ConfigVersion{Version: v, SHA256: sha, Status: "published"}
	if err := a.ReloadMihomo(); err != nil {
		if restoreErr := restoreOld(); restoreErr != nil {
			cv.Status = "published_reload_failed_restore_failed"
			_ = a.store.UpdateVersionStatus(v, cv.Status)
			return cv, fmt.Errorf("新配置重载失败: %v；恢复旧配置失败: %w", err, restoreErr)
		}
		if hadOld {
			if reloadOldErr := a.ReloadMihomo(); reloadOldErr != nil {
				cv.Status = "published_reload_failed_old_reload_failed"
				_ = a.store.UpdateVersionStatus(v, cv.Status)
				return cv, fmt.Errorf("新配置重载失败: %v；旧配置已恢复文件，但重载旧配置也失败: %w", err, reloadOldErr)
			}
		}
		cv.Status = "published_reload_failed_rolled_back"
		_ = a.store.UpdateVersionStatus(v, cv.Status)
		return cv, fmt.Errorf("新配置重载失败，已恢复旧配置: %w", err)
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

	configDir := filepath.Dir(a.cfg.ConfigPath)
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		return nil, fmt.Errorf("创建配置目录失败: %w", err)
	}
	if err := os.MkdirAll(a.cfg.BackupDir, 0o700); err != nil {
		return nil, fmt.Errorf("创建备份目录失败，未回滚: %w", err)
	}

	candidate := a.cfg.ConfigPath + ".rollback-candidate"
	defer os.Remove(candidate)
	if err := os.WriteFile(candidate, []byte(yml), 0o600); err != nil {
		return nil, fmt.Errorf("写入候选配置失败，未回滚: %w", err)
	}

	check := exec.Command("/opt/mihomo/mihomo", "-t", "-d", configDir, "-f", candidate)
	if output, err := check.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("历史配置未通过 Mihomo 校验，未回滚: %w; 输出: %s",
			err, strings.TrimSpace(string(output)))
	}

	oldConfig, readErr := os.ReadFile(a.cfg.ConfigPath)
	if readErr != nil && !os.IsNotExist(readErr) {
		return nil, fmt.Errorf("读取当前配置失败，未回滚: %w", readErr)
	}
	hadOld := readErr == nil

	if hadOld {
		backupPath := filepath.Join(a.cfg.BackupDir,
			"before-rollback-"+time.Now().Format("20060102-150405.000000")+".yaml")
		if err := os.WriteFile(backupPath, oldConfig, 0o600); err != nil {
			return nil, fmt.Errorf("备份当前配置失败，未回滚: %w", err)
		}
	}

	sum := sha256.Sum256([]byte(yml))
	cv := &ConfigVersion{
		Version: version,
		SHA256:  hex.EncodeToString(sum[:]),
		Status:  "rollback_failed",
	}

	tmp := a.cfg.ConfigPath + ".rollback-tmp"
	if err := os.WriteFile(tmp, []byte(yml), 0o600); err != nil {
		return cv, fmt.Errorf("写入回滚临时文件失败: %w", err)
	}
	defer os.Remove(tmp)

	if err := os.Rename(tmp, a.cfg.ConfigPath); err != nil {
		return cv, fmt.Errorf("替换配置失败: %w", err)
	}

	if err := a.ReloadMihomo(); err != nil {
		if !hadOld {
			_ = os.Remove(a.cfg.ConfigPath)
			cv.Status = "rollback_failed_no_previous_config"
			_ = a.store.UpdateVersionStatus(version, cv.Status)
			return cv, fmt.Errorf("历史配置重载失败，原先不存在配置文件，已移除回滚文件: %w", err)
		}

		restore := a.cfg.ConfigPath + ".rollback-restore"
		if writeErr := os.WriteFile(restore, oldConfig, 0o600); writeErr != nil {
			cv.Status = "rollback_failed_restore_failed"
			_ = a.store.UpdateVersionStatus(version, cv.Status)
			return cv, fmt.Errorf("历史配置重载失败: %v；写入恢复文件失败: %w", err, writeErr)
		}
		if renameErr := os.Rename(restore, a.cfg.ConfigPath); renameErr != nil {
			_ = os.Remove(restore)
			cv.Status = "rollback_failed_restore_failed"
			_ = a.store.UpdateVersionStatus(version, cv.Status)
			return cv, fmt.Errorf("历史配置重载失败: %v；恢复原配置失败: %w", err, renameErr)
		}

		if reloadErr := a.ReloadMihomo(); reloadErr != nil {
			cv.Status = "rollback_failed_old_reload_failed"
			_ = a.store.UpdateVersionStatus(version, cv.Status)
			return cv, fmt.Errorf("历史配置重载失败: %v；原配置文件已恢复，但重新加载也失败: %w", err, reloadErr)
		}

		cv.Status = "rollback_failed_restored"
		_ = a.store.UpdateVersionStatus(version, cv.Status)
		return cv, fmt.Errorf("回滚失败，已恢复原配置并重新加载: %w", err)
	}

	cv.Status = "rolled_back"
	if err := a.store.UpdateVersionStatus(version, cv.Status); err != nil {
		return cv, fmt.Errorf("回滚已完成，但记录版本状态失败: %w", err)
	}
	return cv, nil
}
