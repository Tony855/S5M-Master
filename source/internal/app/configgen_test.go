package app

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestSyncAuthorizedNodeConfigsDoesNotWriteBatchWhenAnyExistingYAMLIsInvalid(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "node-config-invalid-yaml.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	if err := store.UpdateSettings(map[string]string{
		"agent_machine_node-a":       "token-a",
		"agent_machine_node-b":       "token-b",
		"agent_mihomo_secret_node-a": "secret-a",
		"agent_mihomo_secret_node-b": "secret-b",
		"tun_enable":                 "true",
	}); err != nil {
		t.Fatalf("UpdateSettings: %v", err)
	}
	const invalidYAML = "proxies: [\n"
	const existingNodeB = "mixed-port: 7888\nsecret: node-b-secret\n"
	if err := store.SaveNodeConfig("node-a", invalidYAML); err != nil {
		t.Fatalf("seed invalid node-a config: %v", err)
	}
	if err := store.SaveNodeConfig("node-b", existingNodeB); err != nil {
		t.Fatalf("seed node-b config: %v", err)
	}
	app := &App{store: store}
	if err := app.syncAuthorizedNodeConfigs(); err == nil {
		t.Fatal("sync should fail when an authorized node has invalid existing YAML")
	}

	for code, want := range map[string]string{
		"node-a": invalidYAML,
		"node-b": existingNodeB,
	} {
		got, err := store.GetNodeConfig(code)
		if err != nil {
			t.Fatalf("GetNodeConfig(%s): %v", code, err)
		}
		if got == nil || got.YAML != want {
			t.Errorf("failed sync changed %s config: got=%+v, want YAML %q", code, got, want)
		}
	}
}

func TestSyncAuthorizedNodeConfigsPreservesNodeSettingsAndCanRetry(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "node-config-sync.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	if err := store.UpdateSettings(map[string]string{
		"agent_machine_node-a":       "agent-token",
		"agent_mihomo_secret_node-a": "node-secret",
		"tun_enable":                 "true",
	}); err != nil {
		t.Fatalf("UpdateSettings: %v", err)
	}
	customYAML := `mixed-port: 7899
secret: keep-this-secret
tun:
  enable: false
dns:
  enable: true
  listen: 127.0.0.1:5353
proxies:
  - name: stale-proxy
    type: socks5
rules:
  - MATCH,DIRECT
`
	if err := store.SaveNodeConfig("node-a", customYAML); err != nil {
		t.Fatalf("SaveNodeConfig: %v", err)
	}
	proxy := &Proxy{
		Name: "managed-proxy", Mode: "proxy", Type: "socks5",
		Server: "192.0.2.50", Port: 1080, MachineCode: "node-a",
		SourceCIDR: "0.0.0.0/0", Enabled: true,
	}
	if err := store.CreateProxy(proxy); err != nil {
		t.Fatalf("CreateProxy: %v", err)
	}

	app := &App{store: store}
	for attempt := 1; attempt <= 2; attempt++ {
		if err := app.syncAuthorizedNodeConfigs(); err != nil {
			t.Fatalf("sync attempt %d: %v", attempt, err)
		}
		got, err := store.GetNodeConfig("node-a")
		if err != nil {
			t.Fatalf("GetNodeConfig attempt %d: %v", attempt, err)
		}
		if got == nil {
			t.Fatalf("node config missing after attempt %d", attempt)
		}
		for _, want := range []string{
			"mixed-port: 7899",
			"secret: keep-this-secret",
			"enable: false",
			"listen: 127.0.0.1:5353",
			"managed-proxy",
		} {
			if !strings.Contains(got.YAML, want) {
				t.Errorf("attempt %d: synced YAML lost or omitted %q:\n%s", attempt, want, got.YAML)
			}
		}
		if strings.Contains(got.YAML, "stale-proxy") || strings.Contains(got.YAML, "MATCH,OLD-DIRECT") {
			t.Errorf("attempt %d: managed proxy/rule sections were not refreshed:\n%s", attempt, got.YAML)
		}
	}
}

func TestSyncAuthorizedNodeConfigsWithNoAuthorizedNodesLeavesExistingConfigsUntouched(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "node-config-no-agents.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	if err := store.SaveNodeConfig("historical-node", "mode: rule\n"); err != nil {
		t.Fatalf("SaveNodeConfig: %v", err)
	}
	app := &App{store: store}
	if err := app.syncAuthorizedNodeConfigs(); err != nil {
		t.Fatalf("sync with no authorized nodes should be a no-op: %v", err)
	}
	got, err := store.GetNodeConfig("historical-node")
	if err != nil {
		t.Fatalf("GetNodeConfig: %v", err)
	}
	if got == nil || got.YAML != "mode: rule\n" {
		t.Fatalf("sync with no authorized nodes unexpectedly changed historical config: %+v", got)
	}
}

func TestSaveNodeConfigsRollsBackEntireBatchOnWriteFailure(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "node-config-atomic.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	if err := store.SaveNodeConfig("node-a", "mode: old\n"); err != nil {
		t.Fatalf("seed node-a config: %v", err)
	}
	if _, err := store.db.Exec(`CREATE TRIGGER reject_node_b_config BEFORE INSERT ON node_configs
		WHEN NEW.machine_code = 'node-b'
		BEGIN SELECT RAISE(ABORT, 'simulated node-b write failure'); END`); err != nil {
		t.Fatalf("create failure trigger: %v", err)
	}

	err = store.SaveNodeConfigs(map[string]string{
		"node-a": "mode: updated\n",
		"node-b": "mode: new\n",
	})
	if err == nil {
		t.Fatal("SaveNodeConfigs should fail when one batch write fails")
	}

	got, err := store.GetNodeConfig("node-a")
	if err != nil {
		t.Fatalf("read node-a after failed batch: %v", err)
	}
	if got == nil || got.YAML != "mode: old\n" {
		t.Fatalf("failed batch partially changed node-a config: got=%+v", got)
	}
	nodeB, err := store.GetNodeConfig("node-b")
	if err != nil {
		t.Fatalf("read node-b after failed batch: %v", err)
	}
	if nodeB != nil {
		t.Fatalf("failed batch unexpectedly persisted node-b config: %+v", nodeB)
	}
}

func TestSaveNodeConfigsEmptyBatchIsNoOp(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "node-config-empty.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	if err := store.SaveNodeConfigs(map[string]string{}); err != nil {
		t.Fatalf("empty batch should be a no-op: %v", err)
	}
}

func TestBuildConfigMapsDisabledCIDRToEnabledEndpoint(t *testing.T) {
	proxies := []Proxy{
		{
			ID: 5, Name: "S5M-23049", Mode: "proxy",
			Type: "socks5", Server: "151.242.11.70", Port: 23049,
			MachineCode: "__GLOBAL__", SourceCIDR: "192.168.1.250/32", Enabled: false,
		},
		{
			ID: 7, Name: "socks5-151.242.11.70:23049", Mode: "proxy",
			Type: "socks5", Server: "151.242.11.70", Port: 23049,
			MachineCode: "__GLOBAL__", SourceCIDR: "0.0.0.0/0", Enabled: true,
		},
		{
			ID: 8, Name: "socks5-2401:b60:e00e:7244:::23050", Mode: "proxy",
			Type: "socks5", Server: "2401:b60:e00e:7244::", Port: 23050,
			MachineCode: "__GLOBAL__", SourceCIDR: "0.0.0.0/0", Enabled: true,
		},
	}

	got, err := buildConfigFromProxies(proxies, "", "test-secret")
	if err != nil {
		t.Fatalf("生成配置失败：%v", err)
	}

	wantRule := "SRC-IP-CIDR,192.168.1.250/32,socks5-151.242.11.70:23049"
	if !strings.Contains(got, wantRule) {
		t.Fatalf("缺少预期分流规则 %q\n生成内容：\n%s", wantRule, got)
	}
	if strings.Contains(got, "NETWORK,UDP,DIRECT") {
		t.Fatal("不应生成全局 UDP 直连规则")
	}
	if !strings.Contains(got, "MATCH,DIRECT") {
		t.Fatal("缺少默认 MATCH,DIRECT 规则")
	}
	for _, unwanted := range []string{"221111cdn", "^abc.*2222com"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("不应自动生成未配置的拦截规则 %q", unwanted)
		}
	}
	if strings.Contains(got, "name: S5M-23049") {
		t.Fatal("禁用的 ID 5 不应被写入代理出口列表")
	}
}

func TestBuildConfigRejectsDuplicateCIDR(t *testing.T) {
	proxies := []Proxy{
		{
			Name: "proxy-a", Mode: "proxy", Type: "socks5",
			Server: "192.0.2.10", Port: 1080,
			MachineCode: "__GLOBAL__", SourceCIDR: "192.168.1.250/32", Enabled: true,
		},
		{
			Name: "proxy-b", Mode: "proxy", Type: "socks5",
			Server: "192.0.2.11", Port: 1080,
			MachineCode: "__GLOBAL__", SourceCIDR: "192.168.1.250/32", Enabled: true,
		},
	}

	if _, err := buildConfigFromProxies(proxies, "", "test-secret"); err == nil {
		t.Fatal("重复客户端网段应返回错误")
	}
}

func TestBuildConfigRejectsInvalidCIDR(t *testing.T) {
	proxies := []Proxy{
		{
			Name: "proxy-a", Mode: "proxy", Type: "socks5",
			Server: "192.0.2.10", Port: 1080,
			MachineCode: "__GLOBAL__", SourceCIDR: "not-a-cidr", Enabled: true,
		},
	}

	if _, err := buildConfigFromProxies(proxies, "", "test-secret"); err == nil {
		t.Fatal("无效 CIDR 应返回错误")
	}
}

func TestBuildConfigRejectsInvalidPersistedProxy(t *testing.T) {
	tests := []struct {
		name  string
		proxy Proxy
	}{
		{name: "empty name", proxy: Proxy{Mode: "proxy", Type: "socks5", Server: "proxy.example", Port: 1080, MachineCode: "__GLOBAL__", Enabled: true}},
		{name: "unsupported type", proxy: Proxy{Name: "proxy-a", Mode: "proxy", Type: "vmess+ws", Server: "proxy.example", Port: 1080, MachineCode: "__GLOBAL__", Enabled: true}},
		{name: "invalid mode", proxy: Proxy{Name: "proxy-a", Mode: "unknown", Type: "socks5", Server: "proxy.example", Port: 1080, MachineCode: "__GLOBAL__", Enabled: true}},
		{name: "empty server", proxy: Proxy{Name: "proxy-a", Mode: "proxy", Type: "socks5", Port: 1080, MachineCode: "__GLOBAL__", Enabled: true}},
		{name: "server contains whitespace", proxy: Proxy{Name: "proxy-a", Mode: "proxy", Type: "socks5", Server: "proxy example", Port: 1080, MachineCode: "__GLOBAL__", Enabled: true}},
		{name: "invalid port", proxy: Proxy{Name: "proxy-a", Mode: "proxy", Type: "socks5", Server: "proxy.example", Port: 65536, MachineCode: "__GLOBAL__", Enabled: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := buildConfigFromProxies([]Proxy{tt.proxy}, "", "test-secret"); err == nil {
				t.Fatal("invalid persisted proxy should be rejected")
			}
		})
	}
}

func TestBuildConfigNormalizesPersistedProxyFields(t *testing.T) {
	proxy := Proxy{
		Name: " proxy-a ", Mode: " proxy ", Type: " SOCKS5 ",
		Server: " proxy.example ", Port: 1080, MachineCode: "__GLOBAL__", Enabled: true,
	}
	got, err := buildConfigFromProxies([]Proxy{proxy}, "", "test-secret")
	if err != nil {
		t.Fatalf("buildConfigFromProxies() error = %v", err)
	}
	for _, want := range []string{"name: proxy-a", "type: socks5", "server: proxy.example"} {
		if !strings.Contains(got, want) {
			t.Errorf("generated config missing normalized field %q:\\n%s", want, got)
		}
	}
}

func TestMergeManagedProxySectionsPreservesCustomSettings(t *testing.T) {
	custom := `mode: global
mixed-port: 7890
dns:
  enable: true
proxies:
  - name: stale-proxy
    type: socks5
rules:
  - MATCH,DIRECT
`
	generated := `mode: rule
mixed-port: 8080
proxies:
  - name: managed-proxy
    type: http
rules:
  - MATCH,managed-proxy
`

	got, err := mergeManagedProxySections(custom, generated)
	if err != nil {
		t.Fatalf("合并全局配置失败: %v", err)
	}
	for _, want := range []string{"mode: global", "mixed-port: 7890", "enable: true", "managed-proxy", "MATCH,managed-proxy"} {
		if !strings.Contains(got, want) {
			t.Errorf("合并配置缺少 %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "stale-proxy") || strings.Contains(got, "MATCH,DIRECT") {
		t.Fatalf("代理数据库管理的 proxies/rules 应覆盖旧内容:\n%s", got)
	}
}

func TestMergeManagedProxySectionsRejectsInvalidOrEmptyYAML(t *testing.T) {
	generated := "mode: rule\nproxies: []\nrules: []\n"
	for _, custom := range []string{"not: [valid", "[]", ""} {
		if _, err := mergeManagedProxySections(custom, generated); err == nil {
			t.Errorf("全局配置 %q 应返回错误", custom)
		}
	}
}

func TestGetOrCreateMihomoSecretReusesConfiguredSecret(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "mihomo-secret-test.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	app := &App{cfg: Config{MihomoSecret: "configured-secret"}, store: store}
	got, err := app.getOrCreateMihomoSecret("mihomo_secret_controller")
	if err != nil {
		t.Fatalf("getOrCreateMihomoSecret(): %v", err)
	}
	if got != "configured-secret" {
		t.Fatalf("secret = %q, want configured secret", got)
	}
	settings, err := store.GetSettings()
	if err != nil {
		t.Fatalf("GetSettings(): %v", err)
	}
	if settings["mihomo_secret_controller"] != "configured-secret" {
		t.Fatalf("persisted secret = %q, want configured secret", settings["mihomo_secret_controller"])
	}
}

func TestBuildConfigForMachineExcludesUnboundProxy(t *testing.T) {
	proxies := []Proxy{
		{Name: "bound-proxy", Mode: "proxy", Type: "socks5", Server: "192.0.2.10", Port: 1080, MachineCode: "node-a", Enabled: true},
		{Name: "unbound-proxy", Mode: "proxy", Type: "socks5", Server: "192.0.2.11", Port: 1081, Enabled: true},
	}
	got, err := buildConfigFromProxies(proxies, "node-a", "test-secret")
	if err != nil {
		t.Fatalf("buildConfigFromProxies() error = %v", err)
	}
	if !strings.Contains(got, "bound-proxy") {
		t.Fatal("node-specific config should include its bound proxy")
	}
	if strings.Contains(got, "unbound-proxy") {
		t.Fatal("node-specific config must exclude unbound proxies")
	}
}

func TestBuildConfigSupportsExplicitGlobalAndUnboundProxies(t *testing.T) {
	proxies := []Proxy{
		{Name: "global-proxy", Mode: "proxy", Type: "socks5", Server: "192.0.2.10", Port: 1080, MachineCode: "__GLOBAL__", Enabled: true},
		{Name: "bound-proxy", Mode: "proxy", Type: "socks5", Server: "192.0.2.11", Port: 1081, MachineCode: "node-a", Enabled: true},
		{Name: "unbound-proxy", Mode: "proxy", Type: "socks5", Server: "192.0.2.12", Port: 1082, Enabled: true},
	}
	nodeConfig, err := buildConfigFromProxies(proxies, "node-a", "test-secret")
	if err != nil {
		t.Fatalf("node config error = %v", err)
	}
	for _, want := range []string{"global-proxy", "bound-proxy"} {
		if !strings.Contains(nodeConfig, want) {
			t.Errorf("node config missing %q", want)
		}
	}
	if strings.Contains(nodeConfig, "unbound-proxy") {
		t.Fatal("node config must exclude unbound proxy")
	}
	globalConfig, err := buildConfigFromProxies(proxies, "", "test-secret")
	if err != nil {
		t.Fatalf("global config error = %v", err)
	}
	if !strings.Contains(globalConfig, "global-proxy") {
		t.Fatal("global config must include explicitly global proxy")
	}
	if strings.Contains(globalConfig, "bound-proxy") || strings.Contains(globalConfig, "unbound-proxy") {
		t.Fatal("global/default config must exclude machine-bound and unbound proxies")
	}
}

func TestBuildConfigRoutesConfiguredDoHThroughProxy(t *testing.T) {
	proxies := []Proxy{{
		Name: "proxy-a", Mode: "proxy", Type: "socks5",
		Server: "192.0.2.10", Port: 1080, MachineCode: "__GLOBAL__", Enabled: true,
	}}
	got, err := buildConfigFromProxies(proxies, "", "test-secret")
	if err != nil {
		t.Fatalf("buildConfigFromProxies() error = %v", err)
	}
	for _, want := range []string{
		"respect-rules: true",
		"proxy-server-nameserver:",
		"DOMAIN-SUFFIX,dns.alidns.com,proxy-a",
		"DOMAIN-SUFFIX,doh.pub,proxy-a",
		"DOMAIN-SUFFIX,dns.cloudflare.com,proxy-a",
		"DOMAIN-SUFFIX,dns.google,proxy-a",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("generated config missing %q:\\n%s", want, got)
		}
	}
}

func TestBuildConfigWithoutProxyKeepsDNSBootstrapValid(t *testing.T) {
	got, err := buildConfigFromProxies(nil, "", "test-secret")
	if err != nil {
		t.Fatalf("buildConfigFromProxies() error = %v", err)
	}
	if !strings.Contains(got, "proxy-server-nameserver:") || !strings.Contains(got, "respect-rules: true") {
		t.Fatalf("DNS bootstrap options should exist even without enabled proxies:\\n%s", got)
	}
	if strings.Contains(got, "DOMAIN-SUFFIX,doh.pub,") {
		t.Fatalf("must not generate DNS proxy rules without an enabled proxy:\\n%s", got)
	}
}

func TestBuildConfigIncludesTUNDNSDefaults(t *testing.T) {
	got, err := buildConfigFromProxies(nil, "", "test-secret")
	if err != nil {
		t.Fatalf("buildConfigFromProxies() error = %v", err)
	}
	for _, want := range []string{
		"enable: true",
		"strict-route: true",
		"any:53",
		"tcp://any:53",
		"enhanced-mode: fake-ip",
		"cache-algorithm: arc",
		"listen: 0.0.0.0:5353",
		"fallback:",
		"https://dns.cloudflare.com/dns-query",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("generated TUN/DNS config missing %q:\n%s", want, got)
		}
	}
	if !strings.Contains(got, "Bootstrap DNS is plain DNS") {
		t.Errorf("generated config should document bootstrap DNS limitation:\n%s", got)
	}
}
