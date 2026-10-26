package app

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildConfigMapsDisabledCIDRToEnabledEndpoint(t *testing.T) {
	proxies := []Proxy{
		{
			ID: 5, Name: "S5M-23049", Mode: "proxy",
			Type: "socks5", Server: "151.242.11.70", Port: 23049,
			SourceCIDR: "192.168.1.250/32", Enabled: false,
		},
		{
			ID: 7, Name: "socks5-151.242.11.70:23049", Mode: "proxy",
			Type: "socks5", Server: "151.242.11.70", Port: 23049,
			SourceCIDR: "0.0.0.0/0", Enabled: true,
		},
		{
			ID: 8, Name: "socks5-2401:b60:e00e:7244:::23050", Mode: "proxy",
			Type: "socks5", Server: "2401:b60:e00e:7244::", Port: 23050,
			SourceCIDR: "0.0.0.0/0", Enabled: true,
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
	if strings.Contains(got, "name: S5M-23049") {
		t.Fatal("禁用的 ID 5 不应被写入代理出口列表")
	}
}

func TestBuildConfigRejectsDuplicateCIDR(t *testing.T) {
	proxies := []Proxy{
		{
			Name: "proxy-a", Mode: "proxy", Type: "socks5",
			Server: "192.0.2.10", Port: 1080,
			SourceCIDR: "192.168.1.250/32", Enabled: true,
		},
		{
			Name: "proxy-b", Mode: "proxy", Type: "socks5",
			Server: "192.0.2.11", Port: 1080,
			SourceCIDR: "192.168.1.250/32", Enabled: true,
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
			SourceCIDR: "not-a-cidr", Enabled: true,
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
		{name: "empty name", proxy: Proxy{Mode: "proxy", Type: "socks5", Server: "proxy.example", Port: 1080, Enabled: true}},
		{name: "unsupported type", proxy: Proxy{Name: "proxy-a", Mode: "proxy", Type: "vmess+ws", Server: "proxy.example", Port: 1080, Enabled: true}},
		{name: "invalid mode", proxy: Proxy{Name: "proxy-a", Mode: "unknown", Type: "socks5", Server: "proxy.example", Port: 1080, Enabled: true}},
		{name: "empty server", proxy: Proxy{Name: "proxy-a", Mode: "proxy", Type: "socks5", Port: 1080, Enabled: true}},
		{name: "server contains whitespace", proxy: Proxy{Name: "proxy-a", Mode: "proxy", Type: "socks5", Server: "proxy example", Port: 1080, Enabled: true}},
		{name: "invalid port", proxy: Proxy{Name: "proxy-a", Mode: "proxy", Type: "socks5", Server: "proxy.example", Port: 65536, Enabled: true}},
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
		Server: " proxy.example ", Port: 1080, Enabled: true,
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

func TestBuildConfigRoutesConfiguredDoHThroughProxy(t *testing.T) {
	proxies := []Proxy{{
		Name: "proxy-a", Mode: "proxy", Type: "socks5",
		Server: "192.0.2.10", Port: 1080, Enabled: true,
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
