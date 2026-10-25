package app

import (
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
