package app

import "testing"

func TestIsInternalSettingKey(t *testing.T) {
	internal := []string{
		"agent_token",
		"agent_machine_abc",
		"agent_mihomo_secret_abc",
		"agent_secret_abc",
		"agent_command_abc",
		"agent_command_result_abc",
		"agent_lastseen_abc",
		"agent_status_abc",
		"mihomo_secret_controller",
	}
	for _, key := range internal {
		if !isInternalSettingKey(key) {
			t.Errorf("expected %q to be internal", key)
		}
	}
	public := []string{"tun_enable", "subscribe_url", "sub_url", "theme"}
	for _, key := range public {
		if isInternalSettingKey(key) {
			t.Errorf("expected %q to remain a public setting", key)
		}
	}
}


func TestValidateProxyRejectsUnknownModeAndInvalidPorts(t *testing.T) {
	tests := []struct {
		name string
		proxy Proxy
		want string
	}{
		{
			name: "unknown mode",
			proxy: Proxy{Name: "proxy-a", Mode: "proxxy", Type: "socks5", Server: "example.com", Port: 1080},
			want: "运行模式无效",
		},
		{
			name: "zero port",
			proxy: Proxy{Name: "proxy-a", Mode: "proxy", Type: "socks5", Server: "example.com", Port: 0},
			want: "代理端口必须在 1–65535 之间",
		},
		{
			name: "port above maximum",
			proxy: Proxy{Name: "proxy-a", Mode: "proxy", Type: "socks5", Server: "example.com", Port: 65536},
			want: "代理端口必须在 1–65535 之间",
		},
		{
			name: "valid upper-bound port",
			proxy: Proxy{Name: "proxy-a", Mode: "proxy", Type: "socks5", Server: "example.com", Port: 65535},
		},
		{
			name: "empty mode defaults to proxy",
			proxy: Proxy{Name: "proxy-a", Type: "socks5", Server: "example.com", Port: 1080},
		},
	}
	app := &App{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := app.validateProxy(&tt.proxy)
			if tt.want == "" && got != "" {
				t.Fatalf("validateProxy() = %q, want success", got)
			}
			if tt.want != "" && !strings.Contains(got, tt.want) {
				t.Fatalf("validateProxy() = %q, want error containing %q", got, tt.want)
			}
		})
	}
}
