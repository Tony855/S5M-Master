package app

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestDecodeErrorStatus(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{name: "oversized body", err: errors.New("请求体超过 8 KiB 限制"), want: http.StatusRequestEntityTooLarge},
		{name: "malformed JSON", err: errors.New("invalid character"), want: http.StatusBadRequest},
		{name: "nil error", err: nil, want: http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := decodeErrorStatus(tt.err); got != tt.want {
				t.Fatalf("decodeErrorStatus() = %d, want %d", got, tt.want)
			}
		})
	}
}

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
		name  string
		proxy Proxy
		want  string
	}{
		{
			name:  "unknown mode",
			proxy: Proxy{Name: "proxy-a", Mode: "proxxy", Type: "socks5", Server: "example.com", Port: 1080},
			want:  "运行模式无效",
		},
		{
			name:  "unsupported direct mode",
			proxy: Proxy{Name: "proxy-a", Mode: "direct"},
			want:  "运行模式无效",
		},
		{
			name:  "zero port",
			proxy: Proxy{Name: "proxy-a", Mode: "proxy", Type: "socks5", Server: "example.com", Port: 0},
			want:  "代理端口必须在 1-65535 之间",
		},
		{
			name:  "port above maximum",
			proxy: Proxy{Name: "proxy-a", Mode: "proxy", Type: "socks5", Server: "example.com", Port: 65536},
			want:  "代理端口必须在 1-65535 之间",
		},
		{
			name:  "valid upper-bound port",
			proxy: Proxy{Name: "proxy-a", Mode: "proxy", Type: "socks5", Server: "example.com", Port: 65535},
		},
		{
			name:  "empty mode defaults to proxy",
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

func TestParseProxyLineRejectsInvalidPort(t *testing.T) {
	for _, line := range []string{
		"socks5://user:pass@example.com:not-a-port",
		"socks5://user:pass@example.com:0",
		"socks5://user:pass@example.com:65536",
	} {
		if _, err := parseProxyLine(line); err == nil {
			t.Errorf("parseProxyLine(%q) should reject invalid port", line)
		}
	}
}

func TestParseProxyLineAcceptsValidPort(t *testing.T) {
	proxy, err := parseProxyLine("socks5://user:pass@example.com:65535#valid")
	if err != nil {
		t.Fatalf("parseProxyLine() error = %v", err)
	}
	if proxy.Port != 65535 {
		t.Fatalf("port = %d, want 65535", proxy.Port)
	}
	if msg := (&App{}).validateProxy(proxy); msg != "" {
		t.Fatalf("validateProxy() = %q, want success", msg)
	}
}

func TestValidateProxyRejectsUnsupportedProtocol(t *testing.T) {
	for _, protocol := range []string{"", "unknown", "socks", "vmess+ws"} {
		proxy := Proxy{Name: "proxy-a", Mode: "proxy", Type: protocol, Server: "example.com", Port: 1080}
		if msg := (&App{}).validateProxy(&proxy); !strings.Contains(msg, "代理类型无效") {
			t.Errorf("validateProxy(type=%q) = %q, want unsupported-protocol error", protocol, msg)
		}
	}
}

func TestValidateProxyNormalizesSupportedProtocol(t *testing.T) {
	proxy := Proxy{Name: "proxy-a", Mode: "proxy", Type: " SOCKS5 ", Server: "example.com", Port: 1080}
	if msg := (&App{}).validateProxy(&proxy); msg != "" {
		t.Fatalf("validateProxy() = %q, want success", msg)
	}
	if proxy.Type != "socks5" {
		t.Fatalf("type = %q, want normalized socks5", proxy.Type)
	}
}

func TestValidateInstance(t *testing.T) {
	tests := []struct {
		name    string
		input   Instance
		wantErr string
	}{
		{name: "blank name", input: Instance{Name: "  "}, wantErr: "实例名称不能为空"},
		{name: "name too long", input: Instance{Name: strings.Repeat("a", 101)}, wantErr: "不能超过 100 个字符"},
		{name: "machine code too long", input: Instance{Name: "node-a", MachineCode: strings.Repeat("a", 129)}, wantErr: "机器码不能超过 128 个字符"},
		{name: "malformed URL", input: Instance{Name: "node-a", APIURL: "://bad"}, wantErr: "API 地址必须是有效的 HTTP 或 HTTPS URL"},
		{name: "unsupported URL scheme", input: Instance{Name: "node-a", APIURL: "ftp://example.com"}, wantErr: "API 地址必须是有效的 HTTP 或 HTTPS URL"},
		{name: "URL with credentials", input: Instance{Name: "node-a", APIURL: "https://user:pass@example.com/api"}, wantErr: "不能包含用户名或密码"},
		{name: "valid URL and normalization", input: Instance{Name: " node-a ", MachineCode: " code-1 ", APIURL: " https://example.com/api "}},
		{name: "optional API URL", input: Instance{Name: "node-a"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.input
			msg := validateInstance(&got)
			if tt.wantErr != "" {
				if !strings.Contains(msg, tt.wantErr) {
					t.Fatalf("validateInstance() = %q, want error containing %q", msg, tt.wantErr)
				}
				return
			}
			if msg != "" {
				t.Fatalf("validateInstance() = %q, want success", msg)
			}
			if got.Name != strings.TrimSpace(tt.input.Name) || got.MachineCode != strings.TrimSpace(tt.input.MachineCode) || got.APIURL != strings.TrimSpace(tt.input.APIURL) {
				t.Fatalf("instance fields were not normalized: %#v", got)
			}
		})
	}
}

func TestDecodeBoundsJSONRequestBody(t *testing.T) {
	t.Run("rejects oversized body", func(t *testing.T) {
		body := strings.NewReader(`{"value":"` + strings.Repeat("a", maxJSONRequestBody) + `"}`)
		req := httptest.NewRequest("POST", "/", body)
		var dst map[string]string
		if err := decode(req, &dst); err == nil || !strings.Contains(err.Error(), "2 MiB") {
			t.Fatalf("decode() error = %v, want request-size error", err)
		}
	})
	t.Run("rejects trailing JSON value", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/", strings.NewReader(`{"ok":true} {"extra":true}`))
		var dst map[string]bool
		if err := decode(req, &dst); err == nil {
			t.Fatal("decode() accepted multiple JSON values")
		}
	})
	t.Run("accepts valid JSON", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/", strings.NewReader(`{"ok":true}`))
		var dst map[string]bool
		if err := decode(req, &dst); err != nil || !dst["ok"] {
			t.Fatalf("decode() = %#v, %v; want valid JSON", dst, err)
		}
	})
}

func TestValidateAgentRegistrationInput(t *testing.T) {
	tests := []struct {
		name        string
		machineCode string
		secret      string
		wantErr     string
	}{
		{name: "trims valid values", machineCode: " node_01-abc ", secret: " token "},
		{name: "rejects blank machine code", machineCode: "   ", secret: "token", wantErr: "机器码格式错误"},
		{name: "rejects invalid machine code characters", machineCode: "node/01", secret: "token", wantErr: "机器码格式错误"},
		{name: "rejects oversized machine code", machineCode: strings.Repeat("a", 65), secret: "token", wantErr: "机器码格式错误"},
		{name: "rejects blank secret", machineCode: "node01", secret: "  ", wantErr: "专属 Token 长度无效"},
		{name: "rejects oversized secret", machineCode: "node01", secret: strings.Repeat("x", 257), wantErr: "专属 Token 长度无效"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			machineCode, secret, gotErr := validateAgentRegistrationInput(tt.machineCode, tt.secret)
			if !strings.Contains(gotErr, tt.wantErr) && tt.wantErr != "" {
				t.Fatalf("error = %q, want %q", gotErr, tt.wantErr)
			}
			if tt.wantErr == "" {
				if gotErr != "" || machineCode != strings.TrimSpace(tt.machineCode) || secret != strings.TrimSpace(tt.secret) {
					t.Fatalf("normalized values = %q, %q, error %q", machineCode, secret, gotErr)
				}
			}
		})
	}
}

func TestAgentAuthorizationUsesOneValidatorAndRevokesChangedTokens(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "agent-auth-test.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	const machineCode = "node_01"
	const machineSecret = "dedicated-secret"
	const globalSecret = "global-secret"
	app := &App{store: store, jwtKey: []byte("test-jwt-secret")}
	if err := store.UpdateSettings(map[string]string{
		"agent_token":                  globalSecret,
		"agent_machine_" + machineCode: machineSecret,
	}); err != nil {
		t.Fatalf("UpdateSettings: %v", err)
	}
	version := sha256.Sum256([]byte(machineSecret))
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":  machineCode,
		"role": "agent",
		"ver":  hex.EncodeToString(version[:]),
	}).SignedString(app.jwtKey)
	if err != nil {
		t.Fatalf("sign Agent token: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/agent/config", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	code, err := app.agentMachineFromRequest(req)
	if err != nil || code != machineCode {
		t.Fatalf("agentMachineFromRequest() = %q, %v; want %q", code, err, machineCode)
	}
	if got, ok := app.agentMachineCode(req); !ok || got != machineCode {
		t.Fatalf("agentMachineCode() = %q, %v; want %q, true", got, ok, machineCode)
	}

	if err := store.UpdateSettings(map[string]string{"agent_machine_" + machineCode: "rotated-secret"}); err != nil {
		t.Fatalf("rotate dedicated token: %v", err)
	}
	if _, err := app.agentMachineFromRequest(req); err == nil {
		t.Fatal("old Agent JWT remained valid after dedicated token rotation")
	}
	if _, ok := app.agentMachineCode(req); ok {
		t.Fatal("boolean Agent validator accepted a revoked JWT")
	}
}

func TestSaveNodeConfigRejectsTrailingJSON(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "node-config-json.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	const code = "node_json"
	if err := store.UpdateSettings(map[string]string{
		"agent_token":           "global-secret",
		"agent_machine_" + code: "dedicated-secret",
	}); err != nil {
		t.Fatalf("UpdateSettings: %v", err)
	}
	app := &App{store: store}
	body := `{"config_yaml":"secret: node-secret\ntun:\n  enable: false\ndns:\n  enable: false\n"} {"unexpected":true}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/nodes/"+code+"/config", strings.NewReader(body))
	req.SetPathValue("code", code)
	rec := httptest.NewRecorder()

	app.handleSaveNodeConfig(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
	if _, err := store.GetNodeConfig(code); err != nil {
		t.Fatalf("GetNodeConfig: %v", err)
	} else if cfg, _ := store.GetNodeConfig(code); cfg != nil {
		t.Fatal("invalid request unexpectedly persisted a node config")
	}
}

func TestDecodeLimitedRejectsTrailingJSONAndOversizedBody(t *testing.T) {
	t.Run("trailing JSON", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/", strings.NewReader(`{"ok":true} {"extra":true}`))
		var dst map[string]bool
		if err := decodeLimited(req, 128, "128 bytes", &dst); err == nil {
			t.Fatal("decodeLimited() accepted multiple JSON values")
		}
	})
	t.Run("oversized body", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/", strings.NewReader(`{"value":"`+strings.Repeat("x", 129)+`"}`))
		var dst map[string]string
		if err := decodeLimited(req, 128, "128 bytes", &dst); err == nil || !strings.Contains(err.Error(), "128 bytes") {
			t.Fatalf("decodeLimited() error = %v, want size-limit error", err)
		}
	})
}

func TestImportProxiesRejectsOversizedBodyWith413(t *testing.T) {
	app := &App{}
	body := `{"content":"` + strings.Repeat("x", (1<<20)+1) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/proxies/import", strings.NewReader(body))
	rec := httptest.NewRecorder()

	app.handleImportProxies(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusRequestEntityTooLarge, rec.Body.String())
	}
}

func TestSaveNodeConfigRejectsOversizedBodyWith413(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "node-config-oversize.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	const code = "node_oversize"
	if err := store.UpdateSettings(map[string]string{
		"agent_token":           "global-secret",
		"agent_machine_" + code: "dedicated-secret",
	}); err != nil {
		t.Fatalf("UpdateSettings: %v", err)
	}
	app := &App{store: store}
	body := `{"config_yaml":"` + strings.Repeat("x", (2<<20)+1) + `"}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/nodes/"+code+"/config", strings.NewReader(body))
	req.SetPathValue("code", code)
	rec := httptest.NewRecorder()

	app.handleSaveNodeConfig(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusRequestEntityTooLarge, rec.Body.String())
	}
	cfg, err := store.GetNodeConfig(code)
	if err != nil {
		t.Fatalf("GetNodeConfig: %v", err)
	}
	if cfg != nil {
		t.Fatal("oversized request unexpectedly persisted a node config")
	}
}

func TestParseProxyImportContentSOCKS5JSONIPv4IPv6(t *testing.T) {
	content := `{
		"protocol":"socks5",
		"authentication":{"enabled":true,"username":"global-user","password":"global-pass"},
		"servers":[
			{"server":"151.242.11.70","port":23049,"username":"","password":"","udp":true},
			{"server":"2401:b60:e00e:7244::","port":23050,"username":"","password":"","udp":true}
		]
	}`
	proxies, failures := parseProxyImportContent(content)
	if len(failures) != 0 {
		t.Fatalf("unexpected failures: %v", failures)
	}
	if len(proxies) != 2 {
		t.Fatalf("got %d proxies, want 2", len(proxies))
	}
	if proxies[0].Server != "151.242.11.70" || proxies[0].Port != 23049 {
		t.Fatalf("unexpected IPv4 proxy: %+v", proxies[0])
	}
	if proxies[1].Server != "2401:b60:e00e:7244::" || proxies[1].Port != 23050 {
		t.Fatalf("unexpected IPv6 proxy: %+v", proxies[1])
	}
	for i, p := range proxies {
		if p.Type != "socks5" {
			t.Errorf("proxy %d type = %q", i, p.Type)
		}
		if p.Extra["username"] != "global-user" || p.Extra["password"] != "global-pass" {
			t.Errorf("proxy %d authentication not inherited: %#v", i, p.Extra)
		}
		if p.Extra["udp"] != true {
			t.Errorf("proxy %d UDP flag not preserved", i)
		}
	}
}

func TestParseProxyImportContentRejectsMalformedJSON(t *testing.T) {
	proxies, failures := parseProxyImportContent(`{"protocol":"socks5","servers":[`)
	if len(proxies) != 0 || len(failures) == 0 {
		t.Fatalf("expected malformed JSON failure, got proxies=%v failures=%v", proxies, failures)
	}
}

func TestWaitForMihomoAPIVersionConfirmsRunningVersion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/version" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"version":"v1.2.3"}`))
	}))
	defer server.Close()

	app := &App{cfg: Config{MihomoAPI: server.URL}}
	if err := app.waitForMihomoAPIVersion("v1.2.3", time.Second); err != nil {
		t.Fatalf("waitForMihomoAPIVersion() unexpected error: %v", err)
	}
}

func TestWaitForMihomoAPIVersionRejectsWrongRunningVersion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"version":"v1.2.2"}`))
	}))
	defer server.Close()

	app := &App{cfg: Config{MihomoAPI: server.URL}}
	err := app.waitForMihomoAPIVersion("v1.2.3", 25*time.Millisecond)
	if err == nil {
		t.Fatal("waitForMihomoAPIVersion() accepted a mismatched running version")
	}
	if !strings.Contains(err.Error(), "运行版本不匹配") {
		t.Fatalf("error = %q, want version mismatch diagnostic", err)
	}
}

func TestHandleGetAgentsExposesPendingAndCompletedCommandState(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "agent-command-state.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	const machineCode = "node_status"
	pending := `{"id":"cmd-2","type":"update_mihomo","version":"v1.2.3","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`
	previous := `{"id":"cmd-1","type":"update_mihomo","status":"failed","message":"previous update failed","updated_at":123}`
	if err := store.UpdateSettings(map[string]string{
		"agent_token":                         "global-secret",
		"agent_machine_" + machineCode:        "dedicated-secret",
		"agent_command_" + machineCode:        pending,
		"agent_command_result_" + machineCode: previous,
	}); err != nil {
		t.Fatalf("UpdateSettings: %v", err)
	}

	app := &App{store: store}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents", nil)
	rec := httptest.NewRecorder()
	app.handleGetAgents(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var payload map[string]map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	node := payload[machineCode]
	if node["token_configured"] != true {
		t.Fatalf("token_configured = %#v, want true for an authorized Agent", node["token_configured"])
	}
	pendingCommand, ok := node["pending_command"].(map[string]any)
	if !ok || pendingCommand["id"] != "cmd-2" || pendingCommand["version"] != "v1.2.3" {
		t.Fatalf("pending_command = %#v, want pending Mihomo update cmd-2/v1.2.3", node["pending_command"])
	}
	commandResult, ok := node["command_result"].(map[string]any)
	if !ok || commandResult["id"] != "cmd-1" || commandResult["status"] != "failed" {
		t.Fatalf("command_result = %#v, want previous failed result cmd-1", node["command_result"])
	}
}


func TestRunningMihomoAPIVersionReportsControllerVersion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/version" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"version":"v1.19.33"}`))
	}))
	defer server.Close()

	app := &App{cfg: Config{MihomoAPI: server.URL}}
	version, err := app.runningMihomoAPIVersion()
	if err != nil {
		t.Fatalf("runningMihomoAPIVersion() error = %v", err)
	}
	if version != "v1.19.33" {
		t.Fatalf("running version = %q, want v1.19.33", version)
	}
}

func TestRunningMihomoAPIVersionRejectsUnavailableController(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "controller unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	app := &App{cfg: Config{MihomoAPI: server.URL}}
	if version, err := app.runningMihomoAPIVersion(); err == nil {
		t.Fatalf("runningMihomoAPIVersion() = %q, nil error; want API error", version)
	}
}
