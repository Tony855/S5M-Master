package main

import (
	"errors"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func TestMihomoSecretCandidates(t *testing.T) {
	dir := t.TempDir()
	configPath := dir + "/config.yaml"
	previousPath := configPath + ".previous"

	if err := os.WriteFile(previousPath, []byte("secret: old-secret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte("secret: \"new-secret\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := mihomoSecretCandidates(configPath)
	if err != nil {
		t.Fatalf("mihomoSecretCandidates() error = %v", err)
	}
	if len(got) != 2 || got[0] != "old-secret" || got[1] != "new-secret" {
		t.Fatalf("secret candidates = %#v, want previous then current", got)
	}

	if err := os.WriteFile(previousPath, []byte("secret: same-secret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte("secret: same-secret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err = mihomoSecretCandidates(configPath)
	if err != nil {
		t.Fatalf("deduplicated candidates returned error: %v", err)
	}
	if len(got) != 1 || got[0] != "same-secret" {
		t.Fatalf("duplicate secret candidates = %#v, want one unique secret", got)
	}

	if err := os.WriteFile(configPath, []byte("secret: \"\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(previousPath); err != nil {
		t.Fatal(err)
	}
	if _, err := mihomoSecretCandidates(configPath); err == nil {
		t.Fatal("expected error when no valid secret exists")
	}
}

func TestValidateCentralURL(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
		ok   bool
	}{
		{name: "https", in: " https://controller.example.com/ ", want: "https://controller.example.com", ok: true},
		{name: "http local network", in: "http://192.0.2.10:8080", want: "http://192.0.2.10:8080", ok: true},
		{name: "missing scheme", in: "controller.example.com", ok: false},
		{name: "unsupported scheme", in: "ftp://controller.example.com", ok: false},
		{name: "missing host", in: "https://", ok: false},
		{name: "userinfo", in: "https://user:pass@controller.example.com", ok: false},
		{name: "query", in: "https://controller.example.com?token=x", ok: false},
		{name: "fragment", in: "https://controller.example.com#fragment", ok: false},
		{name: "newline", in: "https://controller.example.com\r\nX-Injected: yes", ok: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := validateCentralURL(tt.in)
			if tt.ok {
				if err != nil {
					t.Fatalf("expected valid URL, got error: %v", err)
				}
				if got != tt.want {
					t.Fatalf("URL = %q, want %q", got, tt.want)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected invalid URL %q to be rejected; got %q", tt.in, got)
			}
		})
	}
}

func TestValidateKernelUpdateCommand(t *testing.T) {
	tests := []struct {
		name    string
		version string
		sha256  string
		wantErr bool
	}{
		{name: "valid", version: "v1.19.31", sha256: strings.Repeat("a", 64)},
		{name: "missing v prefix", version: "1.19.31", sha256: strings.Repeat("a", 64), wantErr: true},
		{name: "version injection", version: "v1.19.31/../../latest", sha256: strings.Repeat("a", 64), wantErr: true},
		{name: "prerelease unsupported", version: "v1.19.31-rc.1", sha256: strings.Repeat("a", 64), wantErr: true},
		{name: "short checksum", version: "v1.19.31", sha256: "abcd", wantErr: true},
		{name: "non hex checksum", version: "v1.19.31", sha256: strings.Repeat("z", 64), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateKernelUpdateCommand(agentCommand{Version: tt.version, SHA256: tt.sha256})
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateKernelUpdateCommand() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateMihomoConfigYAML(t *testing.T) {
	valid := []byte("mixed-port: 7890\nsecret: test-secret\ntun:\n  enable: false\ndns:\n  enable: true\n  nameserver:\n    - 1.1.1.1\n")
	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{name: "valid full config", data: valid},
		{name: "empty", data: []byte(""), wantErr: true},
		{name: "malformed yaml", data: []byte("tun: ["), wantErr: true},
		{name: "empty document", data: []byte("---\n"), wantErr: true},
		{name: "missing secret", data: []byte("tun: {}\ndns: {}\n"), wantErr: true},
		{name: "blank secret", data: []byte("secret: '  '\ntun: {}\ndns: {}\n"), wantErr: true},
		{name: "missing tun", data: []byte("secret: test\ndns: {}\n"), wantErr: true},
		{name: "tun wrong type", data: []byte("secret: test\ntun: false\ndns: {}\n"), wantErr: true},
		{name: "missing dns", data: []byte("secret: test\ntun: {}\n"), wantErr: true},
		{name: "dns wrong type", data: []byte("secret: test\ntun: {}\ndns: true\n"), wantErr: true},
		{name: "over size limit", data: append(valid, []byte(strings.Repeat(" ", 2*1024*1024))...), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := validateMihomoConfigYAML(tt.data)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateMihomoConfigYAML() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNewMihomoRestartRequest(t *testing.T) {
	req, err := newMihomoRestartRequest("test-secret")
	if err != nil {
		t.Fatalf("newMihomoRestartRequest() error = %v", err)
	}
	if req.Method != http.MethodPost {
		t.Fatalf("restart method = %q, want %q", req.Method, http.MethodPost)
	}
	if req.URL.String() != "http://127.0.0.1:8088/restart" {
		t.Fatalf("restart URL = %q", req.URL.String())
	}
	if got := req.Header.Get("Authorization"); got != "Bearer test-secret" {
		t.Fatalf("Authorization = %q, want bearer secret", got)
	}
}

func TestMihomoVersionMatches(t *testing.T) {
	tests := []struct {
		name, actual, expected string
		want                   bool
	}{
		{name: "exact", actual: "1.19.31", expected: "1.19.31", want: true},
		{name: "prefix v", actual: "v1.19.31", expected: "1.19.31", want: true},
		{name: "both prefix v", actual: "v1.19.31", expected: "v1.19.31", want: true},
		{name: "different version", actual: "1.19.30", expected: "1.19.31"},
		{name: "empty actual", actual: "", expected: "1.19.31"},
		{name: "empty expected", actual: "1.19.31", expected: ""},
		{name: "suffix mismatch", actual: "1.19.31-dev", expected: "1.19.31"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := mihomoVersionMatches(tt.actual, tt.expected); got != tt.want {
				t.Fatalf("mihomoVersionMatches(%q, %q) = %v, want %v", tt.actual, tt.expected, got, tt.want)
			}
		})
	}
}

func TestVerifyKernelUpgrade(t *testing.T) {
	restartFailure := errors.New("restart connection closed")
	healthFailure := errors.New("version health check timed out")
	rollbackFailure := errors.New("restore failed")

	tests := []struct {
		name         string
		restartErr   error
		healthErr    error
		rollbackErr  error
		wantErr      bool
		wantRollback bool
		wantErrParts []string
	}{
		{
			name:       "restart transport error but new version healthy",
			restartErr: restartFailure,
		},
		{
			name:         "health check fails and rollback succeeds",
			healthErr:    healthFailure,
			wantErr:      true,
			wantRollback: true,
			wantErrParts: []string{"健康检查失败", "已恢复旧内核"},
		},
		{
			name:         "health and rollback both fail",
			healthErr:    healthFailure,
			rollbackErr:  rollbackFailure,
			wantErr:      true,
			wantRollback: true,
			wantErrParts: []string{"健康检查失败", "恢复旧内核失败", "restore failed"},
		},
		{
			name:         "restart and health fail but rollback succeeds",
			restartErr:   restartFailure,
			healthErr:    healthFailure,
			wantErr:      true,
			wantRollback: true,
			wantErrParts: []string{"重启请求返回错误", "健康检查", "已恢复旧内核"},
		},
		{
			name:         "restart fails and rollback fails",
			restartErr:   restartFailure,
			healthErr:    healthFailure,
			rollbackErr:  rollbackFailure,
			wantErr:      true,
			wantRollback: true,
			wantErrParts: []string{"重启请求返回错误", "健康检查失败", "恢复旧内核失败"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rollbackCalled := false
			err := verifyKernelUpgrade(
				func() error { return tt.restartErr },
				func() error { return tt.healthErr },
				func() error {
					rollbackCalled = true
					return tt.rollbackErr
				},
			)
			if (err != nil) != tt.wantErr {
				t.Fatalf("verifyKernelUpgrade() error = %v, wantErr %v", err, tt.wantErr)
			}
			if rollbackCalled != tt.wantRollback {
				t.Fatalf("rollback called = %v, want %v", rollbackCalled, tt.wantRollback)
			}
			if !tt.wantErr && rollbackCalled {
				t.Fatal("successful health check must not trigger rollback")
			}
			if err != nil {
				for _, part := range tt.wantErrParts {
					if !strings.Contains(err.Error(), part) {
						t.Errorf("error %q does not contain %q", err, part)
					}
				}
			}
		})
	}
}

func TestExecuteContainerTaskRejectsUnsafeOrIncompleteInput(t *testing.T) {
	tests := []struct {
		name string
		task containerTask
	}{
		{name: "unknown action", task: containerTask{Action: "docker.exec", Params: []byte("{}")}},
		{name: "missing container id", task: containerTask{Action: "docker.inspect", Params: []byte("{}")}},
		{name: "container id with whitespace", task: containerTask{Action: "docker.stop", Params: []byte(`{"container_id":"prod app"}`)}},
		{name: "invalid log tail", task: containerTask{Action: "docker.logs", Params: []byte(`{"container_id":"proxy-1","tail":501}`)}},
		{name: "invalid parameter type", task: containerTask{Action: "docker.inspect", Params: []byte(`{"container_id":123}`)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := executeContainerTask(tt.task); err == nil {
				t.Fatal("expected invalid task input to be rejected")
			}
		})
	}
}

func TestValidDockerContainerID(t *testing.T) {
	valid := []string{"s5m", "proxy_1", "node.example-01", "a1b2c3d4"}
	for _, id := range valid {
		if !validDockerContainerID(id) {
			t.Errorf("valid container ID %q was rejected", id)
		}
	}
	invalid := []string{"", "-f", "--format", "proxy;id", "proxy id", "../container", "x/y", strings.Repeat("a", 129)}
	for _, id := range invalid {
		if validDockerContainerID(id) {
			t.Errorf("invalid container ID %q was accepted", id)
		}
	}
}

func TestCalculateMihomoSpeeds(t *testing.T) {
	mihomoSpeedMu.Lock()
	mihomoSpeedLastTime = time.Time{}
	mihomoSpeedLastUpload = 0
	mihomoSpeedLastDownload = 0
	mihomoSpeedMu.Unlock()

	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	up, down := calculateMihomoSpeeds(100, 200, start)
	if up != 0 || down != 0 {
		t.Fatalf("first sample should have zero speed, got up=%d down=%d", up, down)
	}
	up, down = calculateMihomoSpeeds(500, 800, start.Add(2*time.Second))
	if up != 200 || down != 300 {
		t.Fatalf("speed = up:%d down:%d, want up:200 down:300", up, down)
	}
	up, down = calculateMihomoSpeeds(10, 20, start.Add(4*time.Second))
	if up != 0 || down != 0 {
		t.Fatalf("counter reset should not report negative speed, got up=%d down=%d", up, down)
	}
}

func TestTrafficCounter(t *testing.T) {
	if got, ok := trafficCounter(float64(123)); !ok || got != 123 {
		t.Fatalf("trafficCounter(float64(123)) = %d, %v", got, ok)
	}
	if _, ok := trafficCounter("123"); ok {
		t.Fatal("trafficCounter should reject string counters")
	}
}
