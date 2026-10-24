package main

import (
	"strings"
	"testing"
)

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
