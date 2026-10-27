package app

import (
	"strings"
	"testing"
)

func TestValidateMihomoTemplate(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr bool
	}{
		{name: "valid mapping", yaml: "mixed-port: 7890\nmode: rule\n"},
		{name: "empty", yaml: "  \n", wantErr: true},
		{name: "invalid syntax", yaml: "mixed-port: [\n", wantErr: true},
		{name: "empty document", yaml: "{}\n", wantErr: true},
		{name: "invalid secret type", yaml: "secret: 123\n", wantErr: true},
		{name: "invalid tun type", yaml: "tun: true\n", wantErr: true},
		{name: "invalid dns type", yaml: "dns: true\n", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateMihomoTemplate(tt.yaml)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateMihomoTemplate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDefaultMihomoTemplateIsUsableStarter(t *testing.T) {
	if err := validateMihomoTemplate(defaultMihomoTemplate); err != nil {
		t.Fatalf("default Mihomo template should be valid YAML: %v", err)
	}
	for _, want := range []string{
		"mixed-port: 8080",
		"external-controller: 127.0.0.1:8088",
		"listen: 0.0.0.0:5353",
		"enable: false",
	} {
		if !strings.Contains(defaultMihomoTemplate, want) {
			t.Errorf("default template missing %q", want)
		}
	}
	if strings.Contains(defaultMihomoTemplate, "151.242.11.70") ||
		strings.Contains(defaultMihomoTemplate, "0103da505e81003e") {
		t.Fatal("starter template must not expose a user's proxy endpoint or API secret")
	}
	if strings.Contains(defaultMihomoTemplate, "proxies:") ||
		strings.Contains(defaultMihomoTemplate, "proxy-groups:") ||
		strings.Contains(defaultMihomoTemplate, "rules:") ||
		strings.Contains(defaultMihomoTemplate, "YOUR_PROXY_SERVER") ||
		strings.Contains(defaultMihomoTemplate, "221111cdn") {
		t.Fatal("default template must not duplicate proxy/rule sections managed by the controller")
	}
}

func TestHashConfigIsStable(t *testing.T) {
	yaml := "mixed-port: 7890\nmode: rule\n"
	if got, want := hashConfig(yaml), hashConfig(yaml); got != want {
		t.Fatalf("hashConfig is not stable: %q != %q", got, want)
	}
	if hashConfig(yaml) == hashConfig(yaml+"# changed\n") {
		t.Fatal("different YAML unexpectedly produced the same hash")
	}
}
