package app

import "testing"

func TestValidateMihomoTemplate(t *testing.T) {
	tests := []struct {
		name string
		yaml string
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

func TestHashConfigIsStable(t *testing.T) {
	yaml := "mixed-port: 7890\nmode: rule\n"
	if got, want := hashConfig(yaml), hashConfig(yaml); got != want {
		t.Fatalf("hashConfig is not stable: %q != %q", got, want)
	}
	if hashConfig(yaml) == hashConfig(yaml+"# changed\n") {
		t.Fatal("different YAML unexpectedly produced the same hash")
	}
}
