package main

import (
	"os"\n\t"path/filepath"\n\t"strings"
	"testing"
)

func TestCompactOpenWrtInterfacesFiltersUnknownFields(t *testing.T) {
	input := map[string]any{"interface": []any{
		map[string]any{"interface": "wan", "device": "eth0", "up": true, "secret": "must-not-leak"},
		map[string]any{"device": "eth1", "secret": "ignored"},
	}}
	got := compactOpenWrtInterfaces(input)
	if len(got) != 1 {
		t.Fatalf("got %d interfaces, want 1", len(got))
	}
	if got[0]["interface"] != "wan" || got[0]["device"] != "eth0" {
		t.Fatalf("unexpected interface fields: %#v", got[0])
	}
	if _, exists := got[0]["secret"]; exists {
		t.Fatal("unexpected unapproved field leaked into telemetry")
	}
}

func TestPickOpenWrtFieldsAllowlist(t *testing.T) {
	got := pickOpenWrtFields(map[string]any{"model": "router", "password": "secret"}, []string{"model"})
	if got["model"] != "router" || len(got) != 1 {
		t.Fatalf("unexpected filtered fields: %#v", got)
	}
}

func TestOpenWrtUCIOptionRedaction(t *testing.T) {
	input := "network.wan.proto='dhcp'\n" +
		"network.wan.password='sensitive'\n" +
		"network.wan.private_key='private'\n" +
		"network.wan.username='operator'\n" +
		"firewall.@rule[0].name='allow-ssh'\n"
	got := redactOpenWrtUCIOutput(input)
	for _, secret := range []string{"sensitive", "private'", "operator'"} {
		if strings.Contains(got, secret) {
			t.Fatalf("sensitive UCI value %q was not redacted: %s", secret, got)
		}
	}
	if !strings.Contains(got, "proto='dhcp'") || !strings.Contains(got, "allow-ssh") {
		t.Fatalf("non-sensitive UCI values should remain visible: %s", got)
	}
}

func TestRedactOpenWrtLog(t *testing.T) {
	input := "daemon.info service: started\n" +
		"auth.notice login password=hunter2 token=abc123\n" +
		"api: Authorization: Bearer abc.def.ghi\n" +
		"vpn: password='quoted secret value' private_key=key-material\n" +
		"auth: passwd:colon-secret\n"
	got := redactOpenWrtLog(input)
	for _, secret := range []string{"hunter2", "abc123", "abc.def.ghi", "quoted secret value", "key-material", "colon-secret"} {
		if strings.Contains(got, secret) {
			t.Fatalf("log secret %q was not redacted: %s", secret, got)
		}
	}
	if !strings.Contains(got, "service: started") {
		t.Fatalf("ordinary log content should remain: %s", got)
	}
}

func TestOpenWrtProcessStatusFindsNamedProcesses(t *testing.T) {
	procRoot := t.TempDir()
	for pid, name := range map[string]string{"123": "mihomo", "456": "s5m-agent"} {
		dir := filepath.Join(procRoot, pid)
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "comm"), []byte(name+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	mihomo := openWrtProcessStatus(procRoot, "mihomo")
	if mihomo["running"] != true || mihomo["pid"] != 123 {
		t.Fatalf("unexpected Mihomo status: %#v", mihomo)
	}
	agent := openWrtProcessStatus(procRoot, "s5m-agent")
	if agent["running"] != true || agent["pid"] != 456 {
		t.Fatalf("unexpected Agent status: %#v", agent)
	}
	missing := openWrtProcessStatus(procRoot, "dnsmasq")
	if missing["running"] != false || missing["pid"] != 0 {
		t.Fatalf("missing process should be stopped: %#v", missing)
	}
}

func TestOpenWrtProcessStatusRejectsNonNumericProcEntries(t *testing.T) {
	procRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(procRoot, "self"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(procRoot, "self", "comm"), []byte("mihomo\n"), 0600); err != nil {
		t.Fatal(err)
	}
	got := openWrtProcessStatus(procRoot, "mihomo")
	if got["running"] != false {
		t.Fatalf("non-numeric proc entries must be ignored: %#v", got)
	}
}
