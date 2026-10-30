package main

import "testing"

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
