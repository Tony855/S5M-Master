package app

import (
	"strings"
	"testing"
	"time"
)

func TestAgentStatusIsOnline(t *testing.T) {
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name string
		at string
		want bool
	}{
		{name: "fresh heartbeat", at: now.Add(-30 * time.Second).Format(time.RFC3339), want: true},
		{name: "heartbeat at threshold", at: now.Add(-90 * time.Second).Format(time.RFC3339), want: true},
		{name: "stale heartbeat", at: now.Add(-91 * time.Second).Format(time.RFC3339), want: false},
		{name: "future timestamp", at: now.Add(31 * time.Second).Format(time.RFC3339), want: false},
		{name: "invalid timestamp", at: "unknown", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := agentStatusIsOnline(tt.at, now); got != tt.want {
				t.Fatalf("agentStatusIsOnline(%q) = %v, want %v", tt.at, got, tt.want)
			}
		})
	}
}

func TestValidContainerID(t *testing.T) {
	valid := []string{"s5m", "proxy_1", "node.example-01", "a1b2c3d4"}
	for _, id := range valid {
		if !validContainerID(id) {
			t.Errorf("valid container ID %q was rejected", id)
		}
	}
	invalid := []string{"", "-f", "--format", "proxy;id", "proxy id", "../container", "x/y", strings.Repeat("a", 129)}
	for _, id := range invalid {
		if validContainerID(id) {
			t.Errorf("invalid container ID %q was accepted", id)
		}
	}
}
