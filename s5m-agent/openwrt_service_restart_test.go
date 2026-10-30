package main

import (
	"reflect"
	"testing"
)

func TestMihomoRestartCommand(t *testing.T) {
	command, args := mihomoRestartCommand(true)
	if command != "/etc/init.d/s5m-mihomo" || !reflect.DeepEqual(args, []string{"restart"}) {
		t.Fatalf("unexpected OpenWrt restart command: %q %#v", command, args)
	}
	command, args = mihomoRestartCommand(false)
	if command != "s6-svc" || !reflect.DeepEqual(args, []string{"-r", "/run/service/mihomo"}) {
		t.Fatalf("unexpected s6 restart command: %q %#v", command, args)
	}
}

func TestValidateOpenWrtServiceActionAllowlist(t *testing.T) {
	tests := []struct {
		name    string
		service string
		action  string
		wantErr bool
	}{
		{name: "mihomo start", service: "mihomo", action: "start"},
		{name: "mihomo stop", service: "mihomo", action: "stop"},
		{name: "mihomo restart", service: "mihomo", action: "restart"},
		{name: "agent restart", service: "agent", action: "restart"},
		{name: "agent start is forbidden", service: "agent", action: "start", wantErr: true},
		{name: "agent stop is forbidden", service: "agent", action: "stop", wantErr: true},
		{name: "unknown service", service: "shell", action: "restart", wantErr: true},
		{name: "unknown action", service: "mihomo", action: "reload", wantErr: true},
		{name: "empty service", service: "", action: "restart", wantErr: true},
		{name: "empty action", service: "mihomo", action: "", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateOpenWrtServiceAction(tt.service, tt.action)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateOpenWrtServiceAction(%q, %q) error = %v, wantErr %v", tt.service, tt.action, err, tt.wantErr)
			}
		})
	}
}
