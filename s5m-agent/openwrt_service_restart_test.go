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
