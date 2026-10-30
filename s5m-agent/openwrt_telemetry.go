package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"time"
)

const openWrtTelemetryMaxBytes = 8 << 10

// collectOpenWrtTelemetry is deliberately read-only. It invokes only fixed ubus
// methods (no shell, UCI writes, network changes, or caller-supplied arguments).
func collectOpenWrtTelemetry() map[string]any {
	if _, err := os.Stat("/etc/openwrt_release"); err != nil {
		return nil
	}
	board, boardOK := openWrtUbus("system", "board")
	system, systemOK := openWrtUbus("system", "info")
	network, networkOK := openWrtUbus("network.interface", "dump")
	if !boardOK && !systemOK && !networkOK {
		return map[string]any{"available": false, "error": "OpenWrt ubus telemetry unavailable"}
	}
	result := map[string]any{"available": true}
	if boardOK {
		result["board"] = pickOpenWrtFields(board, []string{"model", "board_name", "system", "hostname", "release"})
	}
	if systemOK {
		result["system"] = pickOpenWrtFields(system, []string{"uptime", "localtime", "memory"})
	}
	if networkOK {
		result["interfaces"] = compactOpenWrtInterfaces(network)
	}
	encoded, err := json.Marshal(result)
	if err != nil || len(encoded) > openWrtTelemetryMaxBytes {
		return map[string]any{"available": true, "truncated": true}
	}
	return result
}

func openWrtUbus(object, method string) (map[string]any, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/sbin/ubus", "call", object, method)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &bytes.Buffer{}
	if err := cmd.Run(); err != nil || stdout.Len() == 0 || stdout.Len() > 24<<10 {
		return nil, false
	}
	var value map[string]any
	if json.Unmarshal(stdout.Bytes(), &value) != nil {
		return nil, false
	}
	return value, true
}

func pickOpenWrtFields(source map[string]any, allowed []string) map[string]any {
	result := make(map[string]any)
	for _, key := range allowed {
		if value, ok := source[key]; ok {
			result[key] = value
		}
	}
	return result
}

func compactOpenWrtInterfaces(source map[string]any) []map[string]any {
	raw, ok := source["interface"].([]any)
	if !ok {
		return []map[string]any{}
	}
	result := make([]map[string]any, 0, len(raw))
	for _, entry := range raw {
		item, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		compact := pickOpenWrtFields(item, []string{"interface", "device", "l3_device", "up", "pending", "available", "autostart", "proto", "uptime", "ipv4-address", "ipv6-address"})
		if name, ok := compact["interface"].(string); !ok || strings.TrimSpace(name) == "" {
			continue
		}
		result = append(result, compact)
	}
	return result
}
