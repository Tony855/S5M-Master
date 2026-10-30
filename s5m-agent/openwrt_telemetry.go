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
	// UCI inspection is read-only and limited to the three requested network
	// domains. Potential credentials are redacted before leaving the device.
	uci := map[string]string{}
	for _, section := range []string{"network", "dhcp", "firewall"} {
		if value, ok := openWrtUCIShow(section); ok {
			uci[section] = value
		}
	}
	if len(uci) > 0 {
		result["uci_readonly"] = uci
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

func openWrtUCIShow(section string) (string, bool) {
	switch section {
	case "network", "dhcp", "firewall":
	default:
		return "", false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/sbin/uci", "-q", "show", section)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &bytes.Buffer{}
	if err := cmd.Run(); err != nil || stdout.Len() == 0 || stdout.Len() > 4<<10 {
		return "", false
	}
	lines := strings.Split(stdout.String(), "\n")
	redacted := make([]string, 0, len(lines))
	for _, line := range lines {
		if len(line) > 1024 {
			continue
		}
		left, _, hasValue := strings.Cut(line, "=")
		if !hasValue {
			continue
		}
		option := strings.ToLower(left[strings.LastIndex(left, ".")+1:])
		for _, sensitive := range []string{"password", "passwd", "secret", "token", "key", "psk", "private_key", "auth"} {
			if option == sensitive || strings.Contains(option, sensitive) {
				line = left + "='[REDACTED]'"
				break
			}
		}
		redacted = append(redacted, line)
	}
	value := strings.Join(redacted, "\n")
	if len(value) == 0 || len(value) > 4<<10 {
		return "", false
	}
	return value, true
}
