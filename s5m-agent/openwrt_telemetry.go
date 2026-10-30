package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const openWrtTelemetryMaxBytes = 8 << 10

var (
	openWrtLogSecretPattern = regexp.MustCompile("(?i)\\b(password|passwd|token|secret|private_key)\\s*[:=]\\s*(\"[^\"]*\"|'[^']*'|[^\\s,;]+)")
	openWrtLogBearerPattern = regexp.MustCompile("(?i)(authorization\\s*:\\s*bearer\\s+)[^\\s,;]+")
)

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
	if disk := collectOpenWrtDiskUsage(); len(disk) > 0 {
		result["disk"] = disk
	}
	if logs, ok := collectOpenWrtSystemLogs(); ok {
		result["logs_tail"] = logs
	}
	result["services"] = collectOpenWrtServiceStatus("/proc")
	// UCI inspection is read-only and limited to the three requested network
	// domains. Potential credentials are redacted before leaving the device.
	uci := map[string]string{}
	uciBytes := 0
	for _, section := range []string{"network", "dhcp", "firewall"} {
		if value, ok := openWrtUCIShow(section); ok && uciBytes+len(value) <= 3<<10 {
			uci[section] = value
			uciBytes += len(value)
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
	value := redactOpenWrtUCIOutput(stdout.String())
	if len(value) == 0 || len(value) > 4<<10 {
		return "", false
	}
	return value, true
}

func redactOpenWrtUCIOutput(raw string) string {
	lines := strings.Split(raw, "\n")
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
		for _, sensitive := range []string{"password", "passwd", "secret", "token", "key", "psk", "private_key", "auth", "username", "identity", "passphrase", "pin"} {
			if option == sensitive || strings.Contains(option, sensitive) {
				line = left + "='[REDACTED]'"
				break
			}
		}
		redacted = append(redacted, line)
	}
	return strings.Join(redacted, "\n")
}

func collectOpenWrtDiskUsage() []map[string]any {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "/bin/df", "-kP", "/overlay", "/").Output()
	if err != nil {
		return nil
	}
	lines := strings.Split(string(output), "\n")
	result := make([]map[string]any, 0, 2)
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		total, errTotal := strconv.ParseUint(fields[1], 10, 64)
		used, errUsed := strconv.ParseUint(fields[2], 10, 64)
		available, errAvailable := strconv.ParseUint(fields[3], 10, 64)
		if errTotal != nil || errUsed != nil || errAvailable != nil || total == 0 {
			continue
		}
		result = append(result, map[string]any{
			"mount": fields[5], "total_bytes": total * 1024,
			"used_bytes": used * 1024, "available_bytes": available * 1024,
			"used_percent": fields[4],
		})
	}
	return result
}

func collectOpenWrtSystemLogs() (string, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "/sbin/logread", "-l", "80").Output()
	if err != nil || len(output) == 0 {
		return "", false
	}
	value := redactOpenWrtLog(string(output))
	if len(value) > 2<<10 {
		value = value[len(value)-(2<<10):]
	}
	return strings.TrimSpace(value), value != ""
}

func redactOpenWrtLog(raw string) string {
	lines := strings.Split(raw, "\n")
	for i, line := range lines {
		line = openWrtLogSecretPattern.ReplaceAllString(line, "$1=[REDACTED]")
		line = openWrtLogBearerPattern.ReplaceAllString(line, "$1[REDACTED]")
		lines[i] = line
	}
	return strings.Join(lines, "\n")
}

func collectOpenWrtServiceStatus(procRoot string) map[string]any {
	return map[string]any{
		"agent":  openWrtProcessStatus(procRoot, "s5m-agent"),
		"mihomo": openWrtProcessStatus(procRoot, "mihomo"),
	}
}

func openWrtProcessStatus(procRoot, processName string) map[string]any {
	status := map[string]any{"running": false, "pid": 0}
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		status["error"] = "无法读取进程信息"
		return status
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		comm, err := os.ReadFile(filepath.Join(procRoot, entry.Name(), "comm"))
		if err != nil || strings.TrimSpace(string(comm)) != processName {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		status["running"] = true
		status["pid"] = pid
		return status
	}
	return status
}
