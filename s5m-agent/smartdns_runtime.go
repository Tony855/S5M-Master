package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const smartDNSConfigPath = "/data/smartdns.conf"

var smartDNSDirectiveAllowlist = map[string]bool{
	"bind": true, "bind-tcp": true,
	"server": true, "server-tcp": true, "server-tls": true,
	"server-https": true, "server-quic": true,
	"cache-size": true, "prefetch-domain": true, "serve-expired": true,
	"log-level": true, "log-console": true, "log-syslog": true,
	"dualstack-ip-selection": true, "rr-ttl": true, "rr-ttl-min": true,
	"rr-ttl-max": true, "force-AAAA-SOA": true, "force-qtype-SOA": true,
	"speed-check-mode": true, "response-mode": true,
}

var smartDNSControlChars = regexp.MustCompile("[\\x00-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f]")

// validateSmartDNSConfig accepts only resolver-related directives. It deliberately
// rejects include/plugin/exec-style directives so a remote config cannot load
// arbitrary files or start unrelated processes inside the Agent container.
func validateSmartDNSConfig(data []byte) error {
	if len(data) == 0 || len(data) > 8<<10 {
		return fmt.Errorf("SmartDNS 配置不能为空且不得超过 8 KiB")
	}
	if smartDNSControlChars.Match(data) {
		return fmt.Errorf("SmartDNS 配置包含非法控制字符")
	}
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	usable := 0
	bindUDP, bindTCP := false, false
	for lineNo, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return fmt.Errorf("第 %d 行配置格式无效", lineNo+1)
		}
		directive := fields[0]
		if !smartDNSDirectiveAllowlist[directive] {
			return fmt.Errorf("第 %d 行不允许配置指令 %q", lineNo+1, directive)
		}
		if strings.ContainsAny(line, "`$") || strings.Contains(line, "include") {
			return fmt.Errorf("第 %d 行包含不允许的特殊内容", lineNo+1)
		}
		if directive == "bind" || directive == "bind-tcp" {
			if len(fields) != 2 || fields[1] != "127.0.0.1:6053" {
				return fmt.Errorf("第 %d 行监听地址必须保持在容器回环地址 127.0.0.1:6053", lineNo+1)
			}
			if directive == "bind" {
				bindUDP = true
			} else {
				bindTCP = true
			}
		}
		if strings.HasPrefix(directive, "server") && len(fields) < 2 {
			return fmt.Errorf("第 %d 行上游 DNS 地址不能为空", lineNo+1)
		}
		usable++
	}
	if usable == 0 {
		return fmt.Errorf("SmartDNS 配置没有有效指令")
	}
	if !bindUDP || !bindTCP {
		return fmt.Errorf("必须同时配置 bind 127.0.0.1:6053 和 bind-tcp 127.0.0.1:6053")
	}
	return nil
}

func smartDNSBinaryAvailable() bool {
	info, err := os.Stat("/usr/sbin/smartdns")
	return err == nil && !info.IsDir()
}

func collectSmartDNSStatus(status map[string]any) {
	status["smartdns_available"] = smartDNSBinaryAvailable()
	status["smartdns_running"] = false
	status["smartdns_dns_healthy"] = false
	status["smartdns_version"] = ""
	status["smartdns_config_sha256"] = ""
	status["smartdns_last_error"] = ""
	if !smartDNSBinaryAvailable() {
		return
	}
	if data, err := os.ReadFile(smartDNSConfigPath); err == nil {
		sum := sha256.Sum256(bytes.TrimSpace(data))
		status["smartdns_config_sha256"] = hex.EncodeToString(sum[:])
	} else {
		status["smartdns_last_error"] = "读取 SmartDNS 配置失败"
	}
	if output, err := exec.Command("/usr/sbin/smartdns", "-v").CombinedOutput(); err == nil {
		version := strings.TrimSpace(string(output))
		if len(version) > 128 {
			version = version[:128]
		}
		status["smartdns_version"] = version
	}
	if err := exec.Command("pidof", "smartdns").Run(); err == nil {
		status["smartdns_running"] = true
	} else if status["smartdns_last_error"] == "" {
		status["smartdns_last_error"] = "SmartDNS 进程未运行"
	}
	if status["smartdns_running"] == true {
		if probeSmartDNSDNS() {
			status["smartdns_dns_healthy"] = true
		} else if status["smartdns_last_error"] == "" {
			status["smartdns_last_error"] = "SmartDNS DNS 查询探测失败"
		}
	}
}

func writeSmartDNSConfig(data []byte) (string, error) {
	if err := validateSmartDNSConfig(data); err != nil {
		return "", err
	}
	if !smartDNSBinaryAvailable() {
		return "", fmt.Errorf("当前 Agent 镜像未安装 SmartDNS")
	}
	if err := os.MkdirAll("/data", 0700); err != nil {
		return "", fmt.Errorf("创建 SmartDNS 数据目录失败")
	}

	// Validate the candidate with the actual SmartDNS parser on a temporary
	// loopback port before replacing the live configuration.
	candidateLines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	for i, line := range candidateLines {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) == 2 && (fields[0] == "bind" || fields[0] == "bind-tcp") {
			candidateLines[i] = fields[0] + " 127.0.0.1:16053"
		}
	}
	candidate := strings.Join(candidateLines, "\n")
	tmp, err := os.CreateTemp("/data", ".smartdns-check-*.conf")
	if err != nil {
		return "", fmt.Errorf("创建 SmartDNS 校验文件失败")
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return "", err
	}
	if _, err := tmp.WriteString(candidate); err != nil {
		_ = tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/sbin/smartdns", "-f", "-x", "-p", "-", "-c", tmpPath)
	output := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("SmartDNS 配置预检启动失败: %w", err)
	}
	go func() { output <- cmd.Wait() }()
	select {
	case err := <-output:
		if err != nil {
			return "", fmt.Errorf("SmartDNS 配置预检失败: %s", safeSmartDNSDiagnostic(err.Error()))
		}
		return "", fmt.Errorf("SmartDNS 配置预检进程意外退出")
	case <-time.After(350 * time.Millisecond):
		_ = cmd.Process.Kill()
		<-output
	case <-ctx.Done():
		_ = cmd.Process.Kill()
		<-output
		return "", fmt.Errorf("SmartDNS 配置预检超时")
	}

	livePath := smartDNSConfigPath
	backupPath := livePath + ".previous"
	oldData, oldErr := os.ReadFile(livePath)
	if oldErr == nil {
		if err := os.WriteFile(backupPath, oldData, 0600); err != nil {
			return "", fmt.Errorf("备份旧 SmartDNS 配置失败")
		}
	}
	liveTmp, err := os.CreateTemp(filepath.Dir(livePath), ".smartdns-live-*.conf")
	if err != nil {
		return "", err
	}
	liveTmpPath := liveTmp.Name()
	defer os.Remove(liveTmpPath)
	if err := liveTmp.Chmod(0600); err != nil {
		_ = liveTmp.Close()
		return "", err
	}
	if _, err := liveTmp.Write(data); err != nil {
		_ = liveTmp.Close()
		return "", err
	}
	if err := liveTmp.Sync(); err != nil {
		_ = liveTmp.Close()
		return "", err
	}
	if err := liveTmp.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(liveTmpPath, livePath); err != nil {
		return "", err
	}
	oldPID, _ := exec.Command("pidof", "smartdns").Output()
	oldPID = bytes.TrimSpace(oldPID)
	if err := exec.Command("s6-svc", "-r", "/run/service/smartdns").Run(); err != nil {
		if oldErr == nil {
			_ = os.WriteFile(livePath, oldData, 0600)
			_ = exec.Command("s6-svc", "-r", "/run/service/smartdns").Run()
		}
		return "", fmt.Errorf("重启 SmartDNS 失败，已尝试恢复旧配置")
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		newPID, pidErr := exec.Command("pidof", "smartdns").Output()
		if pidErr == nil && len(bytes.TrimSpace(newPID)) > 0 && !bytes.Equal(bytes.TrimSpace(newPID), oldPID) {
			sum := sha256.Sum256(bytes.TrimSpace(data))
			_ = os.Remove(backupPath)
			return hex.EncodeToString(sum[:]), nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	if oldErr == nil {
		_ = os.WriteFile(livePath, oldData, 0600)
		_ = exec.Command("s6-svc", "-r", "/run/service/smartdns").Run()
	}
	return "", fmt.Errorf("SmartDNS 重载后未恢复运行，已尝试回滚旧配置")
}

func safeSmartDNSDiagnostic(message string) string {
	message = strings.Join(strings.Fields(message), " ")
	if len(message) > 500 {
		message = message[:500] + "…"
	}
	return message
}

func probeSmartDNSDNS() bool {
	conn, err := net.DialTimeout("udp", "127.0.0.1:6053", 800*time.Millisecond)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(800 * time.Millisecond))
	query := make([]byte, 12)
	binary.BigEndian.PutUint16(query[0:2], 0x534d)
	binary.BigEndian.PutUint16(query[2:4], 0x0100)
	binary.BigEndian.PutUint16(query[4:6], 1)
	for _, label := range []string{"example", "com"} {
		query = append(query, byte(len(label)))
		query = append(query, label...)
	}
	query = append(query, 0, 0, 1, 0, 1) // QNAME terminator, A, IN
	if _, err := conn.Write(query); err != nil {
		return false
	}
	response := make([]byte, 1500)
	n, err := conn.Read(response)
	if err != nil || n < 12 {
		return false
	}
	if binary.BigEndian.Uint16(response[0:2]) != 0x534d {
		return false
	}
	flags := binary.BigEndian.Uint16(response[2:4])
	return flags&0x8000 != 0 && flags&0x000f != 2
}
