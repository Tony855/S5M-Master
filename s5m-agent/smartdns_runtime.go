package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
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
	oldData, hadOldConfig, backupErr := backupSmartDNSConfig(livePath, backupPath)
	if backupErr != nil {
		return "", fmt.Errorf("备份旧 SmartDNS 配置失败: %w", backupErr)
	}
	if err := writeSmartDNSFileAtomically(livePath, data, 0600); err != nil {
		return "", fmt.Errorf("原子替换 SmartDNS 配置失败: %w", err)
	}
	oldPID, _ := exec.Command("pidof", "smartdns").Output()
	oldPID = bytes.TrimSpace(oldPID)
	if err := exec.Command("s6-svc", "-r", "/run/service/smartdns").Run(); err != nil {
		restoreErr := restoreSmartDNSConfig(livePath, oldData, hadOldConfig)
		if restoreErr != nil {
			return "", fmt.Errorf("重启 SmartDNS 失败且恢复旧配置失败: %w", restoreErr)
		}
		if verifyErr := restartAndVerifySmartDNSRollback(livePath, oldData, hadOldConfig,
			func() error { return exec.Command("s6-svc", "-r", "/run/service/smartdns").Run() },
			probeSmartDNSDNS); verifyErr != nil {
			return "", fmt.Errorf("重启 SmartDNS 失败；旧配置回滚验证失败: %w", verifyErr)
		}
		return "", fmt.Errorf("重启 SmartDNS 失败，旧配置已恢复且 UDP/TCP DNS 验证通过")
	}
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		newPID, pidErr := exec.Command("pidof", "smartdns").Output()
		processRestarted := pidErr == nil && len(bytes.TrimSpace(newPID)) > 0 &&
			(len(oldPID) == 0 || !bytes.Equal(bytes.TrimSpace(newPID), oldPID))
		// A live PID is not proof that the new resolver config works. Require
		// successful UDP and TCP DNS answers before reporting the command as applied.
		if processRestarted && probeSmartDNSDNS() {
			sum := sha256.Sum256(bytes.TrimSpace(data))
			_ = os.Remove(backupPath)
			return hex.EncodeToString(sum[:]), nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	restoreErr := restoreSmartDNSConfig(livePath, oldData, hadOldConfig)
	if restoreErr != nil {
		return "", fmt.Errorf("SmartDNS 重载后未恢复运行，且回滚失败: %w", restoreErr)
	}
	if verifyErr := restartAndVerifySmartDNSRollback(livePath, oldData, hadOldConfig,
		func() error { return exec.Command("s6-svc", "-r", "/run/service/smartdns").Run() },
		probeSmartDNSDNS); verifyErr != nil {
		return "", fmt.Errorf("SmartDNS 重载后未恢复运行；旧配置回滚验证失败: %w", verifyErr)
	}
	return "", fmt.Errorf("SmartDNS 重载后未恢复运行，旧配置已恢复且 UDP/TCP DNS 验证通过")
}

// backupSmartDNSConfig reads the live configuration and creates a durable,
// private backup before any live-file replacement. A missing live file is a
// supported first-configuration state; other read or backup failures abort.
func backupSmartDNSConfig(livePath, backupPath string) ([]byte, bool, error) {
	oldData, err := os.ReadFile(livePath)
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if err := writeSmartDNSFileAtomically(backupPath, oldData, 0600); err != nil {
		return nil, false, err
	}
	return oldData, true, nil
}

// restartAndVerifySmartDNSRollback does not treat a successful service-manager
// command or a live PID as proof of recovery. It requires the restored bytes,
// a successful restart, and a working DNS answer on both UDP and TCP.
func restartAndVerifySmartDNSRollback(livePath string, oldData []byte, hadOld bool,
	restart func() error, probe func() bool) error {
	if err := restoreSmartDNSConfig(livePath, oldData, hadOld); err != nil {
		return fmt.Errorf("恢复旧配置文件失败: %w", err)
	}
	if err := restart(); err != nil {
		return fmt.Errorf("重新启动旧配置失败: %w", err)
	}
	if hadOld {
		got, err := os.ReadFile(livePath)
		if err != nil {
			return fmt.Errorf("读取回滚后的配置失败: %w", err)
		}
		if !bytes.Equal(got, oldData) {
			return fmt.Errorf("回滚后的配置内容与旧配置不一致")
		}
	}
	if !probe() {
		return fmt.Errorf("回滚后的 SmartDNS 未通过 UDP/TCP DNS 查询验证")
	}
	return nil
}

// restoreSmartDNSConfig restores the previous file atomically. If there was no
// previous config, it removes the newly installed file instead of leaving a
// configuration that the caller has already reported as failed.
func restoreSmartDNSConfig(livePath string, oldData []byte, hadOld bool) error {
	if !hadOld {
		if err := os.Remove(livePath); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	return writeSmartDNSFileAtomically(livePath, oldData, 0600)
}

func writeSmartDNSFileAtomically(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".smartdns-restore-*.conf")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

func safeSmartDNSDiagnostic(message string) string {
	message = strings.Join(strings.Fields(message), " ")
	if len(message) > 500 {
		message = message[:500] + "…"
	}
	return message
}

func probeSmartDNSDNS() bool {
	return probeSmartDNSDNSAt("127.0.0.1:6053") &&
		probeSmartDNSDNSNetworkAt("tcp", "127.0.0.1:6053")
}

func probeSmartDNSDNSAt(address string) bool {
	return probeSmartDNSDNSNetworkAt("udp", address)
}

func probeSmartDNSDNSNetworkAt(network, address string) bool {
	conn, err := net.DialTimeout(network, address, 800*time.Millisecond)
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
	if network == "tcp" {
		framed := make([]byte, 2, len(query)+2)
		binary.BigEndian.PutUint16(framed, uint16(len(query)))
		framed = append(framed, query...)
		query = framed
	}
	if _, err := conn.Write(query); err != nil {
		return false
	}
	response := make([]byte, 1502)
	n := 0
	if network == "tcp" {
		frameHeader := make([]byte, 2)
		if _, err := io.ReadFull(conn, frameHeader); err != nil {
			return false
		}
		responseLength := int(binary.BigEndian.Uint16(frameHeader))
		if responseLength < 12 || responseLength > 1500 {
			return false
		}
		n, err = io.ReadFull(conn, response[:responseLength])
		if err != nil {
			return false
		}
	} else {
		n, err = conn.Read(response)
		if err != nil {
			return false
		}
	}
	if n < 12 || binary.BigEndian.Uint16(response[0:2]) != 0x534d {
		return false
	}
	flags := binary.BigEndian.Uint16(response[2:4])
	// A healthy A lookup must be a DNS response with NOERROR and at least
	// one answer. NXDOMAIN, REFUSED, SERVFAIL, and empty NOERROR responses
	// must not be reported as a successful resolver probe.
	answerCount := binary.BigEndian.Uint16(response[6:8])
	return flags&0x8000 != 0 && flags&0x000f == 0 && answerCount > 0
}
