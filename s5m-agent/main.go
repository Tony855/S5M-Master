package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// 结构体定义
type Config struct {
	CentralURL string `json:"central_url"`
	Token      string `json:"token"`
}

// 解密函数 (与你原本的实现保持一致)
func decrypt(cryptoText string) (string, error) {
	key := []byte("0123456789abcdef0123456789abcdef") // 32 bytes
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	ciphertext, err := base64.StdEncoding.DecodeString(cryptoText)
	if err != nil {
		return "", err
	}
	if len(ciphertext) < aes.BlockSize {
		return "", fmt.Errorf("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)
	return string(ciphertext), nil
}

// Mihomo 配置目录统一由 MIHOMO_HOME 控制，默认使用持久化挂载目录 /data。
func mihomoHome() string {
	home := strings.TrimSpace(os.Getenv("MIHOMO_HOME"))
	if home == "" {
		return "/data"
	}
	return strings.TrimRight(home, "/")
}

// validateCentralURL rejects malformed URLs and URL userinfo/query/fragment fields.
func validateCentralURL(raw string) (string, error) {
	centralURL := strings.TrimRight(strings.TrimSpace(raw), "/")
	if !strings.HasPrefix(centralURL, "https://") && !strings.HasPrefix(centralURL, "http://") {
		return "", fmt.Errorf("主控地址必须使用 HTTP(S)")
	}
	parsedURL, err := url.Parse(centralURL)
	if err != nil || parsedURL.Host == "" || parsedURL.User != nil || parsedURL.RawQuery != "" || parsedURL.Fragment != "" ||
		strings.ContainsAny(centralURL, "\r\n") {
		return "", fmt.Errorf("主控地址格式无效")
	}
	return centralURL, nil
}

func mihomoConfigPath() string {
	return mihomoHome() + "/config.yaml"
}

// 独立的重载函数，防止变量冲突

// mergeConfig applies the complete controller-generated Mihomo YAML.
// The previous config is kept until Mihomo successfully reloads.
func validateMihomoConfigYAML(data []byte) (map[string]interface{}, error) {
	if len(data) == 0 || len(data) > 2*1024*1024 {
		return nil, fmt.Errorf("主控端配置为空或超过 2 MiB")
	}
	var cfg map[string]interface{}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("主控端 Mihomo YAML 无效: %w", err)
	}
	if len(cfg) == 0 {
		return nil, fmt.Errorf("主控端 Mihomo 配置为空")
	}
	secret, ok := cfg["secret"].(string)
	if !ok || strings.TrimSpace(secret) == "" {
		return nil, fmt.Errorf("主控端配置缺少有效的 Mihomo secret，拒绝覆盖本地配置")
	}
	if _, ok := cfg["tun"].(map[string]interface{}); !ok {
		return nil, fmt.Errorf("主控端配置缺少有效的 tun 配置块")
	}
	if _, ok := cfg["dns"].(map[string]interface{}); !ok {
		return nil, fmt.Errorf("主控端配置缺少有效的 dns 配置块")
	}
	return cfg, nil
}

// mergeConfig applies the complete controller-generated Mihomo YAML.
// The previous config is kept until Mihomo successfully reloads.
func mergeConfig(agentYml []byte) (bool, error) {
	mainPath := mihomoConfigPath()
	previousPath := mainPath + ".previous"
	nextCfg, err := validateMihomoConfigYAML(agentYml)
	if err != nil {
		return false, err
	}
	oldData, err := os.ReadFile(mainPath)
	if err != nil {
		return false, fmt.Errorf("读取本地 Mihomo 配置失败: %w", err)
	}
	var oldCfg map[string]interface{}
	if err := yaml.Unmarshal(oldData, &oldCfg); err != nil {
		return false, fmt.Errorf("本地 Mihomo YAML 无效: %w", err)
	}
	oldNorm, err := yaml.Marshal(oldCfg)
	if err != nil {
		return false, err
	}
	newNorm, err := yaml.Marshal(nextCfg)
	if err != nil {
		return false, err
	}
	if string(oldNorm) == string(newNorm) {
		return false, nil
	}
	if err := os.WriteFile(previousPath, oldData, 0600); err != nil {
		return false, fmt.Errorf("备份旧 Mihomo 配置失败: %w", err)
	}
	tmpPath := mainPath + ".tmp"
	if err := os.WriteFile(tmpPath, agentYml, 0600); err != nil {
		return false, err
	}
	if output, err := exec.Command("/usr/local/bin/mihomo", "-t", "-d", mihomoHome(), "-f", tmpPath).CombinedOutput(); err != nil {
		_ = os.Remove(tmpPath)
		return false, fmt.Errorf("新配置未通过 Mihomo 校验: %w: %s", err, strings.TrimSpace(string(output)))
	}
	if err := os.Rename(tmpPath, mainPath); err != nil {
		_ = os.Remove(tmpPath)
		return false, err
	}
	return true, nil
}

func rollbackConfigAfterReloadFailure() error {
	mainPath := mihomoConfigPath()
	oldData, err := os.ReadFile(mainPath + ".previous")
	if err != nil {
		return fmt.Errorf("读取旧配置备份失败: %w", err)
	}
	tmpPath := mainPath + ".restore"
	if err := os.WriteFile(tmpPath, oldData, 0600); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, mainPath); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return nil
}

// mihomoSecretCandidates returns unique secrets in previous-then-current order.
// During a config transition, the running core may still accept the old secret,
// or it may already have applied the new one despite a lost/ambiguous response.
func mihomoSecretCandidates(configPath string) ([]string, error) {
	seen := make(map[string]struct{}, 2)
	secrets := make([]string, 0, 2)
	for _, path := range []string{configPath + ".previous", configPath} {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var candidate map[string]interface{}
		if err := yaml.Unmarshal(data, &candidate); err != nil {
			continue
		}
		value, ok := candidate["secret"].(string)
		secret := strings.TrimSpace(value)
		if !ok || secret == "" {
			continue
		}
		if _, exists := seen[secret]; exists {
			continue
		}
		seen[secret] = struct{}{}
		secrets = append(secrets, secret)
	}
	if len(secrets) == 0 {
		return nil, fmt.Errorf("当前 Mihomo 配置和备份均没有有效 secret")
	}
	return secrets, nil
}

func reloadMihomo() error {
	configPath := mihomoConfigPath()
	secrets, err := mihomoSecretCandidates(configPath)
	if err != nil {
		return fmt.Errorf("无法确定 Mihomo API 鉴权密钥: %w", err)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	var lastUnauthorized string
	for _, secret := range secrets {
		reloadBody := strings.NewReader(
			fmt.Sprintf(`{"path": %q}`, configPath),
		)
		reloadReq, err := http.NewRequest(
			http.MethodPut,
			"http://127.0.0.1:8088/configs?force=true",
			reloadBody,
		)
		if err != nil {
			return fmt.Errorf("创建 Mihomo 重载请求失败: %w", err)
		}
		reloadReq.Header.Set("Content-Type", "application/json")
		reloadReq.Header.Set("Authorization", "Bearer "+secret)

		reloadResp, err := client.Do(reloadReq)
		if err != nil {
			return fmt.Errorf("请求 Mihomo 重载失败: %w", err)
		}
		responseBody, _ := io.ReadAll(io.LimitReader(reloadResp.Body, 4096))
		statusCode := reloadResp.StatusCode
		_ = reloadResp.Body.Close()

		if statusCode == http.StatusOK || statusCode == http.StatusNoContent {
			return nil
		}
		if statusCode == http.StatusUnauthorized {
			lastUnauthorized = strings.TrimSpace(string(responseBody))
			continue
		}
		return fmt.Errorf(
			"Mihomo 重载返回 HTTP %d: %s",
			statusCode,
			strings.TrimSpace(string(responseBody)),
		)
	}
	if lastUnauthorized == "" {
		lastUnauthorized = http.StatusText(http.StatusUnauthorized)
	}
	return fmt.Errorf("Mihomo 重载鉴权失败：已尝试旧配置和当前配置的有效密钥，最后返回 HTTP 401: %s", lastUnauthorized)
}

var mihomoSpeedMu sync.Mutex
var mihomoSpeedLastTime time.Time
var mihomoSpeedLastUpload uint64
var mihomoSpeedLastDownload uint64

func trafficCounter(value any) (uint64, bool) {
	n, ok := value.(float64)
	if !ok || n < 0 || n > 1.8e19 {
		return 0, false
	}
	return uint64(n), true
}

func calculateMihomoSpeeds(upload, download uint64, now time.Time) (uint64, uint64) {
	mihomoSpeedMu.Lock()
	defer mihomoSpeedMu.Unlock()
	var upSpeed, downSpeed uint64
	if !mihomoSpeedLastTime.IsZero() {
		seconds := now.Sub(mihomoSpeedLastTime).Seconds()
		if seconds > 0 {
			if upload >= mihomoSpeedLastUpload {
				upSpeed = uint64(float64(upload-mihomoSpeedLastUpload) / seconds)
			}
			if download >= mihomoSpeedLastDownload {
				downSpeed = uint64(float64(download-mihomoSpeedLastDownload) / seconds)
			}
		}
	}
	mihomoSpeedLastTime = now
	mihomoSpeedLastUpload = upload
	mihomoSpeedLastDownload = download
	return upSpeed, downSpeed
}

func collectMihomoStatus() map[string]any {
	status := map[string]any{
		"mihomo_version": "", "mihomo_healthy": false,
		"upload_total": int64(0), "download_total": int64(0),
		"upload_speed": float64(0), "download_speed": float64(0),
		"connections": 0, "config_sha256": "", "last_error": "",
	}
	configPath := mihomoConfigPath()
	data, err := os.ReadFile(configPath)
	if err != nil {
		status["last_error"] = "读取配置失败: " + err.Error()
		return status
	}
	sum := sha256.Sum256(data)
	status["config_sha256"] = fmt.Sprintf("%x", sum[:])
	var cfg map[string]interface{}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		status["last_error"] = "解析配置失败: " + err.Error()
		return status
	}
	secret, _ := cfg["secret"].(string)
	client := &http.Client{Timeout: 3 * time.Second}
	get := func(path string) (map[string]any, error) {
		req, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:8088"+path, nil)
		if err != nil {
			return nil, err
		}
		if secret != "" {
			req.Header.Set("Authorization", "Bearer "+secret)
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		var result map[string]any
		if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&result); err != nil {
			return nil, err
		}
		return result, nil
	}
	version, err := get("/version")
	if err != nil {
		status["last_error"] = "读取 Mihomo 版本失败: " + err.Error()
		return status
	}
	versionText, ok := version["version"].(string)
	if !ok || strings.TrimSpace(versionText) == "" {
		status["last_error"] = "读取 Mihomo 版本失败: /version 响应缺少有效 version 字段"
		return status
	}
	status["mihomo_version"] = versionText
	status["mihomo_healthy"] = true
	connections, err := get("/connections")
	if err == nil {
		items, _ := connections["connections"].([]any)
		status["connections"] = len(items)
		status["upload_total"] = connections["uploadTotal"]
		status["download_total"] = connections["downloadTotal"]
		uploadTotal, uploadOK := trafficCounter(connections["uploadTotal"])
		downloadTotal, downloadOK := trafficCounter(connections["downloadTotal"])
		if uploadOK && downloadOK {
			upSpeed, downSpeed := calculateMihomoSpeeds(uploadTotal, downloadTotal, time.Now())
			status["upload_speed"] = upSpeed
			status["download_speed"] = downSpeed
		}
	} else if status["last_error"] == "" {
		status["last_error"] = "读取连接数失败: " + err.Error()
	}
	return status
}

func reportHeartbeat(cfg Config, status map[string]any) error {
	body, err := json.Marshal(status)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(cfg.CentralURL, "/")+"/api/v1/agent/heartbeat", strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("主控端心跳返回 HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	return nil
}

type agentCommand struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}

func processAgentCommand(cfg Config) error {
	request, err := http.NewRequest(http.MethodGet, strings.TrimRight(cfg.CentralURL, "/")+"/api/v1/agent/command", nil)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+cfg.Token)
	client := &http.Client{Timeout: 10 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 2048))
		return fmt.Errorf("读取主控命令返回 HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(body)))
	}
	var envelope struct {
		Command *agentCommand `json:"command"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 16<<10)).Decode(&envelope); err != nil {
		return err
	}
	if envelope.Command == nil {
		return nil
	}
	cmd := envelope.Command
	var runErr error
	message := ""
	switch cmd.Type {
	case "update_mihomo":
		message, runErr = updateMihomoKernel(*cmd)
	default:
		runErr = fmt.Errorf("不支持的 Agent 命令类型: %s", cmd.Type)
	}
	status := "success"
	if runErr != nil {
		status = "failed"
		message = runErr.Error()
	}
	ackBody, _ := json.Marshal(map[string]string{"id": cmd.ID, "status": status, "message": message})
	ackReq, err := http.NewRequest(http.MethodPost, strings.TrimRight(cfg.CentralURL, "/")+"/api/v1/agent/command/ack", bytes.NewReader(ackBody))
	if err != nil {
		return err
	}
	ackReq.Header.Set("Authorization", "Bearer "+cfg.Token)
	ackReq.Header.Set("Content-Type", "application/json")
	ackResp, err := (&http.Client{Timeout: 10 * time.Second}).Do(ackReq)
	if err != nil {
		return fmt.Errorf("执行命令后上报结果失败: %w", err)
	}
	defer ackResp.Body.Close()
	if ackResp.StatusCode < 200 || ackResp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(ackResp.Body, 2048))
		return fmt.Errorf("上报命令结果返回 HTTP %d: %s", ackResp.StatusCode, strings.TrimSpace(string(body)))
	}
	if runErr != nil {
		return runErr
	}
	fmt.Printf("Agent 命令 %s 执行成功: %s\n", cmd.ID, message)
	return nil
}

var mihomoVersionPattern = regexp.MustCompile("^v[0-9]+\\.[0-9]+\\.[0-9]+$")
var sha256Pattern = regexp.MustCompile("^[a-fA-F0-9]{64}$")

func validateKernelUpdateCommand(cmd agentCommand) error {
	if !mihomoVersionPattern.MatchString(strings.TrimSpace(cmd.Version)) {
		return fmt.Errorf("更新命令版本号无效")
	}
	if !sha256Pattern.MatchString(strings.TrimSpace(cmd.SHA256)) {
		return fmt.Errorf("更新命令 SHA-256 必须为 64 位十六进制")
	}
	return nil
}

func updateMihomoKernel(cmd agentCommand) (string, error) {
	if err := validateKernelUpdateCommand(cmd); err != nil {
		return "", err
	}
	cmd.Version = strings.TrimSpace(cmd.Version)
	cmd.SHA256 = strings.TrimSpace(cmd.SHA256)

	// ACK delivery can fail after a successful update. If the same command is
	// delivered again, recognize the already-installed target version and avoid
	// downloading/replacing/restarting the kernel a second time.
	if output, err := exec.Command("/usr/local/bin/mihomo", "-v").CombinedOutput(); err == nil {
		versionPattern := regexp.MustCompile(`\bv` + regexp.QuoteMeta(strings.TrimPrefix(cmd.Version, "v")) + `\b`)
		if versionPattern.Match(output) {
			return "Mihomo 已是目标版本 " + cmd.Version + "，按幂等重试跳过重复安装", nil
		}
	}
	asset := ""
	switch runtime.GOARCH {
	case "amd64":
		asset = "mihomo-linux-amd64-compatible-" + cmd.Version + ".gz"
	case "arm64":
		asset = "mihomo-linux-arm64-" + cmd.Version + ".gz"
	default:
		return "", fmt.Errorf("当前架构 %s 暂不支持自动更新", runtime.GOARCH)
	}
	url := "https://github.com/MetaCubeX/mihomo/releases/download/" + cmd.Version + "/" + asset
	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	client := &http.Client{Timeout: 3 * time.Minute}
	response, err := client.Do(request)
	if err != nil {
		return "", fmt.Errorf("下载官方 Mihomo 内核失败: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("官方 Mihomo 下载返回 HTTP %d", response.StatusCode)
	}
	compressed, err := io.ReadAll(io.LimitReader(response.Body, 200<<20))
	if err != nil {
		return "", err
	}
	if len(compressed) == 0 || len(compressed) >= 200<<20 {
		return "", fmt.Errorf("下载文件为空或超过 200 MiB 限制")
	}
	sum := sha256.Sum256(compressed)
	if !strings.EqualFold(hex.EncodeToString(sum[:]), cmd.SHA256) {
		return "", fmt.Errorf("Mihomo 下载文件 SHA-256 不匹配，已拒绝安装")
	}
	gz, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return "", fmt.Errorf("Mihomo 压缩包损坏: %w", err)
	}
	defer gz.Close()
	newBinary, err := os.CreateTemp("/usr/local/bin", ".mihomo-update-*")
	if err != nil {
		return "", fmt.Errorf("创建内核临时文件失败: %w", err)
	}
	newPath := newBinary.Name()
	defer os.Remove(newPath)
	written, copyErr := io.Copy(newBinary, io.LimitReader(gz, 256<<20))
	closeErr := newBinary.Close()
	if copyErr != nil {
		return "", copyErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	if written == 0 || written >= 256<<20 {
		return "", fmt.Errorf("解压后的内核为空或超过 256 MiB 限制")
	}
	if err := os.Chmod(newPath, 0755); err != nil {
		return "", err
	}
	if output, err := exec.Command(newPath, "-v").CombinedOutput(); err != nil {
		return "", fmt.Errorf("新内核自检失败: %v: %s", err, strings.TrimSpace(string(output)))
	}
	configPath := mihomoConfigPath()
	if output, err := exec.Command(newPath, "-t", "-d", mihomoHome(), "-f", configPath).CombinedOutput(); err != nil {
		return "", fmt.Errorf("新内核未通过当前配置校验: %v: %s", err, strings.TrimSpace(string(output)))
	}
	configData, err := os.ReadFile(configPath)
	if err != nil {
		return "", err
	}
	var config map[string]any
	if err := yaml.Unmarshal(configData, &config); err != nil {
		return "", err
	}
	secret, _ := config["secret"].(string)
	if strings.TrimSpace(secret) == "" {
		return "", fmt.Errorf("当前配置没有 Mihomo API secret")
	}
	const binaryPath = "/usr/local/bin/mihomo"
	backupPath := binaryPath + ".previous"
	_ = os.Remove(backupPath)
	if err := os.Rename(binaryPath, backupPath); err != nil {
		return "", fmt.Errorf("备份现有 Mihomo 内核失败: %w", err)
	}
	if err := os.Rename(newPath, binaryPath); err != nil {
		_ = os.Rename(backupPath, binaryPath)
		return "", fmt.Errorf("安装新 Mihomo 内核失败: %w", err)
	}
	expectedVersion := strings.TrimPrefix(cmd.Version, "v")
	upgradeErr := verifyKernelUpgrade(
		func() error { return restartMihomo(secret) },
		func() error { return waitForMihomoVersion(secret, expectedVersion, 30*time.Second) },
		func() error { return restoreMihomoKernel(binaryPath, backupPath, secret) },
	)
	if upgradeErr != nil {
		return "", upgradeErr
	}
	if err := os.Remove(backupPath); err != nil && !os.IsNotExist(err) {
		return "", fmt.Errorf("新内核已通过健康检查，但删除旧内核备份失败: %w", err)
	}
	return "Mihomo 内核已更新到 " + cmd.Version, nil
}

// verifyKernelUpgrade treats the running version as authoritative when a
// restart request fails because the controller connection may close on exec.
func verifyKernelUpgrade(restart, healthCheck, rollback func() error) error {
	restartErr := restart()
	if healthErr := healthCheck(); healthErr != nil {
		rollbackErr := rollback()
		if rollbackErr != nil {
			if restartErr != nil {
				return fmt.Errorf("重启请求返回错误: %v；新内核健康检查失败: %v；恢复旧内核失败: %w", restartErr, healthErr, rollbackErr)
			}
			return fmt.Errorf("新内核健康检查失败: %v；恢复旧内核失败: %w", healthErr, rollbackErr)
		}
		if restartErr != nil {
			return fmt.Errorf("重启请求返回错误且新内核未通过健康检查，已恢复旧内核: %v（健康检查：%v）", restartErr, healthErr)
		}
		return fmt.Errorf("新内核健康检查失败，已恢复旧内核: %w", healthErr)
	}
	return nil
}

// newMihomoRestartRequest builds the documented Mihomo restart request.
func newMihomoRestartRequest(secret string) (*http.Request, error) {
	req, err := http.NewRequest(http.MethodPost, "http://127.0.0.1:8088/restart", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	return req, nil
}

// restartMihomo asks the local external controller to restart Mihomo.
func restartMihomo(secret string) error {
	restartReq, err := newMihomoRestartRequest(secret)
	if err != nil {
		return err
	}
	restartResp, err := (&http.Client{Timeout: 20 * time.Second}).Do(restartReq)
	if err != nil {
		return fmt.Errorf("请求 Mihomo 重启失败: %w", err)
	}
	defer restartResp.Body.Close()
	if restartResp.StatusCode < 200 || restartResp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(restartResp.Body, 2048))
		return fmt.Errorf("Mihomo 重启返回 HTTP %d: %s", restartResp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

func mihomoVersionMatches(actual, expected string) bool {
	actual = strings.TrimPrefix(strings.TrimSpace(actual), "v")
	expected = strings.TrimPrefix(strings.TrimSpace(expected), "v")
	return actual != "" && expected != "" && actual == expected
}

// waitForMihomoVersion waits until the API responds with the expected running version.
func waitForMihomoVersion(secret, expected string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: 3 * time.Second}
	var lastErr error
	for {
		req, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:8088/version", nil)
		if err == nil {
			req.Header.Set("Authorization", "Bearer "+secret)
			resp, requestErr := client.Do(req)
			if requestErr != nil {
				lastErr = requestErr
			} else {
				var payload map[string]any
				decodeErr := json.NewDecoder(io.LimitReader(resp.Body, 16<<10)).Decode(&payload)
				resp.Body.Close()
				version, _ := payload["version"].(string)
				if resp.StatusCode >= 200 && resp.StatusCode < 300 && decodeErr == nil && mihomoVersionMatches(version, expected) {
					return nil
				}
				if decodeErr != nil {
					lastErr = decodeErr
				} else {
					lastErr = fmt.Errorf("Mihomo API 返回 HTTP %d，版本为 %q，期望 %q", resp.StatusCode, version, expected)
				}
			}
		} else {
			lastErr = err
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(time.Second)
	}
	if lastErr == nil {
		return fmt.Errorf("Mihomo 在 %s 内未通过版本健康检查", timeout)
	}
	return fmt.Errorf("Mihomo 在 %s 内未通过版本健康检查: %w", timeout, lastErr)
}

// restoreMihomoKernel reinstalls the backup and requests a restart.
func restoreMihomoKernel(binaryPath, backupPath, secret string) error {
	if err := os.Remove(binaryPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("删除异常内核失败: %w", err)
	}
	if err := os.Rename(backupPath, binaryPath); err != nil {
		return fmt.Errorf("恢复旧内核文件失败: %w", err)
	}
	if err := restartMihomo(secret); err != nil {
		return fmt.Errorf("旧内核文件已恢复，但请求重启失败: %w", err)
	}
	return nil
}

// containerRequest performs a bounded request to the controller using the registered Agent token.
func containerRequest(cfg Config, method, path string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(method, strings.TrimRight(cfg.CentralURL, "/")+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return (&http.Client{Timeout: 15 * time.Second}).Do(req)
}

func dockerAvailable() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "docker", "version", "--format", "{{json .Server.Version}}").Run() == nil
}

func reportContainerStatus(cfg Config) error {
	hostname, _ := os.Hostname()
	mihomo := collectMihomoStatus()
	version, _ := mihomo["mihomo_version"].(string)
	running, _ := mihomo["mihomo_healthy"].(bool)
	payload, err := json.Marshal(map[string]any{
		"hostname": hostname, "os": runtime.GOOS, "arch": runtime.GOARCH,
		"docker_available": dockerAvailable(), "mihomo_running": running,
		"mihomo_version": version, "status_json": mihomo,
	})
	if err != nil {
		return err
	}
	resp, err := containerRequest(cfg, http.MethodPost, "/api/v1/agent/container/status", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("上报节点状态返回 HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

type containerTask struct {
	ID     int64           `json:"id"`
	Action string          `json:"action"`
	Params json.RawMessage `json:"params"`
}

func processContainerTask(cfg Config) error {
	resp, err := containerRequest(cfg, http.MethodGet, "/api/v1/agent/container/tasks/next", nil)
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusNoContent {
		resp.Body.Close()
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		resp.Body.Close()
		return fmt.Errorf("领取容器任务返回 HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var task containerTask
	err = json.NewDecoder(io.LimitReader(resp.Body, 32<<10)).Decode(&task)
	resp.Body.Close()
	if err != nil {
		return fmt.Errorf("解析容器任务失败: %w", err)
	}
	if task.ID <= 0 {
		return fmt.Errorf("主控返回无效容器任务 ID")
	}
	// Keep the controller-side lease alive while a potentially long operation runs.
	// Stop and join the heartbeat goroutine before reporting the final task result.
	leaseCtx, cancelLease := context.WithCancel(context.Background())
	leaseDone := make(chan struct{})
	go func() {
		defer close(leaseDone)
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-leaseCtx.Done():
				return
			case <-ticker.C:
				leaseResp, leaseErr := containerRequest(cfg, http.MethodPost,
					fmt.Sprintf("/api/v1/agent/container/tasks/%d/heartbeat", task.ID), nil)
				if leaseErr != nil {
					fmt.Printf("容器任务 %d 续租失败: %v\n", task.ID, leaseErr)
					continue
				}
				if leaseResp.StatusCode < 200 || leaseResp.StatusCode >= 300 {
					body, _ := io.ReadAll(io.LimitReader(leaseResp.Body, 2048))
					fmt.Printf("容器任务 %d 续租返回 HTTP %d: %s\n", task.ID, leaseResp.StatusCode, strings.TrimSpace(string(body)))
				}
				leaseResp.Body.Close()
			}
		}
	}()
	result, runErr := executeContainerTask(task)
	cancelLease()
	<-leaseDone
	status, errText := "succeeded", ""
	if runErr != nil {
		status, errText = "failed", runErr.Error()
	}
	resultJSON, _ := json.Marshal(result)
	payload, err := json.Marshal(map[string]any{
		"status": status, "result": json.RawMessage(resultJSON), "error": errText,
	})
	if err != nil {
		return err
	}
	resultResp, err := containerRequest(cfg, http.MethodPost,
		fmt.Sprintf("/api/v1/agent/container/tasks/%d/result", task.ID), bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("上报容器任务结果失败: %w", err)
	}
	defer resultResp.Body.Close()
	if resultResp.StatusCode < 200 || resultResp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resultResp.Body, 2048))
		return fmt.Errorf("上报容器任务结果返回 HTTP %d: %s", resultResp.StatusCode, strings.TrimSpace(string(body)))
	}
	if runErr != nil {
		return runErr
	}
	fmt.Printf("容器任务 %d (%s) 执行成功\n", task.ID, task.Action)
	return nil
}

func validDockerContainerID(s string) bool {
	if s == "" || len(s) > 128 || strings.HasPrefix(s, "-") {
		return false
	}
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return true
}
func executeContainerTask(task containerTask) (map[string]any, error) {
	params := map[string]json.RawMessage{}
	if len(task.Params) > 0 {
		if err := json.Unmarshal(task.Params, &params); err != nil {
			return nil, fmt.Errorf("任务参数格式无效")
		}
	}
	containerID := ""
	if raw, ok := params["container_id"]; ok {
		if err := json.Unmarshal(raw, &containerID); err != nil {
			return nil, fmt.Errorf("container_id 必须是字符串")
		}
		containerID = strings.TrimSpace(containerID)
		if !validDockerContainerID(containerID) {
			return nil, fmt.Errorf("container_id 格式无效")
		}
	}
	tail := 100
	if raw, ok := params["tail"]; ok {
		if err := json.Unmarshal(raw, &tail); err != nil || tail < 1 || tail > 500 {
			return nil, fmt.Errorf("tail 必须是 1 到 500 之间的整数")
		}
	}
	if strings.HasPrefix(task.Action, "docker.") && task.Action != "docker.list" && containerID == "" {
		return nil, fmt.Errorf("该 Docker 操作必须指定 container_id")
	}
	var args []string
	switch task.Action {
	case "docker.list":
		args = []string{"ps", "-a", "--no-trunc", "--format", "{{json .}}"}
	case "docker.inspect":
		args = []string{"inspect", containerID}
	case "docker.logs":
		args = []string{"logs", "--tail", strconv.Itoa(tail), containerID}
	case "docker.start":
		args = []string{"start", containerID}
	case "docker.stop":
		args = []string{"stop", "--time", "10", containerID}
	case "docker.restart":
		args = []string{"restart", "--time", "10", containerID}
	case "mihomo.status":
		return collectMihomoStatus(), nil
	case "mihomo.restart":
		data, err := os.ReadFile(mihomoConfigPath())
		if err != nil {
			return nil, fmt.Errorf("读取 Mihomo 配置失败: %w", err)
		}
		var cfg map[string]any
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return nil, fmt.Errorf("解析 Mihomo 配置失败: %w", err)
		}
		secret, _ := cfg["secret"].(string)
		if strings.TrimSpace(secret) == "" {
			return nil, fmt.Errorf("Mihomo 配置缺少 API secret")
		}
		if err := restartMihomo(secret); err != nil {
			return nil, err
		}
		return map[string]any{"message": "已请求 Mihomo 重启"}, nil
	default:
		return nil, fmt.Errorf("不支持的容器任务动作: %s", task.Action)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", args...)
	output, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return nil, fmt.Errorf("Docker 操作超时（15 秒）")
	}
	text := strings.TrimSpace(string(output))
	if len(text) > 128*1024 {
		text = text[:128*1024]
	}
	if err != nil {
		return map[string]any{"output": text}, fmt.Errorf("Docker 操作失败: %w: %s", err, text)
	}
	return map[string]any{"output": text}, nil
}
func getMachineID() string {
	data, err := os.ReadFile("/etc/machine-id")
	if err != nil {
		return ""
	}

	id := strings.ToLower(strings.TrimSpace(string(data)))
	if len(id) < 11 {
		return ""
	}

	return id[:11]
}

func main() {
	// 启动 81 端口提供 Web 注册界面
	go func() {
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			http.ServeFile(w, r, "/app/index.html")
		})

		// ====== 提供前端页面的 API ======
		http.HandleFunc("/api/machine-id", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"machine_id":"` + getMachineID() + `"}`))
		})

		http.HandleFunc("/api/config", func(w http.ResponseWriter, r *http.Request) {
			data, _ := os.ReadFile(mihomoHome() + "/agent.json")
			var cfg Config
			_ = json.Unmarshal(data, &cfg)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"has_token":   cfg.Token != "",
				"central_url": cfg.CentralURL,
				// This is local binding state, not a live reachability probe.
				"connected": cfg.Token != "",
			})
		})

		http.HandleFunc("/api/bind", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				w.Header().Set("Allow", http.MethodPost)
				http.Error(w, "仅允许 POST", http.StatusMethodNotAllowed)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
			var in struct {
				CentralURL string `json:"central_url"`
				Secret     string `json:"secret"`
			}
			if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
				http.Error(w, "参数错误", http.StatusBadRequest)
				return
			}
			centralURL, urlErr := validateCentralURL(in.CentralURL)
			if urlErr != nil || strings.TrimSpace(in.Secret) == "" {
				http.Error(w, "主控地址或授权密钥无效；地址必须是完整的 HTTP(S) URL，不能包含凭据、查询参数或片段", http.StatusBadRequest)
				return
			}
			machineID := getMachineID()
			if machineID == "" {
				http.Error(w, "无法读取有效机器码", http.StatusInternalServerError)
				return
			}
			requestData, err := json.Marshal(map[string]string{"machine_code": machineID, "secret": in.Secret})
			if err != nil {
				http.Error(w, "生成注册请求失败", http.StatusInternalServerError)
				return
			}
			registerReq, err := http.NewRequest(http.MethodPost, centralURL+"/api/v1/agent/register", bytes.NewReader(requestData))
			if err != nil {
				http.Error(w, "主控地址无效", http.StatusBadRequest)
				return
			}
			registerReq.Header.Set("Content-Type", "application/json")
			resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(registerReq)
			if err != nil {
				http.Error(w, "连接主控端失败，请检查地址和网络", http.StatusBadGateway)
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
				http.Error(w, "主控端拒绝注册，请检查授权密钥", http.StatusUnauthorized)
				return
			}
			var result struct {
				Token string `json:"token"`
			}
			if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<10)).Decode(&result); err != nil || strings.TrimSpace(result.Token) == "" {
				http.Error(w, "主控端返回的注册凭证无效", http.StatusBadGateway)
				return
			}
			if err := os.MkdirAll(mihomoHome(), 0700); err != nil {
				http.Error(w, "创建 Agent 数据目录失败", http.StatusInternalServerError)
				return
			}
			b, err := json.Marshal(Config{CentralURL: centralURL, Token: result.Token})
			if err != nil {
				http.Error(w, "序列化绑定配置失败", http.StatusInternalServerError)
				return
			}
			configPath := mihomoHome() + "/agent.json"
			tmpPath := configPath + ".tmp"
			if err := os.WriteFile(tmpPath, b, 0600); err != nil {
				http.Error(w, "写入绑定配置失败", http.StatusInternalServerError)
				return
			}
			if err := os.Rename(tmpPath, configPath); err != nil {
				_ = os.Remove(tmpPath)
				http.Error(w, "保存绑定配置失败", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"message": "绑定成功"})
		})
		fmt.Println("Agent Web 服务已启动: :81")
		if err := http.ListenAndServe(":81", nil); err != nil {
			fmt.Println("Agent Web 服务启动失败:", err)
		}
	}()

	// 确保 data 目录存在
	os.MkdirAll(mihomoHome(), 0700)

	// 主循环：每 30 秒心跳并检查配置
	for {
		time.Sleep(30 * time.Second)
		data, _ := os.ReadFile(mihomoHome() + "/agent.json")
		if len(data) == 0 {
			continue
		}
		var cfg Config
		json.Unmarshal(data, &cfg)
		if cfg.Token == "" {
			continue
		}

		if err := processContainerTask(cfg); err != nil {
			fmt.Printf("容器任务处理失败: %v\n", err)
		}
		if err := reportContainerStatus(cfg); err != nil {
			fmt.Printf("容器节点状态上报失败: %v\n", err)
		}

		if err := processAgentCommand(cfg); err != nil {
			fmt.Printf("Agent 命令处理失败: %v\n", err)
		}

		fmt.Println("👉 正在向主控台发送心跳...")
		req, err := http.NewRequest(
			http.MethodGet,
			strings.TrimRight(cfg.CentralURL, "/")+"/api/v1/agent/config",
			nil,
		)
		if err != nil {
			fmt.Printf("Agent 配置请求创建失败: %v\n", err)
			continue
		}
		req.Header.Set("Authorization", "Bearer "+cfg.Token)
		if localData, readErr := os.ReadFile(mihomoConfigPath()); readErr == nil && len(localData) > 0 {
			localSum := sha256.Sum256(localData)
			req.Header.Set("If-None-Match", fmt.Sprintf("\"%x\"", localSum[:]))
		}
		client := &http.Client{Timeout: 15 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			fmt.Printf("❌ Agent 心跳请求失败: %v\n", err)
			continue
		}

		if resp.StatusCode == http.StatusNotModified {
			resp.Body.Close()
			if err := reportHeartbeat(cfg, collectMihomoStatus()); err != nil {
				fmt.Printf("Agent 状态上报失败: %v\n", err)
			}
			fmt.Println("主控端配置哈希未变化，跳过下载与重载")
			continue
		}
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			fmt.Printf("❌ Agent 心跳异常: HTTP %d，主控端响应: %s\n", resp.StatusCode, strings.TrimSpace(string(body)))
			continue
		}

		newYml, readErr := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
		resp.Body.Close()
		if readErr != nil {
			fmt.Printf("读取主控台配置失败: %v\n", readErr)
			continue
		}
		if err := reportHeartbeat(cfg, collectMihomoStatus()); err != nil {
			fmt.Printf("Agent 状态上报失败: %v\n", err)
		}
		if len(strings.TrimSpace(string(newYml))) == 0 {
			fmt.Println("主控台返回空配置，本次跳过")
			continue
		}

		// 完整替换本地配置，TUN、DNS、端口和规则均由主控端统一管理
		changed, err := mergeConfig(newYml)
		if err != nil {
			fmt.Println("合并配置失败:", err)
			continue
		}
		if !changed {
			fmt.Println("配置未变化，跳过 Mihomo 重载")
			continue
		}

		fmt.Printf("发现配置更新，已写入 Mihomo 主配置（目录：%s，文件：%s）\n", mihomoHome(), mihomoConfigPath())

		if err := reloadMihomo(); err != nil {
			fmt.Printf("Mihomo 配置重载失败，正在恢复旧配置: %v\n", err)
			if restoreErr := rollbackConfigAfterReloadFailure(); restoreErr != nil {
				fmt.Printf("恢复旧配置失败: %v\n", restoreErr)
				continue
			}
			if reloadErr := reloadMihomo(); reloadErr != nil {
				fmt.Printf("旧配置已恢复，但重新加载失败: %v\n", reloadErr)
				continue
			}
			fmt.Println("已恢复旧配置并重新加载")
			continue
		}
		_ = os.Remove(mihomoConfigPath() + ".previous")
		fmt.Println("完整 Mihomo 配置应用成功")
	}
}
