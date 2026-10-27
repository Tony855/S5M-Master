package main

import (
	"context"
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	cryptorand "crypto/rand"
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
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
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

func mihomoBinaryPath() string {
	if strings.EqualFold(strings.TrimSpace(os.Getenv("S5M_ROUTEROS")), "1") {
		return filepath.Join(mihomoHome(), "bin", "mihomo")
	}
	return "/usr/local/bin/mihomo"
}

func mihomoConfigPath() string {
	return mihomoHome() + "/config.yaml"
}

// 独立的重载函数，防止变量冲突

// preserveMihomoSecret keeps the local external-controller credential stable.
// Mihomo may continue authenticating with its startup secret after a config reload,
// so accepting a controller-provided replacement can lock the Agent out of its API.
func preserveMihomoSecret(current, incoming map[string]interface{}) error {
	secret, ok := current["secret"].(string)
	secret = strings.TrimSpace(secret)
	if !ok || secret == "" {
		return fmt.Errorf("本地 Mihomo 配置缺少有效 secret，拒绝热更新以避免 API 鉴权失联")
	}
	incoming["secret"] = secret
	return nil
}

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
		return false, fmt.Errorf("读取本地 Mihomo 配置失败")
	}
	var oldCfg map[string]interface{}
	if err := yaml.Unmarshal(oldData, &oldCfg); err != nil {
		return false, fmt.Errorf("本地 Mihomo YAML 无效: %w", err)
	}

	// Mihomo's external-controller authentication is established at core startup.
	// A normal /configs reload must not rotate the API secret behind the Agent's
	// back: keep the currently configured secret stable across controller updates.
	if err := preserveMihomoSecret(oldCfg, nextCfg); err != nil {
		return false, err
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
		return false, fmt.Errorf("备份旧 Mihomo 配置失败")
	}
	tmpPath := mainPath + ".tmp"
	// Write the normalized configuration so the preserved local secret is
	// actually persisted; writing agentYml here would undo the protection above.
	if err := os.WriteFile(tmpPath, newNorm, 0600); err != nil {
		return false, err
	}
	if _, err := exec.Command(mihomoBinaryPath(), "-t", "-d", mihomoHome(), "-f", tmpPath).CombinedOutput(); err != nil {
		_ = os.Remove(tmpPath)
		return false, fmt.Errorf("新配置未通过 Mihomo 校验（已隐藏底层路径详情）")
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
		return fmt.Errorf("读取旧配置备份失败")
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
		"arch": runtime.GOARCH, "os": runtime.GOOS,
		"hostname": "", "mihomo_version": "", "mihomo_healthy": false,
		"upload_total": int64(0), "download_total": int64(0),
		"upload_speed": float64(0), "download_speed": float64(0),
		"connections": 0, "config_sha256": "", "last_error": "",
	}
	if hostname, err := agentHostname(); err == nil {
		status["hostname"] = hostname
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

// reportHeartbeat uses WebSocket as the primary telemetry channel.
// HTTP is retained only as a compatibility fallback if the WebSocket handshake,
// heartbeat exchange, or acknowledgement fails.
func reportHeartbeat(cfg Config, status map[string]any) error {
	return reportHeartbeatWebSocket(cfg, status)
}

// fetchAgentConfigWebSocket fetches this machine's configuration without HTTP polling.
// A config hash allows the controller to avoid retransmitting unchanged YAML.
func fetchAgentConfigWebSocket(cfg Config, localHash string) ([]byte, bool, error) {
	base, err := url.Parse(strings.TrimRight(cfg.CentralURL, "/"))
	if err != nil || base.Host == "" {
		return nil, false, fmt.Errorf("主控地址无效")
	}
	switch strings.ToLower(base.Scheme) {
	case "http":
		base.Scheme = "ws"
	case "https":
		base.Scheme = "wss"
	default:
		return nil, false, fmt.Errorf("主控地址协议不支持")
	}
	base.Path = strings.TrimRight(base.Path, "/") + "/api/v1/agent/ws"
	base.RawPath = ""
	header := http.Header{}
	header.Set("Authorization", "Bearer "+cfg.Token)
	conn, response, err := (&websocket.Dialer{HandshakeTimeout: 8 * time.Second}).Dial(base.String(), header)
	if err != nil {
		if response != nil {
			return nil, false, fmt.Errorf("WebSocket 握手失败：HTTP %d：%w", response.StatusCode, err)
		}
		return nil, false, fmt.Errorf("WebSocket 连接失败：%w", err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	_ = conn.SetWriteDeadline(time.Now().Add(8 * time.Second))
	var welcome struct {
		Type string `json:"type"`
	}
	if err := conn.ReadJSON(&welcome); err != nil {
		return nil, false, fmt.Errorf("读取 WebSocket 欢迎消息失败：%w", err)
	}
	if welcome.Type != "welcome" {
		return nil, false, fmt.Errorf("WebSocket 欢迎消息类型无效")
	}
	requestID := fmt.Sprintf("cfg-%d", time.Now().UnixNano())
	if err := conn.WriteJSON(map[string]string{"type": "config.request", "id": requestID, "config_sha256": localHash}); err != nil {
		return nil, false, fmt.Errorf("发送配置请求失败：%w", err)
	}
	var result struct {
		Type    string `json:"type"`
		ID      string `json:"id"`
		SHA256  string `json:"sha256"`
		YAML    string `json:"yaml"`
		Message string `json:"message"`
	}
	if err := conn.ReadJSON(&result); err != nil {
		return nil, false, fmt.Errorf("读取 WebSocket 配置响应失败：%w", err)
	}
	if result.ID != requestID {
		return nil, false, fmt.Errorf("WebSocket 配置响应 ID 不匹配")
	}
	switch result.Type {
	case "config.unchanged":
		return nil, true, nil
	case "config.sync":
		if strings.TrimSpace(result.YAML) == "" {
			return nil, false, fmt.Errorf("主控端返回空配置")
		}
		sum := sha256.Sum256([]byte(result.YAML))
		if result.SHA256 != hex.EncodeToString(sum[:]) {
			return nil, false, fmt.Errorf("主控端配置 SHA-256 校验失败")
		}
		return []byte(result.YAML), false, nil
	case "error":
		return nil, false, fmt.Errorf("主控端拒绝配置请求：%s", result.Message)
	default:
		return nil, false, fmt.Errorf("未知的 WebSocket 配置响应类型: %s", result.Type)
	}
}

func reportHeartbeatWebSocket(cfg Config, status map[string]any) error {
	base, err := url.Parse(strings.TrimRight(cfg.CentralURL, "/"))
	if err != nil || base.Host == "" {
		return fmt.Errorf("主控地址无效")
	}
	switch strings.ToLower(base.Scheme) {
	case "http":
		base.Scheme = "ws"
	case "https":
		base.Scheme = "wss"
	default:
		return fmt.Errorf("主控地址协议不支持")
	}
	base.Path = strings.TrimRight(base.Path, "/") + "/api/v1/agent/ws"
	base.RawPath = ""
	header := http.Header{}
	header.Set("Authorization", "Bearer "+cfg.Token)
	dialer := websocket.Dialer{HandshakeTimeout: 8 * time.Second}
	conn, response, err := dialer.Dial(base.String(), header)
	if err != nil {
		if response != nil {
			return fmt.Errorf("WebSocket 握手失败：HTTP %d：%w", response.StatusCode, err)
		}
		return fmt.Errorf("WebSocket 连接失败：%w", err)
	}
	defer conn.Close()
	if err := conn.SetReadDeadline(time.Now().Add(8 * time.Second)); err != nil {
		return err
	}
	if err := conn.SetWriteDeadline(time.Now().Add(8 * time.Second)); err != nil {
		return err
	}
	var welcome struct {
		Type string `json:"type"`
	}
	if err := conn.ReadJSON(&welcome); err != nil {
		return fmt.Errorf("读取 WebSocket 欢迎消息失败：%w", err)
	}
	if welcome.Type != "welcome" {
		return fmt.Errorf("WebSocket 欢迎消息类型无效")
	}
	heartbeatID := fmt.Sprintf("hb-%d", time.Now().UnixNano())
	if err := conn.WriteJSON(map[string]any{
		"type":   "heartbeat",
		"id":     heartbeatID,
		"status": status,
	}); err != nil {
		return fmt.Errorf("发送 WebSocket 心跳失败：%w", err)
	}
	var ack struct {
		Type string `json:"type"`
		ID   string `json:"id"`
		OK   bool   `json:"ok"`
	}
	if err := conn.ReadJSON(&ack); err != nil {
		return fmt.Errorf("读取 WebSocket 心跳确认失败：%w", err)
	}
	if ack.Type != "heartbeat.ack" || ack.ID != heartbeatID || !ack.OK {
		return fmt.Errorf("主控端心跳确认无效")
	}
	return nil
}

func reportHeartbeatHTTP(cfg Config, status map[string]any) error {
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

// processAgentCommandWebSocket polls and acknowledges commands through the authenticated WebSocket protocol.
func processAgentCommandWebSocket(cfg Config) error {
	base, err := url.Parse(strings.TrimRight(cfg.CentralURL, "/"))
	if err != nil || base.Host == "" {
		return fmt.Errorf("主控地址无效")
	}
	switch strings.ToLower(base.Scheme) {
	case "http":
		base.Scheme = "ws"
	case "https":
		base.Scheme = "wss"
	default:
		return fmt.Errorf("主控地址协议不支持")
	}
	base.Path = strings.TrimRight(base.Path, "/") + "/api/v1/agent/ws"
	base.RawPath = ""
	header := http.Header{}
	header.Set("Authorization", "Bearer "+cfg.Token)
	conn, response, err := (&websocket.Dialer{HandshakeTimeout: 8 * time.Second}).Dial(base.String(), header)
	if err != nil {
		if response != nil {
			return fmt.Errorf("WebSocket 握手失败：HTTP %d：%w", response.StatusCode, err)
		}
		return fmt.Errorf("WebSocket 连接失败：%w", err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(12 * time.Second))
	_ = conn.SetWriteDeadline(time.Now().Add(8 * time.Second))
	var welcome struct {
		Type string `json:"type"`
	}
	if err := conn.ReadJSON(&welcome); err != nil {
		return fmt.Errorf("读取 WebSocket 欢迎消息失败：%w", err)
	}
	if welcome.Type != "welcome" {
		return fmt.Errorf("WebSocket 欢迎消息类型无效")
	}
	requestID := fmt.Sprintf("cmd-poll-%d", time.Now().UnixNano())
	if err := conn.WriteJSON(map[string]string{"type": "command.request", "id": requestID}); err != nil {
		return err
	}
	var envelope struct {
		Type    string        `json:"type"`
		ID      string        `json:"id"`
		Command *agentCommand `json:"command"`
		Message string        `json:"message"`
	}
	if err := conn.ReadJSON(&envelope); err != nil {
		return fmt.Errorf("读取 WebSocket 命令失败：%w", err)
	}
	if envelope.ID != requestID {
		return fmt.Errorf("WebSocket 命令响应 ID 不匹配")
	}
	if envelope.Type == "command.none" {
		return nil
	}
	if envelope.Type == "error" {
		return fmt.Errorf("主控命令查询失败：%s", envelope.Message)
	}
	if envelope.Type != "command.deliver" || envelope.Command == nil {
		return fmt.Errorf("主控端命令响应格式无效")
	}
	cmd := *envelope.Command
	var runErr error
	message := ""
	switch cmd.Type {
	case "update_mihomo":
		message, runErr = updateMihomoKernel(cmd)
	default:
		runErr = fmt.Errorf("不支持的 Agent 命令类型: %s", cmd.Type)
	}
	status := "success"
	if runErr != nil {
		status = "failed"
		message = runErr.Error()
	}
	if len(message) > 2048 {
		message = message[:2048]
	}
	if err := conn.WriteJSON(map[string]string{"type": "command.ack", "id": cmd.ID, "command_status": status, "message": message}); err != nil {
		return fmt.Errorf("命令已执行但 WebSocket ACK 发送失败，主控端可能重新投递: %w", err)
	}
	var ack struct {
		Type    string `json:"type"`
		ID      string `json:"id"`
		OK      bool   `json:"ok"`
		Message string `json:"message"`
	}
	if err := conn.ReadJSON(&ack); err != nil {
		return fmt.Errorf("读取命令 ACK 确认失败：%w", err)
	}
	if ack.Type != "command.acknowledged" || ack.ID != cmd.ID || !ack.OK {
		return fmt.Errorf("主控端命令 ACK 确认无效: %s", ack.Message)
	}
	if runErr != nil {
		return runErr
	}
	fmt.Printf("Agent 命令 %s 执行成功: %s\n", cmd.ID, message)
	return nil
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
	if output, err := exec.Command(mihomoBinaryPath(), "-v").CombinedOutput(); err == nil {
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
	newBinary, err := os.CreateTemp(filepath.Dir(mihomoBinaryPath()), ".mihomo-update-*")
	if err != nil {
		return "", fmt.Errorf("创建内核临时文件失败")
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
	if _, err := exec.Command(newPath, "-v").CombinedOutput(); err != nil {
		return "", fmt.Errorf("新内核自检失败（已隐藏底层路径详情）")
	}
	configPath := mihomoConfigPath()
	if _, err := exec.Command(newPath, "-t", "-d", mihomoHome(), "-f", configPath).CombinedOutput(); err != nil {
		return "", fmt.Errorf("新内核未通过当前配置校验（已隐藏底层路径详情）")
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
	binaryPath := mihomoBinaryPath()
	backupPath := binaryPath + ".previous"
	_ = os.Remove(backupPath)
	if err := os.Rename(binaryPath, backupPath); err != nil {
		return "", fmt.Errorf("备份现有 Mihomo 内核失败")
	}
	if err := os.Rename(newPath, binaryPath); err != nil {
		_ = os.Rename(backupPath, binaryPath)
		return "", fmt.Errorf("安装新 Mihomo 内核失败")
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
		return "", fmt.Errorf("新内核已通过健康检查，但删除旧内核备份失败")
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

// restartMihomo asks s6-supervise to restart only the Mihomo process from
// /usr/local/bin/mihomo. Do not take the service down through s6-rc: the Agent
// declares a dependency on Mihomo, so a dependency-aware down operation may also
// stop the Agent while it is processing this command and prevent its ACK.
func restartMihomo(secret string) error {
	_ = secret // Retained in the signature for compatibility with update flow.
	output, err := exec.Command("s6-svc", "-r", "/run/service/mihomo").CombinedOutput()
	if err != nil {
		return fmt.Errorf("请求 s6 重启 Mihomo 服务失败: %v: %s", err, strings.TrimSpace(string(output)))
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

func replaceFileAtomically(sourcePath, destinationPath string) error {
	// The source and destination must be on the same filesystem for rename to
	// replace the destination atomically. All Mihomo update files are created
	// beside the installed binary, so this holds for supported Linux targets.
	return os.Rename(sourcePath, destinationPath)
}

// restoreMihomoKernel reinstalls the backup and requests a restart.
func restoreMihomoKernel(binaryPath, backupPath, secret string) error {
	return restoreMihomoKernelWithRestart(binaryPath, backupPath, func() error {
		return restartMihomo(secret)
	})
}

// restoreMihomoKernelWithRestart separates file recovery from the controller
// request so both failure modes can be tested without a live Mihomo API.
func restoreMihomoKernelWithRestart(binaryPath, backupPath string, restart func() error) error {
	// Never remove the new binary before attempting replacement: if the rename
	// fails, keep the currently installed executable available for recovery.
	if err := replaceFileAtomically(backupPath, binaryPath); err != nil {
		return fmt.Errorf("恢复旧内核文件失败")
	}
	if err := restart(); err != nil {
		return fmt.Errorf("旧内核文件已恢复，但请求重启失败: %w", err)
	}
	return nil
}

func normalizeMachineID(data []byte) string {
	id := strings.ToLower(strings.TrimSpace(string(data)))
	if len(id) < 11 || len(id) > 32 {
		return ""
	}
	for _, ch := range id {
		if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')) {
			return ""
		}
	}
	if strings.Trim(id, "0") == "" {
		return ""
	}
	return id
}

func machineIDPath() string {
	return filepath.Join(mihomoHome(), "machine-id")
}

func validStoredFallbackMachineID(data []byte) string {
	id := strings.ToLower(strings.TrimSpace(string(data)))
	if len(id) != 32 {
		return ""
	}
	for _, ch := range id {
		if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')) {
			return ""
		}
	}
	if strings.Trim(id, "0") == "" {
		return ""
	}
	return id
}

func readSystemMachineID(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	id := normalizeMachineID(data)
	if id == "" {
		return "", fmt.Errorf("系统机器标识文件为空或格式无效")
	}
	return id[:11], nil
}

// loadOrCreateMachineID prefers /etc/machine-id. If unavailable, it generates
// a random ID and persists it under /data, which survives container recreation
// when the configured volume is retained. Storage errors are never ignored.
func loadOrCreateMachineID(systemPath, storagePath string) (string, error) {
	if id, err := readSystemMachineID(systemPath); err == nil {
		return id, nil
	}
	if err := os.MkdirAll(filepath.Dir(storagePath), 0700); err != nil {
		return "", fmt.Errorf("创建机器标识持久化目录失败")
	}
	if data, err := os.ReadFile(storagePath); err == nil {
		if id := validStoredFallbackMachineID(data); id != "" {
			return id[:11], nil
		}
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("读取备用机器标识失败")
	}
	randomID := make([]byte, 16)
	if _, err := cryptorand.Read(randomID); err != nil {
		return "", fmt.Errorf("生成备用机器标识失败: %w", err)
	}
	fullID := hex.EncodeToString(randomID)
	tmp, err := os.CreateTemp(filepath.Dir(storagePath), ".machine-id-*")
	if err != nil {
		return "", fmt.Errorf("创建机器标识临时文件失败")
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("设置机器标识文件权限失败")
	}
	if _, err := tmp.WriteString(fullID + "\n"); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("写入备用机器标识失败: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("同步备用机器标识失败: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("关闭机器标识临时文件失败: %w", err)
	}
	if err := os.Rename(tmpPath, storagePath); err != nil {
		if data, readErr := os.ReadFile(storagePath); readErr == nil {
			if id := validStoredFallbackMachineID(data); id != "" {
				return id[:11], nil
			}
		}
		return "", fmt.Errorf("持久化备用机器标识失败")
	}
	return fullID[:11], nil
}

func getMachineID() (string, error) {
	return loadOrCreateMachineID("/etc/machine-id", machineIDPath())
}

func agentHostname() (string, error) {
	// Docker containers normally have their own hostname (often the container ID).
	// Deployments should pass the host OS hostname via S5M_HOSTNAME.
	if hostname := strings.TrimSpace(os.Getenv("S5M_HOSTNAME")); hostname != "" {
		return hostname, nil
	}
	hostname, err := os.Hostname()
	if err != nil {
		return "", err
	}
	hostname = strings.TrimSpace(hostname)
	if hostname == "" {
		return "", fmt.Errorf("hostname is empty")
	}
	return hostname, nil
}

func hostnameHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "仅允许 GET", http.StatusMethodNotAllowed)
		return
	}
	hostname, err := agentHostname()
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err != nil {
		http.Error(w, "无法读取主机名", http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]string{"hostname": hostname})
}

func machineIDHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "仅允许 GET", http.StatusMethodNotAllowed)
		return
	}
	id, err := getMachineID()
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error": "无法生成或读取机器标识: " + err.Error(),
		})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]string{"machine_id": id})
}

// probeControllerHTTP is deliberately limited to controller reachability.
// A received HTTP response proves network reachability; application data is never
// read from this endpoint and no HTTP fallback is used for Agent status/config/commands.
func probeControllerHTTP(cfg Config) error {
	base, err := url.Parse(strings.TrimRight(cfg.CentralURL, "/"))
	if err != nil || base.Host == "" {
		return fmt.Errorf("主控地址无效")
	}
	base.Path = strings.TrimRight(base.Path, "/") + "/api/v1/health"
	base.RawPath = ""
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base.String(), nil)
	if err != nil {
		return err
	}
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
	// Even a 4xx/5xx response proves that the controller host is reachable.
	return nil
}

func nextReconnectDelay(current time.Duration) time.Duration {
	if current < 2*time.Second {
		return 2 * time.Second
	}
	current *= 2
	if current > 60*time.Second {
		return 60 * time.Second
	}
	return current
}

// runAgentWebSocketSession owns one persistent connection for all Agent control-plane
// traffic. Every request/response is correlated by ID, and the existing safe config
// apply/rollback and idempotent kernel-upgrade paths are reused.
func runAgentWebSocketSession(cfg Config) error {
	base, err := url.Parse(strings.TrimRight(cfg.CentralURL, "/"))
	if err != nil || base.Host == "" {
		return fmt.Errorf("主控地址无效")
	}
	switch strings.ToLower(base.Scheme) {
	case "http":
		base.Scheme = "ws"
	case "https":
		base.Scheme = "wss"
	default:
		return fmt.Errorf("主控地址协议不支持")
	}
	base.Path = strings.TrimRight(base.Path, "/") + "/api/v1/agent/ws"
	base.RawPath = ""
	header := http.Header{}
	header.Set("Authorization", "Bearer "+cfg.Token)
	dialer := websocket.Dialer{HandshakeTimeout: 8 * time.Second}
	conn, response, err := dialer.Dial(base.String(), header)
	if err != nil {
		if response != nil {
			return fmt.Errorf("WebSocket 握手失败：HTTP %d：%w", response.StatusCode, err)
		}
		return fmt.Errorf("WebSocket 连接失败：%w", err)
	}
	defer conn.Close()
	conn.SetReadLimit(3 << 20)
	_ = conn.SetWriteDeadline(time.Now().Add(8 * time.Second))
	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	var welcome struct {
		Type                 string `json:"type"`
		Protocol             int    `json:"protocol"`
		HeartbeatIntervalSec int    `json:"heartbeat_interval_sec"`
	}
	if err := conn.ReadJSON(&welcome); err != nil {
		return fmt.Errorf("读取 WebSocket 欢迎消息失败：%w", err)
	}
	if welcome.Type != "welcome" || welcome.Protocol != 1 {
		return fmt.Errorf("WebSocket 协议版本或欢迎消息无效")
	}
	heartbeatInterval := time.Duration(welcome.HeartbeatIntervalSec) * time.Second
	if heartbeatInterval < 5*time.Second || heartbeatInterval > 60*time.Second {
		heartbeatInterval = 30 * time.Second
	}

	for {
		// 1. Status/heartbeat is WebSocket-only.
		status := collectMihomoStatus()
		heartbeatID := fmt.Sprintf("hb-%d", time.Now().UnixNano())
		if err := writeAgentWSJSON(conn, map[string]any{
			"type": "heartbeat", "id": heartbeatID, "status": status,
		}); err != nil {
			return fmt.Errorf("发送状态心跳失败：%w", err)
		}
		var heartbeatAck struct {
			Type    string `json:"type"`
			ID      string `json:"id"`
			OK      bool   `json:"ok"`
			Message string `json:"message"`
		}
		if err := readAgentWSJSON(conn, &heartbeatAck, 90*time.Second); err != nil {
			return fmt.Errorf("读取状态心跳确认失败：%w", err)
		}
		if heartbeatAck.Type != "heartbeat.ack" || heartbeatAck.ID != heartbeatID || !heartbeatAck.OK {
			return fmt.Errorf("主控端状态心跳确认无效: %s", heartbeatAck.Message)
		}

		// 2. Fetch config on the same socket. A hash prevents needless YAML transfers.
		localHash := ""
		if localData, readErr := os.ReadFile(mihomoConfigPath()); readErr == nil && len(localData) > 0 {
			sum := sha256.Sum256([]byte(strings.TrimSpace(string(localData))))
			localHash = hex.EncodeToString(sum[:])
		}
		configRequestID := fmt.Sprintf("cfg-%d", time.Now().UnixNano())
		if err := writeAgentWSJSON(conn, map[string]string{
			"type": "config.request", "id": configRequestID, "config_sha256": localHash,
		}); err != nil {
			return fmt.Errorf("请求配置失败：%w", err)
		}
		var configResponse struct {
			Type    string `json:"type"`
			ID      string `json:"id"`
			SHA256  string `json:"sha256"`
			YAML    string `json:"yaml"`
			Message string `json:"message"`
		}
		if err := readAgentWSJSON(conn, &configResponse, 90*time.Second); err != nil {
			return fmt.Errorf("读取配置响应失败：%w", err)
		}
		if configResponse.ID != configRequestID {
			return fmt.Errorf("WebSocket 配置响应 ID 不匹配")
		}
		switch configResponse.Type {
		case "config.unchanged":
		case "config.sync":
			if strings.TrimSpace(configResponse.YAML) == "" {
				return fmt.Errorf("主控端返回空配置")
			}
			changed, applyErr := mergeConfig([]byte(configResponse.YAML))
			if applyErr != nil {
				fmt.Printf("WebSocket 配置校验/写入失败: %v\\n", applyErr)
				break
			}
			if changed {
				if reloadErr := reloadMihomo(); reloadErr != nil {
					fmt.Printf("Mihomo 配置重载失败，正在回滚: %v\\n", reloadErr)
					if rollbackErr := rollbackConfigAfterReloadFailure(); rollbackErr != nil {
						return fmt.Errorf("配置重载失败且回滚失败: %w", rollbackErr)
					}
					if retryErr := reloadMihomo(); retryErr != nil {
						return fmt.Errorf("旧配置已恢复但重载失败: %w", retryErr)
					}
				} else {
					_ = os.Remove(mihomoConfigPath() + ".previous")
					fmt.Println("WebSocket 下发的 Mihomo 配置已应用")
				}
			}
		default:
			return fmt.Errorf("未知的 WebSocket 配置响应类型: %s", configResponse.Type)
		}

		// 3. Fetch and acknowledge commands over this same persistent socket.
		commandRequestID := fmt.Sprintf("cmd-%d", time.Now().UnixNano())
		if err := writeAgentWSJSON(conn, map[string]string{
			"type": "command.request", "id": commandRequestID,
		}); err != nil {
			return fmt.Errorf("请求待执行命令失败：%w", err)
		}
		var commandEnvelope struct {
			Type    string        `json:"type"`
			ID      string        `json:"id"`
			Command *agentCommand `json:"command"`
			Message string        `json:"message"`
		}
		if err := readAgentWSJSON(conn, &commandEnvelope, 90*time.Second); err != nil {
			return fmt.Errorf("读取命令响应失败：%w", err)
		}
		if commandEnvelope.ID != commandRequestID {
			return fmt.Errorf("WebSocket 命令响应 ID 不匹配")
		}
		switch commandEnvelope.Type {
		case "command.none":
		case "command.deliver":
			if commandEnvelope.Command == nil || strings.TrimSpace(commandEnvelope.Command.ID) == "" {
				return fmt.Errorf("WebSocket 命令缺少有效 ID")
			}
			cmd := *commandEnvelope.Command
			var commandErr error
			message := ""
			switch cmd.Type {
			case "update_mihomo":
				message, commandErr = updateMihomoKernel(cmd)
			default:
				commandErr = fmt.Errorf("不支持的 Agent 命令类型: %s", cmd.Type)
			}
			commandStatus := "success"
			if commandErr != nil {
				commandStatus = "failed"
				message = commandErr.Error()
			}
			if len(message) > 2048 {
				message = message[:2048]
			}
			if err := writeAgentWSJSON(conn, map[string]string{
				"type": "command.ack", "id": cmd.ID,
				"command_status": commandStatus, "message": message,
			}); err != nil {
				return fmt.Errorf("命令已执行但 ACK 发送失败（服务端将按命令 ID 幂等重投）: %w", err)
			}
			var ack struct {
				Type    string `json:"type"`
				ID      string `json:"id"`
				OK      bool   `json:"ok"`
				Message string `json:"message"`
			}
			if err := readAgentWSJSON(conn, &ack, 30*time.Second); err != nil {
				return fmt.Errorf("读取命令 ACK 确认失败：%w", err)
			}
			if ack.Type != "command.acknowledged" || ack.ID != cmd.ID || !ack.OK {
				return fmt.Errorf("主控端命令 ACK 确认无效: %s", ack.Message)
			}
			if commandErr != nil {
				fmt.Printf("Agent 命令 %s 执行失败: %v\\n", cmd.ID, commandErr)
			}
		default:
			return fmt.Errorf("未知的 WebSocket 命令响应类型: %s", commandEnvelope.Type)
		}

		// Heartbeats on every cycle keep the socket alive; no HTTP status/config/command fallback.
		time.Sleep(heartbeatInterval)
	}
}

func writeAgentWSJSON(conn *websocket.Conn, value any) error {
	if err := conn.SetWriteDeadline(time.Now().Add(8 * time.Second)); err != nil {
		return err
	}
	return conn.WriteJSON(value)
}

func readAgentWSJSON(conn *websocket.Conn, target any, timeout time.Duration) error {
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	return conn.ReadJSON(target)
}

func main() {
	// 启动 80 端口提供 Web 注册界面
	go func() {
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			http.ServeFile(w, r, "/app/index.html")
		})

		// ====== 提供前端页面的 API ======
		http.HandleFunc("/api/machine-id", machineIDHandler)
		http.HandleFunc("/api/hostname", hostnameHandler)

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
			machineID, machineErr := getMachineID()
			if machineErr != nil {
				http.Error(w, "无法生成或读取有效机器码: "+machineErr.Error(), http.StatusInternalServerError)
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
		fmt.Println("Agent Web 服务已启动: :80")
		if err := http.ListenAndServe(":80", nil); err != nil {
			fmt.Println("Agent Web 服务启动失败:", err)
		}
	}()

	// 确保 data 目录存在
	os.MkdirAll(mihomoHome(), 0700)

	// 控制面采用单条持久 WebSocket：状态、配置同步、命令投递与 ACK 均走该连接。
	// HTTP 仅用于主控连通性探测和首次注册；绝不通过 HTTP 回退传输状态/配置/命令。
	backoff := 2 * time.Second
	for {
		data, readErr := os.ReadFile(filepath.Join(mihomoHome(), "agent.json"))
		if readErr != nil || len(data) == 0 {
			time.Sleep(5 * time.Second)
			continue
		}
		var cfg Config
		if err := json.Unmarshal(data, &cfg); err != nil || strings.TrimSpace(cfg.Token) == "" {
			time.Sleep(5 * time.Second)
			continue
		}
		if err := probeControllerHTTP(cfg); err != nil {
			fmt.Printf("主控 HTTP 连通性探测失败（仅用于诊断，不传输状态/配置/命令）: %v\\n", err)
			time.Sleep(backoff)
			backoff = nextReconnectDelay(backoff)
			continue
		}
		if err := runAgentWebSocketSession(cfg); err != nil {
			fmt.Printf("Agent WebSocket 会话断开: %v\\n", err)
		}
		time.Sleep(backoff)
		backoff = nextReconnectDelay(backoff)
	}
}
