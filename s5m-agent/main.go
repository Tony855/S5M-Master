package main

import (
	"bytes"
	"compress/gzip"
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
	"runtime"
	"regexp"
	"strings"
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
func mergeConfig(agentYml []byte) (bool, error) {
	mainPath := mihomoConfigPath()
	previousPath := mainPath + ".previous"
	if len(agentYml) == 0 || len(agentYml) > 2*1024*1024 {
		return false, fmt.Errorf("主控端配置为空或超过 2 MiB")
	}
	var nextCfg map[string]interface{}
	if err := yaml.Unmarshal(agentYml, &nextCfg); err != nil {
		return false, fmt.Errorf("主控端 Mihomo YAML 无效: %w", err)
	}
	if len(nextCfg) == 0 {
		return false, fmt.Errorf("主控端 Mihomo 配置为空")
	}
	secret, _ := nextCfg["secret"].(string)
	if strings.TrimSpace(secret) == "" {
		return false, fmt.Errorf("主控端配置缺少 Mihomo secret，拒绝覆盖本地配置")
	}
	if _, ok := nextCfg["tun"]; !ok {
		return false, fmt.Errorf("主控端配置缺少 tun 配置块")
	}
	if _, ok := nextCfg["dns"]; !ok {
		return false, fmt.Errorf("主控端配置缺少 dns 配置块")
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

func reloadMihomo() error {
	configPath := mihomoConfigPath()
	configData, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("读取 Mihomo 配置失败: %w", err)
	}
	var config map[string]interface{}
	if err := yaml.Unmarshal(configData, &config); err != nil {
		return fmt.Errorf("解析 Mihomo 配置失败: %w", err)
	}
	// Mihomo 当前运行进程仍使用旧配置的 secret 来认证本次重载。
	// 配置切换时先从 .previous 读取旧 secret；重载成功后调用方才删除备份。
	secret := ""
	for _, path := range []string{configPath + ".previous", configPath} {
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			continue
		}
		var candidate map[string]interface{}
		if yaml.Unmarshal(data, &candidate) == nil {
			if value, ok := candidate["secret"].(string); ok && strings.TrimSpace(value) != "" {
				secret = strings.TrimSpace(value)
				break
			}
		}
	}
	if secret == "" {
		return fmt.Errorf("当前 Mihomo 配置和备份均没有有效 secret，无法执行重载")
	}

	reloadBody := strings.NewReader(
		fmt.Sprintf(`{"path": %q}`, mihomoConfigPath()),
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

	client := &http.Client{Timeout: 10 * time.Second}
	reloadResp, err := client.Do(reloadReq)
	if err != nil {
		return fmt.Errorf("请求 Mihomo 重载失败: %w", err)
	}
	defer reloadResp.Body.Close()

	responseBody, _ := io.ReadAll(io.LimitReader(reloadResp.Body, 4096))
	if reloadResp.StatusCode != http.StatusOK &&
		reloadResp.StatusCode != http.StatusNoContent {
		return fmt.Errorf(
			"Mihomo 重载返回 HTTP %d: %s",
			reloadResp.StatusCode,
			strings.TrimSpace(string(responseBody)),
		)
	}

	return nil
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
	status["mihomo_version"] = version["version"]
	traffic, err := get("/traffic")
	if err == nil {
		status["upload_speed"] = traffic["up"]
		status["download_speed"] = traffic["down"]
	} else {
		status["last_error"] = "读取流量失败: " + err.Error()
	}
	connections, err := get("/connections")
	if err == nil {
		items, _ := connections["connections"].([]any)
		status["connections"] = len(items)
		status["upload_total"] = connections["uploadTotal"]
		status["download_total"] = connections["downloadTotal"]
	} else if status["last_error"] == "" {
		status["last_error"] = "读取连接数失败: " + err.Error()
	}
	status["mihomo_healthy"] = true
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
	restartReq, err := http.NewRequest(http.MethodPut, "http://127.0.0.1:8088/restart", nil)
	if err != nil {
		_ = os.Remove(binaryPath)
		_ = os.Rename(backupPath, binaryPath)
		return "", err
	}
	restartReq.Header.Set("Authorization", "Bearer "+secret)
	restartResp, restartErr := (&http.Client{Timeout: 20 * time.Second}).Do(restartReq)
	if restartErr != nil {
		_ = os.Remove(binaryPath)
		_ = os.Rename(backupPath, binaryPath)
		return "", fmt.Errorf("新内核已替换，但请求 Mihomo 重启失败，已恢复旧内核: %w", restartErr)
	}
	defer restartResp.Body.Close()
	if restartResp.StatusCode < 200 || restartResp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(restartResp.Body, 2048))
		_ = os.Remove(binaryPath)
		_ = os.Rename(backupPath, binaryPath)
		return "", fmt.Errorf("Mihomo 重启返回 HTTP %d: %s；已恢复旧内核", restartResp.StatusCode, strings.TrimSpace(string(body)))
	}
	_ = os.Remove(backupPath)
	return "Mihomo 内核已更新到 " + cmd.Version, nil
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
			http.ServeFile(w, r, "/opt/s5m-agent/index.html")
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
				"has_token": cfg.Token != "",
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

		if err := processAgentCommand(cfg); err != nil {
			fmt.Printf("Agent 命令处理失败: %v\\n", err)
		}

		fmt.Println("👉 正在向主控台发送心跳...")
		req, err := http.NewRequest(
			http.MethodGet,
			strings.TrimRight(cfg.CentralURL, "/")+"/api/v1/agent/config",
			nil,
		)
		if err != nil {
			fmt.Printf("Agent 配置请求创建失败: %v\\n", err)
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
			fmt.Printf("❌ Agent 心跳请求失败: %v\\n", err)
			continue
		}

		if resp.StatusCode == http.StatusNotModified {
			resp.Body.Close()
			if err := reportHeartbeat(cfg, collectMihomoStatus()); err != nil {
				fmt.Printf("Agent 状态上报失败: %v\\n", err)
			}
			fmt.Println("主控端配置哈希未变化，跳过下载与重载")
			continue
		}
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			fmt.Printf("❌ Agent 心跳异常: HTTP %d，主控端响应: %s\\n", resp.StatusCode, strings.TrimSpace(string(body)))
			continue
		}

		newYml, readErr := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
		resp.Body.Close()
		if readErr != nil {
			fmt.Printf("读取主控台配置失败: %v\\n", readErr)
			continue
		}
		if err := reportHeartbeat(cfg, collectMihomoStatus()); err != nil {
			fmt.Printf("Agent 状态上报失败: %v\\n", err)
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
			fmt.Printf("Mihomo 配置重载失败，正在恢复旧配置: %v\\n", err)
			if restoreErr := rollbackConfigAfterReloadFailure(); restoreErr != nil {
				fmt.Printf("恢复旧配置失败: %v\\n", restoreErr)
				continue
			}
			if reloadErr := reloadMihomo(); reloadErr != nil {
				fmt.Printf("旧配置已恢复，但重新加载失败: %v\\n", reloadErr)
				continue
			}
			fmt.Println("已恢复旧配置并重新加载")
			continue
		}
		_ = os.Remove(mihomoConfigPath() + ".previous")
		fmt.Println("完整 Mihomo 配置应用成功")
	}
}
