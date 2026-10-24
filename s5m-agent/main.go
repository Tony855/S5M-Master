package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
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

// 独立的重载函数，防止变量冲突

// mergeConfig applies the complete controller-generated Mihomo YAML.
// The previous config is kept until Mihomo successfully reloads.
func mergeConfig(agentYml []byte) (bool, error) {
	const mainPath = "/data/s5m-next/config.yaml"
	const previousPath = mainPath + ".previous"
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
	if err := os.Rename(tmpPath, mainPath); err != nil {
		_ = os.Remove(tmpPath)
		return false, err
	}
	return true, nil
}

func rollbackConfigAfterReloadFailure() error {
	const mainPath = "/data/s5m-next/config.yaml"
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
	const configPath = "/data/s5m-next/config.yaml"
	configData, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("读取 Mihomo 配置失败: %w", err)
	}
	var config map[string]interface{}
	if err := yaml.Unmarshal(configData, &config); err != nil {
		return fmt.Errorf("解析 Mihomo 配置失败: %w", err)
	}
	secret, _ := config["secret"].(string)
	if strings.TrimSpace(secret) == "" {
		return fmt.Errorf("Mihomo secret 未配置，无法执行重载")
	}

	reloadBody := strings.NewReader(
		`{"path": "/data/s5m-next/config.yaml"}`,
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
	const configPath = "/data/s5m-next/config.yaml"
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
		if err != nil { return nil, err }
		if secret != "" { req.Header.Set("Authorization", "Bearer "+secret) }
		resp, err := client.Do(req)
		if err != nil { return nil, err }
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 { return nil, fmt.Errorf("HTTP %d", resp.StatusCode) }
		var result map[string]any
		if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&result); err != nil { return nil, err }
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
	if err != nil { return err }
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(cfg.CentralURL, "/")+"/api/v1/agent/heartbeat", strings.NewReader(string(body)))
	if err != nil { return err }
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil { return err }
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("主控端心跳返回 HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	return nil
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
			http.ServeFile(w, r, "/opt/s5m-next/s5m-agent/index.html")
		})

		// ====== 提供前端页面的 API ======
		http.HandleFunc("/api/machine-id", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"machine_id":"` + getMachineID() + `"}`))
		})

		http.HandleFunc("/api/config", func(w http.ResponseWriter, r *http.Request) {
			// 读取本地的 agent.json 查看是否已经绑定
			data, _ := os.ReadFile("/data/agent.json")
			var cfg Config
			json.Unmarshal(data, &cfg)

			w.Header().Set("Content-Type", "application/json")
			if cfg.Token != "" {
				w.Write([]byte(`{"has_token":true,"central_url":"` + cfg.CentralURL + `","connected":true}`))
			} else {
				w.Write([]byte(`{"has_token":false,"central_url":"","connected":false}`))
			}
		})

		http.HandleFunc("/api/bind", func(w http.ResponseWriter, r *http.Request) {
			// 保存绑定信息
			var in struct {
				CentralURL string `json:"central_url"`
				Secret     string `json:"secret"`
			}
			if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
				http.Error(w, "参数错误", 400)
				return
			}

			// 这里假设 Agent 注册逻辑，需要调用主控台 /api/v1/agent/register 换取 JWT
			// 但为了简单，我们直接保存 token (由于之前的代码里是加密的，这里为了跑通，直接存明文/或者模拟)
			// 实际上这里需要发送 HTTP 请求去主控台注册并拿到返回的 JWT，然后再加密保存
			reqBody := strings.NewReader(`{"machine_code":"` + getMachineID() + `","secret":"` + in.Secret + `"}`)
			resp, err := http.Post(in.CentralURL+"/api/v1/agent/register", "application/json", reqBody)
			if err != nil || resp.StatusCode != 200 {
				http.Error(w, "主控台验证失败，请检查密钥", 400)
				return
			}
			defer resp.Body.Close()
			var res struct {
				Token string `json:"token"`
			}
			json.NewDecoder(resp.Body).Decode(&res)

			// 将获取到的 JWT 保存到本地
			newCfg := Config{CentralURL: in.CentralURL, Token: res.Token}
			b, _ := json.Marshal(newCfg)
			os.WriteFile("/data/agent.json", b, 0644)

			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"message":"绑定成功"}`))
		})

		fmt.Println("Agent Web 服务已启动: :81")
		if err := http.ListenAndServe(":81", nil); err != nil {
			fmt.Println("Agent Web 服务启动失败:", err)
		}
	}()

	// 确保 data 目录存在
	os.MkdirAll("/data", 0755)

	// 主循环：每 30 秒心跳并检查配置
	for {
		time.Sleep(30 * time.Second)
		data, _ := os.ReadFile("/data/agent.json")
		if len(data) == 0 {
			continue
		}
		var cfg Config
		json.Unmarshal(data, &cfg)
		if cfg.Token == "" {
			continue
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
		client := &http.Client{Timeout: 15 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			fmt.Printf("❌ Agent 心跳请求失败: %v\\n", err)
			continue
		}

		if resp.StatusCode != 200 {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			fmt.Printf("❌ Agent 心跳异常: HTTP %d，主控端响应: %s\\n", resp.StatusCode, strings.TrimSpace(string(body)))
			// 授权异常时保留本地注册信息，避免意外解绑。
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

		fmt.Println("发现配置更新，已写入主配置 /data/s5m-next/config.yaml")

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
		_ = os.Remove("/data/s5m-next/config.yaml.previous")
		fmt.Println("完整 Mihomo 配置应用成功")
	}
}
