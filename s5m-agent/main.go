package main

import (
	"crypto/aes"
	"crypto/cipher"
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

// mergeConfig 把 agent 拉到的 proxies/rules 片段合并进主配置，保留 tun/dns 等系统级设置
func mergeConfig(agentYml []byte) (bool, error) {
	const mainPath = "/data/s5m-next/config.yaml"
	mainData, err := os.ReadFile(mainPath)
	if err != nil {
		return false, err
	}

	var mainCfg map[string]interface{}
	var agentCfg map[string]interface{}
	if err := yaml.Unmarshal(mainData, &mainCfg); err != nil {
		return false, fmt.Errorf("主配置 YAML 无效: %w", err)
	}
	if err := yaml.Unmarshal(agentYml, &agentCfg); err != nil {
		return false, fmt.Errorf("Agent 配置 YAML 无效: %w", err)
	}

	for _, key := range []string{"proxies", "rules"} {
		if value, ok := agentCfg[key]; ok {
			mainCfg[key] = value
		}
	}

	merged, err := yaml.Marshal(mainCfg)
	if err != nil {
		return false, err
	}

	// 比较结构是否发生变化
	var oldNormalized map[string]interface{}
	if err := yaml.Unmarshal(mainData, &oldNormalized); err != nil {
		return false, err
	}
	oldBytes, err := yaml.Marshal(oldNormalized)
	if err != nil {
		return false, err
	}
	if string(oldBytes) == string(merged) {
		return false, nil // 没有变化
	}

	tmpPath := mainPath + ".tmp"
	if err := os.WriteFile(tmpPath, merged, 0600); err != nil {
		return false, err
	}
	if err := os.Rename(tmpPath, mainPath); err != nil {
		_ = os.Remove(tmpPath)
		return false, err
	}
	return true, nil // 发生了变化
}

func reloadMihomo() error {
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
	reloadReq.Header.Set("Authorization", "Bearer change-this-secret")

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
		if len(strings.TrimSpace(string(newYml))) == 0 {
			fmt.Println("主控台返回空配置，本次跳过")
			continue
		}

		// 合并到主配置（保留 tun/dns 等系统配置）
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
			fmt.Printf("Mihomo 配置重载失败: %v\\n", err)
			continue
		}
		fmt.Println("Mihomo 配置重载成功")
	}
}
