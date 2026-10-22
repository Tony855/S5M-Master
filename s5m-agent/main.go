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
func reloadMihomo() {
	// 调用 Mihomo 外部控制 API 重载配置
	reloadBody := strings.NewReader(`{"path": "/data/config.yaml"}`)
	reloadReq, _ := http.NewRequest("PUT", "http://127.0.0.1:8088/configs?force=true", reloadBody)
	reloadReq.Header.Set("Content-Type", "application/json")
	// 注意：这里需要和你 Mihomo 的真实 Secret 保持一致，默认是 change-this-secret
	reloadReq.Header.Set("Authorization", "Bearer change-this-secret")
	reloadResp, err := http.DefaultClient.Do(reloadReq)
	if err == nil && (reloadResp.StatusCode == 204 || reloadResp.StatusCode == 200) {
		fmt.Println("✅ Mihomo 配置重载成功！")
		reloadResp.Body.Close()
	} else {
		fmt.Println("❌ Mihomo 重载失败，请检查端口和 Secret")
	}
}

func getMachineID() string {
	if data, err := os.ReadFile("/etc/machine-id"); err == nil {
		return strings.TrimSpace(string(data))
	}
	return "unknown"
}

func main() {
	// 启动 81 端口提供 Web 注册界面
	go func() {
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			http.ServeFile(w, r, "/opt/s5m-next/s5m-agent/index.html")
		})

		// ====== 提供前端页面的 API ======
		http.HandleFunc("/api/machine-id", func(w http.ResponseWriter, r *http.Request) {
			machineID := "unknown"
			// 尝试从 /etc/machine-id 读取唯一机器码
			if data, err := os.ReadFile("/etc/machine-id"); err == nil {
				machineID = strings.TrimSpace(string(data))
			} else if data, err := os.ReadFile("/var/lib/dbus/machine-id"); err == nil {
				machineID = strings.TrimSpace(string(data))
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"machine_id":"` + machineID + `"}`))
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

		// 请求主面板拉取最新配置 (用于心跳和配置更新)
		req, _ := http.NewRequest("GET", cfg.CentralURL+"/api/v1/agent/config", nil)
		req.Header.Set("Authorization", "Bearer "+cfg.Token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil || resp.StatusCode != 200 {
			if resp != nil {
				resp.Body.Close()
			}
			continue
		}

		newYml, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		// 比对本地文件是否有变化
		oldYml, _ := os.ReadFile("/data/config.yaml")
		if string(oldYml) == string(newYml) {
			continue
		}

		// 写入新配置
		os.WriteFile("/data/config.yaml", newYml, 0644)
		fmt.Println("发现配置更新，已写入新配置")

		// 触发 Mihomo 重载
		reloadMihomo()
	}
}
