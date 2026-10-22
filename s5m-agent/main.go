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

// mergeConfig 把 agent 拉到的 proxies/rules 片段合并进主配置，保留 tun/dns 等系统级设置
func mergeConfig(agentYml []byte) error {
	mainPath := "/data/s5m-next/config.yaml"
	mainData, err := os.ReadFile(mainPath)
	if err != nil {
		return err
	}
	agentStr := string(agentYml)
	mainStr := string(mainData)

	// 从 agent 片段中截出 "proxies:" 到 "rules:" 的块
	pIdx := strings.Index(agentStr, "proxies:")
	rIdx := strings.Index(agentStr, "\nrules:")
	var agentProxies, agentRules string
	if pIdx < 0 {
		return fmt.Errorf("agent 无 proxies 段")
	}
	if rIdx < 0 {
		agentProxies = strings.TrimRight(agentStr[pIdx:], "\n")
	} else {
		agentProxies = strings.TrimRight(agentStr[pIdx:rIdx], "\n")
		agentRules = strings.TrimLeft(agentStr[rIdx+1:], "\n")
	}

	// 在 mainStr 中定位 "proxies:" 和 "rules:"（顶层，行首）
	mainPIdx := -1
	mainRIdx := -1
	lines := strings.Split(mainStr, "\n")
	offset := 0
	for _, ln := range lines {
		if strings.HasPrefix(ln, "proxies:") && mainPIdx < 0 {
			mainPIdx = offset
		}
		if strings.HasPrefix(ln, "rules:") && mainRIdx < 0 {
			mainRIdx = offset
		}
		offset += len(ln) + 1
	}

	if mainPIdx < 0 {
		// 没 proxies 段，追加在 rules 前或文末
		if mainRIdx >= 0 {
			mainStr = mainStr[:mainRIdx] + agentProxies + "\n" + mainStr[mainRIdx:]
		} else {
			mainStr = strings.TrimRight(mainStr, "\n") + "\n" + agentProxies + "\n"
		}
	} else {
		var tail string
		if mainRIdx >= 0 {
			tail = mainStr[mainRIdx:]
		} else {
			tail = ""
		}
		mainStr = mainStr[:mainPIdx] + agentProxies + "\n" + tail
	}

	// 如果 agent 有 rules 段，再替换一次 rules
	if agentRules != "" {
		mainRIdx2 := strings.Index(mainStr, "\nrules:")
		if mainRIdx2 < 0 && strings.HasPrefix(mainStr, "rules:") {
			mainRIdx2 = 0
		} else if mainRIdx2 >= 0 {
			mainRIdx2++
		}
		if mainRIdx2 >= 0 {
			mainStr = mainStr[:mainRIdx2] + agentRules
		}
	}

	return os.WriteFile(mainPath, []byte(mainStr), 0644)
}

func reloadMihomo() {
	// 调用 Mihomo 外部控制 API 重载配置
	reloadBody := strings.NewReader(`{"path": "/data/s5m-next/config.yaml"}`)
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

		fmt.Println("👉 正在向主控台发送心跳...")
		req, _ := http.NewRequest("GET", cfg.CentralURL+"/api/v1/agent/config", nil)
		req.Header.Set("Authorization", "Bearer "+cfg.Token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			continue
		}

		// 如果收到 401，说明被主控台删了，自动解绑
		if resp.StatusCode == 401 {
			body, _ := io.ReadAll(resp.Body)
			fmt.Printf("❌ 被踢下线！主控台返回: %d，原因: %s\n", resp.StatusCode, string(body))
			os.Remove("/data/agent.json")
			resp.Body.Close()
			continue
		}

		if resp.StatusCode != 200 {
			resp.Body.Close()
			continue
		}

		newYml, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		// 合并到主配置（保留 tun/dns 等系统配置）
		if err := mergeConfig(newYml); err != nil {
			fmt.Println("合并配置失败:", err)
			continue
		}
		fmt.Println("发现配置更新，已合并到主配置 /data/s5m-next/config.yaml")

		// 触发 Mihomo 重载
		reloadMihomo()
	}
}
