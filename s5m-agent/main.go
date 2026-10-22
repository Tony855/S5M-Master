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
	"os/exec"
	"path/filepath"
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

const mihomoConfigPath = "/data/s5m-next/config.yaml"
const mihomoBinaryPath = "/opt/mihomo/mihomo"
const mihomoAPIURL = "http://127.0.0.1:8088"

func validateMihomoConfig(path string) error {
	cmd := exec.Command(mihomoBinaryPath, "-t", "-d", "/data/s5m-next", "-f", path)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("Mihomo 配置校验失败: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".s5m-config-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)

	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func mergeConfig(agentYml []byte) (bool, error) {
	mainData, err := os.ReadFile(mihomoConfigPath)
	if err != nil {
		return false, fmt.Errorf("读取主配置失败: %w", err)
	}

	var mainCfg map[string]interface{}
	var agentCfg map[string]interface{}
	if err := yaml.Unmarshal(mainData, &mainCfg); err != nil {
		return false, fmt.Errorf("主配置 YAML 无效: %w", err)
	}
	if err := yaml.Unmarshal(agentYml, &agentCfg); err != nil {
		return false, fmt.Errorf("主控下发的 YAML 无效: %w", err)
	}
	if mainCfg == nil || agentCfg == nil {
		return false, fmt.Errorf("配置必须是 YAML 对象")
	}

	for _, key := range []string{"proxies", "rules"} {
		if value, ok := agentCfg[key]; ok {
			mainCfg[key] = value
		}
	}

	merged, err := yaml.Marshal(mainCfg)
	if err != nil {
		return false, fmt.Errorf("生成合并配置失败: %w", err)
	}

	var oldNorm, newNorm map[string]interface{}
	if err := yaml.Unmarshal(mainData, &oldNorm); err != nil {
		return false, err
	}
	if err := yaml.Unmarshal(merged, &newNorm); err != nil {
		return false, err
	}
	oldBytes, err := yaml.Marshal(oldNorm)
	if err != nil {
		return false, err
	}
	newBytes, err := yaml.Marshal(newNorm)
	if err != nil {
		return false, err
	}
	if string(oldBytes) == string(newBytes) {
		return false, nil
	}

	candidate := mihomoConfigPath + ".candidate"
	if err := atomicWrite(candidate, merged, 0600); err != nil {
		return false, fmt.Errorf("写入候选配置失败: %w", err)
	}
	defer os.Remove(candidate)

	if err := validateMihomoConfig(candidate); err != nil {
		return false, err
	}

	backupPath := fmt.Sprintf("%s.backup-%d", mihomoConfigPath, time.Now().UnixNano())
	if err := atomicWrite(backupPath, mainData, 0600); err != nil {
		return false, fmt.Errorf("创建配置回滚副本失败: %w", err)
	}
	if err := atomicWrite(mihomoConfigPath, merged, 0600); err != nil {
		return false, fmt.Errorf("原子替换配置失败: %w", err)
	}

	if err := reloadMihomo(); err != nil {
		fmt.Printf("配置重载失败，正在回滚：%v\n", err)
		if restoreErr := atomicWrite(mihomoConfigPath, mainData, 0600); restoreErr != nil {
			return false, fmt.Errorf("严重：重载失败且恢复配置失败（备份 %s）：%v；%w",
				backupPath, restoreErr, err)
		}
		if rollbackErr := reloadMihomo(); rollbackErr != nil {
			return false, fmt.Errorf("配置已恢复，但旧配置重载也失败（备份 %s）：%v；原始错误：%w",
				backupPath, rollbackErr, err)
		}
		fmt.Println("配置已恢复旧版本，Mihomo 回滚重载成功")
		return false, fmt.Errorf("新配置重载失败，已回滚")
	}

	fmt.Printf("配置更新成功；恢复副本：%s\n", backupPath)
	return true, nil
}

func reloadMihomo() error {
	data, err := os.ReadFile(mihomoConfigPath)
	if err != nil {
		return fmt.Errorf("读取配置失败: %w", err)
	}

	var cfg map[string]interface{}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("解析配置失败: %w", err)
	}
	secret, _ := cfg["secret"].(string)
	if strings.TrimSpace(secret) == "" {
		return fmt.Errorf("配置中没有有效的 secret")
	}

	body := strings.NewReader(`{"path": "/data/s5m-next/config.yaml"}`)
	req, err := http.NewRequest(http.MethodPut, mihomoAPIURL+"/configs?force=true", body)
	if err != nil {
		return fmt.Errorf("创建重载请求失败: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+secret)

	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("Mihomo API 请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusOK {
		fmt.Println("Mihomo 配置重载成功")
		return nil
	}

	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	return fmt.Errorf("Mihomo API HTTP %d: %s",
		resp.StatusCode, strings.TrimSpace(string(msg)))
}

func getMachineID() string { return "3674c839b56" }

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
		req, _ := http.NewRequest("GET", cfg.CentralURL+"/api/v1/agent/config", nil)
		req.Header.Set("Authorization", "Bearer "+cfg.Token)
		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			fmt.Printf("主控配置请求失败: %v\n", err)
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
			fmt.Printf("主控配置请求返回 HTTP %d\n", resp.StatusCode)
			resp.Body.Close()
			continue
		}

		newYml, readErr := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		resp.Body.Close()
		if readErr != nil {
			fmt.Printf("读取主控配置失败: %v\n", readErr)
			continue
		}

		// 合并到主配置（保留 tun/dns 等系统配置）
		changed, err := mergeConfig(newYml)
		if err != nil {
			fmt.Println("合并配置失败:", err)
			continue
		}
		if !changed {
			continue
		}
		fmt.Println("主控配置同步完成，Mihomo 已成功重载")
	}
}
