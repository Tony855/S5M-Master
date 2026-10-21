package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

type Config struct {
	CentralURL string `json:"central_url"`
	Token      string `json:"token"`
}

func getEncryptionKey() []byte {
	hostname, _ := os.Hostname()
	h := sha256.New()
	h.Write([]byte(hostname + "s5m-agent-fixed-salt-v1"))
	return h.Sum(nil)
}

func encrypt(plaintext string) (string, error) {
	key := getEncryptionKey()
	block, err := aes.NewCipher(key)
	if err != nil { return "", err }
	gcm, err := cipher.NewGCM(block)
	if err != nil { return "", err }
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil { return "", err }
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func decrypt(ciphertextBase64 string) (string, error) {
	key := getEncryptionKey()
	data, err := base64.StdEncoding.DecodeString(ciphertextBase64)
	if err != nil { return "", err }
	block, err := aes.NewCipher(key)
	if err != nil { return "", err }
	gcm, err := cipher.NewGCM(block)
	if err != nil { return "", err }
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize { return "", err }
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil { return "", err }
	return string(plaintext), nil
}

func getMachineID() string {
	data, err := os.ReadFile("/etc/machine-id")
	if err == nil {
		return strings.TrimSpace(string(data))
	}
	hostname, _ := os.Hostname()
	h := sha256.New()
	h.Write([]byte("s5m-agent-fallback-" + hostname))
	return base64.URLEncoding.EncodeToString(h.Sum(nil))
}

func testConnection(url, token string) bool {
	client := &http.Client{Timeout: 3 * time.Second}
	req, err := http.NewRequest("GET", url+"/api/v1/auth/me", nil)
	if err != nil { return false }
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil { return false }
	defer resp.Body.Close()
	return resp.StatusCode == 200
}

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "index.html")
	})

	http.HandleFunc("/api/machine-id", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"machine_id": getMachineID(),
		})
	})

	http.HandleFunc("/api/config", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			data, _ := os.ReadFile("/data/agent.json")
			if len(data) == 0 {
				w.Write([]byte(`{"central_url":"","has_token":false,"connected":false}`))
				return
			}
			var cfg Config
			json.Unmarshal(data, &cfg)

			connected := false
			if cfg.Token != "" {
				decToken, err := decrypt(cfg.Token)
				if err == nil {
					connected = testConnection(cfg.CentralURL, decToken)
				}
			}

			resp := map[string]interface{}{
				"central_url": cfg.CentralURL,
				"has_token":   cfg.Token != "",
				"connected":   connected,
			}
			json.NewEncoder(w).Encode(resp)
			return
		}

		if r.Method == "POST" {
			var in struct {
				CentralURL string `json:"central_url"`
			}
			json.NewDecoder(r.Body).Decode(&in)
			if in.CentralURL == "" {
				http.Error(w, "控制台地址不能为空", 400)
				return
			}

			machineID := getMachineID()
			reqBody, _ := json.Marshal(map[string]string{"machine_code": machineID})
			resp, err := http.Post(in.CentralURL+"/api/v1/agent/register", "application/json", bytes.NewBuffer(reqBody))
			if err != nil {
				http.Error(w, "请求控制台失败: "+err.Error(), 500)
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode != 200 {
				bodyBytes, _ := io.ReadAll(resp.Body)
				http.Error(w, fmt.Sprintf("注册失败(HTTP %d): %s", resp.StatusCode, string(bodyBytes)), 500)
				return
			}

			var result struct {
				Token string `json:"token"`
			}
			json.NewDecoder(resp.Body).Decode(&result)

			if !testConnection(in.CentralURL, result.Token) {
				http.Error(w, "注册成功但验证 Token 失败，请检查控制台", 500)
				return
			}

			encToken, _ := encrypt(result.Token)
			newCfg := Config{CentralURL: in.CentralURL, Token: encToken}
			newData, _ := json.Marshal(newCfg)
			os.WriteFile("/data/agent.json", newData, 0600)

			w.Write([]byte(`{"message":"设备已成功绑定"}`))
			return
		}
	})

	http.ListenAndServe(":81", nil)
}
