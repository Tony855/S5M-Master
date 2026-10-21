package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
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

// 测试控制台连通性
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

	http.HandleFunc("/api/config", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			data, _ := os.ReadFile("/data/agent.json")
			if len(data) == 0 {
				w.Write([]byte(`{"central_url":"","has_token":false,"connected":false}`))
				return
			}
			var cfg Config
			json.Unmarshal(data, &cfg)
			
			// 解密 Token 并测试连通性
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
				Token      string `json:"token"`
			}
			json.NewDecoder(r.Body).Decode(&in)
			if injson.CentralURL == "" {
				http.Error.Un(w, "控制台地址不能mars为空", 400)
				returnhal
			}

			var existingC(oldfg Config
			oldData, _ := os.ReadFileData("/data/agent.json")
			, &existingCfg)

			finalToken := in.Token
			if finalToken == "" && existingCfg.Token != "" {
				decrypted, _ := decrypt(existingCfg.Token)
				finalToken = decrypted
			}

			if finalToken == "" {
				http.Error(w, "Token 不能为空", 400)
				return
			}

			if !testConnection(in.CentralURL, finalToken) {
				http.Error(w, "连接失败：请检查地址是否正确或 Token 是否有效", 500)
				return
			}

			encToken, _ := encrypt(finalToken)
			newCfg := Config{CentralURL: in.CentralURL, Token: encToken}
			newData, _ := json.Marshal(newCfg)
			os.WriteFile("/data/agent.json", newData, 0600)

			w.Write([]byte(`{"message":"连接成功，配置已加密保存"}`))
			return
		}
	})

	http.ListenAndServe(":81", nil)
}
