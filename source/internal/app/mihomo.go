package app

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

func (a *App) mihomoReq(method, path string, body io.Reader) (*http.Response, error) {
	url := strings.TrimRight(a.cfg.MihomoAPI, "/") + path
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if a.cfg.MihomoSecret != "" {
		req.Header.Set("Authorization", "Bearer "+a.cfg.MihomoSecret)
	}
	return (&http.Client{Timeout: 10 * time.Second}).Do(req)
}

func (a *App) ReloadMihomo() error {
	b := fmt.Sprintf(`{"path":%q}`, a.cfg.MihomoConfigPath)
	resp, err := a.mihomoReq(http.MethodPut, "/configs?force=true", strings.NewReader(b))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(raw))
	}
	return nil
}

func (a *App) MihomoInfo() map[string]any {
	out := map[string]any{"online": false}
	resp, err := a.mihomoReq(http.MethodGet, "/version", nil)
	if err != nil {
		out["error"] = err.Error()
		return out
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		out["error"] = fmt.Sprintf("HTTP %d", resp.StatusCode)
		return out
	}
	var v map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&v); err == nil {
		out["online"] = true
		out["version"] = v
	}
	return out
}

// waitForMihomoAPIVersion confirms the running Mihomo process reports the target
// version through its controller API after a restart or binary replacement.
func (a *App) waitForMihomoAPIVersion(expected string, timeout time.Duration) error {
	expected = strings.TrimPrefix(strings.TrimSpace(expected), "v")
	if expected == "" {
		return fmt.Errorf("目标 Mihomo 版本不能为空")
	}
	deadline := time.Now().Add(timeout)
	var lastErr error
	for {
		resp, err := a.mihomoReq(http.MethodGet, "/version", nil)
		if err != nil {
			lastErr = err
		} else {
			var payload map[string]any
			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				lastErr = fmt.Errorf("Mihomo /version 返回 HTTP %d", resp.StatusCode)
				_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 16<<10))
			} else if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<10)).Decode(&payload); err != nil {
				lastErr = fmt.Errorf("解析 Mihomo /version 响应失败: %w", err)
			} else {
				actual, _ := payload["version"].(string)
				actual = strings.TrimPrefix(strings.TrimSpace(actual), "v")
				if actual == expected {
					_ = resp.Body.Close()
					return nil
				}
				lastErr = fmt.Errorf("运行版本不匹配，期望 v%s，实际 %q", expected, actual)
			}
			_ = resp.Body.Close()
		}
		if !time.Now().Before(deadline) {
			if lastErr == nil {
				lastErr = fmt.Errorf("未收到 Mihomo 版本响应")
			}
			return fmt.Errorf("等待 Mihomo 运行版本确认超时: %w", lastErr)
		}
		pause := 500 * time.Millisecond
		if remaining := time.Until(deadline); remaining < pause {
			pause = remaining
		}
		time.Sleep(pause)
	}
}
