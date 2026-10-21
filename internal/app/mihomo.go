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
