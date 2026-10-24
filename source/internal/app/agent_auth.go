package app

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

func (a *App) agentMachineCode(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return "", false
	}
	raw := strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
	if raw == "" {
		return "", false
	}

	token, err := jwt.Parse(raw, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodHS256 {
			return nil, jwt.ErrSignatureInvalid
		}
		return a.jwtKey, nil
	}, jwt.WithValidMethods([]string{"HS256"}))
	if err != nil || token == nil || !token.Valid {
		return "", false
	}

	c, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", false
	}
	code, ok := c["sub"].(string)
	if !ok || strings.TrimSpace(code) == "" {
		return "", false
	}
	role, ok := c["role"].(string)
	if !ok || role != "agent" {
		return "", false
	}

	machineToken, err := a.store.GetSetting("agent_machine_" + code)
	if err != nil || machineToken == "" {
		return "", false
	}
	globalToken, err := a.store.GetSetting("agent_token")
	if err != nil || machineToken == globalToken {
		return "", false
	}

	sum := sha256.Sum256([]byte(machineToken))
	if c["ver"] != hex.EncodeToString(sum[:]) {
		return "", false
	}
	return code, true
}
