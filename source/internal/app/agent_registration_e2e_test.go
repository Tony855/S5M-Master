package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAgentRegisterTokenAuthenticatesAndIsRevokedAfterRotation(t *testing.T) {
	app, code, _ := websocketTestApp(t)
	const dedicatedSecret = "ws-dedicated-secret"

	req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/register",
		strings.NewReader(`{"machine_code":"ws_node_01","secret":"ws-dedicated-secret"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	app.handleAgentRegister(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("registration status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var response struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode registration response: %v", err)
	}
	if strings.TrimSpace(response.Token) == "" {
		t.Fatal("registration succeeded without returning an Agent token")
	}

	authReq := httptest.NewRequest(http.MethodGet, "/api/v1/agent/config", nil)
	authReq.Header.Set("Authorization", "Bearer "+response.Token)
	gotCode, err := app.agentMachineFromRequest(authReq)
	if err != nil || gotCode != code {
		t.Fatalf("registered token authorization = %q, %v; want %q, nil", gotCode, err, code)
	}

	if err := app.store.UpdateSettings(map[string]string{
		"agent_machine_" + code: dedicatedSecret + "-rotated",
	}); err != nil {
		t.Fatalf("rotate dedicated token: %v", err)
	}
	if _, err := app.agentMachineFromRequest(authReq); err == nil {
		t.Fatal("registration token remained valid after dedicated credential rotation")
	}
}

func TestCompositeAgentRegistrationBindsTypeAndInstanceAndRevokesIndependently(t *testing.T) {
	app, machineCode, _ := websocketTestApp(t)
	mihomoSecret := "mihomo-instance-registration-secret-123456"
	wireguardSecret := "wireguard-instance-registration-secret-123456"
	if err := app.store.ProvisionAgentInstance(machineCode, "mihomo", "default", mihomoSecret); err != nil {
		t.Fatalf("provision Mihomo: %v", err)
	}
	if err := app.store.ProvisionAgentInstance(machineCode, "wireguard", "routeros-1", wireguardSecret); err != nil {
		t.Fatalf("provision WireGuard: %v", err)
	}
	register := func(agentType, instanceID, secret string) string {
		t.Helper()
		body, _ := json.Marshal(map[string]string{
			"machine_code": machineCode, "agent_type": agentType,
			"instance_id": instanceID, "secret": secret,
		})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/register", strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		app.handleAgentRegister(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("register %s/%s status=%d body=%s", agentType, instanceID, rec.Code, rec.Body.String())
		}
		var response struct {
			Token string `json:"token"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil || response.Token == "" {
			t.Fatalf("decode %s/%s token: token=%q err=%v", agentType, instanceID, response.Token, err)
		}
		return response.Token
	}
	mihomoToken := register("mihomo", "default", mihomoSecret)
	wireguardToken := register("wireguard", "routeros-1", wireguardSecret)
	authenticate := func(token string) agentRequestIdentity {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/agent/ws", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		identity, err := app.agentIdentityFromRequest(req)
		if err != nil {
			t.Fatalf("authenticate composite token: %v", err)
		}
		return identity
	}
	if got := authenticate(mihomoToken); got != (agentRequestIdentity{MachineCode: machineCode, AgentType: "mihomo", InstanceID: "default"}) {
		t.Fatalf("Mihomo identity = %#v", got)
	}
	if got := authenticate(wireguardToken); got != (agentRequestIdentity{MachineCode: machineCode, AgentType: "wireguard", InstanceID: "routeros-1"}) {
		t.Fatalf("WireGuard identity = %#v", got)
	}
	if err := app.store.ProvisionAgentInstance(machineCode, "wireguard", "routeros-1", "wireguard-rotated-registration-secret-123456"); err != nil {
		t.Fatalf("rotate WireGuard credential: %v", err)
	}
	if _, err := app.agentIdentityFromRequest(httptest.NewRequest(http.MethodGet, "/ws", nil)); err == nil {
		t.Fatal("missing Authorization unexpectedly authenticated")
	}
	mihomoReq := httptest.NewRequest(http.MethodGet, "/ws", nil)
	mihomoReq.Header.Set("Authorization", "Bearer "+mihomoToken)
	if got, err := app.agentIdentityFromRequest(mihomoReq); err != nil || got.AgentType != "mihomo" {
		t.Fatalf("rotating WireGuard credential revoked Mihomo: identity=%#v err=%v", got, err)
	}
	wireguardReq := httptest.NewRequest(http.MethodGet, "/ws", nil)
	wireguardReq.Header.Set("Authorization", "Bearer "+wireguardToken)
	if _, err := app.agentIdentityFromRequest(wireguardReq); err == nil {
		t.Fatal("rotated WireGuard credential did not revoke its prior JWT")
	}
}
