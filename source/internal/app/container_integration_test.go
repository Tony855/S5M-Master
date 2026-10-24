package app

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"
	"testing/fstest"

	"github.com/golang-jwt/jwt/v5"
)

func TestContainerTaskEndToEndAndAuthorization(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "container-e2e.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	const machineCode = "node-e2e-01"
	const machineSecret = "dedicated-agent-secret-for-tests"
	if err := store.UpdateSettings(map[string]string{
		"agent_token":                  "global-registration-secret",
		"agent_machine_" + machineCode: machineSecret,
	}); err != nil {
		t.Fatalf("UpdateSettings: %v", err)
	}
	if err := store.CreateUser("admin", "test-hash-not-used-by-auth-middleware", "admin"); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	a := &App{store: store, jwtKey: []byte("integration-test-jwt-key-at-least-32-bytes"), cfg: Config{DBPath: filepath.Join(t.TempDir(), "container-e2e.db")}}
	admin, err := store.UserByUsername("admin")
	if err != nil || admin == nil {
		t.Fatalf("UserByUsername: user=%v err=%v", admin, err)
	}
	adminToken, err := a.signToken(admin)
	if err != nil {
		t.Fatalf("sign admin token: %v", err)
	}
	router := a.Router(fstest.MapFS{})

	call := func(method, path, token, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		res := httptest.NewRecorder()
		router.ServeHTTP(res, req)
		return res
	}

	// Registration must issue a machine-bound JWT only for the preassigned per-node secret.
	registerBody, _ := json.Marshal(map[string]string{"machine_code": machineCode, "secret": machineSecret})
	register := call(http.MethodPost, "/api/v1/agent/register", "", string(registerBody))
	if register.Code != http.StatusOK {
		t.Fatalf("register: HTTP %d body=%s", register.Code, register.Body.String())
	}
	var registered struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(register.Body.Bytes(), &registered); err != nil || registered.Token == "" {
		t.Fatalf("decode registration token: token-empty=%v err=%v", registered.Token == "", err)
	}

	// The same token must not be accepted for a different machine or after its binding is revoked.
	var claims jwt.MapClaims
	parsed, err := jwt.Parse(registered.Token, func(token *jwt.Token) (any, error) { return a.jwtKey, nil }, jwt.WithValidMethods([]string{"HS256"}))
	if err != nil || parsed == nil || !parsed.Valid {
		t.Fatalf("registered token is invalid: %v", err)
	}
	claims, _ = parsed.Claims.(jwt.MapClaims)
	if claims["sub"] != machineCode || claims["role"] != "agent" {
		t.Fatalf("unexpected Agent token claims: %#v", claims)
	}

	// Agent status registration path must authenticate and persist its latest report.
	statusBody := `{"hostname":"e2e-host","os":"linux","arch":"amd64","docker_available":true,"mihomo_running":true,"mihomo_version":"test","status_json":{"containers":2}}`
	status := call(http.MethodPost, "/api/v1/agent/container/status", registered.Token, statusBody)
	if status.Code != http.StatusOK {
		t.Fatalf("report status: HTTP %d body=%s", status.Code, status.Body.String())
	}

	// The admin node inventory must expose the latest heartbeat and runtime capabilities.
	nodesRes := call(http.MethodGet, "/api/v1/container/nodes", adminToken, "")
	if nodesRes.Code != http.StatusOK {
		t.Fatalf("list container nodes: HTTP %d body=%s", nodesRes.Code, nodesRes.Body.String())
	}
	var nodesPayload struct {
		Nodes []struct {
			MachineCode     string `json:"machine_code"`
			Hostname        string `json:"hostname"`
			OS              string `json:"os"`
			Arch            string `json:"arch"`
			DockerAvailable bool   `json:"docker_available"`
			MihomoRunning   bool   `json:"mihomo_running"`
			MihomoVersion   string `json:"mihomo_version"`
			Online          bool   `json:"online"`
			UpdatedAt       string `json:"updated_at"`
		} `json:"nodes"`
	}
	if err := json.Unmarshal(nodesRes.Body.Bytes(), &nodesPayload); err != nil {
		t.Fatalf("decode node inventory: %v body=%s", err, nodesRes.Body.String())
	}
	if len(nodesPayload.Nodes) != 1 {
		t.Fatalf("node inventory returned %d nodes, want 1: %s", len(nodesPayload.Nodes), nodesRes.Body.String())
	}
	node := nodesPayload.Nodes[0]
	if node.MachineCode != machineCode || node.Hostname != "e2e-host" || node.OS != "linux" || node.Arch != "amd64" {
		t.Fatalf("node identity/runtime metadata mismatch: %+v", node)
	}
	if !node.DockerAvailable || !node.MihomoRunning || node.MihomoVersion != "test" {
		t.Fatalf("node capabilities mismatch: %+v", node)
	}
	if !node.Online || node.UpdatedAt == "" {
		t.Fatalf("fresh heartbeat should be online and have updated_at: %+v", node)
	}

	// An ordinary authenticated admin creates a task; a non-admin is forbidden.
	createBody := `{"machine_code":"` + machineCode + `","action":"docker.list","params":{}}`
	created := call(http.MethodPost, "/api/v1/container/tasks", adminToken, createBody)
	if created.Code != http.StatusCreated {
		t.Fatalf("create task: HTTP %d body=%s", created.Code, created.Body.String())
	}
	var task struct {
		ID     int64  `json:"id"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &task); err != nil || task.ID <= 0 || task.Status != "pending" {
		t.Fatalf("decode created task: task=%+v err=%v", task, err)
	}

	// A non-admin can log in but cannot create management tasks.
	if err := store.CreateUser("viewer", "test-hash-not-used-by-auth-middleware", "viewer"); err != nil {
		t.Fatalf("CreateUser viewer: %v", err)
	}
	viewer, err := store.UserByUsername("viewer")
	if err != nil || viewer == nil {
		t.Fatalf("UserByUsername viewer: %v", err)
	}
	viewerToken, err := a.signToken(viewer)
	if err != nil {
		t.Fatalf("sign viewer token: %v", err)
	}
	forbidden := call(http.MethodPost, "/api/v1/container/tasks", viewerToken, createBody)
	if forbidden.Code != http.StatusForbidden {
		t.Fatalf("viewer task creation HTTP %d, want 403 body=%s", forbidden.Code, forbidden.Body.String())
	}

	// Agent claims exactly one task and returns a result; replay is rejected.
	claimed := call(http.MethodGet, "/api/v1/agent/container/tasks/next", registered.Token, "")
	if claimed.Code != http.StatusOK {
		t.Fatalf("claim task: HTTP %d body=%s", claimed.Code, claimed.Body.String())
	}
	var claimedTask struct {
		ID     int64  `json:"id"`
		Action string `json:"action"`
	}
	if err := json.Unmarshal(claimed.Body.Bytes(), &claimedTask); err != nil || claimedTask.ID != task.ID || claimedTask.Action != "docker.list" {
		t.Fatalf("unexpected claimed task: %+v err=%v", claimedTask, err)
	}
	resultBody := `{"status":"succeeded","result":{"containers":[]}}`
	result := call(http.MethodPost, "/api/v1/agent/container/tasks/"+jsonNumber(task.ID)+"/result", registered.Token, resultBody)
	if result.Code != http.StatusOK {
		t.Fatalf("submit task result: HTTP %d body=%s", result.Code, result.Body.String())
	}
	replay := call(http.MethodPost, "/api/v1/agent/container/tasks/"+jsonNumber(task.ID)+"/result", registered.Token, resultBody)
	if replay.Code != http.StatusConflict {
		t.Fatalf("replay result HTTP %d, want 409 body=%s", replay.Code, replay.Body.String())
	}

	listed := call(http.MethodGet, "/api/v1/container/tasks", adminToken, "")
	if listed.Code != http.StatusOK || !bytes.Contains(listed.Body.Bytes(), []byte(`"status":"succeeded"`)) {
		t.Fatalf("list completed tasks: HTTP %d body=%s", listed.Code, listed.Body.String())
	}

	if err := store.DeleteAgentBinding(machineCode); err != nil {
		t.Fatalf("DeleteAgentBinding: %v", err)
	}
	revoked := call(http.MethodGet, "/api/v1/agent/container/tasks/next", registered.Token, "")
	if revoked.Code != http.StatusUnauthorized {
		t.Fatalf("revoked Agent token HTTP %d, want 401 body=%s", revoked.Code, revoked.Body.String())
	}
}

func jsonNumber(n int64) string {
	return strconv.FormatInt(n, 10)
}
