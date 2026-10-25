package app

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

func TestEnsureAdminRequiresExplicitPassword(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "admin-init.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	a := &App{cfg: Config{AdminUser: "admin"}, store: store}
	if err := a.ensureAdmin(); err == nil {
		t.Fatal("expected first startup without an administrator password to fail")
	}
	count, err := store.CountUsers()
	if err != nil {
		t.Fatalf("CountUsers: %v", err)
	}
	if count != 0 {
		t.Fatalf("unexpected administrator account created without a password: %d", count)
	}

	a.cfg.AdminPass = "test-only-strong-password"
	if err := a.ensureAdmin(); err != nil {
		t.Fatalf("ensureAdmin with configured password: %v", err)
	}
	count, err = store.CountUsers()
	if err != nil {
		t.Fatalf("CountUsers after initialization: %v", err)
	}
	if count != 1 {
		t.Fatalf("administrator count = %d, want 1", count)
	}
}

func TestHealthChecksDatabaseReadiness(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "health.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	a := &App{store: store}
	response := httptest.NewRecorder()
	a.handleHealth(response, httptest.NewRequest("GET", "/api/v1/health", nil))
	if response.Code != 200 {
		t.Fatalf("healthy database returned HTTP %d", response.Code)
	}
	if err := store.db.Close(); err != nil {
		t.Fatalf("close database: %v", err)
	}
	response = httptest.NewRecorder()
	a.handleHealth(response, httptest.NewRequest("GET", "/api/v1/health", nil))
	if response.Code != 503 {
		t.Fatalf("closed database returned HTTP %d, want 503", response.Code)
	}
}

func TestRetryNodeConfigSyncReturnsSuccessWhenNoAuthorizedNodes(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "config-sync.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	a := &App{store: store}
	response := httptest.NewRecorder()
	a.handleRetryNodeConfigSync(response, httptest.NewRequest("POST", "/api/v1/nodes/config-sync", nil))
	if response.Code != 200 {
		t.Fatalf("sync with no authorized nodes returned HTTP %d: %s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `"ok":true`) {
		t.Fatalf("expected success response, got %s", response.Body.String())
	}
}

func TestBackupEndpointRequiresBearerAuthentication(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "backup-auth.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	a := &App{cfg: Config{DBPath: filepath.Join(t.TempDir(), "backup-auth.db")}, store: store, jwtKey: []byte("test-signing-key")}
	handler := a.Router(fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("test")}})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/v1/backup", nil))
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated backup request returned HTTP %d, want %d", response.Code, http.StatusUnauthorized)
	}
}

func TestManagementEndpointsRequireAdminRole(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "role-auth.db")
	store, err := OpenStore(dbPath)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	if err := store.CreateUser("operator", "test-hash", "operator"); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	operator, err := store.UserByUsername("operator")
	if err != nil {
		t.Fatalf("UserByUsername: %v", err)
	}
	a := &App{cfg: Config{DBPath: dbPath}, store: store, jwtKey: []byte("test-signing-key")}
	token, err := a.signToken(operator)
	if err != nil {
		t.Fatalf("signToken: %v", err)
	}

	handler := a.Router(fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("test")}})
	request := httptest.NewRequest(http.MethodGet, "/api/v1/agents", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("operator management request returned HTTP %d, want %d; body=%s", response.Code, http.StatusForbidden, response.Body.String())
	}
}

func TestOperatorCannotAccessAdministrativeRouteMatrix(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "role-matrix.db")
	store, err := OpenStore(dbPath)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	if err := store.CreateUser("operator", "test-hash", "operator"); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	operator, err := store.UserByUsername("operator")
	if err != nil {
		t.Fatalf("UserByUsername: %v", err)
	}
	a := &App{cfg: Config{DBPath: dbPath}, store: store, jwtKey: []byte("test-signing-key")}
	token, err := a.signToken(operator)
	if err != nil {
		t.Fatalf("signToken: %v", err)
	}
	handler := a.Router(fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("test")}})

	cases := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/agents"},
		{http.MethodPut, "/api/v1/settings"},
		{http.MethodPost, "/api/v1/config/publish"},
		{http.MethodPost, "/api/v1/config/rollback"},
		{http.MethodGet, "/api/v1/logs"},
		{http.MethodPost, "/api/v1/restore"},
		{http.MethodPost, "/api/v1/container/tasks"},
		{http.MethodDelete, "/api/v1/agents"},
		{http.MethodPost, "/api/v1/mihomo/update"},
	}

	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader("{}"))
			req.Header.Set("Authorization", "Bearer "+token)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, req)
			if response.Code != http.StatusForbidden {
				t.Fatalf("operator request returned HTTP %d, want %d; body=%s", response.Code, http.StatusForbidden, response.Body.String())
			}
		})
	}
}
