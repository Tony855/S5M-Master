package app

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"testing/fstest"
)

func TestContainerTaskEndpointsAreDisabled(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "container-api-disabled.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	a := &App{cfg: Config{DBPath: filepath.Join(t.TempDir(), "config.db")}, store: store, jwtKey: []byte("test-signing-key")}
	handler := a.Router(fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("test")}})

	cases := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/api/v1/container/tasks"},
		{http.MethodGet, "/api/v1/container/tasks"},
		{http.MethodDelete, "/api/v1/container/tasks/1"},
		{http.MethodGet, "/api/v1/agent/container/tasks/next"},
		{http.MethodPost, "/api/v1/agent/container/tasks/1/heartbeat"},
		{http.MethodPost, "/api/v1/agent/container/tasks/1/result"},
	}
	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, req)
			if response.Code != http.StatusNotFound {
				t.Fatalf("disabled endpoint returned HTTP %d, want %d", response.Code, http.StatusNotFound)
			}
		})
	}
}
