package app

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func restoreRequest(t *testing.T, data []byte) *http.Request {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", "backup.db")
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	if _, err := part.Write(data); err != nil {
		t.Fatalf("write multipart file: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/restore", &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	return req
}

func TestRestoreBackupRejectsInvalidDatabaseWithoutClosingCurrentStore(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "s5m.db")
	store, err := OpenStore(dbPath)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()
	a := &App{cfg: Config{DBPath: dbPath}, store: store}
	response := httptest.NewRecorder()
	a.handleRestoreBackup(response, restoreRequest(t, []byte("not a sqlite database")))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body=%s", response.Code, http.StatusBadRequest, response.Body.String())
	}
	if _, err := store.CountUsers(); err != nil {
		t.Fatalf("current database became unavailable after rejected restore: %v", err)
	}
}

func TestRestoreBackupValidatesAndSwapsDatabase(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "s5m.db")
	current, err := OpenStore(dbPath)
	if err != nil {
		t.Fatalf("OpenStore current: %v", err)
	}
	defer current.db.Close()
	if err := current.CreateUser("current", "not-used-as-password-hash", "admin"); err != nil {
		t.Fatalf("create current user: %v", err)
	}
	backupPath := filepath.Join(dir, "uploaded.db")
	backup, err := OpenStore(backupPath)
	if err != nil {
		t.Fatalf("OpenStore backup: %v", err)
	}
	if err := backup.CreateUser("restored", "not-used-as-password-hash", "admin"); err != nil {
		t.Fatalf("create restored user: %v", err)
	}
	if err := backup.db.Close(); err != nil {
		t.Fatalf("close backup database: %v", err)
	}
	data, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatalf("read backup database: %v", err)
	}
	a := &App{cfg: Config{DBPath: dbPath}, store: current}
	response := httptest.NewRecorder()
	a.handleRestoreBackup(response, restoreRequest(t, data))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", response.Code, http.StatusOK, response.Body.String())
	}
	restored, err := OpenStore(dbPath)
	if err != nil {
		t.Fatalf("open restored database: %v", err)
	}
	defer restored.db.Close()
	if _, err := restored.UserByUsername("restored"); err != nil {
		t.Fatalf("restored user not found: %v", err)
	}
	if _, err := restored.UserByUsername("current"); err == nil {
		t.Fatal("old database contents unexpectedly remained after restore")
	}
}
