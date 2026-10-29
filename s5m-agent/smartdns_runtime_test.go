package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateSmartDNSConfig(t *testing.T) {
	defaultConfig := `bind 127.0.0.1:6053
bind-tcp 127.0.0.1:6053
server 223.5.5.5
server 119.29.29.29
cache-size 16384
prefetch-domain yes
serve-expired yes
log-level info
log-console yes
log-syslog no
`
	if err := validateSmartDNSConfig([]byte(defaultConfig)); err != nil {
		t.Fatalf("default config rejected: %v", err)
	}
	for _, config := range []string{
		"",
		"include /etc/passwd\nbind 127.0.0.1:6053\nbind-tcp 127.0.0.1:6053\n",
		"exec /bin/sh\nbind 127.0.0.1:6053\nbind-tcp 127.0.0.1:6053\n",
		"bind 0.0.0.0:6053\nbind-tcp 127.0.0.1:6053\nserver 223.5.5.5\n",
		"bind 127.0.0.1:6053\nserver 223.5.5.5\n",
		strings.Repeat("x", 9<<10),
	} {
		if err := validateSmartDNSConfig([]byte(config)); err == nil {
			t.Errorf("invalid SmartDNS config unexpectedly accepted")
		}
	}
}


func TestRestoreSmartDNSConfigRestoresPreviousFileAtomically(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "smartdns.conf")
	if err := os.WriteFile(path, []byte("new config"), 0600); err != nil {
		t.Fatal(err)
	}
	old := []byte("old config\n")
	if err := restoreSmartDNSConfig(path, old, true); err != nil {
		t.Fatalf("restore previous config: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read restored config: %v", err)
	}
	if string(got) != string(old) {
		t.Fatalf("restored config = %q, want %q", got, old)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("restored file permissions = %o, want 600", info.Mode().Perm())
	}
}

func TestRestoreSmartDNSConfigRemovesNewFileWhenNoPreviousConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "smartdns.conf")
	if err := os.WriteFile(path, []byte("new config"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := restoreSmartDNSConfig(path, nil, false); err != nil {
		t.Fatalf("remove failed new config: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("config should be absent after rollback, stat error = %v", err)
	}
}

func TestWriteSmartDNSFileAtomicallyReplacesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "smartdns.conf")
	if err := os.WriteFile(path, []byte("before"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := writeSmartDNSFileAtomically(path, []byte("after"), 0600); err != nil {
		t.Fatalf("atomic replace: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "after" {
		t.Fatalf("file content = %q, want after", got)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("file permissions = %o, want 600", info.Mode().Perm())
	}
}
