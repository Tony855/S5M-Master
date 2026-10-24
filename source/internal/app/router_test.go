package app

import (
	"path/filepath"
	"testing"
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
