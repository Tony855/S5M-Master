package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"strings"
)

func TestBackupSmartDNSConfigMissingLiveFileIsSupported(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "smartdns.conf")
	backup := live + ".previous"

	data, hadOld, err := backupSmartDNSConfig(live, backup)
	if err != nil {
		t.Fatalf("backupSmartDNSConfig() error = %v", err)
	}
	if hadOld || data != nil {
		t.Fatalf("missing live config returned data=%q hadOld=%v; want nil,false", data, hadOld)
	}
	if _, err := os.Stat(backup); !os.IsNotExist(err) {
		t.Fatalf("backup should not be created without an old config; stat error=%v", err)
	}
}

func TestBackupSmartDNSConfigFailsClosedWhenBackupCannotBeWritten(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "smartdns.conf")
	old := []byte("bind 127.0.0.1:6053\nbind-tcp 127.0.0.1:6053\n")
	if err := os.WriteFile(live, old, 0600); err != nil {
		t.Fatal(err)
	}

	_, hadOld, err := backupSmartDNSConfig(live, filepath.Join(dir, "missing", "backup.conf"))
	if err == nil {
		t.Fatal("backupSmartDNSConfig() must fail when backup creation fails")
	}
	if !hadOld {
		t.Fatal("the existing live config must be recognized before backup failure")
	}
	got, readErr := os.ReadFile(live)
	if readErr != nil {
		t.Fatalf("live config became unreadable: %v", readErr)
	}
	if !bytes.Equal(got, old) {
		t.Fatalf("live config changed after backup failure: %q", got)
	}
}

func TestWriteSmartDNSFileAtomicallyFailurePreservesExistingConfig(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "smartdns.conf")
	old := []byte("old-config\n")
	if err := os.WriteFile(live, old, 0600); err != nil {
		t.Fatal(err)
	}

	target := filepath.Join(dir, "smartdns.conf")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	err := writeSmartDNSFileAtomically(target, []byte("new-config\n"), 0600)
	if err == nil {
		t.Fatal("atomic replacement must fail when rename targets a directory")
	}
	if info, statErr := os.Stat(target); statErr != nil || !info.IsDir() {
		t.Fatalf("failed replacement changed target directory: info=%v err=%v", info, statErr)
	}
	got, readErr := os.ReadFile(live)
	if readErr != nil {
		t.Fatalf("existing live config is unreadable: %v", readErr)
	}
	if !bytes.Equal(got, old) {
		t.Fatalf("existing live config changed after failed atomic replacement: %q", got)
	}
	entries, readErr := os.ReadDir(dir)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 2 {
		t.Fatalf("unexpected leftover files after failed atomic replacement: %#v", entries)
	}
	for _, entry := range entries {
		if entry.Name() != "smartdns.conf" && !strings.HasPrefix(entry.Name(), ".smartdns-restore-") {
			t.Fatalf("unexpected file after failed atomic replacement: %s", entry.Name())
		}
	}
	if len(entries) == 2 {
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), ".smartdns-restore-") {
				t.Fatalf("temporary file leaked after failed atomic replacement: %s", entry.Name())
			}
		}
	}
}

func TestRestartAndVerifySmartDNSRollbackRestoresOldConfigAndRequiresDNS(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "smartdns.conf")
	old := []byte("bind 127.0.0.1:6053\nbind-tcp 127.0.0.1:6053\nserver 1.1.1.1\n")
	if err := os.WriteFile(live, []byte("broken-new-config\n"), 0600); err != nil {
		t.Fatal(err)
	}

	restarted := false
	probed := false
	err := restartAndVerifySmartDNSRollback(live, old, true, func() error {
		restarted = true
		return nil
	}, func() bool {
		probed = true
		return true
	})
	if err != nil {
		t.Fatalf("rollback verification error = %v", err)
	}
	if !restarted || !probed {
		t.Fatalf("rollback did not restart and probe service: restarted=%v probed=%v", restarted, probed)
	}
	got, readErr := os.ReadFile(live)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !bytes.Equal(got, old) {
		t.Fatalf("restored config = %q, want exact old bytes %q", got, old)
	}
}

func TestRestartAndVerifySmartDNSRollbackFailsWhenOldDNSIsNotHealthy(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "smartdns.conf")
	old := []byte("old-config\n")
	if err := os.WriteFile(live, []byte("new-config\n"), 0600); err != nil {
		t.Fatal(err)
	}
	err := restartAndVerifySmartDNSRollback(live, old, true, func() error {
		return nil
	}, func() bool {
		return false
	})
	if err == nil {
		t.Fatal("rollback must fail when restored DNS does not answer")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("UDP/TCP")) {
		t.Fatalf("rollback error does not identify failed DNS verification: %v", err)
	}
	got, readErr := os.ReadFile(live)
	if readErr != nil || !bytes.Equal(got, old) {
		t.Fatalf("old config should remain restored despite DNS probe failure: got=%q err=%v", got, readErr)
	}
}

func TestRestartAndVerifySmartDNSRollbackReportsRestartFailure(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "smartdns.conf")
	old := []byte("old-config\n")
	if err := os.WriteFile(live, []byte("new-config\n"), 0600); err != nil {
		t.Fatal(err)
	}
	wantErr := errors.New("simulated restart failure")
	probed := false
	err := restartAndVerifySmartDNSRollback(live, old, true, func() error {
		return wantErr
	}, func() bool {
		probed = true
		return true
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want restart error %v", err, wantErr)
	}
	if probed {
		t.Fatal("DNS probe must not run when service restart fails")
	}
}
