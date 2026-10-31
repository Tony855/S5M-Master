package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func startSmartDNSProbeUDPServer(t *testing.T, rcode uint16, answers uint16) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		buf := make([]byte, 2048)
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		response := smartDNSProbeTestResponse(buf[:n], rcode, answers)
		_, _ = conn.WriteTo(response, addr)
	}()
	return conn.LocalAddr().String()
}

func startSmartDNSProbeTCPServer(t *testing.T, rcode uint16, answers uint16) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var header [2]byte
		if _, err := io.ReadFull(conn, header[:]); err != nil {
			return
		}
		length := int(binary.BigEndian.Uint16(header[:]))
		query := make([]byte, length)
		if _, err := io.ReadFull(conn, query); err != nil {
			return
		}
		response := smartDNSProbeTestResponse(query, rcode, answers)
		binary.BigEndian.PutUint16(header[:], uint16(len(response)))
		_, _ = conn.Write(header[:])
		_, _ = conn.Write(response)
	}()
	return listener.Addr().String()
}

func smartDNSProbeTestResponse(query []byte, rcode, answers uint16) []byte {
	if len(query) < 12 {
		return nil
	}
	response := append([]byte(nil), query...)
	binary.BigEndian.PutUint16(response[2:4], 0x8180|rcode)
	binary.BigEndian.PutUint16(response[6:8], answers)
	if answers > 0 {
		response = append(response, 0xc0, 0x0c, 0, 1, 0, 1)
		response = append(response, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4)
	}
	return response
}

func TestSmartDNSDNSProbeRequiresValidUDPAndTCPAnswers(t *testing.T) {
	udpAddress := startSmartDNSProbeUDPServer(t, 0, 1)
	tcpAddress := startSmartDNSProbeTCPServer(t, 0, 1)
	if !probeSmartDNSDNSNetworkAt("udp", udpAddress) {
		t.Fatal("valid UDP DNS answer should pass the probe")
	}
	if !probeSmartDNSDNSNetworkAt("tcp", tcpAddress) {
		t.Fatal("valid TCP DNS answer should pass the probe")
	}
}

func TestSmartDNSDNSProbeRejectsFailureResponses(t *testing.T) {
	tests := []struct {
		name    string
		rcode   uint16
		answers uint16
	}{
		{name: "SERVFAIL", rcode: 2, answers: 1},
		{name: "NXDOMAIN", rcode: 3, answers: 1},
		{name: "empty NOERROR", rcode: 0, answers: 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			address := startSmartDNSProbeUDPServer(t, tc.rcode, tc.answers)
			if probeSmartDNSDNSNetworkAt("udp", address) {
				t.Fatalf("DNS probe unexpectedly accepted %s", tc.name)
			}
		})
	}
}

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
	live := filepath.Join(dir, "existing.conf")
	old := []byte("old-config\n")
	if err := os.WriteFile(live, old, 0600); err != nil {
		t.Fatal(err)
	}

	target := filepath.Join(dir, "blocked.conf")
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
	if entries[0].Name() != "blocked.conf" && entries[0].Name() != "existing.conf" {
		t.Fatalf("unexpected first entry: %s", entries[0].Name())
	}
	if entries[1].Name() != "blocked.conf" && entries[1].Name() != "existing.conf" {
		t.Fatalf("unexpected second entry: %s", entries[1].Name())
	}
	if entries[0].Name() == entries[1].Name() {
		t.Fatalf("unexpected duplicate entries: %#v", entries)
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
	err := restartAndVerifySmartDNSRollbackWithTimeout(live, old, true, func() error {
		return nil
	}, func() bool {
		return false
	}, 20*time.Millisecond, time.Millisecond)
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

func TestRestartAndVerifySmartDNSRollbackRemovesNewFileWhenNoOldConfigExisted(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "smartdns.conf")
	if err := os.WriteFile(live, []byte("failed-new-config\n"), 0600); err != nil {
		t.Fatal(err)
	}
	restarted, probed := false, false
	err := restartAndVerifySmartDNSRollback(live, nil, false, func() error {
		restarted = true
		return nil
	}, func() bool {
		probed = true
		return true
	})
	if err != nil {
		t.Fatalf("rollback without previous config error = %v", err)
	}
	if !restarted || !probed {
		t.Fatalf("expected restart and DNS probe, got restarted=%v probed=%v", restarted, probed)
	}
	if _, err := os.Stat(live); !os.IsNotExist(err) {
		t.Fatalf("new config must be removed when no old config existed; stat error=%v", err)
	}
}

func TestRestartAndVerifySmartDNSRollbackWaitsForDNSReadiness(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "smartdns.conf")
	old := []byte("old-config\n")
	if err := os.WriteFile(live, []byte("new-config\n"), 0600); err != nil {
		t.Fatal(err)
	}
	probes := 0
	err := restartAndVerifySmartDNSRollbackWithTimeout(live, old, true, func() error {
		return nil
	}, func() bool {
		probes++
		return probes >= 3
	}, 100*time.Millisecond, time.Millisecond)
	if err != nil {
		t.Fatalf("rollback should wait for resolver readiness: %v", err)
	}
	if probes < 3 {
		t.Fatalf("expected readiness retries, got %d probe(s)", probes)
	}
}

func TestWaitForSmartDNSDNSRejectsNilProbeAndInvalidTimeout(t *testing.T) {
	if waitForSmartDNSDNS(nil, time.Second, time.Millisecond) {
		t.Fatal("nil DNS probe must not be considered healthy")
	}
	if waitForSmartDNSDNS(func() bool { return true }, 0, time.Millisecond) {
		t.Fatal("zero timeout must not be considered a successful health check")
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

func TestWriteSmartDNSFileAtomicallySetsPrivateModeAndCleansTemporaryFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "smartdns.conf")
	want := []byte("private-config\n")

	if err := writeSmartDNSFileAtomically(path, want, 0600); err != nil {
		t.Fatalf("writeSmartDNSFileAtomically() error = %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("written config = %q, want %q", got, want)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("config permissions = %04o, want 0600", info.Mode().Perm())
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "smartdns.conf" {
		t.Fatalf("temporary files were not cleaned after atomic write: %#v", entries)
	}
}

func TestBackupSmartDNSConfigReplacesStaleBackupWithLatestLiveBytes(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "smartdns.conf")
	backup := live + ".previous"
	old := []byte("old-config\n")
	newConfig := []byte("new-config\n")
	if err := os.WriteFile(live, old, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(backup, []byte("stale-backup\n"), 0600); err != nil {
		t.Fatal(err)
	}

	got, hadOld, err := backupSmartDNSConfig(live, backup)
	if err != nil {
		t.Fatalf("first backup error = %v", err)
	}
	if !hadOld || !bytes.Equal(got, old) {
		t.Fatalf("first backup returned data=%q hadOld=%v", got, hadOld)
	}
	backupBytes, err := os.ReadFile(backup)
	if err != nil || !bytes.Equal(backupBytes, old) {
		t.Fatalf("backup bytes = %q, err=%v; want latest old config %q", backupBytes, err, old)
	}

	if err := os.WriteFile(live, newConfig, 0600); err != nil {
		t.Fatal(err)
	}
	got, hadOld, err = backupSmartDNSConfig(live, backup)
	if err != nil {
		t.Fatalf("second backup error = %v", err)
	}
	if !hadOld || !bytes.Equal(got, newConfig) {
		t.Fatalf("second backup returned data=%q hadOld=%v", got, hadOld)
	}
	backupBytes, err = os.ReadFile(backup)
	if err != nil || !bytes.Equal(backupBytes, newConfig) {
		t.Fatalf("second backup bytes = %q, err=%v; want %q", backupBytes, err, newConfig)
	}
}

func TestBackupSmartDNSConfigConcurrentWritersLeaveCompleteBackup(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "smartdns.conf")
	backup := live + ".previous"
	want := []byte("complete-config-with-no-partial-write\n")
	if err := os.WriteFile(live, want, 0600); err != nil {
		t.Fatal(err)
	}

	const writers = 8
	errs := make(chan error, writers)
	for i := 0; i < writers; i++ {
		go func() {
			_, hadOld, err := backupSmartDNSConfig(live, backup)
			if err == nil && !hadOld {
				err = errors.New("existing live config was not recognized")
			}
			errs <- err
		}()
	}
	for i := 0; i < writers; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("concurrent backup failed: %v", err)
		}
	}

	got, err := os.ReadFile(backup)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("concurrent backup contains partial or unexpected data: %q", got)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("concurrent backup left temporary files: %#v", entries)
	}
}


func TestWithSmartDNSConfigUpdateLockSerializesConcurrentTransactions(t *testing.T) {
	const workers = 12
	var countersMu sync.Mutex
	active := 0
	maxActive := 0
	start := make(chan struct{})
	done := make(chan struct{}, workers)

	for i := 0; i < workers; i++ {
		go func() {
			<-start
			withSmartDNSConfigUpdateLock(func() {
				countersMu.Lock()
				active++
				if active > maxActive {
					maxActive = active
				}
				countersMu.Unlock()

				time.Sleep(2 * time.Millisecond)

				countersMu.Lock()
				active--
				countersMu.Unlock()
			})
			done <- struct{}{}
		}()
	}
	close(start)
	for i := 0; i < workers; i++ {
		<-done
	}
	if maxActive != 1 {
		t.Fatalf("maximum concurrent SmartDNS config transactions = %d, want 1", maxActive)
	}
}
