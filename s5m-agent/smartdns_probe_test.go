package main

import (
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestProbeSmartDNSDNSAtRequiresSuccessfulAnswer(t *testing.T) {
	tests := []struct {
		name        string
		flags       uint16
		answerCount uint16
		want        bool
	}{
		{name: "successful A answer", flags: 0x8180, answerCount: 1, want: true},
		{name: "NOERROR without answers", flags: 0x8180, answerCount: 0, want: false},
		{name: "NXDOMAIN", flags: 0x8183, answerCount: 0, want: false},
		{name: "SERVFAIL", flags: 0x8182, answerCount: 0, want: false},
		{name: "REFUSED", flags: 0x8185, answerCount: 0, want: false},
		{name: "not a DNS response", flags: 0x0100, answerCount: 1, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
			if err != nil {
				t.Fatalf("listen UDP: %v", err)
			}
			defer conn.Close()

			done := make(chan error, 1)
			go func() {
				_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
				query := make([]byte, 1500)
				n, client, err := conn.ReadFromUDP(query)
				if err != nil {
					done <- err
					return
				}
				response := append([]byte(nil), query[:n]...)
				binary.BigEndian.PutUint16(response[2:4], tt.flags)
				binary.BigEndian.PutUint16(response[6:8], tt.answerCount)
				if tt.answerCount > 0 {
					// Compressed owner name (pointer to QNAME), A/IN, TTL 60, 1.2.3.4.
					response = append(response, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01,
						0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 1, 2, 3, 4)
				}
				_, err = conn.WriteToUDP(response, client)
				done <- err
			}()

			got := probeSmartDNSDNSAt(conn.LocalAddr().String())
			if got != tt.want {
				t.Errorf("probeSmartDNSDNSAt() = %v, want %v", got, tt.want)
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("DNS test server: %v", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("DNS test server did not finish")
			}
		})
	}
}

func TestProbeSmartDNSDNSTCPAt(t *testing.T) {
	for _, answerCount := range []uint16{0, 1} {
		t.Run(map[bool]string{true: "answer", false: "empty"}[answerCount > 0], func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			done := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					done <- err
					return
				}
				defer conn.Close()
				var size [2]byte
				if _, err = io.ReadFull(conn, size[:]); err != nil {
					done <- err
					return
				}
				query := make([]byte, int(binary.BigEndian.Uint16(size[:])))
				if _, err = io.ReadFull(conn, query); err != nil {
					done <- err
					return
				}
				binary.BigEndian.PutUint16(query[2:4], 0x8180)
				binary.BigEndian.PutUint16(query[6:8], answerCount)
				if answerCount > 0 {
					query = append(query, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 1, 2, 3, 4)
				}
				binary.BigEndian.PutUint16(size[:], uint16(len(query)))
				if _, err = conn.Write(size[:]); err == nil {
					_, err = conn.Write(query)
				}
				done <- err
			}()
			got := probeSmartDNSDNSTCPAt(listener.Addr().String())
			if got != (answerCount > 0) {
				t.Fatalf("probe = %v, want %v", got, answerCount > 0)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRestoreSmartDNSConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "smartdns.conf")
	if err := os.WriteFile(path, []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := restoreSmartDNSConfig(path, []byte("old"), true); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "old" {
		t.Fatalf("restored config = %q, err=%v", got, err)
	}
	if err := restoreSmartDNSConfig(path, nil, false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected removed config, stat err=%v", err)
	}
}

func TestValidateSmartDNSConfigAllowsSafeUpstreamHostname(t *testing.T) {
	config := []byte("bind 127.0.0.1:6053\nbind-tcp 127.0.0.1:6053\nserver include.example\n")
	if err := validateSmartDNSConfig(config); err != nil {
		t.Fatalf("valid upstream hostname rejected: %v", err)
	}
}

func TestWriteSmartDNSFileAtomicallyFailureModes(t *testing.T) {
	t.Run("backup directory unavailable", func(t *testing.T) {
		root := t.TempDir()
		blocker := filepath.Join(root, "not-a-directory")
		if err := os.WriteFile(blocker, []byte("blocker"), 0600); err != nil {
			t.Fatal(err)
		}
		backupPath := filepath.Join(blocker, "smartdns.conf.previous")
		if err := writeSmartDNSFileAtomically(backupPath, []byte("old config"), 0600); err == nil {
			t.Fatal("expected backup write to fail when parent is not a directory")
		}
	})

	t.Run("atomic replacement target is a directory", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "smartdns.conf")
		if err := os.Mkdir(target, 0700); err != nil {
			t.Fatal(err)
		}
		if err := writeSmartDNSFileAtomically(target, []byte("new config"), 0600); err == nil {
			t.Fatal("expected atomic replacement of a directory to fail")
		}
		info, err := os.Stat(target)
		if err != nil {
			t.Fatalf("original target disappeared after failed replacement: %v", err)
		}
		if !info.IsDir() {
			t.Fatal("failed replacement unexpectedly changed the original target")
		}
	})
}

func TestRestoreSmartDNSConfigWhenPreviousConfigDoesNotExist(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "smartdns.conf")
	if err := os.WriteFile(path, []byte("new config"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := restoreSmartDNSConfig(path, nil, false); err != nil {
		t.Fatalf("rollback without previous config: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("new config should be removed on rollback, stat err=%v", err)
	}
}


func TestProbeSmartDNSDNSTCPAtRejectsMismatchedTransactionID(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		var size [2]byte
		if _, err = io.ReadFull(conn, size[:]); err != nil {
			done <- err
			return
		}
		query := make([]byte, int(binary.BigEndian.Uint16(size[:])))
		if _, err = io.ReadFull(conn, query); err != nil {
			done <- err
			return
		}
		binary.BigEndian.PutUint16(query[:2], 0xffff)
		binary.BigEndian.PutUint16(query[2:4], 0x8180)
		binary.BigEndian.PutUint16(query[6:8], 1)
		query = append(query, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 1, 2, 3, 4)
		binary.BigEndian.PutUint16(size[:], uint16(len(query)))
		if _, err = conn.Write(size[:]); err == nil {
			_, err = conn.Write(query)
		}
		done <- err
	}()

	if probeSmartDNSDNSTCPAt(listener.Addr().String()) {
		t.Fatal("probe accepted a response with a mismatched transaction ID")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
