package main

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestProbeSmartDNSDNSAtRequiresSuccessfulAnswer(t *testing.T) {
	tests := []struct {
		name       string
		flags      uint16
		answerCount uint16
		want       bool
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
