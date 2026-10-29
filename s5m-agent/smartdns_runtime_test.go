package main

import (
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
