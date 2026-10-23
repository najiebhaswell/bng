package pppoe

import (
	"net"
	"testing"
)

func TestSessionSelector(t *testing.T) {
	session := &Session{
		SessionID: "a1b2c3d4e5f60708",
		Username:  "user1",
		ClientMAC: net.HardwareAddr{0x02, 0, 0, 0, 0, 0x01},
		ClientIP:  net.IPv4(100, 64, 0, 10),
	}

	tests := []struct {
		name          string
		acctSessionID string
		username      string
		framedIP      net.IP
		mac           string
		ok, match     bool
	}{
		{name: "no attributes"},
		{name: "Acct-Session-Id", acctSessionID: "a1b2c3d4e5f60708", ok: true, match: true},
		{name: "User-Name", username: "user1", ok: true, match: true},
		{name: "Framed-IP-Address", framedIP: net.IPv4(100, 64, 0, 10).To4(), ok: true, match: true},
		{name: "Calling-Station-Id dashes", mac: "02-00-00-00-00-01", ok: true, match: true},
		{name: "Calling-Station-Id colons", mac: "02:00:00:00:00:01", ok: true, match: true},
		{name: "all must match", username: "user1", framedIP: net.IPv4(100, 64, 0, 11), ok: true},
		{name: "other user", username: "user2", ok: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sel, ok := newSessionSelector(tt.acctSessionID, tt.username, tt.framedIP, tt.mac)
			if ok != tt.ok {
				t.Fatalf("ok = %v, want %v", ok, tt.ok)
			}
			if ok && sel.matches(session) != tt.match {
				t.Fatalf("matches = %v, want %v", !tt.match, tt.match)
			}
		})
	}
}
