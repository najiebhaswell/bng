package dhcp

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
)

type fakeDataplane struct {
	added   map[string]net.IP // MAC -> IP
	removed []string
	fail    error
}

func (f *fakeDataplane) AddLease(l *Lease) error {
	if f.fail != nil {
		return f.fail
	}
	f.added[l.MAC.String()] = l.IP
	return nil
}

func (f *fakeDataplane) RemoveLease(l *Lease) {
	f.removed = append(f.removed, l.MAC.String())
}

func TestDataplaneLeaseLifecycle(t *testing.T) {
	srv, pool := testServer(t)
	dp := &fakeDataplane{added: make(map[string]net.IP)}
	srv.SetDataplane(dp)

	request := func(mac net.HardwareAddr, ip net.IP) *dhcpv4.DHCPv4 {
		t.Helper()
		req := makeDHCPPacket(t, mac, dhcpv4.MessageTypeRequest)
		req.UpdateOption(dhcpv4.OptRequestedIPAddress(ip))
		resp, err := srv.handleRequest(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	// A new session goes into the data plane before the ACK; a renewal
	// does not add it again
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:30")
	ip, err := pool.Allocate(mac)
	if err != nil {
		t.Fatal(err)
	}
	if resp := request(mac, ip); resp.MessageType() != dhcpv4.MessageTypeAck {
		t.Fatalf("got %s", resp.MessageType())
	}
	if !dp.added[mac.String()].Equal(ip) {
		t.Fatalf("data plane has %v", dp.added)
	}
	delete(dp.added, mac.String())
	request(mac, ip)
	if len(dp.added) != 0 {
		t.Fatal("renewal added the subscriber again")
	}

	// Release takes it out
	srv.handleRelease(makeDHCPPacket(t, mac, dhcpv4.MessageTypeRelease))
	if len(dp.removed) != 1 || dp.removed[0] != mac.String() {
		t.Fatalf("removed %v", dp.removed)
	}

	// So does expiry
	mac2, _ := net.ParseMAC("aa:bb:cc:dd:ee:31")
	ip2, _ := pool.Allocate(mac2)
	request(mac2, ip2)
	srv.leasesMu.Lock()
	srv.leases[mac2.String()].ExpiresAt = time.Now().Add(-time.Second)
	srv.leasesMu.Unlock()
	srv.cleanupExpiredLeases()
	if len(dp.removed) != 2 || dp.removed[1] != mac2.String() {
		t.Fatalf("removed %v", dp.removed)
	}

	// No lease when the data plane refuses the subscriber
	dp.fail = errors.New("NAT pool exhausted")
	mac3, _ := net.ParseMAC("aa:bb:cc:dd:ee:32")
	ip3, _ := pool.Allocate(mac3)
	if resp := request(mac3, ip3); resp.MessageType() != dhcpv4.MessageTypeNak {
		t.Fatalf("got %s, want NAK", resp.MessageType())
	}
	srv.leasesMu.RLock()
	_, ok := srv.leases[mac3.String()]
	srv.leasesMu.RUnlock()
	if ok {
		t.Fatal("lease stored although the data plane refused it")
	}
}
