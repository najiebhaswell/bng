package nat

import (
	"net"
	"testing"
)

func TestBlockAllocator(t *testing.T) {
	pub := []net.IP{net.ParseIP("203.0.113.1"), net.ParseIP("203.0.113.2")}
	a, err := NewBlockAllocator(pub, 16384) // 3 blocks per address
	if err != nil {
		t.Fatal(err)
	}
	if used, total := a.Usage(); used != 0 || total != 6 {
		t.Fatalf("usage %d/%d, want 0/6", used, total)
	}

	sub := func(i int) net.IP { return net.IPv4(100, 64, 0, byte(i)) }
	type block struct {
		ip    string
		start uint16
	}
	seen := make(map[block]bool)
	gens := make(map[uint32]bool)
	for i := 1; i <= 6; i++ {
		alloc, gen, err := a.Allocate(sub(i), "user")
		if err != nil {
			t.Fatal(err)
		}
		b := block{alloc.PublicIP.String(), alloc.PortStart}
		if seen[b] || gens[gen] || gen == 0 {
			t.Fatalf("subscriber %d got block %v gen %d twice", i, b, gen)
		}
		seen[b], gens[gen] = true, true
		if alloc.PortStart < BlockPortMin || alloc.PortEnd != alloc.PortStart+16383 {
			t.Fatalf("block %d-%d", alloc.PortStart, alloc.PortEnd)
		}
	}
	// Spread over both addresses
	if !seen[block{"203.0.113.1", 1024}] || !seen[block{"203.0.113.2", 1024}] {
		t.Fatalf("blocks %v not spread over both addresses", seen)
	}
	if _, _, err := a.Allocate(sub(7), "user"); err == nil {
		t.Fatal("allocated from a full pool")
	}

	// Asking again returns the same block
	again, gen, _ := a.Allocate(sub(3), "user")
	if !gens[gen] || !seen[block{again.PublicIP.String(), again.PortStart}] {
		t.Fatal("second Allocate for the same address changed the block")
	}

	// A released block is reused, under a new generation, and no two
	// holders ever share a block
	released := a.Release(sub(3))
	if released == nil || a.Release(sub(3)) != nil {
		t.Fatal("Release")
	}
	alloc, gen, err := a.Allocate(sub(7), "user7")
	if err != nil {
		t.Fatal(err)
	}
	if !alloc.PublicIP.Equal(released.PublicIP) || alloc.PortStart != released.PortStart || gens[gen] {
		t.Fatalf("got %v:%d gen %d after releasing %v:%d", alloc.PublicIP, alloc.PortStart, gen, released.PublicIP, released.PortStart)
	}
	holders := make(map[block]int)
	for i := 1; i <= 7; i++ {
		if i == 3 {
			continue
		}
		al, _, _ := a.Allocate(sub(i), "user")
		holders[block{al.PublicIP.String(), al.PortStart}]++
	}
	for b, n := range holders {
		if n != 1 {
			t.Fatalf("block %v has %d holders", b, n)
		}
	}
}

func TestParsePublicIPs(t *testing.T) {
	ips, err := ParsePublicIPs([]string{"198.51.100.9", "203.0.113.0/29", "192.0.2.0/31"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"198.51.100.9", "203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.4",
		"203.0.113.5", "203.0.113.6", "192.0.2.0", "192.0.2.1"}
	if len(ips) != len(want) {
		t.Fatalf("got %v", ips)
	}
	for i := range want {
		if ips[i].String() != want[i] {
			t.Fatalf("got %v, want %v", ips, want)
		}
	}
	for _, bad := range []string{"2001:db8::1", "10.0.0.0/8", "nonsense"} {
		if _, err := ParsePublicIPs([]string{bad}); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

func TestIsPrivateIPv4(t *testing.T) {
	for ip, want := range map[string]bool{
		"10.1.2.3": true, "172.16.0.1": true, "172.31.255.1": true, "172.32.0.1": false,
		"192.168.1.1": true, "100.64.0.1": true, "100.127.255.1": true, "100.128.0.1": false,
		"203.0.113.1": false, "2001:db8::1": false,
	} {
		if got := IsPrivateIPv4(net.ParseIP(ip)); got != want {
			t.Errorf("%s: %v, want %v", ip, got, want)
		}
	}
}
