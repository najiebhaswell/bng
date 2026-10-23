package ebpf

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

var (
	testWAN6    = mustPrefix("2001:db8:100:5::/64")
	testPD6     = mustPrefix("2001:db8:200:5::/64")
	testClient6 = net.ParseIP("2001:db8:100:5::2")
	testRemote6 = net.ParseIP("2001:db8:ffff::2")
)

func mustPrefix(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}

// ipv6Pkt builds an IPv6/UDP packet with payloadLen bytes of UDP payload
func ipv6Pkt(src, dst net.IP, hopLimit uint8, payloadLen int) []byte {
	pkt := make([]byte, 40+8+payloadLen)
	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:], uint16(8+payloadLen))
	pkt[6] = protoUDP
	pkt[7] = hopLimit
	copy(pkt[8:], src.To16())
	copy(pkt[24:], dst.To16())
	binary.BigEndian.PutUint16(pkt[40+4:], uint16(8+payloadLen))
	return pkt
}

// down6 sends an IPv6 packet from the uplink
func down6(t *testing.T, d *PPPoEDataplane, ip []byte) (uint32, []byte) {
	t.Helper()
	in := append(ethernet(testUplinkMAC, net.HardwareAddr{2, 0, 0, 0, 0, 2}, 0, 0x86dd), ip...)
	return run(t, d.collection.Programs["pppoe_downstream"], in)
}

func setupIPv6(t *testing.T, d *PPPoEDataplane) {
	t.Helper()
	for _, p := range []*net.IPNet{testWAN6, testPD6} {
		if err := d.AddSubscriberPrefix(testClientIP, p); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPPPoEIPv6(t *testing.T) {
	d := newTestPPPoEDataplane(t)
	if err := d.AddSession(testSession(3001)); err != nil {
		t.Fatal(err)
	}
	setupIPv6(t, d)
	up := func(ip []byte) (uint32, []byte) {
		frame := pppoeFrame(3001, 0x1234, 0x0057, ip)
		ret, out := run(t, d.UpstreamProgram(), frame)
		return ret, out[:len(frame)]
	}

	// From the WAN /64 and from the delegated prefix: decapsulated for
	// the kernel (no XDP uplink route in the test)
	for _, src := range []net.IP{testClient6, net.ParseIP("2001:db8:200:5:1::9")} {
		ip := ipv6Pkt(src, testRemote6, 64, 20)
		ret, out := up(ip)
		want := append(ethernet(testServerMAC, testClientMAC, 3001, 0x86dd), ip...)
		if ret != xdpPass || !bytes.Equal(out[:len(want)], want) {
			t.Fatalf("from %v: verdict %d\n %x\nwant\n %x", src, ret, out[:len(want)], want)
		}
	}

	// Outside its prefixes
	if ret, _ := up(ipv6Pkt(net.ParseIP("2001:db8:100:6::2"), testRemote6, 64, 20)); ret != xdpDrop {
		t.Fatalf("spoofed: verdict %d", ret)
	}

	// Control traffic goes to userspace as it is
	for _, c := range [][2]string{{"fe80::2", "ff02::2"}, {"fe80::2", "ff02::1:2"}, {"2001:db8:100:5::2", "fe80::1"}} {
		frame := pppoeFrame(3001, 0x1234, 0x0057, ipv6Pkt(net.ParseIP(c[0]), net.ParseIP(c[1]), 255, 8))
		if ret, out := run(t, d.UpstreamProgram(), frame); ret != xdpPass || !bytes.Equal(out[:len(frame)], frame) {
			t.Fatalf("%s -> %s: verdict %d, want unchanged XDP_PASS", c[0], c[1], ret)
		}
	}

	// Downstream, to both prefixes
	for _, dst := range []net.IP{testClient6, net.ParseIP("2001:db8:200:5::77")} {
		ip := ipv6Pkt(testRemote6, dst, 64, 20)
		ret, out := down6(t, d, ip)
		if ret != xdpRedirect {
			t.Fatalf("to %v: verdict %d, want XDP_REDIRECT", dst, ret)
		}
		fwd := append([]byte(nil), ip...)
		fwd[7]--
		want := pppoeFrame(3001, 0x1234, 0x0057, fwd)
		copy(want[0:6], testClientMAC)
		copy(want[6:12], testServerMAC)
		if !bytes.Equal(out[:len(want)], want) {
			t.Fatalf("to %v:\n %x\nwant\n %x", dst, out[:len(want)], want)
		}
	}
	// Not a subscriber's, too big for the MRU
	if ret, _ := down6(t, d, ipv6Pkt(testRemote6, net.ParseIP("2001:db8:300::1"), 64, 20)); ret != xdpPass {
		t.Fatalf("unknown prefix: verdict %d", ret)
	}
	if ret, _ := down6(t, d, ipv6Pkt(testRemote6, testClient6, 64, 1500-48)); ret != xdpDrop {
		t.Fatalf("too big: verdict %d", ret)
	}

	// The prefix goes with the session
	if err := d.RemoveSubscriberPrefix(testWAN6); err != nil {
		t.Fatal(err)
	}
	if ret, _ := down6(t, d, ipv6Pkt(testRemote6, testClient6, 64, 20)); ret != xdpPass {
		t.Fatalf("removed prefix: verdict %d", ret)
	}

	st, _ := d.Stats()
	if st["up6_kernel"] != 2 || st["up6_spoofed"] != 1 || st["up6_control"] != 3 || st["down6_redirect"] != 2 || st["down6_too_big"] != 1 {
		t.Fatalf("stats %v", st)
	}
}

func TestIPoEIPv6(t *testing.T) {
	d := newTestPPPoEDataplane(t)
	if err := d.AddIPoESession(testIPoESession(3001)); err != nil {
		t.Fatal(err)
	}
	setupIPv6(t, d)
	up := func(ip []byte) (uint32, []byte) {
		frame := append(ethernet(testServerMAC, testClientMAC, 3001, 0x86dd), ip...)
		ret, out := run(t, d.IPoEUpstreamProgram(), frame)
		return ret, out[:len(frame)]
	}

	ip := ipv6Pkt(testClient6, testRemote6, 64, 20)
	if ret, out := up(ip); ret != xdpPass || !bytes.Equal(out[upIPOff:], ip) {
		t.Fatalf("verdict %d", ret)
	}
	if ret, _ := up(ipv6Pkt(net.ParseIP("2001:db8:100:6::2"), testRemote6, 64, 20)); ret != xdpDrop {
		t.Fatalf("spoofed: verdict %d", ret)
	}
	if ret, _ := up(ipv6Pkt(net.ParseIP("fe80::2"), net.ParseIP("ff02::2"), 255, 8)); ret != xdpPass {
		t.Fatalf("RS: verdict %d", ret)
	}

	ret, out := down6(t, d, ipv6Pkt(testRemote6, testClient6, 64, 20))
	wantL2 := ethernet(testClientMAC, testServerMAC, 3001, 0x86dd)
	if ret != xdpRedirect || !bytes.Equal(out[:len(wantL2)], wantL2) || out[len(wantL2)+7] != 63 {
		t.Fatalf("downstream: verdict %d, %x", ret, out[:len(wantL2)+8])
	}

	// Without a lease, only control traffic
	if err := d.SetIPoELeaseOnly(true); err != nil {
		t.Fatal(err)
	}
	frame := append(ethernet(testServerMAC, testClientMAC, 3002, 0x86dd), ip...)
	if ret, _ := run(t, d.IPoEUpstreamProgram(), frame); ret != xdpDrop {
		t.Fatalf("unleased: verdict %d", ret)
	}
}
