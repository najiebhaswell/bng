package ebpf

import (
	"bytes"
	"net"
	"os"
	"testing"

	"github.com/cilium/ebpf"
)

func testIPoESession(vlan uint16) IPoESession {
	return IPoESession{
		ClientMAC:  testClientMAC,
		ServerMAC:  testServerMAC,
		ClientIP:   testClientIP,
		VLANID:     vlan,
		MTU:        1500,
		FIBIfindex: 1,
		TXIfindex:  7,
	}
}

// ipoeUp sends an IPv4 packet from the subscriber on VLAN 3001; the
// returned frame is the whole output buffer
func ipoeUp(t *testing.T, d *PPPoEDataplane, ip []byte) (uint32, []byte) {
	t.Helper()
	frame := append(ethernet(testServerMAC, testClientMAC, 3001, 0x0800), ip...)
	ret, out := run(t, d.IPoEUpstreamProgram(), frame)
	return ret, out[:len(frame)]
}

func TestIPoEUpstream(t *testing.T) {
	d := newTestPPPoEDataplane(t)
	if err := d.AddIPoESession(testIPoESession(3001)); err != nil {
		t.Fatal(err)
	}

	// Without a port block: handed to the kernel unchanged (no route to
	// an XDP uplink in the test)
	ip := natPacket(protoUDP, testClientIP, testRemoteIP, 5000, 53, 0)
	ret, out := ipoeUp(t, d, ip)
	if ret != xdpPass || !bytes.Equal(out[upIPOff:], ip) {
		t.Fatalf("verdict %d, packet %x", ret, out)
	}

	// With one: translated in place
	setupNAT(t, d, 64, 1)
	ret, out = ipoeUp(t, d, natPacket(protoUDP, testClientIP, testRemoteIP, 5000, 53, 0))
	if ret != xdpPass {
		t.Fatalf("verdict %d", ret)
	}
	if src, _, sport, _ := checkPacket(t, out[upIPOff:]); !src.Equal(testPublicIP) || sport != 1032 {
		t.Fatalf("translated to %v:%d", src, sport)
	}

	// Destinations in nat_bypass are reached with the private address
	_, pool, _ := net.ParseCIDR("10.0.0.0/24")
	if err := d.AddNATBypass(pool); err != nil {
		t.Fatal(err)
	}
	ip = natPacket(protoUDP, testClientIP, testRemoteIP, 5000, 53, 0)
	if _, out = ipoeUp(t, d, ip); !bytes.Equal(out[upIPOff:], ip) {
		t.Fatalf("bypassed destination translated: %x", out[upIPOff:])
	}

	// Wrong source address
	spoofed := natPacket(protoUDP, net.IPv4(100, 64, 0, 99), testRemoteIP, 5000, 53, 0)
	if ret, _ := ipoeUp(t, d, spoofed); ret != xdpDrop {
		t.Fatalf("spoofed: verdict %d, want XDP_DROP", ret)
	}

	// Unknown VLAN (or MAC): the kernel decides
	frame := append(ethernet(testServerMAC, testClientMAC, 3002, 0x0800), ip...)
	if ret, out := run(t, d.IPoEUpstreamProgram(), frame); ret != xdpPass || !bytes.Equal(out[:len(frame)], frame) {
		t.Fatalf("unknown VLAN: verdict %d", ret)
	}

	// Unless hosts without a lease may only reach bypass destinations
	if err := d.SetIPoELeaseOnly(true); err != nil {
		t.Fatal(err)
	}
	internet := natPacket(protoUDP, testClientIP, net.IPv4(198, 51, 100, 7), 5000, 53, 0)
	frame = append(ethernet(testServerMAC, testClientMAC, 3002, 0x0800), internet...)
	if ret, _ := run(t, d.IPoEUpstreamProgram(), frame); ret != xdpDrop {
		t.Fatalf("unleased host to the internet: verdict %d, want XDP_DROP", ret)
	}
	frame = append(ethernet(testServerMAC, testClientMAC, 3002, 0x0800), ip...) // to a bypass prefix
	if ret, _ := run(t, d.IPoEUpstreamProgram(), frame); ret != xdpPass {
		t.Fatalf("unleased host to a bypass prefix: verdict %d, want XDP_PASS", ret)
	}
	if err := d.SetIPoELeaseOnly(false); err != nil {
		t.Fatal(err)
	}

	st, err := d.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if st["ipoe_up_kernel"] != 3 || st["ipoe_up_spoofed"] != 1 || st["ipoe_up_no_session"] != 2 ||
		st["ipoe_up_unleased"] != 1 || st["nat_out"] != 1 {
		t.Fatalf("stats %v", st)
	}

	if err := d.RemoveIPoESession(testIPoESession(3001)); err != nil {
		t.Fatal(err)
	}
	if ret, _ := ipoeUp(t, d, spoofed); ret != xdpPass {
		t.Fatalf("after removal: verdict %d, want XDP_PASS", ret)
	}
}

func TestIPoEDownstream(t *testing.T) {
	d := newTestPPPoEDataplane(t)
	setupNAT(t, d, 64, 1)
	if err := d.AddIPoESession(testIPoESession(3001)); err != nil {
		t.Fatal(err)
	}
	// Create the mapping
	ipoeUp(t, d, natPacket(protoUDP, testClientIP, testRemoteIP, 5000, 53, 0))

	for _, c := range []struct {
		name string
		ip   []byte
	}{
		{"translated", natPacket(protoUDP, testRemoteIP, testPublicIP, 53, 1032, 0)},
		{"to the private address", natPacket(protoUDP, testRemoteIP, testClientIP, 53, 5000, 0)},
	} {
		ret, out := natDownRaw(t, d, c.ip)
		if ret != xdpRedirect {
			t.Fatalf("%s: verdict %d, want XDP_REDIRECT", c.name, ret)
		}
		wantL2 := ethernet(testClientMAC, testServerMAC, 3001, 0x0800)
		if !bytes.Equal(out[:len(wantL2)], wantL2) {
			t.Fatalf("%s: L2 %x, want %x", c.name, out[:len(wantL2)], wantL2)
		}
		pkt := fixTTL(out[len(wantL2) : len(wantL2)+len(c.ip)])
		if _, dst, _, dport := checkPacket(t, pkt); !dst.Equal(testClientIP) || dport != 5000 {
			t.Fatalf("%s: to %v:%d", c.name, dst, dport)
		}
	}

	// Untagged subscriber
	s := testIPoESession(0)
	if err := d.AddIPoESession(s); err != nil {
		t.Fatal(err)
	}
	ret, out := natDownRaw(t, d, natPacket(protoUDP, testRemoteIP, testClientIP, 53, 5000, 0))
	wantL2 := ethernet(testClientMAC, testServerMAC, 0, 0x0800)
	if ret != xdpRedirect || !bytes.Equal(out[:len(wantL2)], wantL2) {
		t.Fatalf("untagged: verdict %d, L2 %x", ret, out[:len(wantL2)])
	}
}

// natDownRaw sends an IPv4 packet from the uplink and returns the whole
// output buffer
func natDownRaw(t *testing.T, d *PPPoEDataplane, ip []byte) (uint32, []byte) {
	t.Helper()
	in := append(ethernet(testUplinkMAC, net.HardwareAddr{2, 0, 0, 0, 0, 2}, 0, 0x0800), ip...)
	return run(t, d.collection.Programs["pppoe_downstream"], in)
}

// The DHCP fast path must hand IPv4 data, but not DHCP requests, to the
// IPoE program through pppoe_progs slot 1
func TestDHCPFastPathTailCallsIPoE(t *testing.T) {
	d := newTestPPPoEDataplane(t)
	if _, err := os.Stat(testDHCPObject); err != nil {
		t.Skip("BPF object not built (make -C bpf)")
	}
	coll, err := ebpf.LoadCollection(testDHCPObject)
	if err != nil {
		t.Fatal(err)
	}
	defer coll.Close()
	dhcp := coll.Programs["dhcp_fastpath_prog"]

	key := uint32(1)
	if err := coll.Maps["pppoe_progs"].Put(&key, d.IPoEUpstreamProgram()); err != nil {
		t.Fatal(err)
	}
	if err := d.AddIPoESession(testIPoESession(3001)); err != nil {
		t.Fatal(err)
	}

	spoofed := natPacket(protoUDP, net.IPv4(100, 64, 0, 99), testRemoteIP, 5000, 53, 0)
	frame := append(ethernet(testServerMAC, testClientMAC, 3001, 0x0800), spoofed...)
	if ret, _ := run(t, dhcp, frame); ret != xdpDrop {
		t.Fatalf("IPv4 data: verdict %d, want XDP_DROP from the IPoE program", ret)
	}

	// A DHCP request from that address stays with the DHCP fast path
	// (which passes it on: nothing is cached for this MAC)
	dhcpReq := natPacket(protoUDP, net.IPv4(100, 64, 0, 99), net.IPv4(100, 64, 0, 1), 68, 67, 0)
	frame = append(ethernet(testServerMAC, testClientMAC, 3001, 0x0800), dhcpReq...)
	if ret, _ := run(t, dhcp, frame); ret != xdpPass {
		t.Fatalf("DHCP request: verdict %d, want XDP_PASS", ret)
	}
}
