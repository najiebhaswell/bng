package ebpf

import (
	"encoding/binary"
	"net"
	"os"
	"testing"
	"time"

	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

var (
	testPublicIP  = net.IPv4(203, 0, 113, 1).To4()
	testUplinkMAC = net.HardwareAddr{0xfa, 0xf6, 0xcd, 0x08, 0x1d, 0x70}
)

const (
	protoICMP = 1
	protoTCP  = 6
	protoUDP  = 17

	// Offsets of the IPv4 header in the test frames (VLAN 3001)
	upIPOff   = 18 // upstream, passed to the kernel: Ethernet + VLAN
	downIPOff = 26 // downstream: Ethernet + VLAN + PPPoE/PPP
)

func inetSum(b []byte, sum uint32) uint32 {
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	return sum
}

func foldSum(sum uint32) uint16 {
	for sum > 0xffff {
		sum = (sum & 0xffff) + sum>>16
	}
	return ^uint16(sum)
}

func pseudoSum(src, dst net.IP, proto uint8, l4len int) uint32 {
	sum := inetSum(src.To4(), 0)
	sum = inetSum(dst.To4(), sum)
	return sum + uint32(proto) + uint32(l4len)
}

// natPacket builds an IPv4 packet with valid checksums. For TCP and UDP
// sport/dport are the ports; for ICMP echo (request if dport is 8, reply if
// 0) sport is the identifier.
func natPacket(proto uint8, src, dst net.IP, sport, dport uint16, tcpFlags uint8) []byte {
	var l4 []byte
	switch proto {
	case protoUDP:
		l4 = make([]byte, 8+12)
		binary.BigEndian.PutUint16(l4[0:], sport)
		binary.BigEndian.PutUint16(l4[2:], dport)
		binary.BigEndian.PutUint16(l4[4:], uint16(len(l4)))
		binary.BigEndian.PutUint16(l4[6:], foldSum(inetSum(l4, pseudoSum(src, dst, proto, len(l4)))))
	case protoTCP:
		l4 = make([]byte, 20)
		binary.BigEndian.PutUint16(l4[0:], sport)
		binary.BigEndian.PutUint16(l4[2:], dport)
		l4[12] = 5 << 4
		l4[13] = tcpFlags
		binary.BigEndian.PutUint16(l4[16:], foldSum(inetSum(l4, pseudoSum(src, dst, proto, len(l4)))))
	case protoICMP:
		l4 = make([]byte, 8+8)
		l4[0] = uint8(dport)
		binary.BigEndian.PutUint16(l4[4:], sport)
		binary.BigEndian.PutUint16(l4[6:], 1)
		binary.BigEndian.PutUint16(l4[2:], foldSum(inetSum(l4, 0)))
	}
	return ipv4Header(proto, src, dst, l4)
}

func ipv4Header(proto uint8, src, dst net.IP, payload []byte) []byte {
	pkt := make([]byte, 20, 20+len(payload))
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:], uint16(20+len(payload)))
	binary.BigEndian.PutUint16(pkt[4:], 0x4242)
	pkt[8] = 64
	pkt[9] = proto
	copy(pkt[12:], src.To4())
	copy(pkt[16:], dst.To4())
	binary.BigEndian.PutUint16(pkt[10:], foldSum(inetSum(pkt[:20], 0)))
	return append(pkt, payload...)
}

// checkPacket verifies the IPv4 header and L4 checksums of pkt (exactly one
// IPv4 packet) and returns source, destination and the two port fields
func checkPacket(t *testing.T, pkt []byte) (src, dst net.IP, sport, dport uint16) {
	t.Helper()
	if foldSum(inetSum(pkt[:20], 0)) != 0 {
		t.Fatalf("bad IP header checksum: %x", pkt[:20])
	}
	src, dst = net.IP(pkt[12:16]), net.IP(pkt[16:20])
	l4 := pkt[20:]
	switch pkt[9] {
	case protoTCP, protoUDP:
		if foldSum(inetSum(l4, pseudoSum(src, dst, pkt[9], len(l4)))) != 0 {
			t.Fatalf("bad L4 checksum: %x", pkt)
		}
		return src, dst, binary.BigEndian.Uint16(l4[0:]), binary.BigEndian.Uint16(l4[2:])
	case protoICMP:
		if foldSum(inetSum(l4, 0)) != 0 {
			t.Fatalf("bad ICMP checksum: %x", pkt)
		}
		return src, dst, binary.BigEndian.Uint16(l4[4:]), 0
	}
	return src, dst, 0, 0
}

func setupNAT(t *testing.T, d *PPPoEDataplane, count uint16, gen uint32) {
	t.Helper()
	if err := d.AddNATPublicIP(testPublicIP); err != nil {
		t.Fatal(err)
	}
	b := PPPoENATBlock{PublicIP: testPublicIP, PortStart: 1024, PortCount: count, Gen: gen}
	if err := d.SetSubscriberNAT(testClientIP, b); err != nil {
		t.Fatal(err)
	}
}

// natUp sends an IPv4 packet from the subscriber and returns the translated
// packet handed to the kernel
func natUp(t *testing.T, d *PPPoEDataplane, ip []byte) (uint32, []byte) {
	t.Helper()
	ret, out := run(t, d.UpstreamProgram(), pppoeFrame(3001, 0x1234, 0x0021, ip))
	return ret, out[upIPOff : upIPOff+len(ip)]
}

// natDown sends an IPv4 packet from the uplink and returns the packet
// encapsulated towards the subscriber
func natDown(t *testing.T, d *PPPoEDataplane, ip []byte) (uint32, []byte) {
	t.Helper()
	in := append(ethernet(testUplinkMAC, net.HardwareAddr{2, 0, 0, 0, 0, 2}, 0, 0x0800), ip...)
	ret, out := run(t, d.collection.Programs["pppoe_downstream"], in)
	return ret, out[downIPOff : downIPOff+len(ip)]
}

func TestPPPoENATUDP(t *testing.T) {
	d := newTestPPPoEDataplane(t)
	setupNAT(t, d, 64, 1)
	if err := d.AddSession(testSession(3001)); err != nil {
		t.Fatal(err)
	}

	ret, out := natUp(t, d, natPacket(protoUDP, testClientIP, testRemoteIP, 5000, 53, 0))
	if ret != xdpPass {
		t.Fatalf("upstream verdict = %d, want XDP_PASS (kernel path)", ret)
	}
	src, dst, sport, dport := checkPacket(t, out)
	// The probe starts at 5000 % 64 = 8 in the block
	if !src.Equal(testPublicIP) || !dst.Equal(testRemoteIP) || sport != 1032 || dport != 53 {
		t.Fatalf("translated to %v:%d -> %v:%d, want %v:1032 -> %v:53", src, sport, dst, dport, testPublicIP, testRemoteIP)
	}

	// Endpoint-independent mapping: same port to another destination
	other := net.IPv4(198, 51, 100, 7).To4()
	_, out = natUp(t, d, natPacket(protoUDP, testClientIP, other, 5000, 4500, 0))
	if _, _, sport, _ := checkPacket(t, out); sport != 1032 {
		t.Fatalf("second destination got port %d, want 1032", sport)
	}
	// Another source port gets another public port
	_, out = natUp(t, d, natPacket(protoUDP, testClientIP, testRemoteIP, 5001, 53, 0))
	if _, _, sport, _ := checkPacket(t, out); sport != 1033 {
		t.Fatalf("source port 5001 got port %d, want 1033", sport)
	}

	// Replies, also from an endpoint never contacted (endpoint-independent
	// filtering)
	for _, from := range []net.IP{testRemoteIP, net.IPv4(192, 0, 2, 9).To4()} {
		ret, out = natDown(t, d, natPacket(protoUDP, from, testPublicIP, 53, 1032, 0))
		if ret != xdpRedirect {
			t.Fatalf("downstream from %v: verdict = %d, want XDP_REDIRECT", from, ret)
		}
		src, dst, sport, dport = checkPacket(t, fixTTL(out))
		if !src.Equal(from) || !dst.Equal(testClientIP) || sport != 53 || dport != 5000 {
			t.Fatalf("reply translated to %v:%d -> %v:%d", src, sport, dst, dport)
		}
	}

	// A public port without a mapping
	if ret, _ := natDown(t, d, natPacket(protoUDP, testRemoteIP, testPublicIP, 53, 1050, 0)); ret != xdpDrop {
		t.Fatalf("unmapped port: verdict = %d, want XDP_DROP", ret)
	}

	st, err := d.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if st["nat_new"] != 2 || st["nat_out"] != 3 || st["nat_in"] != 2 || st["nat_no_mapping"] != 1 {
		t.Fatalf("stats %v", st)
	}
}

func TestPPPoENATTCPAndICMP(t *testing.T) {
	d := newTestPPPoEDataplane(t)
	setupNAT(t, d, 64, 1)
	if err := d.AddSession(testSession(3001)); err != nil {
		t.Fatal(err)
	}

	const syn, ack = 0x02, 0x10
	_, out := natUp(t, d, natPacket(protoTCP, testClientIP, testRemoteIP, 40000, 443, syn))
	src, _, sport, _ := checkPacket(t, out)
	if !src.Equal(testPublicIP) || sport != 1024+40000%64 {
		t.Fatalf("TCP translated to %v:%d", src, sport)
	}
	ret, out := natDown(t, d, natPacket(protoTCP, testRemoteIP, testPublicIP, 443, sport, syn|ack))
	if ret != xdpRedirect {
		t.Fatalf("TCP reply verdict = %d", ret)
	}
	if _, dst, _, dport := checkPacket(t, fixTTL(out)); !dst.Equal(testClientIP) || dport != 40000 {
		t.Fatalf("TCP reply to %v:%d", dst, dport)
	}

	// ICMP echo: the identifier is translated
	_, out = natUp(t, d, natPacket(protoICMP, testClientIP, testRemoteIP, 0x0777, 8, 0))
	src, _, id, _ := checkPacket(t, out)
	if !src.Equal(testPublicIP) || id != 1024+0x0777%64 {
		t.Fatalf("echo translated to %v id %d", src, id)
	}
	ret, out = natDown(t, d, natPacket(protoICMP, testRemoteIP, testPublicIP, id, 0, 0))
	if ret != xdpRedirect {
		t.Fatalf("echo reply verdict = %d", ret)
	}
	if _, dst, id, _ := checkPacket(t, fixTTL(out)); !dst.Equal(testClientIP) || id != 0x0777 {
		t.Fatalf("echo reply to %v id %#x", dst, id)
	}

	// ICMP port unreachable about the translated UDP packet: outer
	// destination and quoted source go back to the subscriber
	_, sent := natUp(t, d, natPacket(protoUDP, testClientIP, testRemoteIP, 5000, 53, 0))
	_, _, pubPort, _ := checkPacket(t, sent)
	icmp := make([]byte, 8, 8+len(sent))
	icmp[0], icmp[1] = 3, 3
	icmp = append(icmp, sent...) // the whole datagram, so its checksum can be checked
	binary.BigEndian.PutUint16(icmp[2:], foldSum(inetSum(icmp, 0)))
	ret, out = natDown(t, d, ipv4Header(protoICMP, testRemoteIP, testPublicIP, icmp))
	if ret != xdpRedirect {
		t.Fatalf("ICMP error verdict = %d", ret)
	}
	out = fixTTL(out)
	if _, dst, _, _ := checkPacket(t, out); !dst.Equal(testClientIP) {
		t.Fatalf("ICMP error to %v", dst)
	}
	quoted := out[28:]
	if foldSum(inetSum(quoted[:20], 0)) != 0 {
		t.Fatal("bad quoted IP header checksum")
	}
	if qsrc, qport := net.IP(quoted[12:16]), binary.BigEndian.Uint16(quoted[20:]); !qsrc.Equal(testClientIP) || qport != 5000 {
		t.Fatalf("quoted source %v:%d (was %v:%d)", qsrc, qport, testPublicIP, pubPort)
	}
	// The quoted UDP datagram is complete here, so its checksum must hold
	if foldSum(inetSum(quoted[20:], pseudoSum(net.IP(quoted[12:16]), net.IP(quoted[16:20]), protoUDP, len(quoted)-20))) != 0 {
		t.Fatal("bad quoted UDP checksum")
	}
}

// fixTTL undoes the forwarding TTL decrement so checkPacket can check the
// translated checksums
func fixTTL(pkt []byte) []byte {
	pkt[8]++
	binary.BigEndian.PutUint16(pkt[10:], 0)
	binary.BigEndian.PutUint16(pkt[10:], foldSum(inetSum(pkt[:20], 0)))
	return pkt
}

func TestPPPoENATBlockReuse(t *testing.T) {
	d := newTestPPPoEDataplane(t)
	setupNAT(t, d, 2, 1)
	if err := d.AddSession(testSession(3001)); err != nil {
		t.Fatal(err)
	}

	for _, port := range []uint16{6000, 6001} {
		if ret, _ := natUp(t, d, natPacket(protoUDP, testClientIP, testRemoteIP, port, 53, 0)); ret != xdpPass {
			t.Fatalf("port %d: verdict = %d", port, ret)
		}
	}
	// The block (2 ports) is full
	if ret, _ := natUp(t, d, natPacket(protoUDP, testClientIP, testRemoteIP, 6002, 53, 0)); ret != xdpDrop {
		t.Fatalf("exhausted block: verdict = %d, want XDP_DROP", ret)
	}

	// The session ends: its mappings stop working at once
	if err := d.DeleteSubscriberNAT(testClientIP); err != nil {
		t.Fatal(err)
	}
	if ret, _ := natDown(t, d, natPacket(protoUDP, testRemoteIP, testPublicIP, 53, 1024, 0)); ret != xdpDrop {
		t.Fatalf("mapping of an ended session: verdict = %d, want XDP_DROP", ret)
	}

	// The same address and block under a new generation: the stale
	// mappings are replaced, not reused
	setupNAT(t, d, 2, 2)
	for _, port := range []uint16{7000, 7001} {
		if ret, _ := natUp(t, d, natPacket(protoUDP, testClientIP, testRemoteIP, port, 53, 0)); ret != xdpPass {
			t.Fatalf("new generation, port %d: verdict = %d", port, ret)
		}
	}

	sweep, err := d.ExpireNAT(DefaultNATTimeouts)
	if err != nil {
		t.Fatal(err)
	}
	if sweep.Active != 2 || sweep.Stale != 2 {
		t.Fatalf("sweep %+v, want 2 active and the 2 old ones stale", sweep)
	}

	// Everything goes once the block is gone
	if err := d.DeleteSubscriberNAT(testClientIP); err != nil {
		t.Fatal(err)
	}
	if sweep, err = d.ExpireNAT(DefaultNATTimeouts); err != nil {
		t.Fatal(err)
	}
	if sweep.Active != 0 || sweep.Stale != 2 {
		t.Fatalf("sweep %+v, want 2 stale", sweep)
	}
	var k natKey
	var v natMapping
	if d.nat.out.Iterate().Next(&k, &v) || d.nat.in.Iterate().Next(&k, &v) {
		t.Fatal("mappings left after the sweep")
	}
}

func TestPPPoENATTimeout(t *testing.T) {
	d := newTestPPPoEDataplane(t)
	setupNAT(t, d, 64, 1)
	if err := d.AddSession(testSession(3001)); err != nil {
		t.Fatal(err)
	}
	natUp(t, d, natPacket(protoUDP, testClientIP, testRemoteIP, 5000, 53, 0))

	if sweep, _ := d.ExpireNAT(DefaultNATTimeouts); sweep.Active != 1 {
		t.Fatalf("sweep %+v, want 1 active", sweep)
	}
	if sweep, _ := d.ExpireNAT(NATTimeouts{}); sweep.Expired != 1 {
		t.Fatalf("sweep %+v with zero timeouts, want 1 expired", sweep)
	}
}

// Subscribers without a port block (public addresses) are not translated
func TestPPPoENATOnlyWithBlock(t *testing.T) {
	d := newTestPPPoEDataplane(t)
	if err := d.AddSession(testSession(3001)); err != nil {
		t.Fatal(err)
	}
	ip := natPacket(protoUDP, testClientIP, testRemoteIP, 5000, 53, 0)
	_, out := natUp(t, d, ip)
	if src, _, sport, _ := checkPacket(t, out); !src.Equal(testClientIP) || sport != 5000 {
		t.Fatalf("translated without a block: %v:%d", src, sport)
	}
}

// fragment sets the fragment fields of an IPv4 packet and fixes its header
// checksum
func fragment(pkt []byte, more bool, offset8 uint16) []byte {
	v := offset8
	if more {
		v |= 0x2000
	}
	binary.BigEndian.PutUint16(pkt[6:], v)
	binary.BigEndian.PutUint16(pkt[10:], 0)
	binary.BigEndian.PutUint16(pkt[10:], foldSum(inetSum(pkt[:20], 0)))
	return pkt
}

func TestPPPoENATFragments(t *testing.T) {
	d := newTestPPPoEDataplane(t)
	setupNAT(t, d, 64, 1)
	if err := d.AddSession(testSession(3001)); err != nil {
		t.Fatal(err)
	}
	rest := func(src, dst net.IP) []byte {
		return fragment(ipv4Header(protoUDP, src, dst, make([]byte, 24)), false, 3)
	}

	// A later fragment ahead of the first one cannot be translated
	if ret, _ := natUp(t, d, rest(testClientIP, testRemoteIP)); ret != xdpDrop {
		t.Fatalf("early fragment: verdict = %d, want XDP_DROP", ret)
	}

	first := fragment(natPacket(protoUDP, testClientIP, testRemoteIP, 5000, 53, 0), true, 0)
	if _, out := natUp(t, d, first); !net.IP(out[12:16]).Equal(testPublicIP) {
		t.Fatalf("first fragment from %v", net.IP(out[12:16]))
	}
	ret, out := natUp(t, d, rest(testClientIP, testRemoteIP))
	if ret != xdpPass || !net.IP(out[12:16]).Equal(testPublicIP) || foldSum(inetSum(out[:20], 0)) != 0 {
		t.Fatalf("later fragment: verdict %d, from %v", ret, net.IP(out[12:16]))
	}

	// And downstream
	first = fragment(natPacket(protoUDP, testRemoteIP, testPublicIP, 53, 1032, 0), true, 0)
	if ret, out := natDown(t, d, first); ret != xdpRedirect || !net.IP(out[16:20]).Equal(testClientIP) {
		t.Fatalf("first fragment down: verdict %d, to %v", ret, net.IP(out[16:20]))
	}
	ret, out = natDown(t, d, rest(testRemoteIP, testPublicIP))
	if ret != xdpRedirect || !net.IP(out[16:20]).Equal(testClientIP) || foldSum(inetSum(fixTTL(out)[:20], 0)) != 0 {
		t.Fatalf("later fragment down: verdict %d, to %v", ret, net.IP(out[16:20]))
	}
}

// Sweep time at scale: BNG_NAT_SCALE=1 go test -run NATSweepScale -v
func TestPPPoENATSweepScale(t *testing.T) {
	if os.Getenv("BNG_NAT_SCALE") == "" {
		t.Skip("set BNG_NAT_SCALE=1")
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	d, err := NewPPPoEDataplane(testPPPoEObject, PPPoEDataplaneOptions{NATMappings: 1 << 20}, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	// 1000 subscribers x 500 mappings
	const subs, per = 1000, 500
	var outK, inK []natKey
	var outV, inV []natMapping
	var ts unix.Timespec
	unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	now := uint64(ts.Nano())
	for s := 0; s < subs; s++ {
		priv := [4]byte{100, 64, byte(s >> 8), byte(s)}
		pub := [4]byte{198, 18, 0, byte(s / 63)}
		start := uint16(1024 + (s%63)*1024)
		if err := d.SetSubscriberNAT(net.IP(priv[:]), PPPoENATBlock{PublicIP: net.IP(pub[:]), PortStart: start, PortCount: 1024, Gen: uint32(s + 1)}); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < per; i++ {
			var pp, up [2]byte
			binary.BigEndian.PutUint16(pp[:], uint16(10000+i))
			binary.BigEndian.PutUint16(up[:], start+uint16(i))
			outK = append(outK, natKey{Addr: priv, Port: pp, Proto: protoUDP})
			outV = append(outV, natMapping{Addr: pub, Port: up, Gen: uint32(s + 1), LastSeen: now})
			inK = append(inK, natKey{Addr: pub, Port: up, Proto: protoUDP})
			inV = append(inV, natMapping{Addr: priv, Port: pp, Gen: uint32(s + 1), LastSeen: now})
		}
	}
	if _, err := d.nat.out.BatchUpdate(outK, outV, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := d.nat.in.BatchUpdate(inK, inV, nil); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	res, err := d.ExpireNAT(DefaultNATTimeouts)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("sweep of %d mappings, nothing to delete: %v %+v", len(outK), time.Since(start), res)
	if res.Active != subs*per {
		t.Fatalf("active %d", res.Active)
	}

	// Half the subscribers leave
	for s := 0; s < subs; s += 2 {
		d.DeleteSubscriberNAT(net.IP([]byte{100, 64, byte(s >> 8), byte(s)}))
	}
	start = time.Now()
	res, err = d.ExpireNAT(DefaultNATTimeouts)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("sweep deleting half: %v %+v", time.Since(start), res)
	if res.Stale != subs*per/2 {
		t.Fatalf("stale %d", res.Stale)
	}
}
