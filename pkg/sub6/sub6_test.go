package sub6

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"

	"github.com/codelaboratoryltd/bng/pkg/dhcpv6"
)

func mustCIDR(t *testing.T, s string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestPrefixPool(t *testing.T) {
	p, err := NewPrefixPool("2001:db8:100::/62", 64) // 4 prefixes
	if err != nil {
		t.Fatal(err)
	}
	a, _ := p.Allocate("a")
	b, _ := p.Allocate("b")
	if a.String() != "2001:db8:100::/64" || b.String() != "2001:db8:100:1::/64" {
		t.Fatalf("got %v %v", a, b)
	}
	if again, _ := p.Allocate("a"); again.String() != a.String() {
		t.Fatal("second Allocate changed the prefix")
	}

	// RADIUS: a free prefix of the pool, one in use, one outside the pool
	if err := p.Reserve("c", mustCIDR(t, "2001:db8:100:3::/64")); err != nil {
		t.Fatal(err)
	}
	if err := p.Reserve("d", mustCIDR(t, "2001:db8:100:1::/64")); err == nil {
		t.Fatal("reserved a prefix in use")
	}
	if err := p.Reserve("e", mustCIDR(t, "2001:db8:999::/64")); err != nil {
		t.Fatal(err)
	}

	// 2001:db8:100:2::/64 was skipped by the reservation and is left
	if d, _ := p.Allocate("d"); d.String() != "2001:db8:100:2::/64" {
		t.Fatalf("got %v", d)
	}
	if _, err := p.Allocate("f"); err == nil {
		t.Fatal("allocated from a full pool")
	}
	p.Release("a")
	if f, _ := p.Allocate("f"); f.String() != a.String() {
		t.Fatalf("got %v after releasing %v", f, a)
	}
	if used, total := p.Usage(); used != 4 || total != 4 {
		t.Fatalf("usage %d/%d", used, total)
	}

	if _, err := NewPrefixPool("2001:db8::/64", 64); err == nil {
		t.Fatal("accepted a pool no larger than its prefixes")
	}
	pd, err := NewPrefixPool("2001:db8:200::/40", 56)
	if err != nil {
		t.Fatal(err)
	}
	if x, _ := pd.Allocate("x"); x.String() != "2001:db8:200::/56" {
		t.Fatalf("got %v", x)
	}
	if y, _ := pd.Allocate("y"); y.String() != "2001:db8:200:100::/56" {
		t.Fatalf("got %v", y)
	}
}

var (
	testRouterLL = LinkLocal(0x0200_00ff_fe00_0001)
	testClientLL = net.ParseIP("fe80::2")
	testDNS      = net.ParseIP("2001:4860:4860::8888")
)

func testResponder(t *testing.T) (*Responder, *Subscriber) {
	t.Helper()
	r := NewResponder(Config{
		DNS:               []net.IP{testDNS},
		ServerDUID:        DUIDFromMAC(net.HardwareAddr{2, 0, 0, 0, 0, 0xfe}),
		PreferredLifetime: 3600,
		ValidLifetime:     7200,
		MTU:               1492,
	})
	return r, &Subscriber{
		WAN:      mustCIDR(t, "2001:db8:100:5::/64"),
		PD:       mustCIDR(t, "2001:db8:200:5::/64"),
		RouterIP: testRouterLL,
	}
}

func TestRouterSolicitation(t *testing.T) {
	r, sub := testResponder(t)
	rs := buildIPv6(testClientLL, net.ParseIP("ff02::2"), protoICMPv6, 255, []byte{icmpRouterSolicit, 0, 0, 0, 0, 0, 0, 0})
	out := r.Handle(rs, sub)
	p, ok := parseIPv6(out)
	if !ok || !p.validChecksum() {
		t.Fatalf("invalid RA %x", out)
	}
	if !p.src.Equal(testRouterLL) || !p.dst.Equal(testClientLL) || p.hopLimit != 255 || p.payload[0] != icmpRouterAdvert {
		t.Fatalf("RA %v -> %v hop %d type %d", p.src, p.dst, p.hopLimit, p.payload[0])
	}
	if p.payload[5] != 0x40 {
		t.Fatalf("flags %#x, want O only", p.payload[5])
	}
	var prefix, mtu, rdnss bool
	for opts := p.payload[16:]; len(opts) >= 8; opts = opts[int(opts[1])*8:] {
		switch opts[0] {
		case 3:
			prefix = opts[2] == 64 && opts[3] == 0xc0 && net.IP(opts[16:32]).Equal(sub.WAN.IP)
		case 5:
			mtu = binary.BigEndian.Uint32(opts[4:]) == 1492
		case 25:
			rdnss = net.IP(opts[8:24]).Equal(testDNS)
		}
	}
	if !prefix || !mtu || !rdnss {
		t.Fatalf("options: prefix %v mtu %v rdnss %v", prefix, mtu, rdnss)
	}

	// Not a valid RS: wrong hop limit
	if out := r.Handle(buildIPv6(testClientLL, net.ParseIP("ff02::2"), protoICMPv6, 64,
		[]byte{icmpRouterSolicit, 0, 0, 0, 0, 0, 0, 0}), sub); out != nil {
		t.Fatal("answered an RS with hop limit 64")
	}
}

func dhcpv6Request(t *testing.T, msgType uint8, opts ...dhcpv6.Option) []byte {
	t.Helper()
	m := &dhcpv6.Message{Type: msgType, TransactionID: [3]byte{1, 2, 3}, Options: append([]dhcpv6.Option{
		dhcpv6.MakeClientIDOption(DUIDFromMAC(net.HardwareAddr{2, 0, 0, 0, 0, 1})),
	}, opts...)}
	return buildIPv6(testClientLL, allDHCPAgents, protoUDP, 1, udpDatagram(dhcpv6ClientPort, dhcpv6ServerPort, m.Serialize()))
}

func dhcpv6Answer(t *testing.T, r *Responder, sub *Subscriber, req []byte) *dhcpv6.Message {
	t.Helper()
	out := r.Handle(req, sub)
	p, ok := parseIPv6(out)
	if !ok || !p.validChecksum() || p.next != protoUDP {
		t.Fatalf("invalid reply %x", out)
	}
	if binary.BigEndian.Uint16(p.payload[0:]) != dhcpv6ServerPort || binary.BigEndian.Uint16(p.payload[2:]) != dhcpv6ClientPort ||
		!p.dst.Equal(testClientLL) || !p.src.Equal(testRouterLL) {
		t.Fatalf("reply addressing %v -> %v", p.src, p.dst)
	}
	m, err := dhcpv6.ParseMessage(p.payload[8:])
	if err != nil {
		t.Fatal(err)
	}
	if m.TransactionID != [3]byte{1, 2, 3} {
		t.Fatal("transaction ID")
	}
	return m
}

func delegated(t *testing.T, m *dhcpv6.Message) *net.IPNet {
	t.Helper()
	opt := m.GetOption(dhcpv6.OptIAPD)
	if opt == nil {
		return nil
	}
	ia, err := dhcpv6.ParseIAPD(opt.Data)
	if err != nil || ia.IAID != 7 {
		t.Fatalf("IA_PD %+v %v", ia, err)
	}
	for _, o := range ia.Options {
		if o.Code == dhcpv6.OptIAPrefix {
			p, _ := dhcpv6.ParseIAPrefix(o.Data)
			return &net.IPNet{IP: p.Prefix, Mask: net.CIDRMask(int(p.PrefixLength), 128)}
		}
	}
	return nil
}

func TestDHCPv6PrefixDelegation(t *testing.T) {
	r, sub := testResponder(t)
	iapd := dhcpv6.MakeIAPDOption(&dhcpv6.IAPD{IAID: 7})

	adv := dhcpv6Answer(t, r, sub, dhcpv6Request(t, dhcpv6.MsgTypeSolicit, iapd))
	if adv.Type != dhcpv6.MsgTypeAdvertise {
		t.Fatalf("type %d, want Advertise", adv.Type)
	}
	if pd := delegated(t, adv); pd == nil || pd.String() != sub.PD.String() {
		t.Fatalf("delegated %v", pd)
	}
	if dns := adv.GetOption(dhcpv6.OptDNSServers); dns == nil || !net.IP(dns.Data).Equal(testDNS) {
		t.Fatal("no DNS servers")
	}

	// Rapid commit: Reply straight away
	rc := dhcpv6Answer(t, r, sub, dhcpv6Request(t, dhcpv6.MsgTypeSolicit, iapd, dhcpv6.Option{Code: dhcpv6.OptRapidCommit}))
	if rc.Type != dhcpv6.MsgTypeReply || rc.GetOption(dhcpv6.OptRapidCommit) == nil {
		t.Fatalf("rapid commit: type %d", rc.Type)
	}

	serverID := dhcpv6.Option{Code: dhcpv6.OptServerID, Data: r.cfg.ServerDUID}
	for _, typ := range []uint8{dhcpv6.MsgTypeRequest, dhcpv6.MsgTypeRenew, dhcpv6.MsgTypeRebind} {
		rep := dhcpv6Answer(t, r, sub, dhcpv6Request(t, typ, iapd, serverID))
		if rep.Type != dhcpv6.MsgTypeReply || delegated(t, rep).String() != sub.PD.String() {
			t.Fatalf("type %d: reply %d", typ, rep.Type)
		}
	}

	// For another server: ignored
	other := dhcpv6.Option{Code: dhcpv6.OptServerID, Data: []byte{0, 3, 0, 1, 9, 9, 9, 9, 9, 9}}
	if out := r.Handle(dhcpv6Request(t, dhcpv6.MsgTypeRequest, iapd, other), sub); out != nil {
		t.Fatal("answered a Request for another server")
	}

	// IA_NA: no addresses, SLAAC is used
	na := dhcpv6Answer(t, r, sub, dhcpv6Request(t, dhcpv6.MsgTypeSolicit,
		dhcpv6.MakeIANAOption(&dhcpv6.IANA{IAID: 3})))
	ia, _ := dhcpv6.ParseIANA(na.GetOption(dhcpv6.OptIANA).Data)
	if len(ia.Options) != 1 || ia.Options[0].Code != dhcpv6.OptStatusCode ||
		binary.BigEndian.Uint16(ia.Options[0].Data) != dhcpv6.StatusNoAddrsAvail {
		t.Fatalf("IA_NA %+v", ia)
	}

	// Without a prefix to delegate
	sub.PD = nil
	np := dhcpv6Answer(t, r, sub, dhcpv6Request(t, dhcpv6.MsgTypeSolicit, iapd))
	pdOpt, _ := dhcpv6.ParseIAPD(np.GetOption(dhcpv6.OptIAPD).Data)
	if !bytes.Equal(pdOpt.Options[0].Data[:2], []byte{0, dhcpv6.StatusNoPrefixAvail}) {
		t.Fatalf("IA_PD without prefix %+v", pdOpt)
	}
}

func TestIsControl(t *testing.T) {
	for _, c := range []struct {
		src, dst string
		want     bool
	}{
		{"fe80::2", "ff02::2", true},
		{"fe80::2", "fe80::1", true},
		{"2001:db8:100:5::2", "ff02::1:2", true},
		{"2001:db8:100:5::2", "2001:4860:4860::8888", false},
	} {
		pkt := buildIPv6(net.ParseIP(c.src), net.ParseIP(c.dst), protoUDP, 64, udpDatagram(1, 2, nil))
		if got := IsControl(pkt); got != c.want {
			t.Errorf("%s -> %s: %v", c.src, c.dst, got)
		}
	}
}
