package pppoe

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/codelaboratoryltd/bng/pkg/sub6"
)

// fakeDataplane records what the server installs
type fakeDataplane struct {
	sessions int
	prefixes map[string]bool
}

func (f *fakeDataplane) AddSession(*Session) error    { f.sessions++; return nil }
func (f *fakeDataplane) RemoveSession(*Session) error { f.sessions--; return nil }
func (f *fakeDataplane) SetRate(*Session, uint64, uint64) error {
	return nil
}
func (f *fakeDataplane) Counters(*Session) (Counters, error) { return Counters{}, nil }
func (f *fakeDataplane) AddIPv6(s *Session) error {
	for _, p := range []*net.IPNet{s.WANPrefix, s.PDPrefix} {
		if p != nil {
			f.prefixes[p.String()] = true
		}
	}
	return nil
}
func (f *fakeDataplane) RemoveIPv6(s *Session) error {
	for _, p := range []*net.IPNet{s.WANPrefix, s.PDPrefix} {
		if p != nil {
			delete(f.prefixes, p.String())
		}
	}
	return nil
}

func ipv6cpPacket(code, id uint8, opts ...LCPOption) []byte {
	return (&LCPPacket{Code: code, Identifier: id, Data: SerializeLCPOptions(opts)}).Serialize()
}

func ifID(id uint64) LCPOption {
	return ifIDOption(id)
}

// icmpv6Packet builds an IPv6 packet with an ICMPv6 message and its checksum
func icmpv6Packet(src, dst net.IP, hopLimit uint8, msg []byte) []byte {
	pkt := make([]byte, 40+len(msg))
	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:], uint16(len(msg)))
	pkt[6], pkt[7] = 58, hopLimit
	copy(pkt[8:], src.To16())
	copy(pkt[24:], dst.To16())
	copy(pkt[40:], msg)
	var sum uint32
	add := func(b []byte) {
		for i := 0; i+1 < len(b); i += 2 {
			sum += uint32(binary.BigEndian.Uint16(b[i:]))
		}
	}
	add(pkt[8:40])
	sum += uint32(len(msg)) + 58
	add(pkt[40:])
	for sum > 0xffff {
		sum = sum&0xffff + sum>>16
	}
	binary.BigEndian.PutUint16(pkt[42:], ^uint16(sum))
	return pkt
}

func TestIPv6CPAndPrefixes(t *testing.T) {
	s, sock, session := newTestServer(t)
	wan, _ := sub6.NewPrefixPool("2001:db8:100::/48", 64)
	pd, _ := sub6.NewPrefixPool("2001:db8:200::/48", 64)
	s.SetIPv6(&IPv6{WANPool: wan, PDPool: pd, Responder: sub6.NewResponder(sub6.Config{
		ServerDUID: sub6.DUIDFromMAC(net.HardwareAddr{0, 0x11, 0x22, 0x33, 0x44, 0x55}),
		MTU:        1492,
	})})
	dp := &fakeDataplane{prefixes: make(map[string]bool)}
	s.SetDataplane(dp)
	send := func(proto uint16, ppp []byte) {
		s.handleFrame(sessionFrame(session.ServerMAC, session.ClientMAC, session.ID, proto, ppp))
	}

	session.SetState(StateIPCPNegotiation)
	s.startIPCPNegotiation(session)
	if countSent(sock, ProtocolIPv6CP, LCPCodeConfigRequest) != 1 {
		t.Fatal("no IPv6CP Configure-Request alongside IPCP")
	}

	// A zero interface identifier is nak'ed, a usable one acked
	send(ProtocolIPv6CP, ipv6cpPacket(LCPCodeConfigRequest, 1, ifID(0)))
	if countSent(sock, ProtocolIPv6CP, LCPCodeConfigNak) != 1 {
		t.Fatal("zero interface identifier not nak'ed")
	}
	const peerID = 0x0200_00ff_fe00_0001
	send(ProtocolIPv6CP, ipv6cpPacket(LCPCodeConfigRequest, 2, ifID(peerID)))
	send(ProtocolIPv6CP, ipv6cpPacket(LCPCodeConfigAck, 1, ifID(session.localIfID)))
	if countSent(sock, ProtocolIPv6CP, LCPCodeConfigAck) != 1 || session.ipv6Up {
		t.Fatal("IPv6 must wait for IPCP")
	}

	// IPCP completes: IPv6 comes up with both prefixes and an RA
	send(ProtocolIPCP, ipv6cpPacket(LCPCodeConfigAck, 3))
	if !session.ipv6Up || session.WANPrefix == nil || session.PDPrefix == nil {
		t.Fatalf("IPv6 not up: %v %v", session.WANPrefix, session.PDPrefix)
	}
	if !dp.prefixes[session.WANPrefix.String()] || !dp.prefixes[session.PDPrefix.String()] {
		t.Fatalf("data plane prefixes %v", dp.prefixes)
	}
	if countSent(sock, ProtocolIPv6, 0x60) != 1 {
		t.Fatal("no RA when IPv6 came up")
	}

	// A Router Solicitation is answered
	peerLL := sub6.LinkLocal(peerID)
	send(ProtocolIPv6, icmpv6Packet(peerLL, net.ParseIP("ff02::2"), 255, []byte{133, 0, 0, 0, 0, 0, 0, 0}))
	protos, payloads := sentPPP(sock)
	last := payloads[len(payloads)-1]
	if protos[len(protos)-1] != ProtocolIPv6 || last[40] != 134 || !net.IP(last[24:40]).Equal(peerLL) {
		t.Fatalf("RS not answered with an RA to %v", peerLL)
	}

	// The prefixes go back to the pools with the session
	wanPrefix := session.WANPrefix
	s.endSession(session, 0)
	if len(dp.prefixes) != 0 {
		t.Fatalf("prefixes left in the data plane: %v", dp.prefixes)
	}
	if used, _ := wan.Usage(); used != 0 {
		t.Fatalf("WAN prefix %v not released", wanPrefix)
	}
}

// RADIUS prefixes win over the pools
func TestIPv6PrefixesFromRADIUS(t *testing.T) {
	s, _, session := newTestServer(t)
	wan, _ := sub6.NewPrefixPool("2001:db8:100::/48", 64)
	s.SetIPv6(&IPv6{WANPool: wan, Responder: sub6.NewResponder(sub6.Config{ServerDUID: []byte{0, 3, 0, 1, 1, 2, 3, 4, 5, 6}})})
	_, framed, _ := net.ParseCIDR("2001:db8:100:77::/64")
	_, delegated, _ := net.ParseCIDR("2001:db8:999:1::/64")
	session.FramedIPv6Prefix, session.DelegatedIPv6Prefix = framed, delegated
	session.SetState(StateEstablished)
	session.ipv6cpLocalAcked, session.ipv6cpPeerAcked = true, true

	s.maybeIPv6Up(session)
	if session.WANPrefix.String() != framed.String() || session.PDPrefix.String() != delegated.String() {
		t.Fatalf("got %v %v", session.WANPrefix, session.PDPrefix)
	}
	// The RADIUS WAN prefix is taken out of the pool
	if err := wan.Reserve("other", framed); err == nil {
		t.Fatal("RADIUS prefix still free in the pool")
	}

	// DHCPv6 delegates the RADIUS prefix
	if sub := s.subscriber6(session); sub.PD.String() != delegated.String() {
		t.Fatalf("subscriber PD %v", sub.PD)
	}
}

// Without IPv6, IPv6CP is rejected so the peer stops
func TestIPv6CPRejectedWithoutIPv6(t *testing.T) {
	s, sock, session := newTestServer(t)
	session.SetState(StateIPCPNegotiation)
	s.handleFrame(sessionFrame(session.ServerMAC, session.ClientMAC, session.ID, ProtocolIPv6CP,
		ipv6cpPacket(LCPCodeConfigRequest, 1, ifID(42))))
	if countSent(sock, ProtocolLCP, LCPCodeProtoReject) != 1 {
		t.Fatal("no LCP Protocol-Reject for IPv6CP")
	}
}

// A peer without IPv6 rejects IPv6CP: no more IPv6CP is sent
func TestIPv6CPProtocolReject(t *testing.T) {
	s, sock, session := newTestServer(t)
	wan, _ := sub6.NewPrefixPool("2001:db8:100::/48", 64)
	s.SetIPv6(&IPv6{WANPool: wan, Responder: sub6.NewResponder(sub6.Config{ServerDUID: []byte{0, 3, 0, 1, 1, 2, 3, 4, 5, 6}})})
	session.SetState(StateIPCPNegotiation)
	s.startIPCPNegotiation(session)

	_, payloads := sentPPP(sock)
	var ipv6cpReq []byte
	protos, _ := sentPPP(sock)
	for i, p := range protos {
		if p == ProtocolIPv6CP {
			ipv6cpReq = payloads[i]
		}
	}
	rej := make([]byte, 2, 2+len(ipv6cpReq))
	binary.BigEndian.PutUint16(rej, ProtocolIPv6CP)
	rej = append(rej, ipv6cpReq...)
	s.handleFrame(sessionFrame(session.ServerMAC, session.ClientMAC, session.ID, ProtocolLCP,
		(&LCPPacket{Code: LCPCodeProtoReject, Identifier: 9, Data: rej}).Serialize()))

	for i := 1; i <= maxConfigure; i++ {
		s.retransmitIPv6CP(session, time.Now().Add(time.Duration(i)*restartInterval))
	}
	if n := countSent(sock, ProtocolIPv6CP, LCPCodeConfigRequest); n != 1 {
		t.Fatalf("sent %d IPv6CP requests after Protocol-Reject, want only the first", n)
	}
	if s.GetStats()["ipv6cp_rejected"] != 1 {
		t.Fatal("rejection not counted")
	}
}
