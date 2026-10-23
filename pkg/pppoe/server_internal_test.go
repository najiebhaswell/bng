package pppoe

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"go.uber.org/zap"
)

// fakeSocket records sent frames instead of writing to the wire
type fakeSocket struct {
	sent [][]byte
}

func (f *fakeSocket) open(string, uint16) error { return nil }
func (f *fakeSocket) close() error              { return nil }
func (f *fakeSocket) recv([]byte) (int, error)  { return 0, nil }
func (f *fakeSocket) send(_ string, _ net.HardwareAddr, _ uint16, data []byte) error {
	f.sent = append(f.sent, data)
	return nil
}

func newTestServer(t *testing.T) (*Server, *fakeSocket, *Session) {
	t.Helper()
	serverMAC, _ := net.ParseMAC("00:11:22:33:44:55")
	clientMAC, _ := net.ParseMAC("02:00:00:00:00:01")
	s, err := NewServerWithInterface(ServerConfig{
		Interface:    "eth0",
		ServerIP:     "10.0.0.1",
		ClientPool:   "10.0.0.0/24",
		PoolGateway:  "10.0.0.1",
		PrimaryDNS:   "8.8.8.8",
		SecondaryDNS: "8.8.4.4",
	}, zap.NewNop(), &net.Interface{Name: "eth0", HardwareAddr: serverMAC})
	if err != nil {
		t.Fatal(err)
	}
	sock := &fakeSocket{}
	s.socket = sock
	s.sessionSocket = sock

	session, err := s.sessions.CreateSession(clientMAC, serverMAC)
	if err != nil {
		t.Fatal(err)
	}
	return s, sock, session
}

// sessionFrame builds an Ethernet frame carrying a PPP packet in a PPPoE session
func sessionFrame(dst, src net.HardwareAddr, sessionID, protocol uint16, ppp []byte) []byte {
	payload := make([]byte, 2+len(ppp))
	binary.BigEndian.PutUint16(payload, protocol)
	copy(payload[2:], ppp)
	hdr := &PPPoEHeader{VerType: 0x11, Code: CodeSession, SessionID: sessionID, Length: uint16(len(payload))}
	return BuildEthernetFrame(dst, src, EtherTypePPPoESession, append(hdr.Serialize(), payload...))
}

// lastIPCPCode returns the IPCP code of the last frame the server sent
func lastIPCPCode(t *testing.T, sock *fakeSocket) uint8 {
	t.Helper()
	if len(sock.sent) == 0 {
		t.Fatal("server sent nothing")
	}
	frame := sock.sent[len(sock.sent)-1]
	if proto := binary.BigEndian.Uint16(frame[20:22]); proto != ProtocolIPCP {
		t.Fatalf("last frame protocol = 0x%04x, want IPCP", proto)
	}
	return frame[22]
}

// Session frames arrive on a separate EtherType from discovery; the server
// must dispatch them to the PPP handlers.
func TestHandleFrameDispatchesSessionFrames(t *testing.T) {
	s, sock, session := newTestServer(t)

	echo := (&LCPPacket{Code: LCPCodeEchoRequest, Identifier: 7, Data: []byte{0, 0, 0, 0}}).Serialize()
	s.handleFrame(sessionFrame(s.serverMAC, session.ClientMAC, session.ID, ProtocolLCP, echo))

	if len(sock.sent) != 1 {
		t.Fatalf("sent %d frames, want 1 echo reply", len(sock.sent))
	}
	if code := sock.sent[0][22]; code != LCPCodeEchoReply {
		t.Fatalf("reply code = %d, want Echo-Reply", code)
	}
}

// A client that repeats the NAKed values back must get a Configure-Ack,
// otherwise IPCP loops on NAKs and the session never comes up.
func TestIPCPAcksAssignedValues(t *testing.T) {
	s, sock, session := newTestServer(t)
	session.ClientIP = net.ParseIP("10.0.0.2")

	request := func(ip, dns1, dns2 string) uint8 {
		opts := SerializeLCPOptions([]LCPOption{
			{Type: IPCPOptIPAddress, Data: net.ParseIP(ip).To4()},
			{Type: IPCPOptPrimaryDNS, Data: net.ParseIP(dns1).To4()},
			{Type: IPCPOptSecondaryDNS, Data: net.ParseIP(dns2).To4()},
		})
		s.handleIPCP(session, (&LCPPacket{Code: LCPCodeConfigRequest, Identifier: 1, Data: opts}).Serialize())
		return lastIPCPCode(t, sock)
	}

	if code := request("0.0.0.0", "0.0.0.0", "0.0.0.0"); code != LCPCodeConfigNak {
		t.Errorf("initial request: code = %d, want Configure-Nak", code)
	}
	if code := request("10.0.0.2", "8.8.8.8", "8.8.4.4"); code != LCPCodeConfigAck {
		t.Errorf("request with assigned values: code = %d, want Configure-Ack", code)
	}
}

// A PPPoE length field that disagrees with the frame must not panic.
func TestMalformedLengthDoesNotPanic(t *testing.T) {
	s, _, session := newTestServer(t)

	for _, length := range []uint16{0, 1, 0xffff} {
		frame := sessionFrame(s.serverMAC, session.ClientMAC, session.ID, ProtocolLCP, []byte{1, 1, 0, 4})
		binary.BigEndian.PutUint16(frame[18:20], length)
		s.handleFrame(frame)

		disc := BuildEthernetFrame(s.serverMAC, session.ClientMAC, EtherTypePPPoEDiscovery,
			(&PPPoEHeader{VerType: 0x11, Code: CodePADI, Length: length}).Serialize())
		s.handleFrame(disc)
	}
}

// sentPPP returns the PPP protocol and payload of every frame the server sent
func sentPPP(sock *fakeSocket) (protos []uint16, payloads [][]byte) {
	for _, f := range sock.sent {
		if binary.BigEndian.Uint16(f[12:14]) != EtherTypePPPoESession {
			continue
		}
		protos = append(protos, binary.BigEndian.Uint16(f[20:22]))
		payloads = append(payloads, f[22:])
	}
	return protos, payloads
}

func lcpNak(id uint8, opts ...LCPOption) []byte {
	return (&LCPPacket{Code: LCPCodeConfigNak, Identifier: id, Data: SerializeLCPOptions(opts)}).Serialize()
}

var chapMD5 = LCPOption{Type: LCPOptAuthProto, Data: []byte{0xC2, 0x23, CHAPAlgorithmMD5}}

// What BNG Blaster did in the lab: Nak our PAP request with CHAP-MD5. With
// pap-only config the server must give up instead of resending PAP forever.
func TestLCPNakForDisabledAuthTerminates(t *testing.T) {
	s, sock, session := newTestServer(t)
	session.AuthProto = ProtocolPAP

	s.handleLCP(session, lcpNak(1, chapMD5))

	if s.sessions.GetSession(session.ID) != nil {
		t.Fatal("session still present after unacceptable Nak")
	}
	last := sock.sent[len(sock.sent)-1]
	if binary.BigEndian.Uint16(last[12:14]) != EtherTypePPPoEDiscovery || last[15] != CodePADT {
		t.Fatal("last frame is not a PADT")
	}
}

// With "both", a Nak suggesting CHAP switches the request to CHAP.
func TestLCPNakSwitchesToCHAP(t *testing.T) {
	s, sock, session := newTestServer(t)
	s.authType = "both"
	session.AuthProto = ProtocolPAP

	s.handleLCP(session, lcpNak(1, chapMD5))

	protos, payloads := sentPPP(sock)
	if len(protos) != 1 || protos[0] != ProtocolLCP {
		t.Fatalf("sent %v, want one LCP Configure-Request", protos)
	}
	pkt, _ := ParseLCPPacket(payloads[0])
	opts, _ := ParseLCPOptions(pkt.Data)
	found := false
	for _, o := range opts {
		if o.Type == LCPOptAuthProto {
			found = binary.BigEndian.Uint16(o.Data) == ProtocolCHAP
		}
	}
	if pkt.Code != LCPCodeConfigRequest || !found {
		t.Fatalf("resent request %+v does not ask for CHAP", opts)
	}
}

// A peer that keeps Nak'ing (e.g. MRU) must not keep the server looping.
func TestLCPNakLoopIsBounded(t *testing.T) {
	s, _, session := newTestServer(t)
	mru := LCPOption{Type: LCPOptMRU, Data: []byte{0x05, 0xDC}}

	for i := 0; i <= maxLCPConfigNaks; i++ {
		s.handleLCP(session, lcpNak(uint8(i), mru))
	}
	if s.sessions.GetSession(session.ID) != nil {
		t.Fatal("session still present after endless Naks")
	}
}

// Full CHAP exchange: LCP opens both ways, server challenges, a valid
// response (no RADIUS: accept) gets Success and IPCP starts.
func TestCHAPFlow(t *testing.T) {
	s, sock, session := newTestServer(t)
	session.AuthProto = ProtocolCHAP
	session.SetState(StateLCPNegotiation)

	peerReq := (&LCPPacket{Code: LCPCodeConfigRequest, Identifier: 1,
		Data: SerializeLCPOptions([]LCPOption{{Type: LCPOptMagicNumber, Data: []byte{1, 2, 3, 4}}})}).Serialize()
	s.handleLCP(session, peerReq)
	s.handleLCP(session, (&LCPPacket{Code: LCPCodeConfigAck, Identifier: 1}).Serialize())

	if session.chapChallenge == nil {
		t.Fatal("no CHAP challenge after LCP opened")
	}

	name := []byte("user")
	resp := make([]byte, 5+16+len(name))
	resp[0] = CHAPCodeResponse
	resp[1] = session.chapID
	binary.BigEndian.PutUint16(resp[2:4], uint16(len(resp)))
	resp[4] = 16
	copy(resp[21:], name)
	s.handleCHAP(session, resp)

	protos, payloads := sentPPP(sock)
	n := len(protos)
	if n < 2 || protos[n-2] != ProtocolCHAP || payloads[n-2][0] != CHAPCodeSuccess {
		t.Fatalf("no CHAP Success sent: %v", protos)
	}
	if protos[n-1] != ProtocolIPCP || session.Username != "user" || session.GetState() != StateIPCPNegotiation {
		t.Fatalf("IPCP not started (state %v, user %q)", session.GetState(), session.Username)
	}
}

// countSent returns how many frames the server sent for a PPP protocol and code
func countSent(sock *fakeSocket, proto uint16, code uint8) int {
	protos, payloads := sentPPP(sock)
	n := 0
	for i, p := range protos {
		if p == proto && payloads[i][0] == code {
			n++
		}
	}
	return n
}

// A lost LCP Configure-Request is resent on the restart timer, and the
// session is given up after maxConfigure tries.
func TestRetransmitLCPConfigRequest(t *testing.T) {
	s, sock, session := newTestServer(t)
	session.SetState(StateLCPNegotiation)
	s.startLCPNegotiation(session)

	s.retransmit(time.Now())
	if n := countSent(sock, ProtocolLCP, LCPCodeConfigRequest); n != 1 {
		t.Fatalf("resent before the restart timer expired: %d requests", n)
	}

	for i := 0; i < maxConfigure; i++ {
		s.retransmit(time.Now().Add(restartInterval))
	}
	if n := countSent(sock, ProtocolLCP, LCPCodeConfigRequest); n != 1+maxConfigure {
		t.Fatalf("sent %d requests, want %d", n, 1+maxConfigure)
	}

	s.retransmit(time.Now().Add(restartInterval))
	if s.sessions.GetSession(session.ID) != nil {
		t.Fatal("session still present after maxConfigure retransmissions")
	}
}

// Once our request is acked, LCP must not be retransmitted.
func TestNoRetransmitAfterLCPAck(t *testing.T) {
	s, sock, session := newTestServer(t)
	session.SetState(StateLCPNegotiation)
	s.startLCPNegotiation(session)
	s.handleLCP(session, (&LCPPacket{Code: LCPCodeConfigAck, Identifier: 1}).Serialize())

	s.retransmit(time.Now().Add(restartInterval))
	if n := countSent(sock, ProtocolLCP, LCPCodeConfigRequest); n != 1 {
		t.Fatalf("sent %d requests after Ack, want 1", n)
	}
}

// A lost CHAP Challenge is resent with a new identifier; a response to the
// new one completes authentication.
func TestRetransmitCHAPChallenge(t *testing.T) {
	s, sock, session := newTestServer(t)
	session.AuthProto = ProtocolCHAP
	session.SetState(StateAuthentication)
	s.sendCHAPChallenge(session)
	firstID := session.chapID

	s.retransmit(time.Now().Add(restartInterval))
	if n := countSent(sock, ProtocolCHAP, CHAPCodeChallenge); n != 2 || session.chapID == firstID {
		t.Fatalf("challenges sent = %d, id %d -> %d; want a second challenge with a new id", n, firstID, session.chapID)
	}
}

// A lost IPCP Configure-Request is resent without allocating another address.
func TestRetransmitIPCPKeepsAddress(t *testing.T) {
	s, sock, session := newTestServer(t)
	session.SetState(StateIPCPNegotiation)
	s.startIPCPNegotiation(session)
	ip := session.ClientIP

	s.retransmit(time.Now().Add(restartInterval))
	if n := countSent(sock, ProtocolIPCP, LCPCodeConfigRequest); n != 2 {
		t.Fatalf("sent %d IPCP requests, want 2", n)
	}
	if !session.ClientIP.Equal(ip) {
		t.Fatalf("client IP changed from %v to %v", ip, session.ClientIP)
	}
}

// A second PADR from the same MAC replaces the half-open session.
func TestPADRReplacesExistingSession(t *testing.T) {
	s, _, old := newTestServer(t)
	tags := []Tag{{Type: TagACCookie, Value: []byte("cookie")}}

	s.handlePADR(old.ClientMAC, tags)

	if s.sessions.GetSession(old.ID) != nil {
		t.Fatal("old session still present")
	}
	if cur := s.sessions.GetSessionByMAC(old.ClientMAC); cur == nil || cur.ID == old.ID {
		t.Fatal("no new session for the MAC")
	}
}
