package pppoe

// IPv6 for PPPoE sessions (dual stack): IPv6CP (RFC 5072) negotiates
// interface identifiers, then the session gets a WAN /64 advertised in
// Router Advertisements (SLAAC) and a prefix delegated with DHCPv6, from the
// pools or from RADIUS. IPv6 comes up once both IPCP and IPv6CP are open;
// the data plane forwards it, and link-local/multicast traffic (RS, DHCPv6)
// reaches handleIPv6Packet.

import (
	"crypto/rand"
	"encoding/binary"
	"net"
	"time"

	"github.com/codelaboratoryltd/bng/pkg/radius"
	"github.com/codelaboratoryltd/bng/pkg/sub6"
	"go.uber.org/zap"
)

// IPv6 enables dual stack for PPPoE sessions
type IPv6 struct {
	WANPool   *sub6.PrefixPool // WAN /64 per session, advertised for SLAAC (nil = none)
	PDPool    *sub6.PrefixPool // Prefix delegated per session (nil = none)
	Responder *sub6.Responder
	// RAInterval between unsolicited Router Advertisements (default 10
	// minutes); keep it well below the router lifetime
	RAInterval time.Duration
}

// SetIPv6 enables IPv6 for new sessions. Without it IPv6CP is rejected.
func (s *Server) SetIPv6(v *IPv6) {
	if v.RAInterval == 0 {
		v.RAInterval = 10 * time.Minute
	}
	s.ipv6 = v
}

// randomIfID returns a random interface identifier that is not 0 and not
// avoid
func randomIfID(avoid uint64) uint64 {
	var b [8]byte
	for {
		rand.Read(b[:])
		id := binary.BigEndian.Uint64(b[:])
		if id != 0 && id != avoid {
			return id
		}
	}
}

func ifIDOption(id uint64) LCPOption {
	data := make([]byte, 8)
	binary.BigEndian.PutUint64(data, id)
	return LCPOption{Type: IPV6CPOptInterfaceID, Data: data}
}

// startIPv6CP opens IPv6CP alongside IPCP once the session is authenticated
func (s *Server) startIPv6CP(session *Session) {
	if s.ipv6 == nil || session.ipv6cpStarted {
		return
	}
	session.ipv6cpStarted = true
	session.ipv6cpRetries = 0
	session.localIfID = randomIfID(0)
	s.sendIPv6CPConfigRequest(session)
}

func (s *Server) sendIPv6CPConfigRequest(session *Session) {
	session.ipv6cpSentAt = time.Now()
	pkt := &LCPPacket{
		Code:       LCPCodeConfigRequest,
		Identifier: session.NextLCPIdentifier(),
		Data:       SerializeLCPOptions([]LCPOption{ifIDOption(session.localIfID)}),
	}
	s.sendPPPPacket(session, ProtocolIPv6CP, pkt.Serialize())
}

// retransmitIPv6CP resends our IPv6CP Configure-Request; after
// maxConfigure tries the session stays IPv4-only
func (s *Server) retransmitIPv6CP(session *Session, now time.Time) {
	if !session.ipv6cpStarted || session.ipv6cpLocalAcked || now.Sub(session.ipv6cpSentAt) < restartInterval {
		return
	}
	if session.ipv6cpRetries >= maxConfigure {
		session.ipv6cpStarted = false
		s.logger.Info("IPv6CP not answered, session stays IPv4-only", zap.Uint16("session_id", session.ID))
		return
	}
	session.ipv6cpRetries++
	s.sendIPv6CPConfigRequest(session)
}

// handleIPv6CP handles IPv6CP packets; without IPv6 the protocol is
// rejected so the peer stops trying
func (s *Server) handleIPv6CP(session *Session, data []byte) {
	if s.ipv6 == nil {
		s.sendProtocolReject(session, ProtocolIPv6CP, data)
		return
	}
	pkt, err := ParseLCPPacket(data)
	if err != nil {
		return
	}
	switch pkt.Code {
	case LCPCodeConfigRequest:
		s.handleIPv6CPConfigRequest(session, pkt)
	case LCPCodeConfigAck:
		session.ipv6cpLocalAcked = true
	case LCPCodeConfigNak:
		// The peer suggests another identifier for us
		if opts, err := ParseLCPOptions(pkt.Data); err == nil {
			for _, opt := range opts {
				if opt.Type == IPV6CPOptInterfaceID && len(opt.Data) == 8 {
					if id := binary.BigEndian.Uint64(opt.Data); id != 0 && id != session.peerIfID {
						session.localIfID = id
					} else {
						session.localIfID = randomIfID(session.peerIfID)
					}
				}
			}
		}
		s.sendIPv6CPConfigRequest(session)
	case LCPCodeConfigReject:
		// The peer will not have an interface identifier from us: no IPv6
		session.ipv6cpStarted = false
	case LCPCodeTermRequest:
		ack := &LCPPacket{Code: LCPCodeTermAck, Identifier: pkt.Identifier}
		s.sendPPPPacket(session, ProtocolIPv6CP, ack.Serialize())
		s.ipv6Down(session)
		session.ipv6cpLocalAcked, session.ipv6cpPeerAcked = false, false
		return
	}
	s.maybeIPv6Up(session)
}

// handleIPv6CPConfigRequest acks a usable interface identifier, naks a
// missing, zero or clashing one and rejects every other option
func (s *Server) handleIPv6CPConfigRequest(session *Session, pkt *LCPPacket) {
	opts, err := ParseLCPOptions(pkt.Data)
	if err != nil {
		return
	}
	var nak, reject []LCPOption
	sawIfID := false
	for _, opt := range opts {
		if opt.Type != IPV6CPOptInterfaceID || len(opt.Data) != 8 {
			reject = append(reject, opt)
			continue
		}
		sawIfID = true
		id := binary.BigEndian.Uint64(opt.Data)
		if id == 0 || id == session.localIfID {
			nak = append(nak, ifIDOption(randomIfID(session.localIfID)))
			continue
		}
		session.peerIfID = id
	}
	if !sawIfID && len(reject) == 0 {
		nak = append(nak, ifIDOption(randomIfID(session.localIfID)))
	}

	resp := &LCPPacket{Identifier: pkt.Identifier}
	switch {
	case len(reject) > 0:
		resp.Code, resp.Data = LCPCodeConfigReject, SerializeLCPOptions(reject)
	case len(nak) > 0:
		resp.Code, resp.Data = LCPCodeConfigNak, SerializeLCPOptions(nak)
	default:
		resp.Code, resp.Data = LCPCodeConfigAck, pkt.Data
		session.ipv6cpPeerAcked = true
		// The peer may open IPv6CP before we have sent ours
		if st := session.GetState(); !session.ipv6cpStarted && (st == StateIPCPNegotiation || st == StateEstablished) {
			s.startIPv6CP(session)
		}
	}
	s.sendPPPPacket(session, ProtocolIPv6CP, resp.Serialize())
}

// sendProtocolReject rejects a PPP protocol (RFC 1661 5.7)
func (s *Server) sendProtocolReject(session *Session, protocol uint16, data []byte) {
	if session.GetState() < StateAuthentication {
		return
	}
	body := make([]byte, 2, 2+len(data))
	binary.BigEndian.PutUint16(body, protocol)
	body = append(body, data...)
	// Keep the reply within the peer's MRU
	if max := 1400; len(body) > max {
		body = body[:max]
	}
	pkt := &LCPPacket{Code: LCPCodeProtoReject, Identifier: session.NextLCPIdentifier(), Data: body}
	s.sendPPPPacket(session, ProtocolLCP, pkt.Serialize())
}

// maybeIPv6Up brings IPv6 up once IPCP and IPv6CP are both open
func (s *Server) maybeIPv6Up(session *Session) {
	if s.ipv6 == nil || session.ipv6Up || !session.ipv6cpLocalAcked || !session.ipv6cpPeerAcked ||
		!session.IsEstablished() {
		return
	}

	// Prefixes: from RADIUS if it sent them, else from the pools
	assign := func(pool *sub6.PrefixPool, fromRADIUS *net.IPNet, what string) *net.IPNet {
		if fromRADIUS != nil {
			if pool != nil {
				if err := pool.Reserve(session.SessionID, fromRADIUS); err != nil {
					s.logger.Warn("RADIUS IPv6 prefix not usable",
						zap.Uint16("session_id", session.ID),
						zap.String("prefix", fromRADIUS.String()),
						zap.String("kind", what),
						zap.Error(err),
					)
					return nil
				}
			}
			return fromRADIUS
		}
		if pool == nil {
			return nil
		}
		p, err := pool.Allocate(session.SessionID)
		if err != nil {
			s.logger.Warn("No IPv6 prefix for session",
				zap.Uint16("session_id", session.ID),
				zap.String("kind", what),
				zap.Error(err),
			)
			return nil
		}
		return p
	}
	session.WANPrefix = assign(s.ipv6.WANPool, session.FramedIPv6Prefix, "wan")
	session.PDPrefix = assign(s.ipv6.PDPool, session.DelegatedIPv6Prefix, "pd")
	if session.WANPrefix == nil && session.PDPrefix == nil {
		s.releaseIPv6(session)
		return
	}

	if s.dataplane != nil {
		if err := s.dataplane.AddIPv6(session); err != nil {
			s.logger.Error("Failed to add IPv6 prefixes to the data plane",
				zap.Uint16("session_id", session.ID),
				zap.Error(err),
			)
			s.releaseIPv6(session)
			return
		}
	}
	session.ipv6Up = true
	s.logger.Info("PPPoE session IPv6 up",
		zap.Uint16("session_id", session.ID),
		zap.String("username", session.Username),
		zap.Stringer("wan_prefix", session.WANPrefix),
		zap.Stringer("delegated_prefix", session.PDPrefix),
	)

	s.sendRA(session)
	// Tell RADIUS about the prefixes now rather than at the next interim
	if session.acctStarted {
		s.sendAccounting(session, radius.AcctStatusInterimUpdate, 0, nil)
	}
}

// ipv6Down takes the session's IPv6 prefixes away
func (s *Server) ipv6Down(session *Session) {
	if !session.ipv6Up {
		return
	}
	if s.dataplane != nil {
		if err := s.dataplane.RemoveIPv6(session); err != nil {
			s.logger.Warn("Failed to remove IPv6 prefixes from the data plane",
				zap.Uint16("session_id", session.ID),
				zap.Error(err),
			)
		}
	}
	session.ipv6Up = false
	s.releaseIPv6(session)
}

func (s *Server) releaseIPv6(session *Session) {
	if s.ipv6 == nil {
		return
	}
	if s.ipv6.WANPool != nil {
		s.ipv6.WANPool.Release(session.SessionID)
	}
	if s.ipv6.PDPool != nil {
		s.ipv6.PDPool.Release(session.SessionID)
	}
	session.WANPrefix, session.PDPrefix = nil, nil
}

func (s *Server) subscriber6(session *Session) *sub6.Subscriber {
	return &sub6.Subscriber{
		WAN:      session.WANPrefix,
		PD:       session.PDPrefix,
		RouterIP: sub6.LinkLocal(session.localIfID),
	}
}

// sendRA sends an unsolicited Router Advertisement to the peer
func (s *Server) sendRA(session *Session) {
	ra := s.ipv6.Responder.RouterAdvertisement(s.subscriber6(session), sub6.LinkLocal(session.peerIfID))
	s.sendPPPPacket(session, ProtocolIPv6, ra)
	session.nextRA = time.Now().Add(s.ipv6.RAInterval)
}

// handleIPv6Packet answers the IPv6 control traffic the data plane passes
// up: Router Solicitations and DHCPv6
func (s *Server) handleIPv6Packet(session *Session, data []byte) {
	if s.ipv6 == nil || !session.ipv6Up {
		return
	}
	if reply := s.ipv6.Responder.Handle(data, s.subscriber6(session)); reply != nil {
		s.sendPPPPacket(session, ProtocolIPv6, reply)
	}
}
