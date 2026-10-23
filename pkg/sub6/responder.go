package sub6

import (
	"encoding/binary"
	"net"

	"github.com/codelaboratoryltd/bng/pkg/dhcpv6"
)

// Subscriber is what one subscriber gets over IPv6
type Subscriber struct {
	// WAN is the /64 its WAN interface autoconfigures from (SLAAC); nil
	// = no prefix in the RA
	WAN *net.IPNet
	// PD is the prefix delegated with DHCPv6 IA_PD; nil = none
	PD *net.IPNet
	// RouterIP is the BNG's link-local address on the subscriber's link,
	// the source of RAs and DHCPv6 replies
	RouterIP net.IP
	// RouterMAC, if set, goes into RAs as the source link-layer address
	// (IPoE; PPP has no link-layer addresses)
	RouterMAC net.HardwareAddr
}

// Config are the settings common to all subscribers
type Config struct {
	DNS []net.IP
	// ServerDUID identifies the BNG as DHCPv6 server
	ServerDUID []byte
	// Lifetimes (seconds) of the WAN prefix and the delegated prefix
	PreferredLifetime uint32
	ValidLifetime     uint32
	// RouterLifetime (seconds) of the BNG as default router
	RouterLifetime uint16
	// MTU advertised in RAs (0 = none)
	MTU uint32
}

// Responder answers subscribers' IPv6 control packets
type Responder struct {
	cfg Config
}

// NewResponder creates a responder
func NewResponder(cfg Config) *Responder {
	if cfg.PreferredLifetime == 0 {
		cfg.PreferredLifetime = 3600
	}
	if cfg.ValidLifetime < cfg.PreferredLifetime {
		cfg.ValidLifetime = 2 * cfg.PreferredLifetime
	}
	if cfg.RouterLifetime == 0 {
		cfg.RouterLifetime = 1800
	}
	return &Responder{cfg: cfg}
}

// DUIDFromMAC returns a DUID-LL (RFC 8415) for a MAC address
func DUIDFromMAC(mac net.HardwareAddr) []byte {
	d := make([]byte, 4+len(mac))
	binary.BigEndian.PutUint16(d[0:], dhcpv6.DUIDTypeLL)
	binary.BigEndian.PutUint16(d[2:], 1) // Ethernet
	copy(d[4:], mac)
	return d
}

// Handle answers an IPv6 control packet from a subscriber: a Router
// Solicitation gets a Router Advertisement, a DHCPv6 message its reply.
// Anything else returns nil.
func (r *Responder) Handle(pkt []byte, sub *Subscriber) []byte {
	p, ok := parseIPv6(pkt)
	if !ok || !p.validChecksum() {
		return nil
	}
	switch p.next {
	case protoICMPv6:
		// RFC 4861 6.1.1: hop limit 255, code 0
		if len(p.payload) >= 8 && p.payload[0] == icmpRouterSolicit && p.payload[1] == 0 && p.hopLimit == 255 {
			dst := p.src
			if dst.IsUnspecified() {
				dst = allNodes
			}
			return r.RouterAdvertisement(sub, dst)
		}
	case protoUDP:
		if len(p.payload) < 8 || binary.BigEndian.Uint16(p.payload[2:]) != dhcpv6ServerPort {
			return nil
		}
		reply := r.dhcpv6Reply(p.payload[8:], sub)
		if reply == nil {
			return nil
		}
		return buildIPv6(sub.RouterIP, p.src, protoUDP, 255,
			udpDatagram(dhcpv6ServerPort, binary.BigEndian.Uint16(p.payload[0:]), reply))
	}
	return nil
}

// RouterAdvertisement builds an RA for a subscriber, to dst (the
// subscriber's link-local address, or ff02::1)
func (r *Responder) RouterAdvertisement(sub *Subscriber, dst net.IP) []byte {
	ra := make([]byte, 16, 128)
	ra[0] = icmpRouterAdvert
	ra[4] = 64   // Cur Hop Limit
	ra[5] = 0x40 // O: other configuration (DNS, prefix delegation) by DHCPv6
	binary.BigEndian.PutUint16(ra[6:], r.cfg.RouterLifetime)

	if sub.RouterMAC != nil {
		opt := make([]byte, 8)
		opt[0], opt[1] = 1, 1 // Source Link-Layer Address
		copy(opt[2:], sub.RouterMAC)
		ra = append(ra, opt...)
	}
	if r.cfg.MTU != 0 {
		opt := make([]byte, 8)
		opt[0], opt[1] = 5, 1
		binary.BigEndian.PutUint32(opt[4:], r.cfg.MTU)
		ra = append(ra, opt...)
	}
	if sub.WAN != nil {
		ones, _ := sub.WAN.Mask.Size()
		opt := make([]byte, 32)
		opt[0], opt[1] = 3, 4 // Prefix Information
		opt[2] = uint8(ones)
		opt[3] = 0xc0 // L: on-link, A: autonomous address configuration
		binary.BigEndian.PutUint32(opt[4:], r.cfg.ValidLifetime)
		binary.BigEndian.PutUint32(opt[8:], r.cfg.PreferredLifetime)
		copy(opt[16:], sub.WAN.IP.To16())
		ra = append(ra, opt...)
	}
	if len(r.cfg.DNS) > 0 {
		// RFC 8106 Recursive DNS Server
		opt := make([]byte, 8+16*len(r.cfg.DNS))
		opt[0], opt[1] = 25, uint8(len(opt)/8)
		binary.BigEndian.PutUint32(opt[4:], 3*uint32(r.cfg.RouterLifetime))
		for i, ip := range r.cfg.DNS {
			copy(opt[8+16*i:], ip.To16())
		}
		ra = append(ra, opt...)
	}
	return buildIPv6(sub.RouterIP, dst, protoICMPv6, 255, ra)
}

// dhcpv6Reply answers a DHCPv6 message (RFC 8415): the subscriber's
// delegated prefix in every IA_PD, NoAddrsAvail in IA_NA (addresses come
// from SLAAC) and DNS servers
func (r *Responder) dhcpv6Reply(data []byte, sub *Subscriber) []byte {
	req, err := dhcpv6.ParseMessage(data)
	if err != nil {
		return nil
	}
	clientID := req.GetOption(dhcpv6.OptClientID)

	var replyType uint8 = dhcpv6.MsgTypeReply
	switch req.Type {
	case dhcpv6.MsgTypeSolicit:
		if clientID == nil {
			return nil
		}
		if req.GetOption(dhcpv6.OptRapidCommit) == nil {
			replyType = dhcpv6.MsgTypeAdvertise
		}
	case dhcpv6.MsgTypeRequest, dhcpv6.MsgTypeRenew, dhcpv6.MsgTypeRebind,
		dhcpv6.MsgTypeRelease, dhcpv6.MsgTypeDecline, dhcpv6.MsgTypeConfirm:
		if clientID == nil {
			return nil
		}
	case dhcpv6.MsgTypeInformationRequest:
	default:
		return nil
	}
	// Messages for another server
	if sid := req.GetOption(dhcpv6.OptServerID); sid != nil && string(sid.Data) != string(r.cfg.ServerDUID) {
		return nil
	}

	reply := &dhcpv6.Message{Type: replyType, TransactionID: req.TransactionID}
	if clientID != nil {
		reply.Options = append(reply.Options, dhcpv6.MakeClientIDOption(clientID.Data))
	}
	reply.Options = append(reply.Options, dhcpv6.Option{Code: dhcpv6.OptServerID, Data: r.cfg.ServerDUID})
	if replyType == dhcpv6.MsgTypeReply && req.Type == dhcpv6.MsgTypeSolicit {
		reply.Options = append(reply.Options, dhcpv6.Option{Code: dhcpv6.OptRapidCommit})
	}

	switch req.Type {
	case dhcpv6.MsgTypeRelease, dhcpv6.MsgTypeDecline:
		// The prefix belongs to the session, not to the DHCPv6 binding:
		// it stays until the session ends
		reply.Options = append(reply.Options, dhcpv6.MakeStatusCodeOption(dhcpv6.StatusSuccess, "ok"))
	case dhcpv6.MsgTypeConfirm:
		reply.Options = append(reply.Options, dhcpv6.MakeStatusCodeOption(dhcpv6.StatusSuccess, "ok"))
	case dhcpv6.MsgTypeInformationRequest:
	default:
		for _, opt := range req.GetAllOptions(dhcpv6.OptIAPD) {
			ia, err := dhcpv6.ParseIAPD(opt.Data)
			if err != nil {
				continue
			}
			reply.Options = append(reply.Options, r.iaPD(ia.IAID, sub.PD))
		}
		for _, opt := range req.GetAllOptions(dhcpv6.OptIANA) {
			ia, err := dhcpv6.ParseIANA(opt.Data)
			if err != nil {
				continue
			}
			reply.Options = append(reply.Options, dhcpv6.MakeIANAOption(&dhcpv6.IANA{
				IAID:    ia.IAID,
				Options: []dhcpv6.Option{dhcpv6.MakeStatusCodeOption(dhcpv6.StatusNoAddrsAvail, "use SLAAC")},
			}))
		}
	}
	if len(r.cfg.DNS) > 0 {
		reply.Options = append(reply.Options, dhcpv6.MakeDNSServersOption(r.cfg.DNS))
	}
	return reply.Serialize()
}

func (r *Responder) iaPD(iaid uint32, pd *net.IPNet) dhcpv6.Option {
	ia := &dhcpv6.IAPD{IAID: iaid}
	if pd == nil {
		ia.Options = []dhcpv6.Option{dhcpv6.MakeStatusCodeOption(dhcpv6.StatusNoPrefixAvail, "no prefix")}
		return dhcpv6.MakeIAPDOption(ia)
	}
	ones, _ := pd.Mask.Size()
	ia.T1 = r.cfg.PreferredLifetime / 2
	ia.T2 = r.cfg.PreferredLifetime * 4 / 5
	ia.Options = []dhcpv6.Option{dhcpv6.MakeIAPrefixOption(&dhcpv6.IAPrefix{
		PreferredLifetime: r.cfg.PreferredLifetime,
		ValidLifetime:     r.cfg.ValidLifetime,
		PrefixLength:      uint8(ones),
		Prefix:            pd.IP,
	})}
	return dhcpv6.MakeIAPDOption(ia)
}
