package sub6

import (
	"encoding/binary"
	"net"
)

const (
	protoUDP    = 17
	protoICMPv6 = 58

	ipv6HeaderLen = 40

	icmpRouterSolicit = 133
	icmpRouterAdvert  = 134

	dhcpv6ClientPort = 546
	dhcpv6ServerPort = 547
)

var (
	allNodes      = net.ParseIP("ff02::1")
	allDHCPAgents = net.ParseIP("ff02::1:2")
)

// ipv6Packet is a parsed IPv6 packet without extension headers
type ipv6Packet struct {
	src, dst net.IP
	next     uint8
	hopLimit uint8
	payload  []byte
}

func parseIPv6(pkt []byte) (*ipv6Packet, bool) {
	if len(pkt) < ipv6HeaderLen || pkt[0]>>4 != 6 {
		return nil, false
	}
	plen := int(binary.BigEndian.Uint16(pkt[4:6]))
	if ipv6HeaderLen+plen > len(pkt) {
		return nil, false
	}
	return &ipv6Packet{
		src:      net.IP(pkt[8:24]),
		dst:      net.IP(pkt[24:40]),
		next:     pkt[6],
		hopLimit: pkt[7],
		payload:  pkt[ipv6HeaderLen : ipv6HeaderLen+plen],
	}, true
}

// buildIPv6 builds an IPv6 packet around an ICMPv6 message or UDP datagram
// and fills in its checksum
func buildIPv6(src, dst net.IP, next, hopLimit uint8, payload []byte) []byte {
	pkt := make([]byte, ipv6HeaderLen+len(payload))
	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:6], uint16(len(payload)))
	pkt[6] = next
	pkt[7] = hopLimit
	copy(pkt[8:24], src.To16())
	copy(pkt[24:40], dst.To16())
	l4 := pkt[ipv6HeaderLen:]
	copy(l4, payload)

	var sumAt int
	switch next {
	case protoICMPv6:
		sumAt = 2
	case protoUDP:
		sumAt = 6
	default:
		return pkt
	}
	l4[sumAt], l4[sumAt+1] = 0, 0
	sum := checksum(pkt[8:40], 0)
	sum += uint32(len(l4)) + uint32(next)
	sum = checksum(l4, sum)
	c := ^fold(sum)
	if next == protoUDP && c == 0 {
		c = 0xffff
	}
	binary.BigEndian.PutUint16(l4[sumAt:], c)
	return pkt
}

func checksum(b []byte, sum uint32) uint32 {
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	return sum
}

func fold(sum uint32) uint16 {
	for sum > 0xffff {
		sum = sum&0xffff + sum>>16
	}
	return uint16(sum)
}

// validChecksum checks the ICMPv6 or UDP checksum of a parsed packet
func (p *ipv6Packet) validChecksum() bool {
	sum := checksum(p.src, 0)
	sum = checksum(p.dst, sum)
	sum += uint32(len(p.payload)) + uint32(p.next)
	return fold(checksum(p.payload, sum)) == 0xffff
}

func udpDatagram(srcPort, dstPort uint16, data []byte) []byte {
	b := make([]byte, 8+len(data))
	binary.BigEndian.PutUint16(b[0:], srcPort)
	binary.BigEndian.PutUint16(b[2:], dstPort)
	binary.BigEndian.PutUint16(b[4:], uint16(len(b)))
	copy(b[8:], data)
	return b
}

// LinkLocal returns the link-local address with an interface identifier
func LinkLocal(ifID uint64) net.IP {
	ip := make(net.IP, 16)
	ip[0], ip[1] = 0xfe, 0x80
	binary.BigEndian.PutUint64(ip[8:], ifID)
	return ip
}

// IsControl reports whether an IPv6 packet from a subscriber is for the
// BNG's control plane rather than to be forwarded: link-local or multicast
// destinations, or a link-local source
func IsControl(pkt []byte) bool {
	if len(pkt) < ipv6HeaderLen {
		return false
	}
	src, dst := net.IP(pkt[8:24]), net.IP(pkt[24:40])
	return dst.IsMulticast() || dst.IsLinkLocalUnicast() || src.IsLinkLocalUnicast()
}
