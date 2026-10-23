package dhcp

// Lease management for operators (the BNG's management API)

import (
	"net"

	"github.com/codelaboratoryltd/bng/pkg/radius"
	"go.uber.org/zap"
)

// Leases returns a snapshot of the active leases
func (s *Server) Leases() []Lease {
	s.leasesMu.RLock()
	defer s.leasesMu.RUnlock()
	out := make([]Lease, 0, len(s.leases))
	for _, l := range s.leases {
		out = append(out, *l)
	}
	return out
}

// TerminateLease ends a subscriber's lease as if it had expired at once:
// Accounting-Stop with Admin-Reset, and its address, NAT ports and data
// plane entries go back. The client gets a new lease (and RADIUS
// authentication) when it next renews. Reports whether the MAC had a lease.
func (s *Server) TerminateLease(mac net.HardwareAddr) bool {
	s.leasesMu.Lock()
	lease, ok := s.leases[mac.String()]
	if ok {
		delete(s.leases, mac.String())
	}
	s.leasesMu.Unlock()
	if !ok {
		return false
	}
	s.removeLease(lease, radius.TerminateCauseAdminReset, true)
	s.logger.Info("DHCP lease terminated by operator",
		zap.String("mac", mac.String()),
		zap.String("ip", lease.IP.String()),
	)
	return true
}
