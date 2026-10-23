package pppoe

// Session management for operators (the BNG's management API): snapshots
// of the sessions and termination by session ID, user name, address or MAC.

import (
	"errors"
	"net"
	"time"
)

// ErrBusy is returned when the PPPoE server does not get to a request in
// time
var ErrBusy = errors.New("PPPoE server busy")

// SessionInfo is a snapshot of a PPPoE session
type SessionInfo struct {
	ID            uint16 // PPPoE session ID
	AcctSessionID string // Acct-Session-Id, unique per session
	Username      string
	AuthMethod    string
	MAC           net.HardwareAddr
	State         string
	ClientIP      net.IP
	WANPrefix     *net.IPNet // IPv6 /64 for SLAAC (nil = no IPv6)
	PDPrefix      *net.IPNet // Delegated IPv6 prefix
	UpRateBPS     uint64
	DownRateBPS   uint64
	CreatedAt     time.Time
	EstablishedAt time.Time // Zero until IPCP is up
	// Limits from RADIUS or CoA (0 = none)
	SessionTimeout time.Duration
	IdleTimeout    time.Duration
}

// Sessions returns a snapshot of all sessions. Safe to call from any
// goroutine.
func (s *Server) Sessions() ([]SessionInfo, error) {
	var out []SessionInfo
	if !s.do(func() {
		for _, session := range s.sessions.GetAllSessions() {
			out = append(out, SessionInfo{
				ID:             session.ID,
				AcctSessionID:  session.SessionID,
				Username:       session.Username,
				AuthMethod:     session.AuthMethod,
				MAC:            session.ClientMAC,
				State:          session.GetState().String(),
				ClientIP:       session.ClientIP,
				WANPrefix:      session.WANPrefix,
				PDPrefix:       session.PDPrefix,
				UpRateBPS:      session.UpRateBPS,
				DownRateBPS:    session.DownRateBPS,
				CreatedAt:      session.CreatedAt,
				EstablishedAt:  session.EstablishedAt,
				SessionTimeout: session.SessionLimit,
				IdleTimeout:    session.IdleLimit,
			})
		}
	}) {
		return nil, ErrBusy
	}
	return out, nil
}

// Terminate ends the established sessions matching all the given
// identifiers (empty ones are ignored, at least one is needed), as a RADIUS
// Disconnect-Request would: PADT, Accounting-Stop with Admin-Reset, and the
// address, prefixes and NAT ports go back. Safe to call from any goroutine.
func (s *Server) Terminate(acctSessionID, username string, ip net.IP, mac string) (int, error) {
	sel, ok := newSessionSelector(acctSessionID, username, ip, mac)
	if !ok {
		return 0, errors.New("no session identifier given")
	}
	n, ok := s.terminateMatching(sel, "terminated by operator")
	if !ok {
		return 0, ErrBusy
	}
	return n, nil
}
