package pppoe

// RADIUS authorization, accounting (RFC 2866) and Change of Authorization /
// Disconnect (RFC 5176) for PPPoE sessions.
//
// Session state is only touched by the processing goroutine: accounting
// requests are built there and handed to acctWorker, and CoA/Disconnect
// requests from the CoA server run there through Server.do.

import (
	"context"
	"encoding/hex"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/codelaboratoryltd/bng/pkg/radius"
	"go.uber.org/zap"
)

// applyAuthorization stores what an Access-Accept grants the session. With
// no RADIUS (resp nil) the session has no limits.
func (s *Server) applyAuthorization(session *Session, resp *radius.AuthResponse) {
	if resp == nil {
		return
	}
	session.Class = resp.Class
	session.FramedIP = resp.FramedIP
	session.SessionLimit = time.Duration(resp.SessionTimeout) * time.Second
	session.IdleLimit = time.Duration(resp.IdleTimeout) * time.Second
	session.InterimInterval = time.Duration(resp.AcctInterimInterval) * time.Second
	if up, down, ok := s.rateFor(resp.UploadBPS, resp.DownloadBPS, resp.FilterID); ok {
		session.UpRateBPS, session.DownRateBPS = up, down
	}
}

// rateFor picks a session's speed: an explicit rate (Mikrotik-Rate-Limit)
// wins over a Filter-Id naming a QoS policy. ok is false if neither applies.
func (s *Server) rateFor(upBPS, downBPS uint64, filterID string) (up, down uint64, ok bool) {
	if upBPS != 0 || downBPS != 0 {
		return upBPS, downBPS, true
	}
	if filterID != "" && s.policies != nil {
		if p := s.policies.GetPolicy(filterID); p != nil {
			return p.UploadBPS, p.DownloadBPS, true
		}
	}
	return 0, 0, false
}

// interimInterval is the session's Acct-Interim-Interval, or the server
// default when RADIUS did not send one
func (s *Server) interimInterval(session *Session) time.Duration {
	if session.InterimInterval > 0 {
		return session.InterimInterval
	}
	return s.defaultInterim
}

// sessionCounters reads a session's data plane counters (zero without one)
func (s *Server) sessionCounters(session *Session) Counters {
	if s.dataplane == nil {
		return Counters{}
	}
	c, err := s.dataplane.Counters(session)
	if err != nil {
		s.logger.Debug("Failed to read PPPoE session counters",
			zap.Uint16("session_id", session.ID),
			zap.Error(err),
		)
	}
	return c
}

// sendAccounting queues an Accounting-Request for the session. counters may
// be nil to read them from the data plane. The request is dropped (and
// counted) if the queue is full rather than blocking PPPoE processing.
func (s *Server) sendAccounting(session *Session, status radius.AcctStatusType, cause uint32, counters *Counters) {
	if s.acctQueue == nil {
		return
	}
	if counters == nil {
		c := s.sessionCounters(session)
		counters = &c
	}
	req := &radius.AcctRequest{
		SessionID:      session.SessionID,
		Username:       session.Username,
		MAC:            session.ClientMAC,
		FramedIP:       session.ClientIP,
		StatusType:     status,
		InputOctets:    counters.InOctets,
		OutputOctets:   counters.OutOctets,
		InputPackets:   counters.InPackets,
		OutputPackets:  counters.OutPackets,
		TerminateCause: cause,
		Class:          session.Class,
		NASPort:        uint32(session.ID),
	}
	if !session.EstablishedAt.IsZero() {
		req.SessionTime = uint32(time.Since(session.EstablishedAt).Seconds())
	}

	select {
	case s.acctQueue <- req:
	default:
		atomic.AddUint64(&s.acctDropped, 1)
		s.logger.Warn("RADIUS accounting queue full, dropping request",
			zap.Uint16("session_id", session.ID),
			zap.Uint32("status_type", uint32(status)),
		)
	}
}

// acctWorker sends queued Accounting-Requests
func (s *Server) acctWorker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case req := <-s.acctQueue:
			sendCtx, cancel := context.WithTimeout(ctx, acctTimeout)
			if err := s.radiusClient.SendAccounting(sendCtx, req); err != nil {
				s.logger.Warn("RADIUS accounting failed",
					zap.String("acct_session_id", req.SessionID),
					zap.Uint32("status_type", uint32(req.StatusType)),
					zap.Error(err),
				)
			}
			cancel()
		}
	}
}

// tickSessions runs once a second for established sessions: Session-Timeout,
// Idle-Timeout (no forwarded packets in either direction) and Interim-Update
func (s *Server) tickSessions(now time.Time) {
	for _, session := range s.sessions.GetAllSessions() {
		if !session.IsEstablished() {
			continue
		}
		if session.SessionLimit > 0 && now.Sub(session.limitsFrom) >= session.SessionLimit {
			s.terminateSession(session, "session timeout", radius.TerminateCauseSessionTimeout)
			continue
		}

		interimDue := !session.nextInterim.IsZero() && !now.Before(session.nextInterim)
		if session.IdleLimit == 0 && !interimDue {
			continue
		}
		counters := s.sessionCounters(session)

		if session.IdleLimit > 0 {
			if counters.InPackets != session.lastUpPackets || counters.OutPackets != session.lastDownPackets {
				session.lastUpPackets, session.lastDownPackets = counters.InPackets, counters.OutPackets
				session.lastTraffic = now
			} else if now.Sub(session.lastTraffic) >= session.IdleLimit {
				s.terminateSession(session, "idle timeout", radius.TerminateCauseIdleTimeout)
				continue
			}
		}

		if interimDue {
			s.sendAccounting(session, radius.AcctStatusInterimUpdate, 0, &counters)
			next := session.nextInterim.Add(s.interimInterval(session))
			if next.Before(now) {
				next = now.Add(s.interimInterval(session))
			}
			session.nextInterim = next
		}
	}
}

// do runs fn on the processing goroutine and waits for it. It reports false
// if the server is not processing (not started, or stuck).
func (s *Server) do(fn func()) bool {
	done := make(chan struct{})
	timer := time.NewTimer(cmdTimeout)
	defer timer.Stop()
	select {
	case s.cmds <- func() { fn(); close(done) }:
	case <-timer.C:
		return false
	}
	select {
	case <-done:
		return true
	case <-timer.C:
		return false
	}
}

// sessionSelector holds the session identification attributes of a CoA or
// Disconnect-Request; a session matches if it matches all of them (RFC 5176
// section 3).
type sessionSelector struct {
	acctSessionID string
	username      string
	framedIP      net.IP
	mac           string // Calling-Station-Id, normalized to lower-case hex
}

func newSessionSelector(acctSessionID, username string, framedIP net.IP, callingStation string) (sessionSelector, bool) {
	sel := sessionSelector{
		acctSessionID: acctSessionID,
		username:      username,
		framedIP:      framedIP,
		mac:           normalizeMAC(callingStation),
	}
	ok := sel.acctSessionID != "" || sel.username != "" || sel.framedIP != nil || sel.mac != ""
	return sel, ok
}

func (sel sessionSelector) matches(session *Session) bool {
	if sel.acctSessionID != "" && sel.acctSessionID != session.SessionID {
		return false
	}
	if sel.username != "" && sel.username != session.Username {
		return false
	}
	if sel.framedIP != nil && !sel.framedIP.Equal(session.ClientIP) {
		return false
	}
	if sel.mac != "" && sel.mac != hex.EncodeToString(session.ClientMAC) {
		return false
	}
	return true
}

// normalizeMAC turns "02-00-00-00-00-01", "02:00:00:00:00:01" and similar
// into "020000000001"
func normalizeMAC(s string) string {
	return strings.ToLower(strings.NewReplacer("-", "", ":", "", ".", "").Replace(s))
}

// matchingSessions returns the established sessions a selector picks
func (s *Server) matchingSessions(sel sessionSelector) []*Session {
	var out []*Session
	for _, session := range s.sessions.GetAllSessions() {
		if session.IsEstablished() && sel.matches(session) {
			out = append(out, session)
		}
	}
	return out
}

// Disconnect handles a RADIUS Disconnect-Request: the matching sessions are
// terminated with Acct-Terminate-Cause Admin-Reset. Safe to call from any
// goroutine.
func (s *Server) Disconnect(req *radius.DisconnectRequest) *radius.DisconnectResponse {
	sel, ok := newSessionSelector(req.AcctSessionID, req.Username, req.FramedIP, req.CallingStation)
	if !ok {
		return &radius.DisconnectResponse{ErrorCause: radius.ErrorCauseMissingAttribute,
			Message: "no session identification attribute"}
	}

	var n int
	if !s.do(func() {
		for _, session := range s.matchingSessions(sel) {
			s.terminateSession(session, "RADIUS Disconnect-Request", radius.TerminateCauseAdminReset)
			n++
		}
	}) {
		return &radius.DisconnectResponse{ErrorCause: radius.ErrorCauseResourcesUnavailable,
			Message: "PPPoE server busy"}
	}
	if n == 0 {
		return &radius.DisconnectResponse{ErrorCause: radius.ErrorCauseSessionContextNotFound,
			Message: "session not found"}
	}
	s.logger.Info("RADIUS Disconnect-Request handled", zap.Int("sessions", n))
	return &radius.DisconnectResponse{Success: true}
}

// ChangeAuthorization handles a RADIUS CoA-Request for the matching
// sessions. Supported changes: speed (Mikrotik-Rate-Limit, or Filter-Id
// naming a QoS policy), Session-Timeout and Idle-Timeout (both counted from
// the CoA). Safe to call from any goroutine.
func (s *Server) ChangeAuthorization(req *radius.CoARequest) *radius.CoAResponse {
	sel, ok := newSessionSelector(req.SessionID, req.Username, req.FramedIP, req.CallingStation)
	if !ok {
		return &radius.CoAResponse{ErrorCause: radius.ErrorCauseMissingAttribute,
			Message: "no session identification attribute"}
	}

	up, down, setRate := req.UploadBPS, req.DownloadBPS, req.RateLimitSet
	if !setRate && req.FilterID != "" {
		if up, down, setRate = s.rateFor(0, 0, req.FilterID); !setRate {
			return &radius.CoAResponse{ErrorCause: radius.ErrorCauseInvalidRequest,
				Message: "unknown Filter-Id " + req.FilterID}
		}
	}
	if !setRate && req.SessionTimeout == 0 && req.IdleTimeout == 0 {
		return &radius.CoAResponse{ErrorCause: radius.ErrorCauseUnsupportedService,
			Message: "no supported attribute to change"}
	}

	var n int
	var failed error
	if !s.do(func() {
		now := time.Now()
		for _, session := range s.matchingSessions(sel) {
			n++
			if setRate {
				if s.dataplane != nil {
					if err := s.dataplane.SetRate(session, up, down); err != nil {
						failed = err
						continue
					}
				}
				session.UpRateBPS, session.DownRateBPS = up, down
			}
			if req.SessionTimeout > 0 {
				session.SessionLimit = time.Duration(req.SessionTimeout) * time.Second
				session.limitsFrom = now
			}
			if req.IdleTimeout > 0 {
				session.IdleLimit = time.Duration(req.IdleTimeout) * time.Second
				session.lastTraffic = now
			}
			s.logger.Info("RADIUS CoA applied",
				zap.Uint16("session_id", session.ID),
				zap.String("username", session.Username),
				zap.Uint64("up_bps", session.UpRateBPS),
				zap.Uint64("down_bps", session.DownRateBPS),
				zap.Duration("session_timeout", session.SessionLimit),
				zap.Duration("idle_timeout", session.IdleLimit),
			)
		}
	}) {
		return &radius.CoAResponse{ErrorCause: radius.ErrorCauseResourcesUnavailable,
			Message: "PPPoE server busy"}
	}
	switch {
	case n == 0:
		return &radius.CoAResponse{ErrorCause: radius.ErrorCauseSessionContextNotFound,
			Message: "session not found"}
	case failed != nil:
		s.logger.Warn("RADIUS CoA could not update the data plane", zap.Error(failed))
		return &radius.CoAResponse{ErrorCause: radius.ErrorCauseResourcesUnavailable,
			Message: "rate limit not applied"}
	}
	return &radius.CoAResponse{Success: true}
}

// AccountingStats returns the accounting counters for monitoring
func (s *Server) AccountingStats() map[string]uint64 {
	queued := 0
	if s.acctQueue != nil {
		queued = len(s.acctQueue)
	}
	return map[string]uint64{
		"acct_queued":  uint64(queued),
		"acct_dropped": atomic.LoadUint64(&s.acctDropped),
	}
}
