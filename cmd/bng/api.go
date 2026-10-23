package main

// Management API: subscriber sessions (PPPoE sessions and IPoE leases) for
// operators and tools, used by "bng sessions".
//
//	GET    /api/v1/sessions[?type=&username=&ip=&mac=&public=&state=]
//	GET    /api/v1/sessions/{id}
//	DELETE /api/v1/sessions/{id}
//	DELETE /api/v1/sessions?username=|ip=|mac=   (all matching)
//	PATCH  /api/v1/sessions/{id}   {"up_bps": N, "down_bps": N}
//	GET    /api/v1/summary

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/codelaboratoryltd/bng/pkg/dhcp"
	"github.com/codelaboratoryltd/bng/pkg/ebpf"
	"github.com/codelaboratoryltd/bng/pkg/pppoe"
	"github.com/codelaboratoryltd/bng/pkg/radius"
	"github.com/codelaboratoryltd/bng/pkg/sub6"
	"go.uber.org/zap"
)

type mgmtAPI struct {
	pppoe    *pppoe.Server        // nil = no PPPoE
	dhcp     *dhcp.Server         // IPoE leases
	dp       *ebpf.PPPoEDataplane // nil = no XDP data plane (no counters)
	nat      *subscriberCGNAT     // nil = no CGNAT in the data plane
	ipoe6    *sub6.IPoEServer     // nil = no IPv6 for IPoE
	policies *radius.PolicyManager
	vlan     uint16 // access VLAN the subscribers are on
	token    string // "" = no authentication
	logger   *zap.Logger
}

type apiSession struct {
	ID             string       `json:"id"` // Acct-Session-Id
	Type           string       `json:"type"`
	PPPoESessionID uint16       `json:"pppoe_session_id,omitempty"`
	Username       string       `json:"username,omitempty"`
	Auth           string       `json:"auth,omitempty"`
	MAC            string       `json:"mac"`
	VLAN           uint16       `json:"vlan,omitempty"`
	State          string       `json:"state"`
	IPv4           string       `json:"ipv4,omitempty"`
	IPv6WAN        string       `json:"ipv6_wan_prefix,omitempty"`
	IPv6PD         string       `json:"ipv6_delegated_prefix,omitempty"`
	NAT            *apiNAT      `json:"nat,omitempty"`
	UpRateBPS      uint64       `json:"up_rate_bps,omitempty"`
	DownRateBPS    uint64       `json:"down_rate_bps,omitempty"`
	Since          *time.Time   `json:"since,omitempty"`
	UptimeSeconds  int64        `json:"uptime_seconds"`
	SessionTimeout int64        `json:"session_timeout_seconds,omitempty"`
	IdleTimeout    int64        `json:"idle_timeout_seconds,omitempty"`
	LeaseExpires   *time.Time   `json:"lease_expires,omitempty"`
	CircuitID      string       `json:"circuit_id,omitempty"`
	Counters       *apiCounters `json:"counters,omitempty"`
}

type apiNAT struct {
	PublicIP  string `json:"public_ip"`
	PortStart uint16 `json:"port_start"`
	PortEnd   uint16 `json:"port_end"`
}

type apiCounters struct {
	UpPackets   uint64 `json:"up_packets"`
	UpBytes     uint64 `json:"up_bytes"`
	DownPackets uint64 `json:"down_packets"`
	DownBytes   uint64 `json:"down_bytes"`
	UpDropped   uint64 `json:"up_dropped"`
	DownDropped uint64 `json:"down_dropped"`
}

func (a *mgmtAPI) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/sessions", a.list)
	mux.HandleFunc("GET /api/v1/sessions/{id}", a.get)
	mux.HandleFunc("DELETE /api/v1/sessions/{id}", a.killOne)
	mux.HandleFunc("DELETE /api/v1/sessions", a.killMatching)
	mux.HandleFunc("PATCH /api/v1/sessions/{id}", a.setRate)
	mux.HandleFunc("GET /api/v1/summary", a.summary)
	return a.auth(mux)
}

func (a *mgmtAPI) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.token != "" {
			got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if subtle.ConstantTimeCompare([]byte(got), []byte(a.token)) != 1 {
				apiError(w, http.StatusUnauthorized, errors.New("missing or wrong API token"))
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func apiJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

func apiError(w http.ResponseWriter, status int, err error) {
	apiJSON(w, status, map[string]string{"error": err.Error()})
}

// sessions collects every subscriber session
func (a *mgmtAPI) sessions() ([]apiSession, error) {
	now := time.Now()
	var out []apiSession

	if a.pppoe != nil {
		infos, err := a.pppoe.Sessions()
		if err != nil {
			return nil, err
		}
		for _, si := range infos {
			s := apiSession{
				ID:             si.AcctSessionID,
				Type:           "pppoe",
				PPPoESessionID: si.ID,
				Username:       si.Username,
				Auth:           si.AuthMethod,
				MAC:            si.MAC.String(),
				VLAN:           a.vlan,
				State:          si.State,
				UpRateBPS:      si.UpRateBPS,
				DownRateBPS:    si.DownRateBPS,
				SessionTimeout: int64(si.SessionTimeout / time.Second),
				IdleTimeout:    int64(si.IdleTimeout / time.Second),
			}
			if si.ClientIP != nil {
				s.IPv4 = si.ClientIP.String()
			}
			s.IPv6WAN, s.IPv6PD = prefixString(si.WANPrefix), prefixString(si.PDPrefix)
			if !si.EstablishedAt.IsZero() {
				t := si.EstablishedAt
				s.Since = &t
				s.UptimeSeconds = int64(now.Sub(t) / time.Second)
				a.addDataplane(&s, si.ClientIP)
			}
			out = append(out, s)
		}
	}

	if a.dhcp != nil {
		for _, l := range a.dhcp.Leases() {
			start, expires := l.SessionStart, l.ExpiresAt
			s := apiSession{
				ID:            l.SessionID,
				Type:          "ipoe",
				Username:      l.MAC.String(),
				MAC:           l.MAC.String(),
				VLAN:          a.vlan,
				State:         "Leased",
				IPv4:          l.IP.String(),
				Since:         &start,
				UptimeSeconds: int64(now.Sub(start) / time.Second),
				LeaseExpires:  &expires,
				CircuitID:     string(l.CircuitID),
			}
			if l.PolicyName != "" && a.policies != nil {
				if p := a.policies.GetPolicy(l.PolicyName); p != nil {
					s.UpRateBPS, s.DownRateBPS = p.UploadBPS, p.DownloadBPS
				}
			}
			if a.ipoe6 != nil {
				wan, pd := a.ipoe6.Prefixes(l.MAC)
				s.IPv6WAN, s.IPv6PD = prefixString(wan), prefixString(pd)
			}
			a.addDataplane(&s, l.IP)
			out = append(out, s)
		}
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Type != out[j].Type {
			return out[i].Type > out[j].Type // pppoe first
		}
		return out[i].Username < out[j].Username
	})
	return out, nil
}

func prefixString(p *net.IPNet) string {
	if p == nil {
		return ""
	}
	return p.String()
}

// addDataplane adds the NAT block and live counters of a subscriber address
func (a *mgmtAPI) addDataplane(s *apiSession, ip net.IP) {
	if ip == nil {
		return
	}
	if a.nat != nil {
		if alloc := a.nat.blocks.Lookup(ip); alloc != nil {
			s.NAT = &apiNAT{PublicIP: alloc.PublicIP.String(), PortStart: alloc.PortStart, PortEnd: alloc.PortEnd}
		}
	}
	if a.dp != nil {
		if c, err := a.dp.SessionCounters(ip); err == nil {
			s.Counters = &apiCounters{
				UpPackets: c.UpPackets, UpBytes: c.UpBytes,
				DownPackets: c.DownPackets, DownBytes: c.DownBytes,
				UpDropped: c.UpDropped, DownDropped: c.DownDropped,
			}
		}
	}
}

// sessionFilter selects sessions by query parameters; empty fields match
// everything
type sessionFilter struct {
	typ, username, mac, state string
	ip                        net.IP
	publicIP                  net.IP
	publicPort                int // -1 = any
}

func parseFilter(r *http.Request) (sessionFilter, error) {
	q := r.URL.Query()
	f := sessionFilter{
		typ:        strings.ToLower(q.Get("type")),
		username:   q.Get("username"),
		mac:        normalizeMACString(q.Get("mac")),
		state:      strings.ToLower(q.Get("state")),
		publicPort: -1,
	}
	if v := q.Get("ip"); v != "" {
		if f.ip = net.ParseIP(v); f.ip == nil {
			return f, fmt.Errorf("invalid ip %q", v)
		}
	}
	if v := q.Get("public"); v != "" {
		host, port := v, ""
		if h, p, err := net.SplitHostPort(v); err == nil {
			host, port = h, p
		}
		if f.publicIP = net.ParseIP(host); f.publicIP == nil {
			return f, fmt.Errorf("invalid public address %q", v)
		}
		if port != "" {
			n, err := strconv.Atoi(port)
			if err != nil || n < 0 || n > 65535 {
				return f, fmt.Errorf("invalid public port %q", port)
			}
			f.publicPort = n
		}
	}
	return f, nil
}

// empty reports whether the filter selects nothing in particular
func (f sessionFilter) empty() bool {
	return f.username == "" && f.mac == "" && f.ip == nil && f.publicIP == nil
}

func normalizeMACString(s string) string {
	return strings.ToLower(strings.NewReplacer("-", "", ":", "", ".", "").Replace(s))
}

func inPrefix(ip net.IP, prefix string) bool {
	if prefix == "" {
		return false
	}
	_, n, err := net.ParseCIDR(prefix)
	return err == nil && n.Contains(ip)
}

func (f sessionFilter) match(s apiSession) bool {
	if f.typ != "" && f.typ != s.Type {
		return false
	}
	if f.username != "" && f.username != s.Username {
		return false
	}
	if f.mac != "" && f.mac != normalizeMACString(s.MAC) {
		return false
	}
	if f.state != "" && f.state != strings.ToLower(s.State) {
		return false
	}
	if f.ip != nil {
		v4 := net.ParseIP(s.IPv4)
		if !(v4 != nil && v4.Equal(f.ip)) && !inPrefix(f.ip, s.IPv6WAN) && !inPrefix(f.ip, s.IPv6PD) {
			return false
		}
	}
	if f.publicIP != nil {
		if s.NAT == nil || !net.ParseIP(s.NAT.PublicIP).Equal(f.publicIP) {
			return false
		}
		if f.publicPort >= 0 && (f.publicPort < int(s.NAT.PortStart) || f.publicPort > int(s.NAT.PortEnd)) {
			return false
		}
	}
	return true
}

func (a *mgmtAPI) list(w http.ResponseWriter, r *http.Request) {
	f, err := parseFilter(r)
	if err != nil {
		apiError(w, http.StatusBadRequest, err)
		return
	}
	all, err := a.sessions()
	if err != nil {
		apiError(w, http.StatusServiceUnavailable, err)
		return
	}
	out := []apiSession{}
	for _, s := range all {
		if f.match(s) {
			out = append(out, s)
		}
	}
	apiJSON(w, http.StatusOK, map[string]any{"count": len(out), "sessions": out})
}

func (a *mgmtAPI) find(w http.ResponseWriter, r *http.Request) (apiSession, bool) {
	all, err := a.sessions()
	if err != nil {
		apiError(w, http.StatusServiceUnavailable, err)
		return apiSession{}, false
	}
	id := r.PathValue("id")
	for _, s := range all {
		if s.ID == id {
			return s, true
		}
	}
	apiError(w, http.StatusNotFound, fmt.Errorf("no session %s", id))
	return apiSession{}, false
}

func (a *mgmtAPI) get(w http.ResponseWriter, r *http.Request) {
	if s, ok := a.find(w, r); ok {
		apiJSON(w, http.StatusOK, s)
	}
}

// kill ends one session
func (a *mgmtAPI) kill(s apiSession) error {
	switch s.Type {
	case "pppoe":
		n, err := a.pppoe.Terminate(s.ID, "", nil, "")
		if err != nil {
			return err
		}
		if n == 0 {
			return fmt.Errorf("session %s is not established", s.ID)
		}
	case "ipoe":
		mac, err := net.ParseMAC(s.MAC)
		if err != nil {
			return err
		}
		if !a.dhcp.TerminateLease(mac) {
			return fmt.Errorf("lease %s is gone", s.ID)
		}
	}
	a.logger.Info("Session terminated by operator",
		zap.String("id", s.ID),
		zap.String("type", s.Type),
		zap.String("username", s.Username),
		zap.String("ipv4", s.IPv4),
	)
	return nil
}

func (a *mgmtAPI) killOne(w http.ResponseWriter, r *http.Request) {
	s, ok := a.find(w, r)
	if !ok {
		return
	}
	if err := a.kill(s); err != nil {
		apiError(w, http.StatusConflict, err)
		return
	}
	apiJSON(w, http.StatusOK, map[string]any{"killed": 1, "sessions": []apiSession{s}})
}

func (a *mgmtAPI) killMatching(w http.ResponseWriter, r *http.Request) {
	f, err := parseFilter(r)
	if err != nil {
		apiError(w, http.StatusBadRequest, err)
		return
	}
	if f.empty() {
		apiError(w, http.StatusBadRequest, errors.New("give username, ip, mac or public to select the sessions to kill"))
		return
	}
	all, err := a.sessions()
	if err != nil {
		apiError(w, http.StatusServiceUnavailable, err)
		return
	}
	killed := []apiSession{}
	var errs []string
	for _, s := range all {
		if !f.match(s) {
			continue
		}
		if err := a.kill(s); err != nil {
			errs = append(errs, err.Error())
			continue
		}
		killed = append(killed, s)
	}
	resp := map[string]any{"killed": len(killed), "sessions": killed}
	if len(errs) > 0 {
		resp["errors"] = errs
	}
	apiJSON(w, http.StatusOK, resp)
}

func (a *mgmtAPI) setRate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		UpBPS   *uint64 `json:"up_bps"`
		DownBPS *uint64 `json:"down_bps"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.UpBPS == nil || body.DownBPS == nil {
		apiError(w, http.StatusBadRequest, errors.New(`body must be {"up_bps": N, "down_bps": N} (0 = unlimited)`))
		return
	}
	s, ok := a.find(w, r)
	if !ok {
		return
	}
	switch s.Type {
	case "pppoe":
		resp := a.pppoe.ChangeAuthorization(&radius.CoARequest{
			SessionID: s.ID, UploadBPS: *body.UpBPS, DownloadBPS: *body.DownBPS, RateLimitSet: true,
		})
		if !resp.Success {
			apiError(w, http.StatusConflict, fmt.Errorf("%s (Error-Cause %d)", resp.Message, resp.ErrorCause))
			return
		}
	case "ipoe":
		if a.dp == nil {
			apiError(w, http.StatusConflict, errors.New("IPoE subscribers are not in the XDP data plane"))
			return
		}
		if err := a.dp.SetSessionRate(net.ParseIP(s.IPv4), *body.UpBPS, *body.DownBPS); err != nil {
			apiError(w, http.StatusInternalServerError, err)
			return
		}
	}
	a.logger.Info("Session rate changed by operator",
		zap.String("id", s.ID), zap.String("username", s.Username),
		zap.Uint64("up_bps", *body.UpBPS), zap.Uint64("down_bps", *body.DownBPS))
	s.UpRateBPS, s.DownRateBPS = *body.UpBPS, *body.DownBPS
	apiJSON(w, http.StatusOK, s)
}

func (a *mgmtAPI) summary(w http.ResponseWriter, r *http.Request) {
	all, err := a.sessions()
	if err != nil {
		apiError(w, http.StatusServiceUnavailable, err)
		return
	}
	byType := map[string]map[string]int{}
	ipv6 := 0
	for _, s := range all {
		if byType[s.Type] == nil {
			byType[s.Type] = map[string]int{}
		}
		byType[s.Type][s.State]++
		if s.IPv6WAN != "" || s.IPv6PD != "" {
			ipv6++
		}
	}
	resp := map[string]any{"sessions": len(all), "by_type": byType, "dual_stack": ipv6}
	if a.nat != nil {
		used, total := a.nat.blocks.Usage()
		resp["nat_port_blocks"] = map[string]int{"used": used, "total": total}
	}
	if a.dp != nil {
		if st, err := a.dp.Stats(); err == nil {
			resp["dataplane"] = st
		}
	}
	if a.pppoe != nil {
		resp["pppoe"] = a.pppoe.GetStats()
	}
	apiJSON(w, http.StatusOK, resp)
}
