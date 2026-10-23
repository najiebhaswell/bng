package pppoe

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/codelaboratoryltd/bng/pkg/radius"
	"go.uber.org/zap"
)

// maxLCPConfigNaks bounds how often the peer may Nak our LCP
// Configure-Request before the session is torn down (RFC 1661 Max-Failure
// is 5; Max-Configure is 10).
const maxLCPConfigNaks = 10

// Retransmission of our requests (RFC 1661 Restart timer and Max-Configure):
// a lost Configure-Request or CHAP Challenge must not leave a session stuck.
const (
	restartInterval = 3 * time.Second
	maxConfigure    = 10
)

// Dataplane forwards the traffic of established sessions outside userspace
// (e.g. the XDP PPPoE data plane). Sessions are added once IPCP is up and
// removed when they end.
type Dataplane interface {
	// AddSession installs a session with its rate limit and zeroed counters
	AddSession(session *Session) error
	RemoveSession(session *Session) error
	// SetRate changes an established session's limit (bits/s, 0 = unlimited)
	SetRate(session *Session, upBPS, downBPS uint64) error
	// Counters returns the traffic forwarded for an established session
	Counters(session *Session) (Counters, error)
}

// Counters is a session's forwarded traffic; In is from the subscriber, as
// in RADIUS accounting
type Counters struct {
	InPackets  uint64
	InOctets   uint64
	OutPackets uint64
	OutOctets  uint64
}

// acctQueueLen bounds the accounting backlog; RADIUS being slow or down must
// not hold up the PPPoE processing goroutine
const (
	acctQueueLen = 16384
	acctWorkers  = 4
	acctTimeout  = 10 * time.Second
	// cmdTimeout bounds how long a CoA waits for the processing goroutine
	cmdTimeout = 5 * time.Second
)

// rawSocket is an interface for platform-specific raw socket operations
type rawSocket interface {
	open(iface string, etherType uint16) error
	close() error
	recv(buf []byte) (int, error)
	send(iface string, dstMAC net.HardwareAddr, etherType uint16, data []byte) error
}

// Server is a PPPoE Access Concentrator (AC) server
type Server struct {
	iface       string
	serverMAC   net.HardwareAddr
	acName      string
	serviceName string
	logger      *zap.Logger

	// Session management
	sessions *SessionManager

	// IP pool
	serverIP     net.IP
	clientIPPool *IPPool
	primaryDNS   net.IP
	secondaryDNS net.IP

	// PPP negotiation settings
	authType       string        // "pap", "chap", or "both"
	sessionTimeout time.Duration // Idle timeout
	mru            uint16        // Maximum Receive Unit

	// RADIUS client (optional)
	radiusClient *radius.Client

	// QoS policies a Filter-Id can name (optional)
	policies *radius.PolicyManager

	// Accounting: Interim-Update interval when RADIUS sends none, and the
	// queue the accounting workers send from
	defaultInterim time.Duration
	acctQueue      chan *radius.AcctRequest
	acctDropped    uint64

	// Work run on the processing goroutine on behalf of other goroutines
	// (CoA and Disconnect requests)
	cmds chan func()

	// Data plane for established sessions (optional)
	dataplane Dataplane

	// Raw sockets (platform-specific). An AF_PACKET socket is bound to a
	// single EtherType, so discovery (0x8863) and session (0x8864) frames
	// each need their own.
	socket        rawSocket
	sessionSocket rawSocket

	// Statistics
	padiReceived  uint64
	padoSent      uint64
	padrReceived  uint64
	padsSent      uint64
	padtReceived  uint64
	padtSent      uint64
	sessionsTotal uint64
}

// IPPool is a simple IP address pool for PPPoE clients
type IPPool struct {
	network   *net.IPNet
	gateway   net.IP
	available []net.IP
	allocated map[string]net.IP // session ID -> IP
}

// NewIPPool creates a new IP pool
func NewIPPool(network string, gateway string) (*IPPool, error) {
	_, ipnet, err := net.ParseCIDR(network)
	if err != nil {
		return nil, fmt.Errorf("invalid network: %w", err)
	}

	gw := net.ParseIP(gateway)
	if gw == nil {
		return nil, fmt.Errorf("invalid gateway")
	}

	pool := &IPPool{
		network:   ipnet,
		gateway:   gw,
		available: make([]net.IP, 0),
		allocated: make(map[string]net.IP),
	}

	// Generate available IPs (skip network, gateway, and broadcast)
	ip := ipnet.IP.Mask(ipnet.Mask)
	for {
		ip = nextIP(ip)
		if !ipnet.Contains(ip) {
			break
		}
		// Skip gateway and broadcast
		if !ip.Equal(gw) && !isBroadcast(ip, ipnet) {
			pool.available = append(pool.available, copyIP(ip))
		}
	}

	return pool, nil
}

// Allocate allocates an IP for a session
func (p *IPPool) Allocate(sessionID string) net.IP {
	if len(p.available) == 0 {
		return nil
	}
	ip := p.available[0]
	p.available = p.available[1:]
	p.allocated[sessionID] = ip
	return ip
}

// Reserve assigns a specific address (RADIUS Framed-IP-Address) to a
// session. Addresses outside the pool are not tracked and always succeed;
// an address inside the pool must be free.
func (p *IPPool) Reserve(sessionID string, ip net.IP) bool {
	if !p.network.Contains(ip) {
		return true
	}
	for i, avail := range p.available {
		if avail.Equal(ip) {
			p.available = append(p.available[:i], p.available[i+1:]...)
			p.allocated[sessionID] = avail
			return true
		}
	}
	return false
}

// Release releases an IP back to the pool
func (p *IPPool) Release(sessionID string) {
	if ip, ok := p.allocated[sessionID]; ok {
		delete(p.allocated, sessionID)
		p.available = append(p.available, ip)
	}
}

// ServerConfig configures the PPPoE server
type ServerConfig struct {
	Interface    string
	ACName       string
	ServiceName  string
	ServerIP     string
	ClientPool   string
	PoolGateway  string
	PrimaryDNS   string
	SecondaryDNS string

	// PPP negotiation settings
	AuthType       string        // "pap", "chap", or "both" (default: "pap")
	SessionTimeout time.Duration // Idle timeout for sessions
	MRU            uint16        // Maximum Receive Unit (default: 1492)

	// Interim-Update interval when Access-Accept has no Acct-Interim-Interval
	// (0 = Start and Stop only)
	AcctInterimInterval time.Duration
}

// NewServer creates a new PPPoE server
func NewServer(cfg ServerConfig, logger *zap.Logger) (*Server, error) {
	if cfg.Interface == "" {
		return nil, fmt.Errorf("interface required")
	}

	// Get interface MAC
	iface, err := net.InterfaceByName(cfg.Interface)
	if err != nil {
		return nil, fmt.Errorf("failed to get interface: %w", err)
	}

	return newServerWithInterface(cfg, logger, iface)
}

// NewServerWithInterface creates a new PPPoE server with explicit interface (for testing)
func NewServerWithInterface(cfg ServerConfig, logger *zap.Logger, iface *net.Interface) (*Server, error) {
	if cfg.Interface == "" {
		return nil, fmt.Errorf("interface required")
	}
	if iface == nil {
		return nil, fmt.Errorf("interface cannot be nil")
	}
	return newServerWithInterface(cfg, logger, iface)
}

// newServerWithInterface is the internal server creation logic
func newServerWithInterface(cfg ServerConfig, logger *zap.Logger, iface *net.Interface) (*Server, error) {
	acName := cfg.ACName
	if acName == "" {
		acName = "BNG-AC"
	}

	serviceName := cfg.ServiceName
	if serviceName == "" {
		serviceName = "internet"
	}

	serverIP := net.ParseIP(cfg.ServerIP)
	if serverIP == nil {
		serverIP = net.ParseIP("10.0.0.1")
	}

	// Create IP pool
	var pool *IPPool
	var err error
	if cfg.ClientPool != "" {
		gateway := cfg.PoolGateway
		if gateway == "" {
			gateway = cfg.ServerIP
		}
		pool, err = NewIPPool(cfg.ClientPool, gateway)
		if err != nil {
			return nil, fmt.Errorf("failed to create IP pool: %w", err)
		}
	}

	authType := cfg.AuthType
	if authType == "" {
		authType = "pap"
	}
	switch authType {
	case "pap", "chap", "both":
	default:
		return nil, fmt.Errorf("invalid auth type %q (must be pap, chap or both)", authType)
	}

	mru := cfg.MRU
	if mru == 0 {
		mru = 1492
	}

	return &Server{
		iface:          cfg.Interface,
		serverMAC:      iface.HardwareAddr,
		acName:         acName,
		serviceName:    serviceName,
		authType:       authType,
		sessionTimeout: cfg.SessionTimeout,
		mru:            mru,
		logger:         logger,
		sessions:       NewSessionManager(),
		serverIP:       serverIP,
		clientIPPool:   pool,
		primaryDNS:     net.ParseIP(cfg.PrimaryDNS),
		secondaryDNS:   net.ParseIP(cfg.SecondaryDNS),
		defaultInterim: cfg.AcctInterimInterval,
		cmds:           make(chan func(), 64),
	}, nil
}

// SetRADIUSClient sets the RADIUS client for authentication and accounting
func (s *Server) SetRADIUSClient(client *radius.Client) {
	s.radiusClient = client
}

// SetPolicyManager sets the QoS policies an Access-Accept or CoA Filter-Id
// can name. Call before Start.
func (s *Server) SetPolicyManager(pm *radius.PolicyManager) {
	s.policies = pm
}

// SetDataplane sets the data plane that forwards established sessions.
// Call before Start.
func (s *Server) SetDataplane(dp Dataplane) {
	s.dataplane = dp
}

// Start starts the PPPoE server
func (s *Server) Start(ctx context.Context) error {
	s.logger.Info("Starting PPPoE server",
		zap.String("interface", s.iface),
		zap.String("ac_name", s.acName),
		zap.String("service", s.serviceName),
	)

	// Create platform-specific sockets
	s.socket = newRawSocket()
	if err := s.socket.open(s.iface, EtherTypePPPoEDiscovery); err != nil {
		return fmt.Errorf("failed to open discovery socket: %w", err)
	}
	s.sessionSocket = newRawSocket()
	if err := s.sessionSocket.open(s.iface, EtherTypePPPoESession); err != nil {
		s.socket.close()
		return fmt.Errorf("failed to open session socket: %w", err)
	}

	if s.radiusClient != nil {
		s.acctQueue = make(chan *radius.AcctRequest, acctQueueLen)
		for i := 0; i < acctWorkers; i++ {
			go s.acctWorker(ctx)
		}
	}

	// Both sockets feed one processing goroutine, so session state and the
	// IP pool are only ever touched from a single goroutine
	frames := make(chan []byte, 256)
	go s.receiveLoop(ctx, s.socket, frames)
	go s.receiveLoop(ctx, s.sessionSocket, frames)
	go s.processLoop(ctx, frames)

	return nil
}

// Stop stops the PPPoE server
func (s *Server) Stop() error {
	s.logger.Info("Stopping PPPoE server")
	var err error
	if s.socket != nil {
		err = s.socket.close()
	}
	if s.sessionSocket != nil {
		if cerr := s.sessionSocket.close(); err == nil {
			err = cerr
		}
	}
	return err
}

// receiveLoop reads frames from one socket and queues them for processLoop
func (s *Server) receiveLoop(ctx context.Context, sock rawSocket, frames chan<- []byte) {
	buf := make([]byte, 1522) // Max Ethernet frame size

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, err := sock.recv(buf)
		if err != nil {
			// Timeout or temporary error, continue
			continue
		}

		if n < 14 {
			continue
		}

		frame := make([]byte, n)
		copy(frame, buf[:n])
		select {
		case frames <- frame:
		case <-ctx.Done():
			return
		}
	}
}

// processLoop handles queued frames from all sockets and expires idle
// sessions, so session state is only touched from this goroutine
func (s *Server) processLoop(ctx context.Context, frames <-chan []byte) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	restart := time.NewTicker(time.Second)
	defer restart.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case frame := <-frames:
			s.handleFrame(frame)
		case cmd := <-s.cmds:
			cmd()
		case <-ticker.C:
			s.cleanupExpired()
		case now := <-restart.C:
			s.retransmit(now)
			s.tickSessions(now)
		}
	}
}

// retransmit resends our outstanding request for sessions whose restart
// timer expired, and gives up on sessions after maxConfigure retries. Only
// requests we originate are covered; the peer retransmits its own.
func (s *Server) retransmit(now time.Time) {
	for _, session := range s.sessions.GetAllSessions() {
		if now.Sub(session.negSentAt) < restartInterval {
			continue
		}

		var resend func(*Session)
		switch session.GetState() {
		case StateLCPNegotiation:
			if session.lcpLocalAcked {
				continue
			}
			resend = s.startLCPNegotiation
		case StateAuthentication:
			// PAP is driven by the peer's Authenticate-Request
			if session.chapChallenge == nil {
				continue
			}
			resend = s.sendCHAPChallenge
		case StateIPCPNegotiation:
			resend = s.sendIPCPConfigRequest
		default:
			continue
		}

		if session.negRetries >= maxConfigure {
			s.terminateSession(session, "negotiation timed out", radius.TerminateCauseLostCarrier)
			continue
		}
		session.negRetries++
		resend(session)
	}
}

// handleFrame dispatches one Ethernet frame
func (s *Server) handleFrame(frame []byte) {
	// Parse Ethernet header
	dstMAC := net.HardwareAddr(frame[0:6])
	srcMAC := net.HardwareAddr(frame[6:12])
	etherType := binary.BigEndian.Uint16(frame[12:14])

	// Check if it's for us (broadcast or our MAC)
	if !isBroadcastMAC(dstMAC) && dstMAC.String() != s.serverMAC.String() {
		return
	}

	switch etherType {
	case EtherTypePPPoEDiscovery:
		s.handleDiscovery(srcMAC, frame[14:])
	case EtherTypePPPoESession:
		s.handleSession(srcMAC, frame[14:])
	}
}

// handleDiscovery handles PPPoE discovery packets
func (s *Server) handleDiscovery(clientMAC net.HardwareAddr, data []byte) {
	if len(data) < 6 {
		return
	}

	hdr, err := ParsePPPoEHeader(data)
	if err != nil {
		s.logger.Debug("Invalid PPPoE header", zap.Error(err))
		return
	}

	if int(hdr.Length) > len(data)-6 {
		s.logger.Debug("PPPoE length exceeds frame", zap.Uint16("length", hdr.Length))
		return
	}
	payload := data[6 : 6+hdr.Length]
	tags, err := ParseTags(payload)
	if err != nil {
		s.logger.Debug("Invalid PPPoE tags", zap.Error(err))
		return
	}

	switch hdr.Code {
	case CodePADI:
		atomic.AddUint64(&s.padiReceived, 1)
		s.handlePADI(clientMAC, tags)
	case CodePADR:
		atomic.AddUint64(&s.padrReceived, 1)
		s.handlePADR(clientMAC, tags)
	case CodePADT:
		atomic.AddUint64(&s.padtReceived, 1)
		s.handlePADT(clientMAC, hdr.SessionID)
	}
}

// handlePADI handles PPPoE Active Discovery Initiation
func (s *Server) handlePADI(clientMAC net.HardwareAddr, tags []Tag) {
	s.logger.Debug("Received PADI",
		zap.String("client_mac", clientMAC.String()),
	)

	// Check service name (if specified, must match)
	if sn := FindTag(tags, TagServiceName); sn != nil {
		if len(sn.Value) > 0 && string(sn.Value) != s.serviceName {
			s.logger.Debug("Service name mismatch",
				zap.String("requested", string(sn.Value)),
				zap.String("offered", s.serviceName),
			)
			return
		}
	}

	// Get Host-Uniq for session correlation
	var hostUniq []byte
	if hu := FindTag(tags, TagHostUniq); hu != nil {
		hostUniq = hu.Value
	}

	// Generate AC-Cookie
	cookie := make([]byte, 16)
	if _, err := rand.Read(cookie); err != nil {
		s.logger.Error("Failed to generate AC-Cookie",
			zap.String("client_mac", clientMAC.String()),
			zap.Error(err),
		)
		return
	}

	// Build PADO response
	responseTags := []Tag{
		{Type: TagServiceName, Value: []byte(s.serviceName)},
		{Type: TagACName, Value: []byte(s.acName)},
		{Type: TagACCookie, Value: cookie},
	}

	if hostUniq != nil {
		responseTags = append(responseTags, Tag{Type: TagHostUniq, Value: hostUniq})
	}

	s.sendDiscoveryPacket(clientMAC, CodePADO, 0, responseTags)
	atomic.AddUint64(&s.padoSent, 1)

	s.logger.Debug("Sent PADO",
		zap.String("client_mac", clientMAC.String()),
	)
}

// handlePADR handles PPPoE Active Discovery Request
func (s *Server) handlePADR(clientMAC net.HardwareAddr, tags []Tag) {
	s.logger.Debug("Received PADR",
		zap.String("client_mac", clientMAC.String()),
	)

	// Verify AC-Cookie
	if cookie := FindTag(tags, TagACCookie); cookie == nil {
		s.logger.Warn("PADR without AC-Cookie")
		return
	}

	// Get Host-Uniq
	var hostUniq []byte
	if hu := FindTag(tags, TagHostUniq); hu != nil {
		hostUniq = hu.Value
	}

	// A PADR from a MAC that already has a session means the client never
	// got our PADS (or restarted): replace the old session instead of
	// leaving it behind
	if old := s.sessions.GetSessionByMAC(clientMAC); old != nil {
		s.logger.Info("Replacing PPPoE session on new PADR",
			zap.Uint16("session_id", old.ID),
			zap.String("client_mac", clientMAC.String()),
		)
		s.endSession(old, radius.TerminateCauseLostCarrier)
	}

	// Create session
	session, err := s.sessions.CreateSession(clientMAC, s.serverMAC)
	if err != nil {
		s.logger.Error("Failed to create session",
			zap.String("client_mac", clientMAC.String()),
			zap.Error(err),
		)
		return
	}
	session.HostUniq = hostUniq

	if sn := FindTag(tags, TagServiceName); sn != nil {
		session.ServiceName = string(sn.Value)
	}

	// Build PADS response
	responseTags := []Tag{
		{Type: TagServiceName, Value: []byte(s.serviceName)},
	}

	if hostUniq != nil {
		responseTags = append(responseTags, Tag{Type: TagHostUniq, Value: hostUniq})
	}

	s.sendDiscoveryPacket(clientMAC, CodePADS, session.ID, responseTags)
	atomic.AddUint64(&s.padsSent, 1)
	atomic.AddUint64(&s.sessionsTotal, 1)

	// Move to LCP negotiation
	session.SetState(StateLCPNegotiation)
	session.AuthProto = ProtocolPAP
	if s.authType == "chap" {
		session.AuthProto = ProtocolCHAP
	}

	s.logger.Info("PPPoE session created",
		zap.Uint16("session_id", session.ID),
		zap.String("client_mac", clientMAC.String()),
	)

	// Start LCP negotiation (synchronously: session state is only touched
	// from the processing goroutine)
	s.startLCPNegotiation(session)
}

// handlePADT handles PPPoE Active Discovery Terminate
func (s *Server) handlePADT(clientMAC net.HardwareAddr, sessionID uint16) {
	session := s.sessions.GetSession(sessionID)
	// Only the session's own client may tear it down
	if session == nil || !bytes.Equal(session.ClientMAC, clientMAC) {
		return
	}

	s.logger.Info("PPPoE session terminated by client",
		zap.Uint16("session_id", sessionID),
		zap.String("client_mac", clientMAC.String()),
	)

	s.endSession(session, radius.TerminateCauseUserRequest)
}

// handleSession handles PPPoE session packets (PPP)
func (s *Server) handleSession(clientMAC net.HardwareAddr, data []byte) {
	if len(data) < 8 {
		return
	}

	hdr, err := ParsePPPoEHeader(data)
	if err != nil {
		return
	}
	// Length covers the 2-byte PPP protocol field and the payload
	if hdr.Length < 2 || int(hdr.Length) > len(data)-6 {
		return
	}

	session := s.sessions.GetSession(hdr.SessionID)
	if session == nil {
		return
	}

	session.UpdateActivity()
	session.AddBytesIn(uint64(len(data)))

	// Parse PPP header
	pppProto := binary.BigEndian.Uint16(data[6:8])
	pppPayload := data[8 : 6+int(hdr.Length)]

	switch pppProto {
	case ProtocolLCP:
		s.handleLCP(session, pppPayload)
	case ProtocolPAP:
		s.handlePAP(session, pppPayload)
	case ProtocolCHAP:
		s.handleCHAP(session, pppPayload)
	case ProtocolIPCP:
		s.handleIPCP(session, pppPayload)
	case ProtocolIP:
		s.handleIPPacket(session, pppPayload)
	}
}

// startLCPNegotiation initiates LCP negotiation
func (s *Server) startLCPNegotiation(session *Session) {
	session.negSentAt = time.Now()

	// Encode MRU as big-endian uint16
	mruBytes := []byte{byte(s.mru >> 8), byte(s.mru)}

	// Auth protocol for this session (config default, or what the peer Nak'ed)
	var authProtoData []byte
	switch session.AuthProto {
	case ProtocolCHAP:
		authProtoData = []byte{0xC2, 0x23, CHAPAlgorithmMD5} // CHAP with MD5
	default:
		authProtoData = []byte{0xC0, 0x23} // PAP
	}

	// Send Configure-Request
	opts := []LCPOption{
		{Type: LCPOptMRU, Data: mruBytes},
		{Type: LCPOptMagicNumber, Data: magicToBytes(session.MagicNumber)},
		{Type: LCPOptAuthProto, Data: authProtoData},
	}

	pkt := &LCPPacket{
		Code:       LCPCodeConfigRequest,
		Identifier: session.NextLCPIdentifier(),
		Data:       SerializeLCPOptions(opts),
	}

	s.sendPPPPacket(session, ProtocolLCP, pkt.Serialize())
}

// handleLCP handles LCP packets
func (s *Server) handleLCP(session *Session, data []byte) {
	pkt, err := ParseLCPPacket(data)
	if err != nil {
		return
	}

	switch pkt.Code {
	case LCPCodeConfigRequest:
		s.handleLCPConfigRequest(session, pkt)
	case LCPCodeConfigAck:
		s.handleLCPConfigAck(session, pkt)
	case LCPCodeConfigNak:
		s.handleLCPConfigNak(session, pkt)
	case LCPCodeConfigReject:
		s.handleLCPConfigReject(session, pkt)
	case LCPCodeEchoRequest:
		s.handleLCPEchoRequest(session, pkt)
	case LCPCodeTermRequest:
		s.handleLCPTermRequest(session, pkt)
	}
}

// handleLCPConfigRequest handles LCP Configure-Request
func (s *Server) handleLCPConfigRequest(session *Session, pkt *LCPPacket) {
	opts, err := ParseLCPOptions(pkt.Data)
	if err != nil {
		return
	}

	// Check options and build response
	accepted := true
	for _, opt := range opts {
		switch opt.Type {
		case LCPOptMRU:
			if len(opt.Data) >= 2 {
				session.PeerMRU = binary.BigEndian.Uint16(opt.Data)
			}
		case LCPOptMagicNumber:
			if len(opt.Data) >= 4 {
				session.PeerMagic = binary.BigEndian.Uint32(opt.Data)
			}
		}
	}

	var respCode uint8
	if accepted {
		respCode = LCPCodeConfigAck
	} else {
		respCode = LCPCodeConfigNak
	}

	resp := &LCPPacket{
		Code:       respCode,
		Identifier: pkt.Identifier,
		Data:       pkt.Data,
	}

	s.sendPPPPacket(session, ProtocolLCP, resp.Serialize())

	if accepted {
		session.lcpPeerAcked = true
		s.maybeStartAuth(session)
	}
}

// handleLCPConfigAck handles LCP Configure-Ack
func (s *Server) handleLCPConfigAck(session *Session, pkt *LCPPacket) {
	s.logger.Debug("LCP Configure-Ack received",
		zap.Uint16("session_id", session.ID),
	)

	session.lcpLocalAcked = true
	s.maybeStartAuth(session)
}

// maybeStartAuth moves to the authentication phase once LCP is open in both
// directions; for CHAP the authenticator then sends the first Challenge.
func (s *Server) maybeStartAuth(session *Session) {
	if !session.lcpLocalAcked || !session.lcpPeerAcked || session.GetState() != StateLCPNegotiation {
		return
	}
	session.SetState(StateAuthentication)
	session.negRetries = 0
	if session.AuthProto == ProtocolCHAP {
		s.sendCHAPChallenge(session)
	}
}

// handleLCPConfigNak handles LCP Configure-Nak by adopting the peer's
// suggested auth protocol if our config allows it. Without a usable
// suggestion, resending the same request would loop forever, so the number
// of Naks is bounded and an unacceptable auth protocol ends the session.
func (s *Server) handleLCPConfigNak(session *Session, pkt *LCPPacket) {
	session.lcpConfigNaks++
	if session.lcpConfigNaks > maxLCPConfigNaks {
		s.terminateSession(session, "LCP negotiation did not converge", radius.TerminateCauseNASError)
		return
	}

	opts, err := ParseLCPOptions(pkt.Data)
	if err != nil {
		return
	}
	for _, opt := range opts {
		if opt.Type != LCPOptAuthProto || len(opt.Data) < 2 {
			continue
		}
		proto := binary.BigEndian.Uint16(opt.Data)
		if !s.authProtoAllowed(proto, opt.Data[2:]) {
			s.logger.Warn("Peer requires an auth protocol that is not enabled",
				zap.Uint16("session_id", session.ID),
				zap.String("requested", fmt.Sprintf("0x%x", opt.Data)),
				zap.String("auth_type", s.authType),
			)
			s.terminateSession(session, "no common auth protocol", radius.TerminateCauseNASError)
			return
		}
		session.AuthProto = proto
	}

	s.startLCPNegotiation(session)
}

// handleLCPConfigReject handles LCP Configure-Reject. Every option we send
// (MRU, Magic-Number, Auth-Protocol) is one we cannot drop safely, in
// particular authentication, so the session is ended.
func (s *Server) handleLCPConfigReject(session *Session, pkt *LCPPacket) {
	s.terminateSession(session, "peer rejected LCP options", radius.TerminateCauseNASError)
}

// authProtoAllowed reports whether an Auth-Protocol suggested by the peer
// (protocol plus its data, e.g. the CHAP algorithm) is enabled by config.
func (s *Server) authProtoAllowed(proto uint16, data []byte) bool {
	switch proto {
	case ProtocolPAP:
		return s.authType == "pap" || s.authType == "both"
	case ProtocolCHAP:
		return (s.authType == "chap" || s.authType == "both") &&
			len(data) >= 1 && data[0] == CHAPAlgorithmMD5
	}
	return false
}

// terminateSession ends a session from the server side: LCP
// Terminate-Request, then PADT, then the session and its IP are released.
// cause is the RADIUS Acct-Terminate-Cause for the Accounting-Stop.
func (s *Server) terminateSession(session *Session, reason string, cause uint32) {
	s.logger.Info("Terminating PPPoE session",
		zap.Uint16("session_id", session.ID),
		zap.String("client_mac", session.ClientMAC.String()),
		zap.String("reason", reason),
	)

	term := &LCPPacket{
		Code:       LCPCodeTermRequest,
		Identifier: session.NextLCPIdentifier(),
		Data:       []byte(reason),
	}
	s.sendPPPPacket(session, ProtocolLCP, term.Serialize())

	s.sendDiscoveryPacket(session.ClientMAC, CodePADT, session.ID, nil)
	atomic.AddUint64(&s.padtSent, 1)

	s.endSession(session, cause)
}

// endSession releases everything a session holds: its accounting (an
// Accounting-Stop with the final counters, read before the data plane
// entries go), its data plane entries, its IP address and the session itself
func (s *Server) endSession(session *Session, cause uint32) {
	if session.acctStarted {
		s.sendAccounting(session, radius.AcctStatusStop, cause, nil)
		session.acctStarted = false
	}
	if s.dataplane != nil && session.IsEstablished() {
		if err := s.dataplane.RemoveSession(session); err != nil {
			s.logger.Warn("Failed to remove PPPoE session from data plane",
				zap.Uint16("session_id", session.ID),
				zap.Error(err),
			)
		}
	}
	session.SetState(StateClosed)
	if s.clientIPPool != nil {
		s.clientIPPool.Release(session.SessionID)
	}
	s.sessions.RemoveSession(session.ID)
}

// handleLCPEchoRequest handles LCP Echo-Request
func (s *Server) handleLCPEchoRequest(session *Session, pkt *LCPPacket) {
	resp := &LCPPacket{
		Code:       LCPCodeEchoReply,
		Identifier: pkt.Identifier,
		Data:       magicToBytes(session.MagicNumber),
	}
	s.sendPPPPacket(session, ProtocolLCP, resp.Serialize())
}

// handleLCPTermRequest handles LCP Terminate-Request
func (s *Server) handleLCPTermRequest(session *Session, pkt *LCPPacket) {
	// Send Terminate-Ack
	resp := &LCPPacket{
		Code:       LCPCodeTermAck,
		Identifier: pkt.Identifier,
	}
	s.sendPPPPacket(session, ProtocolLCP, resp.Serialize())

	// Terminate session
	s.endSession(session, radius.TerminateCauseUserRequest)
}

// handlePAP handles PAP authentication packets
func (s *Server) handlePAP(session *Session, data []byte) {
	if len(data) < 4 {
		return
	}

	code := data[0]
	identifier := data[1]
	// length := binary.BigEndian.Uint16(data[2:4])

	if code != PAPCodeAuthRequest {
		return
	}

	// Parse username and password
	if len(data) < 6 {
		return
	}

	usernameLen := int(data[4])
	if len(data) < 5+usernameLen+1 {
		return
	}

	username := string(data[5 : 5+usernameLen])
	passwordLen := int(data[5+usernameLen])
	if len(data) < 6+usernameLen+passwordLen {
		return
	}

	passwordBytes := make([]byte, passwordLen)
	copy(passwordBytes, data[6+usernameLen:6+usernameLen+passwordLen])
	// Zero password in the original packet buffer
	for i := 0; i < passwordLen; i++ {
		data[6+usernameLen+i] = 0
	}

	s.logger.Debug("PAP authentication attempt",
		zap.Uint16("session_id", session.ID),
		zap.String("username", username),
	)

	// Authenticate (via RADIUS if configured)
	var authenticated bool
	var authResp *radius.AuthResponse

	if s.radiusClient != nil {
		var err error
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		authResp, err = s.radiusClient.Authenticate(ctx, &radius.AuthRequest{
			Username: username,
			Password: string(passwordBytes),
			MAC:      session.ClientMAC,
		})
		authenticated = err == nil && authResp != nil && authResp.Accepted
	} else {
		// Accept all if no RADIUS
		authenticated = true
	}
	// Zero password now that authentication is complete
	zeroBytes(passwordBytes)

	session.Username = username
	session.Authenticated = authenticated
	session.AuthMethod = "PAP"

	// Send response
	var respCode uint8
	var msg string
	if authenticated {
		respCode = PAPCodeAuthAck
		msg = "Login OK"
		s.logger.Info("PAP authentication successful",
			zap.Uint16("session_id", session.ID),
			zap.String("username", username),
		)
	} else {
		respCode = PAPCodeAuthNak
		msg = "Login incorrect"
		s.logger.Warn("PAP authentication failed",
			zap.Uint16("session_id", session.ID),
			zap.String("username", username),
		)
	}

	respData := make([]byte, 5+len(msg))
	respData[0] = respCode
	respData[1] = identifier
	binary.BigEndian.PutUint16(respData[2:4], uint16(5+len(msg)))
	respData[4] = byte(len(msg))
	copy(respData[5:], msg)

	s.sendPPPPacket(session, ProtocolPAP, respData)

	if authenticated {
		s.applyAuthorization(session, authResp)
		// Move to IPCP
		session.SetState(StateIPCPNegotiation)
		s.startIPCPNegotiation(session)
	} else {
		// RFC 1994: after a Failure the authenticator ends the link
		s.terminateSession(session, "authentication failed", radius.TerminateCauseUserRequest)
	}
}

// sendCHAPChallenge sends a CHAP Challenge (RFC 1994) for the session
func (s *Server) sendCHAPChallenge(session *Session) {
	challenge := make([]byte, 16)
	if _, err := rand.Read(challenge); err != nil {
		s.logger.Error("Failed to generate CHAP challenge",
			zap.Uint16("session_id", session.ID),
			zap.Error(err),
		)
		return
	}
	session.chapID++
	session.chapChallenge = challenge
	session.negSentAt = time.Now()

	// Code (1) + Identifier (1) + Length (2) + Value-Size (1) + Value + Name
	name := []byte(s.acName)
	data := make([]byte, 5+len(challenge)+len(name))
	data[0] = CHAPCodeChallenge
	data[1] = session.chapID
	binary.BigEndian.PutUint16(data[2:4], uint16(len(data)))
	data[4] = byte(len(challenge))
	copy(data[5:], challenge)
	copy(data[5+len(challenge):], name)

	s.sendPPPPacket(session, ProtocolCHAP, data)
}

// handleCHAP handles a CHAP Response to our Challenge
func (s *Server) handleCHAP(session *Session, data []byte) {
	if len(data) < 5 || data[0] != CHAPCodeResponse {
		return
	}
	identifier := data[1]
	if session.chapChallenge == nil || identifier != session.chapID {
		s.logger.Debug("Unexpected CHAP response",
			zap.Uint16("session_id", session.ID),
			zap.Uint8("identifier", identifier),
		)
		return
	}
	length := int(binary.BigEndian.Uint16(data[2:4]))
	if length < 5 || length > len(data) {
		return
	}
	data = data[:length]

	// MD5 responses are 16 bytes; the rest of the packet is the name
	valueSize := int(data[4])
	if valueSize != 16 || len(data) < 5+valueSize {
		return
	}
	response := data[5 : 5+valueSize]
	username := string(data[5+valueSize:])
	challenge := session.chapChallenge
	session.chapChallenge = nil // one Response per Challenge

	s.logger.Debug("CHAP authentication attempt",
		zap.Uint16("session_id", session.ID),
		zap.String("username", username),
	)

	// Authenticate (via RADIUS if configured)
	var authenticated bool
	var authResp *radius.AuthResponse

	if s.radiusClient != nil {
		var err error
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		authResp, err = s.radiusClient.Authenticate(ctx, &radius.AuthRequest{
			Username:      username,
			MAC:           session.ClientMAC,
			CHAPID:        identifier,
			CHAPChallenge: challenge,
			CHAPResponse:  response,
		})
		authenticated = err == nil && authResp != nil && authResp.Accepted
	} else {
		// Accept all if no RADIUS
		authenticated = true
	}

	session.Username = username
	session.Authenticated = authenticated
	session.AuthMethod = "CHAP"

	// Send response: Code, Identifier, Length, Message
	var respCode uint8
	var msg string
	if authenticated {
		respCode = CHAPCodeSuccess
		msg = "Login OK"
		s.logger.Info("CHAP authentication successful",
			zap.Uint16("session_id", session.ID),
			zap.String("username", username),
		)
	} else {
		respCode = CHAPCodeFailure
		msg = "Login incorrect"
		s.logger.Warn("CHAP authentication failed",
			zap.Uint16("session_id", session.ID),
			zap.String("username", username),
		)
	}

	respData := make([]byte, 4+len(msg))
	respData[0] = respCode
	respData[1] = identifier
	binary.BigEndian.PutUint16(respData[2:4], uint16(4+len(msg)))
	copy(respData[4:], msg)

	s.sendPPPPacket(session, ProtocolCHAP, respData)

	if authenticated {
		s.applyAuthorization(session, authResp)
		// Move to IPCP
		session.SetState(StateIPCPNegotiation)
		s.startIPCPNegotiation(session)
	} else {
		// RFC 1994: after a Failure the authenticator ends the link
		s.terminateSession(session, "authentication failed", radius.TerminateCauseUserRequest)
	}
}

// startIPCPNegotiation initiates IPCP negotiation
func (s *Server) startIPCPNegotiation(session *Session) {
	// Address for the client: RADIUS Framed-IP-Address, else from the pool
	switch {
	case session.FramedIP != nil:
		if s.clientIPPool != nil && !s.clientIPPool.Reserve(session.SessionID, session.FramedIP) {
			s.terminateSession(session, "Framed-IP-Address "+session.FramedIP.String()+" is in use",
				radius.TerminateCauseNASError)
			return
		}
		session.ClientIP = session.FramedIP
	case s.clientIPPool != nil:
		session.ClientIP = s.clientIPPool.Allocate(session.SessionID)
	}
	session.ServerIP = s.serverIP

	if session.ClientIP == nil {
		s.logger.Error("Failed to allocate IP for session",
			zap.Uint16("session_id", session.ID),
		)
		s.terminateSession(session, "no IP address available", radius.TerminateCauseNASError)
		return
	}

	session.negRetries = 0
	s.sendIPCPConfigRequest(session)
}

// sendIPCPConfigRequest sends our IPCP Configure-Request
func (s *Server) sendIPCPConfigRequest(session *Session) {
	session.negSentAt = time.Now()

	opts := []LCPOption{
		{Type: IPCPOptIPAddress, Data: session.ServerIP.To4()},
	}

	pkt := &LCPPacket{
		Code:       LCPCodeConfigRequest,
		Identifier: session.NextLCPIdentifier(),
		Data:       SerializeLCPOptions(opts),
	}

	s.sendPPPPacket(session, ProtocolIPCP, pkt.Serialize())
}

// handleIPCP handles IPCP packets
func (s *Server) handleIPCP(session *Session, data []byte) {
	pkt, err := ParseLCPPacket(data)
	if err != nil {
		return
	}

	switch pkt.Code {
	case LCPCodeConfigRequest:
		s.handleIPCPConfigRequest(session, pkt)
	case LCPCodeConfigAck:
		s.handleIPCPConfigAck(session, pkt)
	}
}

// handleIPCPConfigRequest handles IPCP Configure-Request
func (s *Server) handleIPCPConfigRequest(session *Session, pkt *LCPPacket) {
	opts, err := ParseLCPOptions(pkt.Data)
	if err != nil {
		return
	}

	// Build response options
	var respOpts []LCPOption
	nakOptions := false

	// NAK an option only when the client asks for something other than what
	// we assign; once it repeats our values back the request must be ACKed,
	// or the negotiation never completes
	nakIfDifferent := func(opt LCPOption, want net.IP) {
		if want == nil {
			return
		}
		want = want.To4()
		if !bytes.Equal(opt.Data, want) {
			respOpts = append(respOpts, LCPOption{Type: opt.Type, Data: want})
			nakOptions = true
		}
	}

	for _, opt := range opts {
		switch opt.Type {
		case IPCPOptIPAddress:
			// Client requesting IP - give them the allocated one
			nakIfDifferent(opt, session.ClientIP)
		case IPCPOptPrimaryDNS:
			nakIfDifferent(opt, s.primaryDNS)
		case IPCPOptSecondaryDNS:
			nakIfDifferent(opt, s.secondaryDNS)
		}
	}

	var respCode uint8
	var respData []byte
	if nakOptions {
		respCode = LCPCodeConfigNak
		respData = SerializeLCPOptions(respOpts)
	} else {
		respCode = LCPCodeConfigAck
		respData = pkt.Data
	}

	resp := &LCPPacket{
		Code:       respCode,
		Identifier: pkt.Identifier,
		Data:       respData,
	}

	s.sendPPPPacket(session, ProtocolIPCP, resp.Serialize())
}

// handleIPCPConfigAck handles IPCP Configure-Ack
func (s *Server) handleIPCPConfigAck(session *Session, pkt *LCPPacket) {
	// A retransmitted Ack must not restart the session's accounting
	if session.IsEstablished() {
		return
	}
	session.SetState(StateEstablished)

	s.logger.Info("PPPoE session established",
		zap.Uint16("session_id", session.ID),
		zap.String("username", session.Username),
		zap.String("client_ip", session.ClientIP.String()),
		zap.Uint64("up_bps", session.UpRateBPS),
		zap.Uint64("down_bps", session.DownRateBPS),
	)

	// A session the data plane cannot forward (e.g. no CGNAT port block
	// left) is no use to the subscriber: end it so the client retries
	if s.dataplane != nil {
		if err := s.dataplane.AddSession(session); err != nil {
			s.logger.Error("Failed to add PPPoE session to data plane",
				zap.Uint16("session_id", session.ID),
				zap.Error(err),
			)
			s.terminateSession(session, "data plane error", radius.TerminateCauseNASError)
			return
		}
	}

	now := time.Now()
	session.limitsFrom = now
	session.lastTraffic = now
	session.lastUpPackets, session.lastDownPackets = 0, 0
	session.nextInterim = time.Time{}
	if interval := s.interimInterval(session); interval > 0 {
		session.nextInterim = now.Add(interval)
	}
	if s.acctQueue != nil {
		session.acctStarted = true
		s.sendAccounting(session, radius.AcctStatusStart, 0, &Counters{})
	}
}

// handleIPPacket handles encapsulated IP packets
func (s *Server) handleIPPacket(session *Session, data []byte) {
	if !session.IsEstablished() {
		return
	}

	// In a real implementation, this would forward the packet
	// For now, just log it
	s.logger.Debug("IP packet received",
		zap.Uint16("session_id", session.ID),
		zap.Int("length", len(data)),
	)
}

// sendDiscoveryPacket sends a PPPoE discovery packet
func (s *Server) sendDiscoveryPacket(dstMAC net.HardwareAddr, code uint8, sessionID uint16, tags []Tag) {
	tagData := SerializeTags(tags)

	hdr := &PPPoEHeader{
		VerType:   0x11,
		Code:      code,
		SessionID: sessionID,
		Length:    uint16(len(tagData)),
	}

	payload := append(hdr.Serialize(), tagData...)
	frame := BuildEthernetFrame(dstMAC, s.serverMAC, EtherTypePPPoEDiscovery, payload)

	s.socket.send(s.iface, dstMAC, EtherTypePPPoEDiscovery, frame)
}

// sendPPPPacket sends a PPP packet over PPPoE session
func (s *Server) sendPPPPacket(session *Session, protocol uint16, data []byte) {
	payload := make([]byte, 2+len(data))
	binary.BigEndian.PutUint16(payload[0:2], protocol)
	copy(payload[2:], data)

	hdr := &PPPoEHeader{
		VerType:   0x11,
		Code:      CodeSession,
		SessionID: session.ID,
		Length:    uint16(len(payload)),
	}

	frame := append(hdr.Serialize(), payload...)
	ethFrame := BuildEthernetFrame(session.ClientMAC, s.serverMAC, EtherTypePPPoESession, frame)

	s.sessionSocket.send(s.iface, session.ClientMAC, EtherTypePPPoESession, ethFrame)
	session.AddBytesOut(uint64(len(ethFrame)))
}

// cleanupExpired terminates sessions that have been idle for longer than
// the session timeout. Data plane traffic bypasses userspace, so activity
// here means control traffic such as LCP Echo keepalives.
func (s *Server) cleanupExpired() {
	timeout := s.sessionTimeout
	if timeout == 0 {
		timeout = 5 * time.Minute
	}
	now := time.Now()
	for _, session := range s.sessions.GetAllSessions() {
		session.mu.RLock()
		inactive := now.Sub(session.LastActivity) > timeout
		session.mu.RUnlock()
		if inactive {
			s.terminateSession(session, "no LCP keepalive", radius.TerminateCauseLostCarrier)
		}
	}
}

// GetSessionCount returns the number of active sessions
func (s *Server) GetSessionCount() int {
	return s.sessions.Count()
}

// GetStats returns PPPoE statistics
func (s *Server) GetStats() map[string]uint64 {
	return map[string]uint64{
		"padi_received":   atomic.LoadUint64(&s.padiReceived),
		"pado_sent":       atomic.LoadUint64(&s.padoSent),
		"padr_received":   atomic.LoadUint64(&s.padrReceived),
		"pads_sent":       atomic.LoadUint64(&s.padsSent),
		"padt_received":   atomic.LoadUint64(&s.padtReceived),
		"padt_sent":       atomic.LoadUint64(&s.padtSent),
		"sessions_total":  atomic.LoadUint64(&s.sessionsTotal),
		"sessions_active": uint64(s.sessions.Count()),
	}
}

// Helper functions

func htons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}

func nextIP(ip net.IP) net.IP {
	next := make(net.IP, len(ip))
	copy(next, ip)
	for i := len(next) - 1; i >= 0; i-- {
		next[i]++
		if next[i] != 0 {
			break
		}
	}
	return next
}

func copyIP(ip net.IP) net.IP {
	dup := make(net.IP, len(ip))
	copy(dup, ip)
	return dup
}

func isBroadcast(ip net.IP, network *net.IPNet) bool {
	if ip == nil {
		return false
	}
	// Check for all-ones broadcast
	ip4 := ip.To4()
	if ip4 != nil {
		return ip4[0] == 255 && ip4[1] == 255 && ip4[2] == 255 && ip4[3] == 255
	}
	// For MAC address broadcast check
	if len(ip) == 6 {
		for _, b := range ip {
			if b != 0xff {
				return false
			}
		}
		return true
	}
	return false
}

func magicToBytes(magic uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, magic)
	return b
}

func isBroadcastMAC(mac net.HardwareAddr) bool {
	if len(mac) != 6 {
		return false
	}
	for _, b := range mac {
		if b != 0xff {
			return false
		}
	}
	return true
}
