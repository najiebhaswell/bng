package sub6

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

// PrefixRouter installs subscribers' prefixes in the data plane
type PrefixRouter interface {
	AddSubscriberPrefix(clientIP net.IP, prefix *net.IPNet) error
	RemoveSubscriberPrefix(prefix *net.IPNet) error
}

// IPoEServer gives DHCP (IPoE) subscribers on an access VLAN interface
// their IPv6: a WAN /64 in Router Advertisements sent to each subscriber
// alone (unicast at layer 2, so subscribers sharing the VLAN do not see each
// other's prefixes) and a delegated prefix over DHCPv6. It reads RS and
// DHCPv6 from an AF_PACKET socket, which tells the sender's MAC address.
type IPoEServer struct {
	iface      *net.Interface
	routerIP   net.IP // the interface's link-local address
	resp       *Responder
	wan, pd    *PrefixPool
	router     PrefixRouter
	raInterval time.Duration
	logger     *zap.Logger

	fd int

	mu   sync.Mutex
	subs map[string]*ipoeSub // MAC -> subscriber
}

type ipoeSub struct {
	mac      net.HardwareAddr
	clientIP net.IP
	sub      Subscriber
}

// IPoEConfig configures an IPoEServer
type IPoEConfig struct {
	Interface  string
	Responder  *Responder
	WANPool    *PrefixPool // nil = no WAN prefix
	PDPool     *PrefixPool // nil = no prefix delegation
	Router     PrefixRouter
	RAInterval time.Duration // unsolicited RAs per subscriber (default 10 min)
}

// NewIPoEServer opens the access interface
func NewIPoEServer(cfg IPoEConfig, logger *zap.Logger) (*IPoEServer, error) {
	iface, err := net.InterfaceByName(cfg.Interface)
	if err != nil {
		return nil, err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	var ll net.IP
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.To4() == nil && n.IP.IsLinkLocalUnicast() {
			ll = n.IP
		}
	}
	if ll == nil {
		return nil, fmt.Errorf("%s has no IPv6 link-local address (is IPv6 disabled on it?)", cfg.Interface)
	}

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_IPV6)))
	if err != nil {
		return nil, fmt.Errorf("AF_PACKET socket: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_IPV6), Ifindex: iface.Index}); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("bind to %s: %w", cfg.Interface, err)
	}
	tv := unix.Timeval{Sec: 1}
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		unix.Close(fd)
		return nil, err
	}

	if cfg.RAInterval == 0 {
		cfg.RAInterval = 10 * time.Minute
	}
	return &IPoEServer{
		iface:      iface,
		routerIP:   ll,
		resp:       cfg.Responder,
		wan:        cfg.WANPool,
		pd:         cfg.PDPool,
		router:     cfg.Router,
		raInterval: cfg.RAInterval,
		logger:     logger,
		fd:         fd,
		subs:       make(map[string]*ipoeSub),
	}, nil
}

func htons(v uint16) uint16 {
	return v<<8 | v>>8
}

// Add gives a leased subscriber its IPv6 prefixes (RADIUS ones if set, else
// from the pools), routes them and advertises the WAN prefix. Adding a MAC
// again changes nothing.
func (s *IPoEServer) Add(mac net.HardwareAddr, clientIP net.IP, framed, delegated *net.IPNet) error {
	key := mac.String()
	s.mu.Lock()
	if _, ok := s.subs[key]; ok {
		s.mu.Unlock()
		return nil
	}
	s.mu.Unlock()

	assign := func(pool *PrefixPool, fromRADIUS *net.IPNet) (*net.IPNet, error) {
		if fromRADIUS != nil {
			if pool != nil {
				if err := pool.Reserve(key, fromRADIUS); err != nil {
					return nil, err
				}
			}
			return fromRADIUS, nil
		}
		if pool == nil {
			return nil, nil
		}
		return pool.Allocate(key)
	}
	release := func() {
		if s.wan != nil {
			s.wan.Release(key)
		}
		if s.pd != nil {
			s.pd.Release(key)
		}
	}

	wan, err := assign(s.wan, framed)
	if err != nil {
		release()
		return fmt.Errorf("WAN prefix: %w", err)
	}
	pd, err := assign(s.pd, delegated)
	if err != nil {
		release()
		return fmt.Errorf("delegated prefix: %w", err)
	}
	for _, p := range []*net.IPNet{wan, pd} {
		if p == nil {
			continue
		}
		if err := s.router.AddSubscriberPrefix(clientIP, p); err != nil {
			for _, q := range []*net.IPNet{wan, pd} {
				if q != nil {
					s.router.RemoveSubscriberPrefix(q)
				}
			}
			release()
			return err
		}
	}

	sub := &ipoeSub{
		mac:      mac,
		clientIP: clientIP,
		sub:      Subscriber{WAN: wan, PD: pd, RouterIP: s.routerIP, RouterMAC: s.iface.HardwareAddr},
	}
	s.mu.Lock()
	s.subs[key] = sub
	s.mu.Unlock()
	s.logger.Info("IPoE subscriber IPv6 up",
		zap.String("mac", key),
		zap.Stringer("wan_prefix", wan),
		zap.Stringer("delegated_prefix", pd),
	)
	s.sendRA(sub, allNodes)
	return nil
}

// Remove takes a subscriber's IPv6 prefixes away
func (s *IPoEServer) Remove(mac net.HardwareAddr) {
	key := mac.String()
	s.mu.Lock()
	sub, ok := s.subs[key]
	delete(s.subs, key)
	s.mu.Unlock()
	if !ok {
		return
	}
	for _, p := range []*net.IPNet{sub.sub.WAN, sub.sub.PD} {
		if p == nil {
			continue
		}
		if err := s.router.RemoveSubscriberPrefix(p); err != nil {
			s.logger.Warn("Failed to remove IPv6 prefix", zap.Stringer("prefix", p), zap.Error(err))
		}
	}
	if s.wan != nil {
		s.wan.Release(key)
	}
	if s.pd != nil {
		s.pd.Release(key)
	}
}

// Prefixes returns a subscriber's WAN and delegated prefix (nil if none)
func (s *IPoEServer) Prefixes(mac net.HardwareAddr) (wan, pd *net.IPNet) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sub, ok := s.subs[mac.String()]; ok {
		return sub.sub.WAN, sub.sub.PD
	}
	return nil, nil
}

func (s *IPoEServer) send(mac net.HardwareAddr, pkt []byte) {
	sa := &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_IPV6), Ifindex: s.iface.Index, Halen: 6}
	copy(sa.Addr[:], mac)
	if err := unix.Sendto(s.fd, pkt, 0, sa); err != nil {
		s.logger.Debug("Failed to send IPv6 control packet", zap.String("mac", mac.String()), zap.Error(err))
	}
}

// sendRA sends a Router Advertisement to one subscriber only: the IPv6
// destination may be ff02::1, the frame goes to its MAC
func (s *IPoEServer) sendRA(sub *ipoeSub, dst net.IP) {
	s.send(sub.mac, s.resp.RouterAdvertisement(&sub.sub, dst))
}

// Run answers RS and DHCPv6 and sends the periodic RAs until ctx ends
func (s *IPoEServer) Run(ctx context.Context) {
	go s.raLoop(ctx)
	defer unix.Close(s.fd)

	buf := make([]byte, 2048)
	for ctx.Err() == nil {
		n, from, err := unix.Recvfrom(s.fd, buf, 0)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
				continue
			}
			s.logger.Warn("IPv6 access socket read failed", zap.Error(err))
			return
		}
		sa, ok := from.(*unix.SockaddrLinklayer)
		if !ok || sa.Pkttype == unix.PACKET_OUTGOING || sa.Halen != 6 || !IsControl(buf[:n]) {
			continue
		}
		mac := net.HardwareAddr(append([]byte(nil), sa.Addr[:6]...))
		s.mu.Lock()
		sub, ok := s.subs[mac.String()]
		s.mu.Unlock()
		if !ok {
			continue
		}
		if reply := s.resp.Handle(buf[:n], &sub.sub); reply != nil {
			s.send(mac, reply)
		}
	}
}

func (s *IPoEServer) raLoop(ctx context.Context) {
	t := time.NewTicker(s.raInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.mu.Lock()
			subs := make([]*ipoeSub, 0, len(s.subs))
			for _, sub := range s.subs {
				subs = append(subs, sub)
			}
			s.mu.Unlock()
			for _, sub := range subs {
				s.sendRA(sub, allNodes)
			}
		}
	}
}
