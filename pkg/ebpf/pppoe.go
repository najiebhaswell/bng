package ebpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"go.uber.org/zap"
)

// PPPoE data plane (bpf/pppoe_dataplane.c): established PPPoE sessions are
// decapsulated on the access port (pppoe_upstream, tail-called from the DHCP
// fast path) and encapsulated on uplink ports (pppoe_downstream) in XDP.

// pppoeUpKey mirrors struct pppoe_up_key
type pppoeUpKey struct {
	ClientMAC [6]byte
	SessionID [2]byte // network byte order
	VLANID    uint16
	_         uint16
}

// pppoeUpVal mirrors struct pppoe_up_val
type pppoeUpVal struct {
	ClientIP   [4]byte // network byte order
	FIBIfindex uint32
}

// pppoeDownVal mirrors struct pppoe_down_val
type pppoeDownVal struct {
	ClientMAC [6]byte
	ServerMAC [6]byte
	SessionID [2]byte // network byte order
	VLANID    uint16
	TXIfindex uint32
	MRU       uint16
	_         uint16
}

// pppoePolicy mirrors struct pppoe_policy (rates in bytes per second)
type pppoePolicy struct {
	UpRate    uint64
	DownRate  uint64
	UpBurst   uint32
	DownBurst uint32
}

// pppoeSessStats mirrors struct pppoe_sess_stats
type pppoeSessStats struct {
	Lock        uint32 // struct bpf_spin_lock
	_           uint32
	UpTokens    uint64
	UpLastNS    uint64
	DownTokens  uint64
	DownLastNS  uint64
	UpPackets   uint64
	UpBytes     uint64
	DownPackets uint64
	DownBytes   uint64
	UpDropped   uint64
	DownDropped uint64
}

// PPPoE statistic indices (enum in bpf/pppoe_dataplane.c)
var pppoeStatNames = []string{
	"up_redirect",
	"up_kernel",
	"up_control",
	"up_no_session",
	"up_spoofed",
	"down_redirect",
	"down_too_big",
	"down_kernel",
	"up_policed",
	"down_policed",
	"nat_out",
	"nat_in",
	"nat_new",
	"nat_exhausted",
	"nat_no_mapping",
	"nat_unsupported",
	"nat_frag_miss",
	"nat_icmp_error",
}

// PPPoESession describes an established PPPoE session for the data plane
type PPPoESession struct {
	SessionID   uint16
	ClientMAC   net.HardwareAddr
	ServerMAC   net.HardwareAddr
	ClientIP    net.IP
	VLANID      uint16 // Outer VLAN on the access port (0 = untagged)
	MRU         uint16 // Peer MRU: largest IP packet sent to the client
	FIBIfindex  int    // L3 interface of the session (e.g. the VLAN subinterface)
	TXIfindex   int    // Access port the XDP fast path runs on
	UpRateBPS   uint64 // Upload limit in bits/s (0 = unlimited)
	DownRateBPS uint64 // Download limit in bits/s (0 = unlimited)
}

// PPPoECounters are a session's forwarded traffic, as seen by the data plane
type PPPoECounters struct {
	UpPackets   uint64 // From the client
	UpBytes     uint64 // IP bytes from the client
	DownPackets uint64 // To the client
	DownBytes   uint64
	UpDropped   uint64 // Over the upload limit
	DownDropped uint64 // Over the download limit
}

// PPPoEDataplane manages the PPPoE XDP programs and session maps
type PPPoEDataplane struct {
	logger       *zap.Logger
	collection   *ebpf.Collection
	sessionsUp   *ebpf.Map
	sessionsDn   *ebpf.Map
	txPorts      *ebpf.Map
	stats        *ebpf.Map
	policies     *ebpf.Map
	sessionStats *ebpf.Map
	links        []link.Link
	nat          pppoeNATMaps
}

// PPPoEDataplaneOptions tunes the PPPoE data plane
type PPPoEDataplaneOptions struct {
	// NATMappings sizes each of the CGNAT mapping tables (0 = the
	// object's default of 1M). Both are preallocated, about 80 bytes an
	// entry each.
	NATMappings int
}

// NewPPPoEDataplane loads the PPPoE data plane object. Nothing is attached
// until the upstream program is installed with Loader.SetPPPoEProgram and
// uplinks are added with AttachUplink.
func NewPPPoEDataplane(bpfPath string, opts PPPoEDataplaneOptions, logger *zap.Logger) (*PPPoEDataplane, error) {
	if err := checkBPFCapabilities(); err != nil {
		return nil, err
	}

	path := resolveBPFPath(bpfPath)
	spec, err := ebpf.LoadCollectionSpec(path)
	if err != nil {
		return nil, fmt.Errorf("failed to load eBPF spec from %s: %w", path, err)
	}
	if opts.NATMappings > 0 {
		for _, name := range []string{"nat_out", "nat_in"} {
			if m := spec.Maps[name]; m != nil {
				m.MaxEntries = uint32(opts.NATMappings)
			}
		}
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("failed to create eBPF collection: %w", err)
	}

	d := &PPPoEDataplane{
		logger:       logger,
		collection:   coll,
		sessionsUp:   coll.Maps["pppoe_up"],
		sessionsDn:   coll.Maps["pppoe_down"],
		txPorts:      coll.Maps["pppoe_tx_ports"],
		stats:        coll.Maps["pppoe_stats"],
		policies:     coll.Maps["pppoe_policy"],
		sessionStats: coll.Maps["pppoe_sess_stats"],
		nat: pppoeNATMaps{
			subs:    coll.Maps["nat_subs"],
			out:     coll.Maps["nat_out"],
			in:      coll.Maps["nat_in"],
			poolIPs: coll.Maps["nat_pool_ips"],
		},
	}
	if d.sessionsUp == nil || d.sessionsDn == nil || d.txPorts == nil || d.stats == nil ||
		d.policies == nil || d.sessionStats == nil ||
		d.nat.subs == nil || d.nat.out == nil || d.nat.in == nil || d.nat.poolIPs == nil ||
		coll.Programs["pppoe_upstream"] == nil || coll.Programs["pppoe_downstream"] == nil {
		coll.Close()
		return nil, fmt.Errorf("%s is missing PPPoE programs or maps", path)
	}
	return d, nil
}

// UpstreamProgram returns the access-side program for Loader.SetPPPoEProgram
func (d *PPPoEDataplane) UpstreamProgram() *ebpf.Program {
	return d.collection.Programs["pppoe_upstream"]
}

// AttachUplink attaches the downstream program to an uplink port.
//
// XDP_REDIRECT between two ports needs compatible modes: a driver-mode
// redirect transmits through the target driver's XDP queues, which only
// exist while that port runs an XDP program in driver mode. So the uplink
// follows the access port's mode, and upstream traffic is only redirected to
// it if both ended up in the same mode; otherwise upstream goes through the
// kernel (downstream works either way).
func (d *PPPoEDataplane) AttachUplink(iface string, mode, accessMode link.XDPAttachFlags) error {
	netIface, err := net.InterfaceByName(iface)
	if err != nil {
		return fmt.Errorf("failed to get interface %s: %w", iface, err)
	}

	if accessMode == link.XDPGenericMode {
		mode = link.XDPGenericMode
	}
	prog := d.collection.Programs["pppoe_downstream"]
	l, err := link.AttachXDP(link.XDPOptions{Program: prog, Interface: netIface.Index, Flags: mode})
	if err != nil && mode != link.XDPGenericMode {
		d.logger.Warn("Driver mode XDP attach failed on uplink, trying generic mode",
			zap.String("interface", iface),
			zap.Error(err),
		)
		mode = link.XDPGenericMode
		l, err = link.AttachXDP(link.XDPOptions{Program: prog, Interface: netIface.Index, Flags: mode})
	}
	if err != nil {
		return fmt.Errorf("failed to attach PPPoE downstream program to %s: %w", iface, err)
	}
	d.links = append(d.links, l)

	redirect := mode == accessMode
	if redirect {
		ifindex, one := uint32(netIface.Index), uint32(1)
		if err := d.txPorts.Put(&ifindex, &one); err != nil {
			return fmt.Errorf("failed to add %s to pppoe_tx_ports: %w", iface, err)
		}
	}

	d.logger.Info("PPPoE XDP data plane attached to uplink",
		zap.String("interface", iface),
		zap.Uint32("mode", uint32(mode)),
		zap.Bool("upstream_redirect", redirect),
	)
	return nil
}

// AddSession installs (or updates) a session in both directions. Its
// counters start from zero and its rate limit is set from the session.
func (d *PPPoEDataplane) AddSession(s PPPoESession) error {
	upKey, upVal, ip, downVal, err := pppoeEntries(s)
	if err != nil {
		return err
	}
	var zero pppoeSessStats
	if err := d.sessionStats.Put(&ip, &zero); err != nil {
		return fmt.Errorf("failed to add session counters: %w", err)
	}
	if err := d.setPolicy(ip, s.UpRateBPS, s.DownRateBPS); err != nil {
		return err
	}
	if err := d.sessionsUp.Put(&upKey, &upVal); err != nil {
		return fmt.Errorf("failed to add upstream session: %w", err)
	}
	if err := d.sessionsDn.Put(&ip, &downVal); err != nil {
		d.sessionsUp.Delete(&upKey)
		return fmt.Errorf("failed to add downstream session: %w", err)
	}
	return nil
}

// RemoveSession removes a session; entries already gone are not an error
func (d *PPPoEDataplane) RemoveSession(s PPPoESession) error {
	upKey, _, ip, _, err := pppoeEntries(s)
	if err != nil {
		return err
	}
	errs := []error{
		d.sessionsUp.Delete(&upKey),
		d.sessionsDn.Delete(&ip),
		d.policies.Delete(&ip),
		d.sessionStats.Delete(&ip),
	}
	for _, err := range errs {
		if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("failed to remove session: %w", err)
		}
	}
	return nil
}

// SetSessionRate changes the rate limit of an established session (bits/s,
// 0 = unlimited). Counters are not touched.
func (d *PPPoEDataplane) SetSessionRate(clientIP net.IP, upBPS, downBPS uint64) error {
	ip, err := pppoeIPKey(clientIP)
	if err != nil {
		return err
	}
	return d.setPolicy(ip, upBPS, downBPS)
}

// SessionCounters returns a session's forwarded traffic counters
func (d *PPPoEDataplane) SessionCounters(clientIP net.IP) (PPPoECounters, error) {
	ip, err := pppoeIPKey(clientIP)
	if err != nil {
		return PPPoECounters{}, err
	}
	var st pppoeSessStats
	if err := d.sessionStats.Lookup(&ip, &st); err != nil {
		return PPPoECounters{}, fmt.Errorf("failed to read counters for %v: %w", clientIP, err)
	}
	return PPPoECounters{
		UpPackets:   st.UpPackets,
		UpBytes:     st.UpBytes,
		DownPackets: st.DownPackets,
		DownBytes:   st.DownBytes,
		UpDropped:   st.UpDropped,
		DownDropped: st.DownDropped,
	}, nil
}

// setPolicy writes a session's rate limit; no limit in either direction
// removes the entry so the data plane skips the policer entirely.
func (d *PPPoEDataplane) setPolicy(ip [4]byte, upBPS, downBPS uint64) error {
	if upBPS == 0 && downBPS == 0 {
		if err := d.policies.Delete(&ip); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("failed to clear rate limit: %w", err)
		}
		return nil
	}
	pol := pppoePolicy{
		UpRate:    upBPS / 8,
		DownRate:  downBPS / 8,
		UpBurst:   pppoeBurst(upBPS),
		DownBurst: pppoeBurst(downBPS),
	}
	if err := d.policies.Put(&ip, &pol); err != nil {
		return fmt.Errorf("failed to set rate limit: %w", err)
	}
	return nil
}

// pppoeBurst sizes a token bucket at 100 ms of traffic, at least 32 KiB so a
// few full-size packets always fit.
func pppoeBurst(bps uint64) uint32 {
	const minBurst = 32 * 1024
	burst := bps / 8 / 10
	if burst < minBurst {
		return minBurst
	}
	if burst > 1<<31 {
		return 1 << 31
	}
	return uint32(burst)
}

// pppoeIPKey converts a session IPv4 address to its map key
func pppoeIPKey(clientIP net.IP) ([4]byte, error) {
	var ip [4]byte
	ip4 := clientIP.To4()
	if ip4 == nil {
		return ip, fmt.Errorf("client IP %v is not IPv4", clientIP)
	}
	copy(ip[:], ip4)
	return ip, nil
}

// Stats returns the data plane counters summed over all CPUs
func (d *PPPoEDataplane) Stats() (map[string]uint64, error) {
	out := make(map[string]uint64, len(pppoeStatNames))
	for i, name := range pppoeStatNames {
		var perCPU []uint64
		if err := d.stats.Lookup(uint32(i), &perCPU); err != nil {
			return nil, fmt.Errorf("failed to read %s: %w", name, err)
		}
		var sum uint64
		for _, v := range perCPU {
			sum += v
		}
		out[name] = sum
	}
	return out, nil
}

// Close detaches the uplink programs and frees the maps. Remove the upstream
// program from the DHCP fast path (Loader.SetPPPoEProgram(nil)) first.
func (d *PPPoEDataplane) Close() error {
	var errs []error
	for _, l := range d.links {
		if err := l.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	d.links = nil
	d.collection.Close()
	return errors.Join(errs...)
}

// pppoeEntries builds the map entries for a session
func pppoeEntries(s PPPoESession) (pppoeUpKey, pppoeUpVal, [4]byte, pppoeDownVal, error) {
	var upKey pppoeUpKey
	var upVal pppoeUpVal
	var ip [4]byte
	var downVal pppoeDownVal

	ip4 := s.ClientIP.To4()
	if ip4 == nil {
		return upKey, upVal, ip, downVal, fmt.Errorf("session %d: client IP %v is not IPv4", s.SessionID, s.ClientIP)
	}
	if len(s.ClientMAC) != 6 || len(s.ServerMAC) != 6 {
		return upKey, upVal, ip, downVal, fmt.Errorf("session %d: invalid MAC address", s.SessionID)
	}
	copy(ip[:], ip4)

	copy(upKey.ClientMAC[:], s.ClientMAC)
	binary.BigEndian.PutUint16(upKey.SessionID[:], s.SessionID)
	upKey.VLANID = s.VLANID

	upVal.ClientIP = ip
	upVal.FIBIfindex = uint32(s.FIBIfindex)

	copy(downVal.ClientMAC[:], s.ClientMAC)
	copy(downVal.ServerMAC[:], s.ServerMAC)
	downVal.SessionID = upKey.SessionID
	downVal.VLANID = s.VLANID
	downVal.TXIfindex = uint32(s.TXIfindex)
	downVal.MRU = s.MRU

	return upKey, upVal, ip, downVal, nil
}
