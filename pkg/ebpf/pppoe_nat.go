package ebpf

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// CGNAT in the PPPoE data plane (CGNAT section of bpf/pppoe_dataplane.c).
// Userspace assigns each subscriber a port block (SetSubscriberNAT); the
// data plane creates the mappings from it and ExpireNAT removes idle and
// stale ones.

// natFlagFIN mirrors NAT_F_FIN
const natFlagFIN = 0x01

type pppoeNATMaps struct {
	subs    *ebpf.Map
	out     *ebpf.Map
	in      *ebpf.Map
	poolIPs *ebpf.Map

	// nat_in entries without a matching nat_out entry at the last sweep.
	// They are only deleted if still orphaned at the next one, so a
	// mapping the data plane is creating right now is left alone.
	orphans map[natKey]bool
}

// natSub mirrors struct nat_sub
type natSub struct {
	PublicIP  [4]byte
	PortStart uint16
	PortCount uint16
	Gen       uint32
	_         uint32
}

// natKey mirrors struct nat_key
type natKey struct {
	Addr  [4]byte
	Port  [2]byte // network byte order
	Proto uint8
	_     uint8
}

// natMapping mirrors struct nat_mapping
type natMapping struct {
	Addr     [4]byte
	Port     [2]byte // network byte order
	Flags    uint8
	_        uint8
	Gen      uint32
	_        uint32
	LastSeen uint64 // CLOCK_MONOTONIC ns, 0 = no packet yet
}

// PPPoENATBlock is a subscriber's CGNAT port block
type PPPoENATBlock struct {
	PublicIP  net.IP
	PortStart uint16
	PortCount uint16
	// Gen identifies this assignment of the block; mappings made under
	// another generation are never used. Must not be 0.
	Gen uint32
}

// NATTimeouts are the idle times after which a mapping is removed
type NATTimeouts struct {
	UDP            time.Duration
	TCPEstablished time.Duration
	TCPTransient   time.Duration // Before any reply, and after FIN or RST
	ICMP           time.Duration
}

// DefaultNATTimeouts follow RFC 4787 (UDP at least 2 minutes, 5
// recommended), RFC 5382 (established TCP at least 2 h 4 min, transitory 4
// min) and RFC 5508 (ICMP query 60 s).
var DefaultNATTimeouts = NATTimeouts{
	UDP:            5 * time.Minute,
	TCPEstablished: 124 * time.Minute,
	TCPTransient:   4 * time.Minute,
	ICMP:           time.Minute,
}

// AddNATPublicIP marks a public pool address: traffic to it is translated,
// or dropped if it has no mapping
func (d *PPPoEDataplane) AddNATPublicIP(ip net.IP) error {
	key, err := pppoeIPKey(ip)
	if err != nil {
		return err
	}
	var one uint32 = 1
	if err := d.nat.poolIPs.Put(&key, &one); err != nil {
		return fmt.Errorf("failed to add NAT pool address %v: %w", ip, err)
	}
	return nil
}

// SetSubscriberNAT gives a subscriber address a port block. Install it
// before the session, so no packet leaves untranslated.
func (d *PPPoEDataplane) SetSubscriberNAT(privateIP net.IP, b PPPoENATBlock) error {
	priv, err := pppoeIPKey(privateIP)
	if err != nil {
		return err
	}
	pub, err := pppoeIPKey(b.PublicIP)
	if err != nil {
		return err
	}
	if b.Gen == 0 || b.PortCount == 0 {
		return fmt.Errorf("invalid NAT port block %+v", b)
	}
	v := natSub{PublicIP: pub, PortStart: b.PortStart, PortCount: b.PortCount, Gen: b.Gen}
	if err := d.nat.subs.Put(&priv, &v); err != nil {
		return fmt.Errorf("failed to set NAT port block for %v: %w", privateIP, err)
	}
	return nil
}

// DeleteSubscriberNAT takes a subscriber's port block away. Its mappings
// stop working at once and are deleted by the next ExpireNAT.
func (d *PPPoEDataplane) DeleteSubscriberNAT(privateIP net.IP) error {
	priv, err := pppoeIPKey(privateIP)
	if err != nil {
		return err
	}
	if err := d.nat.subs.Delete(&priv); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("failed to delete NAT port block for %v: %w", privateIP, err)
	}
	return nil
}

// NATSweep is the result of ExpireNAT
type NATSweep struct {
	Active  int // Mappings left
	Expired int // Idle mappings removed
	Stale   int // Mappings of ended sessions removed
	Orphans int // Half-created mappings removed
}

// ExpireNAT removes mappings that were idle longer than their timeout or
// belong to a port block that is gone. Not safe for concurrent use.
func (d *PPPoEDataplane) ExpireNAT(t NATTimeouts) (NATSweep, error) {
	var res NATSweep
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return res, err
	}
	now := uint64(ts.Nano())

	// Work on snapshots read in batches: a lookup per entry would take
	// minutes for a million mappings. Entries the data plane adds or
	// changes meanwhile are at worst kept until the next sweep.
	subKeys, subVals, err := natDump[[4]byte, natSub](d.nat.subs)
	if err != nil {
		return res, fmt.Errorf("failed to read nat_subs: %w", err)
	}
	gens := make(map[[4]byte]uint32, len(subKeys)) // subscriber -> live generation
	for i, k := range subKeys {
		gens[k] = subVals[i].Gen
	}
	live := func(addr [4]byte, gen uint32) bool {
		g, ok := gens[addr]
		return ok && g == gen
	}

	outKeys, outVals, err := natDump[natKey, natMapping](d.nat.out)
	if err != nil {
		return res, fmt.Errorf("failed to read nat_out: %w", err)
	}
	inKeys, inVals, err := natDump[natKey, natMapping](d.nat.in)
	if err != nil {
		return res, fmt.Errorf("failed to read nat_in: %w", err)
	}
	ins := make(map[natKey]natMapping, len(inKeys))
	for i, k := range inKeys {
		ins[k] = inVals[i]
	}
	outs := make(map[natKey]natMapping, len(outKeys))

	for i, outKey := range outKeys {
		out := outVals[i]
		inKey := natKey{Addr: out.Addr, Port: out.Port, Proto: outKey.Proto}
		// The public side, if it still belongs to this mapping: its port
		// may have been claimed again
		in, ok := ins[inKey]
		ok = ok && in.Addr == outKey.Addr && in.Port == outKey.Port && in.Gen == out.Gen
		if !ok {
			in = natMapping{}
		}

		expired := false
		if !live(outKey.Addr, out.Gen) {
			res.Stale++
			expired = true
		} else {
			last := out.LastSeen
			if in.LastSeen > last {
				last = in.LastSeen
			}
			var timeout time.Duration
			switch outKey.Proto {
			case unix.IPPROTO_TCP:
				timeout = t.TCPEstablished
				if in.LastSeen == 0 || (out.Flags|in.Flags)&natFlagFIN != 0 {
					timeout = t.TCPTransient
				}
			case unix.IPPROTO_UDP:
				timeout = t.UDP
			default:
				timeout = t.ICMP
			}
			if now > last && time.Duration(now-last) > timeout {
				res.Expired++
				expired = true
			}
		}
		if !expired {
			res.Active++
			outs[outKey] = out
			continue
		}
		if ok {
			d.nat.in.Delete(&inKey)
			delete(ins, inKey)
		}
		d.nat.out.Delete(&outKey)
	}

	// Public sides whose private side is gone
	orphans := make(map[natKey]bool)
	for inKey, in := range ins {
		outKey := natKey{Addr: in.Addr, Port: in.Port, Proto: inKey.Proto}
		if o, ok := outs[outKey]; ok && o.Addr == inKey.Addr && o.Port == inKey.Port {
			continue
		}
		if !live(in.Addr, in.Gen) || d.nat.orphans[inKey] {
			res.Orphans++
			d.nat.in.Delete(&inKey)
			continue
		}
		orphans[inKey] = true
	}
	d.nat.orphans = orphans
	return res, nil
}

// natDump reads a whole hash map with batch lookups
func natDump[K comparable, V any](m *ebpf.Map) ([]K, []V, error) {
	const batch = 4096
	var keys []K
	var vals []V
	kbuf := make([]K, batch)
	vbuf := make([]V, batch)
	var cursor K
	var prev any // nil: start from the beginning
	for {
		n, err := m.BatchLookup(prev, &cursor, kbuf, vbuf, nil)
		keys = append(keys, kbuf[:n]...)
		vals = append(vals, vbuf[:n]...)
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return keys, vals, nil
		}
		if err != nil {
			return nil, nil, err
		}
		next := cursor
		prev = &next
	}
}
