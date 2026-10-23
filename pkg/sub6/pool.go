// Package sub6 is the per-subscriber IPv6 control plane of the BNG: prefix
// pools for the subscribers' WAN /64 (SLAAC) and delegated prefixes, and
// the answers to their Router Solicitations and DHCPv6 requests. It works
// on raw IPv6 packets, so PPPoE (inside PPP) and IPoE (on the access VLAN)
// share it.
package sub6

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
)

// PrefixPool hands out prefixes of one length (at most /64) from a larger
// prefix. Released prefixes are reused oldest first.
type PrefixPool struct {
	mu     sync.Mutex
	base   uint64 // upper 64 bits of the pool prefix
	shift  uint   // 64 - length: index -> prefix
	count  uint64 // prefixes in the pool
	length int
	next   uint64   // never handed out from here on
	free   []uint64 // released, oldest first
	owners map[string]uint64
	used   map[uint64]string
}

// NewPrefixPool splits cidr into prefixes of length bits
func NewPrefixPool(cidr string, length int) (*PrefixPool, error) {
	_, pool, err := net.ParseCIDR(cidr)
	if err != nil || pool.IP.To4() != nil {
		return nil, fmt.Errorf("invalid IPv6 prefix %q", cidr)
	}
	ones, _ := pool.Mask.Size()
	if length > 64 || length <= ones || length-ones > 32 {
		return nil, fmt.Errorf("cannot split %s into /%d prefixes (at most /64 and 2^32 prefixes)", cidr, length)
	}
	return &PrefixPool{
		base:   binary.BigEndian.Uint64(pool.IP[:8]),
		shift:  uint(64 - length),
		count:  1 << uint(length-ones),
		length: length,
		owners: make(map[string]uint64),
		used:   make(map[uint64]string),
	}, nil
}

// Length returns the length of the prefixes handed out
func (p *PrefixPool) Length() int {
	return p.length
}

func (p *PrefixPool) prefix(i uint64) *net.IPNet {
	ip := make(net.IP, 16)
	binary.BigEndian.PutUint64(ip[:8], p.base|i<<p.shift)
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(p.length, 128)}
}

// index returns the pool index of prefix, if it is one of the pool's
func (p *PrefixPool) index(prefix *net.IPNet) (uint64, bool) {
	ones, bits := prefix.Mask.Size()
	ip := prefix.IP.To16()
	if bits != 128 || ones != p.length || ip == nil || ip.To4() != nil {
		return 0, false
	}
	hi := binary.BigEndian.Uint64(ip[:8])
	i := (hi - p.base) >> p.shift
	if hi&^(^uint64(0)<<p.shift) != 0 || i >= p.count || p.base|i<<p.shift != hi {
		return 0, false
	}
	return i, true
}

// Allocate returns owner's prefix, allocating one if it has none
func (p *PrefixPool) Allocate(owner string) (*net.IPNet, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if i, ok := p.owners[owner]; ok {
		return p.prefix(i), nil
	}
	var i uint64
	switch {
	case len(p.free) > 0:
		i, p.free = p.free[0], p.free[1:]
	case p.next < p.count:
		i = p.next
		p.next++
	default:
		return nil, fmt.Errorf("IPv6 pool exhausted (%d /%d prefixes in use)", len(p.used), p.length)
	}
	p.owners[owner] = i
	p.used[i] = owner
	return p.prefix(i), nil
}

// Reserve gives owner a specific prefix (e.g. from RADIUS). A prefix
// outside the pool is accepted as is; one inside must be free.
func (p *PrefixPool) Reserve(owner string, prefix *net.IPNet) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	i, inPool := p.index(prefix)
	if !inPool {
		return nil
	}
	if o, ok := p.used[i]; ok {
		if o == owner {
			return nil
		}
		return fmt.Errorf("prefix %v is in use", prefix)
	}
	if old, ok := p.owners[owner]; ok {
		p.releaseLocked(owner, old)
	}
	if i >= p.next {
		// Skip it when handing out new prefixes; the ones in between are
		// free
		for j := p.next; j < i; j++ {
			p.free = append(p.free, j)
		}
		p.next = i + 1
	} else {
		for k, j := range p.free {
			if j == i {
				p.free = append(p.free[:k], p.free[k+1:]...)
				break
			}
		}
	}
	p.owners[owner] = i
	p.used[i] = owner
	return nil
}

// Release returns owner's prefix to the pool
func (p *PrefixPool) Release(owner string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if i, ok := p.owners[owner]; ok {
		p.releaseLocked(owner, i)
	}
}

func (p *PrefixPool) releaseLocked(owner string, i uint64) {
	delete(p.owners, owner)
	delete(p.used, i)
	p.free = append(p.free, i)
}

// Usage returns the prefixes in use and in total
func (p *PrefixPool) Usage() (used int, total uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.used), p.count
}
