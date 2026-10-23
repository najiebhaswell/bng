package nat

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// BlockAllocator hands out CGNAT port blocks (RFC 6431 port block
// allocation) for a data plane that creates the individual mappings itself,
// such as the PPPoE XDP data plane. Every public address is split into
// equal blocks above port 1023; a subscriber gets one block on the least
// used address. Released blocks go to the back of a queue, so a block is
// reused as late as possible.
type BlockAllocator struct {
	mu        sync.Mutex
	blockSize uint16
	addrs     []*blockAddr
	owners    map[[4]byte]*blockOwner // private IP -> block
	gen       uint32
}

type blockAddr struct {
	ip   net.IP
	free []uint16 // block start ports, oldest released first
	used int
}

type blockOwner struct {
	alloc *Allocation
	addr  *blockAddr
}

// BlockPortMin is the first port handed out: well-known ports are not used
const BlockPortMin = 1024

// NewBlockAllocator splits the public addresses into blocks of blockSize
// ports
func NewBlockAllocator(publicIPs []net.IP, blockSize int) (*BlockAllocator, error) {
	if len(publicIPs) == 0 {
		return nil, fmt.Errorf("no public addresses")
	}
	if blockSize < 64 || blockSize > 65536-BlockPortMin {
		return nil, fmt.Errorf("block size %d out of range 64-%d", blockSize, 65536-BlockPortMin)
	}
	a := &BlockAllocator{
		blockSize: uint16(blockSize),
		owners:    make(map[[4]byte]*blockOwner),
	}
	seen := make(map[[4]byte]bool)
	for _, ip := range publicIPs {
		ip4 := ip.To4()
		if ip4 == nil {
			return nil, fmt.Errorf("public address %v is not IPv4", ip)
		}
		if seen[[4]byte(ip4)] {
			continue
		}
		seen[[4]byte(ip4)] = true
		addr := &blockAddr{ip: ip4}
		for start := BlockPortMin; start+blockSize <= 65536; start += blockSize {
			addr.free = append(addr.free, uint16(start))
		}
		a.addrs = append(a.addrs, addr)
	}
	return a, nil
}

// Allocate gives privateIP a port block, or returns the one it holds. gen
// changes with every new assignment and is never 0.
func (a *BlockAllocator) Allocate(privateIP net.IP, username string) (*Allocation, uint32, error) {
	priv := privateIP.To4()
	if priv == nil {
		return nil, 0, fmt.Errorf("private address %v is not IPv4", privateIP)
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	if o, ok := a.owners[[4]byte(priv)]; ok {
		return o.alloc, o.alloc.SubscriberID, nil
	}

	var best *blockAddr
	for _, addr := range a.addrs {
		if len(addr.free) > 0 && (best == nil || addr.used < best.used) {
			best = addr
		}
	}
	if best == nil {
		return nil, 0, fmt.Errorf("NAT pool exhausted: all %d port blocks in use", a.totalLocked())
	}
	start := best.free[0]
	best.free = best.free[1:]
	best.used++

	a.gen++
	if a.gen == 0 {
		a.gen = 1
	}
	alloc := &Allocation{
		PrivateIP:    append(net.IP(nil), priv...),
		PublicIP:     best.ip,
		PortStart:    start,
		PortEnd:      start + a.blockSize - 1,
		SubscriberID: a.gen,
		Username:     username,
		AllocatedAt:  time.Now(),
	}
	a.owners[[4]byte(priv)] = &blockOwner{alloc: alloc, addr: best}
	return alloc, a.gen, nil
}

// Release returns privateIP's block, if it has one
func (a *BlockAllocator) Release(privateIP net.IP) *Allocation {
	priv := privateIP.To4()
	if priv == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	o, ok := a.owners[[4]byte(priv)]
	if !ok {
		return nil
	}
	delete(a.owners, [4]byte(priv))
	o.addr.free = append(o.addr.free, o.alloc.PortStart)
	o.addr.used--
	return o.alloc
}

// BlockSize returns the ports per block
func (a *BlockAllocator) BlockSize() uint16 {
	return a.blockSize
}

// Usage returns the blocks in use and in total
func (a *BlockAllocator) Usage() (used, total int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.owners), a.totalLocked()
}

func (a *BlockAllocator) totalLocked() int {
	n := 0
	for _, addr := range a.addrs {
		n += addr.used + len(addr.free)
	}
	return n
}

// IsPrivateIPv4 reports whether ip is in RFC 1918 or RFC 6598 shared space,
// i.e. a subscriber address that needs CGNAT
func IsPrivateIPv4(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	return ip4[0] == 10 ||
		(ip4[0] == 172 && ip4[1]&0xf0 == 16) ||
		(ip4[0] == 192 && ip4[1] == 168) ||
		(ip4[0] == 100 && ip4[1]&0xc0 == 64)
}

// ParsePublicIPs parses a comma-separated list of addresses and CIDR
// prefixes. For prefixes shorter than /31 the network and broadcast
// addresses are left out.
func ParsePublicIPs(list []string) ([]net.IP, error) {
	var out []net.IP
	for _, s := range list {
		if s == "" {
			continue
		}
		if ip := net.ParseIP(s); ip != nil {
			if ip.To4() == nil {
				return nil, fmt.Errorf("%s is not IPv4", s)
			}
			out = append(out, ip.To4())
			continue
		}
		_, prefix, err := net.ParseCIDR(s)
		if err != nil || prefix.IP.To4() == nil {
			return nil, fmt.Errorf("invalid IPv4 address or prefix %q", s)
		}
		ones, bits := prefix.Mask.Size()
		if bits-ones > 16 {
			return nil, fmt.Errorf("prefix %s is too large", s)
		}
		n := uint32(1) << (bits - ones)
		base := uint32(prefix.IP[0])<<24 | uint32(prefix.IP[1])<<16 | uint32(prefix.IP[2])<<8 | uint32(prefix.IP[3])
		first, last := uint32(0), n-1
		if n > 2 {
			first, last = 1, n-2
		}
		for i := first; i <= last; i++ {
			v := base + i
			out = append(out, net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v)).To4())
		}
	}
	return out, nil
}
