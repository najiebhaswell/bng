//go:build linux

package pppoe

import (
	"net"
	"sync/atomic"
	"syscall"

	"golang.org/x/sys/unix"
)

// socketRcvBuf absorbs bursts of control frames (thousands of sessions
// negotiating at once) while the processing goroutine catches up
const socketRcvBuf = 8 << 20

// linuxRawSocket implements rawSocket using AF_PACKET
type linuxRawSocket struct {
	fd      int
	ifindex int
	dropped uint64 // frames the kernel dropped for a full receive buffer
}

// newRawSocket creates a new platform-specific raw socket
func newRawSocket() rawSocket {
	return &linuxRawSocket{}
}

// open opens the raw socket and binds to the interface
func (s *linuxRawSocket) open(iface string, etherType uint16) error {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(etherType)))
	if err != nil {
		return err
	}
	s.fd = fd

	// Get interface index
	netIface, err := net.InterfaceByName(iface)
	if err != nil {
		syscall.Close(fd)
		return err
	}
	s.ifindex = netIface.Index

	// Bind to interface
	addr := syscall.SockaddrLinklayer{
		Protocol: htons(etherType),
		Ifindex:  netIface.Index,
	}

	if err := syscall.Bind(fd, &addr); err != nil {
		syscall.Close(fd)
		return err
	}

	// Set receive timeout
	tv := syscall.Timeval{Sec: 1, Usec: 0}
	syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

	// A larger receive buffer (beyond rmem_max if we may), and none of
	// the frames we send coming back to us
	if unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, socketRcvBuf) != nil {
		unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, socketRcvBuf)
	}
	unix.SetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_IGNORE_OUTGOING, 1)

	return nil
}

// close closes the raw socket
func (s *linuxRawSocket) close() error {
	if s.fd != 0 {
		return syscall.Close(s.fd)
	}
	return nil
}

// recv receives a packet from the socket
func (s *linuxRawSocket) recv(buf []byte) (int, error) {
	n, _, err := syscall.Recvfrom(s.fd, buf, 0)
	return n, err
}

// send sends a packet on the socket (the interface it was opened on)
func (s *linuxRawSocket) send(_ string, dstMAC net.HardwareAddr, etherType uint16, data []byte) error {
	addr := syscall.SockaddrLinklayer{
		Protocol: htons(etherType),
		Ifindex:  s.ifindex,
		Halen:    6,
	}
	copy(addr.Addr[:], dstMAC)

	return syscall.Sendto(s.fd, data, 0, &addr)
}

// drops returns the frames dropped so far for a full receive buffer
func (s *linuxRawSocket) drops() uint64 {
	// PACKET_STATISTICS resets the kernel's counters on every read
	if st, err := unix.GetsockoptTpacketStats(s.fd, unix.SOL_PACKET, unix.PACKET_STATISTICS); err == nil {
		atomic.AddUint64(&s.dropped, uint64(st.Drops))
	}
	return atomic.LoadUint64(&s.dropped)
}
