package ebpf

import (
	"bytes"
	"encoding/binary"
	"net"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"go.uber.org/zap"
)

// These tests run the PPPoE XDP programs in the kernel with BPF_PROG_TEST_RUN.
// They need root and the compiled objects (make -C bpf).

const (
	testPPPoEObject = "../../bpf/pppoe_dataplane.bpf.o"
	testDHCPObject  = "../../bpf/dhcp_fastpath.bpf.o"

	xdpDrop     = 1
	xdpPass     = 2
	xdpRedirect = 4
)

var (
	testClientMAC = net.HardwareAddr{0x02, 0, 0, 0, 0, 0x01}
	testServerMAC = net.HardwareAddr{0xae, 0x93, 0xc7, 0xf4, 0xf1, 0x1a}
	testClientIP  = net.IPv4(100, 64, 0, 3).To4()
	testRemoteIP  = net.IPv4(10, 0, 0, 2).To4()
)

func newTestPPPoEDataplane(t *testing.T) *PPPoEDataplane {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root to load BPF programs")
	}
	if _, err := os.Stat(testPPPoEObject); err != nil {
		t.Skip("BPF object not built (make -C bpf)")
	}
	d, err := NewPPPoEDataplane(testPPPoEObject, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func testSession(vlan uint16) PPPoESession {
	return PPPoESession{
		SessionID:  0x1234,
		ClientMAC:  testClientMAC,
		ServerMAC:  testServerMAC,
		ClientIP:   testClientIP,
		VLANID:     vlan,
		MRU:        1492,
		FIBIfindex: 1,
		TXIfindex:  7,
	}
}

// ipv4Packet builds an IPv4/UDP packet with a valid header checksum
func ipv4Packet(src, dst net.IP, ttl uint8, payloadLen int) []byte {
	pkt := make([]byte, 20+8+payloadLen)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[8] = ttl
	pkt[9] = 17
	copy(pkt[12:16], src)
	copy(pkt[16:20], dst)
	binary.BigEndian.PutUint16(pkt[10:12], ipChecksum(pkt[:20]))
	binary.BigEndian.PutUint16(pkt[24:26], uint16(8+payloadLen))
	return pkt
}

func ipChecksum(hdr []byte) uint16 {
	var sum uint32
	for i := 0; i < len(hdr); i += 2 {
		if i == 10 {
			continue
		}
		sum += uint32(binary.BigEndian.Uint16(hdr[i:]))
	}
	for sum > 0xffff {
		sum = sum>>16 + sum&0xffff
	}
	return ^uint16(sum)
}

// ethernet builds dst | src | [802.1Q tag] | etherType
func ethernet(dst, src net.HardwareAddr, vlan uint16, etherType uint16) []byte {
	b := append(append([]byte{}, dst...), src...)
	if vlan != 0 {
		b = binary.BigEndian.AppendUint16(b, 0x8100)
		b = binary.BigEndian.AppendUint16(b, vlan)
	}
	return binary.BigEndian.AppendUint16(b, etherType)
}

// pppoeFrame builds a PPPoE session frame from the client
func pppoeFrame(vlan, sessionID, pppProto uint16, payload []byte) []byte {
	b := ethernet(testServerMAC, testClientMAC, vlan, 0x8864)
	b = append(b, 0x11, 0)
	b = binary.BigEndian.AppendUint16(b, sessionID)
	b = binary.BigEndian.AppendUint16(b, uint16(len(payload)+2))
	b = binary.BigEndian.AppendUint16(b, pppProto)
	return append(b, payload...)
}

func run(t *testing.T, prog *ebpf.Program, in []byte) (uint32, []byte) {
	t.Helper()
	out := make([]byte, len(in)+64)
	ret, err := prog.Run(&ebpf.RunOptions{Data: in, DataOut: out})
	if err != nil {
		t.Fatalf("test run: %v", err)
	}
	return ret, out
}

func TestPPPoEUpstream(t *testing.T) {
	d := newTestPPPoEDataplane(t)
	if err := d.AddSession(testSession(3001)); err != nil {
		t.Fatal(err)
	}
	prog := d.UpstreamProgram()
	ip := ipv4Packet(testClientIP, testRemoteIP, 64, 18)

	t.Run("decapsulates to the kernel without a redirect port", func(t *testing.T) {
		ret, out := run(t, prog, pppoeFrame(3001, 0x1234, 0x0021, ip))
		if ret != xdpPass {
			t.Fatalf("verdict = %d, want XDP_PASS", ret)
		}
		want := append(ethernet(testServerMAC, testClientMAC, 3001, 0x0800), ip...)
		if !bytes.Equal(out[:len(want)], want) {
			t.Fatalf("output\n %x\nwant\n %x", out[:len(want)], want)
		}
	})

	t.Run("drops spoofed source", func(t *testing.T) {
		spoofed := ipv4Packet(net.IPv4(100, 64, 0, 99).To4(), testRemoteIP, 64, 18)
		if ret, _ := run(t, prog, pppoeFrame(3001, 0x1234, 0x0021, spoofed)); ret != xdpDrop {
			t.Fatalf("verdict = %d, want XDP_DROP", ret)
		}
	})

	for name, frame := range map[string][]byte{
		"unknown session": pppoeFrame(3001, 0x9999, 0x0021, ip),
		"other VLAN":      pppoeFrame(3002, 0x1234, 0x0021, ip),
		"LCP":             pppoeFrame(3001, 0x1234, 0xc021, []byte{9, 1, 0, 8, 0, 0, 0, 0}),
	} {
		t.Run(name+" goes to userspace unchanged", func(t *testing.T) {
			ret, out := run(t, prog, frame)
			if ret != xdpPass || !bytes.Equal(out[:len(frame)], frame) {
				t.Fatalf("verdict = %d, frame modified = %v; want unchanged XDP_PASS", ret, !bytes.Equal(out[:len(frame)], frame))
			}
		})
	}

	t.Run("removed session goes to userspace", func(t *testing.T) {
		if err := d.RemoveSession(testSession(3001)); err != nil {
			t.Fatal(err)
		}
		frame := pppoeFrame(3001, 0x1234, 0x0021, ip)
		if ret, out := run(t, prog, frame); ret != xdpPass || !bytes.Equal(out[:len(frame)], frame) {
			t.Fatalf("verdict = %d; want unchanged XDP_PASS", ret)
		}
	})
}

func TestPPPoEDownstream(t *testing.T) {
	d := newTestPPPoEDataplane(t)
	prog := d.collection.Programs["pppoe_downstream"]
	uplinkMAC := net.HardwareAddr{0xfa, 0xf6, 0xcd, 0x08, 0x1d, 0x70}

	for _, vlan := range []uint16{3001, 0} {
		if err := d.AddSession(testSession(vlan)); err != nil {
			t.Fatal(err)
		}
		ip := ipv4Packet(testRemoteIP, testClientIP, 64, 18)
		in := append(ethernet(uplinkMAC, net.HardwareAddr{2, 0, 0, 0, 0, 2}, 0, 0x0800), ip...)

		ret, out := run(t, prog, in)
		if ret != xdpRedirect {
			t.Fatalf("vlan %d: verdict = %d, want XDP_REDIRECT", vlan, ret)
		}
		forwarded := ipv4Packet(testRemoteIP, testClientIP, 63, 18)
		want := pppoeFrame(vlan, 0x1234, 0x0021, forwarded)
		copy(want[0:6], testClientMAC) // server -> client
		copy(want[6:12], testServerMAC)
		if !bytes.Equal(out[:len(want)], want) {
			t.Fatalf("vlan %d: output\n %x\nwant\n %x", vlan, out[:len(want)], want)
		}
	}

	cases := []struct {
		name string
		ip   []byte
		want uint32
	}{
		{"unknown destination", ipv4Packet(testRemoteIP, net.IPv4(100, 64, 0, 9).To4(), 64, 18), xdpPass},
		{"expiring TTL", ipv4Packet(testRemoteIP, testClientIP, 1, 18), xdpPass},
		{"larger than MRU", ipv4Packet(testRemoteIP, testClientIP, 64, 1500-28), xdpDrop},
	}
	for _, c := range cases {
		in := append(ethernet(uplinkMAC, net.HardwareAddr{2, 0, 0, 0, 0, 2}, 0, 0x0800), c.ip...)
		if ret, _ := run(t, prog, in); ret != c.want {
			t.Errorf("%s: verdict = %d, want %d", c.name, ret, c.want)
		}
	}
}

// The DHCP fast path must hand PPPoE session frames to the PPPoE program
// through its pppoe_progs tail call, and pass them untouched without one.
func TestDHCPFastPathTailCallsPPPoE(t *testing.T) {
	d := newTestPPPoEDataplane(t)
	if _, err := os.Stat(testDHCPObject); err != nil {
		t.Skip("BPF object not built (make -C bpf)")
	}
	coll, err := ebpf.LoadCollection(testDHCPObject)
	if err != nil {
		t.Fatal(err)
	}
	defer coll.Close()
	dhcp := coll.Programs["dhcp_fastpath_prog"]

	if err := d.AddSession(testSession(3001)); err != nil {
		t.Fatal(err)
	}
	ip := ipv4Packet(testClientIP, testRemoteIP, 64, 18)
	frame := pppoeFrame(3001, 0x1234, 0x0021, ip)

	if ret, out := run(t, dhcp, frame); ret != xdpPass || !bytes.Equal(out[:len(frame)], frame) {
		t.Fatalf("without PPPoE program: verdict = %d; want unchanged XDP_PASS", ret)
	}

	var key uint32
	if err := coll.Maps["pppoe_progs"].Put(&key, d.UpstreamProgram()); err != nil {
		t.Fatal(err)
	}
	ret, out := run(t, dhcp, frame)
	want := append(ethernet(testServerMAC, testClientMAC, 3001, 0x0800), ip...)
	if ret != xdpPass || !bytes.Equal(out[:len(want)], want) {
		t.Fatalf("with PPPoE program: verdict = %d, output\n %x\nwant decapsulated\n %x", ret, out[:len(want)], want)
	}
}
