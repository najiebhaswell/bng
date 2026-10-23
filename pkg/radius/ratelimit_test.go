package radius

import (
	"encoding/binary"
	"testing"
)

func TestParseMikrotikRateLimit(t *testing.T) {
	tests := []struct {
		in       string
		up, down uint64
		wantErr  bool
	}{
		{"10M/20M", 10_000_000, 20_000_000, false},
		{"512k/2M", 512_000, 2_000_000, false},
		{"1G", 1_000_000_000, 1_000_000_000, false},
		{"5M/10M 6M/12M 4M/8M 10/10 8", 5_000_000, 10_000_000, false},
		{"2.5M/7.5M", 2_500_000, 7_500_000, false},
		{"1000000/2000000", 1_000_000, 2_000_000, false},
		{"", 0, 0, true},
		{"10X/20M", 0, 0, true},
		{"1M/2M/3M", 0, 0, true},
	}
	for _, tt := range tests {
		up, down, err := ParseMikrotikRateLimit(tt.in)
		if (err != nil) != tt.wantErr || up != tt.up || down != tt.down {
			t.Errorf("ParseMikrotikRateLimit(%q) = %d, %d, %v; want %d, %d, err=%v",
				tt.in, up, down, err, tt.up, tt.down, tt.wantErr)
		}
	}
}

func TestVendorAttribute(t *testing.T) {
	vsa := func(vendor uint32, subs ...[]byte) []byte {
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, vendor)
		for _, s := range subs {
			b = append(b, s...)
		}
		return b
	}
	sub := func(t byte, v string) []byte { return append([]byte{t, byte(2 + len(v))}, v...) }

	got, ok := vendorAttribute(vsa(VendorMikrotik, sub(1, "x"), sub(MikrotikRateLimitAttr, "10M/20M")),
		VendorMikrotik, MikrotikRateLimitAttr)
	if !ok || string(got) != "10M/20M" {
		t.Errorf("vendorAttribute = %q, %v; want 10M/20M", got, ok)
	}
	if _, ok := vendorAttribute(vsa(9, sub(MikrotikRateLimitAttr, "1M")), VendorMikrotik, MikrotikRateLimitAttr); ok {
		t.Error("vendorAttribute matched another vendor")
	}
	if _, ok := vendorAttribute(vsa(VendorMikrotik, []byte{MikrotikRateLimitAttr, 40, 'x'}), VendorMikrotik, MikrotikRateLimitAttr); ok {
		t.Error("vendorAttribute accepted a sub-attribute longer than the VSA")
	}
	if _, ok := vendorAttribute([]byte{0, 0}, VendorMikrotik, MikrotikRateLimitAttr); ok {
		t.Error("vendorAttribute accepted a truncated VSA")
	}
}
