package radius

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

// Mikrotik-Rate-Limit (vendor 14988, attribute 8), the usual way ISPs push a
// subscriber's speed in Access-Accept and CoA-Request.
const (
	VendorMikrotik         = 14988
	MikrotikRateLimitAttr  = 8
	vendorSpecificHdrLen   = 4 // Vendor-Id
	vendorSubAttrHdrLen    = 2 // Vendor-Type + Vendor-Length
	mikrotikRateLimitParts = 2 // rx-rate/tx-rate
)

// vendorAttribute returns the value of sub-attribute vtype of vendor from the
// value of a Vendor-Specific (26) attribute.
func vendorAttribute(vsa []byte, vendor uint32, vtype byte) ([]byte, bool) {
	if len(vsa) < vendorSpecificHdrLen || binary.BigEndian.Uint32(vsa) != vendor {
		return nil, false
	}
	for b := vsa[vendorSpecificHdrLen:]; len(b) >= vendorSubAttrHdrLen; {
		l := int(b[1])
		if l < vendorSubAttrHdrLen || l > len(b) {
			return nil, false
		}
		if b[0] == vtype {
			return b[vendorSubAttrHdrLen:l], true
		}
		b = b[l:]
	}
	return nil, false
}

// ParseMikrotikRateLimit parses a Mikrotik-Rate-Limit value into upload and
// download limits in bits/s. Only the leading "rx-rate[/tx-rate]" part is
// used (burst settings are ignored). As on a MikroTik PPP server, rx is what
// the NAS receives from the subscriber (upload) and tx what it sends
// (download); a single rate applies to both. Suffixes k, M and G are powers
// of 1000.
func ParseMikrotikRateLimit(s string) (upBPS, downBPS uint64, err error) {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return 0, 0, fmt.Errorf("empty rate limit")
	}
	parts := strings.Split(fields[0], "/")
	if len(parts) > mikrotikRateLimitParts {
		return 0, 0, fmt.Errorf("invalid rate limit %q", s)
	}
	if upBPS, err = parseRate(parts[0]); err != nil {
		return 0, 0, fmt.Errorf("invalid rate limit %q: %w", s, err)
	}
	downBPS = upBPS
	if len(parts) == mikrotikRateLimitParts {
		if downBPS, err = parseRate(parts[1]); err != nil {
			return 0, 0, fmt.Errorf("invalid rate limit %q: %w", s, err)
		}
	}
	return upBPS, downBPS, nil
}

// parseRate parses "512k", "10M", "1G" or a plain number of bits/s
func parseRate(s string) (uint64, error) {
	mult := uint64(1)
	switch {
	case strings.HasSuffix(s, "k"), strings.HasSuffix(s, "K"):
		mult = 1_000
	case strings.HasSuffix(s, "M"):
		mult = 1_000_000
	case strings.HasSuffix(s, "G"):
		mult = 1_000_000_000
	}
	if mult != 1 {
		s = s[:len(s)-1]
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil || v < 0 {
		return 0, fmt.Errorf("invalid rate %q", s)
	}
	return uint64(v * float64(mult)), nil
}
