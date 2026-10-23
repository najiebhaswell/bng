package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"
)

func TestSessionFilter(t *testing.T) {
	s := apiSession{
		ID: "a1", Type: "pppoe", Username: "gmedia1", MAC: "02:00:00:00:00:01", State: "Established",
		IPv4: "100.64.0.5", IPv6WAN: "2001:db8:100:5::/64", IPv6PD: "2001:db8:200:5::/64",
		NAT: &apiNAT{PublicIP: "198.18.0.1", PortStart: 1024, PortEnd: 2047},
	}
	for query, want := range map[string]bool{
		"":                             true,
		"username=gmedia1":             true,
		"username=gmedia2":             false,
		"mac=02-00-00-00-00-01":        true,
		"ip=100.64.0.5":                true,
		"ip=2001:db8:100:5::abcd":      true,
		"ip=2001:db8:200:5:1::1":       true,
		"ip=2001:db8:100:6::1":         false,
		"public=198.18.0.1":            true,
		"public=198.18.0.1:1500":       true,
		"public=198.18.0.1:2048":       false,
		"public=198.18.0.2":            false,
		"type=ipoe":                    false,
		"state=established":            true,
		"username=gmedia1&type=pppoe":  true,
		"username=gmedia1&ip=10.0.0.1": false,
	} {
		f, err := parseFilter(httptest.NewRequest("GET", "/api/v1/sessions?"+query, nil))
		if err != nil {
			t.Fatalf("%q: %v", query, err)
		}
		if got := f.match(s); got != want {
			t.Errorf("%q: match = %v, want %v", query, got, want)
		}
	}
	for _, bad := range []string{"ip=nonsense", "public=1.2.3.4:99999"} {
		if _, err := parseFilter(httptest.NewRequest("GET", "/api/v1/sessions?"+bad, nil)); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if f, _ := parseFilter(httptest.NewRequest("GET", "/api/v1/sessions?type=pppoe", nil)); !f.empty() {
		t.Error("a type alone must not select sessions to kill")
	}
}

func TestParseBPS(t *testing.T) {
	for in, want := range map[string]uint64{"0": 0, "10M": 10_000_000, "1.5G": 1_500_000_000, "512k": 512_000, "2500000": 2_500_000} {
		if got, err := parseBPS(in); err != nil || got != want {
			t.Errorf("parseBPS(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	if _, err := parseBPS("fast"); err == nil {
		t.Error("parseBPS accepted nonsense")
	}
	if formatBPS(20_000_000) != "20M" || formatBPS(0) != "unlimited" {
		t.Error("formatBPS")
	}
}

func TestAPIToken(t *testing.T) {
	api := &mgmtAPI{token: "s3cret", logger: zap.NewNop()}
	h := api.handler()
	for auth, want := range map[string]int{
		"":              http.StatusUnauthorized,
		"Bearer wrong":  http.StatusUnauthorized,
		"Bearer s3cret": http.StatusOK,
	} {
		req := httptest.NewRequest("GET", "/api/v1/summary", nil)
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Errorf("Authorization %q: status %d, want %d", auth, rec.Code, want)
		}
	}
}
