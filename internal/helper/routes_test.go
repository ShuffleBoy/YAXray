package helper

import (
	"net/netip"
	"testing"
)

func TestTunRoutesCoverEverythingExceptZeroNet(t *testing.T) {
	var prefixes []netip.Prefix
	total := uint64(0)
	for _, r := range tunRoutes4 {
		p := netip.MustParsePrefix(r)
		prefixes = append(prefixes, p)
		total += 1 << (32 - p.Bits())
	}
	if want := uint64(1<<32 - 1<<24); total != want {
		t.Fatalf("routes cover %d addresses, want %d", total, want)
	}
	for _, probe := range []string{"0.0.0.0", "0.255.255.255"} {
		for _, p := range prefixes {
			if p.Contains(netip.MustParseAddr(probe)) {
				t.Fatalf("%s is covered by %s", probe, p)
			}
		}
	}
	for _, probe := range []string{"1.1.1.1", "8.8.8.8", "77.88.8.8", "127.0.0.1", "255.255.255.254", "93.90.226.243"} {
		found := false
		for _, p := range prefixes {
			found = found || p.Contains(netip.MustParseAddr(probe))
		}
		if !found {
			t.Fatalf("%s is not covered", probe)
		}
	}
}

func TestHostOf(t *testing.T) {
	cases := map[string]string{
		"https://netbird.example.ru:443":  "netbird.example.ru",
		"stun:nb-relay1.example.ru:3478":  "nb-relay1.example.ru",
		"rels://nb-relay2.example.ru:443": "nb-relay2.example.ru",
	}
	for in, want := range cases {
		if got := hostOf(in); got != want {
			t.Errorf("hostOf(%q) = %q, want %q", in, got, want)
		}
	}
}
