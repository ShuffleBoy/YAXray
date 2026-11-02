package xrayconf

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/xtls/xray-core/infra/conf/serial"
	_ "github.com/xtls/xray-core/main/distro/all"

	"yaxray/internal/sub"
)

const testLink = "vless://11111111-2222-3333-4444-555555555555@msk-2.example.com:443?encryption=none&flow=xtls-rprx-vision&type=tcp&security=reality&sni=msk-2.example.com&fp=firefox&pbk=TUKku0H2I_0zC0j9l8ZiZP_gEsu0gUzFs73ezNut9w8&sid=0bf536fb336347c3#t"

func testRouting() *sub.Routing {
	return &sub.Routing{
		GlobalProxy: true, RouteOrder: "block-proxy-direct",
		RemoteDNS: "https://8.8.8.8/dns-query", DomesticDNS: "https://77.88.8.8/dns-query",
		DirectSites:    []string{"geosite:private", "geosite:category-ru", "geosite:missing", "domain:example.ru"},
		DirectIP:       []string{"geoip:private", "geoip:direct"},
		ProxySites:     []string{"geosite:youtube"},
		BlockSites:     []string{"geosite:category-ads"},
		DomainStrategy: "IPIfNonMatch",
	}
}

func fakeGeo(e string) bool { return !strings.Contains(e, "missing") }

func build(t *testing.T, o Options) map[string]any {
	t.Helper()
	b, err := Build(o)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestBuildTUNIsValidXrayConfig(t *testing.T) {
	s, err := sub.ParseURI(testLink)
	if err != nil {
		t.Fatal(err)
	}
	o := Options{
		Mode: ModeTUN, Outbound: s.Outbound, TunName: "utun233", Interface: "en0",
		SocksPort: 10808, HTTPPort: 10809,
		Hosts:  map[string][]string{"msk-2.example.com": {"203.0.113.10"}},
		Bypass: Bypass{Domains: []string{"netbird.example.com"}, IPs: []string{"198.51.100.7"}, SourcePorts: []int{51820}},
	}
	b, err := Build(o)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := serial.DecodeJSONConfig(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("decode: %v\n%s", err, b)
	}
	if _, err := cfg.Build(); err != nil {
		t.Fatalf("xray rejected config: %v\n%s", err, b)
	}
}

func TestDNSNeverHijacked(t *testing.T) {
	s, _ := sub.ParseURI(testLink)
	m := build(t, Options{Mode: ModeTUN, Outbound: s.Outbound, TunName: "utun233", Interface: "en0"})
	for _, in := range m["inbounds"].([]any) {
		if p := in.(map[string]any)["protocol"]; p == "dns" || p == "dokodemo-door" {
			t.Fatalf("unexpected DNS inbound %v", p)
		}
	}
	for _, ob := range m["outbounds"].([]any) {
		if ob.(map[string]any)["protocol"] == "dns" {
			t.Fatal("dns outbound would hijack system DNS")
		}
	}
}

func TestRoutingFromHapp(t *testing.T) {
	s, _ := sub.ParseURI(testLink)
	m := build(t, Options{Mode: ModeTUN, Outbound: s.Outbound, TunName: "utun233", Interface: "en0", Routing: testRouting(), HasGeo: fakeGeo})
	rules := m["routing"].(map[string]any)["rules"].([]any)
	var tags []string
	for _, r := range rules {
		tags = append(tags, r.(map[string]any)["outboundTag"].(string))
	}
	want := []string{"direct", "block", "proxy", "direct", "direct", "proxy"}
	if strings.Join(tags, ",") != strings.Join(want, ",") {
		t.Fatalf("rule order %v, want %v", tags, want)
	}
	b, _ := json.Marshal(m)
	if strings.Contains(string(b), "geosite:missing") {
		t.Fatal("missing geosite entry was not filtered")
	}
	if m["routing"].(map[string]any)["domainStrategy"] != "IPIfNonMatch" {
		t.Fatal("domain strategy not taken from profile")
	}
}

func TestOutboundsBoundToInterface(t *testing.T) {
	s, _ := sub.ParseURI(testLink)
	m := build(t, Options{Mode: ModeTUN, Outbound: s.Outbound, TunName: "utun233", Interface: "en7"})
	for _, ob := range m["outbounds"].([]any) {
		o := ob.(map[string]any)
		if o["tag"] == "block" {
			continue
		}
		so := o["streamSettings"].(map[string]any)["sockopt"].(map[string]any)
		if so["interface"] != "en7" {
			t.Fatalf("%v not bound: %v", o["tag"], so)
		}
	}
}

func TestProxyModeHasNoTun(t *testing.T) {
	s, _ := sub.ParseURI(testLink)
	m := build(t, Options{Mode: ModeProxy, Outbound: s.Outbound, SocksPort: 1080, HTTPPort: 1081})
	for _, in := range m["inbounds"].([]any) {
		if in.(map[string]any)["protocol"] == "tun" {
			t.Fatal("tun inbound in proxy mode")
		}
	}
}

func TestProbeInboundForcedThroughProxy(t *testing.T) {
	s, _ := sub.ParseURI(testLink)
	m := build(t, Options{Mode: ModeTUN, Outbound: s.Outbound, TunName: "utun233", Interface: "en0", ProbePort: 47001, Routing: testRouting(), HasGeo: fakeGeo})
	first := m["routing"].(map[string]any)["rules"].([]any)[0].(map[string]any)
	if first["outboundTag"] != "proxy" || first["inboundTag"].([]any)[0] != "probe-in" {
		t.Fatalf("probe rule must be first and go to proxy: %v", first)
	}
}
