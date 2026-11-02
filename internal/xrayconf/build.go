package xrayconf

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"yaxray/internal/sub"
)

type Mode string

const (
	ModeTUN   Mode = "tun"
	ModeProxy Mode = "proxy"
)

var PrivateCIDRs = []string{
	"10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
	"172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "255.255.255.255/32",
	"::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
}

type Bypass struct {
	Domains     []string
	IPs         []string
	SourcePorts []int
}

type Options struct {
	Mode      Mode
	Outbound  map[string]any
	TunName   string
	TunMTU    int
	Interface string
	SocksPort int
	HTTPPort  int
	ProbePort int
	Hosts     map[string][]string
	Routing   *sub.Routing
	Bypass    Bypass
	LogLevel  string
	LogFile   string
	HasGeo    func(entry string) bool
}

func Build(o Options) ([]byte, error) {
	if o.Outbound == nil {
		return nil, errors.New("no outbound")
	}
	if o.Mode == ModeTUN && (o.TunName == "" || o.Interface == "") {
		return nil, errors.New("tun mode needs TunName and Interface")
	}
	if o.LogLevel == "" {
		o.LogLevel = "warning"
	}
	if o.TunMTU == 0 {
		o.TunMTU = 1500
	}

	logCfg := map[string]any{"loglevel": o.LogLevel, "access": "none", "dnsLog": false}
	if o.LogFile != "" {
		logCfg["error"] = o.LogFile
	}

	cfg := map[string]any{
		"log":       logCfg,
		"inbounds":  inbounds(o),
		"outbounds": outbounds(o),
		"dns":       dnsSection(o),
		"routing":   routingSection(o),
	}
	return json.MarshalIndent(cfg, "", "  ")
}

func sniffing() map[string]any {
	return map[string]any{
		"enabled":      true,
		"destOverride": []string{"http", "tls", "quic"},
		"routeOnly":    true,
	}
}

func inbounds(o Options) []any {
	var in []any
	if o.Mode == ModeTUN {
		in = append(in, map[string]any{
			"tag":      "tun-in",
			"protocol": "tun",
			"port":     0,
			"settings": map[string]any{"name": o.TunName, "MTU": o.TunMTU},
			"sniffing": sniffing(),
		})
	}
	if o.ProbePort > 0 {
		in = append(in, map[string]any{
			"tag": "probe-in", "protocol": "socks", "listen": "127.0.0.1", "port": o.ProbePort,
			"settings": map[string]any{"udp": false, "auth": "noauth"},
		})
	}
	if o.SocksPort > 0 {
		in = append(in, map[string]any{
			"tag": "socks-in", "protocol": "socks", "listen": "127.0.0.1", "port": o.SocksPort,
			"settings": map[string]any{"udp": true, "auth": "noauth"},
			"sniffing": sniffing(),
		})
	}
	if o.HTTPPort > 0 {
		in = append(in, map[string]any{
			"tag": "http-in", "protocol": "http", "listen": "127.0.0.1", "port": o.HTTPPort,
			"sniffing": sniffing(),
		})
	}
	return in
}

func withSockopt(ob map[string]any, sockopt map[string]any) map[string]any {
	stream, _ := ob["streamSettings"].(map[string]any)
	stream = maps.Clone(stream)
	if stream == nil {
		stream = map[string]any{}
	}
	so, _ := stream["sockopt"].(map[string]any)
	so = maps.Clone(so)
	if so == nil {
		so = map[string]any{}
	}
	maps.Copy(so, sockopt)
	stream["sockopt"] = so
	ob["streamSettings"] = stream
	return ob
}

func outbounds(o Options) []any {
	proxy := deepCopy(o.Outbound)
	proxy["tag"] = "proxy"
	direct := map[string]any{"tag": "direct", "protocol": "freedom", "settings": map[string]any{"domainStrategy": "AsIs"}}
	block := map[string]any{"tag": "block", "protocol": "blackhole"}

	proxySock := map[string]any{}
	if len(o.Hosts) > 0 {
		proxySock["domainStrategy"] = "UseIP"
	}
	if o.Mode == ModeTUN {
		proxySock["interface"] = o.Interface
		direct = withSockopt(direct, map[string]any{"interface": o.Interface})
	}
	if len(proxySock) > 0 {
		proxy = withSockopt(proxy, proxySock)
	}
	return []any{proxy, direct, block}
}

func dnsSection(o Options) map[string]any {
	hosts := map[string]any{}
	for h, ips := range o.Hosts {
		hosts[h] = ips
	}
	var servers []any
	if r := o.Routing; r != nil {
		for h, ip := range r.DNSHosts {
			if _, pinned := hosts[h]; !pinned && ip != "" {
				hosts[h] = ip
			}
		}
		if r.DomesticDNS != "" {
			if doms := geoFilter(o, onlyDomains(r.DirectSites)); len(doms) > 0 {
				servers = append(servers, map[string]any{
					"address": r.DomesticDNS, "domains": doms, "skipFallback": true,
				})
			}
		}
		if r.RemoteDNS != "" {
			servers = append(servers, r.RemoteDNS)
		}
	}
	if len(servers) == 0 {
		servers = append(servers, "https://1.1.1.1/dns-query")
	}
	d := map[string]any{"servers": servers, "queryStrategy": "UseIPv4"}
	if len(hosts) > 0 {
		d["hosts"] = hosts
	}
	return d
}

func onlyDomains(list []string) []string {
	var out []string
	for _, s := range list {
		if !strings.HasPrefix(s, "geoip:") {
			out = append(out, s)
		}
	}
	return out
}

func geoFilter(o Options, list []string) []string {
	var out []string
	for _, e := range list {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if strings.HasPrefix(e, "geosite:") || strings.HasPrefix(e, "geoip:") || strings.HasPrefix(e, "ext:") {
			if o.HasGeo == nil || !o.HasGeo(e) {
				continue
			}
		}
		out = append(out, e)
	}
	return out
}

func rule(tag string, kv ...any) map[string]any {
	r := map[string]any{"type": "field", "outboundTag": tag}
	for i := 0; i+1 < len(kv); i += 2 {
		r[kv[i].(string)] = kv[i+1]
	}
	return r
}

func routingSection(o Options) map[string]any {
	var rules []any
	strategy := "AsIs"

	if o.ProbePort > 0 {
		rules = append(rules, rule("proxy", "inboundTag", []string{"probe-in"}))
	}
	if len(o.Bypass.SourcePorts) > 0 {
		ports := make([]string, 0, len(o.Bypass.SourcePorts))
		for _, p := range o.Bypass.SourcePorts {
			ports = append(ports, fmt.Sprint(p))
		}
		rules = append(rules, rule("direct", "sourcePort", strings.Join(ports, ",")))
	}
	if len(o.Bypass.Domains) > 0 {
		doms := make([]string, 0, len(o.Bypass.Domains))
		for _, d := range o.Bypass.Domains {
			doms = append(doms, "domain:"+d)
		}
		rules = append(rules, rule("direct", "domain", doms))
	}
	rules = append(rules, rule("direct", "ip", slices.Concat(PrivateCIDRs, o.Bypass.IPs)))

	final := "proxy"
	if r := o.Routing; r != nil {
		if r.DomainStrategy != "" {
			strategy = r.DomainStrategy
		}
		groups := map[string][2][]string{
			"block":  {r.BlockSites, r.BlockIP},
			"proxy":  {r.ProxySites, r.ProxyIP},
			"direct": {r.DirectSites, r.DirectIP},
		}
		for _, tag := range routeOrder(r.RouteOrder) {
			g := groups[tag]
			if doms := geoFilter(o, g[0]); len(doms) > 0 {
				rules = append(rules, rule(tag, "domain", doms))
			}
			if ips := geoFilter(o, g[1]); len(ips) > 0 {
				rules = append(rules, rule(tag, "ip", ips))
			}
		}
		if !r.GlobalProxy {
			final = "direct"
		}
	}
	rules = append(rules, rule(final, "network", "tcp,udp"))
	return map[string]any{"domainStrategy": strategy, "rules": rules}
}

func routeOrder(s string) []string {
	var out []string
	seen := map[string]bool{}
	for _, p := range strings.Split(s, "-") {
		p = strings.TrimSpace(strings.ToLower(p))
		if (p == "block" || p == "proxy" || p == "direct") && !seen[p] {
			out = append(out, p)
			seen[p] = true
		}
	}
	for _, p := range []string{"block", "proxy", "direct"} {
		if !seen[p] {
			out = append(out, p)
		}
	}
	return out
}

func deepCopy(m map[string]any) map[string]any {
	b, _ := json.Marshal(m)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	return out
}
