package sub

import (
	"encoding/json"
	"errors"
	"strings"
)

type Routing struct {
	Name           string            `json:"name"`
	GlobalProxy    bool              `json:"globalProxy"`
	RouteOrder     string            `json:"routeOrder"`
	RemoteDNS      string            `json:"remoteDns"`
	DomesticDNS    string            `json:"domesticDns"`
	GeoIPURL       string            `json:"geoipUrl"`
	GeoSiteURL     string            `json:"geositeUrl"`
	DNSHosts       map[string]string `json:"dnsHosts,omitempty"`
	DirectSites    []string          `json:"directSites"`
	DirectIP       []string          `json:"directIp"`
	ProxySites     []string          `json:"proxySites"`
	ProxyIP        []string          `json:"proxyIp"`
	BlockSites     []string          `json:"blockSites"`
	BlockIP        []string          `json:"blockIp"`
	DomainStrategy string            `json:"domainStrategy"`
	LastUpdated    string            `json:"lastUpdated"`
}

type happBool bool

func (b *happBool) UnmarshalJSON(data []byte) error {
	s := strings.Trim(strings.ToLower(string(data)), `"`)
	*b = happBool(s == "true" || s == "1")
	return nil
}

type happRouting struct {
	Name              string            `json:"Name"`
	GlobalProxy       happBool          `json:"GlobalProxy"`
	RouteOrder        string            `json:"RouteOrder"`
	RemoteDNSType     string            `json:"RemoteDNSType"`
	RemoteDNSDomain   string            `json:"RemoteDNSDomain"`
	RemoteDNSIP       string            `json:"RemoteDNSIP"`
	DomesticDNSType   string            `json:"DomesticDNSType"`
	DomesticDNSDomain string            `json:"DomesticDNSDomain"`
	DomesticDNSIP     string            `json:"DomesticDNSIP"`
	GeoIPURL          string            `json:"Geoipurl"`
	GeoSiteURL        string            `json:"Geositeurl"`
	LastUpdated       string            `json:"LastUpdated"`
	DNSHosts          map[string]string `json:"DnsHosts"`
	DirectSites       []string          `json:"DirectSites"`
	DirectIP          []string          `json:"DirectIp"`
	ProxySites        []string          `json:"ProxySites"`
	ProxyIP           []string          `json:"ProxyIp"`
	BlockSites        []string          `json:"BlockSites"`
	BlockIP           []string          `json:"BlockIp"`
	DomainStrategy    string            `json:"DomainStrategy"`
}

func ParseHappRouting(v string) (*Routing, error) {
	v = strings.TrimSpace(v)
	if rest, ok := strings.CutPrefix(v, "happ://routing/"); ok {
		_, payload, ok := strings.Cut(rest, "/")
		if !ok {
			return nil, errors.New("malformed happ routing link")
		}
		v = payload
	}
	var data []byte
	if strings.HasPrefix(v, "{") {
		data = []byte(v)
	} else {
		b, err := decodeBase64(v)
		if err != nil {
			return nil, err
		}
		data = b
	}
	var h happRouting
	if err := json.Unmarshal(data, &h); err != nil {
		return nil, err
	}
	r := &Routing{
		Name:           h.Name,
		GlobalProxy:    bool(h.GlobalProxy),
		RouteOrder:     orDefault(h.RouteOrder, "block-proxy-direct"),
		RemoteDNS:      dnsAddress(h.RemoteDNSType, h.RemoteDNSDomain, h.RemoteDNSIP),
		DomesticDNS:    dnsAddress(h.DomesticDNSType, h.DomesticDNSDomain, h.DomesticDNSIP),
		GeoIPURL:       h.GeoIPURL,
		GeoSiteURL:     h.GeoSiteURL,
		DNSHosts:       h.DNSHosts,
		DirectSites:    h.DirectSites,
		DirectIP:       h.DirectIP,
		ProxySites:     h.ProxySites,
		ProxyIP:        h.ProxyIP,
		BlockSites:     h.BlockSites,
		BlockIP:        h.BlockIP,
		DomainStrategy: orDefault(h.DomainStrategy, "IPIfNonMatch"),
		LastUpdated:    h.LastUpdated,
	}
	return r, nil
}

func dnsAddress(typ, domain, ip string) string {
	switch strings.ToLower(typ) {
	case "doh":
		if domain != "" {
			return domain
		}
		if ip != "" {
			return "https://" + ip + "/dns-query"
		}
	case "dot", "tcp":
		if ip != "" {
			return "tcp://" + ip
		}
	}
	return ip
}
