package xrayconf

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/xtls/xray-core/app/router"
	"google.golang.org/protobuf/proto"
)

type GeoIndex struct {
	ip   map[string]bool
	site map[string]bool
}

func LoadGeoIndex(dir string) *GeoIndex {
	g := &GeoIndex{ip: map[string]bool{}, site: map[string]bool{}}
	if b, err := os.ReadFile(filepath.Join(dir, "geoip.dat")); err == nil {
		var list router.GeoIPList
		if proto.Unmarshal(b, &list) == nil {
			for _, e := range list.Entry {
				g.ip[strings.ToUpper(e.CountryCode)] = true
			}
		}
	}
	if b, err := os.ReadFile(filepath.Join(dir, "geosite.dat")); err == nil {
		var list router.GeoSiteList
		if proto.Unmarshal(b, &list) == nil {
			for _, e := range list.Entry {
				g.site[strings.ToUpper(e.CountryCode)] = true
			}
		}
	}
	return g
}

func (g *GeoIndex) Has(entry string) bool {
	kind, code, ok := strings.Cut(entry, ":")
	if !ok {
		return false
	}
	code = strings.TrimPrefix(code, "!")
	code, _, _ = strings.Cut(code, "@")
	code = strings.ToUpper(code)
	switch kind {
	case "geoip":
		return g.ip[code]
	case "geosite":
		return g.site[code]
	}
	return false
}

func (g *GeoIndex) Empty() bool { return len(g.ip) == 0 && len(g.site) == 0 }
