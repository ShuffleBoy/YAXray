package sub

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

const (
	vlessReality = "vless://11111111-2222-3333-4444-555555555555@msk-2.example.com:443?encryption=none&flow=xtls-rprx-vision&type=tcp&security=reality&sni=msk-2.example.com&fp=firefox&pbk=TUKku0H2I_0zC0j9l8ZiZP_gEsu0gUzFs73ezNut9w8&sid=0bf536fb336347c3#%F0%9F%87%AA%F0%9F%87%BA%20%D0%95%D0%B2%D1%80%D0%BE%D0%BF%D0%B0"
	vlessXHTTP   = "vless://11111111-2222-3333-4444-555555555555@msk-1.example.com:443?encryption=none&type=xhttp&path=%2Fdownload%2Fupdates&mode=auto&security=reality&sni=msk-1.example.com&fp=firefox&pbk=yKTXHGbVR4Q65WIjz6PSva1wbTJr3a-OpdMP0v2u1E8&sid=1dc16ba81c209d8e#xhttp"
)

func dig(t *testing.T, m any, path ...string) any {
	t.Helper()
	cur := m
	for _, p := range path {
		mm, ok := cur.(map[string]any)
		if !ok {
			t.Fatalf("path %v: %T is not a map", path, cur)
		}
		cur = mm[p]
	}
	return cur
}

func TestParseVLESSReality(t *testing.T) {
	s, err := ParseURI(vlessReality)
	if err != nil {
		t.Fatal(err)
	}
	if s.Name != "🇪🇺 Европа" || s.Address != "msk-2.example.com" || s.Port != 443 {
		t.Fatalf("unexpected server %+v", s)
	}
	if got := dig(t, s.Outbound, "streamSettings", "realitySettings", "publicKey"); got != "TUKku0H2I_0zC0j9l8ZiZP_gEsu0gUzFs73ezNut9w8" {
		t.Fatalf("pbk = %v", got)
	}
	if got := dig(t, s.Outbound, "streamSettings", "network"); got != "tcp" {
		t.Fatalf("network = %v", got)
	}
	user := s.Outbound["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)["users"].([]any)[0].(map[string]any)
	if user["flow"] != "xtls-rprx-vision" {
		t.Fatalf("flow = %v", user["flow"])
	}
}

func TestParseVLESSXHTTP(t *testing.T) {
	s, err := ParseURI(vlessXHTTP)
	if err != nil {
		t.Fatal(err)
	}
	if got := dig(t, s.Outbound, "streamSettings", "xhttpSettings", "path"); got != "/download/updates" {
		t.Fatalf("path = %v", got)
	}
	if got := dig(t, s.Outbound, "streamSettings", "xhttpSettings", "mode"); got != "auto" {
		t.Fatalf("mode = %v", got)
	}
}

func TestParseVMess(t *testing.T) {
	j := `{"v":"2","ps":"vm","add":"1.2.3.4","port":"8443","id":"11111111-2222-3333-4444-555555555555","aid":"0","net":"ws","host":"cdn.example.com","path":"/ws","tls":"tls"}`
	s, err := ParseURI("vmess://" + base64.StdEncoding.EncodeToString([]byte(j)))
	if err != nil {
		t.Fatal(err)
	}
	if s.Port != 8443 || dig(t, s.Outbound, "streamSettings", "wsSettings", "host") != "cdn.example.com" {
		t.Fatalf("unexpected %+v", s.Outbound)
	}
	if dig(t, s.Outbound, "streamSettings", "tlsSettings", "serverName") != "cdn.example.com" {
		t.Fatal("sni should fall back to host")
	}
}

func TestParseShadowsocks(t *testing.T) {
	for _, link := range []string{
		"ss://" + base64.RawURLEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:pa:ss")) + "@5.6.7.8:8388#ss1",
		"ss://" + base64.StdEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:pa:ss@5.6.7.8:8388")) + "#ss1",
		"ss://2022-blake3-aes-128-gcm:pa%3Ass@5.6.7.8:8388#ss1",
	} {
		s, err := ParseURI(link)
		if err != nil {
			t.Fatalf("%s: %v", link, err)
		}
		srv := s.Outbound["settings"].(map[string]any)["servers"].([]any)[0].(map[string]any)
		if srv["password"] != "pa:ss" || s.Port != 8388 || s.Name != "ss1" {
			t.Fatalf("%s: %+v", link, srv)
		}
	}
}

func TestParseTrojanDefaultsToTLS(t *testing.T) {
	s, err := ParseURI("trojan://secret@example.com:443?sni=example.com#tr")
	if err != nil {
		t.Fatal(err)
	}
	if dig(t, s.Outbound, "streamSettings", "security") != "tls" {
		t.Fatal("trojan should default to tls")
	}
}

func TestParseHysteria2(t *testing.T) {
	s, err := ParseURI("hysteria2://pass@example.com:8443?sni=h.example.com&insecure=1#hy")
	if err != nil {
		t.Fatal(err)
	}
	if dig(t, s.Outbound, "streamSettings", "hysteriaSettings", "auth") != "pass" ||
		dig(t, s.Outbound, "streamSettings", "tlsSettings", "serverName") != "h.example.com" {
		t.Fatalf("unexpected %+v", s.Outbound)
	}
}

func TestParseBodyBase64(t *testing.T) {
	body := base64.StdEncoding.EncodeToString([]byte(vlessReality + "\n" + vlessXHTTP + "\nfoo://bar\n"))
	servers, _, skipped := ParseBody([]byte(body))
	if len(servers) != 2 || len(skipped) != 1 {
		t.Fatalf("servers=%d skipped=%v", len(servers), skipped)
	}
}

func TestParseBodyJSON(t *testing.T) {
	cfg := []map[string]any{{
		"remarks": "json-srv",
		"outbounds": []any{
			map[string]any{"tag": "direct", "protocol": "freedom"},
			map[string]any{"tag": "proxy", "protocol": "vless", "settings": map[string]any{
				"vnext": []any{map[string]any{"address": "a.example.com", "port": 443}},
			}},
		},
	}}
	b, _ := json.Marshal(cfg)
	servers, _, _ := ParseBody(b)
	if len(servers) != 1 || servers[0].Address != "a.example.com" || servers[0].Port != 443 {
		t.Fatalf("unexpected %+v", servers)
	}
}

func TestParseHappRouting(t *testing.T) {
	payload := `{"Name":"Только заблокированные","GlobalProxy":"true","RouteOrder":"block-proxy-direct","RemoteDNSType":"DoH","RemoteDNSDomain":"https://8.8.8.8/dns-query","RemoteDNSIP":"8.8.8.8","DomesticDNSType":"DoH","DomesticDNSDomain":"https://77.88.8.8/dns-query","DomesticDNSIP":"77.88.8.8","Geoipurl":"https://x/geoip.dat","Geositeurl":"https://x/geosite.dat","DirectSites":["geosite:private","geosite:category-ru"],"DirectIp":["geoip:private","geoip:direct"],"ProxySites":["geosite:youtube"],"BlockSites":["geosite:category-ads"],"DomainStrategy":"IPIfNonMatch"}`
	r, err := ParseHappRouting("happ://routing/onadd/" + base64.StdEncoding.EncodeToString([]byte(payload)))
	if err != nil {
		t.Fatal(err)
	}
	if !r.GlobalProxy || r.RemoteDNS != "https://8.8.8.8/dns-query" || len(r.DirectSites) != 2 || r.GeoSiteURL != "https://x/geosite.dat" {
		t.Fatalf("unexpected %+v", r)
	}
}

func TestHeaderText(t *testing.T) {
	if got := headerText("base64:0J/QpdCj0Jg="); !strings.HasPrefix(got, "П") {
		t.Fatalf("got %q", got)
	}
}

func TestHappServerDescriptionStripped(t *testing.T) {
	s, err := ParseURI(vlessXHTTP + "%20%20(2)?serverDescription=0JzQtdC00LvQtdC90LXQtQ")
	if err != nil {
		t.Fatal(err)
	}
	if s.Name != "xhttp (2)" {
		t.Fatalf("name = %q", s.Name)
	}
}
