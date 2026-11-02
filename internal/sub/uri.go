package sub

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

type Server struct {
	Name     string         `json:"name"`
	Protocol string         `json:"protocol"`
	Address  string         `json:"address"`
	Port     int            `json:"port"`
	Outbound map[string]any `json:"outbound"`
}

func (s Server) Key() string {
	return fmt.Sprintf("%s|%s|%d|%s", s.Protocol, s.Address, s.Port, s.Name)
}

func ParseURI(raw string) (Server, error) {
	raw = strings.TrimSpace(raw)
	scheme, _, ok := strings.Cut(raw, "://")
	if !ok {
		return Server{}, errors.New("not a share link")
	}
	switch strings.ToLower(scheme) {
	case "vless":
		return parseVLESS(raw)
	case "trojan":
		return parseTrojan(raw)
	case "vmess":
		return parseVMess(raw)
	case "ss":
		return parseShadowsocks(raw)
	case "hysteria2", "hy2":
		return parseHysteria2(raw)
	default:
		return Server{}, fmt.Errorf("unsupported scheme %q", scheme)
	}
}

func hostPort(u *url.URL) (string, int, error) {
	host := u.Hostname()
	if host == "" {
		return "", 0, errors.New("empty host")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port <= 0 || port > 65535 {
		return "", 0, fmt.Errorf("bad port %q", u.Port())
	}
	return host, port, nil
}

func fragmentName(u *url.URL, fallback string) string {
	if name := cleanName(u.Fragment); name != "" {
		return name
	}
	return fallback
}

func cleanName(s string) string {
	if i := strings.Index(s, "?serverDescription="); i >= 0 {
		s = s[:i]
	}
	return strings.Join(strings.Fields(s), " ")
}

func parseVLESS(raw string) (Server, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return Server{}, err
	}
	host, port, err := hostPort(u)
	if err != nil {
		return Server{}, err
	}
	q := u.Query()
	id := u.User.Username()
	if id == "" {
		return Server{}, errors.New("vless: empty id")
	}
	user := map[string]any{"id": id, "encryption": orDefault(q.Get("encryption"), "none")}
	if flow := q.Get("flow"); flow != "" {
		user["flow"] = flow
	}
	stream, err := streamFromQuery(q, "none")
	if err != nil {
		return Server{}, err
	}
	out := map[string]any{
		"protocol": "vless",
		"settings": map[string]any{
			"vnext": []any{map[string]any{"address": host, "port": port, "users": []any{user}}},
		},
		"streamSettings": stream,
	}
	return Server{Name: fragmentName(u, host), Protocol: "vless", Address: host, Port: port, Outbound: out}, nil
}

func parseTrojan(raw string) (Server, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return Server{}, err
	}
	host, port, err := hostPort(u)
	if err != nil {
		return Server{}, err
	}
	q := u.Query()
	pass := u.User.Username()
	if pass == "" {
		return Server{}, errors.New("trojan: empty password")
	}
	stream, err := streamFromQuery(q, "tls")
	if err != nil {
		return Server{}, err
	}
	srv := map[string]any{"address": host, "port": port, "password": pass}
	if flow := q.Get("flow"); flow != "" {
		srv["flow"] = flow
	}
	out := map[string]any{
		"protocol":       "trojan",
		"settings":       map[string]any{"servers": []any{srv}},
		"streamSettings": stream,
	}
	return Server{Name: fragmentName(u, host), Protocol: "trojan", Address: host, Port: port, Outbound: out}, nil
}

type vmessLink struct {
	PS   string          `json:"ps"`
	Add  string          `json:"add"`
	Port json.RawMessage `json:"port"`
	ID   string          `json:"id"`
	Aid  json.RawMessage `json:"aid"`
	Scy  string          `json:"scy"`
	Net  string          `json:"net"`
	Type string          `json:"type"`
	Host string          `json:"host"`
	Path string          `json:"path"`
	TLS  string          `json:"tls"`
	SNI  string          `json:"sni"`
	ALPN string          `json:"alpn"`
	FP   string          `json:"fp"`
}

func jsonInt(r json.RawMessage) int {
	s := strings.Trim(string(r), `"`)
	n, _ := strconv.Atoi(s)
	return n
}

func parseVMess(raw string) (Server, error) {
	data, err := decodeBase64(raw[len("vmess://"):])
	if err != nil {
		return Server{}, fmt.Errorf("vmess: %w", err)
	}
	var v vmessLink
	if err := json.Unmarshal(data, &v); err != nil {
		return Server{}, fmt.Errorf("vmess: %w", err)
	}
	port := jsonInt(v.Port)
	if v.Add == "" || port <= 0 || v.ID == "" {
		return Server{}, errors.New("vmess: incomplete link")
	}
	q := url.Values{}
	q.Set("type", orDefault(v.Net, "tcp"))
	q.Set("headerType", v.Type)
	q.Set("host", v.Host)
	q.Set("path", v.Path)
	q.Set("security", orDefault(v.TLS, "none"))
	q.Set("sni", v.SNI)
	q.Set("alpn", v.ALPN)
	q.Set("fp", v.FP)
	if v.Net == "grpc" {
		q.Set("serviceName", v.Path)
		if v.Type == "multi" {
			q.Set("mode", "multi")
		}
	}
	stream, err := streamFromQuery(q, "none")
	if err != nil {
		return Server{}, err
	}
	out := map[string]any{
		"protocol": "vmess",
		"settings": map[string]any{
			"vnext": []any{map[string]any{
				"address": v.Add, "port": port,
				"users": []any{map[string]any{"id": v.ID, "alterId": jsonInt(v.Aid), "security": orDefault(v.Scy, "auto")}},
			}},
		},
		"streamSettings": stream,
	}
	return Server{Name: orDefault(cleanName(v.PS), v.Add), Protocol: "vmess", Address: v.Add, Port: port, Outbound: out}, nil
}

func parseShadowsocks(raw string) (Server, error) {
	rest := raw[len("ss://"):]
	name := ""
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		name, _ = url.PathUnescape(rest[i+1:])
		rest = rest[:i]
	}
	if i := strings.IndexByte(rest, '?'); i >= 0 {
		rest = rest[:i]
	}
	rest = strings.TrimSuffix(rest, "/")
	var userinfo, hp string
	if at := strings.LastIndexByte(rest, '@'); at >= 0 {
		userinfo, hp = rest[:at], rest[at+1:]
		if dec, err := decodeBase64(userinfo); err == nil && strings.Contains(string(dec), ":") {
			userinfo = string(dec)
		} else if un, err := url.PathUnescape(userinfo); err == nil {
			userinfo = un
		}
	} else {
		dec, err := decodeBase64(rest)
		if err != nil {
			return Server{}, fmt.Errorf("ss: %w", err)
		}
		at := strings.LastIndexByte(string(dec), '@')
		if at < 0 {
			return Server{}, errors.New("ss: malformed link")
		}
		userinfo, hp = string(dec[:at]), string(dec[at+1:])
	}
	method, password, ok := strings.Cut(userinfo, ":")
	if !ok {
		return Server{}, errors.New("ss: missing method or password")
	}
	host, portStr, err := net.SplitHostPort(hp)
	if err != nil {
		return Server{}, fmt.Errorf("ss: %w", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return Server{}, fmt.Errorf("ss: bad port")
	}
	out := map[string]any{
		"protocol": "shadowsocks",
		"settings": map[string]any{"servers": []any{map[string]any{
			"address": host, "port": port, "method": method, "password": password,
		}}},
	}
	return Server{Name: orDefault(cleanName(name), host), Protocol: "shadowsocks", Address: host, Port: port, Outbound: out}, nil
}

func parseHysteria2(raw string) (Server, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return Server{}, err
	}
	host, port, err := hostPort(u)
	if err != nil {
		return Server{}, err
	}
	q := u.Query()
	if q.Get("obfs") != "" {
		return Server{}, errors.New("hysteria2: obfs is not supported")
	}
	auth := u.User.Username()
	if p, ok := u.User.Password(); ok {
		auth += ":" + p
	}
	tls := map[string]any{"serverName": orDefault(q.Get("sni"), host), "alpn": []string{"h3"}}
	if q.Get("insecure") == "1" {
		tls["allowInsecure"] = true
	}
	if pin := q.Get("pinSHA256"); pin != "" {
		tls["pinnedPeerCertSha256"] = pin
	}
	out := map[string]any{
		"protocol": "hysteria",
		"settings": map[string]any{"version": 2, "address": host, "port": port},
		"streamSettings": map[string]any{
			"network":          "hysteria",
			"hysteriaSettings": map[string]any{"version": 2, "auth": auth},
			"security":         "tls",
			"tlsSettings":      tls,
		},
	}
	return Server{Name: fragmentName(u, host), Protocol: "hysteria2", Address: host, Port: port, Outbound: out}, nil
}

func streamFromQuery(q url.Values, defSecurity string) (map[string]any, error) {
	network := strings.ToLower(orDefault(q.Get("type"), "tcp"))
	switch network {
	case "splithttp":
		network = "xhttp"
	case "http", "h2":
		network = "xhttp"
	case "raw":
		network = "tcp"
	}
	stream := map[string]any{"network": network}
	host, path := q.Get("host"), q.Get("path")

	switch network {
	case "tcp":
		if q.Get("headerType") == "http" {
			req := map[string]any{"path": []string{orDefault(path, "/")}}
			if host != "" {
				req["headers"] = map[string]any{"Host": strings.Split(host, ",")}
			}
			stream["tcpSettings"] = map[string]any{"header": map[string]any{"type": "http", "request": req}}
		}
	case "ws":
		ws := map[string]any{"path": orDefault(path, "/")}
		if host != "" {
			ws["host"] = host
		}
		stream["wsSettings"] = ws
	case "httpupgrade":
		hu := map[string]any{"path": orDefault(path, "/")}
		if host != "" {
			hu["host"] = host
		}
		stream["httpupgradeSettings"] = hu
	case "grpc":
		g := map[string]any{"serviceName": q.Get("serviceName"), "multiMode": q.Get("mode") == "multi"}
		if a := q.Get("authority"); a != "" {
			g["authority"] = a
		}
		stream["grpcSettings"] = g
	case "xhttp":
		x := map[string]any{"path": orDefault(path, "/")}
		if host != "" {
			x["host"] = host
		}
		if m := q.Get("mode"); m != "" {
			x["mode"] = m
		}
		if extra := q.Get("extra"); extra != "" {
			var e map[string]any
			if err := json.Unmarshal([]byte(extra), &e); err != nil {
				return nil, fmt.Errorf("xhttp extra: %w", err)
			}
			x["extra"] = e
		}
		stream["xhttpSettings"] = x
	case "kcp", "mkcp":
		stream["network"] = "kcp"
		k := map[string]any{}
		if seed := q.Get("seed"); seed != "" {
			k["seed"] = seed
		}
		if ht := q.Get("headerType"); ht != "" && ht != "none" {
			k["header"] = map[string]any{"type": ht}
		}
		stream["kcpSettings"] = k
	default:
		return nil, fmt.Errorf("unsupported transport %q", network)
	}

	security := strings.ToLower(orDefault(q.Get("security"), defSecurity))
	switch security {
	case "", "none":
		stream["security"] = "none"
	case "tls", "xtls":
		tls := map[string]any{}
		if sni := q.Get("sni"); sni != "" {
			tls["serverName"] = sni
		} else if host != "" && network != "tcp" {
			tls["serverName"] = strings.Split(host, ",")[0]
		}
		if fp := q.Get("fp"); fp != "" {
			tls["fingerprint"] = fp
		}
		if alpn := q.Get("alpn"); alpn != "" {
			tls["alpn"] = strings.Split(alpn, ",")
		}
		if q.Get("allowInsecure") == "1" || q.Get("insecure") == "1" {
			tls["allowInsecure"] = true
		}
		if ech := q.Get("ech"); ech != "" {
			tls["echConfigList"] = ech
		}
		stream["security"] = "tls"
		stream["tlsSettings"] = tls
	case "reality":
		pbk := q.Get("pbk")
		if pbk == "" {
			return nil, errors.New("reality: missing pbk")
		}
		r := map[string]any{
			"serverName":  q.Get("sni"),
			"fingerprint": orDefault(q.Get("fp"), "chrome"),
			"publicKey":   pbk,
			"shortId":     q.Get("sid"),
		}
		if spx := q.Get("spx"); spx != "" {
			r["spiderX"] = spx
		}
		if pqv := q.Get("pqv"); pqv != "" {
			r["mldsa65Verify"] = pqv
		}
		stream["security"] = "reality"
		stream["realitySettings"] = r
	default:
		return nil, fmt.Errorf("unsupported security %q", security)
	}
	return stream, nil
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func decodeBase64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.NewReplacer("\n", "", "\r", "", " ", "").Replace(s)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("invalid base64")
}
