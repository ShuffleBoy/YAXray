package sub

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"yaxray/internal/i18n"
)

const ClientName = "YAXray"

const HappUserAgent = "Happ/3.10.2"

func UserAgent(mimicHapp bool) string {
	if mimicHapp {
		return HappUserAgent
	}
	return ClientName
}

type Subscription struct {
	URL            string    `json:"url"`
	Title          string    `json:"title"`
	Servers        []Server  `json:"servers"`
	Routing        *Routing  `json:"routing,omitempty"`
	Upload         int64     `json:"upload"`
	Download       int64     `json:"download"`
	Total          int64     `json:"total"`
	Expire         int64     `json:"expire"`
	UpdateInterval int       `json:"updateInterval"`
	Announce       string    `json:"announce,omitempty"`
	SupportURL     string    `json:"supportUrl,omitempty"`
	WebPageURL     string    `json:"webPageUrl,omitempty"`
	UpdatedAt      time.Time `json:"updatedAt"`
	Skipped        []string  `json:"skipped,omitempty"`
}

func Fetch(ctx context.Context, client *http.Client, rawURL, userAgent string) (*Subscription, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "*/*")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(i18n.T("subscription server responded %s", "сервер подписки ответил %s"), resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, err
	}
	s := &Subscription{URL: rawURL, UpdatedAt: time.Now()}
	s.applyHeaders(resp.Header)
	servers, routing, skipped := ParseBody(body)
	s.Servers, s.Skipped = servers, skipped
	if s.Routing == nil {
		s.Routing = routing
	}
	if len(s.Servers) == 0 {
		if len(skipped) > 0 {
			return nil, fmt.Errorf(i18n.T("subscription has no supported servers (%s)", "в подписке нет поддерживаемых серверов (%s)"), skipped[0])
		}
		return nil, errors.New(i18n.T("subscription has no servers", "в подписке нет серверов"))
	}
	if s.Title == "" {
		s.Title = req.URL.Host
	}
	return s, nil
}

func (s *Subscription) applyHeaders(h http.Header) {
	s.Title = headerText(h.Get("Profile-Title"))
	s.Announce = headerText(h.Get("Announce"))
	s.SupportURL = h.Get("Support-Url")
	s.WebPageURL = h.Get("Profile-Web-Page-Url")
	if v, err := strconv.Atoi(strings.TrimSpace(h.Get("Profile-Update-Interval"))); err == nil {
		s.UpdateInterval = v
	}
	for _, part := range strings.Split(h.Get("Subscription-Userinfo"), ";") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		n, _ := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		switch strings.ToLower(k) {
		case "upload":
			s.Upload = n
		case "download":
			s.Download = n
		case "total":
			s.Total = n
		case "expire":
			s.Expire = n
		}
	}
	if r := h.Get("Routing"); r != "" {
		if routing, err := ParseHappRouting(r); err == nil {
			s.Routing = routing
		}
	}
}

func headerText(v string) string {
	v = strings.TrimSpace(v)
	if rest, ok := strings.CutPrefix(v, "base64:"); ok {
		if b, err := decodeBase64(rest); err == nil {
			return strings.TrimSpace(string(b))
		}
	}
	return v
}

func ParseBody(body []byte) (servers []Server, routing *Routing, skipped []string) {
	body = bytes.TrimSpace(bytes.TrimPrefix(body, []byte("\xef\xbb\xbf")))
	if len(body) == 0 {
		return nil, nil, nil
	}
	if body[0] == '[' || body[0] == '{' {
		srv, err := parseJSONConfigs(body)
		if err != nil {
			return nil, nil, []string{err.Error()}
		}
		return srv, nil, nil
	}
	if !bytes.Contains(body, []byte("://")) {
		if dec, err := decodeBase64(string(body)); err == nil {
			body = dec
		}
	}
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "happ://routing/") {
			if r, err := ParseHappRouting(line); err == nil {
				routing = r
			}
			continue
		}
		srv, err := ParseURI(line)
		if err != nil {
			skipped = append(skipped, fmt.Sprintf("%s: %v", schemeOf(line), err))
			continue
		}
		servers = append(servers, srv)
	}
	return servers, routing, skipped
}

func schemeOf(line string) string {
	if s, _, ok := strings.Cut(line, "://"); ok {
		return s
	}
	return "?"
}

func parseJSONConfigs(body []byte) ([]Server, error) {
	var configs []map[string]any
	if body[0] == '{' {
		var one map[string]any
		if err := json.Unmarshal(body, &one); err != nil {
			return nil, err
		}
		configs = []map[string]any{one}
	} else if err := json.Unmarshal(body, &configs); err != nil {
		return nil, err
	}
	var out []Server
	for i, c := range configs {
		obs, _ := c["outbounds"].([]any)
		var chosen map[string]any
		for _, o := range obs {
			ob, _ := o.(map[string]any)
			if ob == nil {
				continue
			}
			proto, _ := ob["protocol"].(string)
			if proto == "freedom" || proto == "blackhole" || proto == "dns" || proto == "loopback" {
				continue
			}
			if tag, _ := ob["tag"].(string); tag == "proxy" || chosen == nil {
				chosen = ob
			}
		}
		if chosen == nil {
			continue
		}
		delete(chosen, "tag")
		name, _ := c["remarks"].(string)
		proto, _ := chosen["protocol"].(string)
		addr, port := OutboundEndpoint(chosen)
		if name == "" {
			name = fmt.Sprintf("%s #%d", proto, i+1)
		}
		out = append(out, Server{Name: name, Protocol: proto, Address: addr, Port: port, Outbound: chosen})
	}
	return out, nil
}

func OutboundEndpoint(ob map[string]any) (string, int) {
	settings, _ := ob["settings"].(map[string]any)
	if settings == nil {
		return "", 0
	}
	pick := func(m map[string]any) (string, int) {
		a, _ := m["address"].(string)
		p, _ := m["port"].(float64)
		if pi, ok := m["port"].(int); ok {
			p = float64(pi)
		}
		return a, int(p)
	}
	for _, key := range []string{"vnext", "servers"} {
		if list, ok := settings[key].([]any); ok && len(list) > 0 {
			if m, ok := list[0].(map[string]any); ok {
				return pick(m)
			}
		}
	}
	return pick(settings)
}
