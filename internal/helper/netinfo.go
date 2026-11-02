package helper

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func run(ctx context.Context, name string, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

func scutilGet(ctx context.Context, key string) map[string]string {
	cmd := exec.CommandContext(ctx, "/usr/sbin/scutil")
	cmd.Stdin = strings.NewReader("show " + key + "\n")
	out, err := cmd.Output()
	res := map[string]string{}
	if err != nil {
		return res
	}
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), " : ")
		if ok {
			res[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return res
}

func isVirtual(iface string) bool {
	for _, p := range []string{"utun", "ipsec", "ppp", "lo", "gif", "stf", "awdl", "llw", "bridge", "anpi", "ap"} {
		if strings.HasPrefix(iface, p) {
			return true
		}
	}
	return false
}

func hasIPv4(name string) bool {
	ifc, err := net.InterfaceByName(name)
	if err != nil || ifc.Flags&net.FlagUp == 0 {
		return false
	}
	addrs, _ := ifc.Addrs()
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil && !ipn.IP.IsLinkLocalUnicast() {
			return true
		}
	}
	return false
}

func physicalInterface(ctx context.Context) string {
	g := scutilGet(ctx, "State:/Network/Global/IPv4")
	if p := g["PrimaryInterface"]; p != "" && !isVirtual(p) && hasIPv4(p) {
		return p
	}
	out, err := run(ctx, "/usr/sbin/networksetup", "-listnetworkserviceorder")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(out, "\n") {
		_, rest, ok := strings.Cut(line, "Device: ")
		if !ok {
			continue
		}
		dev := strings.TrimSuffix(strings.TrimSpace(rest), ")")
		if dev != "" && !isVirtual(dev) && hasIPv4(dev) {
			return dev
		}
	}
	return ""
}

func freeUtun() (string, error) {
	for n := 233; n < 400; n++ {
		name := "utun" + strconv.Itoa(n)
		if _, err := net.InterfaceByName(name); err != nil {
			return name, nil
		}
	}
	return "", fmt.Errorf("no free utun interface")
}

func waitInterface(name string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if ifc, err := net.InterfaceByName(name); err == nil && ifc.Flags&net.FlagUp != 0 {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("interface %s did not come up", name)
}

func resolveIPv4(ctx context.Context, host string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", host)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out, nil
}

type NetBirdInfo struct {
	Hosts      []string
	IPs        []string
	WGPort     int
	DNSDomains []string
}

func netbirdBinary() string {
	for _, p := range []string{"/usr/local/bin/netbird", "/opt/homebrew/bin/netbird", "/Applications/NetBird.app/Contents/MacOS/netbird"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	if p, err := exec.LookPath("netbird"); err == nil {
		return p
	}
	return ""
}

func netbirdInfo(ctx context.Context) (*NetBirdInfo, error) {
	bin := netbirdBinary()
	if bin == "" {
		return nil, fmt.Errorf("netbird not installed")
	}
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "status", "--json").Output()
	if err != nil {
		return nil, err
	}
	var st struct {
		DaemonStatus string `json:"daemonStatus"`
		Management   struct {
			URL string `json:"url"`
		} `json:"management"`
		Signal struct {
			URL string `json:"url"`
		} `json:"signal"`
		Relays struct {
			Details []struct {
				URI string `json:"uri"`
			} `json:"details"`
		} `json:"relays"`
		WireguardPort int `json:"wireguardPort"`
		DNSServers    []struct {
			Domains []string `json:"domains"`
		} `json:"dnsServers"`
	}
	if err := json.Unmarshal(out, &st); err != nil {
		return nil, err
	}
	info := &NetBirdInfo{WGPort: st.WireguardPort}
	seen := map[string]bool{}
	addHost := func(raw string) {
		h := hostOf(raw)
		if h == "" || seen[h] {
			return
		}
		seen[h] = true
		info.Hosts = append(info.Hosts, h)
	}
	addHost(st.Management.URL)
	addHost(st.Signal.URL)
	for _, r := range st.Relays.Details {
		addHost(r.URI)
	}
	for _, h := range info.Hosts {
		if ip := net.ParseIP(h); ip != nil {
			info.IPs = append(info.IPs, ip.String())
			continue
		}
		if ips, err := resolveIPv4(ctx, h); err == nil {
			info.IPs = append(info.IPs, ips...)
		}
	}
	dseen := map[string]bool{}
	for _, d := range st.DNSServers {
		for _, dom := range d.Domains {
			if dom != "" && !dseen[dom] {
				dseen[dom] = true
				info.DNSDomains = append(info.DNSDomains, dom)
			}
		}
	}
	return info, nil
}

func hostOf(raw string) string {
	if raw == "" {
		return ""
	}
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		return u.Hostname()
	}
	_, rest, ok := strings.Cut(raw, ":")
	if !ok {
		return raw
	}
	rest = strings.TrimPrefix(rest, "//")
	if h, _, err := net.SplitHostPort(rest); err == nil {
		return h
	}
	return rest
}

func netFingerprint(ctx context.Context) string {
	iface := physicalInterface(ctx)
	if iface == "" {
		return ""
	}
	var addrs []string
	if ifc, err := net.InterfaceByName(iface); err == nil {
		as, _ := ifc.Addrs()
		for _, a := range as {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
				addrs = append(addrs, ipn.IP.String())
			}
		}
	}
	router := scutilGet(ctx, "State:/Network/Global/IPv4")["Router"]
	return iface + "|" + strings.Join(addrs, ",") + "|" + router
}

func waitForNetwork(ctx context.Context, timeout time.Duration) string {
	deadline := time.Now().Add(timeout)
	for {
		if iface := physicalInterface(ctx); iface != "" {
			return iface
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return ""
		}
		select {
		case <-ctx.Done():
			return ""
		case <-time.After(time.Second):
		}
	}
}

func freeLocalPort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func probe(ctx context.Context, port int) (time.Duration, error) {
	tr := &http.Transport{
		Proxy:             http.ProxyURL(&url.URL{Scheme: "socks5", Host: fmt.Sprintf("127.0.0.1:%d", port)}),
		DisableKeepAlives: true,
	}
	defer tr.CloseIdleConnections()
	c := &http.Client{Transport: tr, Timeout: 10 * time.Second}
	var lastErr error
	for _, target := range []string{"http://cp.cloudflare.com/generate_204", "http://www.gstatic.com/generate_204"} {
		start := time.Now()
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		resp, err := c.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusOK {
			return time.Since(start), nil
		}
		lastErr = fmt.Errorf("%s: HTTP %d", target, resp.StatusCode)
	}
	return 0, lastErr
}

func cachedNetbirdInfo(ctx context.Context) (*NetBirdInfo, error) {
	cache := filepath.Join(stateDir, "netbird.json")
	info, err := netbirdInfo(ctx)
	if err == nil && len(info.Hosts) > 0 {
		if b, mErr := json.Marshal(info); mErr == nil {
			_ = os.WriteFile(cache, b, 0o600)
		}
		return info, nil
	}
	b, rErr := os.ReadFile(cache)
	if rErr != nil {
		return nil, err
	}
	var cached NetBirdInfo
	if json.Unmarshal(b, &cached) != nil {
		return nil, err
	}
	return &cached, nil
}
