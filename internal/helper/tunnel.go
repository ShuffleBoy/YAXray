package helper

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"yaxray/internal/i18n"
	"yaxray/internal/ipc"
	"yaxray/internal/sub"
	"yaxray/internal/xrayconf"
)

const stateDir = "/Library/Application Support/YAXray"

var (
	tunRoutes4 = []string{
		"1.0.0.0/8", "2.0.0.0/7", "4.0.0.0/6", "8.0.0.0/5",
		"16.0.0.0/4", "32.0.0.0/3", "64.0.0.0/2", "128.0.0.0/1",
	}
	tunRoutes6 = []string{"2000::/3"}
)

const (
	healthEvery     = 30 * time.Second
	healthRetry     = 5 * time.Second
	healthFailLimit = 3
	superviseTick   = 2 * time.Second
	sleepGap        = 10 * time.Second
)

type session struct {
	proc      *xrayProc
	mode      xrayconf.Mode
	tun       string
	iface     string
	netFP     string
	probePort int
	routes    []routeEntry
	proxied   bool
	notes     []string
}

type routeEntry struct{ family, cidr, iface string }

type Manager struct {
	build string

	opMu sync.Mutex
	sess *session
	req  *ipc.ConnectRequest
	stop context.CancelFunc

	stMu   sync.Mutex
	status ipc.Status
}

func NewManager(build string) *Manager {
	m := &Manager{build: build, status: ipc.Status{State: ipc.StateDisconnected}}
	if _, err := os.Stat(filepath.Join(stateDir, "proxy-on")); err == nil {
		clearSystemProxy(context.Background())
		_ = os.Remove(filepath.Join(stateDir, "proxy-on"))
	}
	return m
}

func (m *Manager) Status() ipc.Status {
	m.stMu.Lock()
	defer m.stMu.Unlock()
	s := m.status
	s.Build = m.build
	return s
}

func (m *Manager) setStatus(fn func(*ipc.Status)) ipc.Status {
	m.stMu.Lock()
	defer m.stMu.Unlock()
	fn(&m.status)
	s := m.status
	s.Build = m.build
	return s
}

func (m *Manager) Connect(ctx context.Context, req ipc.ConnectRequest) (ipc.Status, error) {
	i18n.Set(req.Lang)
	m.opMu.Lock()
	defer m.opMu.Unlock()
	m.stopSupervisorLocked()
	m.teardownLocked()
	m.req = nil
	m.setStatus(func(s *ipc.Status) {
		*s = ipc.Status{State: ipc.StateConnecting, Server: req.ServerName, Mode: req.Mode}
	})

	sess, err := m.startSession(ctx, req)
	if err != nil {
		log.Printf("connect failed: %v", err)
		st := m.setStatus(func(s *ipc.Status) {
			*s = ipc.Status{State: ipc.StateError, Server: req.ServerName, Mode: req.Mode, Error: err.Error()}
		})
		return st, err
	}
	m.sess, m.req = sess, &req
	st := m.markUp(sess, req, time.Now())
	supCtx, cancel := context.WithCancel(context.Background())
	m.stop = cancel
	go m.supervise(supCtx)
	log.Printf("connected: server=%q mode=%s iface=%s tun=%s", req.ServerName, req.Mode, sess.iface, sess.tun)
	return st, nil
}

func (m *Manager) markUp(sess *session, req ipc.ConnectRequest, since time.Time) ipc.Status {
	return m.setStatus(func(s *ipc.Status) {
		*s = ipc.Status{
			State: ipc.StateConnected, Server: req.ServerName, Mode: req.Mode,
			Interface: sess.iface, Tun: sess.tun, Since: since, Notes: sess.notes,
		}
	})
}

func (m *Manager) Disconnect() ipc.Status {
	m.opMu.Lock()
	defer m.opMu.Unlock()
	m.stopSupervisorLocked()
	m.teardownLocked()
	m.req = nil
	log.Printf("disconnected")
	return m.setStatus(func(s *ipc.Status) { *s = ipc.Status{State: ipc.StateDisconnected} })
}

func (m *Manager) stopSupervisorLocked() {
	if m.stop != nil {
		m.stop()
		m.stop = nil
	}
}

func (m *Manager) startSession(ctx context.Context, req ipc.ConnectRequest) (*session, error) {
	if req.Outbound == nil {
		return nil, errors.New(i18n.T("no server selected", "не выбран сервер"))
	}
	mode := xrayconf.Mode(req.Mode)
	if mode != xrayconf.ModeTUN && mode != xrayconf.ModeProxy {
		mode = xrayconf.ModeTUN
	}
	if req.SocksPort == 0 {
		req.SocksPort = 10808
	}
	if req.HTTPPort == 0 {
		req.HTTPPort = 10809
	}
	sess := &session{mode: mode}
	opts := xrayconf.Options{
		Mode: mode, Outbound: req.Outbound, Routing: req.Routing,
		SocksPort: req.SocksPort, HTTPPort: req.HTTPPort,
		LogFile: filepath.Join(ipc.LogDir, "xray.log"),
	}
	prepareLogFile(opts.LogFile)

	if iface := waitForNetwork(ctx, 15*time.Second); iface == "" {
		return nil, errors.New(i18n.T("no active network connection", "нет активного сетевого подключения"))
	}

	host, _ := sub.OutboundEndpoint(req.Outbound)
	if host != "" && net.ParseIP(host) == nil {
		ips, err := resolveIPv4(ctx, host)
		if err != nil {
			return nil, fmt.Errorf(i18n.T("cannot resolve server address %s: %w", "не удалось разрешить адрес сервера %s: %w"), host, err)
		}
		opts.Hosts = map[string][]string{host: ips}
	}

	var nb *NetBirdInfo
	if req.BypassNetBird {
		info, err := cachedNetbirdInfo(ctx)
		if err != nil {
			log.Printf("netbird info unavailable: %v", err)
		} else {
			nb = info
			opts.Bypass = xrayconf.Bypass{Domains: info.Hosts, IPs: info.IPs}
			if info.WGPort > 0 {
				opts.Bypass.SourcePorts = []int{info.WGPort}
			}
			sess.notes = append(sess.notes, fmt.Sprintf(i18n.T("NetBird: %d hosts bypass the tunnel", "NetBird: в обход туннеля %d хостов"), len(info.Hosts)))
			log.Printf("netbird bypass: hosts=%v ips=%v wg=%d", info.Hosts, info.IPs, info.WGPort)
		}
	}

	var assetDir string
	if req.GeoDir != "" {
		geo := xrayconf.LoadGeoIndex(req.GeoDir)
		if !geo.Empty() {
			opts.HasGeo = geo.Has
			assetDir = req.GeoDir
		} else if req.Routing != nil {
			sess.notes = append(sess.notes, i18n.T("geo files not found: geosite/geoip rules skipped", "geo-файлы не найдены: правила geosite/geoip пропущены"))
		}
	}

	port, err := freeLocalPort()
	if err != nil {
		return nil, err
	}
	opts.ProbePort, sess.probePort = port, port

	sess.netFP = netFingerprint(ctx)
	if mode == xrayconf.ModeTUN {
		sess.iface = physicalInterface(ctx)
		if sess.iface == "" {
			return nil, errors.New(i18n.T("no active network connection", "нет активного сетевого подключения"))
		}
		tun, err := freeUtun()
		if err != nil {
			return nil, err
		}
		opts.Interface, opts.TunName, sess.tun = sess.iface, tun, tun
	}

	cfg, err := xrayconf.Build(opts)
	if err != nil {
		return nil, err
	}
	_ = os.MkdirAll(stateDir, 0o755)
	cfgPath := filepath.Join(stateDir, "xray-config.json")
	if err := os.WriteFile(cfgPath, cfg, 0o600); err != nil {
		return nil, err
	}

	proc, err := startXrayProc(cfgPath, assetDir)
	if err != nil {
		return nil, fmt.Errorf("xray: %w", err)
	}
	sess.proc = proc

	fail := func(err error) (*session, error) {
		m.teardownSession(sess)
		return nil, err
	}
	switch mode {
	case xrayconf.ModeTUN:
		if err := waitInterface(sess.tun, 5*time.Second); err != nil {
			return fail(err)
		}
		for _, cidr := range tunRoutes4 {
			if err := addRoute(ctx, sess, "-inet", cidr); err != nil {
				return fail(err)
			}
		}
		for _, cidr := range tunRoutes6 {
			if err := addRoute(ctx, sess, "-inet6", cidr); err != nil {
				log.Printf("ipv6 route skipped: %v", err)
			}
		}
	case xrayconf.ModeProxy:
		if err := setSystemProxy(ctx, req.HTTPPort, req.SocksPort, proxyBypassList(nb)); err != nil {
			return fail(fmt.Errorf(i18n.T("system proxy: %w", "системный прокси: %w"), err))
		}
		sess.proxied = true
		_ = os.WriteFile(filepath.Join(stateDir, "proxy-on"), nil, 0o600)
	}
	return sess, nil
}

func prepareLogFile(path string) {
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	if f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644); err == nil {
		f.Close()
	}
	_ = os.Chmod(path, 0o644)
	if st, err := os.Stat(path); err == nil && st.Size() > 20<<20 {
		_ = os.Rename(path, path+".1")
	}
}

func addRoute(ctx context.Context, sess *session, family, cidr string) error {
	_, _ = run(ctx, "/sbin/route", "-q", "-n", "delete", family, "-net", cidr, "-interface", sess.tun)
	if _, err := run(ctx, "/sbin/route", "-q", "-n", "add", family, "-net", cidr, "-interface", sess.tun); err != nil {
		return err
	}
	sess.routes = append(sess.routes, routeEntry{family, cidr, sess.tun})
	return nil
}

func (m *Manager) teardownLocked() {
	if m.sess != nil {
		m.teardownSession(m.sess)
		m.sess = nil
	}
}

func (m *Manager) teardownSession(sess *session) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, r := range sess.routes {
		_, _ = run(ctx, "/sbin/route", "-q", "-n", "delete", r.family, "-net", r.cidr, "-interface", r.iface)
	}
	sess.routes = nil
	if sess.proxied {
		clearSystemProxy(ctx)
		_ = os.Remove(filepath.Join(stateDir, "proxy-on"))
		sess.proxied = false
	}
	sess.proc.stop()
}

func (m *Manager) supervise(ctx context.Context) {
	tick := time.NewTicker(superviseTick)
	defer tick.Stop()

	last := time.Now()
	nextHealth := time.Now().Add(3 * time.Second)
	fails := 0
	backoff := 5 * time.Second

	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		now := time.Now()
		slept := now.Round(0).Sub(last.Round(0)) - now.Sub(last)
		last = now

		m.opMu.Lock()
		sess := m.sess
		m.opMu.Unlock()

		reason := ""
		switch {
		case slept > sleepGap:
			reason = fmt.Sprintf(i18n.T("woke from sleep (%s)", "пробуждение после сна (%s)"), slept.Round(time.Second))
		case sess == nil:
			reason = i18n.T("tunnel is down", "туннель не поднят")
		case !sess.proc.alive():
			reason = fmt.Sprintf(i18n.T("xray exited: %v", "xray завершился: %v"), sess.proc.err)
		default:
			if fp := netFingerprint(ctx); fp != "" && fp != sess.netFP {
				reason = fmt.Sprintf(i18n.T("network changed: %s → %s", "сменилась сеть: %s → %s"), sess.netFP, fp)
			}
		}

		if reason == "" && now.After(nextHealth) {
			rtt, err := probe(ctx, sess.probePort)
			if ctx.Err() != nil {
				return
			}
			if err == nil {
				if fails > 0 {
					log.Printf("health ok again after %d failures, rtt=%s", fails, rtt.Round(time.Millisecond))
				}
				fails, backoff = 0, 5*time.Second
				nextHealth = now.Add(healthEvery)
				m.setStatus(func(s *ipc.Status) {
					s.State, s.Error = ipc.StateConnected, ""
					s.CheckedAt, s.LatencyMS = time.Now(), int(rtt/time.Millisecond)
				})
			} else {
				fails++
				log.Printf("health check failed (%d/%d): %v", fails, healthFailLimit, err)
				nextHealth = now.Add(healthRetry)
				if fails >= healthFailLimit {
					reason = i18n.T("no connectivity through server: ", "нет связи через сервер: ") + err.Error()
				} else if fails >= 2 {
					m.setStatus(func(s *ipc.Status) {
						s.State, s.Error = ipc.StateReconnecting, i18n.T("no connectivity through server", "нет связи через сервер")
					})
				}
			}
		}
		if reason == "" {
			continue
		}

		log.Printf("restarting tunnel: %s", reason)
		m.setStatus(func(s *ipc.Status) { s.State, s.Error = ipc.StateReconnecting, reason })
		if !m.restart(ctx) {
			if ctx.Err() != nil {
				return
			}
			log.Printf("restart failed, next attempt in %s", backoff)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff = min(backoff*2, time.Minute)
			continue
		}
		fails = 0
		last = time.Now()
		nextHealth = time.Now().Add(3 * time.Second)
	}
}

func (m *Manager) restart(ctx context.Context) bool {
	m.opMu.Lock()
	defer m.opMu.Unlock()
	if ctx.Err() != nil || m.req == nil {
		return false
	}
	req := *m.req
	m.teardownLocked()
	sess, err := m.startSession(ctx, req)
	if err != nil {
		log.Printf("restart: %v", err)
		m.setStatus(func(s *ipc.Status) { s.State, s.Error = ipc.StateReconnecting, err.Error() })
		return false
	}
	m.sess = sess
	m.setStatus(func(s *ipc.Status) {
		s.State, s.Error = ipc.StateConnected, ""
		s.Interface, s.Tun, s.Notes = sess.iface, sess.tun, sess.notes
	})
	log.Printf("tunnel rebuilt: iface=%s tun=%s", sess.iface, sess.tun)
	return true
}
