package app

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"fyne.io/systray"

	"yaxray/internal/helper"
	"yaxray/internal/i18n"
	"yaxray/internal/ipc"
	"yaxray/internal/sub"
)

const appName = "YAXray"

type App struct {
	mu       sync.Mutex
	cfg      *Config
	status   ipc.Status
	helperUp bool
	busy     bool

	client  *ipc.Client
	exePath string
	build   string
	icons   map[iconKind][]byte

	menuDone   chan struct{}
	statusItem *systray.MenuItem
	toggleItem *systray.MenuItem
}

func Run() {
	i18n.Detect()
	exe, _ := os.Executable()
	exe, _ = filepath.EvalSymlinks(exe)
	lock, err := singleInstance()
	if err != nil {
		Alert(appName, i18n.T("YAXray is already running — look for the shield icon in the menu bar.", "YAXray уже запущен — ищите иконку щита в строке меню."), false)
		return
	}
	defer lock.Close()

	_ = os.MkdirAll(supportDir(), 0o700)
	if f, err := os.OpenFile(filepath.Join(supportDir(), "app.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err == nil {
		log.SetOutput(f)
	}

	a := &App{
		cfg:     loadConfig(),
		client:  ipc.NewClient(),
		exePath: exe,
		build:   helper.BuildID(exe),
		status:  ipc.Status{State: ipc.StateDisconnected},
		icons: map[iconKind][]byte{
			iconOff: renderIcon(iconOff), iconBusy: renderIcon(iconBusy), iconOn: renderIcon(iconOn),
		},
	}
	systray.Run(a.onReady, func() {})
}

func singleInstance() (*os.File, error) {
	_ = os.MkdirAll(supportDir(), 0o700)
	f, err := os.OpenFile(filepath.Join(supportDir(), "app.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func (a *App) onReady() {
	systray.SetTemplateIcon(a.icons[iconOff], a.icons[iconOff])
	systray.SetTooltip(appName)
	a.refreshStatus()
	a.rebuildMenu()
	go a.pollLoop()
	go a.autoUpdateLoop()

	a.mu.Lock()
	noSubs := len(a.cfg.Subs) == 0
	autoConnect := a.cfg.Settings.ConnectOnLaunch && a.status.State != ipc.StateConnected && a.status.State != ipc.StateReconnecting
	a.mu.Unlock()
	switch {
	case noSubs:
		go a.addSubscription()
	case autoConnect:
		go a.connect()
	}
}

func (a *App) refreshStatus() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	st, err := a.client.Status(ctx)
	a.mu.Lock()
	prev := a.status.State
	a.helperUp = err == nil
	if err != nil {
		st = ipc.Status{State: ipc.StateDisconnected}
	}
	if a.busy && st.State != ipc.StateConnected {
		st.State = ipc.StateConnecting
	}
	a.status = st
	a.mu.Unlock()
	if prev != st.State {
		log.Printf("state %s → %s (server=%q err=%q helper=%v)", prev, st.State, st.Server, st.Error, err == nil)
	}
	switch {
	case prev == ipc.StateConnected && st.State == ipc.StateReconnecting:
		Notify(appName, i18n.T("VPN connection lost, reconnecting: ", "Связь через VPN пропала, переподключаюсь: ")+st.Error)
	case prev == ipc.StateReconnecting && st.State == ipc.StateConnected:
		Notify(appName, i18n.T("Connection restored", "Связь восстановлена"))
	case prev == ipc.StateConnected && st.State == ipc.StateError:
		Notify(appName, i18n.T("Connection lost: ", "Соединение потеряно: ")+st.Error)
	}
	a.renderStatus()
}

func (a *App) pollLoop() {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for range t.C {
		a.refreshStatus()
	}
}

func (a *App) renderStatus() {
	a.mu.Lock()
	st, busy := a.status, a.busy
	statusItem, toggleItem := a.statusItem, a.toggleItem
	a.mu.Unlock()

	var line, toggle string
	icon := iconOff
	switch {
	case busy || st.State == ipc.StateConnecting:
		icon, line, toggle = iconBusy, i18n.T("Connecting…", "Подключение…"), i18n.T("Connecting…", "Подключение…")
	case st.State == ipc.StateConnected:
		icon = iconOn
		mode := "TUN"
		if st.Mode == "proxy" {
			mode = i18n.T("proxy", "прокси")
		}
		line = fmt.Sprintf(i18n.T("Connected · %s · %s since %s", "Подключено · %s · %s с %s"), st.Server, mode, st.Since.Local().Format("15:04"))
		if st.LatencyMS > 0 {
			line += fmt.Sprintf(i18n.T(" · %d ms", " · %d мс"), st.LatencyMS)
		}
		toggle = i18n.T("Disconnect", "Отключить")
	case st.State == ipc.StateReconnecting:
		icon = iconBusy
		line = i18n.T("No connectivity, reconnecting… ", "Нет связи, переподключаюсь… ") + truncate(st.Error, 50)
		toggle = i18n.T("Disconnect", "Отключить")
	case st.State == ipc.StateError:
		line, toggle = i18n.T("Error: ", "Ошибка: ")+truncate(st.Error, 60), i18n.T("Connect", "Подключить")
	default:
		line, toggle = i18n.T("Not connected", "Не подключено"), i18n.T("Connect", "Подключить")
	}
	systray.SetTemplateIcon(a.icons[icon], a.icons[icon])
	systray.SetTooltip(appName + " — " + line)
	if statusItem != nil {
		statusItem.SetTitle(line)
	}
	if toggleItem != nil {
		toggleItem.SetTitle(toggle)
		if busy {
			toggleItem.Disable()
		} else {
			toggleItem.Enable()
		}
	}
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

func (a *App) ensureHelper() error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	st, err := a.client.Status(ctx)
	cancel()
	if err == nil && st.Build == a.build {
		return nil
	}
	msg := i18n.T("YAXray needs a system component for the VPN: it creates the TUN interface and routes.\n\nIt does not touch system DNS — NetBird and split DNS keep working.\n\nmacOS will ask for an administrator password.", "Для работы VPN нужен системный компонент YAXray: он создаёт TUN-интерфейс и маршруты.\n\nСистемный DNS он не трогает — NetBird и split-DNS продолжат работать.\n\nmacOS попросит пароль администратора.")
	if err == nil {
		msg = i18n.T("The YAXray system component is outdated and will be updated. macOS will ask for an administrator password.", "Системный компонент YAXray устарел и будет обновлён. macOS попросит пароль администратора.")
	}
	if !Confirm(appName, msg, i18n.T("Install", "Установить")) {
		return errCancelled
	}
	uid := strconv.Itoa(os.Getuid())
	if err := RunAsAdmin(i18n.T("YAXray is installing its VPN system component.", "YAXray устанавливает системный компонент для VPN."), a.exePath, "install-helper", "--uid", uid, "--src", a.exePath); err != nil {
		return fmt.Errorf(i18n.T("installation failed: %w", "установка не удалась: %w"), err)
	}
	for range 30 {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		st, err = a.client.Status(ctx)
		cancel()
		if err == nil && st.Build == a.build {
			return nil
		}
		time.Sleep(300 * time.Millisecond)
	}
	return errors.New(i18n.T("system component is not responding, see /Library/Logs/YAXray/helper.log", "системный компонент не отвечает, см. /Library/Logs/YAXray/helper.log"))
}

func (a *App) setBusy(b bool) {
	a.mu.Lock()
	a.busy = b
	a.mu.Unlock()
	a.renderStatus()
}

func (a *App) connect() {
	a.mu.Lock()
	if a.busy {
		a.mu.Unlock()
		return
	}
	a.busy = true
	a.mu.Unlock()
	a.renderStatus()
	defer func() {
		a.setBusy(false)
		a.refreshStatus()
	}()

	if err := a.ensureHelper(); err != nil {
		if !errors.Is(err, errCancelled) {
			Alert(appName, err.Error(), true)
		}
		return
	}

	a.mu.Lock()
	s, srv := a.cfg.selected()
	settings := a.cfg.Settings
	_ = a.cfg.save()
	a.mu.Unlock()
	if srv == nil {
		Alert(appName, i18n.T("No servers. Add a subscription: menu → Subscriptions → Add…", "Нет серверов. Добавьте подписку: меню → Подписки → Добавить…"), false)
		return
	}

	req := ipc.ConnectRequest{
		ServerName: srv.Name, Outbound: srv.Outbound, Mode: settings.Mode,
		BypassNetBird: settings.BypassNetBird, SocksPort: settings.SocksPort, HTTPPort: settings.HTTPPort,
		Lang: i18n.Lang(),
	}
	if settings.UseSubRouting && s.Routing != nil {
		req.Routing = s.Routing
		dir, err := ensureGeo(context.Background(), s.Routing)
		if err != nil {
			Notify(appName, i18n.T("Geo files failed to download, geosite/geoip rules will be skipped: ", "Не скачались geo-файлы, geosite/geoip правила будут пропущены: ")+err.Error())
		}
		req.GeoDir = dir
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	st, err := a.client.Connect(ctx, req)
	if err != nil {
		Alert(i18n.T("Could not connect", "Не удалось подключиться"), err.Error(), true)
		return
	}
	for _, n := range st.Notes {
		log.Printf("note: %s", n)
	}
}

func (a *App) disconnect() {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := a.client.Disconnect(ctx); err != nil && a.helperUp {
		Alert(appName, i18n.T("Could not disconnect: ", "Не удалось отключиться: ")+err.Error(), true)
	}
	a.refreshStatus()
}

func (a *App) isConnected() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.status.State == ipc.StateConnected || a.status.State == ipc.StateReconnecting
}

func (a *App) reconnectIfActive() {
	if a.isConnected() {
		a.connect()
	}
}

func (a *App) toggle() {
	a.mu.Lock()
	state := a.status.State
	a.mu.Unlock()
	if state == ipc.StateConnected || state == ipc.StateReconnecting {
		a.disconnect()
	} else {
		a.connect()
	}
}

var httpClient = &http.Client{Timeout: 30 * time.Second}

func clipboardURL() string {
	out, err := exec.Command("/usr/bin/pbpaste").Output()
	if err != nil {
		return ""
	}
	s := strings.TrimSpace(string(out))
	if (strings.HasPrefix(s, "https://") || strings.HasPrefix(s, "http://")) && !strings.ContainsAny(s, " \n") {
		return s
	}
	return ""
}

func (a *App) addSubscription() {
	raw, err := Prompt(appName, i18n.T("Paste the subscription link:", "Вставьте ссылку на подписку:"), clipboardURL())
	if err != nil {
		return
	}
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		Alert(appName, i18n.T("This does not look like a subscription link (an http/https URL is required).", "Это не похоже на ссылку подписки (нужен http/https URL)."), true)
		return
	}
	id := subID(raw)
	a.mu.Lock()
	exists := a.cfg.findSub(id) != nil
	a.mu.Unlock()
	if exists {
		a.refreshSub(id, true)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s, err := sub.Fetch(ctx, httpClient, raw, a.userAgent())
	if err != nil {
		Alert(i18n.T("Could not load subscription", "Не удалось загрузить подписку"), err.Error(), true)
		return
	}
	a.mu.Lock()
	a.cfg.Subs = append(a.cfg.Subs, &StoredSub{ID: id, Subscription: *s})
	if a.cfg.Selected.SubID == "" {
		a.cfg.Selected = Selection{SubID: id, Key: s.Servers[0].Key()}
	}
	_ = a.cfg.save()
	a.mu.Unlock()
	a.rebuildMenu()
	msg := fmt.Sprintf(i18n.T("“%s”: %d servers", "«%s»: серверов — %d"), s.Title, len(s.Servers))
	if s.Routing != nil {
		msg += fmt.Sprintf(i18n.T(", routing “%s”", ", маршрутизация «%s»"), s.Routing.Name)
	}
	Notify(appName, msg)
}

func (a *App) refreshSub(id string, interactive bool) {
	a.mu.Lock()
	s := a.cfg.findSub(id)
	a.mu.Unlock()
	if s == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	fresh, err := sub.Fetch(ctx, httpClient, s.URL, a.userAgent())
	if err != nil {
		log.Printf("refresh %s: %v", id, err)
		if interactive {
			Alert(i18n.T("Could not update subscription", "Не удалось обновить подписку"), err.Error(), true)
		}
		return
	}

	a.mu.Lock()
	_, before := a.cfg.selected()
	var beforeJSON string
	if before != nil {
		beforeJSON = fmt.Sprint(before.Outbound)
	}
	s.Subscription = *fresh
	if a.cfg.Selected.SubID == id {
		found := false
		for _, srv := range s.Servers {
			if srv.Key() == a.cfg.Selected.Key {
				found = true
				break
			}
		}
		if !found && before != nil {
			for _, srv := range s.Servers {
				if srv.Name == before.Name {
					a.cfg.Selected.Key = srv.Key()
					found = true
					break
				}
			}
		}
		if !found {
			a.cfg.Selected = Selection{}
		}
	}
	_, after := a.cfg.selected()
	changed := after == nil || fmt.Sprint(after.Outbound) != beforeJSON
	_ = a.cfg.save()
	a.mu.Unlock()
	a.rebuildMenu()
	if interactive {
		Notify(appName, fmt.Sprintf(i18n.T("“%s” updated: %d servers", "«%s» обновлена: серверов — %d"), fresh.Title, len(fresh.Servers)))
	}
	if changed && a.isConnected() {
		a.connect()
	}
}

func (a *App) removeSub(id string) {
	a.mu.Lock()
	s := a.cfg.findSub(id)
	a.mu.Unlock()
	if s == nil || !Confirm(appName, fmt.Sprintf(i18n.T("Remove subscription “%s”?", "Удалить подписку «%s»?"), s.Title), i18n.T("Remove", "Удалить")) {
		return
	}
	a.mu.Lock()
	for i, x := range a.cfg.Subs {
		if x.ID == id {
			a.cfg.Subs = append(a.cfg.Subs[:i], a.cfg.Subs[i+1:]...)
			break
		}
	}
	if a.cfg.Selected.SubID == id {
		a.cfg.Selected = Selection{}
		a.cfg.selected()
	}
	_ = a.cfg.save()
	a.mu.Unlock()
	a.rebuildMenu()
}

func (a *App) autoUpdateLoop() {
	t := time.NewTicker(15 * time.Minute)
	defer t.Stop()
	for ; ; <-t.C {
		a.mu.Lock()
		var due []string
		for _, s := range a.cfg.Subs {
			every := time.Duration(s.UpdateInterval) * time.Hour
			if every <= 0 {
				every = 12 * time.Hour
			}
			if time.Since(s.UpdatedAt) >= every {
				due = append(due, s.ID)
			}
		}
		a.mu.Unlock()
		for _, id := range due {
			a.refreshSub(id, false)
		}
	}
}

func (a *App) selectServer(subID, key string) {
	a.mu.Lock()
	a.cfg.Selected = Selection{SubID: subID, Key: key}
	_ = a.cfg.save()
	a.mu.Unlock()
	a.rebuildMenu()
	a.reconnectIfActive()
}

func (a *App) updateSettings(fn func(*Settings)) {
	a.mu.Lock()
	fn(&a.cfg.Settings)
	_ = a.cfg.save()
	a.mu.Unlock()
	a.rebuildMenu()
}

func (a *App) userAgent() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return sub.UserAgent(a.cfg.Settings.MimicHapp)
}

func (a *App) refreshAllSubs(interactive bool) {
	a.mu.Lock()
	ids := make([]string, 0, len(a.cfg.Subs))
	for _, s := range a.cfg.Subs {
		ids = append(ids, s.ID)
	}
	a.mu.Unlock()
	for _, id := range ids {
		a.refreshSub(id, interactive)
	}
}

func (a *App) uninstallHelper() {
	if !Confirm(appName, i18n.T("Remove the YAXray system component? The VPN will be disconnected. macOS will ask for a password.", "Удалить системный компонент YAXray? VPN будет отключён. macOS попросит пароль."), i18n.T("Remove", "Удалить")) {
		return
	}
	if err := RunAsAdmin(i18n.T("YAXray is removing its system component.", "YAXray удаляет системный компонент."), a.exePath, "uninstall-helper"); err != nil && !errors.Is(err, errCancelled) {
		Alert(appName, err.Error(), true)
	}
	a.refreshStatus()
}

func (a *App) quit() {
	if a.isConnected() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_, _ = a.client.Disconnect(ctx)
		cancel()
	}
	systray.Quit()
}
