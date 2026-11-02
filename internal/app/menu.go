package app

import (
	"fmt"
	"html"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"fyne.io/systray"

	"yaxray/internal/i18n"
	"yaxray/internal/ipc"
	"yaxray/internal/sub"
)

func (a *App) rebuildMenu() {
	a.mu.Lock()
	if a.menuDone != nil {
		close(a.menuDone)
	}
	done := make(chan struct{})
	a.menuDone = done
	var selSubID, selKey, selName string
	var selRouting *sub.Routing
	if s, srv := a.cfg.selected(); srv != nil {
		selSubID, selKey, selName, selRouting = s.ID, srv.Key(), srv.Name, s.Routing
	}
	settings := a.cfg.Settings
	subs := make([]StoredSub, len(a.cfg.Subs))
	for i, s := range a.cfg.Subs {
		subs[i] = *s
	}
	a.mu.Unlock()

	systray.ResetMenu()
	on := func(item *systray.MenuItem, fn func()) {
		go func() {
			for {
				select {
				case <-done:
					return
				case <-item.ClickedCh:
					go fn()
				}
			}
		}()
	}

	statusItem := systray.AddMenuItem("…", "")
	statusItem.Disable()
	toggleItem := systray.AddMenuItem(i18n.T("Connect", "Подключить"), "")
	on(toggleItem, a.toggle)
	a.mu.Lock()
	a.statusItem, a.toggleItem = statusItem, toggleItem
	a.mu.Unlock()
	systray.AddSeparator()

	serversTitle := i18n.T("Server: —", "Сервер: —")
	if selName != "" {
		serversTitle = i18n.T("Server: ", "Сервер: ") + selName
	}
	servers := systray.AddMenuItem(serversTitle, "")
	if len(subs) == 0 {
		servers.AddSubMenuItem(i18n.T("No subscriptions", "Нет подписок"), "").Disable()
	}
	for _, s := range subs {
		parent := servers
		if len(subs) > 1 {
			parent = servers.AddSubMenuItem(s.Title, "")
		}
		for _, srv := range s.Servers {
			checked := selSubID == s.ID && selKey == srv.Key()
			item := parent.AddSubMenuItemCheckbox(srv.Name, srv.Protocol+" · "+srv.Address, checked)
			subID, key := s.ID, srv.Key()
			on(item, func() { a.selectServer(subID, key) })
		}
	}

	subsItem := systray.AddMenuItem(i18n.T("Subscriptions", "Подписки"), "")
	on(subsItem.AddSubMenuItem(i18n.T("Add…", "Добавить…"), ""), a.addSubscription)
	if len(subs) > 0 {
		on(subsItem.AddSubMenuItem(i18n.T("Update all", "Обновить все"), ""), func() { a.refreshAllSubs(true) })
	}
	for _, s := range subs {
		m := subsItem.AddSubMenuItem(s.Title, s.URL)
		for _, line := range subInfo(&s) {
			m.AddSubMenuItem(line, "").Disable()
		}
		id := s.ID
		on(m.AddSubMenuItem(i18n.T("Update", "Обновить"), ""), func() { a.refreshSub(id, true) })
		if s.WebPageURL != "" {
			link := s.WebPageURL
			on(m.AddSubMenuItem(i18n.T("Open subscription page", "Открыть страницу подписки"), ""), func() { _ = exec.Command("/usr/bin/open", link).Run() })
		}
		if s.SupportURL != "" {
			link := s.SupportURL
			on(m.AddSubMenuItem(i18n.T("Support", "Поддержка"), ""), func() { _ = exec.Command("/usr/bin/open", link).Run() })
		}
		on(m.AddSubMenuItem(i18n.T("Remove…", "Удалить…"), ""), func() { a.removeSub(id) })
	}
	systray.AddSeparator()

	modeItem := systray.AddMenuItem(i18n.T("Mode", "Режим"), "")
	tun := modeItem.AddSubMenuItemCheckbox(i18n.T("TUN — all system traffic", "TUN — весь трафик системы"), "", settings.Mode != "proxy")
	proxy := modeItem.AddSubMenuItemCheckbox(fmt.Sprintf(i18n.T("System proxy (HTTP %d, SOCKS %d)", "Системный прокси (HTTP %d, SOCKS %d)"), settings.HTTPPort, settings.SocksPort), "", settings.Mode == "proxy")
	on(tun, func() { a.updateSettings(func(s *Settings) { s.Mode = "tun" }); a.reconnectIfActive() })
	on(proxy, func() { a.updateSettings(func(s *Settings) { s.Mode = "proxy" }); a.reconnectIfActive() })

	routingItem := systray.AddMenuItem(i18n.T("Routing", "Маршрутизация"), "")
	subRoutingTitle := i18n.T("From subscription", "Из подписки")
	if selRouting != nil {
		subRoutingTitle = fmt.Sprintf(i18n.T("From subscription: “%s”", "Из подписки: «%s»"), selRouting.Name)
	} else {
		subRoutingTitle += i18n.T(" (subscription sent no rules)", " (подписка не прислала правил)")
	}
	subRouting := routingItem.AddSubMenuItemCheckbox(subRoutingTitle, "", settings.UseSubRouting)
	global := routingItem.AddSubMenuItemCheckbox(i18n.T("All traffic through VPN", "Весь трафик через VPN"), "", !settings.UseSubRouting)
	on(subRouting, func() { a.updateSettings(func(s *Settings) { s.UseSubRouting = true }); a.reconnectIfActive() })
	on(global, func() { a.updateSettings(func(s *Settings) { s.UseSubRouting = false }); a.reconnectIfActive() })
	directNote := i18n.T("Local networks always go direct", "Локальные сети всегда идут напрямую")
	if settings.BypassNetBird {
		directNote = i18n.T("Local networks and NetBird always go direct", "Локальные сети и NetBird всегда идут напрямую")
	}
	routingItem.AddSubMenuItem(directNote, "").Disable()

	options := systray.AddMenuItem(i18n.T("Options", "Опции"), "")
	nb := options.AddSubMenuItemCheckbox(i18n.T("NetBird compatibility", "Совместимость с NetBird"),
		i18n.T("NetBird control traffic and WireGuard bypass the VPN", "Управляющий трафик и WireGuard NetBird идут мимо VPN"), settings.BypassNetBird)
	on(nb, func() {
		a.updateSettings(func(s *Settings) { s.BypassNetBird = !s.BypassNetBird })
		a.reconnectIfActive()
	})
	happ := options.AddSubMenuItemCheckbox(i18n.T("Masquerade as Happ", "Маскировка под Happ"),
		i18n.T("Fetch subscriptions with Happ's User-Agent so panels send routing rules", "Запрашивать подписки с User-Agent Happ, чтобы панели присылали правила маршрутизации"), settings.MimicHapp)
	on(happ, func() { a.updateSettings(func(s *Settings) { s.MimicHapp = !s.MimicHapp }); a.refreshAllSubs(false) })

	autoConn := systray.AddMenuItemCheckbox(i18n.T("Connect on launch", "Подключаться при запуске"), "", settings.ConnectOnLaunch)
	on(autoConn, func() { a.updateSettings(func(s *Settings) { s.ConnectOnLaunch = !s.ConnectOnLaunch }) })
	login := systray.AddMenuItemCheckbox(i18n.T("Launch at login", "Запускать при входе в систему"), "", loginItemEnabled())
	on(login, func() {
		if err := setLoginItem(!loginItemEnabled(), a.exePath); err != nil {
			Alert(appName, err.Error(), true)
		}
		a.rebuildMenu()
	})
	systray.AddSeparator()

	more := systray.AddMenuItem(i18n.T("More", "Ещё"), "")
	on(more.AddSubMenuItem(i18n.T("Open logs", "Открыть логи"), ""), func() {
		_ = exec.Command("/usr/bin/open", "-a", "Console", filepath.Join(ipc.LogDir, "helper.log")).Run()
	})
	on(more.AddSubMenuItem(i18n.T("Show settings file", "Показать файл настроек"), ""), func() {
		_ = exec.Command("/usr/bin/open", "-R", filepath.Join(supportDir(), "config.json")).Run()
	})
	on(more.AddSubMenuItem(i18n.T("Remove system component…", "Удалить системный компонент…"), ""), a.uninstallHelper)
	on(systray.AddMenuItem(i18n.T("Quit", "Выйти"), ""), a.quit)

	a.renderStatus()
}

func subInfo(s *StoredSub) []string {
	var lines []string
	used := s.Upload + s.Download
	if s.Total > 0 {
		lines = append(lines, fmt.Sprintf(i18n.T("Traffic: %s of %s", "Трафик: %s из %s"), humanBytes(used), humanBytes(s.Total)))
	} else if used > 0 {
		lines = append(lines, fmt.Sprintf(i18n.T("Traffic: %s (unlimited)", "Трафик: %s (безлимит)"), humanBytes(used)))
	}
	if s.Expire > 0 {
		lines = append(lines, i18n.T("Valid until ", "Действует до ")+time.Unix(s.Expire, 0).Format(i18n.T("Jan 2, 2006", "02.01.2006")))
	}
	lines = append(lines, fmt.Sprintf(i18n.T("Servers: %d · updated %s", "Серверов: %d · обновлено %s"), len(s.Servers), s.UpdatedAt.Local().Format(i18n.T("Jan 2 15:04", "02.01 15:04"))))
	if len(s.Skipped) > 0 {
		lines = append(lines, fmt.Sprintf(i18n.T("Skipped links: %d", "Пропущено ссылок: %d"), len(s.Skipped)))
	}
	return lines
}

func humanBytes(n int64) string {
	units := []string{"B", "KB", "MB", "GB", "TB", "PB"}
	if i18n.Lang() == i18n.RU {
		units = []string{"Б", "КБ", "МБ", "ГБ", "ТБ", "ПБ"}
	}
	f := float64(n)
	i := 0
	for f >= 1024 && i < len(units)-1 {
		f /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%d %s", n, units[0])
	}
	return fmt.Sprintf("%.1f %s", f, units[i])
}

const loginLabel = "space.shff.yaxray.app"

func loginPlistPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Library", "LaunchAgents", loginLabel+".plist")
}

func loginItemEnabled() bool {
	_, err := os.Stat(loginPlistPath())
	return err == nil
}

func setLoginItem(enable bool, exe string) error {
	if !enable {
		return os.Remove(loginPlistPath())
	}
	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key><string>%s</string>
	<key>ProgramArguments</key><array><string>%s</string></array>
	<key>RunAtLoad</key><true/>
	<key>ProcessType</key><string>Interactive</string>
</dict>
</plist>
`, loginLabel, html.EscapeString(exe))
	if err := os.MkdirAll(filepath.Dir(loginPlistPath()), 0o755); err != nil {
		return err
	}
	return os.WriteFile(loginPlistPath(), []byte(plist), 0o644)
}
