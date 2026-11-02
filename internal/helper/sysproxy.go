package helper

import (
	"context"
	"strconv"
	"strings"
)

const networksetup = "/usr/sbin/networksetup"

func networkServices(ctx context.Context) []string {
	out, err := run(ctx, networksetup, "-listallnetworkservices")
	if err != nil {
		return nil
	}
	var res []string
	for i, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if i == 0 || line == "" || strings.HasPrefix(line, "*") {
			continue
		}
		res = append(res, line)
	}
	return res
}

func setSystemProxy(ctx context.Context, httpPort, socksPort int, bypass []string) error {
	hp, sp := strconv.Itoa(httpPort), strconv.Itoa(socksPort)
	for _, svc := range networkServices(ctx) {
		cmds := [][]string{
			{"-setwebproxy", svc, "127.0.0.1", hp},
			{"-setsecurewebproxy", svc, "127.0.0.1", hp},
			{"-setsocksfirewallproxy", svc, "127.0.0.1", sp},
			append([]string{"-setproxybypassdomains", svc}, bypass...),
		}
		for _, c := range cmds {
			if _, err := run(ctx, networksetup, c...); err != nil {
				return err
			}
		}
	}
	return nil
}

func clearSystemProxy(ctx context.Context) {
	for _, svc := range networkServices(ctx) {
		for _, c := range []string{"-setwebproxystate", "-setsecurewebproxystate", "-setsocksfirewallproxystate"} {
			_, _ = run(ctx, networksetup, c, svc, "off")
		}
	}
}

func proxyBypassList(nb *NetBirdInfo) []string {
	list := []string{
		"127.0.0.1", "localhost", "*.local", "169.254/16",
		"10/8", "172.16/12", "192.168/16", "100.64/10",
	}
	if nb != nil {
		for _, d := range nb.DNSDomains {
			list = append(list, d, "*."+d)
		}
		list = append(list, nb.Hosts...)
	}
	return list
}
