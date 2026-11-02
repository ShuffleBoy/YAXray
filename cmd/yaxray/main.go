package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"yaxray/internal/app"
	"yaxray/internal/helper"
	"yaxray/internal/sub"
	"yaxray/internal/xrayconf"
)

func main() {
	if len(os.Args) < 2 || os.Args[1] == "" || os.Args[1][0] == '-' {
		app.Run()
		return
	}
	if err := runCommand(os.Args[1], os.Args[2:]); err != nil {
		fmt.Fprintln(os.Stderr, "yaxray:", err)
		os.Exit(1)
	}
}

func runCommand(cmd string, args []string) error {
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	switch cmd {
	case "helper":
		uid := fs.Int("owner-uid", 0, "uid allowed to use the control socket")
		_ = fs.Parse(args)
		return helper.Serve(*uid)
	case "install-helper":
		uid := fs.Int("uid", 0, "owner uid")
		src := fs.String("src", "", "binary to install")
		_ = fs.Parse(args)
		if *src == "" {
			exe, _ := os.Executable()
			*src = exe
		}
		return helper.Install(*src, *uid)
	case "xray-run":
		cfg := fs.String("config", "", "xray config path")
		asset := fs.String("asset", "", "geo assets dir")
		_ = fs.Parse(args)
		return helper.RunXrayChild(*cfg, *asset)
	case "uninstall-helper":
		return helper.Uninstall()
	case "gen-config":
		mode := fs.String("mode", "tun", "tun|proxy")
		idx := fs.Int("server", 0, "server index")
		geo := fs.String("geo", "", "dir with geoip.dat/geosite.dat")
		happ := fs.Bool("happ", true, "send Happ User-Agent instead of "+sub.ClientName)
		_ = fs.Parse(args)
		if fs.NArg() != 1 {
			return fmt.Errorf("usage: yaxray gen-config [-mode tun|proxy] [-server N] [-geo DIR] [-happ=false] URL")
		}
		return genConfig(fs.Arg(0), *mode, *idx, *geo, sub.UserAgent(*happ))
	default:
		return fmt.Errorf("unknown command %q", cmd)
	}
}

func genConfig(url, mode string, idx int, geoDir, userAgent string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s, err := sub.Fetch(ctx, &http.Client{}, url, userAgent)
	if err != nil {
		return err
	}
	for i, srv := range s.Servers {
		fmt.Fprintf(os.Stderr, "[%d] %s (%s %s:%d)\n", i, srv.Name, srv.Protocol, srv.Address, srv.Port)
	}
	for _, sk := range s.Skipped {
		fmt.Fprintln(os.Stderr, "skipped:", sk)
	}
	if idx < 0 || idx >= len(s.Servers) {
		return fmt.Errorf("server index out of range")
	}
	o := xrayconf.Options{
		Mode: xrayconf.Mode(mode), Outbound: s.Servers[idx].Outbound, Routing: s.Routing,
		TunName: "utun233", Interface: "en0", SocksPort: 10808, HTTPPort: 10809,
	}
	if geoDir != "" {
		o.HasGeo = xrayconf.LoadGeoIndex(geoDir).Has
	}
	b, err := xrayconf.Build(o)
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
}
