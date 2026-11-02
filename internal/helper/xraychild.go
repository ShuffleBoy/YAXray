package helper

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	core "github.com/xtls/xray-core/core"
	_ "github.com/xtls/xray-core/main/distro/all"

	"yaxray/internal/i18n"
	"yaxray/internal/ipc"
)

func RunXrayChild(cfgPath, assetDir string) error {
	if assetDir != "" {
		_ = os.Setenv("xray.location.asset", assetDir)
	}
	cfg, err := os.ReadFile(cfgPath)
	if err != nil {
		fmt.Println("ERR " + err.Error())
		return err
	}
	inst, err := core.StartInstance("json", cfg)
	if err != nil {
		fmt.Println("ERR " + strings.ReplaceAll(err.Error(), "\n", " "))
		return err
	}
	fmt.Println("READY")

	stop := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(io.Discard, os.Stdin)
		stop <- struct{}{}
	}()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sig
		stop <- struct{}{}
	}()
	<-stop
	_ = inst.Close()
	return nil
}

type xrayProc struct {
	cmd   *exec.Cmd
	stdin io.WriteCloser
	done  chan struct{}
	err   error
}

func startXrayProc(cfgPath, assetDir string) (*xrayProc, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	args := []string{"xray-run", "--config", cfgPath}
	if assetDir != "" {
		args = append(args, "--asset", assetDir)
	}
	cmd := exec.Command(exe, args...)
	if stderr, err := os.OpenFile(filepath.Join(ipc.LogDir, "xray-stderr.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644); err == nil {
		defer stderr.Close()
		cmd.Stderr = stderr
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	p := &xrayProc{cmd: cmd, stdin: stdin, done: make(chan struct{})}

	ready := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(stdout)
		if sc.Scan() {
			ready <- sc.Text()
		} else {
			ready <- "ERR xray exited before start"
		}
		_, _ = io.Copy(io.Discard, stdout)
	}()
	go func() {
		p.err = cmd.Wait()
		close(p.done)
	}()

	select {
	case line := <-ready:
		if line == "READY" {
			return p, nil
		}
		p.stop()
		return nil, errors.New(strings.TrimPrefix(line, "ERR "))
	case <-time.After(20 * time.Second):
		p.stop()
		return nil, errors.New(i18n.T("xray did not start within 20 seconds", "xray не запустился за 20 секунд"))
	}
}

func (p *xrayProc) alive() bool {
	select {
	case <-p.done:
		return false
	default:
		return true
	}
}

func (p *xrayProc) stop() {
	if p == nil {
		return
	}
	_ = p.stdin.Close()
	_ = p.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-p.done:
	case <-time.After(3 * time.Second):
		_ = p.cmd.Process.Kill()
		<-p.done
	}
}
