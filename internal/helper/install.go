package helper

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"yaxray/internal/ipc"
)

const plistTemplate = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>%s</string>
	<key>ProgramArguments</key>
	<array>
		<string>%s</string>
		<string>helper</string>
		<string>--owner-uid</string>
		<string>%d</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>StandardErrorPath</key>
	<string>%s/helper.stderr.log</string>
</dict>
</plist>
`

func Install(src string, ownerUID int) error {
	if os.Geteuid() != 0 {
		return errors.New("install must run as root")
	}
	if ownerUID <= 0 {
		return errors.New("owner uid required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, _ = run(ctx, "/bin/launchctl", "bootout", "system/"+ipc.HelperLabel)

	if err := os.MkdirAll(filepath.Dir(ipc.HelperPath), 0o755); err != nil {
		return err
	}
	if err := copyFile(src, ipc.HelperPath+".new", 0o755); err != nil {
		return err
	}
	if err := os.Rename(ipc.HelperPath+".new", ipc.HelperPath); err != nil {
		return err
	}
	if err := os.Chown(ipc.HelperPath, 0, 0); err != nil {
		return err
	}
	_ = os.MkdirAll(ipc.LogDir, 0o755)
	plist := fmt.Sprintf(plistTemplate, ipc.HelperLabel, ipc.HelperPath, ownerUID, ipc.LogDir)
	if err := os.WriteFile(ipc.PlistPath, []byte(plist), 0o644); err != nil {
		return err
	}
	_ = os.Chown(ipc.PlistPath, 0, 0)
	_ = os.Remove(ipc.SocketPath)
	var err error
	for range 5 {
		if _, err = run(ctx, "/bin/launchctl", "bootstrap", "system", ipc.PlistPath); err == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if err != nil {
		return err
	}
	for range 50 {
		if _, err := os.Stat(ipc.SocketPath); err == nil {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return errors.New("helper did not start, see " + ipc.LogDir)
}

func Uninstall() error {
	if os.Geteuid() != 0 {
		return errors.New("uninstall must run as root")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, _ = run(ctx, "/bin/launchctl", "bootout", "system/"+ipc.HelperLabel)
	for _, p := range []string{ipc.PlistPath, ipc.HelperPath, ipc.SocketPath} {
		_ = os.Remove(p)
	}
	_ = os.RemoveAll(stateDir)
	return nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
