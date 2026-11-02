package app

import (
	"errors"
	"os/exec"
	"strings"

	"yaxray/internal/i18n"
)

var errCancelled = errors.New("cancelled")

func cancelLabel() string { return i18n.T("Cancel", "Отмена") }

func osascript(script string, args ...string) (string, error) {
	cmdArgs := []string{}
	for _, line := range strings.Split(script, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			cmdArgs = append(cmdArgs, "-e", line)
		}
	}
	cmdArgs = append(cmdArgs, args...)
	out, err := exec.Command("/usr/bin/osascript", cmdArgs...).CombinedOutput()
	res := strings.TrimSpace(string(out))
	if err != nil {
		if strings.Contains(res, "-128") {
			return "", errCancelled
		}
		return "", errors.New(res)
	}
	return res, nil
}

func Prompt(title, message, defaultAnswer string) (string, error) {
	return osascript(`
on run argv
activate
set r to display dialog (item 2 of argv) default answer (item 3 of argv) with title (item 1 of argv) buttons {(item 4 of argv), "OK"} default button "OK" cancel button (item 4 of argv)
return text returned of r
end run`, title, message, defaultAnswer, cancelLabel())
}

func Alert(title, message string, critical bool) {
	icon := "note"
	if critical {
		icon = "stop"
	}
	_, _ = osascript(`
on run argv
activate
display dialog (item 2 of argv) with title (item 1 of argv) buttons {"OK"} default button "OK" with icon `+icon+`
end run`, title, message)
}

func Confirm(title, message, okLabel string) bool {
	_, err := osascript(`
on run argv
activate
display dialog (item 2 of argv) with title (item 1 of argv) buttons {(item 4 of argv), (item 3 of argv)} default button (item 3 of argv) cancel button (item 4 of argv)
end run`, title, message, okLabel, cancelLabel())
	return err == nil
}

func Notify(title, message string) {
	go func() {
		_, _ = osascript(`
on run argv
display notification (item 2 of argv) with title (item 1 of argv)
end run`, title, message)
	}()
}

func RunAsAdmin(prompt string, argv ...string) error {
	script := `
on run argv
set cmd to ""
repeat with i from 2 to count of argv
set cmd to cmd & quoted form of (item i of argv) & " "
end repeat
do shell script cmd with administrator privileges with prompt (item 1 of argv)
end run`
	_, err := osascript(script, append([]string{prompt}, argv...)...)
	return err
}
