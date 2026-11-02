package i18n

import (
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
)

const (
	EN = "en"
	RU = "ru"
)

var ru atomic.Bool

func Detect() {
	Set(detect())
}

func detect() string {
	if out, err := exec.Command("/usr/bin/defaults", "read", "-g", "AppleLanguages").Output(); err == nil {
		if l := firstAppleLanguage(string(out)); l != "" {
			return normalize(l)
		}
	}
	for _, env := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		if v := os.Getenv(env); v != "" {
			return normalize(v)
		}
	}
	return EN
}

func firstAppleLanguage(out string) string {
	for line := range strings.SplitSeq(out, "\n") {
		line = strings.Trim(strings.TrimSpace(line), `",`)
		if line != "" && line != "(" && line != ")" {
			return line
		}
	}
	return ""
}

func normalize(l string) string {
	if strings.HasPrefix(strings.ToLower(l), "ru") {
		return RU
	}
	return EN
}

func Set(lang string) { ru.Store(normalize(lang) == RU) }

func Lang() string {
	if ru.Load() {
		return RU
	}
	return EN
}

func T(en, ruText string) string {
	if ru.Load() {
		return ruText
	}
	return en
}
