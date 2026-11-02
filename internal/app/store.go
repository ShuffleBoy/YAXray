package app

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"

	"yaxray/internal/sub"
)

type Settings struct {
	Mode            string `json:"mode"`
	UseSubRouting   bool   `json:"useSubRouting"`
	BypassNetBird   bool   `json:"bypassNetbird"`
	MimicHapp       bool   `json:"mimicHapp"`
	ConnectOnLaunch bool   `json:"connectOnLaunch"`
	SocksPort       int    `json:"socksPort"`
	HTTPPort        int    `json:"httpPort"`
}

type StoredSub struct {
	ID string `json:"id"`
	sub.Subscription
}

type Selection struct {
	SubID string `json:"subId"`
	Key   string `json:"key"`
}

type Config struct {
	Subs     []*StoredSub `json:"subs"`
	Selected Selection    `json:"selected"`
	Settings Settings     `json:"settings"`
}

func supportDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Library", "Application Support", "YAXray")
}

func configPath() string { return filepath.Join(supportDir(), "config.json") }

func defaultConfig() *Config {
	return &Config{Settings: Settings{
		Mode: "tun", UseSubRouting: true, BypassNetBird: true, MimicHapp: true,
		SocksPort: 10808, HTTPPort: 10809,
	}}
}

func loadConfig() *Config {
	c := defaultConfig()
	b, err := os.ReadFile(configPath())
	if err != nil {
		return c
	}
	_ = json.Unmarshal(b, c)
	return c
}

func (c *Config) save() error {
	if err := os.MkdirAll(supportDir(), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := configPath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, configPath())
}

func subID(url string) string {
	h := sha256.Sum256([]byte(url))
	return hex.EncodeToString(h[:])[:12]
}

func (c *Config) findSub(id string) *StoredSub {
	for _, s := range c.Subs {
		if s.ID == id {
			return s
		}
	}
	return nil
}

func (c *Config) selected() (*StoredSub, *sub.Server) {
	if s := c.findSub(c.Selected.SubID); s != nil {
		for i := range s.Servers {
			if s.Servers[i].Key() == c.Selected.Key {
				return s, &s.Servers[i]
			}
		}
	}
	for _, s := range c.Subs {
		if len(s.Servers) > 0 {
			c.Selected = Selection{SubID: s.ID, Key: s.Servers[0].Key()}
			return s, &s.Servers[0]
		}
	}
	return nil, nil
}
