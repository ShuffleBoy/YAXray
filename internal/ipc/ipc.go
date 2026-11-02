package ipc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"yaxray/internal/sub"
)

const (
	SocketPath  = "/var/run/yaxray.sock"
	HelperLabel = "space.shff.yaxray.helper"
	HelperPath  = "/Library/PrivilegedHelperTools/space.shff.yaxray.helper"
	PlistPath   = "/Library/LaunchDaemons/space.shff.yaxray.helper.plist"
	LogDir      = "/Library/Logs/YAXray"
)

type State string

const (
	StateDisconnected State = "disconnected"
	StateConnecting   State = "connecting"
	StateConnected    State = "connected"
	StateReconnecting State = "reconnecting"
	StateError        State = "error"
)

type ConnectRequest struct {
	ServerName    string         `json:"serverName"`
	Outbound      map[string]any `json:"outbound"`
	Mode          string         `json:"mode"`
	Routing       *sub.Routing   `json:"routing,omitempty"`
	GeoDir        string         `json:"geoDir,omitempty"`
	BypassNetBird bool           `json:"bypassNetbird"`
	SocksPort     int            `json:"socksPort"`
	HTTPPort      int            `json:"httpPort"`
	Lang          string         `json:"lang,omitempty"`
}

type Status struct {
	State     State     `json:"state"`
	Server    string    `json:"server,omitempty"`
	Mode      string    `json:"mode,omitempty"`
	Interface string    `json:"interface,omitempty"`
	Tun       string    `json:"tun,omitempty"`
	Since     time.Time `json:"since,omitempty"`
	Error     string    `json:"error,omitempty"`
	Notes     []string  `json:"notes,omitempty"`
	CheckedAt time.Time `json:"checkedAt,omitempty"`
	LatencyMS int       `json:"latencyMs,omitempty"`
	Build     string    `json:"build"`
}

type errorBody struct {
	Error string `json:"error"`
}

type Client struct{ hc *http.Client }

func NewClient() *Client {
	return &Client{hc: &http.Client{
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", SocketPath)
		}},
	}}
}

func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://helper"+path, body)
	if err != nil {
		return err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		var e errorBody
		if json.Unmarshal(data, &e) == nil && e.Error != "" {
			return errors.New(e.Error)
		}
		return fmt.Errorf("helper: %s", resp.Status)
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

func (c *Client) Status(ctx context.Context) (Status, error) {
	var s Status
	err := c.do(ctx, http.MethodGet, "/v1/status", nil, &s)
	return s, err
}

func (c *Client) Connect(ctx context.Context, r ConnectRequest) (Status, error) {
	var s Status
	err := c.do(ctx, http.MethodPost, "/v1/connect", r, &s)
	return s, err
}

func (c *Client) Disconnect(ctx context.Context) (Status, error) {
	var s Status
	err := c.do(ctx, http.MethodPost, "/v1/disconnect", nil, &s)
	return s, err
}

func WriteError(w http.ResponseWriter, code int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(errorBody{Error: err.Error()})
}

func WriteJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
