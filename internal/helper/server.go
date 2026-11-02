package helper

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"yaxray/internal/ipc"
)

func BuildID(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return "unknown"
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "unknown"
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

func Serve(ownerUID int) error {
	if os.Geteuid() != 0 {
		return errors.New("helper must run as root")
	}
	_ = os.MkdirAll(ipc.LogDir, 0o755)
	if f, err := os.OpenFile(filepath.Join(ipc.LogDir, "helper.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644); err == nil {
		log.SetOutput(f)
	}
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	exe, _ := os.Executable()
	m := NewManager(BuildID(exe))
	log.Printf("helper started, build=%s owner=%d", m.build, ownerUID)

	_ = os.Remove(ipc.SocketPath)
	ln, err := net.Listen("unix", ipc.SocketPath)
	if err != nil {
		return err
	}
	if err := os.Chown(ipc.SocketPath, ownerUID, 0); err != nil {
		return err
	}
	if err := os.Chmod(ipc.SocketPath, 0o600); err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, r *http.Request) {
		ipc.WriteJSON(w, m.Status())
	})
	mux.HandleFunc("POST /v1/connect", func(w http.ResponseWriter, r *http.Request) {
		var req ipc.ConnectRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, 4<<20)).Decode(&req); err != nil {
			ipc.WriteError(w, http.StatusBadRequest, fmt.Errorf("bad request: %w", err))
			return
		}
		st, err := m.Connect(r.Context(), req)
		if err != nil {
			ipc.WriteError(w, http.StatusUnprocessableEntity, err)
			return
		}
		ipc.WriteJSON(w, st)
	})
	mux.HandleFunc("POST /v1/disconnect", func(w http.ResponseWriter, r *http.Request) {
		ipc.WriteJSON(w, m.Disconnect())
	})

	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		s := <-sig
		log.Printf("signal %v, shutting down", s)
		m.Disconnect()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
