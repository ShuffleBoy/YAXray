package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"yaxray/internal/sub"
)

func ensureGeo(ctx context.Context, r *sub.Routing) (string, error) {
	if r == nil || (r.GeoIPURL == "" && r.GeoSiteURL == "") {
		return "", nil
	}
	h := sha256.Sum256([]byte(r.GeoIPURL + "\n" + r.GeoSiteURL))
	dir := filepath.Join(supportDir(), "geo", hex.EncodeToString(h[:])[:12])
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	for name, url := range map[string]string{"geoip.dat": r.GeoIPURL, "geosite.dat": r.GeoSiteURL} {
		if url == "" {
			continue
		}
		dst := filepath.Join(dir, name)
		if st, err := os.Stat(dst); err == nil && st.Size() > 0 {
			continue
		}
		if err := download(ctx, url, dst); err != nil {
			return dir, fmt.Errorf("%s: %w", name, err)
		}
	}
	return dir, nil
}

func download(ctx context.Context, url, dst string) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %s", resp.Status)
	}
	tmp := dst + ".part"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, io.LimitReader(resp.Body, 256<<20)); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}
