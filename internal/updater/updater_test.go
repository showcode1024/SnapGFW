package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestUpdater_CheckAndVerifiedApply(t *testing.T) {
	newPayload := []byte("#!/bin/sh\necho 'snapgfw v0.3.0'\n")
	sum := sha256.Sum256(newPayload)
	wantHex := hex.EncodeToString(sum[:])

	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/showcode1024/SnapGFW/releases/latest":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"tag_name":     "v0.3.0",
				"html_url":     "https://github.com/showcode1024/SnapGFW/releases/tag/v0.3.0",
				"published_at": "2026-11-19T00:00:00Z",
				"assets": []map[string]string{
					{"name": "snapgfw-linux-amd64", "browser_download_url": srvURL + "/dl/bin"},
					{"name": "SHA256SUMS", "browser_download_url": srvURL + "/dl/sums"},
				},
			})
		case "/dl/bin":
			_, _ = w.Write(newPayload)
		case "/dl/sums":
			_, _ = fmt.Fprintf(w, "%s  snapgfw-linux-amd64\n", wantHex)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	srvURL = srv.URL

	tmpDir := t.TempDir()
	targetBin := filepath.Join(tmpDir, "snapgfw")
	if err := os.WriteFile(targetBin, []byte("old-binary"), 0o755); err != nil {
		t.Fatal(err)
	}

	var restarted atomic.Bool
	up := New("v0.2.1", func() { restarted.Store(true) })
	up.apiBase = srv.URL
	up.osName = "linux"
	up.archName = "amd64"
	up.execPathFn = func() (string, error) { return targetBin, nil }
	up.smokeTestFn = func(_ context.Context, binPath string) error {
		b, err := os.ReadFile(binPath)
		if err != nil || string(b) != string(newPayload) {
			return fmt.Errorf("unexpected temp binary contents")
		}
		return nil
	}

	info := up.Check(context.Background(), true)
	if info.CheckError != "" || !info.HasUpdate || info.LatestVersion != "v0.3.0" {
		t.Fatalf("unexpected check result: %+v", info)
	}

	applied, err := up.ApplyUpdate(context.Background())
	if err != nil {
		t.Fatalf("ApplyUpdate failed: %v", err)
	}
	if applied.LatestVersion != "v0.3.0" {
		t.Fatalf("unexpected applied info: %+v", applied)
	}

	got, err := os.ReadFile(targetBin)
	if err != nil || string(got) != string(newPayload) {
		t.Fatalf("target binary not swapped cleanly: err=%v got=%q", err, got)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && !restarted.Load() {
		time.Sleep(25 * time.Millisecond)
	}
	if !restarted.Load() {
		t.Fatal("expected restart hook to be triggered")
	}
}

func TestUpdater_RejectsBadChecksumAndVersionCompare(t *testing.T) {
	if !isNewerVersion("v0.2.1", "v0.2.10") || isNewerVersion("v0.2.10", "v0.2.2") || isNewerVersion("v0.2.1", "v0.2.1") {
		t.Fatal("semver comparison failed")
	}

	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/showcode1024/SnapGFW/releases/latest":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"tag_name": "v0.9.0",
				"assets": []map[string]string{
					{"name": "snapgfw-linux-amd64", "browser_download_url": srvURL + "/dl/bin"},
					{"name": "SHA256SUMS", "browser_download_url": srvURL + "/dl/sums"},
				},
			})
		case "/dl/bin":
			_, _ = w.Write([]byte("tampered-binary"))
		case "/dl/sums":
			_, _ = fmt.Fprintf(w, "%064x  snapgfw-linux-amd64\n", 1)
		}
	}))
	defer srv.Close()
	srvURL = srv.URL

	targetBin := filepath.Join(t.TempDir(), "snapgfw")
	_ = os.WriteFile(targetBin, []byte("keep-original"), 0o755)

	up := New("v0.2.1", nil)
	up.apiBase = srv.URL
	up.osName = "linux"
	up.archName = "amd64"
	up.execPathFn = func() (string, error) { return targetBin, nil }

	if _, err := up.ApplyUpdate(context.Background()); err == nil {
		t.Fatal("expected sha256 mismatch error")
	}
	got, _ := os.ReadFile(targetBin)
	if string(got) != "keep-original" {
		t.Fatalf("original binary was modified on checksum failure: %q", got)
	}
}
