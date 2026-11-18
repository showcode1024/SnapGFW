package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"natgfw/internal/config"
	"natgfw/internal/engine"
	"natgfw/internal/store"
)

func TestWebAuthCSRFAndPolicyPresets(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.DataDir = dir
	hash, _ := bcrypt.GenerateFromPassword([]byte("secret123"), bcrypt.MinCost)
	cfg.AdminPassHash = string(hash)

	ps, err := store.NewPolicyStore(filepath.Join(dir, "policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	as, err := store.NewAuditStore(filepath.Join(dir, "audit.jsonl"), 100, 1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	defer as.Close()

	eng := engine.New(cfg, ps.Get(), as, nil, nil)
	srv := NewServer(filepath.Join(dir, "config.json"), cfg, ps, as, eng, nil, nil, nil)
	h := srv.Handler()

	// 1. Unauthenticated overview must fail with 401
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/overview", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}

	// 2. Login
	loginBody, _ := json.Marshal(map[string]string{"username": "admin", "password": "secret123"})
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader(loginBody)))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 login, got %d: %s", rec.Code, rec.Body.String())
	}
	cookies := rec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("expected session cookie")
	}

	// 3. State change without X-Natgfw CSRF header must fail with 403
	req := httptest.NewRequest(http.MethodPost, "/api/presets/strict_block/apply", nil)
	req.AddCookie(cookies[0])
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 without CSRF header, got %d", rec.Code)
	}

	// 4. With X-Natgfw header, preset applies cleanly
	req = httptest.NewRequest(http.MethodPost, "/api/presets/strict_block/apply", nil)
	req.AddCookie(cookies[0])
	req.Header.Set("X-Natgfw", "1")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || ps.Get().ActivePreset != "strict_block" {
		t.Fatalf("preset apply failed: %d %s", rec.Code, rec.Body.String())
	}
}
