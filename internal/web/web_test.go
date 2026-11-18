package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"snapgfw/internal/config"
	"snapgfw/internal/engine"
	"snapgfw/internal/store"
	"snapgfw/internal/updater"
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
	srv.SetUpdater(updater.New("v0.3.2", nil))
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

	// Default initial policy must be empty (custom, all disabled)
	if ps.Get().ActivePreset != "custom" || len(ps.Get().PortRules) != 0 {
		t.Fatalf("expected empty initial policy, got preset=%s ports=%d", ps.Get().ActivePreset, len(ps.Get().PortRules))
	}

	// 3. State change without X-Snapgfw CSRF header must fail with 403
	req := httptest.NewRequest(http.MethodPost, "/api/presets/anti_abuse/apply", nil)
	req.AddCookie(cookies[0])
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 without CSRF header, got %d", rec.Code)
	}

	// 4. With X-Snapgfw header, recommended anti_abuse preset applies cleanly
	req = httptest.NewRequest(http.MethodPost, "/api/presets/anti_abuse/apply", nil)
	req.AddCookie(cookies[0])
	req.Header.Set("X-Snapgfw", "1")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || ps.Get().ActivePreset != "anti_abuse" {
		t.Fatalf("preset apply failed: %d %s", rec.Code, rec.Body.String())
	}

	// 5. After importing preset, user can freely edit and save custom modifications
	edited := ps.Get()
	edited.ActivePreset = "custom"
	edited.Protocols[0].Enabled = false
	putBody, _ := json.Marshal(edited)
	req = httptest.NewRequest(http.MethodPut, "/api/policy", bytes.NewReader(putBody))
	req.AddCookie(cookies[0])
	req.Header.Set("X-Snapgfw", "1")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || ps.Get().Protocols[0].Enabled {
		t.Fatalf("custom edit after preset import failed: %d %s", rec.Code, rec.Body.String())
	}

	// 6. Verify /api/presets exposes only anti_abuse
	req = httptest.NewRequest(http.MethodGet, "/api/presets", nil)
	req.AddCookie(cookies[0])
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 presets, got %d", rec.Code)
	}
	var presets []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &presets); err != nil || len(presets) != 1 || presets[0].ID != "anti_abuse" {
		t.Fatalf("expected single preset anti_abuse, got %s", rec.Body.String())
	}

	// 7. Verify GET / renders SnapGFW Web UI
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK || !bytes.Contains(rec.Body.Bytes(), []byte("SnapGFW")) || !bytes.Contains(rec.Body.Bytes(), []byte("导入推荐 · 防滥用")) {
		t.Fatalf("unexpected UI response: code=%d", rec.Code)
	}

	// 8. Verify GET /api/overview returns version and GET /api/system/update returns structured payload
	req = httptest.NewRequest(http.MethodGet, "/api/overview", nil)
	req.AddCookie(cookies[0])
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !bytes.Contains(rec.Body.Bytes(), []byte(`"version":"v0.3.2"`)) {
		t.Fatalf("unexpected overview response: code=%d body=%s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/api/system/update", nil)
	req.AddCookie(cookies[0])
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !bytes.Contains(rec.Body.Bytes(), []byte(`"current_version":"v0.3.2"`)) {
		t.Fatalf("unexpected update check response: code=%d body=%s", rec.Code, rec.Body.String())
	}
}
