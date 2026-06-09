package gui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newApp(t *testing.T) *App {
	return New(t.TempDir(), "127.0.0.1:0", "test", 0)
}

func req(h http.Handler, method, path, lt, cookie, body string) *httptest.ResponseRecorder {
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	r.RemoteAddr = "127.0.0.1:5000"
	if lt != "" {
		r.Header.Set("X-Launch-Token", lt)
	}
	if cookie != "" {
		r.Header.Set("Cookie", cookie)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func sessionFrom(w *httptest.ResponseRecorder) string {
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookie && c.Value != "" {
			return sessionCookie + "=" + c.Value
		}
	}
	return ""
}

// TestSetupRequiresLaunchToken: a co-resident process without the launch token can't set
// the master password (defeats first-launch setup-capture).
func TestSetupRequiresLaunchToken(t *testing.T) {
	h := newApp(t).handler()
	if w := req(h, "POST", "/api/setup", "", "", `{"password":"x"}`); w.Code != 401 {
		t.Fatalf("setup without launch token => %d, want 401", w.Code)
	}
	if w := req(h, "POST", "/api/unlock", "", "", `{"password":"x"}`); w.Code != 401 {
		t.Fatalf("unlock without launch token => %d, want 401", w.Code)
	}
}

// TestSetupUnlockFlow: with the launch token, setup creates the store, sets a session
// cookie, returns a use token, and gates the agent token behind the session.
func TestSetupUnlockFlow(t *testing.T) {
	a := newApp(t)
	h := a.handler()
	w := req(h, "POST", "/api/setup", a.launchToken, "", `{"password":"hunter2"}`)
	if w.Code != 200 {
		t.Fatalf("setup => %d %s", w.Code, w.Body.String())
	}
	cookie := sessionFrom(w)
	if cookie == "" {
		t.Fatal("no session cookie on setup")
	}
	if !strings.Contains(w.Body.String(), "use_token") {
		t.Fatal("setup did not return a use token")
	}
	// state without the session must not leak the agent token
	if w := req(h, "GET", "/api/state", "", "", ""); !strings.Contains(w.Body.String(), `"use_token":""`) {
		t.Fatalf("state without session leaked a token: %s", w.Body.String())
	}
	// control plane reachable with the session, refused without
	if w := req(h, "GET", "/api/foundry/tools", "", cookie, ""); w.Code != 200 {
		t.Fatalf("control via session => %d, want 200", w.Code)
	}
	if w := req(h, "POST", "/api/lock", "", "", ""); w.Code != 401 {
		t.Fatalf("lock without session => %d, want 401", w.Code)
	}
}

// TestLockedProxy: before unlock, the planes proxy returns 423.
func TestLockedProxy(t *testing.T) {
	h := newApp(t).handler()
	if w := req(h, "GET", "/api/foundry/tools", "", "", ""); w.Code != 423 {
		t.Fatalf("control before unlock => %d, want 423", w.Code)
	}
}

// TestLoopbackGuard: a non-loopback client is refused.
func TestLoopbackGuard(t *testing.T) {
	h := loopbackGuard(newApp(t).handler())
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "203.0.113.9:9999"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("remote access => %d, want 403", w.Code)
	}
}
