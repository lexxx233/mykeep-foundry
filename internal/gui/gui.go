// Package gui serves Foundry's local control app: a loopback dashboard that derives the
// DEK from a password, unlocks the component, and lets the human install + grant tools,
// author dev tools, and watch the audit. It carries the same hardening as the other mykeep
// GUIs: a launch token (so a co-resident process can't drive first-launch setup), a
// password-derived session gating the control plane + the agent token, idle auto-lock that
// ignores agent (/v1) traffic, and a loopback-only guard. Pure Go, no toolkit, no CGo.
package gui

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"mykeep.ai/foundry/component"
	"mykeep.ai/foundry/internal/secret"
)

//go:embed web/index.html
var indexHTML []byte

const sessionCookie = "fdy_session"

// App owns the GUI lifecycle: locked until the human unlocks via the browser.
type App struct {
	dataDir     string
	addr        string
	version     string
	idle        time.Duration
	launchToken string

	// Marketplace config (empty = no marketplace; the catalog card reports "not
	// configured"). A release pins the registry key + URL here.
	marketURL string
	pubkeys   []ed25519.PublicKey

	mu       sync.Mutex
	comp     *component.Component
	planes   http.Handler
	session  string
	lastSeen time.Time
}

// New builds a GUI over a data directory. idle<=0 disables idle auto-lock.
func New(dataDir, addr, version string, idle time.Duration) *App {
	return &App{dataDir: dataDir, addr: addr, version: version, idle: idle, launchToken: randHex(24)}
}

// WithMarketplace configures the pinned registry so the catalog card can install tools.
func (a *App) WithMarketplace(url string, pubkeys []ed25519.PublicKey) *App {
	a.marketURL, a.pubkeys = url, pubkeys
	return a
}

func (a *App) keyPath() string { return filepath.Join(a.dataDir, "foundry.key.json") }

// Run serves the GUI and opens the browser, blocking until ctx is done.
func (a *App) Run(ctx context.Context) error {
	srv := &http.Server{Addr: a.addr, Handler: loopbackGuard(a.touch(a.handler()))}
	errCh := make(chan error, 1)
	go func() {
		if e := srv.ListenAndServe(); e != nil && e != http.ErrServerClosed {
			errCh <- e
		}
	}()
	url := "http://" + a.addr + "/?lt=" + a.launchToken
	fmt.Printf("\n🧰  Foundry: %s  (opening your browser…)\n", url)
	_ = openBrowser(url)

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = srv.Shutdown(sctx)
			cancel()
			return a.lockNow()
		case e := <-errCh:
			_ = a.lockNow()
			return e
		case <-ticker.C:
			a.maybeIdleLock()
		}
	}
}

func (a *App) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", a.index)
	mux.HandleFunc("GET /api/state", a.state)
	mux.HandleFunc("POST /api/setup", a.setup)
	mux.HandleFunc("POST /api/unlock", a.unlock)
	mux.HandleFunc("POST /api/lock", a.lock)
	mux.Handle("/v1/foundry/", http.HandlerFunc(a.proxy))
	mux.Handle("/api/foundry/", http.HandlerFunc(a.proxy))
	return mux
}

func (a *App) index(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, must-revalidate")
	_, _ = w.Write(indexHTML)
}

func (a *App) state(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	unlocked := a.comp != nil
	sess := a.session
	useToken := ""
	if unlocked {
		useToken = a.comp.UseToken()
	}
	a.mu.Unlock()
	tok := ""
	if unlocked && sess != "" && hasCookie(r, sess) {
		tok = useToken // only the human's session sees the agent token
	}
	_, statErr := os.Stat(a.keyPath())
	writeJSON(w, 200, map[string]any{
		"first_launch": os.IsNotExist(statErr),
		"unlocked":     unlocked,
		"use_token":    tok,
	})
}

type passReq struct {
	Password string `json:"password"`
}

func (a *App) setup(w http.ResponseWriter, r *http.Request) {
	if !a.hasLaunchToken(r) {
		writeErr(w, 401, "launch token required")
		return
	}
	if _, err := os.Stat(a.keyPath()); err == nil {
		writeErr(w, 409, "already set up")
		return
	}
	a.open(w, r, true)
}

func (a *App) unlock(w http.ResponseWriter, r *http.Request) {
	if !a.hasLaunchToken(r) {
		writeErr(w, 401, "launch token required")
		return
	}
	a.open(w, r, false)
}

func (a *App) open(w http.ResponseWriter, r *http.Request, create bool) {
	var req passReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Password == "" {
		writeErr(w, 400, "password required")
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.comp != nil {
		writeJSON(w, 200, map[string]any{"unlocked": true})
		return
	}

	dek, err := a.deriveDEK([]byte(req.Password), create)
	if err != nil {
		if errors.Is(err, secret.ErrWrongPassword) {
			writeErr(w, 401, "wrong password")
			return
		}
		writeErr(w, 500, "could not unlock")
		return
	}
	session := randHex(32)
	comp, err := component.New(component.Options{
		DataDir: a.dataDir, Version: a.version,
		ControlSession: session, SessionCookie: sessionCookie,
		MarketURL: a.marketURL, RegistryPubKeys: a.pubkeys,
	})
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if err := comp.Unlock(context.Background(), dek); err != nil {
		writeErr(w, 500, "could not open store")
		return
	}
	mux := http.NewServeMux()
	comp.Mount(mux)
	a.comp, a.planes, a.session, a.lastSeen = comp, mux, session, time.Now()
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: session, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
	writeJSON(w, 200, map[string]any{"unlocked": true, "use_token": comp.UseToken()})
}

// deriveDEK creates or opens the standalone password envelope (foundry.key.json).
func (a *App) deriveDEK(password []byte, create bool) ([]byte, error) {
	if create {
		env, dek, err := secret.NewEnvelope(password)
		if err != nil {
			return nil, err
		}
		b, _ := json.Marshal(env)
		if err := os.WriteFile(a.keyPath(), b, 0o600); err != nil {
			return nil, err
		}
		return dek, nil
	}
	b, err := os.ReadFile(a.keyPath())
	if err != nil {
		return nil, err
	}
	var env secret.Envelope
	if err := json.Unmarshal(b, &env); err != nil {
		return nil, err
	}
	return env.Unwrap(password)
}

func (a *App) lock(w http.ResponseWriter, r *http.Request) {
	if !a.hasSession(r) {
		writeErr(w, 401, "unauthorized")
		return
	}
	_ = a.lockNow()
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1})
	writeJSON(w, 200, map[string]any{"unlocked": false})
}

func (a *App) proxy(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	h := a.planes
	a.mu.Unlock()
	if h == nil {
		writeErr(w, 423, "locked — unlock Foundry first")
		return
	}
	h.ServeHTTP(w, r)
}

func (a *App) lockNow() error {
	a.mu.Lock()
	comp := a.comp
	a.comp, a.planes, a.session = nil, nil, ""
	a.mu.Unlock()
	if comp != nil {
		return comp.Lock()
	}
	return nil
}

func (a *App) maybeIdleLock() {
	if a.idle <= 0 {
		return
	}
	a.mu.Lock()
	idle := a.comp != nil && time.Since(a.lastSeen) > a.idle
	a.mu.Unlock()
	if idle {
		fmt.Fprintln(os.Stderr, "idle auto-lock — sealing Foundry")
		_ = a.lockNow()
	}
}

// touch resets the idle clock on human/control activity only — not agent /v1 traffic.
func (a *App) touch(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/v1/") {
			a.mu.Lock()
			if a.comp != nil {
				a.lastSeen = time.Now()
			}
			a.mu.Unlock()
		}
		next.ServeHTTP(w, r)
	})
}

func (a *App) hasLaunchToken(r *http.Request) bool {
	got := r.Header.Get("X-Launch-Token")
	return got != "" && subtle.ConstantTimeCompare([]byte(got), []byte(a.launchToken)) == 1
}

func (a *App) hasSession(r *http.Request) bool {
	a.mu.Lock()
	sess := a.session
	a.mu.Unlock()
	return sess != "" && hasCookie(r, sess)
}

func hasCookie(r *http.Request, want string) bool {
	c, err := r.Cookie(sessionCookie)
	return err == nil && subtle.ConstantTimeCompare([]byte(c.Value), []byte(want)) == 1
}

// --- helpers ---

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]any{"error": msg})
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func loopbackGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
			http.Error(w, "loopback only", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func openBrowser(url string) error {
	switch runtime.GOOS {
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		return exec.Command("open", url).Start()
	default:
		return exec.Command("xdg-open", url).Start()
	}
}
