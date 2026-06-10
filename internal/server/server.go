// Package server exposes Foundry over two HTTP planes on one mux, mirroring Vault's plane
// split — the load-bearing control. The USE plane (/v1/foundry, agent token, loopback
// unless LAN) lets an agent list and RUN granted tools but never install or grant. The
// CONTROL plane (/api/foundry, always loopback, control token or session) is the human's:
// install, capability grants, the dev-author loop, and audit.
package server

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"

	"mykeep.ai/foundry/internal/registry"
	"mykeep.ai/foundry/internal/runtime"
)

// Options configure the two planes.
type Options struct {
	EnableLAN      bool   // expose the USE plane on the LAN (control plane stays loopback)
	UseToken       string // agent token for /v1/foundry (X-Foundry-Token); generated if empty
	ControlToken   string // control token for /api/foundry; generated if empty
	ControlSession string // GUI session-cookie value also accepted on the control plane
	SessionCookie  string // cookie name (default "fdy_session"; the suite uses "mykeep_session")
}

// Server brokers the two planes over a runtime + registry (+ an optional marketplace client).
type Server struct {
	rt     *runtime.Runtime
	reg    *registry.Registry
	market *registry.Client // nil when no marketplace is configured
	opt    Options
}

func New(rt *runtime.Runtime, reg *registry.Registry, market *registry.Client, opt Options) *Server {
	if opt.UseToken == "" {
		opt.UseToken = randToken()
	}
	if opt.ControlToken == "" {
		opt.ControlToken = randToken()
	}
	if opt.SessionCookie == "" {
		opt.SessionCookie = "fdy_session"
	}
	return &Server{rt: rt, reg: reg, market: market, opt: opt}
}

func (s *Server) UseToken() string     { return s.opt.UseToken }
func (s *Server) ControlToken() string { return s.opt.ControlToken }

// Mount attaches both planes to a shared mux (the standalone GUI or the suite aggregator).
func (s *Server) Mount(mux *http.ServeMux) {
	use := http.NewServeMux()
	use.HandleFunc("GET /v1/foundry/guide", s.guide)
	use.HandleFunc("GET /v1/foundry/tools", s.useCatalog)
	use.HandleFunc("POST /v1/foundry/tools/{name}", s.useRun)
	useGuard := s.requireToken(s.opt.UseToken, use)
	if !s.opt.EnableLAN {
		useGuard = loopbackOnly(useGuard)
	}
	mux.Handle("/v1/foundry/", useGuard)

	ctrl := http.NewServeMux()
	ctrl.HandleFunc("GET /api/foundry/tools", s.ctrlList)
	ctrl.HandleFunc("POST /api/foundry/tools/{name}/grant", s.ctrlGrant)
	ctrl.HandleFunc("DELETE /api/foundry/tools/{name}", s.ctrlRemove)
	ctrl.HandleFunc("POST /api/foundry/dev/tools", s.ctrlDevInstall)
	ctrl.HandleFunc("POST /api/foundry/dev/tools/{name}/run", s.ctrlDevRun)
	ctrl.HandleFunc("POST /api/foundry/market/refresh", s.ctrlMarketRefresh)
	ctrl.HandleFunc("POST /api/foundry/tools/install", s.ctrlInstall)
	mux.Handle("/api/foundry/", loopbackOnly(s.controlAuth(ctrl)))
}

// --- USE plane (agent) ---

func (s *Server) guide(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(GuideText(baseURL(r))))
}

// useCatalog lists the tools an agent may run: marketplace-class tools that are granted.
// Dev tools are NEVER auto-listed here — a co-resident agent must not invoke unreviewed
// code; the human runs dev tools from the control plane.
func (s *Server) useCatalog(w http.ResponseWriter, _ *http.Request) {
	tools, err := s.reg.List()
	if err != nil {
		writeErr(w, 500, "list_failed")
		return
	}
	type entry struct {
		Name         string          `json:"name"`
		Version      string          `json:"version"`
		Description  string          `json:"description"`
		Verified     bool            `json:"verified"`
		ParamsSchema json.RawMessage `json:"params_schema,omitempty"`
	}
	out := []entry{}
	for _, t := range tools {
		if t.Class != registry.ClassMarketplace {
			continue
		}
		if _, err := s.reg.Grant(t.Manifest.Name); err != nil {
			continue // ungranted → not runnable
		}
		out = append(out, entry{t.Manifest.Name, t.Manifest.Version, t.Manifest.Description, t.Verified, t.Manifest.ParamsSchema})
	}
	writeJSON(w, 200, map[string]any{"tools": out})
}

func (s *Server) useRun(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	tool, err := s.reg.Get(name)
	if err != nil || tool.Class != registry.ClassMarketplace {
		writeErr(w, 404, "not_found") // dev tools aren't runnable on the USE plane
		return
	}
	s.runTool(w, r, name)
}

// --- CONTROL plane (human) ---

func (s *Server) ctrlList(w http.ResponseWriter, _ *http.Request) {
	tools, err := s.reg.List()
	if err != nil {
		writeErr(w, 500, "list_failed")
		return
	}
	type entry struct {
		Name        string `json:"name"`
		Version     string `json:"version"`
		Class       string `json:"class"`
		Description string `json:"description"`
		Granted     bool   `json:"granted"`
		Verified    bool   `json:"verified"`
	}
	out := []entry{}
	for _, t := range tools {
		_, gerr := s.reg.Grant(t.Manifest.Name)
		out = append(out, entry{t.Manifest.Name, t.Manifest.Version, t.Class, t.Manifest.Description, gerr == nil, t.Verified})
	}
	writeJSON(w, 200, map[string]any{"tools": out})
}

func (s *Server) ctrlGrant(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var g registry.Grant
	if err := json.NewDecoder(r.Body).Decode(&g); err != nil {
		writeErr(w, 400, "bad_request")
		return
	}
	if err := s.reg.SetGrant(name, g); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"granted": true})
}

func (s *Server) ctrlRemove(w http.ResponseWriter, r *http.Request) {
	if err := s.reg.Remove(r.PathValue("name")); err != nil {
		writeErr(w, 500, "remove_failed")
		return
	}
	writeJSON(w, 200, map[string]any{"removed": true})
}

type devInstallReq struct {
	Manifest json.RawMessage `json:"manifest"`
	Source   string          `json:"source"`
}

func (s *Server) ctrlDevInstall(w http.ResponseWriter, r *http.Request) {
	var req devInstallReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "bad_request")
		return
	}
	m, err := registry.ParseManifest(req.Manifest)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if err := s.reg.InstallDev(m, req.Source); err != nil {
		writeErr(w, 500, "install_failed")
		return
	}
	writeJSON(w, 200, map[string]any{"installed": m.Name, "class": registry.ClassDev,
		"manifest_hash": m.Hash(), "default_grant": registry.DefaultGrant(m)})
}

func (s *Server) ctrlDevRun(w http.ResponseWriter, r *http.Request) {
	s.runTool(w, r, r.PathValue("name")) // dev run is control-plane only (human consent in the GUI)
}

// ctrlMarketRefresh fetches + verifies the signed catalog and returns it for the GUI.
func (s *Server) ctrlMarketRefresh(w http.ResponseWriter, r *http.Request) {
	if s.market == nil {
		writeErr(w, 501, "marketplace not configured")
		return
	}
	if err := s.market.EnsureIndex(r.Context()); err != nil {
		writeErr(w, 502, "catalog unavailable")
		return
	}
	writeJSON(w, 200, map[string]any{"catalog": s.market.Catalog()})
}

type installReq struct {
	ID      string `json:"id"`
	Version string `json:"version"`
}

// ctrlInstall installs a published tool from the verified catalog (download → verify zip
// hash → verify source signature → install). It returns the default grant for the human to
// approve, mirroring the dev-install flow.
func (s *Server) ctrlInstall(w http.ResponseWriter, r *http.Request) {
	if s.market == nil {
		writeErr(w, 501, "marketplace not configured")
		return
	}
	var req installReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" {
		writeErr(w, 400, "bad_request")
		return
	}
	m, err := s.market.Install(r.Context(), s.reg, req.ID, req.Version)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	verified := false
	if t, gerr := s.reg.Get(m.Name); gerr == nil {
		verified = t.Verified
	}
	writeJSON(w, 200, map[string]any{"installed": m.Name, "version": m.Version,
		"class": registry.ClassMarketplace, "verified": verified,
		"manifest_hash": m.Hash(), "default_grant": registry.DefaultGrant(m)})
}

// runTool runs a tool by name with the request body as input, shared by both planes.
func (s *Server) runTool(w http.ResponseWriter, r *http.Request, name string) {
	input, _ := readBody(r)
	res, err := s.rt.Run(r.Context(), name, input)
	if err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	logs := make([]map[string]string, 0, len(res.Logs))
	for _, l := range res.Logs {
		logs = append(logs, map[string]string{"level": l.Level, "msg": l.Msg})
	}
	writeJSON(w, 200, map[string]any{"ok": true, "result": res.Value, "logs": logs})
}

// --- guards + helpers ---

func (s *Server) requireToken(token string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !tokenOK(r.Header.Get("X-Foundry-Token"), token) {
			writeErr(w, 401, "unauthorized")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// controlAuth accepts the control token OR the GUI session cookie; a co-resident agent has
// neither (it never sees the control token and can't unlock to mint a session).
func (s *Server) controlAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if tokenOK(r.Header.Get("X-Foundry-Token"), s.opt.ControlToken) {
			next.ServeHTTP(w, r)
			return
		}
		if s.opt.ControlSession != "" {
			if c, err := r.Cookie(s.opt.SessionCookie); err == nil && tokenOK(c.Value, s.opt.ControlSession) {
				next.ServeHTTP(w, r)
				return
			}
		}
		writeErr(w, 401, "unauthorized")
	})
}

func loopbackOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
			writeErr(w, 403, "loopback_only")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func tokenOK(got, want string) bool {
	return want != "" && len(got) == len(want) && subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func randToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func readBody(r *http.Request) (json.RawMessage, error) {
	if r.Body == nil {
		return json.RawMessage("{}"), nil
	}
	var raw json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		return json.RawMessage("{}"), nil
	}
	return raw, nil
}

func baseURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]any{"error": msg})
}
