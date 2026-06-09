package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"mykeep.ai/foundry/internal/host"
	"mykeep.ai/foundry/internal/jsengine"
	"mykeep.ai/foundry/internal/registry"
	"mykeep.ai/foundry/internal/runtime"
	"mykeep.ai/foundry/internal/store"
)

func testDEK() []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(i + 7)
	}
	return b
}

const mManifest = `{"name":"greet","version":"1.0.0","description":"says hi","capabilities":{"storage":{"namespace":"greet"}}}`
const mSource = `async function run(input){ return "hi " + (input.name||"world"); }`

func newServer(t *testing.T) (*Server, *registry.Registry) {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "f.db.enc"), testDEK())
	if err != nil {
		t.Fatal(err)
	}
	e, err := jsengine.New(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close(); e.Close(ctx) })
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	reg := registry.New(st, []ed25519.PublicKey{pub})
	rt := runtime.New(e, st, reg, host.NewBroker(0), nil)
	srv := New(rt, reg, nil, Options{UseToken: "USE", ControlToken: "CTRL"})

	// install a granted marketplace tool (runnable on the USE plane)
	m, _ := registry.ParseManifest([]byte(mManifest))
	sig := registry.Sign(priv, m.Name, m.Version, []byte(mSource))
	if err := reg.InstallMarketplace(m, mSource, sig); err != nil {
		t.Fatal(err)
	}
	if err := reg.SetGrant("greet", registry.DefaultGrant(m)); err != nil {
		t.Fatal(err)
	}
	return srv, reg
}

func req(t *testing.T, srv *Server, method, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	srv.Mount(mux)
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	r.RemoteAddr = "127.0.0.1:5000"
	if token != "" {
		r.Header.Set("X-Foundry-Token", token)
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w
}

// TestUsePlaneRunsTool proves the agent can list and run a granted marketplace tool.
func TestUsePlaneRunsTool(t *testing.T) {
	srv, _ := newServer(t)
	if w := req(t, srv, "GET", "/v1/foundry/tools", "USE", ""); w.Code != 200 || !strings.Contains(w.Body.String(), "greet") {
		t.Fatalf("catalog => %d %s", w.Code, w.Body.String())
	}
	w := req(t, srv, "POST", "/v1/foundry/tools/greet", "USE", `{"name":"ada"}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `hi ada`) {
		t.Fatalf("run => %d %s", w.Code, w.Body.String())
	}
}

// TestUsePlaneRejectsBadToken proves the agent token is required.
func TestUsePlaneRejectsBadToken(t *testing.T) {
	srv, _ := newServer(t)
	if w := req(t, srv, "GET", "/v1/foundry/tools", "wrong", ""); w.Code != 401 {
		t.Fatalf("bad token => %d, want 401", w.Code)
	}
}

// TestAgentCannotControl proves the USE token is rejected on the control plane: the agent
// can run tools but never install or grant.
func TestAgentCannotControl(t *testing.T) {
	srv, _ := newServer(t)
	// the agent's USE token must NOT authorize the control plane
	if w := req(t, srv, "GET", "/api/foundry/tools", "USE", ""); w.Code != 401 {
		t.Fatalf("agent token on control plane => %d, want 401", w.Code)
	}
	if w := req(t, srv, "POST", "/api/foundry/tools/greet/grant", "USE", `{}`); w.Code != 401 {
		t.Fatalf("agent grant => %d, want 401", w.Code)
	}
	// with the control token it works
	if w := req(t, srv, "GET", "/api/foundry/tools", "CTRL", ""); w.Code != 200 {
		t.Fatalf("control token on control plane => %d, want 200", w.Code)
	}
}

// TestControlPlaneLoopbackOnly proves the control plane refuses a non-loopback client even
// with the right token.
func TestControlPlaneLoopbackOnly(t *testing.T) {
	srv, _ := newServer(t)
	mux := http.NewServeMux()
	srv.Mount(mux)
	r := httptest.NewRequest("GET", "/api/foundry/tools", nil)
	r.RemoteAddr = "203.0.113.7:9999"
	r.Header.Set("X-Foundry-Token", "CTRL")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("remote control access => %d, want 403", w.Code)
	}
}

// TestDevToolNotOnUsePlane proves a dev (unsigned) tool is not runnable by the agent even
// when granted — only via the control plane.
func TestDevToolNotOnUsePlane(t *testing.T) {
	srv, reg := newServer(t)
	m, _ := registry.ParseManifest([]byte(`{"name":"scratch","version":"0.1.0","description":"dev","capabilities":{"storage":{"namespace":"scratch"}}}`))
	if err := reg.InstallDev(m, `async function run(){ return "dev-ran"; }`); err != nil {
		t.Fatal(err)
	}
	_ = reg.SetGrant("scratch", registry.DefaultGrant(m))

	// not in the agent catalog
	if w := req(t, srv, "GET", "/v1/foundry/tools", "USE", ""); strings.Contains(w.Body.String(), "scratch") {
		t.Fatalf("dev tool leaked into USE catalog: %s", w.Body.String())
	}
	// not runnable on the USE plane
	if w := req(t, srv, "POST", "/v1/foundry/tools/scratch", "USE", `{}`); w.Code != 404 {
		t.Fatalf("dev run on USE plane => %d, want 404", w.Code)
	}
	// runnable on the control plane (human consent)
	w := req(t, srv, "POST", "/api/foundry/dev/tools/scratch/run", "CTRL", `{}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "dev-ran") {
		t.Fatalf("dev run on control plane => %d %s", w.Code, w.Body.String())
	}
}

// TestDevAuthorLoop proves the agent/human can author a dev tool and run it immediately.
func TestDevAuthorLoop(t *testing.T) {
	srv, _ := newServer(t)
	install := `{"manifest":` + mManifestJSON(t, "scratch2") + `,"source":"async function run(){ return 99; }"}`
	w := req(t, srv, "POST", "/api/foundry/dev/tools", "CTRL", install)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "default_grant") {
		t.Fatalf("dev install => %d %s", w.Code, w.Body.String())
	}
	// grant from the returned default, then run
	req(t, srv, "POST", "/api/foundry/tools/scratch2/grant", "CTRL", grantFromDefault(t, w.Body.Bytes()))
	rw := req(t, srv, "POST", "/api/foundry/dev/tools/scratch2/run", "CTRL", `{}`)
	if rw.Code != 200 || !strings.Contains(rw.Body.String(), "99") {
		t.Fatalf("dev run => %d %s", rw.Code, rw.Body.String())
	}
}

func mManifestJSON(t *testing.T, name string) string {
	return `{"name":"` + name + `","version":"0.1.0","description":"d","capabilities":{"storage":{"namespace":"` + name + `"}}}`
}

func grantFromDefault(t *testing.T, installResp []byte) string {
	t.Helper()
	var r struct {
		DefaultGrant json.RawMessage `json:"default_grant"`
	}
	if err := json.Unmarshal(installResp, &r); err != nil {
		t.Fatal(err)
	}
	return string(r.DefaultGrant)
}
