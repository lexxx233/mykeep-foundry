package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
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

const mktSource = `async function run(input){ return "bought " + (input.item||"nothing"); }`

// fakeRegistry serves a signed catalog + artifact, simulating the deployed marketplace.
func fakeRegistry(t *testing.T, priv ed25519.PrivateKey) *httptest.Server {
	t.Helper()
	m, _ := registry.ParseManifest([]byte(`{"name":"shop","version":"1.0.0","description":"buys things","capabilities":{"storage":{"namespace":"shop"}}}`))
	zip, err := registry.PackTool(m, mktSource)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(zip)
	idx := &registry.Index{
		Schema: 1, GeneratedAt: "2026-06-09T00:00:00Z",
		Tools: []registry.IndexTool{{
			ID: "acme/shop", Author: "acme", Name: "shop", Latest: "1.0.0",
			Versions: []registry.IndexVersion{{
				Version: "1.0.0", Artifact: "tools/acme/shop/1.0.0/tool.zip",
				ZipSHA256: hex.EncodeToString(sum[:]),
				SourceSig: registry.Sign(priv, m.Name, m.Version, []byte(mktSource)),
				Manifest:  json.RawMessage(m.Canonical()),
				Review:    &registry.Review{Verdict: "pass", Model: "@cf/moonshotai/kimi-k2.6", RiskScore: 4},
			}},
		}},
	}
	raw := registry.CanonicalIndex(idx)
	sig := registry.SignIndex(priv, idx)
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/index.json", func(w http.ResponseWriter, _ *http.Request) { w.Write(raw) })
	mux.HandleFunc("/v1/index.json.sig", func(w http.ResponseWriter, _ *http.Request) { w.Write(sig) })
	mux.HandleFunc("/v1/tools/acme/shop/1.0.0/tool.zip", func(w http.ResponseWriter, _ *http.Request) { w.Write(zip) })
	return httptest.NewServer(mux)
}

// TestMarketplaceInstallFlow proves the control plane can refresh the signed catalog,
// install a published tool, and — once granted — the agent can run it on the USE plane.
func TestMarketplaceInstallFlow(t *testing.T) {
	ctx := context.Background()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	srvHTTP := fakeRegistry(t, priv)
	defer srvHTTP.Close()

	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "f.db.enc"), testDEK())
	if err != nil {
		t.Fatal(err)
	}
	e, err := jsengine.New(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close(); e.Close(ctx) })
	reg := registry.New(st, []ed25519.PublicKey{pub})
	rt := runtime.New(e, st, reg, host.NewBroker(0), nil)
	client := registry.NewClient(srvHTTP.URL+"/v1/", []ed25519.PublicKey{pub})
	srv := New(rt, reg, client, Options{UseToken: "USE", ControlToken: "CTRL"})

	// refresh the catalog
	if w := req(t, srv, "POST", "/api/foundry/market/refresh", "CTRL", ""); w.Code != 200 || !strings.Contains(w.Body.String(), "acme/shop") {
		t.Fatalf("market refresh => %d %s", w.Code, w.Body.String())
	}
	// install
	iw := req(t, srv, "POST", "/api/foundry/tools/install", "CTRL", `{"id":"acme/shop"}`)
	if iw.Code != 200 || !strings.Contains(iw.Body.String(), "default_grant") {
		t.Fatalf("install => %d %s", iw.Code, iw.Body.String())
	}
	// before grant: not on the agent catalog
	if w := req(t, srv, "GET", "/v1/foundry/tools", "USE", ""); strings.Contains(w.Body.String(), "shop") {
		t.Fatalf("ungranted tool on USE catalog: %s", w.Body.String())
	}
	// grant, then it's runnable by the agent
	req(t, srv, "POST", "/api/foundry/tools/shop/grant", "CTRL", grantFromDefault(t, iw.Body.Bytes()))
	if w := req(t, srv, "GET", "/v1/foundry/tools", "USE", ""); !strings.Contains(w.Body.String(), "shop") {
		t.Fatalf("granted marketplace tool missing from USE catalog: %s", w.Body.String())
	}
	rw := req(t, srv, "POST", "/v1/foundry/tools/shop", "USE", `{"item":"hat"}`)
	if rw.Code != 200 || !strings.Contains(rw.Body.String(), "bought hat") {
		t.Fatalf("run installed marketplace tool => %d %s", rw.Code, rw.Body.String())
	}
}

// TestInstallWithoutMarketplace proves the install endpoints 501 when no marketplace is
// configured (standalone with no pinned key / URL).
func TestInstallWithoutMarketplace(t *testing.T) {
	srv, _ := newServer(t) // newServer passes nil client
	if w := req(t, srv, "POST", "/api/foundry/market/refresh", "CTRL", ""); w.Code != 501 {
		t.Fatalf("refresh without marketplace => %d, want 501", w.Code)
	}
	if w := req(t, srv, "POST", "/api/foundry/tools/install", "CTRL", `{"id":"x/y"}`); w.Code != 501 {
		t.Fatalf("install without marketplace => %d, want 501", w.Code)
	}
}
