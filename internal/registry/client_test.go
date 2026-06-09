package registry

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"mykeep.ai/foundry/internal/store"
)

func testDEK() []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(i + 3)
	}
	return b
}

const mclientManifest = `{"name":"greet","version":"1.0.0","description":"says hi","capabilities":{"storage":{"namespace":"greet"}}}`
const mclientSource = `async function run(input){ return "hi " + input.name; }`

// fakeRegistry serves a signed index + a tool artifact, simulating the R2/custom-domain edge.
func fakeRegistry(t *testing.T, priv ed25519.PrivateKey, tamperZip bool) *httptest.Server {
	t.Helper()
	m, err := ParseManifest([]byte(mclientManifest))
	if err != nil {
		t.Fatal(err)
	}
	zipped, err := PackTool(m, mclientSource)
	if err != nil {
		t.Fatal(err)
	}
	served := zipped
	if tamperZip {
		served = append(append([]byte(nil), zipped...), 0x00) // corrupt the artifact bytes
	}
	idx := &Index{
		Schema: 1, GeneratedAt: "2026-06-09T00:00:00Z",
		Tools: []IndexTool{{
			ID: "alice/greet", Author: "alice", Name: "greet", Latest: "1.0.0",
			Versions: []IndexVersion{{
				Version: "1.0.0", Artifact: "tools/alice/greet/1.0.0/tool.zip",
				ZipSHA256: zipSHA256(zipped), // hash of the GENUINE zip
				SourceSig: Sign(priv, m.Name, m.Version, []byte(mclientSource)),
				Manifest:  json.RawMessage(m.Canonical()),
				Review:    &Review{Verdict: "pass", Model: "@cf/moonshotai/kimi-k2.6", RiskScore: 5},
			}},
		}},
	}
	raw := CanonicalIndex(idx)
	sig := SignIndex(priv, idx)

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/index.json", func(w http.ResponseWriter, _ *http.Request) { w.Write(raw) })
	mux.HandleFunc("/v1/index.json.sig", func(w http.ResponseWriter, _ *http.Request) { w.Write(sig) })
	mux.HandleFunc("/v1/tools/alice/greet/1.0.0/tool.zip", func(w http.ResponseWriter, _ *http.Request) { w.Write(served) })
	return httptest.NewServer(mux)
}

func newStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "f.db.enc"), testDEK())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// TestMarketplaceInstall proves the full install-on-demand path: verify signed index,
// download artifact, check its hash, unpack, verify source signature, install.
func TestMarketplaceInstall(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	srv := fakeRegistry(t, priv, false)
	defer srv.Close()

	reg := New(newStore(t), []ed25519.PublicKey{pub})
	c := NewClient(srv.URL+"/v1/", []ed25519.PublicKey{pub})

	if err := c.EnsureIndex(context.Background()); err != nil {
		t.Fatalf("EnsureIndex: %v", err)
	}
	if c.Catalog().Tools[0].Versions[0].Review.Verdict != "pass" {
		t.Fatal("review verdict not surfaced in catalog")
	}
	m, err := c.Install(context.Background(), reg, "alice/greet", "")
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if m.Name != "greet" {
		t.Fatalf("installed %q, want greet", m.Name)
	}
	tool, err := reg.Get("greet")
	if err != nil || tool.Class != ClassMarketplace || !strings.Contains(tool.Source, "hi ") {
		t.Fatalf("installed tool wrong: %+v err=%v", tool, err)
	}
}

// TestIndexSignatureRequired proves a catalog signed by the wrong key is rejected.
func TestIndexSignatureRequired(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader) // server signs with priv
	srv := fakeRegistry(t, priv, false)
	defer srv.Close()

	otherPub, _, _ := ed25519.GenerateKey(rand.Reader) // client pins a DIFFERENT key
	c := NewClient(srv.URL+"/v1/", []ed25519.PublicKey{otherPub})
	if err := c.EnsureIndex(context.Background()); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("EnsureIndex with wrong pinned key => %v, want ErrBadSignature", err)
	}
}

// TestArtifactHashMismatch proves a tampered artifact (valid index, corrupted zip) is refused.
func TestArtifactHashMismatch(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	srv := fakeRegistry(t, priv, true) // serves a corrupted zip whose hash != index
	defer srv.Close()

	reg := New(newStore(t), []ed25519.PublicKey{pub})
	c := NewClient(srv.URL+"/v1/", []ed25519.PublicKey{pub})
	if _, err := c.Install(context.Background(), reg, "alice/greet", ""); err == nil || !strings.Contains(err.Error(), "hash mismatch") {
		t.Fatalf("tampered artifact => %v, want hash mismatch", err)
	}
}
