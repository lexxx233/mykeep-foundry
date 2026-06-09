package registry

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestWorkerInterop proves the Cloudflare Worker's hand-rolled zip and WebCrypto ed25519
// signature are byte-compatible with the Go consumer: a node-produced artifact unpacks via
// archive/zip and installs (signature verifies) against the matching pinned key. Skipped if
// node is unavailable.
func TestWorkerInterop(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not available; skipping JS<->Go interop")
	}
	out := t.TempDir()
	gen, err := filepath.Abs("../../cloudflare/interop/gen.mjs")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(node, gen, out)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("gen.mjs: %v\n%s", err, b)
	}

	zip, err := os.ReadFile(filepath.Join(out, "tool.zip"))
	if err != nil {
		t.Fatal(err)
	}
	metaBytes, err := os.ReadFile(filepath.Join(out, "meta.json"))
	if err != nil {
		t.Fatal(err)
	}
	var meta struct {
		PubB64  string `json:"pubkey_b64"`
		SigB64  string `json:"source_sig_b64"`
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal(metaBytes, &meta); err != nil {
		t.Fatal(err)
	}
	pub, err := base64.StdEncoding.DecodeString(meta.PubB64)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := base64.StdEncoding.DecodeString(meta.SigB64)
	if err != nil {
		t.Fatal(err)
	}

	// Go can read the Worker's zip.
	m, source, err := unpackTool(zip)
	if err != nil {
		t.Fatalf("unpack Worker zip: %v", err)
	}
	if m.Name != "interop" {
		t.Fatalf("unpacked manifest name = %q, want interop", m.Name)
	}

	// Go verifies the WebCrypto signature and installs.
	reg := New(newStore(t), []ed25519.PublicKey{pub})
	if err := reg.InstallMarketplace(m, source, sig); err != nil {
		t.Fatalf("InstallMarketplace on Worker artifact: %v", err)
	}

	// A flipped signature byte is rejected.
	bad := append([]byte(nil), sig...)
	bad[0] ^= 0xff
	if err := reg.InstallMarketplace(m, source, bad); err == nil {
		t.Fatal("tampered signature accepted")
	}
}
