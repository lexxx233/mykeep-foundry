package runtime

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"mykeep.ai/foundry/internal/host"
	"mykeep.ai/foundry/internal/jsengine"
	"mykeep.ai/foundry/internal/registry"
	"mykeep.ai/foundry/internal/store"
)

func testDEK() []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(i + 1)
	}
	return b
}

func fixture(t *testing.T, pub []ed25519.PublicKey) (*Runtime, *registry.Registry, func()) {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "f.db.enc"), testDEK())
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	e, err := jsengine.New(ctx)
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	b := host.NewBroker(0)
	b2 := b
	reg := registry.New(st, pub)
	rt := New(e, st, reg, b2, nil)
	return rt, reg, func() { st.Close(); e.Close(ctx) }
}

const weatherManifest = `{
	"name": "weather",
	"version": "1.0.0",
	"description": "remembers a city",
	"capabilities": { "storage": { "namespace": "weather", "quota_bytes": 1000000 } }
}`

const weatherSrc = `async function run(input){
	await foundry.kv.set("city", input.city);
	return { saved: await foundry.kv.get("city") };
}`

// TestRunRequiresGrant proves a tool can't run until the human grants its capabilities.
func TestRunRequiresGrant(t *testing.T) {
	rt, reg, done := fixture(t, nil)
	defer done()

	m, err := registry.ParseManifest([]byte(weatherManifest))
	if err != nil {
		t.Fatalf("manifest: %v", err)
	}
	if err := reg.InstallDev(m, weatherSrc); err != nil {
		t.Fatalf("install: %v", err)
	}

	// no grant yet → refused
	if _, err := rt.Run(context.Background(), "weather", json.RawMessage(`{"city":"oslo"}`)); !errors.Is(err, registry.ErrNotGranted) {
		t.Fatalf("run before grant => %v, want ErrNotGranted", err)
	}

	// grant the declared caps → runs
	if err := reg.SetGrant("weather", registry.DefaultGrant(m)); err != nil {
		t.Fatalf("grant: %v", err)
	}
	out, err := rt.Run(context.Background(), "weather", json.RawMessage(`{"city":"oslo"}`))
	if err != nil {
		t.Fatalf("run after grant: %v", err)
	}
	if !strings.Contains(string(out.Value), `"oslo"`) {
		t.Fatalf("tool result wrong: %s", out.Value)
	}
}

// TestManifestChangeRevokesGrant proves a re-install with a changed manifest invalidates
// the prior grant (no silent capability escalation on update).
func TestManifestChangeRevokesGrant(t *testing.T) {
	rt, reg, done := fixture(t, nil)
	defer done()
	m, _ := registry.ParseManifest([]byte(weatherManifest))
	_ = reg.InstallDev(m, weatherSrc)
	_ = reg.SetGrant("weather", registry.DefaultGrant(m))

	// re-install a v2 that also requests a network host — manifest hash changes
	m2, _ := registry.ParseManifest([]byte(`{
		"name":"weather","version":"2.0.0","description":"now phones home",
		"capabilities":{ "storage":{"namespace":"weather"}, "network":{"hosts":["evil.example"]} }
	}`))
	_ = reg.InstallDev(m2, weatherSrc)

	if _, err := rt.Run(context.Background(), "weather", json.RawMessage(`{"city":"x"}`)); !errors.Is(err, registry.ErrNotGranted) {
		t.Fatalf("run after manifest change => %v, want ErrNotGranted (re-approval)", err)
	}
}

// TestMarketplaceSignature proves a marketplace install is rejected without a valid
// registry signature and accepted with one.
func TestMarketplaceSignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, reg, done := fixture(t, []ed25519.PublicKey{pub})
	defer done()
	m, _ := registry.ParseManifest([]byte(weatherManifest))

	// wrong signature (signed by a different key) → rejected
	_, badPriv, _ := ed25519.GenerateKey(rand.Reader)
	badSig := registry.Sign(badPriv, m.Name, m.Version, []byte(weatherSrc))
	if err := reg.InstallMarketplace(m, weatherSrc, badSig, true); !errors.Is(err, registry.ErrBadSignature) {
		t.Fatalf("bad-sig install => %v, want ErrBadSignature", err)
	}

	// correct registry signature → installs
	goodSig := registry.Sign(priv, m.Name, m.Version, []byte(weatherSrc))
	if err := reg.InstallMarketplace(m, weatherSrc, goodSig, true); err != nil {
		t.Fatalf("good-sig install: %v", err)
	}
	tool, err := reg.Get("weather")
	if err != nil || tool.Class != registry.ClassMarketplace {
		t.Fatalf("installed tool => %+v err=%v, want marketplace class", tool, err)
	}

	// tampered source under the same signature → rejected
	if err := reg.InstallMarketplace(m, weatherSrc+"// evil", goodSig, true); !errors.Is(err, registry.ErrBadSignature) {
		t.Fatalf("tampered-source install => %v, want ErrBadSignature", err)
	}
}
