package host

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"mykeep.ai/foundry/internal/jsengine"
	"mykeep.ai/foundry/internal/store"
)

// brokerFixture returns an engine + a dispatcher whose network grant allows `host`, with
// a broker that (for the test) permits private/loopback addresses so httptest works.
func brokerFixture(t *testing.T, allowHosts, vaultCreds []string, vault VaultFiller) (*jsengine.Engine, *Dispatcher) {
	t.Helper()
	st, err := store.Open(context.Background(), t.TempDir()+"/f.db.enc", testDEK())
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	e, err := jsengine.New(context.Background())
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	t.Cleanup(func() { e.Close(context.Background()) })
	b := NewBroker(0)
	b.allowPrivate = true // httptest binds to 127.0.0.1
	return e, New(Config{Store: st, Namespace: "t", AllowHosts: allowHosts, VaultCreds: vaultCreds, Broker: b, Vault: vault})
}

// TestHTTPFetchAllowed proves a tool can fetch an allowlisted host through the broker.
func TestHTTPFetchAllowed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Demo", "ok")
		w.Write([]byte(`{"hello":"` + r.Header.Get("X-From") + `"}`))
	}))
	defer srv.Close()
	host := mustHost(t, srv.URL)

	e, d := brokerFixture(t, []string{host}, nil, nil)
	tool := `async function run(input){
		const r = await foundry.http.fetch({ url: input.url, headers: { "X-From": "tool" } });
		return { status: r.status, body: JSON.parse(r.body).hello, demo: r.headers["X-Demo"] };
	}`
	out := run(t, e, d, tool, mustJSON(t, map[string]string{"url": srv.URL}))
	var got struct {
		Status int    `json:"status"`
		Body   string `json:"body"`
		Demo   string `json:"demo"`
	}
	if err := json.Unmarshal(out.Value, &got); err != nil {
		t.Fatalf("unmarshal %s: %v", out.Value, err)
	}
	if got.Status != 200 || got.Body != "tool" || got.Demo != "ok" {
		t.Fatalf("fetch result wrong: %+v", got)
	}
}

// TestHTTPFetchHostNotGranted proves a tool cannot reach a host outside its grant.
func TestHTTPFetchHostNotGranted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("secret")) }))
	defer srv.Close()

	e, d := brokerFixture(t, []string{"api.allowed.example"}, nil, nil) // does NOT include the test host
	tool := `async function run(input){
		try { await foundry.http.fetch({ url: input.url }); return { reached: true }; }
		catch (e) { return { reached: false, err: String(e.message) }; }
	}`
	out := run(t, e, d, tool, mustJSON(t, map[string]string{"url": srv.URL}))
	if !strings.Contains(string(out.Value), `"reached":false`) {
		t.Fatalf("tool reached an un-granted host: %s", out.Value)
	}
	if !strings.Contains(string(out.Value), "host_not_granted") {
		t.Fatalf("expected host_not_granted, got: %s", out.Value)
	}
}

// TestSSRFBlocksPrivateIP proves the resolve-then-pin guard refuses a granted host that
// resolves into private space (the metadata-endpoint / internal-service attack).
func TestSSRFBlocksPrivateIP(t *testing.T) {
	// A broker WITHOUT allowPrivate; grant "localhost" which resolves to loopback.
	st, _ := store.Open(context.Background(), t.TempDir()+"/f.db.enc", testDEK())
	defer st.Close()
	e, _ := jsengine.New(context.Background())
	defer e.Close(context.Background())
	d := New(Config{Store: st, Namespace: "t", AllowHosts: []string{"localhost"}, Broker: NewBroker(0)})

	tool := `async function run(){
		try { await foundry.http.fetch({ url: "http://localhost/" }); return { blocked: false }; }
		catch (e) { return { blocked: true, err: String(e.message) }; }
	}`
	out := run(t, e, d, tool, nil)
	if !strings.Contains(string(out.Value), `"blocked":true`) || !strings.Contains(string(out.Value), "blocked_address") {
		t.Fatalf("SSRF to loopback not blocked: %s", out.Value)
	}
}

// fakeVault is a VaultFiller that asserts the secret never reaches Foundry/the tool: it
// attaches auth itself and returns only the response.
type fakeVault struct{ used string }

func (f *fakeVault) Fetch(_ context.Context, credential string, req VaultReq) (VaultResp, error) {
	f.used = credential
	// The real Vault attaches the secret here; the response never contains it.
	return VaultResp{Status: 200, Body: `{"account":"acct_123","authed_with":"` + credential + `"}`}, nil
}

// TestVaultByReference proves a tool makes an authenticated call by naming a granted
// credential, and never sees the secret (only the response).
func TestVaultByReference(t *testing.T) {
	fv := &fakeVault{}
	e, d := brokerFixture(t, nil, []string{"stripe"}, fv)
	tool := `async function run(){
		const r = await foundry.vault.fetch({ credential: "stripe", method: "GET", url: "https://api.stripe.com/v1/account" });
		return { status: r.status, body: JSON.parse(r.body).account };
	}`
	out := run(t, e, d, tool, nil)
	if !strings.Contains(string(out.Value), `"acct_123"`) {
		t.Fatalf("vault.fetch result wrong: %s", out.Value)
	}
	if fv.used != "stripe" {
		t.Fatalf("filler used credential %q, want stripe", fv.used)
	}
}

// TestVaultCredNotGranted proves a tool can't use a credential it wasn't granted.
func TestVaultCredNotGranted(t *testing.T) {
	fv := &fakeVault{}
	e, d := brokerFixture(t, nil, []string{"stripe"}, fv) // only stripe granted
	tool := `async function run(){
		try { await foundry.vault.fetch({ credential: "aws", url: "https://x" }); return { used: true }; }
		catch (e) { return { used: false, err: String(e.message) }; }
	}`
	out := run(t, e, d, tool, nil)
	if !strings.Contains(string(out.Value), `"used":false`) || !strings.Contains(string(out.Value), "not granted") {
		t.Fatalf("ungranted credential was usable: %s", out.Value)
	}
	if fv.used != "" {
		t.Fatalf("filler invoked for an ungranted credential")
	}
}

func mustHost(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Hostname()
}

func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
