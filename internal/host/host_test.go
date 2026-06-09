package host

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mykeep.ai/foundry/internal/jsengine"
	"mykeep.ai/foundry/internal/store"
)

func testDEK() []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

func run(t *testing.T, e *jsengine.Engine, d *Dispatcher, src string, input json.RawMessage) *jsengine.Result {
	t.Helper()
	out, err := e.InvokeWithLimits(context.Background(), src, input, d.HostFunc(),
		jsengine.Limits{Wall: 90 * time.Second, MemPages: jsengine.DefaultLimits.MemPages})
	if err != nil {
		t.Fatalf("invoke: %v", err)
	}
	return out
}

// TestToolUsesInfra is the M3 gate: a real tool drives the encrypted backend through the
// foundry global — kv, queue, cache, blob — all brokered by the host and namespaced.
func TestToolUsesInfra(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "foundry.db.enc")
	st, err := store.Open(ctx, path, testDEK())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	e, err := jsengine.New(ctx)
	if err != nil {
		t.Fatalf("engine.New: %v", err)
	}
	defer e.Close(ctx)
	d := New(st, "weather")

	tool := `
		async function run(input) {
			await foundry.kv.set("city", input.city);
			await foundry.queue.push("jobs", { id: 1 });
			await foundry.cache.set("temp", 21, 60);
			await foundry.blob.put("note", btoa("hi"));
			const city = await foundry.kv.get("city");
			const job  = await foundry.queue.pop("jobs");
			const temp = await foundry.cache.get("temp");
			const note = atob(await foundry.blob.get("note"));
			return { city: city, job: job, temp: temp, note: note,
			         missing: await foundry.kv.get("nope") };
		}
	`
	out := run(t, e, d, tool, json.RawMessage(`{"city":"oslo"}`))
	var got struct {
		City    string         `json:"city"`
		Job     map[string]int `json:"job"`
		Temp    int            `json:"temp"`
		Note    string         `json:"note"`
		Missing *string        `json:"missing"`
	}
	if err := json.Unmarshal(out.Value, &got); err != nil {
		t.Fatalf("unmarshal %s: %v", out.Value, err)
	}
	if got.City != "oslo" || got.Job["id"] != 1 || got.Temp != 21 || got.Note != "hi" || got.Missing != nil {
		t.Fatalf("infra round-trip wrong: %+v", got)
	}

	// persistence: close, reopen, a second tool sees the kv value
	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	st2, err := store.Open(ctx, path, testDEK())
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer st2.Close()
	d2 := New(st2, "weather")
	out2 := run(t, e, d2, `async function run(){ return await foundry.kv.get("city"); }`, nil)
	if strings.TrimSpace(string(out2.Value)) != `"oslo"` {
		t.Fatalf("kv did not persist across reopen: %s", out2.Value)
	}
}

// TestToolNamespaceIsolation proves two tools with different namespaces can't see each
// other's storage even on the same store.
func TestToolNamespaceIsolation(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "f.db.enc"), testDEK())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer st.Close()
	e, err := jsengine.New(ctx)
	if err != nil {
		t.Fatalf("engine.New: %v", err)
	}
	defer e.Close(ctx)

	run(t, e, New(st, "toolA"), `async function run(){ await foundry.kv.set("secret","A"); return 1; }`, nil)
	out := run(t, e, New(st, "toolB"), `async function run(){ return await foundry.kv.get("secret"); }`, nil)
	if strings.TrimSpace(string(out.Value)) != "null" {
		t.Fatalf("toolB read toolA's namespace: %s", out.Value)
	}
}
