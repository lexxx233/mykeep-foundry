package jsengine

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

// TestLimitWallClock proves a runaway synchronous loop is interrupted at the deadline and
// the engine remains usable for the next call (the instance is discarded, not the host).
func TestLimitWallClock(t *testing.T) {
	ctx := context.Background()
	e, err := New(ctx)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer e.Close(ctx)

	lim := Limits{Wall: 500 * time.Millisecond, MemPages: DefaultLimits.MemPages}
	start := time.Now()
	_, err = e.InvokeWithLimits(ctx, `async function run(){ while(true){} }`, nil, echoSumHost, lim)
	elapsed := time.Since(start)
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("runaway loop => %v, want ErrTimeout", err)
	}
	// The interrupt firing at all proves it works (a failure-to-interrupt would hang until
	// the test harness timeout). Exact latency is environment-dependent: wazero notices the
	// deadline at its next woven exit-code check, which under -race instrumentation can lag
	// several seconds — so the bound here is generous, not tight.
	if elapsed > 60*time.Second {
		t.Fatalf("interrupt took %v — far past the 500ms deadline", elapsed)
	}

	// host still healthy: a normal tool runs fine afterward
	if out := mustInvoke(t, e, `async function run(){ return 7 }`, nil, echoSumHost); string(out.Value) != "7" {
		t.Fatalf("post-timeout invoke => %s, want 7", out.Value)
	}
}

// TestLimitMemory proves an allocation bomb is bounded by the memory-pages cap and surfaces
// as an error rather than exhausting the host.
func TestLimitMemory(t *testing.T) {
	ctx := context.Background()
	e, err := New(ctx)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer e.Close(ctx)

	// A small cap (enough to boot QuickJS, not enough for the bomb). The bomb grows an
	// array of large strings until allocation fails.
	lim := Limits{Wall: 5 * time.Second, MemPages: memFloorPages + 64} // ~4 MiB headroom
	bomb := `async function run(){ const a=[]; for(;;){ a.push(new Uint8Array(1<<20)); } }`
	if _, err := e.InvokeWithLimits(ctx, bomb, nil, echoSumHost, lim); err == nil {
		t.Fatal("allocation bomb was not bounded")
	}

	// host still healthy
	if out := mustInvoke(t, e, `async function run(){ return 9 }`, nil, echoSumHost); string(out.Value) != "9" {
		t.Fatalf("post-OOM invoke => %s, want 9", out.Value)
	}
}

// TestMemFloor documents the minimum pages needed to boot QuickJS + run a trivial tool,
// so the per-call cap can be set with confidence.
func TestMemFloor(t *testing.T) {
	ctx := context.Background()
	e, err := New(ctx)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer e.Close(ctx)
	for _, pages := range []uint32{memFloorPages, memFloorPages * 2} {
		out, err := e.InvokeWithLimits(ctx, `async function run(){ return 1+1 }`, json.RawMessage(`{}`),
			echoSumHost, Limits{Wall: 90 * time.Second, MemPages: pages})
		if err != nil || string(out.Value) != "2" {
			t.Fatalf("pages=%d (%d MiB) => out=%v err=%v; memFloorPages may be too low",
				pages, pages*64/1024, out, err)
		}
	}
}

// memFloorPages is the empirically-confirmed minimum wasm pages (64 KiB each) for the
// QuickJS reactor to instantiate and run a trivial tool. Confirmed by TestMemFloor.
const memFloorPages uint32 = 256 // 16 MiB
