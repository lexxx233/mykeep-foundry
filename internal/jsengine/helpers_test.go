package jsengine

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

// mustInvoke runs a tool that is expected to succeed, with a generous wall clock. The
// large bound is deliberate: -race instrumentation slows wasm execution ~10x, so a
// production-realistic 5s wall would flake. Tools in production use DefaultLimits; the
// short-deadline interrupt behaviour is asserted separately in TestLimitWallClock.
func mustInvoke(t *testing.T, e *Engine, src string, input json.RawMessage, host HostFunc) *Result {
	t.Helper()
	out, err := e.InvokeWithLimits(context.Background(), src, input, host,
		Limits{Wall: 90 * time.Second, MemPages: DefaultLimits.MemPages})
	if err != nil {
		t.Fatalf("invoke: %v", err)
	}
	return out
}
