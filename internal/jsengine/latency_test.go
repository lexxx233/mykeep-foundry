package jsengine

import (
	"context"
	"testing"
	"time"
)

func TestEvalLatency(t *testing.T) {
	ctx := context.Background()
	e, err := New(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close(ctx)
	// warm
	e.Eval(ctx, `1+1`)
	n := 10
	start := time.Now()
	for i := 0; i < n; i++ {
		if _, err := e.Eval(ctx, `console.log(JSON.stringify({x:[1,2,3].reduce((a,b)=>a+b,0)}))`); err != nil {
			t.Fatal(err)
		}
	}
	per := time.Since(start) / time.Duration(n)
	t.Logf("per-call instantiate+eval+close: %v", per)
	if per > 300*time.Millisecond {
		t.Fatalf("per-call too slow: %v (need a pooled/precompiled strategy)", per)
	}
}
