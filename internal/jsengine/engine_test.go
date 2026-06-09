package jsengine

import (
	"context"
	"strings"
	"testing"
)

// TestEvalArithmetic is the M0 gate: the embedded QuickJS-on-wasm engine runs JS under
// wazero (pure Go, no CGo) and we can capture its output.
func TestEvalArithmetic(t *testing.T) {
	ctx := context.Background()
	e, err := New(ctx)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer e.Close(ctx)

	out, err := e.Eval(ctx, `console.log(1 + 1)`)
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if strings.TrimSpace(out) != "2" {
		t.Fatalf("1+1 => %q, want 2", out)
	}
}

// TestEvalReuse proves the compiled module is reusable across many per-call instances
// (the instantiate-per-call model), each with isolated state.
func TestEvalReuse(t *testing.T) {
	ctx := context.Background()
	e, err := New(ctx)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer e.Close(ctx)

	for i, tc := range []struct{ code, want string }{
		{`console.log(JSON.stringify({a:[1,2,3].map(x=>x*2)}))`, `{"a":[2,4,6]}`},
		{`globalThis.leak = 42; console.log(typeof leak)`, `number`},
		{`console.log(typeof leak)`, `undefined`}, // fresh instance: previous global is gone
	} {
		out, err := e.Eval(ctx, tc.code)
		if err != nil {
			t.Fatalf("case %d Eval: %v", i, err)
		}
		if strings.TrimSpace(out) != tc.want {
			t.Fatalf("case %d => %q, want %q", i, strings.TrimSpace(out), tc.want)
		}
	}
}

// TestEvalSyntaxError confirms a broken tool surfaces an error rather than hanging.
func TestEvalSyntaxError(t *testing.T) {
	ctx := context.Background()
	e, err := New(ctx)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer e.Close(ctx)

	if _, err := e.Eval(ctx, `function (`); err == nil {
		t.Fatal("syntax error did not surface")
	}
}
