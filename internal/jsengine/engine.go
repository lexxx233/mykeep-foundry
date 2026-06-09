// Package jsengine runs untrusted tool JavaScript inside a QuickJS engine that is
// itself compiled to WebAssembly and executed on the pure-Go wazero runtime. This is
// the core of Foundry's sandbox: no CGo, the same static binary on every OS, and a hard
// wasm memory boundary around code we did not write.
//
// The engine module is embedded (github.com/aperturerobotics/go-quickjs-wasi-reactor).
// Every tool call gets a FRESH wazero runtime + QuickJS instance, so state never leaks
// between calls — all persistence flows through host functions, never the JS heap. A
// shared wazero CompilationCache makes the per-call runtime cheap: the expensive machine-
// code generation for the QuickJS module happens once and is reused across calls.
package jsengine

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	quickjs "github.com/aperturerobotics/go-quickjs-wasi-reactor/wazero-quickjs"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

// Engine holds the shared compilation cache. It is safe for concurrent use: each call
// builds its own runtime, so there is no shared mutable wasm state to guard.
type Engine struct {
	cache wazero.CompilationCache
}

// New builds the engine and warms the compilation cache by compiling the embedded
// QuickJS module once on a throwaway runtime. Subsequent per-call compiles are cache hits.
func New(ctx context.Context) (*Engine, error) {
	cache := wazero.NewCompilationCache()
	r := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig().WithCompilationCache(cache))
	defer r.Close(ctx)
	if _, err := wasi_snapshot_preview1.Instantiate(ctx, r); err != nil {
		_ = cache.Close(ctx)
		return nil, fmt.Errorf("instantiate wasi: %w", err)
	}
	if _, err := quickjs.CompileQuickJS(ctx, r); err != nil {
		_ = cache.Close(ctx)
		return nil, fmt.Errorf("compile quickjs: %w", err)
	}
	return &Engine{cache: cache}, nil
}

// Close releases the compilation cache.
func (e *Engine) Close(ctx context.Context) error {
	return e.cache.Close(ctx)
}

// newRuntime builds a fresh, isolated runtime backed by the shared cache, with
// context-cancellation wired in so a per-call deadline can interrupt even a tight JS loop.
func (e *Engine) newRuntime(ctx context.Context) wazero.Runtime {
	return wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig().
		WithCompilationCache(e.cache).
		WithCloseOnContextDone(true))
}

// Eval instantiates a fresh QuickJS, runs code, and returns whatever the script wrote to
// stdout (console.log / std.out). It is the M0 proof that the sandbox executes JS; the
// real per-call invocation path (input/output marshaling + the foundry host global) is
// built on top of this in later milestones.
func (e *Engine) Eval(ctx context.Context, code string) (string, error) {
	r := e.newRuntime(ctx)
	defer r.Close(ctx)

	var out bytes.Buffer
	cfg := wazero.NewModuleConfig().WithStdout(&out).WithStderr(&out)
	q, err := quickjs.NewQuickJS(ctx, r, cfg)
	if err != nil {
		return "", fmt.Errorf("instantiate quickjs: %w", err)
	}
	defer q.Close(ctx)

	if err := q.Init(ctx, []string{"qjs"}); err != nil {
		return out.String(), fmt.Errorf("init: %w", err)
	}
	if err := q.Eval(ctx, code, false); err != nil {
		return out.String(), fmt.Errorf("eval: %w (%s)", err, strings.TrimSpace(out.String()))
	}
	if err := q.RunLoop(ctx); err != nil {
		return out.String(), fmt.Errorf("run loop: %w", err)
	}
	return out.String(), nil
}
