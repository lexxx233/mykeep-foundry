package jsengine

import (
	_ "embed"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	quickjs "github.com/aperturerobotics/go-quickjs-wasi-reactor/wazero-quickjs"
	"github.com/tetratelabs/wazero"
)

// ErrTimeout is returned when a tool exceeds its wall-clock limit (a runaway loop or a
// host call that never completes). The instance is discarded; the engine stays healthy.
var ErrTimeout = errors.New("tool exceeded time limit")

//go:embed bootstrap.js
var bootstrapJS string

// HostFunc is the Go side of the host ABI: it executes one tool host call (kv.get,
// http.fetch, …) and returns the JSON result, or an error the tool sees as a thrown
// exception. Capability enforcement lives here, never in the JS.
type HostFunc func(ctx context.Context, op string, args json.RawMessage) (json.RawMessage, error)

// LogLine is one console.* / foundry.log line the tool emitted.
type LogLine struct {
	Level string
	Msg   string
}

// Result is the outcome of a tool invocation.
type Result struct {
	Value json.RawMessage // the value run(input) resolved to
	Logs  []LogLine
}

// maxIdleSpins bounds a stalled tool (one awaiting something the host never delivers)
// when no context deadline is set; a real deployment always passes a timeout.
const maxIdleSpins = 256

// Invoke runs a tool with DefaultLimits. See InvokeWithLimits for per-tool bounds.
func (e *Engine) Invoke(ctx context.Context, toolSrc string, input json.RawMessage, host HostFunc) (*Result, error) {
	return e.InvokeWithLimits(ctx, toolSrc, input, host, DefaultLimits)
}

// InvokeWithLimits runs a tool's JS source against an input, brokering its host calls
// through host, and returns what run(input) resolved to. A fresh sandbox is used per call
// (clean state). The call is bounded by lim: a wall-clock deadline (interrupts even a tight
// JS loop) and a wasm-memory cap (bounds an allocation bomb). On either breach the instance
// is discarded and a clear error returned; the engine stays healthy for the next call.
func (e *Engine) InvokeWithLimits(ctx context.Context, toolSrc string, input json.RawMessage, host HostFunc, lim Limits) (*Result, error) {
	// Boot the engine (instantiate + bootstrap) detached from the caller's deadline —
	// engine startup is Foundry's overhead, not the tool's, so it must not count against
	// the wall clock (and stays robust under slow, e.g. race-instrumented, environments).
	bootCtx := context.WithoutCancel(ctx)
	r := e.newRuntime(bootCtx, lim.MemPages)
	defer r.Close(bootCtx)

	fw := &frameWriter{}
	in := newRespPipe()
	if len(input) == 0 {
		input = json.RawMessage("{}")
	}
	cfg := wazero.NewModuleConfig().
		WithStdin(in).WithStdout(fw).WithStderr(fw).
		WithEnv("FOUNDRY_INPUT", string(input))

	q, err := quickjs.NewQuickJS(bootCtx, r, cfg)
	if err != nil {
		return nil, fmt.Errorf("instantiate quickjs: %w", err)
	}
	defer q.Close(bootCtx)

	if err := q.Init(bootCtx, []string{"qjs", "--std"}); err != nil {
		return nil, fmt.Errorf("init: %w", err)
	}
	if err := q.Eval(bootCtx, bootstrapJS, false); err != nil {
		return nil, fmt.Errorf("bootstrap: %w", err)
	}

	// From here on the tool's own code runs, so the wall-clock deadline applies. wazero's
	// WithCloseOnContextDone honors the per-call context, so passing this to Eval/LoopOnce
	// interrupts even a tight JS loop with no host calls.
	if lim.Wall > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, lim.Wall)
		defer cancel()
	}

	if err := q.Eval(ctx, toolSrc, false); err != nil {
		if ctx.Err() != nil {
			return nil, ErrTimeout
		}
		return nil, fmt.Errorf("tool load: %w", err)
	}
	if err := q.Eval(ctx, "__run()", false); err != nil {
		if ctx.Err() != nil {
			return nil, ErrTimeout
		}
		return nil, fmt.Errorf("tool start: %w", err)
	}

	var logs []LogLine
	idle := 0
	for {
		if ctx.Err() != nil {
			return nil, ErrTimeout
		}

		progressed := false
		for _, f := range fw.take() {
			progressed = true
			switch f.T {
			case "call":
				val, herr := host(ctx, f.Op, f.Args)
				if werr := e.writeResp(ctx, q, in, f.ID, val, herr); werr != nil {
					return nil, werr
				}
			case "log":
				logs = append(logs, LogLine{Level: f.Level, Msg: f.Msg})
			case "result":
				return &Result{Value: f.Value, Logs: logs}, nil
			case "error":
				return &Result{Logs: logs}, fmt.Errorf("tool error: %s", f.Error)
			}
		}

		res, err := q.LoopOnce(ctx)
		if err != nil {
			if ce := ctx.Err(); ce != nil {
				return nil, ErrTimeout // wazero interrupted a runaway loop at the deadline
			}
			return nil, fmt.Errorf("event loop: %w", err)
		}
		if res.IsPending() || progressed {
			idle = 0
			continue
		}
		// Idle with no frames and no microtasks: nudge the read handler, then give up if
		// the tool truly never completes (the deadline is the real bound in production).
		if _, err := q.PollIO(ctx, 0); err != nil {
			return nil, fmt.Errorf("poll io: %w", err)
		}
		if idle++; idle > maxIdleSpins {
			return &Result{Logs: logs}, fmt.Errorf("tool did not complete (stalled)")
		}
	}
}

// writeResp delivers one host-call response to the tool and pokes the event loop so the
// in-sandbox read handler runs and resolves the awaiting Promise.
func (e *Engine) writeResp(ctx context.Context, q *quickjs.QuickJS, in *respPipe, id int, val json.RawMessage, herr error) error {
	var line []byte
	if herr != nil {
		line, _ = json.Marshal(struct {
			ID    int    `json:"id"`
			Error string `json:"error"`
		}{id, herr.Error()})
	} else {
		if len(val) == 0 {
			val = json.RawMessage("null")
		}
		line, _ = json.Marshal(struct {
			ID    int             `json:"id"`
			Value json.RawMessage `json:"value"`
		}{id, val})
	}
	if _, err := in.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("write response: %w", err)
	}
	if _, err := q.PollIO(ctx, 0); err != nil {
		return fmt.Errorf("poll io: %w", err)
	}
	return nil
}
