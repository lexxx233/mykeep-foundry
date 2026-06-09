package jsengine

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// echoSumHost is a test host: it implements `echo` (returns its args) and `sum`
// (adds a JSON array of numbers), proving JSON round-trips Go↔JS↔Go in both directions.
func echoSumHost(_ context.Context, op string, args json.RawMessage) (json.RawMessage, error) {
	switch op {
	case "echo":
		return args, nil // bounce the argument straight back
	case "sum":
		var nums []float64
		if err := json.Unmarshal(args, &nums); err != nil {
			return nil, err
		}
		var total float64
		for _, n := range nums {
			total += n
		}
		return json.Marshal(total)
	default:
		return nil, errUnknownOp(op)
	}
}

type errUnknownOp string

func (e errUnknownOp) Error() string { return "unknown op: " + string(e) }

// TestInvokeRoundTrip is the M1 gate: a tool awaits host calls, the Go host answers them,
// and the tool's returned value comes back intact — the full host_call trampoline.
func TestInvokeRoundTrip(t *testing.T) {
	ctx := context.Background()
	e, err := New(ctx)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer e.Close(ctx)

	simple := `
		async function run(input) {
			const echoed = await foundry.echo({ greet: "hi " + input.name });
			return { echoed: echoed, doubled: input.n * 2 };
		}
	`
	out := mustInvoke(t, e, simple, json.RawMessage(`{"name":"ada","n":21}`), echoSumHost)
	var got struct {
		Echoed  map[string]string `json:"echoed"`
		Doubled int               `json:"doubled"`
	}
	if err := json.Unmarshal(out.Value, &got); err != nil {
		t.Fatalf("unmarshal result %s: %v", out.Value, err)
	}
	if got.Echoed["greet"] != "hi ada" {
		t.Fatalf("echo round-trip failed: %v", got.Echoed)
	}
	if got.Doubled != 42 {
		t.Fatalf("doubled => %d, want 42", got.Doubled)
	}
}

// TestInvokeSequentialCalls proves multiple awaited host calls in one tool all resolve.
func TestInvokeSequentialCalls(t *testing.T) {
	ctx := context.Background()
	e, err := New(ctx)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer e.Close(ctx)

	tool := `
		async function run(input) {
			let acc = 0;
			for (const batch of input.batches) {
				acc += await foundry.echo(batch).then(b => b.reduce((x,y)=>x+y,0));
			}
			return { sum: acc };
		}
	`
	out := mustInvoke(t, e, tool, json.RawMessage(`{"batches":[[1,2],[3,4],[5]]}`), echoSumHost)
	if strings.TrimSpace(string(out.Value)) != `{"sum":15}` {
		t.Fatalf("sequential calls => %s, want {\"sum\":15}", out.Value)
	}
}

// TestInvokeHostError surfaces a host-side error as a thrown JS exception the tool can catch.
func TestInvokeHostError(t *testing.T) {
	ctx := context.Background()
	e, err := New(ctx)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer e.Close(ctx)

	tool := `
		async function run() {
			try { await foundry.kv.get("x"); return { caught: false }; }
			catch (e) { return { caught: true, msg: String(e.message) }; }
		}
	`
	denyHost := func(_ context.Context, op string, _ json.RawMessage) (json.RawMessage, error) {
		return nil, errUnknownOp(op)
	}
	out := mustInvoke(t, e, tool, nil, denyHost)
	if !strings.Contains(string(out.Value), `"caught":true`) {
		t.Fatalf("tool did not catch host error: %s", out.Value)
	}
}

// TestInvokeCapturesLogs proves console.log is captured as structured log lines.
func TestInvokeCapturesLogs(t *testing.T) {
	ctx := context.Background()
	e, err := New(ctx)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer e.Close(ctx)

	tool := `async function run() { console.log("hello", 42); return 1; }`
	out := mustInvoke(t, e, tool, nil, echoSumHost)
	if len(out.Logs) != 1 || !strings.Contains(out.Logs[0].Msg, "hello 42") {
		t.Fatalf("logs => %+v, want one 'hello 42'", out.Logs)
	}
}
