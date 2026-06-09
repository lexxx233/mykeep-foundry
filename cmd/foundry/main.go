// Command foundry runs the Foundry tool host: a portable, sandboxed WebAssembly runtime
// that loads JS "tools" off the stick and runs them for an AI agent, with the encrypted
// backend (kv/queue/cache/blob) they run on — all pure Go, no CGo.
//
// Subcommands (gui[default]/serve/version) are wired up as the milestones land; today the
// engine sandbox (internal/jsengine) is in place and this entrypoint reports the build.
package main

import (
	"context"
	"fmt"
	"os"

	"mykeep.ai/foundry/internal/jsengine"
)

var version = "0.1.0-dev"

func main() {
	mode := "version"
	if len(os.Args) > 1 {
		mode = os.Args[1]
	}
	switch mode {
	case "version":
		fmt.Printf("foundry %s\n", version)
	case "selftest":
		// Quick proof the embedded QuickJS sandbox runs on this host (pure-Go wazero).
		if err := selftest(); err != nil {
			fmt.Fprintln(os.Stderr, "selftest failed:", err)
			os.Exit(1)
		}
		fmt.Println("foundry sandbox OK")
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q (use: version | selftest)\n", mode)
		os.Exit(2)
	}
}

func selftest() error {
	ctx := context.Background()
	e, err := jsengine.New(ctx)
	if err != nil {
		return err
	}
	defer e.Close(ctx)
	out, err := e.Eval(ctx, `console.log("foundry:" + (6*7))`)
	if err != nil {
		return err
	}
	if want := "foundry:42"; len(out) < len(want) {
		return fmt.Errorf("unexpected sandbox output: %q", out)
	}
	return nil
}
