// Command foundry runs the Foundry tool host: a portable, sandboxed WebAssembly runtime
// that loads JS "tools" off the stick and runs them for an AI agent, with the encrypted
// backend (kv/queue/cache/blob) they run on — all pure Go, no CGo.
//
//	foundry            open the local GUI (unlock + manage tools in the browser)
//	foundry gui        same as default
//	foundry serve      headless: unlock at launch (env/stdin), serve the API only
//	foundry version    print the build
//	foundry selftest   prove the embedded sandbox runs on this host
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"mykeep.ai/foundry/component"
	"mykeep.ai/foundry/internal/gui"
	"mykeep.ai/foundry/internal/jsengine"
	"mykeep.ai/foundry/internal/secret"
)

var version = "0.1.0-dev"

func main() {
	mode := "gui"
	args := os.Args[1:]
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		mode, args = args[0], args[1:]
	}
	var err error
	switch mode {
	case "gui":
		err = runGUI(args)
	case "serve":
		err = runServe(args)
	case "version":
		fmt.Printf("foundry %s\n", version)
	case "selftest":
		if err = selftest(); err == nil {
			fmt.Println("foundry sandbox OK")
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q (use: gui | serve | version | selftest)\n", mode)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func runGUI(args []string) error {
	fs := flag.NewFlagSet("gui", flag.ExitOnError)
	dir := fs.String("data", "mykeep_kb", "data directory (foundry.key.json + foundry.db.enc)")
	addr := fs.String("addr", "127.0.0.1:8772", "loopback listen address")
	idleMin := fs.Int("idle", 15, "idle minutes before auto-lock (0 disables)")
	fs.Parse(args)
	if err := os.MkdirAll(*dir, 0o700); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return gui.New(*dir, *addr, version, time.Duration(*idleMin)*time.Minute).Run(ctx)
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	dir := fs.String("data", "mykeep_kb", "data directory")
	addr := fs.String("addr", "127.0.0.1:8772", "listen address")
	lan := fs.Bool("lan", false, "expose the USE plane on the LAN (control plane stays loopback)")
	fs.Parse(args)
	if err := os.MkdirAll(*dir, 0o700); err != nil {
		return err
	}

	pw := passphrase()
	if len(pw) == 0 {
		return fmt.Errorf("empty passphrase")
	}
	dek, err := loadOrCreateDEK(*dir, pw)
	if err != nil {
		return err
	}
	comp, err := component.New(component.Options{DataDir: *dir, Version: version, EnableLAN: *lan})
	if err != nil {
		return err
	}
	if err := comp.Unlock(context.Background(), dek); err != nil {
		return err
	}
	mux := http.NewServeMux()
	comp.Mount(mux)
	fmt.Printf("\nFoundry serving on %s  (LAN use plane: %v)\n", *addr, *lan)
	fmt.Printf("  agent (use)  token: %s\n", comp.UseToken())
	fmt.Printf("  control      token: %s   ← keep this off the wire\n\n", comp.ControlToken())

	httpSrv := &http.Server{Addr: *addr, Handler: mux}
	errCh := make(chan error, 1)
	go func() {
		if e := httpSrv.ListenAndServe(); e != nil && e != http.ErrServerClosed {
			errCh <- e
		}
	}()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	select {
	case <-ctx.Done():
	case e := <-errCh:
		_ = comp.Lock()
		return e
	}
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(sctx)
	return comp.Lock()
}

func loadOrCreateDEK(dir string, pw []byte) ([]byte, error) {
	keyPath := filepath.Join(dir, "foundry.key.json")
	if b, err := os.ReadFile(keyPath); err == nil {
		var env secret.Envelope
		if err := json.Unmarshal(b, &env); err != nil {
			return nil, err
		}
		return env.Unwrap(pw)
	}
	env, dek, err := secret.NewEnvelope(pw)
	if err != nil {
		return nil, err
	}
	b, _ := json.Marshal(env)
	if err := os.WriteFile(keyPath, b, 0o600); err != nil {
		return nil, err
	}
	fmt.Println("• created a new Foundry store")
	return dek, nil
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
	if !strings.Contains(out, "foundry:42") {
		return fmt.Errorf("unexpected sandbox output: %q", out)
	}
	return nil
}

func passphrase() []byte {
	if v := os.Getenv("MYKEEP_FOUNDRY_PASSPHRASE"); v != "" {
		return []byte(v)
	}
	fmt.Fprint(os.Stderr, "Foundry passphrase: ")
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return []byte(strings.TrimRight(line, "\r\n"))
}
