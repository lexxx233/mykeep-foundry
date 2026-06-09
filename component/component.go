// Package component is Foundry's public integration surface: the duck-typed contract the
// mykeep suite aggregator composes (New/ID/FirstLaunch/Unlock/Mount/Lock/UseToken/
// ControlToken), mirroring Vault and Showstone. The boundary is stdlib + []byte: the suite
// injects a 32-byte HKDF sub-key as the DEK; standalone Foundry derives its own.
package component

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	"mykeep.ai/foundry/internal/host"
	"mykeep.ai/foundry/internal/jsengine"
	"mykeep.ai/foundry/internal/registry"
	"mykeep.ai/foundry/internal/runtime"
	"mykeep.ai/foundry/internal/server"
	"mykeep.ai/foundry/internal/store"
)

// ID is the component identity (used for the HKDF label mykeep/component/foundry).
const ID = "foundry"

const dbFile = "foundry.db.enc"

// Options configure a Foundry component.
type Options struct {
	DataDir         string              // where foundry.db.enc lives
	Version         string              // host binary version
	EnableLAN       bool                // expose the USE plane on the LAN
	UseToken        string              // agent token (generated if empty)
	ControlToken    string              // control token (generated if empty)
	ControlSession  string              // GUI session value also accepted on control plane
	SessionCookie   string              // cookie name (suite uses "mykeep_session")
	RegistryPubKeys []ed25519.PublicKey // pinned marketplace keys (empty = no marketplace install)
	Vault           host.VaultFiller    // by-reference Vault (suite injects; nil standalone)
}

// Component owns Foundry's runtime once unlocked.
type Component struct {
	opts Options
	path string

	mu     sync.Mutex
	store  *store.Store
	engine *jsengine.Engine
	srv    *server.Server
}

func New(opts Options) (*Component, error) {
	if opts.DataDir == "" {
		return nil, errors.New("DataDir required")
	}
	return &Component{opts: opts, path: filepath.Join(opts.DataDir, dbFile)}, nil
}

func (c *Component) ID() string { return ID }

// FirstLaunch reports whether the encrypted store does not yet exist.
func (c *Component) FirstLaunch() bool {
	_, err := os.Stat(c.path)
	return os.IsNotExist(err)
}

// Unlock opens the store under the supplied DEK and assembles the runtime + server.
func (c *Component) Unlock(ctx context.Context, dek []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.srv != nil {
		return nil // already unlocked
	}
	st, err := store.Open(ctx, c.path, dek)
	if err != nil {
		return err
	}
	eng, err := jsengine.New(ctx)
	if err != nil {
		_ = st.Close()
		return err
	}
	reg := registry.New(st, c.opts.RegistryPubKeys)
	rt := runtime.New(eng, st, reg, host.NewBroker(0), c.opts.Vault)
	c.store, c.engine = st, eng
	c.srv = server.New(rt, reg, server.Options{
		EnableLAN:      c.opts.EnableLAN,
		UseToken:       c.opts.UseToken,
		ControlToken:   c.opts.ControlToken,
		ControlSession: c.opts.ControlSession,
		SessionCookie:  c.opts.SessionCookie,
	})
	return nil
}

// Mount attaches the two planes to the shared mux (no-op until unlocked).
func (c *Component) Mount(mux *http.ServeMux) {
	c.mu.Lock()
	srv := c.srv
	c.mu.Unlock()
	if srv != nil {
		srv.Mount(mux)
	}
}

// UseToken / ControlToken expose the minted tokens (empty before Unlock).
func (c *Component) UseToken() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.srv == nil {
		return ""
	}
	return c.srv.UseToken()
}
func (c *Component) ControlToken() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.srv == nil {
		return ""
	}
	return c.srv.ControlToken()
}

// Lock seals the store and tears down the runtime. Idempotent.
func (c *Component) Lock() error {
	c.mu.Lock()
	st, eng := c.store, c.engine
	c.store, c.engine, c.srv = nil, nil, nil
	c.mu.Unlock()
	var err error
	if st != nil {
		err = st.Close()
	}
	if eng != nil {
		_ = eng.Close(context.Background())
	}
	return err
}

// Server returns the underlying server (for the standalone GUI to read tokens). Nil if locked.
func (c *Component) Server() *server.Server {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.srv
}
