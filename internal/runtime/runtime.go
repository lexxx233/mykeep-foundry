// Package runtime ties the pieces together: given a tool name and input, it loads the
// tool + its human-approved grant, builds the capability-scoped host dispatcher, and runs
// the tool in the sandbox under the grant's limits. This is the one place a tool, its
// grant, and its enforcement meet.
package runtime

import (
	"context"
	"encoding/json"

	"mykeep.ai/foundry/internal/host"
	"mykeep.ai/foundry/internal/jsengine"
	"mykeep.ai/foundry/internal/registry"
	"mykeep.ai/foundry/internal/store"
)

// Runtime executes installed, granted tools.
type Runtime struct {
	engine *jsengine.Engine
	store  *store.Store
	reg    *registry.Registry
	broker *host.Broker
	vault  host.VaultFiller
}

// New builds a runtime. vault may be nil (no by-reference Vault available standalone).
func New(engine *jsengine.Engine, st *store.Store, reg *registry.Registry, broker *host.Broker, vault host.VaultFiller) *Runtime {
	return &Runtime{engine: engine, store: st, reg: reg, broker: broker, vault: vault}
}

// Run executes a tool by name with the given input. It refuses a tool with no current
// grant (registry.ErrNotGranted, including the "manifest changed" case), and bounds the
// call by the grant's limits. Everything the tool can touch is the grant — enforced in Go.
func (rt *Runtime) Run(ctx context.Context, name string, input json.RawMessage) (*jsengine.Result, error) {
	tool, err := rt.reg.Get(name)
	if err != nil {
		return nil, err
	}
	grant, err := rt.reg.Grant(name)
	if err != nil {
		return nil, err
	}

	// Apply the granted storage quota for this tool's namespace before it runs.
	if grant.QuotaBytes > 0 {
		if err := rt.store.SetQuota(grant.Namespace, grant.QuotaBytes); err != nil {
			return nil, err
		}
	}

	d := host.New(host.Config{
		Store:      rt.store,
		Namespace:  grant.Namespace,
		AllowHosts: grant.Hosts,
		VaultCreds: grant.VaultCreds,
		Broker:     rt.broker,
		Vault:      rt.vault,
	})
	lim := jsengine.Limits{Wall: grant.Wall, MemPages: grant.MemPages}
	_ = tool.Class // (dev vs marketplace gating is enforced at the server/catalog layer)
	return rt.engine.InvokeWithLimits(ctx, tool.Source, input, d.HostFunc(), lim)
}
