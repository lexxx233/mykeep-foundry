package registry

import (
	"encoding/json"
	"time"

	"mykeep.ai/foundry/internal/jsengine"
)

// Grant is the human-approved subset of a tool's declared capabilities, bound to the
// manifest hash it was approved against. Enforcement reads this — never the manifest.
type Grant struct {
	Hosts        []string      `json:"hosts"`
	VaultCreds   []string      `json:"vault_creds"`
	Namespace    string        `json:"namespace"`
	QuotaBytes   int64         `json:"quota_bytes"`
	Wall         time.Duration `json:"wall"`
	MemPages     uint32        `json:"mem_pages"`
	ManifestHash string        `json:"manifest_hash"`
}

// DefaultGrant proposes the full set a manifest requests (the human can narrow it before
// approving). MemPages/Wall fall back to engine defaults when unspecified.
func DefaultGrant(m *Manifest) Grant {
	g := Grant{
		Hosts:        append([]string(nil), m.Capabilities.Network.Hosts...),
		VaultCreds:   append([]string(nil), m.Capabilities.Vault.Credentials...),
		Namespace:    m.Capabilities.Storage.Namespace,
		QuotaBytes:   m.Capabilities.Storage.QuotaBytes,
		Wall:         m.wallDefault(),
		MemPages:     m.Capabilities.Limits.MemPages,
		ManifestHash: m.Hash(),
	}
	if g.MemPages == 0 {
		g.MemPages = jsengine.DefaultLimits.MemPages
	}
	return g
}

func (g Grant) marshal() []byte { b, _ := json.Marshal(g); return b }

func unmarshalGrant(b []byte) (Grant, error) {
	var g Grant
	err := json.Unmarshal(b, &g)
	return g, err
}
