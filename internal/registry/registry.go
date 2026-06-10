package registry

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"

	"mykeep.ai/foundry/internal/store"
)

// Class is a tool's provenance.
const (
	ClassDev         = "dev"         // agent/user-authored, unsigned, local-only consent
	ClassMarketplace = "marketplace" // ed25519-signed by the registry
)

// ErrNotGranted means a tool exists but the human has not approved its capabilities.
var ErrNotGranted = errors.New("tool not granted")

// bytesReader avoids importing bytes in manifest.go just for the decoder.
func bytesReader(b []byte) *bytes.Reader { return bytes.NewReader(b) }

// Tool is an installed tool: manifest + source + provenance + verification status.
type Tool struct {
	Manifest *Manifest
	Source   string
	Class    string
	Verified bool // marketplace tool that passed AI review
}

// Registry installs/loads tools against the encrypted store, verifying marketplace
// signatures against a pinned set of registry public keys.
type Registry struct {
	store   *store.Store
	pubkeys []ed25519.PublicKey
}

func New(st *store.Store, pubkeys []ed25519.PublicKey) *Registry {
	return &Registry{store: st, pubkeys: pubkeys}
}

// InstallDev installs an unsigned, locally-authored tool (the agent's inner loop). It is
// runnable only after an explicit grant and never auto-listed on the agent USE plane.
func (r *Registry) InstallDev(m *Manifest, source string) error {
	return r.store.PutTool(store.ToolRow{
		Name: m.Name, Version: m.Version, Class: ClassDev,
		Manifest: m.Canonical(), Source: []byte(source), SourceSHA: sourceSHA256([]byte(source)),
	})
}

// InstallMarketplace verifies the registry signature over the artifact (integrity +
// provenance — the registry signs every published tool, verified or not), then installs
// it. verified records whether it passed AI review; an unverified tool still installs.
func (r *Registry) InstallMarketplace(m *Manifest, source string, sig []byte, verified bool) error {
	sha := sourceSHA256([]byte(source))
	if err := verify(r.pubkeys, m.Name, m.Version, sha, sig); err != nil {
		return err
	}
	return r.store.PutTool(store.ToolRow{
		Name: m.Name, Version: m.Version, Class: ClassMarketplace,
		Manifest: m.Canonical(), Source: []byte(source), SourceSHA: sha, Verified: verified,
	})
}

// Get loads an installed tool by name.
func (r *Registry) Get(name string) (*Tool, error) {
	row, ok, err := r.store.GetTool(name)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("tool not installed: %s", name)
	}
	m, err := ParseManifest(row.Manifest)
	if err != nil {
		return nil, err
	}
	return &Tool{Manifest: m, Source: string(row.Source), Class: row.Class, Verified: row.Verified}, nil
}

// List returns installed tools (manifests + class), for the catalog.
func (r *Registry) List() ([]*Tool, error) {
	rows, err := r.store.ListTools()
	if err != nil {
		return nil, err
	}
	out := make([]*Tool, 0, len(rows))
	for _, row := range rows {
		m, err := ParseManifest(row.Manifest)
		if err != nil {
			return nil, err
		}
		out = append(out, &Tool{Manifest: m, Class: row.Class, Verified: row.Verified})
	}
	return out, nil
}

// Remove uninstalls a tool and its grant.
func (r *Registry) Remove(name string) error { return r.store.DeleteTool(name) }

// SetGrant records the human-approved capability grant for a tool, bound to the tool's
// current manifest hash.
func (r *Registry) SetGrant(name string, g Grant) error {
	t, err := r.Get(name)
	if err != nil {
		return err
	}
	g.ManifestHash = t.Manifest.Hash()
	return r.store.PutGrant(name, g.marshal(), g.ManifestHash)
}

// Grant returns a tool's active grant. It returns ErrNotGranted if none exists, or if the
// stored grant was bound to a different (now-superseded) manifest — forcing re-approval on
// update, so a tool can never silently escalate its capabilities.
func (r *Registry) Grant(name string) (Grant, error) {
	t, err := r.Get(name)
	if err != nil {
		return Grant{}, err
	}
	caps, manifestSHA, ok, err := r.store.GetGrant(name)
	if err != nil {
		return Grant{}, err
	}
	if !ok {
		return Grant{}, ErrNotGranted
	}
	if manifestSHA != t.Manifest.Hash() {
		return Grant{}, fmt.Errorf("%w: manifest changed since grant (re-approve required)", ErrNotGranted)
	}
	return unmarshalGrant(caps)
}
