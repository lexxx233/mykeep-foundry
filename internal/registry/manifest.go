// Package registry installs, verifies, and grants tools. A tool is JS source + a manifest
// declaring what it needs; the human grants a (possibly narrowed) subset, bound to the
// manifest hash so an update must be re-approved. Marketplace tools are ed25519-signed by
// the registry; dev tools are unsigned and run only with explicit local consent.
package registry

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Manifest is a tool's declared identity + capability request.
type Manifest struct {
	Name         string          `json:"name"`
	Version      string          `json:"version"`
	Description  string          `json:"description"`
	Author       string          `json:"author,omitempty"`
	ParamsSchema json.RawMessage `json:"params_schema,omitempty"`
	Capabilities Capabilities    `json:"capabilities"`
}

// Capabilities is what a tool asks for; the granted subset is a Grant.
type Capabilities struct {
	Network struct {
		Hosts []string `json:"hosts"`
	} `json:"network"`
	Vault struct {
		Credentials []string `json:"credentials"`
	} `json:"vault"`
	Storage struct {
		Namespace  string `json:"namespace"`
		QuotaBytes int64  `json:"quota_bytes"`
	} `json:"storage"`
	Limits struct {
		MemPages uint32 `json:"mem_pages"`
		WallMs   int    `json:"wall_ms"`
	} `json:"limits"`
}

// ParseManifest decodes and validates a manifest.
func ParseManifest(b []byte) (*Manifest, error) {
	var m Manifest
	dec := json.NewDecoder(bytesReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	if m.Name == "" || m.Version == "" {
		return nil, errors.New("manifest: name and version are required")
	}
	if m.Capabilities.Storage.Namespace == "" {
		m.Capabilities.Storage.Namespace = m.Name // default the storage namespace to the tool name
	}
	return &m, nil
}

// Canonical returns the manifest re-marshaled deterministically (stable key order via the
// struct), used as the signed/hashed bytes.
func (m *Manifest) Canonical() []byte {
	b, _ := json.Marshal(m)
	return b
}

// Hash is the hex SHA-256 of the canonical manifest; a grant binds to it so a changed
// manifest invalidates the grant.
func (m *Manifest) Hash() string {
	sum := sha256.Sum256(m.Canonical())
	return hex.EncodeToString(sum[:])
}

// Limits resolves the manifest's requested execution limits, applying defaults.
func (m *Manifest) wallDefault() time.Duration {
	if m.Capabilities.Limits.WallMs > 0 {
		return time.Duration(m.Capabilities.Limits.WallMs) * time.Millisecond
	}
	return 5 * time.Second
}
