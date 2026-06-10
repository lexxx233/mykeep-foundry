package registry

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client is the marketplace half: it fetches the signed catalog index from the registry's
// base URL (a Cloudflare-fronted custom domain over R2), verifies it against the pinned
// registry keys, and installs a named tool version — download → verify zip SHA-256 →
// unpack → verify the per-artifact source signature → install into the encrypted store.
type Client struct {
	baseURL string // e.g. https://foundry.mykeep.ai/v1/
	pubkeys []ed25519.PublicKey
	http    *http.Client

	idx *Index // last-verified catalog, cached in memory
}

// NewClient builds a marketplace client. baseURL should end with a slash.
func NewClient(baseURL string, pubkeys []ed25519.PublicKey) *Client {
	if !strings.HasSuffix(baseURL, "/") {
		baseURL += "/"
	}
	return &Client{baseURL: baseURL, pubkeys: pubkeys, http: &http.Client{Timeout: 30 * time.Second}}
}

// EnsureIndex fetches index.json + index.json.sig, verifies the signature against a pinned
// key, and caches the catalog. It also enforces monotonic freshness: a fetched index older
// than the one already cached is rejected (anti-rollback).
func (c *Client) EnsureIndex(ctx context.Context) error {
	raw, err := c.get(ctx, "index.json")
	if err != nil {
		return err
	}
	sig, err := c.get(ctx, "index.json.sig")
	if err != nil {
		return err
	}
	if err := verifyIndex(c.pubkeys, raw, sig); err != nil {
		return err
	}
	var idx Index
	if err := json.Unmarshal(raw, &idx); err != nil {
		return fmt.Errorf("index: %w", err)
	}
	if c.idx != nil && idx.GeneratedAt < c.idx.GeneratedAt {
		return fmt.Errorf("refusing older index (rollback): %s < %s", idx.GeneratedAt, c.idx.GeneratedAt)
	}
	c.idx = &idx
	return nil
}

// Catalog returns the verified catalog (call EnsureIndex first).
func (c *Client) Catalog() *Index { return c.idx }

// Install resolves id@version in the verified catalog, downloads + verifies the artifact,
// and installs it into reg as a signed marketplace tool. version=="" installs the latest.
func (c *Client) Install(ctx context.Context, reg *Registry, id, version string) (*Manifest, error) {
	if c.idx == nil {
		if err := c.EnsureIndex(ctx); err != nil {
			return nil, err
		}
	}
	_, ver, err := c.idx.find(id, version)
	if err != nil {
		return nil, err
	}

	zipped, err := c.get(ctx, ver.Artifact)
	if err != nil {
		return nil, err
	}
	if zipSHA256(zipped) != ver.ZipSHA256 {
		return nil, fmt.Errorf("artifact hash mismatch for %s@%s", id, ver.Version)
	}
	m, source, err := unpackTool(zipped)
	if err != nil {
		return nil, err
	}
	// InstallMarketplace re-verifies the source signature against the pinned key — so even
	// the verified catalog can't smuggle in code the registry didn't sign. ver.Verified is
	// trustworthy because the whole index was signature-checked in EnsureIndex.
	if err := reg.InstallMarketplace(m, source, ver.SourceSig, ver.Verified); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *Client) get(ctx context.Context, rel string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+rel, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", rel, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 16<<20))
}
