package registry

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Index is the marketplace catalog: a single JSON document served from the registry's
// custom domain, with a detached ed25519 signature (Index.json.sig) over its canonical
// bytes. Verifying that one signature authenticates every entry transitively (and blocks
// an R2-only attacker from injecting, removing, or rolling back tools).
type Index struct {
	Schema      int         `json:"schema"`
	GeneratedAt string      `json:"generated_at"`
	Tools       []IndexTool `json:"tools"`
}

// IndexTool is one tool's catalog entry.
type IndexTool struct {
	ID       string         `json:"id"` // author/name
	Author   string         `json:"author"`
	Name     string         `json:"name"`
	Latest   string         `json:"latest"`
	Versions []IndexVersion `json:"versions"`
}

// IndexVersion is one published version: where the artifact is, its integrity hash, the
// embedded manifest, the AI review verdict (advisory), and the per-artifact source
// signature InstallMarketplace re-verifies.
type IndexVersion struct {
	Version   string          `json:"version"`
	Artifact  string          `json:"artifact"`   // relative path under the registry base URL
	ZipSHA256 string          `json:"zip_sha256"` // integrity of the downloaded artifact
	SourceSig []byte          `json:"source_sig"` // ed25519 over name|version|source-sha
	Manifest  json.RawMessage `json:"manifest"`
	Verified  bool            `json:"verified"` // passed AI review (else listed + installable, just not vouched)
	Review    *Review         `json:"review,omitempty"`
}

// Review is the advisory AI-review verdict surfaced in the catalog (never a trust root).
type Review struct {
	Verdict   string `json:"verdict"` // pass | flag
	Model     string `json:"model"`
	RiskScore int    `json:"risk_score"`
}

// CanonicalIndex returns the deterministic bytes signed/verified for the index.
func CanonicalIndex(idx *Index) []byte { b, _ := json.Marshal(idx); return b }

// SignIndex produces the detached index signature (publish side / tests).
func SignIndex(priv ed25519.PrivateKey, idx *Index) []byte {
	return ed25519.Sign(priv, CanonicalIndex(idx))
}

// verifyIndex checks the detached index signature against any pinned registry key.
func verifyIndex(pubkeys []ed25519.PublicKey, raw, sig []byte) error {
	for _, pk := range pubkeys {
		if len(pk) == ed25519.PublicKeySize && ed25519.Verify(pk, raw, sig) {
			return nil
		}
	}
	return ErrBadSignature
}

// find returns the requested version (or the latest if version=="").
func (idx *Index) find(id, version string) (*IndexTool, *IndexVersion, error) {
	for i := range idx.Tools {
		t := &idx.Tools[i]
		if t.ID != id {
			continue
		}
		if version == "" {
			version = t.Latest
		}
		for j := range t.Versions {
			if t.Versions[j].Version == version {
				return t, &t.Versions[j], nil
			}
		}
		return nil, nil, fmt.Errorf("version not found: %s@%s", id, version)
	}
	return nil, nil, fmt.Errorf("tool not in catalog: %s", id)
}

// --- tool.zip artifact (manifest.json + tool.js) ---

// PackTool builds a tool.zip artifact (publish side / tests).
func PackTool(m *Manifest, source string) ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	mf, err := zw.Create("manifest.json")
	if err != nil {
		return nil, err
	}
	if _, err := mf.Write(m.Canonical()); err != nil {
		return nil, err
	}
	sf, err := zw.Create("tool.js")
	if err != nil {
		return nil, err
	}
	if _, err := sf.Write([]byte(source)); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// unpackTool extracts manifest.json + tool.js from a tool.zip, guarding against oversized
// or malformed archives.
func unpackTool(data []byte) (*Manifest, string, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, "", fmt.Errorf("bad artifact: %w", err)
	}
	var manifestBytes []byte
	var source string
	for _, f := range zr.File {
		switch f.Name {
		case "manifest.json":
			manifestBytes, err = readZip(f, 1<<20)
		case "tool.js":
			var b []byte
			b, err = readZip(f, 4<<20)
			source = string(b)
		default:
			// ignore unexpected members
		}
		if err != nil {
			return nil, "", err
		}
	}
	if manifestBytes == nil || source == "" {
		return nil, "", errors.New("artifact missing manifest.json or tool.js")
	}
	m, err := ParseManifest(manifestBytes)
	return m, source, err
}

func readZip(f *zip.File, max int64) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(io.LimitReader(rc, max))
}

func zipSHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
