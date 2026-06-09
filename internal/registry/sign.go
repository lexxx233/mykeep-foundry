package registry

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

// ErrBadSignature means a marketplace artifact failed verification against every pinned
// registry key — it was not published by the registry (or was tampered with).
var ErrBadSignature = errors.New("registry signature invalid")

// signedMessage is the canonical bytes the registry signs per artifact: the tool id, the
// version, and the source SHA-256 — binding the signature to the exact published code.
func signedMessage(name, version, sourceSHA string) []byte {
	return []byte(name + "\n" + version + "\n" + sourceSHA)
}

// sourceSHA256 is the hex SHA-256 of a tool's JS source.
func sourceSHA256(source []byte) string {
	sum := sha256.Sum256(source)
	return hex.EncodeToString(sum[:])
}

// verify checks sig over (name|version|sourceSHA) against any pinned registry public key.
func verify(pubkeys []ed25519.PublicKey, name, version, sourceSHA string, sig []byte) error {
	msg := signedMessage(name, version, sourceSHA)
	for _, pk := range pubkeys {
		if len(pk) == ed25519.PublicKeySize && ed25519.Verify(pk, msg, sig) {
			return nil
		}
	}
	return ErrBadSignature
}

// Sign produces a registry signature for an artifact (used by the publish pipeline / tests).
func Sign(priv ed25519.PrivateKey, name, version string, source []byte) []byte {
	return ed25519.Sign(priv, signedMessage(name, version, sourceSHA256(source)))
}
