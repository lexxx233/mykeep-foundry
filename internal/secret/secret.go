// Package secret holds Foundry's at-rest crypto: a whole-DB seal under a 32-byte data
// encryption key (DEK). The DEK is supplied externally — derived by the standalone CLI's
// own argon2id envelope (NewEnvelope/Unwrap) or injected by the suite as an HKDF sub-key.
// The store never sees a password; it only seals/opens blobs under the DEK.
package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"

	"golang.org/x/crypto/argon2"
)

// DEKLen is the data-encryption-key length (AES-256).
const DEKLen = 32

// ErrWrongPassword is returned when an envelope cannot be unwrapped (bad password or
// tampered file): the GCM tag fails to authenticate.
var ErrWrongPassword = errors.New("wrong password")

// Seal encrypts plaintext under dek with a fresh nonce, returning nonce||ciphertext.
func Seal(dek, plaintext []byte) ([]byte, error) {
	g, err := gcm(dek)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return g.Seal(nonce, nonce, plaintext, nil), nil
}

// Open decrypts a nonce||ciphertext blob produced by Seal.
func Open(dek, blob []byte) ([]byte, error) {
	g, err := gcm(dek)
	if err != nil {
		return nil, err
	}
	if len(blob) < g.NonceSize() {
		return nil, errors.New("sealed blob too short")
	}
	nonce, ct := blob[:g.NonceSize()], blob[g.NonceSize():]
	pt, err := g.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, ErrWrongPassword
	}
	return pt, nil
}

func gcm(key []byte) (cipher.AEAD, error) {
	if len(key) != DEKLen {
		return nil, errors.New("dek must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// --- standalone password envelope (used by cmd/foundry; the suite injects a DEK instead) ---

const (
	argonTime    = 4
	argonMemory  = 256 * 1024 // 256 MiB
	argonThreads = 4
	saltLen      = 16
)

// Envelope wraps a random DEK under a password-derived key; persisted beside the binary.
type Envelope struct {
	Version int    `json:"version"`
	Salt    []byte `json:"salt"`
	Wrapped []byte `json:"wrapped"` // nonce||ciphertext of the DEK under the KEK
}

// NewEnvelope mints a fresh DEK, wraps it under a key derived from password, and returns
// both the envelope (to persist) and the live DEK (the caller wipes it on lock).
func NewEnvelope(password []byte) (*Envelope, []byte, error) {
	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, nil, err
	}
	dek := make([]byte, DEKLen)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, nil, err
	}
	kek := argon2.IDKey(password, salt, argonTime, argonMemory, argonThreads, DEKLen)
	defer wipe(kek)
	wrapped, err := Seal(kek, dek)
	if err != nil {
		wipe(dek)
		return nil, nil, err
	}
	return &Envelope{Version: 1, Salt: salt, Wrapped: wrapped}, dek, nil
}

// Unwrap re-derives the DEK from the password. A wrong password fails the GCM tag.
func (e *Envelope) Unwrap(password []byte) ([]byte, error) {
	kek := argon2.IDKey(password, e.Salt, argonTime, argonMemory, argonThreads, DEKLen)
	defer wipe(kek)
	return Open(kek, e.Wrapped)
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
