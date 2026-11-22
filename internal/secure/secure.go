// Package secure holds small cryptographic helpers shared by the auth service.
package secure

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

// Random returns n cryptographically random bytes.
func Random(n int) []byte {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		// crypto/rand.Read is documented never to fail on supported platforms.
		panic("secure: entropy source failed: " + err.Error())
	}
	return b
}

// Token returns n random bytes encoded as unpadded base64url. Use this for
// anything handed to a client or emailed: session tokens, recovery tokens,
// invite tokens, recovery codes.
func Token(n int) string {
	return base64.RawURLEncoding.EncodeToString(Random(n))
}

// HMAC computes HMAC-SHA256 over the concatenation of parts.
func HMAC(key []byte, parts ...[]byte) []byte {
	m := hmac.New(sha256.New, key)
	for _, p := range parts {
		m.Write(p)
	}
	return m.Sum(nil)
}

// Equal is a constant-time comparison.
func Equal(a, b []byte) bool { return subtle.ConstantTimeCompare(a, b) == 1 }

// Zero overwrites b with zeros. Best effort: the compiler may keep copies.
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// Label returns a domain-separated subkey.
func Label(master []byte, label string) []byte {
	return HMAC(master, []byte("opaqueauth/key/v1\x00"), []byte(label))
}

// ErrDecode indicates a malformed encoded secret.
var ErrDecode = errors.New("secure: malformed encoding")

// DecodeToken decodes a token produced by Token.
func DecodeToken(s string) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(b) == 0 {
		return nil, ErrDecode
	}
	return b, nil
}

// B64 encodes bytes for JSON transport.
func B64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// UnB64 decodes JSON transport bytes.
func UnB64(s string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, ErrDecode
	}
	return b, nil
}

// Sealed is the serialized form of one AEAD-protected value.
//
// The nonce is random per seal. The associated data binds the ciphertext to
// its purpose and to the specific principal, so a ciphertext copied from one
// row to another (or from one table to another) fails to open.
type Sealed struct {
	Nonce []byte
	CT    []byte
}

// Seal encrypts plaintext with AES-256-GCM under key, binding aad.
func Seal(key, aad, plaintext []byte) (Sealed, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return Sealed{}, fmt.Errorf("secure: seal: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return Sealed{}, fmt.Errorf("secure: seal: %w", err)
	}
	nonce := Random(gcm.NonceSize())
	ct := gcm.Seal(nil, nonce, plaintext, aad)
	return Sealed{Nonce: nonce, CT: ct}, nil
}

// Open decrypts s under key, verifying aad.
func Open(key, aad []byte, s Sealed) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("secure: open: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("secure: open: %w", err)
	}
	if len(s.Nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("secure: open: bad nonce length")
	}
	pt, err := gcm.Open(nil, s.Nonce, s.CT, aad)
	if err != nil {
		return nil, fmt.Errorf("secure: open: authentication failed")
	}
	return pt, nil
}
