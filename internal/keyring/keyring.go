// Package keyring wraps long-lived application keys with explicit versions and
// supports re-encryption, so that rotating the KMS root does not lock users out.
//
// Why this matters: every wrapped value in this system (contacts, legacy
// digests, in-flight state) is bound to a key. If the root is ever replaced —
// as it must be if it leaks, or on a schedule — the old key has to remain
// readable during the rollover window while new writes use the new key. Without
// a versioned envelope that rollover is all-or-nothing and a botched rotation
// is an outage.
package keyring

import (
	"encoding/binary"
	"errors"
	"fmt"

	"opaqueauth/internal/secure"
)

// ErrUnknownVersion is returned when a ciphertext names a key version this
// process does not hold.
var ErrUnknownVersion = errors.New("keyring: ciphertext was wrapped under an unknown key version")

// Ring holds the active key and the retained previous key.
type Ring struct {
	active   uint32
	activeK  []byte
	previous map[uint32][]byte
}

// New builds a Ring. activeKey is used for all new writes; retained maps older
// versions to their keys and may be empty.
func New(activeVersion uint32, activeKey []byte, retained map[uint32][]byte) (*Ring, error) {
	if activeVersion == 0 {
		return nil, errors.New("keyring: version 0 is reserved")
	}
	if len(activeKey) != 32 {
		return nil, fmt.Errorf("keyring: key must be 32 bytes, got %d", len(activeKey))
	}
	prev := make(map[uint32][]byte, len(retained))
	for v, k := range retained {
		if v == activeVersion {
			continue
		}
		if len(k) != 32 {
			return nil, fmt.Errorf("keyring: retained key v%d must be 32 bytes", v)
		}
		prev[v] = k
	}
	return &Ring{active: activeVersion, activeK: activeKey, previous: prev}, nil
}

// ActiveVersion returns the version new writes use.
func (r *Ring) ActiveVersion() uint32 { return r.active }

// Seal encrypts under the active key and prefixes the ciphertext with the key
// version. The version is also passed as AAD so that a version byte edited by
// an attacker makes decryption fail rather than misrouting.
func (r *Ring) Seal(aad, plaintext []byte) ([]byte, error) {
	verBytes := versionBytes(r.active)
	sealed, err := secure.Seal(r.activeK, append(verBytes, aad...), plaintext)
	if err != nil {
		return nil, err
	}
	out := append([]byte(nil), verBytes...)
	out = append(out, sealed.Nonce...)
	out = append(out, sealed.CT...)
	return out, nil
}

// Open decrypts a value produced by Seal, using whichever retained key it names.
func (r *Ring) Open(aad, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 4 {
		return nil, errors.New("keyring: ciphertext too short")
	}
	ver := binary.BigEndian.Uint32(ciphertext[:4])
	key, ok := r.keyFor(ver)
	if !ok {
		return nil, fmt.Errorf("%w: v%d", ErrUnknownVersion, ver)
	}
	_, nonce, ct, err := Split(ciphertext)
	if err != nil {
		return nil, err
	}
	return secure.Open(key, append(versionBytes(ver), aad...), secure.Sealed{Nonce: nonce, CT: ct})
}

// NeedsRewrap reports whether ciphertext was written under an older version.
func (r *Ring) NeedsRewrap(ciphertext []byte) bool {
	if len(ciphertext) < 4 {
		return true
	}
	return binary.BigEndian.Uint32(ciphertext[:4]) != r.active
}

// Rewrap decrypts under whatever version it names and re-encrypts under the
// active key. It is idempotent.
func (r *Ring) Rewrap(aad, ciphertext []byte) ([]byte, error) {
	pt, err := r.Open(aad, ciphertext)
	if err != nil {
		return nil, err
	}
	return r.Seal(aad, pt)
}

func (r *Ring) keyFor(v uint32) ([]byte, bool) {
	if v == r.active {
		return r.activeK, true
	}
	k, ok := r.previous[v]
	return k, ok
}

// Split separates a version-prefixed ciphertext into version, nonce, and
// ciphertext. Nonce length is fixed at the AES-GCM default used by secure.Seal.
func Split(b []byte) (ver uint32, nonce, ct []byte, err error) {
	const nonceLen = 12
	if len(b) < 4+nonceLen {
		return 0, nil, nil, errors.New("keyring: ciphertext too short")
	}
	return binary.BigEndian.Uint32(b[:4]), b[4 : 4+nonceLen], b[4+nonceLen:], nil
}

func versionBytes(v uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return b[:]
}

// NewActiveKey returns fresh key material for a new version.
func NewActiveKey() []byte { return secure.Random(32) }
