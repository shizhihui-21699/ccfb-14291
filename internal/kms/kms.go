// Package kms abstracts access to the small set of long-lived secrets that
// must never be stored in the application database.
//
// Threat model in one paragraph: OPAQUE removes the password verifier from
// the server, but the server still holds key material that can turn a stolen
// database back into an offline-guessable one. Specifically, if an attacker
// obtains both a credential record and the OPRF seed (or a per-user OPRF key),
// they can evaluate the OPRF for a password guess locally and check the
// envelope offline. RFC 9807 Section 10.11 says this explicitly. The only
// structural defence is to keep that key material out of the database and out
// of database backups: an HSM, a cloud KMS, or (as in the provided file
// implementation) a key file provisioned separately and never included in a
// dump. A database-only breach then leaves the attacker with ciphertext-shaped
// records that cannot verify any guess, which forces per-account online
// attempts against a rate limiter.
package kms

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"sync"
)

// Name identifies a long-lived secret.
type Name string

const (
	// OPAQUEServerKeyMaterial is the encoded OPAQUE ServerKeyMaterial
	// (AKE private key + public key + OPRF global seed), hex encoded.
	OPAQUEServerKeyMaterial Name = "opaque.server_key_material"

	// AppRoot is 32 bytes of entropy from which every application subkey
	// (account index pepper, record MAC, session MAC, recovery, PoW) is
	// derived with domain separation.
	AppRoot Name = "app.root"
)

// Provider supplies long-lived secrets to the process.
//
// Implementations must be safe for concurrent use. A real deployment should
// use a KMS/HSM-backed implementation (AWS KMS, GCP KMS, Vault Transit, or an
// HSM) so that the key material is never readable as bytes by the
// application host at all; this interface deliberately returns bytes because
// the pure-Go OPAQUE implementation needs them, and the file implementation is
// a development stand-in that mirrors the same separation-of-storage property.
type Provider interface {
	Get(Name) ([]byte, error)
}

// FileProvider reads keys from a JSON file that is provisioned out of band
// (for example from a secret manager, mounted tmpfs, or an operator's
// password manager) and is never written by the service and never part of the
// database backup. The file maps key name to hex value.
type FileProvider struct {
	mu   sync.RWMutex
	keys map[string][]byte
}

// NewFileProvider loads a key file. The file must not be group/world readable.
func NewFileProvider(path string) (*FileProvider, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("kms: stat key file: %w", err)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("kms: key file %s must not be accessible by group/other (mode %o)", path, fi.Mode().Perm())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("kms: read key file: %w", err)
	}
	var doc map[string]string
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("kms: parse key file: %w", err)
	}
	keys := make(map[string][]byte, len(doc))
	for name, hexVal := range doc {
		b, err := hex.DecodeString(hexVal)
		if err != nil {
			return nil, fmt.Errorf("kms: key %q is not valid hex: %w", name, err)
		}
		keys[name] = b
	}
	return &FileProvider{keys: keys}, nil
}

// Get implements Provider.
func (f *FileProvider) Get(name Name) ([]byte, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	v, ok := f.keys[string(name)]
	if !ok {
		return nil, fmt.Errorf("kms: key %q not present in key file", name)
	}
	return append([]byte(nil), v...), nil
}

// MemoryProvider is an in-memory Provider for tests and the local demo CLI.
type MemoryProvider struct {
	mu   sync.RWMutex
	keys map[string][]byte
}

// NewMemoryProvider returns an empty provider.
func NewMemoryProvider() *MemoryProvider {
	return &MemoryProvider{keys: make(map[string][]byte)}
}

// Set stores a key.
func (m *MemoryProvider) Set(name Name, value []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.keys[string(name)] = append([]byte(nil), value...)
}

// Get implements Provider.
func (m *MemoryProvider) Get(name Name) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	v, ok := m.keys[string(name)]
	if !ok {
		return nil, fmt.Errorf("kms: key %q not present", name)
	}
	return append([]byte(nil), v...), nil
}

// Names returns the names present in the provider, sorted. Used by tooling.
func (m *MemoryProvider) Names() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]string, 0, len(m.keys))
	for k := range m.keys {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ErrMissing indicates required key material is absent.
var ErrMissing = errors.New("kms: required key material missing")
