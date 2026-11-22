// Package ident canonicalizes and normalizes user identifiers.
//
// The OPAQUE credential identifier must be stable for the whole lifetime of a
// credential: it is the input to the per-user OPRF key derivation
// (RFC 9807, Section 10.9). If we ever changed the canonical form (e.g. by
// starting to lower-case e-mail addresses), every existing user would lock
// out of their account permanently, and the only recovery would be an
// out-of-band reset. Therefore the canonicalization rule is versioned and
// written down here, and is part of the credential record (ident_version).
package ident

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// Version identifies the canonicalization rule in force for a credential.
//
// Version 1: trim leading/trailing Unicode whitespace, then lower-case ASCII
// A-Z only. Non-ASCII is left untouched (no Unicode case-folding) so that the
// rule is trivial to reimplement identically in every client language and can
// never depend on a Unicode data table version.
const Version = 1

// MaxLen bounds the identifier length in bytes after normalization, so that
// per-user key derivation and database keys stay bounded.
const MaxLen = 254

// ErrInvalid is returned for identifiers that cannot be canonicalized.
var ErrInvalid = errors.New("ident: invalid identifier")

// Canonicalize returns the canonical byte form of a user identifier.
func Canonicalize(raw string) ([]byte, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil, fmt.Errorf("%w: empty", ErrInvalid)
	}
	if !utf8.ValidString(s) {
		return nil, fmt.Errorf("%w: not valid UTF-8", ErrInvalid)
	}
	// Reject control characters: they enable homograph/log confusion and can
	// break the textual transport encoding.
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return nil, fmt.Errorf("%w: control character", ErrInvalid)
		}
	}
	b := []byte(s)
	for i := 0; i < len(b); i++ {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	if len(b) > MaxLen {
		return nil, fmt.Errorf("%w: longer than %d bytes", ErrInvalid, MaxLen)
	}
	return b, nil
}

// AccountKey derives the opaque, stable database key for a canonical
// identifier under the given server-side pepper.
//
// The login path must look up a credential before any authentication has
// happened, so the lookup key cannot itself be a secret from an attacker who
// holds the database. Peppering it with a key held outside the database (KMS
// or a file the database backup does not include) means that a database-only
// compromise cannot enumerate the user table, cannot correlate it with other
// leaked breach data, and cannot precompute per-victim guessing work ahead of
// the breach. See docs/THREAT-MODEL.md, "Enumeration and the account index".
func AccountKey(pepper []byte, canonical []byte) []byte {
	m := sha256.New()
	m.Write([]byte("opaqueauth/account-key/v1\x00"))
	m.Write(pepper)
	m.Write([]byte{0})
	m.Write(canonical)
	return m.Sum(nil)
}

// CredentialID derives the OPAQUE credential_identifier from an account key.
//
// It MUST be derived from the account key and nothing else: registration,
// login, password change, recovery, and legacy import all compute it, and the
// per-user OPRF key is derived from it (RFC 9807 §10.9). If any caller derived
// it from a different input — as a canonical identifier instead of the
// account key, say — that caller's users would authenticate against a
// different OPRF key than the one their credential was registered under, which
// fails closed but is a silent, total outage for those users.
//
// Accounts store it so the invariant is auditable, but every read recomputes
// it from the account key and compares; a stored value that disagrees is
// treated as corruption.
func CredentialID(pepper, accountKey []byte) []byte {
	m := sha256.New()
	m.Write([]byte("opaqueauth/credential-id/v1\x00"))
	m.Write(pepper)
	m.Write([]byte{0})
	m.Write(accountKey)
	return m.Sum(nil)
}

// FakeCredentialID derives a credential identifier for a user that does not
// exist. The server uses it to build a decoy OPAQUE record so that an unknown
// user is indistinguishable from a known one during login (RFC 9807 §10.9).
func FakeCredentialID(pepper, accountKey []byte) []byte {
	m := sha256.New()
	m.Write([]byte("opaqueauth/fake-credential-id/v1\x00"))
	m.Write(pepper)
	m.Write([]byte{0})
	m.Write(accountKey)
	return m.Sum(nil)
}
