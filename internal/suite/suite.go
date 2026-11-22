// Package suite pins the OPAQUE ciphersuite and the associated policy
// constants for this deployment.
//
// Why OPAQUE and not SRP or a plain salted hash:
//
//   - A salted hash (what we have today) is a verifier: given the stored
//     value, a guess can be checked locally. A database breach is therefore a
//     batch offline attack, exactly what happened to us in the prior incident.
//   - SRP (RFC 2945) is an augmented PAKE, so an *active* attacker cannot
//     mount an offline attack, but the server's stored verifier v = g^x is
//     itself a checkable value: anyone who steals it can test guesses locally.
//     SRP therefore does not meet the goal.
//   - OPAQUE (RFC 9807) is an aPAKE in which the server stores only a
//     "credential file" (client public key, masking key, envelope) that cannot
//     be tested against a password guess without the OPRF key. RFC 9807
//     Section 10.11 states this dependency explicitly. If the OPRF key lives
//     outside the database (see package kms), a database-only breach yields
//     nothing offline-checkable, and each guess costs an online round trip
//     against the rate limiter.
//
// Ciphersuite: Ristretto255 + SHA-512 for both the OPRF and the 3DH AKE, which
// is the pairing used by the RFC 9807 reference instantiation and by
// RFC 9497's ristretto255-SHA512 OPRF suite. Ristretto255 avoids the cofactor
// and non-canonical-encoding pitfalls of raw Curve25519 and has no invalid-
// curve attack surface such as NIST P-256's. Argon2id is the KSF (RFC 9106).
package suite

import (
	"crypto"
	"fmt"

	"github.com/bytemare/ksf"
	"github.com/bytemare/opaque"
)

// ID identifies this OPAQUE configuration. It is stored in the database
// metadata and must never change for an existing deployment: changing the
// ciphersuite, the context string, or the server identity invalidates every
// stored credential. Rolling a new suite requires a re-registration plan, not
// an in-place config edit.
const ID = "opaqueauth-opaque-v1-ristretto255-sha512"

// AADContext is the OPAQUE configuration Context. It is mixed into the AKE
// transcript, so a credential registered with one deployment cannot be
// replayed against another deployment that happens to share key material.
const AADContext = "opaqueauth/v1/opaque-context"

// ServerIdentity is the fixed server identity bound into every envelope and
// every login transcript. Clients must use exactly this value. Rotating it
// invalidates envelopes, so it is a permanent identifier, not a hostname.
const ServerIdentity = "opaqueauth/v1/server"

// Configuration returns the pinned OPAQUE configuration.
func Configuration() *opaque.Configuration {
	return &opaque.Configuration{
		OPRF:    opaque.RistrettoSha512,
		AKE:     opaque.RistrettoSha512,
		KSF:     ksf.Argon2id,
		KDF:     crypto.SHA512,
		MAC:     crypto.SHA512,
		Hash:    crypto.SHA512,
		Context: []byte(AADContext),
	}
}

// KSFProfile describes the client-side Argon2id parameters. The value is
// recorded per credential so that (a) clients know which parameters to use at
// login, and (b) an operator can detect credentials registered with a
// downgraded profile. The server cannot cryptographically verify the KSF
// because, by construction, only the client runs it (RFC 9807 Section 10.8);
// this field is an audited declaration, not a proof.
type KSFProfile struct {
	ID      string
	Time    uint64
	Memory  uint64 // KiB
	Threads uint64
	Length  int
}

// ProfileV1 is the current profile: RFC 9106's SECOND RECOMMENDED option
// (t=3, m=64 MiB, p=4). The FIRST RECOMMENDED option (2 GiB) is deliberately
// not used: it would allocate 2 GiB on every client device including phones,
// and OPAQUE's security margin against a database-only breach does not depend
// on the KSF at all, because the OPRF key is not in the database. The KSF is
// the second layer that matters only if the OPRF key also leaks.
var ProfileV1 = KSFProfile{
	ID:      "argon2id-rfc9106-second-64MiB",
	Time:    3,
	Memory:  64 * 1024,
	Threads: 4,
	Length:  64, // SHA-512 output size; the library expands to this length
}

// Profiles maps profile IDs to their parameters. It contains only profiles this
// build is willing to accept. A test build may add its own via RegisterProfile
// before any Service is constructed; the production binary does not.
var Profiles = map[string]KSFProfile{
	ProfileV1.ID: ProfileV1,
}

// RegisterProfile adds a profile to the accepted set. It is intended for test
// harnesses that cannot afford 64 MiB and 3 passes per login. Production code
// must not call it.
func RegisterProfile(p KSFProfile) {
	Profiles[p.ID] = p
}

// ProfileByName resolves a profile ID, rejecting unknown/downgraded values.
func ProfileByName(id string) (KSFProfile, error) {
	p, ok := Profiles[id]
	if !ok {
		return KSFProfile{}, fmt.Errorf("suite: unknown KSF profile %q", id)
	}
	return p, nil
}

// Params returns the Argon2id parameter slice the client must pass to
// opaque.ClientOptions.KSFParameters.
func (p KSFProfile) Params() []uint64 { return []uint64{p.Time, p.Memory, p.Threads} }

// LegacyDecoyCost is the bcrypt cost advertised for accounts that have no
// legacy verifier. It is the modal cost of the pre-migration database, so a
// decoy login is indistinguishable from a real one by cost alone. The value
// is part of the migration compatibility contract: it must match the legacy
// dump, and changing it would itself become an enumeration signal.
const LegacyDecoyCost = 12

// LegacyMaxCost bounds the bcrypt cost accepted from the legacy database. A
// hostile or corrupted import cannot make clients burn unbounded CPU, and it
// cannot claim a cost so low that it undercuts the decoy.
const LegacyMaxCost = 14

// LegacyMinCost bounds it from below.
const LegacyMinCost = 10
