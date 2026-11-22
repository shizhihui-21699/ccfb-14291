// Package keys derives every application subkey from one root secret held in
// the KMS, so that a database dump alone contains no key material at all.
//
// Every subkey is derived with a distinct domain-separation label; none can be
// recovered from another. The root itself is never written to the database.
package keys

import (
	"errors"
	"fmt"

	"opaqueauth/internal/kms"
	"opaqueauth/internal/secure"
)

// Keys is the set of application subkeys.
type Keys struct {
	// AccountPepper keys the account index (ident.AccountKey) and the OPAQUE
	// credential identifier (ident.CredentialID).
	AccountPepper []byte
	// RecordMAC keys the integrity MAC over each stored OPAQUE credential.
	RecordMAC []byte
	// SessionToken keys the HMAC under which app session tokens are stored.
	SessionToken []byte
	// LoginState keys the HMAC under which in-flight login state is stored.
	LoginState []byte
	// RecoveryToken keys the HMAC under which recovery tokens/codes are stored.
	RecoveryToken []byte
	// ProofOfWork keys stateless PoW challenges.
	ProofOfWork []byte
	// Audit keys the tamper-evident audit-log chain.
	Audit []byte
	// LegacyVerifier seals the transitional bcrypt digests in the database, so
	// that a database dump during the migration window does not hand an
	// attacker a testable verifier. The bcrypt salt and cost are not secret and
	// stay in the clear; only the 23-byte digest is sealed.
	LegacyVerifier []byte

	// OPAQUEServerKeyMaterial is the encoded OPAQUE ServerKeyMaterial.
	OPAQUEServerKeyMaterial []byte
}

// Load reads the root secret from the KMS and derives all subkeys.
func Load(p kms.Provider) (*Keys, error) {
	root, err := p.Get(kms.AppRoot)
	if err != nil {
		return nil, fmt.Errorf("keys: load app root: %w", err)
	}
	defer secure.Zero(root)
	if len(root) != 32 {
		return nil, fmt.Errorf("keys: app root must be 32 bytes, got %d", len(root))
	}
	skm, err := p.Get(kms.OPAQUEServerKeyMaterial)
	if err != nil {
		return nil, fmt.Errorf("keys: load OPAQUE server key material: %w", err)
	}
	k := &Keys{
		AccountPepper:           secure.Label(root, "account-index-pepper"),
		RecordMAC:               secure.Label(root, "credential-record-mac"),
		SessionToken:            secure.Label(root, "session-token"),
		LoginState:              secure.Label(root, "login-state"),
		RecoveryToken:           secure.Label(root, "recovery-token"),
		ProofOfWork:             secure.Label(root, "proof-of-work"),
		Audit:                   secure.Label(root, "audit-chain"),
		LegacyVerifier:          secure.Label(root, "legacy-verifier"),
		OPAQUEServerKeyMaterial: skm,
	}
	for name, sub := range map[string][]byte{
		"account-index-pepper":  k.AccountPepper,
		"credential-record-mac": k.RecordMAC,
		"session-token":         k.SessionToken,
		"login-state":           k.LoginState,
		"recovery-token":        k.RecoveryToken,
		"proof-of-work":         k.ProofOfWork,
		"audit-chain":           k.Audit,
		"legacy-verifier":       k.LegacyVerifier,
	} {
		if len(sub) != 32 {
			return nil, errors.New("keys: derived subkey " + name + " is not 32 bytes")
		}
	}
	return k, nil
}

// GenerateRoot returns fresh root key material for provisioning.
func GenerateRoot() []byte { return secure.Random(32) }
