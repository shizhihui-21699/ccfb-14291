package auth

import (
	"encoding/json"
	"errors"

	"github.com/bytemare/opaque/message"

	"opaqueauth/internal/keyring"
	"opaqueauth/internal/secure"
	"opaqueauth/internal/store"
	"opaqueauth/internal/suite"
)

// AAD labels version the sealed formats. Changing one invalidates every
// in-flight value, which is the intended upgrade path.

func (s *Service) ceremonyAAD(id []byte, kind string) []byte {
	return append(append([]byte("ceremony/v1\x00"), []byte(kind)...), append([]byte{0}, id...)...)
}

func (s *Service) loginAAD(id []byte) []byte {
	return append([]byte("login-state/v2\x00"), id...)
}

func (s *Service) sealCeremony(id []byte, kind string, idn identity, blob []byte) ([]byte, error) {
	pt := make([]byte, 0, len(idn.canonical)+len(idn.credID)+len(blob)+16)
	pt = put32(pt, uint32(len(idn.canonical)))
	pt = append(pt, idn.canonical...)
	pt = put32(pt, uint32(len(idn.credID)))
	pt = append(pt, idn.credID...)
	pt = put32(pt, uint32(len(blob)))
	pt = append(pt, blob...)
	sealed, err := secure.Seal(s.keys.LoginState, s.ceremonyAAD(id, kind), pt)
	if err != nil {
		return nil, err
	}
	return joinSealed(sealed), nil
}

func (s *Service) openCeremony(id []byte, kind string, c *store.Ceremony) (identity, []byte, error) {
	sealed, err := splitSealed(c.Payload)
	if err != nil {
		return identity{}, nil, err
	}
	pt, err := secure.Open(s.keys.LoginState, s.ceremonyAAD(id, kind), sealed)
	if err != nil {
		return identity{}, nil, ErrExpired
	}
	canonical, rest, ok := take32(pt)
	if !ok {
		return identity{}, nil, ErrBadRequest
	}
	credID, rest, ok := take32(rest)
	if !ok {
		return identity{}, nil, ErrBadRequest
	}
	blob, _, ok := take32(rest)
	if !ok {
		return identity{}, nil, ErrBadRequest
	}
	return identity{canonical: canonical, credID: credID, account: c.AccountKey}, blob, nil
}

// loginStateWire is the serialized login state.
type loginStateWire struct {
	AccountKey      []byte `json:"a"`
	CredentialID    []byte `json:"c"`
	ClientID        []byte `json:"i"`
	ServerOutput    []byte `json:"m"`
	KSF             string `json:"k"`
	KSFSalt         []byte `json:"ks"`
	LegacySalt      []byte `json:"ls"`
	LegacyCost      int    `json:"lc"`
	LegacyChallenge []byte `json:"lch"`
	LegacyDigestEnc []byte `json:"ld"`
	IsLegacy        bool   `json:"il"`
	RegResponse     []byte `json:"rr"`
}

func (s *Service) sealLoginState(id []byte, st *loginStatePayload) ([]byte, error) {
	pt, err := json.Marshal(loginStateWire{
		AccountKey: st.AccountKey, CredentialID: st.CredentialID, ClientID: st.ClientID,
		ServerOutput: st.ServerOutput,
		KSF:          st.KSF, KSFSalt: st.KSFSalt,
		LegacySalt: st.LegacySalt, LegacyCost: st.LegacyCost,
		LegacyChallenge: st.LegacyChallenge, LegacyDigestEnc: st.LegacyDigestEnc,
		IsLegacy: st.IsLegacy, RegResponse: st.RegResponse,
	})
	if err != nil {
		return nil, err
	}
	defer secure.Zero(pt)
	sealed, err := secure.Seal(s.keys.LoginState, s.loginAAD(id), pt)
	if err != nil {
		return nil, err
	}
	return joinSealed(sealed), nil
}

func (s *Service) openLoginState(id []byte, l *store.LoginState) (*loginStatePayload, error) {
	sealed, err := splitSealed(l.Payload)
	if err != nil {
		return nil, err
	}
	pt, err := secure.Open(s.keys.LoginState, s.loginAAD(id), sealed)
	if err != nil {
		return nil, ErrExpired
	}
	defer secure.Zero(pt)
	var w loginStateWire
	if err := json.Unmarshal(pt, &w); err != nil {
		return nil, errors.New("auth: malformed login state")
	}
	return &loginStatePayload{
		AccountKey: w.AccountKey, CredentialID: w.CredentialID, ClientID: w.ClientID,
		ServerOutput: w.ServerOutput,
		KSF:          w.KSF, KSFSalt: w.KSFSalt,
		LegacySalt: w.LegacySalt, LegacyCost: w.LegacyCost,
		LegacyChallenge: w.LegacyChallenge, LegacyDigestEnc: w.LegacyDigestEnc,
		IsLegacy: w.IsLegacy, RegResponse: w.RegResponse,
	}, nil
}

// contactAAD binds a sealed contact to its account.
func contactAAD(accountKey []byte) []byte {
	return append([]byte("contact/v1\x00"), accountKey...)
}

// sealContact encrypts a recovery address for storage, under the versioned
// keyring so that a key rotation does not lose recovery addresses.
func (s *Service) sealContact(accountKey []byte, contact string) []byte {
	sealed, err := s.legacyRing.Seal(contactAAD(accountKey), []byte(contact))
	if err != nil {
		return nil
	}
	return sealed
}

// SetRecoveryContact stores an encrypted recovery address for an account.
func (s *Service) SetRecoveryContact(accountKey []byte, contact string) error {
	if contact == "" {
		return nil
	}
	return s.store.PutContact(accountKey, s.sealContact(accountKey, contact))
}

// OpenContact decrypts a stored contact. Used by the recovery mailer only.
func (s *Service) OpenContact(accountKey []byte) (string, bool) {
	raw, err := s.store.GetContact(accountKey)
	if err != nil {
		return "", false
	}
	pt, err := s.legacyRing.Open(contactAAD(accountKey), raw)
	if err != nil {
		return "", false
	}
	return string(pt), true
}

// LegacyDigestAAD binds a sealed digest to its account.
func LegacyDigestAAD(accountKey []byte) []byte {
	return append([]byte("legacy-digest/v1\x00"), accountKey...)
}

// SealLegacyDigest encrypts a bcrypt digest for the transitional table. This
// makes the migration window safe — even before a user logs in, their old
// verifier is not directly readable from a database dump — and it is
// version-tagged so that rotating the key does not orphan un-migrated users.
func SealLegacyDigest(ring *keyring.Ring, accountKey, digest []byte) ([]byte, error) {
	return ring.Seal(LegacyDigestAAD(accountKey), digest)
}

// OpenLegacyDigest is the inverse of SealLegacyDigest.
func OpenLegacyDigest(ring *keyring.Ring, accountKey, enc []byte) ([]byte, error) {
	return ring.Open(LegacyDigestAAD(accountKey), enc)
}

// regRespBlob serializes a RegistrationResponse for storage in a ceremony.
func regRespBlob(r *message.RegistrationResponse) []byte {
	if r == nil {
		return nil
	}
	return r.Serialize()
}

func put32(dst []byte, v uint32) []byte {
	return append(dst, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func take32(b []byte) (field, rest []byte, ok bool) {
	if len(b) < 4 {
		return nil, nil, false
	}
	n := int(b[0])<<24 | int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	if n < 0 || len(b) < 4+n {
		return nil, nil, false
	}
	return b[4 : 4+n], b[4+n:], true
}

func splitSealed(b []byte) (secure.Sealed, error) {
	nonce, rest, ok := take32(b)
	if !ok || len(nonce) == 0 {
		return secure.Sealed{}, ErrBadRequest
	}
	return secure.Sealed{Nonce: nonce, CT: rest}, nil
}

func joinSealed(s secure.Sealed) []byte {
	out := put32(nil, uint32(len(s.Nonce)))
	out = append(out, s.Nonce...)
	return append(out, s.CT...)
}

// legacyCostInRange validates an imported bcrypt cost.
func legacyCostInRange(cost int) bool {
	return cost >= suite.LegacyMinCost && cost <= suite.LegacyMaxCost
}
