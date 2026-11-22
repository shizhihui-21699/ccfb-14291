// Package auth implements the authentication service: OPAQUE registration and
// login, transparent migration from the legacy bcrypt database, password
// change, and account recovery.
//
// Security invariants this package maintains (each is tested):
//
//	I1. The server never receives, derives, or stores a plaintext password, at
//	    registration, login, change, recovery, or migration.
//	I2. A database row cannot be used to test a password guess without the
//	    KMS-resident OPRF key and legacy-verifier key. This holds for migrated
//	    accounts (OPAQUE) *and* for not-yet-migrated accounts (whose bcrypt
//	    digest is sealed). Tested by the database-leak simulation.
//	I3. Login responses are indistinguishable for unknown users, known users
//	    with a wrong password, disabled accounts, and not-yet-migrated
//	    accounts: same fields, same lengths, same status codes.
//	I4. Every one-shot ceremony, login state, recovery token, and session is
//	    single-use and atomically consumed.
//	I5. A failed attempt never makes an account unreachable: there is no lock
//	    state, only rate/price escalation with trusted-device and
//	    proof-of-work escape hatches.
package auth

import (
	"errors"
	"fmt"
	"time"

	"github.com/bytemare/opaque"
	"github.com/bytemare/opaque/message"

	"opaqueauth/internal/ident"
	"opaqueauth/internal/keyring"
	"opaqueauth/internal/keys"
	"opaqueauth/internal/kms"
	"opaqueauth/internal/locks"
	"opaqueauth/internal/pow"
	"opaqueauth/internal/ratelimit"
	"opaqueauth/internal/secure"
	"opaqueauth/internal/store"
	"opaqueauth/internal/suite"
	"opaqueauth/internal/wire"
)

// Internal error classes. The API layer maps every one of them to the same
// coarse public response; they are distinct only for tests and audit.
var (
	ErrBadRequest      = errors.New("auth: bad request")
	ErrUnauthenticated = errors.New("auth: authentication failed")
	ErrRateLimited     = errors.New("auth: rate limited")
	ErrConflict        = errors.New("auth: already exists")
	ErrNotAllowed      = errors.New("auth: not allowed")
	ErrExpired         = errors.New("auth: expired")
)

// Config configures a Service.
type Config struct {
	Store   *store.Store
	KMS     kms.Provider
	Limiter *ratelimit.Limiter
	Pow     *pow.Challenger
	Now     func() time.Time

	LoginStateTTL    time.Duration
	CeremonyTTL      time.Duration
	SessionTTL       time.Duration
	SessionIdleTTL   time.Duration
	RecoveryTTL      time.Duration
	TrustedDeviceTTL time.Duration

	RequireInvite  bool
	InviteVerifier func(code string) bool

	// KSF is the Argon2id profile this deployment advertises and accepts. Zero
	// value means suite.ProfileV1. It is advisory on the client side (the
	// server cannot verify the stretch ran, RFC 9807 §10.8), but pinning it
	// prevents a client from claiming a cheaper profile than policy allows.
	KSF suite.KSFProfile

	// LegacyRing wraps the transitional bcrypt digests. Optional: without it a
	// fresh keyring is built from Keys.LegacyVerifier at version 1, which is
	// what the tests and single-key deployments use.
	LegacyRing *keyring.Ring
}

// Service is the authentication service.
type Service struct {
	cfg        Config
	store      *store.Store
	keys       *keys.Keys
	conf       *opaque.Configuration
	server     *opaque.Server
	lock       *locks.Stripes
	now        func() time.Time
	legacyRing *keyring.Ring
}

// New constructs a Service and loads OPAQUE server key material.
func New(cfg Config) (*Service, error) {
	if cfg.Store == nil || cfg.KMS == nil || cfg.Limiter == nil || cfg.Pow == nil {
		return nil, errors.New("auth: incomplete configuration")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.LoginStateTTL <= 0 {
		cfg.LoginStateTTL = 2 * time.Minute
	}
	if cfg.CeremonyTTL <= 0 {
		cfg.CeremonyTTL = 10 * time.Minute
	}
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = 12 * time.Hour
	}
	if cfg.SessionIdleTTL <= 0 {
		cfg.SessionIdleTTL = 30 * time.Minute
	}
	if cfg.RecoveryTTL <= 0 {
		cfg.RecoveryTTL = 30 * time.Minute
	}
	if cfg.TrustedDeviceTTL <= 0 {
		cfg.TrustedDeviceTTL = 30 * 24 * time.Hour
	}
	if cfg.KSF.ID == "" {
		cfg.KSF = suite.ProfileV1
	} else if _, err := suite.ProfileByName(cfg.KSF.ID); err != nil {
		return nil, fmt.Errorf("auth: %w", err)
	}
	k, err := keys.Load(cfg.KMS)
	if err != nil {
		return nil, err
	}
	if cfg.LegacyRing == nil {
		cfg.LegacyRing, err = keyring.New(1, k.LegacyVerifier, nil)
		if err != nil {
			return nil, err
		}
	}
	conf := suite.Configuration()
	skm, err := conf.DecodeServerKeyMaterial(k.OPAQUEServerKeyMaterial)
	if err != nil {
		return nil, fmt.Errorf("auth: decode OPAQUE server key material: %w", err)
	}
	if string(skm.Identity) != suite.ServerIdentity {
		return nil, fmt.Errorf("auth: server key material identity %q does not match pinned %q", skm.Identity, suite.ServerIdentity)
	}
	server, err := conf.Server()
	if err != nil {
		return nil, err
	}
	if err := server.SetKeyMaterial(skm); err != nil {
		return nil, fmt.Errorf("auth: set OPAQUE key material: %w", err)
	}
	return &Service{
		cfg: cfg, store: cfg.Store, keys: k, conf: conf, server: server,
		lock: locks.New(512), now: cfg.Now, legacyRing: cfg.LegacyRing,
	}, nil
}

// Action rates bound state-amplifying endpoints that are not password checks:
// starting registrations, sending recovery mail, issuing challenges. They are
// charged on admission because the cost (a stored row, an e-mail) is incurred
// whether or not the caller later succeeds.
var (
	registerRate = ratelimit.Rate{PerSecond: 0.02, Burst: 10} // 10 burst, ~1/50s
	recoverRate  = ratelimit.Rate{PerSecond: 0.01, Burst: 5}  // 5 burst, ~1/100s
)

// ClientConfig is the non-secret configuration a client needs.
type ClientConfig struct {
	Suite          string
	ServerIdentity []byte
	Context        []byte
	KSF            suite.KSFProfile
	ProofBits      int
}

// ClientConfig returns the non-secret client parameters.
func (s *Service) ClientConfig() ClientConfig {
	return ClientConfig{
		Suite: suite.ID, ServerIdentity: []byte(suite.ServerIdentity),
		Context: []byte(suite.AADContext), KSF: s.cfg.KSF,
		ProofBits: s.cfg.Pow.Bits(),
	}
}

// identity is the set of per-identifier derived values.
type identity struct {
	canonical []byte
	account   []byte
	credID    []byte
	clientID  []byte
	ksfSalt   []byte
}

func (s *Service) resolve(raw string) (identity, error) {
	canonical, err := ident.Canonicalize(raw)
	if err != nil {
		return identity{}, fmt.Errorf("%w: %s", ErrBadRequest, err)
	}
	account := ident.AccountKey(s.keys.AccountPepper, canonical)
	return identity{
		canonical: canonical,
		account:   account,
		// All OPAQUE-side identifiers are derived from the account key with
		// distinct labels. Registration, login, change, and recovery all go
		// through this one function, so they cannot drift apart.
		credID:   s.credentialIDFor(account),
		clientID: s.clientIdentityFor(account),
		// The KSF salt is public and deterministic per account. It does not
		// need to be secret (the OPRF output is already unique per user); it
		// only has to be identical on every client and every login.
		ksfSalt: s.ksfSaltFor(account),
	}, nil
}

func (s *Service) credentialIDFor(accountKey []byte) []byte {
	return ident.CredentialID(s.keys.AccountPepper, accountKey)
}

// clientIdentityFor is unused for the AKE (the client public key is the
// identity) but is retained for sealed state and future use.
func (s *Service) clientIdentityFor(accountKey []byte) []byte {
	return secure.HMAC(s.keys.AccountPepper, []byte("client-identity/v1\x00"), accountKey)
}

func (s *Service) ksfSaltFor(accountKey []byte) []byte {
	return secure.HMAC(s.keys.AccountPepper, []byte("ksf-salt/v1\x00"), accountKey)[:16]
}

// recordMAC binds a stored credential to its account, suite, profile, and salt.
//
// Threat: an attacker who can write to the database (SQL injection, a
// compromised backup, a malicious operator) could otherwise replace a victim's
// envelope with one derived from an attacker-chosen password and then log in
// as the victim. The MAC key lives in the KMS, so a database-only writer
// cannot forge it.
func (s *Service) recordMAC(c *store.Credential) []byte {
	return secure.HMAC(s.keys.RecordMAC,
		[]byte("credential-record/v1\x00"),
		c.AccountKey, []byte{0}, []byte(c.SuiteID), []byte{0},
		[]byte(c.KSFProfile), []byte{0}, c.KSFSalt, []byte{0},
		c.ClientPublicKey, []byte{0}, c.MaskingKey, []byte{0}, c.Envelope,
	)
}

func (s *Service) verifyRecordMAC(c *store.Credential) bool {
	return secure.Equal(c.RecordMAC, s.recordMAC(c))
}

// clientRecord converts a stored credential into the opaque.ClientRecord used
// by the server, after verifying the integrity MAC.
func (s *Service) clientRecord(c *store.Credential) (*opaque.ClientRecord, error) {
	if !s.verifyRecordMAC(c) {
		return nil, fmt.Errorf("auth: credential record MAC mismatch")
	}
	raw := append(append(append([]byte(nil), c.ClientPublicKey...), c.MaskingKey...), c.Envelope...)
	rec, err := s.deser().RegistrationRecord(raw)
	if err != nil {
		return nil, fmt.Errorf("auth: corrupt credential record: %w", err)
	}
	// ClientIdentity is left nil so that both sides bind the client's public
	// key as the AKE identity and the envelope, which was created with a nil
	// client identity, verifies. Binding a derived value here instead would
	// silently break envelope recovery.
	return &opaque.ClientRecord{
		RegistrationRecord:   rec,
		CredentialIdentifier: s.credentialIDFor(c.AccountKey),
		ClientIdentity:       nil,
	}, nil
}

// fakeRecord builds a decoy ClientRecord for an account key. It is used for
// unknown users, disabled accounts, and not-yet-migrated accounts, so that all
// three produce a KE2 of exactly the same shape as a real user.
func (s *Service) fakeRecord(accountKey []byte) (*opaque.ClientRecord, error) {
	return s.conf.GetFakeRecord(ident.FakeCredentialID(s.keys.AccountPepper, accountKey))
}

// profile resolves a client-declared KSF profile, requiring it to be the one
// this deployment advertises. A mismatch is a client error, not a downgrade
// the server silently accepts.
func (s *Service) profile(id string) (suite.KSFProfile, error) {
	p, err := suite.ProfileByName(id)
	if err != nil {
		return suite.KSFProfile{}, fmt.Errorf("%w: %s", ErrBadRequest, err)
	}
	if p.ID != s.cfg.KSF.ID {
		return suite.KSFProfile{}, fmt.Errorf("%w: KSF profile %q not permitted", ErrBadRequest, id)
	}
	return p, nil
}

// deser returns the deserializer for the pinned configuration.
func (s *Service) deser() *opaque.Deserializer { return s.server.Deserialize }

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

// RegisterBegin handles the first registration message.
func (s *Service) RegisterBegin(rawIdent string, regReq *message.RegistrationRequest, inviteCode, source string) (ceremonyID []byte, resp *message.RegistrationResponse, ksfSalt []byte, err error) {
	id, err := s.resolve(rawIdent)
	if err != nil {
		return nil, nil, nil, err
	}
	// Registration is unauthenticated; bound it per source so an attacker
	// cannot fill the ceremony table or use the endpoint as a bulk oracle.
	if ok, retry := s.cfg.Limiter.AdmitKey("register:"+source, registerRate); !ok {
		return nil, nil, nil, fmt.Errorf("%w: retry after %s", ErrRateLimited, retry)
	}
	if s.cfg.RequireInvite {
		if inviteCode == "" || (s.cfg.InviteVerifier != nil && !s.cfg.InviteVerifier(inviteCode)) {
			return nil, nil, nil, fmt.Errorf("%w: invite required", ErrNotAllowed)
		}
	}
	// Registration is necessarily an existence oracle: a taken name must be
	// refused, and RFC 9807 §10.9 says so. We mitigate with invitation and
	// rate limiting at the API layer rather than by lying here (lying would
	// produce two accounts for one identifier).
	unlock := s.lock.Lock(id.account)
	defer unlock()
	if _, err := s.store.GetAccount(id.account); err == nil {
		return nil, nil, nil, fmt.Errorf("%w: identifier already registered", ErrConflict)
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, nil, nil, err
	}
	if _, err := s.store.GetLegacy(id.account); err == nil {
		return nil, nil, nil, fmt.Errorf("%w: identifier already registered", ErrConflict)
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, nil, nil, err
	}
	resp, err = s.server.RegistrationResponse(regReq, id.credID, nil)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%w: %s", ErrBadRequest, err)
	}
	ceremonyID = secure.Random(24)
	payload, err := s.sealCeremony(ceremonyID, store.CeremonyRegister, id, regRespBlob(resp))
	if err != nil {
		return nil, nil, nil, err
	}
	if err := s.store.CreateCeremony(&store.Ceremony{
		ID: ceremonyID, Kind: store.CeremonyRegister, AccountKey: id.account,
		Payload: payload, ExpiresAt: s.now().Add(s.cfg.CeremonyTTL),
	}); err != nil {
		return nil, nil, nil, err
	}
	return ceremonyID, resp, id.ksfSalt, nil
}

// RegisterFinish handles the last registration message and creates the account.
func (s *Service) RegisterFinish(ceremonyID []byte, record *message.RegistrationRecord, ksfID, contact, deviceLabel string) (*Session, error) {
	profile, err := s.profile(ksfID)
	if err != nil {
		return nil, err
	}
	if err := s.store.ConsumeCeremony(ceremonyID, store.CeremonyRegister); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrExpired
		}
		return nil, err
	}
	cer, err := s.store.GetCeremony(ceremonyID)
	if err != nil {
		return nil, err
	}
	id, _, err := s.openCeremony(ceremonyID, store.CeremonyRegister, cer)
	if err != nil {
		return nil, err
	}

	unlock := s.lock.Lock(id.account)
	defer unlock()

	cred, err := s.newCredential(id.account, profile, record)
	if err != nil {
		return nil, err
	}
	if err := s.store.RegisterNew(id.account, id.credID, ident.Version, suite.ID, cred); err != nil {
		if errors.Is(err, store.ErrAlreadyExists) {
			return nil, fmt.Errorf("%w: identifier already registered", ErrConflict)
		}
		return nil, err
	}
	if contact != "" {
		if err := s.SetRecoveryContact(id.account, contact); err != nil {
			return nil, err
		}
	}
	sess, err := s.issueSession(id.account, deviceLabel)
	if err != nil {
		return nil, err
	}
	s.audit("register", id.account)
	return sess, nil
}

// newCredential assembles a storable credential from a client RegistrationRecord.
func (s *Service) newCredential(accountKey []byte, profile suite.KSFProfile, record *message.RegistrationRecord) (*store.Credential, error) {
	if record == nil || record.ClientPublicKey == nil {
		return nil, fmt.Errorf("%w: empty registration record", ErrBadRequest)
	}
	c := &store.Credential{
		AccountKey:      accountKey,
		SuiteID:         suite.ID,
		KSFProfile:      profile.ID,
		KSFSalt:         s.ksfSaltFor(accountKey),
		ClientPublicKey: record.ClientPublicKey.Encode(),
		MaskingKey:      append([]byte(nil), record.MaskingKey...),
		Envelope:        append([]byte(nil), record.Envelope...),
	}
	// Round-trip through the protocol deserializer to reject malformed points
	// or wrong-length fields before storing them.
	raw := append(append(append([]byte(nil), c.ClientPublicKey...), c.MaskingKey...), c.Envelope...)
	if _, err := s.deser().RegistrationRecord(raw); err != nil {
		return nil, fmt.Errorf("%w: malformed registration record: %s", ErrBadRequest, err)
	}
	c.RecordMAC = s.recordMAC(c)
	return c, nil
}

// ---------------------------------------------------------------------------
// Login
// ---------------------------------------------------------------------------

// loginStatePayload is sealed into the login_states row between the two
// login round trips.
type loginStatePayload struct {
	AccountKey   []byte
	CredentialID []byte
	ClientID     []byte
	ServerOutput []byte // expected client MAC
	// The OPAQUE session secret is intentionally not carried across the
	// exchange: it is never used. Session identity is our own bearer token,
	// and keeping the secret out of the sealed state reduces what a stolen
	// state row would yield.
	KSF     string
	KSFSalt []byte

	// Migration material. Present for every login (decoy values for
	// non-legacy accounts) so the response shape never reveals whether an
	// account has a legacy verifier.
	LegacySalt      []byte
	LegacyCost      int
	LegacyChallenge []byte
	LegacyDigestEnc []byte // only for real legacy accounts; sealed under KMS key
	IsLegacy        bool

	// RegistrationResponse for the client's fresh registration request. For a
	// legacy account this is the response the client uses to build the record
	// that replaces the bcrypt verifier. For everyone else it is unused.
	RegResponse []byte
}

// LoginStartResult is the internal result of LoginBegin.
type LoginStartResult struct {
	Challenge       *wire.Challenge
	KE2             *message.KE2
	StateID         []byte
	KSF             string
	KSFSalt         []byte
	LegacySalt      []byte
	LegacyCost      int
	LegacyChallenge []byte
	RegResponse     []byte
	RateLimited     bool
	RetryAfter      time.Duration
}

// LoginBegin handles KE1.
//
// regReq is optional but the reference client always sends one: the server
// then includes a RegistrationResponse in the sealed state, which is what makes
// migration possible without a second unauthenticated lookup and without
// revealing which accounts are still on the old scheme.
//
// deviceToken, when it names a live trusted device for this account, exempts
// the request from the per-account throttle (but not from per-source limits).
func (s *Service) LoginBegin(rawIdent string, ke1 *message.KE1, regReq *message.RegistrationRequest, source, deviceToken string, proof *wire.Proof) (*LoginStartResult, error) {
	id, err := s.resolve(rawIdent)
	if err != nil {
		return nil, err
	}
	// A request is exempt from the per-account throttle if it presents a live
	// trusted device, or a valid proof-of-work solution. A malformed or
	// invalid proof is simply not evidence: it cannot turn a denial into an
	// admission, and it does not reveal whether the account exists.
	trusted := s.IsTrustedDevice(id.account, deviceToken)
	if !trusted && proof != nil {
		if s.cfg.Pow.Verify(proof.Challenge, proof.Nonce) == nil {
			trusted = true
		}
	}
	dec := s.cfg.Limiter.Admit(string(id.account), source, trusted)
	if !dec.Allow {
		// Tell the client how to get through: it must solve a challenge. This
		// is safe to reveal because it is identical for every identifier.
		ch := s.cfg.Pow.Issue()
		return &LoginStartResult{
			RateLimited: true, RetryAfter: dec.RetryAfter,
			Challenge: &wire.Challenge{Token: ch, Bits: s.cfg.Pow.Bits()},
		}, nil
	}

	acct, aerr := s.store.GetAccount(id.account)
	known := aerr == nil
	if aerr != nil && !errors.Is(aerr, store.ErrNotFound) {
		return nil, aerr
	}
	// The stored credential identifier is redundant (always derivable from the
	// account key). A mismatch means the row was written by a different
	// derivation and cannot be authenticated; treat it as unknown rather than
	// serving an unusable record.
	if known && !secure.Equal(acct.CredentialID, id.credID) {
		known = false
	}

	// Decide which record to hand the OPAQUE server. Every branch produces a
	// record of identical length.
	var (
		record    *opaque.ClientRecord
		legacy    *store.Legacy
		ksfID     = s.cfg.KSF.ID
		digestEnc []byte
	)
	active := known && acct.Status == "active"
	if active {
		if cred, err := s.store.GetCredential(id.account); err == nil {
			if rec, err := s.clientRecord(cred); err == nil {
				record = rec
				ksfID = cred.KSFProfile
			}
		} else if !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
		// A legacy row and an OPAQUE credential are mutually exclusive by
		// InstallCredential's transaction; check legacy only when there is no
		// usable credential.
		if record == nil {
			if l, err := s.store.GetLegacy(id.account); err == nil {
				legacy = l
				digestEnc = l.Hash
			} else if !errors.Is(err, store.ErrNotFound) {
				return nil, err
			}
		}
	}
	if record == nil {
		fake, err := s.fakeRecord(id.account)
		if err != nil {
			return nil, err
		}
		record = fake
	}

	ke2, out, err := s.server.GenerateKE2(ke1, record)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrBadRequest, err)
	}

	// Migration material is always present, real or decoy.
	legacySalt := secure.HMAC(s.keys.LegacyVerifier, []byte("decoy-salt/v1\x00"), id.account)[:16]
	legacyCost := suite.LegacyDecoyCost
	if legacy != nil {
		legacySalt = append([]byte(nil), legacy.Salt...)
		legacyCost = legacy.Cost
	}

	st := &loginStatePayload{
		AccountKey: id.account, CredentialID: id.credID, ClientID: id.clientID,
		ServerOutput: out.ClientMAC,
		KSF:          ksfID, KSFSalt: id.ksfSalt,
		LegacySalt: legacySalt, LegacyCost: legacyCost,
		LegacyChallenge: secure.Random(32),
		LegacyDigestEnc: digestEnc,
		IsLegacy:        legacy != nil,
	}
	if regReq != nil {
		regResp, err := s.server.RegistrationResponse(regReq, id.credID, nil)
		if err != nil {
			return nil, fmt.Errorf("%w: %s", ErrBadRequest, err)
		}
		st.RegResponse = regResp.Serialize()
	}

	stateID := secure.Random(24)
	sealed, err := s.sealLoginState(stateID, st)
	if err != nil {
		return nil, err
	}
	if err := s.store.CreateLoginState(&store.LoginState{
		ID: stateID, AccountKey: id.account, Payload: sealed,
		ExpiresAt: s.now().Add(s.cfg.LoginStateTTL),
	}); err != nil {
		return nil, err
	}
	return &LoginStartResult{
		KE2: ke2, StateID: stateID, KSF: ksfID, KSFSalt: id.ksfSalt,
		LegacySalt: st.LegacySalt, LegacyCost: st.LegacyCost,
		LegacyChallenge: st.LegacyChallenge, RegResponse: st.RegResponse,
	}, nil
}

// LoginFinishInput is the internal finish request.
type LoginFinishInput struct {
	StateID     []byte
	KE3         *message.KE3
	Migration   *MigrationProof
	DeviceLabel string
	Source      string
}

// MigrationProof carries the client's legacy-password proof and its new
// OPAQUE registration record.
type MigrationProof struct {
	// Proof = HMAC-SHA256(challenge, bcrypt digest), computed client-side from
	// the password and the published salt/cost. The digest is never sent.
	Proof []byte
	// Registration is the OPAQUE RegistrationRecord built from the
	// RegistrationResponse the server returned in the same start response.
	Registration *message.RegistrationRecord
	KSF          string
}

// LoginFinish completes an exchange. It returns a session on either a normal
// OPAQUE success or a verified legacy migration.
func (s *Service) LoginFinish(in LoginFinishInput) (*Session, error) {
	state, err := s.store.ConsumeLoginState(in.StateID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrExpired
		}
		return nil, err
	}
	st, err := s.openLoginState(in.StateID, state)
	if err != nil {
		return nil, err
	}

	// Path A: OPAQUE login completes. This cannot succeed for a legacy-only
	// account, because the record was a decoy; that is by design.
	if in.KE3 != nil && s.server.LoginFinish(in.KE3, st.ServerOutput) == nil {
		return s.finishActive(st, in.DeviceLabel)
	}

	// Path B: legacy migration proof.
	if st.IsLegacy && in.Migration != nil {
		if err := s.verifyLegacyProof(st, in.Migration.Proof); err == nil {
			return s.finishMigration(st, in.Migration, in.DeviceLabel)
		}
	}

	// Both paths failed: charge only now, so failed *attempts* cost the
	// account budget but rejected requests and successes do not.
	s.cfg.Limiter.Fail([]string{
		"src:" + in.Source,
		"global",
		"acct-src:" + string(st.AccountKey) + ":" + in.Source,
		"acct-fail:" + string(st.AccountKey),
	})
	return nil, ErrUnauthenticated
}

func (s *Service) finishActive(st *loginStatePayload, deviceLabel string) (*Session, error) {
	acct, err := s.store.GetAccount(st.AccountKey)
	if err != nil || acct.Status != "active" {
		return nil, ErrUnauthenticated
	}
	s.cfg.Limiter.Succeed(string(st.AccountKey))
	sess, err := s.issueSession(st.AccountKey, deviceLabel)
	if err != nil {
		return nil, err
	}
	s.audit("login", st.AccountKey)
	return sess, nil
}

// verifyLegacyProof compares HMAC(challenge, stored digest) with the client's
// HMAC(challenge, locally computed digest). It never receives the password and
// the digest never leaves the server.
func (s *Service) verifyLegacyProof(st *loginStatePayload, proof []byte) error {
	if len(st.LegacyDigestEnc) == 0 || len(st.LegacyChallenge) != 32 {
		return ErrUnauthenticated
	}
	digest, err := OpenLegacyDigest(s.legacyRing, st.AccountKey, st.LegacyDigestEnc)
	if err != nil {
		return ErrUnauthenticated
	}
	defer secure.Zero(digest)
	want := secure.HMAC(st.LegacyChallenge, digest)
	if !secure.Equal(want, proof) {
		return ErrUnauthenticated
	}
	return nil
}

func (s *Service) finishMigration(st *loginStatePayload, mp *MigrationProof, deviceLabel string) (*Session, error) {
	profile, err := s.profile(mp.KSF)
	if err != nil {
		return nil, err
	}
	cred, err := s.newCredential(st.AccountKey, profile, mp.Registration)
	if err != nil {
		return nil, err
	}
	unlock := s.lock.Lock(st.AccountKey)
	defer unlock()
	// A concurrent migration may have won. InstallCredentialIfAbsent makes the
	// first finish the winner; a later one with a different credential is a
	// no-op (it cannot hijack the account), and the login still succeeds
	// because the legacy password proof was valid.
	installed, err := s.store.InstallCredentialIfAbsent(st.AccountKey, cred)
	if err != nil {
		return nil, err
	}
	s.cfg.Limiter.Succeed(string(st.AccountKey))
	sess, err := s.issueSession(st.AccountKey, deviceLabel)
	if err != nil {
		return nil, err
	}
	if installed {
		s.audit("migrate", st.AccountKey)
	} else {
		s.audit("login", st.AccountKey)
	}
	return sess, nil
}

// ---------------------------------------------------------------------------
// Password change
// ---------------------------------------------------------------------------

// ChangeBegin starts a password change for an authenticated session.
func (s *Service) ChangeBegin(accountKey []byte, regReq *message.RegistrationRequest) (ceremonyID []byte, resp *message.RegistrationResponse, ksfSalt []byte, err error) {
	credID := s.credentialIDFor(accountKey)
	resp, err = s.server.RegistrationResponse(regReq, credID, nil)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%w: %s", ErrBadRequest, err)
	}
	ceremonyID = secure.Random(24)
	payload, err := s.sealCeremony(ceremonyID, store.CeremonyChange, identity{account: accountKey, credID: credID}, regRespBlob(resp))
	if err != nil {
		return nil, nil, nil, err
	}
	if err := s.store.CreateCeremony(&store.Ceremony{
		ID: ceremonyID, Kind: store.CeremonyChange, AccountKey: accountKey,
		Payload: payload, ExpiresAt: s.now().Add(s.cfg.CeremonyTTL),
	}); err != nil {
		return nil, nil, nil, err
	}
	return ceremonyID, resp, s.ksfSaltFor(accountKey), nil
}

// ChangeFinish installs the new credential and revokes every other session.
func (s *Service) ChangeFinish(accountKey, ceremonyID []byte, record *message.RegistrationRecord, ksfID string) error {
	profile, err := s.profile(ksfID)
	if err != nil {
		return err
	}
	if err := s.store.ConsumeCeremony(ceremonyID, store.CeremonyChange); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return ErrExpired
		}
		return err
	}
	cer, err := s.store.GetCeremony(ceremonyID)
	if err != nil {
		return err
	}
	id, _, err := s.openCeremony(ceremonyID, store.CeremonyChange, cer)
	if err != nil {
		return err
	}
	if !secure.Equal(id.account, accountKey) {
		return ErrUnauthenticated
	}
	cred, err := s.newCredential(accountKey, profile, record)
	if err != nil {
		return err
	}
	if err := s.store.InstallCredential(accountKey, cred, true, true); err != nil {
		return err
	}
	s.audit("change", accountKey)
	return nil
}

// ---------------------------------------------------------------------------
// Recovery
// ---------------------------------------------------------------------------

// RecoverBegin issues a recovery token if, and only if, the account exists, is
// active, and has a contact address. The caller must return the same response
// to the user in every case; the boolean is for the mailer, not the user.
func (s *Service) RecoverBegin(rawIdent, source string) (accountKey []byte, token string, send bool) {
	id, err := s.resolve(rawIdent)
	if err != nil {
		return nil, "", false
	}
	// Recovery triggers an e-mail and creates a token row. Charge on admission
	// per source; the caller must still return a uniform response.
	if ok, _ := s.cfg.Limiter.AdmitKey("recover:"+source, recoverRate); !ok {
		return nil, "", false
	}
	if ok, _ := s.cfg.Limiter.AdmitKey("recover-acct:"+string(id.account), recoverRate); !ok {
		return nil, "", false
	}
	acct, err := s.store.GetAccount(id.account)
	if err != nil || acct.Status != "active" {
		return nil, "", false
	}
	if _, err := s.store.GetContact(id.account); err != nil {
		return nil, "", false
	}
	tok := secure.Token(32)
	th := secure.HMAC(s.keys.RecoveryToken, []byte("recovery-token/v1\x00"), []byte(tok))
	if err := s.store.CreateRecoveryToken(&store.RecoveryToken{
		TokenHash: th, AccountKey: id.account, ExpiresAt: s.now().Add(s.cfg.RecoveryTTL),
	}); err != nil {
		return nil, "", false
	}
	s.audit("recover-request", id.account)
	return id.account, tok, true
}

// RecoveryContact returns the decrypted contact address for an account that
// RecoverBegin just authorised. It is separate from RecoverBegin so the caller
// can only obtain the address for a request that actually issued a token.
func (s *Service) RecoveryContact(accountKey []byte) (string, bool) {
	return s.OpenContact(accountKey)
}

// RecoverRedeemBegin validates a recovery token and starts a registration for
// the new password. The token is not consumed until the credential is
// installed, so a dropped ceremony does not burn the link.
func (s *Service) RecoverRedeemBegin(token string, regReq *message.RegistrationRequest) (ceremonyID []byte, resp *message.RegistrationResponse, ksfSalt []byte, err error) {
	th := secure.HMAC(s.keys.RecoveryToken, []byte("recovery-token/v1\x00"), []byte(token))
	rt, err := s.store.GetRecoveryToken(th)
	if err != nil {
		return nil, nil, nil, ErrExpired
	}
	credID := s.credentialIDFor(rt.AccountKey)
	resp, err = s.server.RegistrationResponse(regReq, credID, nil)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%w: %s", ErrBadRequest, err)
	}
	ceremonyID = secure.Random(24)
	payload, err := s.sealCeremony(ceremonyID, store.CeremonyRecover, identity{account: rt.AccountKey, credID: credID}, regRespBlob(resp))
	if err != nil {
		return nil, nil, nil, err
	}
	if err := s.store.CreateCeremony(&store.Ceremony{
		ID: ceremonyID, Kind: store.CeremonyRecover, AccountKey: rt.AccountKey,
		Payload: payload, ExpiresAt: s.now().Add(s.cfg.CeremonyTTL),
	}); err != nil {
		return nil, nil, nil, err
	}
	return ceremonyID, resp, s.ksfSaltFor(rt.AccountKey), nil
}

// RecoverRedeemFinish installs the new credential and revokes all sessions.
func (s *Service) RecoverRedeemFinish(token string, ceremonyID []byte, record *message.RegistrationRecord, ksfID string) (*Session, error) {
	profile, err := s.profile(ksfID)
	if err != nil {
		return nil, err
	}
	th := secure.HMAC(s.keys.RecoveryToken, []byte("recovery-token/v1\x00"), []byte(token))
	rt, err := s.store.GetRecoveryToken(th)
	if err != nil {
		return nil, ErrExpired
	}
	if err := s.store.ConsumeCeremony(ceremonyID, store.CeremonyRecover); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrExpired
		}
		return nil, err
	}
	cer, err := s.store.GetCeremony(ceremonyID)
	if err != nil {
		return nil, err
	}
	id, _, err := s.openCeremony(ceremonyID, store.CeremonyRecover, cer)
	if err != nil {
		return nil, err
	}
	if !secure.Equal(id.account, rt.AccountKey) {
		return nil, ErrUnauthenticated
	}
	if err := s.store.ConsumeRecoveryToken(th); err != nil {
		return nil, ErrExpired
	}
	cred, err := s.newCredential(rt.AccountKey, profile, record)
	if err != nil {
		return nil, err
	}
	if err := s.store.ReplaceAfterRecovery(rt.AccountKey, cred); err != nil {
		return nil, err
	}
	sess, err := s.issueSession(rt.AccountKey, "recovery")
	if err != nil {
		return nil, err
	}
	s.audit("recover-complete", rt.AccountKey)
	return sess, nil
}

// Serialization helpers used by the API layer. They keep the wire package free
// of a dependency on the protocol library.

// DeserializeKE1 parses a serialized OPAQUE KE1.
func (s *Service) DeserializeKE1(b []byte) (*message.KE1, error) {
	return s.deser().KE1(b)
}

// DeserializeKE3 parses a serialized OPAQUE KE3.
func (s *Service) DeserializeKE3(b []byte) (*message.KE3, error) {
	return s.deser().KE3(b)
}

// DeserializeRegistrationRequest parses a serialized RegistrationRequest.
func (s *Service) DeserializeRegistrationRequest(b []byte) (*message.RegistrationRequest, error) {
	if len(b) == 0 {
		return nil, nil
	}
	return s.deser().RegistrationRequest(b)
}

// DeserializeRegistrationRecord parses a serialized RegistrationRecord.
func (s *Service) DeserializeRegistrationRecord(b []byte) (*message.RegistrationRecord, error) {
	return s.deser().RegistrationRecord(b)
}

// DeserializeRegistrationResponse parses a serialized RegistrationResponse.
func (s *Service) DeserializeRegistrationResponse(b []byte) (*message.RegistrationResponse, error) {
	return s.deser().RegistrationResponse(b)
}

// IssueChallenge returns a proof-of-work challenge.
func (s *Service) IssueChallenge() string { return s.cfg.Pow.Issue() }

// VerifyChallenge checks a proof-of-work solution.
func (s *Service) VerifyChallenge(token string, nonce uint64) error {
	return s.cfg.Pow.Verify(token, nonce)
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

// Session is an issued session.
type Session struct {
	Token       string
	TokenHash   []byte
	AccountKey  []byte
	ExpiresAt   time.Time
	AuthTime    time.Time
	DeviceToken string
}

func (s *Service) issueSession(accountKey []byte, deviceLabel string) (*Session, error) {
	token := secure.Token(32)
	th := secure.HMAC(s.keys.SessionToken, []byte("session-token/v1\x00"), []byte(token))
	now := s.now()
	device := secure.HMAC(s.keys.SessionToken, []byte("device/v1\x00"), accountKey, []byte(deviceLabel))
	sess := &store.Session{
		TokenHash: th, AccountKey: accountKey, AuthTime: now,
		ExpiresAt: now.Add(s.cfg.SessionTTL), DeviceHash: device,
	}
	if err := s.store.CreateSession(sess); err != nil {
		return nil, err
	}
	dt := secure.Token(32)
	dh := secure.HMAC(s.keys.SessionToken, []byte("device-token/v1\x00"), []byte(dt))
	if err := s.store.PutTrustedDevice(&store.TrustedDevice{
		AccountKey: accountKey, DeviceHash: dh,
		ExpiresAt: now.Add(s.cfg.TrustedDeviceTTL),
	}); err != nil {
		return nil, err
	}
	return &Session{
		Token: token, TokenHash: th, AccountKey: accountKey,
		ExpiresAt: sess.ExpiresAt, AuthTime: now, DeviceToken: dt,
	}, nil
}

// Authenticate resolves a session token to a session. Enforces idle timeout.
func (s *Service) Authenticate(token string) (*Session, error) {
	if token == "" {
		return nil, ErrUnauthenticated
	}
	th := secure.HMAC(s.keys.SessionToken, []byte("session-token/v1\x00"), []byte(token))
	sess, err := s.store.GetSession(th)
	if err != nil {
		return nil, ErrUnauthenticated
	}
	if s.now().Sub(sess.LastSeen) > s.cfg.SessionIdleTTL {
		_ = s.store.RevokeSession(th)
		return nil, ErrUnauthenticated
	}
	if err := s.store.TouchSession(th); err != nil {
		return nil, err
	}
	return &Session{Token: token, TokenHash: th, AccountKey: sess.AccountKey, ExpiresAt: sess.ExpiresAt, AuthTime: sess.AuthTime}, nil
}

// Logout revokes a session.
func (s *Service) Logout(token string) error {
	if token == "" {
		return nil
	}
	th := secure.HMAC(s.keys.SessionToken, []byte("session-token/v1\x00"), []byte(token))
	return s.store.RevokeSession(th)
}

// IsTrustedDevice reports whether deviceToken is a live trusted device for
// accountKey. The device token is per-account, so the account key must be
// known first — which is why callers resolve the identifier before asking.
func (s *Service) IsTrustedDevice(accountKey []byte, deviceToken string) bool {
	if deviceToken == "" {
		return false
	}
	dh := secure.HMAC(s.keys.SessionToken, []byte("device-token/v1\x00"), []byte(deviceToken))
	ok, err := s.store.GetTrustedDevice(accountKey, dh)
	return err == nil && ok
}

// RequiresReauth reports whether a session's authentication is old enough that
// security-sensitive actions (password change) should require a fresh login.
func (s *Service) RequiresReauth(sess *Session, maxAge time.Duration) bool {
	return s.now().Sub(sess.AuthTime) > maxAge
}
