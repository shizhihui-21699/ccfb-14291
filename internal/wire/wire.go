// Package wire defines the JSON request and response bodies of the auth API.
//
// Binary values are standard-base64 strings. Every field that is
// attacker-controlled is length-checked by the service; see the handlers.
//
// The API is deliberately shaped like OPAQUE's message flow:
//
//	POST /v1/login/start   {identifier, ke1}          -> {session, ke2}
//	POST /v1/login/finish  {session, ke3}             -> {token, ...}
//
//	POST /v1/register/start  {identifier, reg_request}          -> {ceremony, reg_response}
//	POST /v1/register/finish {ceremony, reg_record}              -> {token, ...}
//
// A migration login looks exactly like a login until authentication succeeds,
// at which point the server answers 200 with `migrate` set; the client then
// completes registration without ever resending the password.
package wire

// LoginStartRequest begins an online authentication.
type LoginStartRequest struct {
	// Identifier is the user-supplied identifier. It is canonicalized and
	// peppered before any database access; it is never logged.
	Identifier string `json:"identifier"`
	// KE1 is the serialized OPAQUE KE1 message.
	KE1 []byte `json:"ke1"`
	// RacerRegistrationRequest is the serialized OPAQUE RegistrationRequest
	// for a *new* password, sent alongside KE1. It lets the server return a
	// RegistrationResponse in the same reply and makes transparent migration
	// possible on the login round trip: if this login turns out to be a
	// legacy account, the client can immediately build the replacement
	// record. Sending it for a non-legacy account has no effect, so its
	// presence is not an existence signal.
	RacerRegistrationRequest []byte `json:"registration_request,omitempty"`
	// DeviceLabel is an optional human label for the session list.
	DeviceLabel string `json:"device_label,omitempty"`
	// Proof is the solution to a proof-of-work challenge, if required.
	Proof *Proof `json:"proof,omitempty"`
}

// Proof is a stateless proof-of-work solution.
type Proof struct {
	Challenge string `json:"challenge"`
	Nonce     uint64 `json:"nonce"`
}

// LoginStartResponse answers LoginStartRequest.
//
// Every field except Session and KE2 is identical for a real account, an
// unknown account, a disabled account, and a not-yet-migrated account. In
// particular MigrationMaterial is always populated (with decoy values when the
// account has nothing to migrate) so that its presence cannot be used to learn
// which accounts are still on the legacy scheme.
type LoginStartResponse struct {
	Session string `json:"session,omitempty"`
	KE2     []byte `json:"ke2,omitempty"`
	// KSF names the Argon2id profile and its deterministic per-account salt.
	KSF     string `json:"ksf,omitempty"`
	KSFSalt []byte `json:"ksf_salt,omitempty"`
	// Migration material: always present.
	LegacySalt      []byte `json:"legacy_salt,omitempty"`
	LegacyCost      int    `json:"legacy_cost,omitempty"`
	LegacyChallenge []byte `json:"legacy_challenge,omitempty"`
	// RegistrationResponse is present iff the request carried a
	// registration_request.
	RegistrationResponse []byte `json:"registration_response,omitempty"`
	// Error is a coarse, non-enumerating error code.
	Error string `json:"error,omitempty"`
	// RetryAfter is set on 429.
	RetryAfter int `json:"retry_after,omitempty"`
	// ProofOfWork is set on 429: the client may solve it and retry once.
	ProofOfWork *Challenge `json:"proof_of_work,omitempty"`
}

// Challenge is a stateless proof-of-work challenge.
type Challenge struct {
	Token string `json:"token"`
	Bits  int    `json:"bits"`
}

// LoginFinishRequest completes authentication.
type LoginFinishRequest struct {
	Session string `json:"session"`
	KE3     []byte `json:"ke3"`
	// Migration, when present, proves the client knows the legacy password
	// without revealing it and transports the new OPAQUE registration record.
	Migration   *MigrationProof `json:"migration,omitempty"`
	DeviceLabel string          `json:"device_label,omitempty"`
}

// MigrationProof is the client half of a transparent upgrade on login.
//
// The client has just proved knowledge of the password through OPAQUE. To
// upgrade it additionally proves knowledge of the *legacy* password against
// the legacy verifier:
//
//	raw   = BCryptRaw(password, salt, cost)              (client-local)
//	proof = HMAC-SHA256(legacy_challenge, raw)           (never sent: raw)
//
// The server computes the same HMAC from the digest stored in its own legacy
// row and compares. The legacy challenge is a random value tied to this login
// state, so the proof cannot be replayed.
type MigrationProof struct {
	// Proof is HMAC-SHA256(key=legacy_challenge, msg=raw bcrypt digest).
	Proof []byte `json:"proof"`
	// Registration is the serialized OPAQUE RegistrationRecord produced by the
	// client from the server's RegistrationResponse (see /v1/login/start's
	// migrate response), binding the new envelope.
	Registration []byte `json:"registration"`
	// KSF is the Argon2id profile the client used to build the record.
	KSF string `json:"ksf"`
}

// LoginFinishResponse returns the session token.
type LoginFinishResponse struct {
	Token      string `json:"token,omitempty"`
	ExpiresAt  int64  `json:"expires_at,omitempty"`
	Migrated   bool   `json:"migrated,omitempty"`
	AccountID  string `json:"account_id,omitempty"`
	Error      string `json:"error,omitempty"`
	RetryAfter int    `json:"retry_after,omitempty"`
}

// RegisterStartRequest begins onboarding of a new account.
type RegisterStartRequest struct {
	Identifier string `json:"identifier"`
	// RegistrationRequest is the serialized OPAQUE RegistrationRequest.
	RegistrationRequest []byte `json:"registration_request"`
	// InviteCode, when the deployment requires invitation, is checked before
	// any registration response is produced.
	InviteCode string `json:"invite_code,omitempty"`
}

// RegisterStartResponse answers RegisterStartRequest.
type RegisterStartResponse struct {
	Ceremony string `json:"ceremony,omitempty"`
	// RegistrationResponse is the serialized OPAQUE RegistrationResponse.
	RegistrationResponse []byte `json:"registration_response,omitempty"`
	KSF                  string `json:"ksf,omitempty"`
	KSFSalt              []byte `json:"ksf_salt,omitempty"`
	Error                string `json:"error,omitempty"`
}

// RegisterFinishRequest completes onboarding.
type RegisterFinishRequest struct {
	Ceremony string `json:"ceremony"`
	// RegistrationRecord is the serialized OPAQUE RegistrationRecord.
	RegistrationRecord []byte `json:"registration_record"`
	// KSF must match the profile the server announced.
	KSF string `json:"ksf"`
	// Contact, if supplied, is stored encrypted for recovery notices. It is
	// never returned and is not an authentication factor.
	Contact     string `json:"contact,omitempty"`
	DeviceLabel string `json:"device_label,omitempty"`
}

// RegisterFinishResponse returns the first session.
type RegisterFinishResponse struct {
	Token     string `json:"token,omitempty"`
	ExpiresAt int64  `json:"expires_at,omitempty"`
	Error     string `json:"error,omitempty"`
}

// ChangeStartRequest begins a password change. Requires a fresh session.
type ChangeStartRequest struct {
	// RegistrationRequest is the serialized OPAQUE RegistrationRequest for the
	// new password.
	RegistrationRequest []byte `json:"registration_request"`
}

// ChangeStartResponse carries the server's RegistrationResponse.
type ChangeStartResponse struct {
	Ceremony             string `json:"ceremony,omitempty"`
	RegistrationResponse []byte `json:"registration_response,omitempty"`
	KSF                  string `json:"ksf,omitempty"`
	KSFSalt              []byte `json:"ksf_salt,omitempty"`
	Error                string `json:"error,omitempty"`
}

// ChangeFinishRequest commits the change.
type ChangeFinishRequest struct {
	Ceremony           string `json:"ceremony"`
	RegistrationRecord []byte `json:"registration_record"`
	KSF                string `json:"ksf"`
}

// ChangeFinishResponse confirms.
type ChangeFinishResponse struct {
	OK        bool   `json:"ok"`
	ExpiresAt int64  `json:"expires_at,omitempty"`
	Error     string `json:"error,omitempty"`
}

// RecoverStartRequest asks for a recovery message.
type RecoverStartRequest struct {
	Identifier string `json:"identifier"`
}

// RecoverStartResponse is deliberately identical whether or not the account
// exists or has a contact address.
type RecoverStartResponse struct {
	OK bool `json:"ok"`
}

// RecoverRedeemStartRequest begins the second half of recovery, where the user
// holds the emailed token and starts an OPAQUE registration for a new password.
type RecoverRedeemStartRequest struct {
	Token               string `json:"token"`
	RegistrationRequest []byte `json:"registration_request"`
}

// RecoverRedeemStartResponse carries the RegistrationResponse.
type RecoverRedeemStartResponse struct {
	Ceremony             string `json:"ceremony,omitempty"`
	RegistrationResponse []byte `json:"registration_response,omitempty"`
	KSF                  string `json:"ksf,omitempty"`
	KSFSalt              []byte `json:"ksf_salt,omitempty"`
	Error                string `json:"error,omitempty"`
}

// RecoverRedeemFinishRequest installs the new credential.
type RecoverRedeemFinishRequest struct {
	Token              string `json:"token"`
	Ceremony           string `json:"ceremony"`
	RegistrationRecord []byte `json:"registration_record"`
	KSF                string `json:"ksf"`
}

// RecoverRedeemFinishResponse returns a fresh session and revokes the rest.
type RecoverRedeemFinishResponse struct {
	Token     string `json:"token,omitempty"`
	ExpiresAt int64  `json:"expires_at,omitempty"`
	Error     string `json:"error,omitempty"`
}

// ServerConfigResponse exposes the non-secret parameters a client needs.
type ServerConfigResponse struct {
	Suite          string `json:"suite"`
	ServerIdentity []byte `json:"server_identity"`
	Context        []byte `json:"context"`
	KSF            string `json:"ksf"`
	KSFTime        uint64 `json:"ksf_time"`
	KSFMemory      uint64 `json:"ksf_memory"`
	KSFThreads     uint64 `json:"ksf_threads"`
	KSFKeyLen      int    `json:"ksf_key_len"`
	ProofBits      int    `json:"proof_bits"`
}

// ErrorBody is the uniform error envelope.
type ErrorBody struct {
	Code       string `json:"error"`
	RetryAfter int    `json:"retry_after,omitempty"`
}
