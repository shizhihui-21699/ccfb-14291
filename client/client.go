// Package client is the reference OPAQUE client. It runs in the user's process
// and is the only place the plaintext password ever exists.
//
// The client never sends the password, nor any password-derived value that
// functions as a verifier. During migration it computes the old bcrypt digest
// locally and returns only an HMAC under a server-issued challenge, so even the
// legacy upgrade path does not put the old verifier on the network.
package client

import (
	"bytes"
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/bytemare/ksf"
	"github.com/bytemare/opaque"

	"opaqueauth/internal/legacy"
	"opaqueauth/internal/pow"
	"opaqueauth/internal/secure"
	"opaqueauth/internal/wire"
)

// Config is the decoded GET /v1/config response.
type Config struct {
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

// Client talks to the auth API.
type Client struct {
	BaseURL     string
	HTTP        *http.Client
	Identifier  string
	DeviceToken string
	Session     string

	cfg  Config
	conf *opaque.Configuration
	// opq drives the login AKE; reg drives registration/change records. They
	// must be separate instances: the library keeps a single OPRF-blind slot
	// per Client and refuses to hold a KE1 and a registration blind at once.
	opq *opaque.Client
	reg *opaque.Client
}

// New loads server configuration and creates a client bound to identifier.
func New(ctx context.Context, baseURL, identifier string) (*Client, error) {
	c := &Client{BaseURL: baseURL, HTTP: &http.Client{Timeout: 60 * time.Second}, Identifier: identifier}
	if err := c.do(ctx, http.MethodGet, "/v1/config", nil, &c.cfg); err != nil {
		return nil, err
	}
	conf, err := suiteFor(c.cfg)
	if err != nil {
		return nil, err
	}
	c.conf = conf
	if c.opq, err = conf.Client(); err != nil {
		return nil, err
	}
	if c.reg, err = conf.Client(); err != nil {
		return nil, err
	}
	return c, nil
}

// suiteFor rebuilds the pinned OPAQUE configuration from the server's
// advertised parameters, rejecting anything that is not the expected suite.
func suiteFor(cfg Config) (*opaque.Configuration, error) {
	conf := &opaque.Configuration{
		OPRF:    opaque.RistrettoSha512,
		AKE:     opaque.RistrettoSha512,
		KSF:     ksf.Argon2id,
		KDF:     crypto.SHA512,
		MAC:     crypto.SHA512,
		Hash:    crypto.SHA512,
		Context: cfg.Context,
	}
	// Refuse a downgraded KSF: the whole point of advertising it is to detect
	// this.
	if cfg.KSFTime == 0 || cfg.KSFMemory == 0 || cfg.KSFThreads == 0 || cfg.KSFKeyLen == 0 {
		return nil, errors.New("client: server announced an incomplete KSF profile")
	}
	return conf, nil
}

// opts builds client options for the announced salt.
func (c *Client) opts(ksfSalt []byte) *opaque.ClientOptions {
	return &opaque.ClientOptions{
		KSFSalt:       ksfSalt,
		KSFParameters: []uint64{c.cfg.KSFTime, c.cfg.KSFMemory, c.cfg.KSFThreads},
		KSFLength:     c.cfg.KSFKeyLen,
	}
}

// deser returns the deserializer for the client's configuration.
func (c *Client) deser() *opaque.Deserializer {
	d, err := c.conf.Deserializer()
	if err != nil {
		panic("client: configuration became invalid: " + err.Error())
	}
	return d
}

// serverIdentity is the bytes the client binds as the OPAQUE server identity.
func (c *Client) serverIdentity() []byte {
	if len(c.cfg.ServerIdentity) > 0 {
		return c.cfg.ServerIdentity
	}
	return []byte("opaqueauth/v1/server")
}

// Register creates a new account.
func (c *Client) Register(ctx context.Context, password string) error {
	req, err := c.reg.RegistrationInit([]byte(password))
	if err != nil {
		return err
	}
	var start wire.RegisterStartResponse
	if err := c.do(ctx, http.MethodPost, "/v1/register/start", wire.RegisterStartRequest{
		Identifier:          c.Identifier,
		RegistrationRequest: req.Serialize(),
	}, &start); err != nil {
		return err
	}
	resp, err := c.deser().RegistrationResponse(start.RegistrationResponse)
	if err != nil {
		return err
	}
	rec, _, err := c.reg.RegistrationFinalize(resp, nil, c.serverIdentity(), c.opts(start.KSFSalt))
	if err != nil {
		return err
	}
	c.reg.ClearState()
	var fin wire.RegisterFinishResponse
	if err := c.do(ctx, http.MethodPost, "/v1/register/finish", wire.RegisterFinishRequest{
		Ceremony: start.Ceremony, RegistrationRecord: rec.Serialize(), KSF: start.KSF,
	}, &fin); err != nil {
		return err
	}
	c.Session = fin.Token
	c.reg.ClearState()
	return nil
}

// Login performs a full online authentication. If the account still has a
// legacy verifier, the same call transparently upgrades it.
//
// If the server refuses the start with 429, it returns a proof-of-work
// challenge; Login solves it and retries once with a fresh exchange. That is
// the client half of the anti-lockout story: a user on a new device is never
// permanently refused, only asked to spend a bounded amount of CPU.
func (c *Client) Login(ctx context.Context, password string) error {
	var proof *wire.Proof
	err := c.loginOnce(ctx, password, proof)
	if err == nil {
		return nil
	}
	var apiErr *APIError
	if errors.As(err, &apiErr) && apiErr.Status == http.StatusTooManyRequests && apiErr.Challenge != nil {
		n, serr := pow.Solve(apiErr.Challenge.Token, apiErr.Challenge.Bits, 1<<30)
		if serr != nil {
			return serr
		}
		proof = &wire.Proof{Challenge: apiErr.Challenge.Token, Nonce: n}
		return c.loginOnce(ctx, password, proof)
	}
	return err
}

// loginOnce runs one start/finish exchange.
func (c *Client) loginOnce(ctx context.Context, password string, proof *wire.Proof) error {
	c.opq.ClearState()
	c.reg.ClearState()
	ke1, err := c.opq.GenerateKE1([]byte(password))
	if err != nil {
		return err
	}
	// Build the replacement credential material unconditionally. If this turns
	// out to be a legacy account the server supplies the RegistrationResponse;
	// otherwise it is unused. Sending it always means the request cannot be
	// distinguished by whether the client expects an upgrade.
	newReq, err := c.reg.RegistrationInit([]byte(password))
	if err != nil {
		return err
	}
	req := wire.LoginStartRequest{
		Identifier:               c.Identifier,
		KE1:                      ke1.Serialize(),
		RacerRegistrationRequest: newReq.Serialize(),
		Proof:                    proof,
	}
	var start wire.LoginStartResponse
	if err := c.do(ctx, http.MethodPost, "/v1/login/start", req, &start); err != nil {
		return err
	}
	ke2, err := c.deser().KE2(start.KE2)
	if err != nil {
		return err
	}
	ke3, _, _, err := c.opq.GenerateKE3(ke2, nil, c.serverIdentity(), c.opts(start.KSFSalt))
	if err != nil {
		// The OPAQUE round failed. For a legacy account this is expected: the
		// server sent a decoy record because no OPAQUE credential exists yet.
		if len(start.RegistrationResponse) > 0 && len(start.LegacyChallenge) > 0 {
			return c.finishLegacy(ctx, password, start)
		}
		return errors.New("client: authentication failed")
	}
	var fin wire.LoginFinishResponse
	if err := c.do(ctx, http.MethodPost, "/v1/login/finish", wire.LoginFinishRequest{
		Session: start.Session, KE3: ke3.Serialize(),
	}, &fin); err != nil {
		return err
	}
	c.Session = fin.Token
	c.reg.ClearState()
	return nil
}

// finishLegacy completes a migration login without transmitting the verifier.
func (c *Client) finishLegacy(ctx context.Context, password string, start wire.LoginStartResponse) error {
	digest, err := legacy.BCryptRaw([]byte(password), start.LegacySalt, start.LegacyCost)
	if err != nil {
		return errors.New("client: authentication failed")
	}
	proof := secure.HMAC(start.LegacyChallenge, []byte(digest))
	regResp, err := c.deser().RegistrationResponse(start.RegistrationResponse)
	if err != nil {
		return err
	}
	// The blind from the start request is still held in the client's
	// registration state; finalize against the server's response.
	rec, _, err := c.reg.RegistrationFinalize(regResp, nil, c.serverIdentity(), c.opts(start.KSFSalt))
	if err != nil {
		return err
	}
	var fin wire.LoginFinishResponse
	if err := c.do(ctx, http.MethodPost, "/v1/login/finish", wire.LoginFinishRequest{
		Session: start.Session,
		Migration: &wire.MigrationProof{
			Proof: proof, Registration: rec.Serialize(), KSF: start.KSF,
		},
	}, &fin); err != nil {
		return err
	}
	c.Session = fin.Token
	c.reg.ClearState()
	return nil
}

// ChangePassword rotates the password for the logged-in account.
func (c *Client) ChangePassword(ctx context.Context, oldPass, newPass string) error {
	if err := c.Login(ctx, oldPass); err != nil {
		return err
	}
	newReq, err := c.reg.RegistrationInit([]byte(newPass))
	if err != nil {
		return err
	}
	var start wire.ChangeStartResponse
	if err := c.do(ctx, http.MethodPost, "/v1/change/start", wire.ChangeStartRequest{
		RegistrationRequest: newReq.Serialize(),
	}, &start); err != nil {
		return err
	}
	resp, err := c.deser().RegistrationResponse(start.RegistrationResponse)
	if err != nil {
		return err
	}
	rec, _, err := c.reg.RegistrationFinalize(resp, nil, c.serverIdentity(), c.opts(start.KSFSalt))
	if err != nil {
		return err
	}
	var fin wire.ChangeFinishResponse
	if err := c.do(ctx, http.MethodPost, "/v1/change/finish", wire.ChangeFinishRequest{
		Ceremony: start.Ceremony, RegistrationRecord: rec.Serialize(), KSF: start.KSF,
	}, &fin); err != nil {
		return err
	}
	return nil
}

// Logout revokes the current session.
func (c *Client) Logout(ctx context.Context) error {
	return c.do(ctx, http.MethodPost, "/v1/logout", nil, nil)
}

// do performs one API call.
func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	var rdr *bytes.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(buf)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.Session != "" {
		req.Header.Set("Authorization", "Bearer "+c.Session)
	}
	if c.DeviceToken != "" {
		req.Header.Set("X-Opaque-Device", c.DeviceToken)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if dt := resp.Header.Get("X-Opaque-Device"); dt != "" {
		c.DeviceToken = dt
	}
	if resp.StatusCode/100 != 2 {
		// 429 carries a challenge; surface it so Login can solve and retry.
		if resp.StatusCode == http.StatusTooManyRequests {
			var lr wire.LoginStartResponse
			if err := json.NewDecoder(resp.Body).Decode(&lr); err == nil {
				code := lr.Error
				if code == "" {
					code = "rate_limited"
				}
				return &APIError{Status: resp.StatusCode, Code: code, RetryAfter: lr.RetryAfter, Challenge: lr.ProofOfWork}
			}
			return &APIError{Status: resp.StatusCode, Code: "rate_limited"}
		}
		var eb wire.ErrorBody
		_ = json.NewDecoder(resp.Body).Decode(&eb)
		if eb.Code == "" {
			eb.Code = fmt.Sprintf("http_%d", resp.StatusCode)
		}
		return &APIError{Status: resp.StatusCode, Code: eb.Code, RetryAfter: eb.RetryAfter}
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// APIError is a non-2xx API response.
type APIError struct {
	Status     int
	Code       string
	RetryAfter int
	// Challenge is set on 429 when the server offers a proof-of-work path.
	Challenge *wire.Challenge
}

func (e *APIError) Error() string { return fmt.Sprintf("api: %s (status %d)", e.Code, e.Status) }

// SolveChallenge obtains and solves a proof-of-work challenge. Exposed so the
// CLI and tests can exercise the anti-lockout path.
func (c *Client) SolveChallenge(ctx context.Context) (*wire.Proof, error) {
	var ch wire.Challenge
	if err := c.do(ctx, http.MethodGet, "/v1/challenge", nil, &ch); err != nil {
		return nil, err
	}
	n, err := pow.Solve(ch.Token, ch.Bits, 1<<32)
	if err != nil {
		return nil, err
	}
	return &wire.Proof{Challenge: ch.Token, Nonce: n}, nil
}
