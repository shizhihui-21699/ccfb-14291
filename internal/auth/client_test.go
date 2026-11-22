package auth_test

import (
	"testing"

	"github.com/bytemare/opaque"

	"opaqueauth/internal/auth"
	"opaqueauth/internal/legacy"
	"opaqueauth/internal/secure"
	"opaqueauth/internal/suite"
	"opaqueauth/internal/wire"
)

// testClient drives the service the way a real client would, without HTTP. It
// keeps a password only in this struct and never passes it to the service.
type testClient struct {
	t      *testing.T
	ident  string
	conf   *opaque.Configuration
	ake    *opaque.Client // login state
	reg    *opaque.Client // registration state
	device string
	token  string
	// msgsource overrides the rate-limit source label; empty means per-ident.
	msgsource string
	// lastChallenge is the challenge returned by the most recent refused start.
	lastChallenge *wire.Challenge
	prodProfile   bool
	// ksfSalt is what the server announced for the most recent ceremony.
	ksfSalt []byte
}

func newTestClient(t *testing.T, ident string) *testClient {
	t.Helper()
	conf := suite.Configuration()
	ake, err := conf.Client()
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	reg, err := conf.Client()
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	return &testClient{t: t, ident: ident, conf: conf, ake: ake, reg: reg}
}

func (c *testClient) opts() *opaque.ClientOptions {
	p := cheapProfile
	if c.prodProfile {
		p = suite.ProfileV1
	}
	return &opaque.ClientOptions{
		KSFSalt:       c.ksfSalt,
		KSFParameters: p.Params(),
		KSFLength:     p.Length,
	}
}

func (c *testClient) ksf() string {
	if c.prodProfile {
		return suite.ProfileV1.ID
	}
	return cheapProfile.ID
}

func (c *testClient) serverIdentity() []byte { return []byte(suite.ServerIdentity) }

// register creates an account.
func (c *testClient) register(h *harness, password string) error {
	c.reg.ClearState()
	req, err := c.reg.RegistrationInit([]byte(password))
	if err != nil {
		return err
	}
	cer, resp, salt, err := h.svc.RegisterBegin(c.ident, req, "", "test")
	if err != nil {
		return err
	}
	c.ksfSalt = salt
	rec, _, err := c.reg.RegistrationFinalize(resp, nil, c.serverIdentity(), c.opts())
	if err != nil {
		return err
	}
	sess, err := h.svc.RegisterFinish(cer, rec, c.ksf(), "", "")
	if err != nil {
		return err
	}
	c.token = sess.Token
	c.device = sess.DeviceToken
	return nil
}

// login performs a full login, using migration when the server indicates it.
func (c *testClient) login(h *harness, password string) (*auth.Session, error) {
	return c.loginWithProof(h, password, nil)
}

// loginWithProof performs a login optionally carrying a PoW proof.
func (c *testClient) loginWithProof(h *harness, password string, proof *wire.Proof) (*auth.Session, error) {
	// Each login is a fresh protocol run.
	c.ake.ClearState()
	c.reg.ClearState()
	ke1, err := c.ake.GenerateKE1([]byte(password))
	if err != nil {
		return nil, err
	}
	newReq, err := c.reg.RegistrationInit([]byte(password))
	if err != nil {
		return nil, err
	}
	src := c.msgsource
	if src == "" {
		src = "src-" + c.ident
	}
	start, err := h.svc.LoginBegin(c.ident, ke1, newReq, src, c.device, proof)
	if err != nil {
		return nil, err
	}
	if start.RateLimited {
		c.lastChallenge = start.Challenge
		return nil, auth.ErrRateLimited
	}
	c.ksfSalt = start.KSFSalt

	deser, err := c.conf.Deserializer()
	if err != nil {
		return nil, err
	}
	ke2msg, err := deser.KE2(start.KE2.Serialize())
	if err != nil {
		return nil, err
	}
	ke3, _, _, err := c.ake.GenerateKE3(ke2msg, nil, c.serverIdentity(), c.opts())
	if err != nil {
		// A legacy account cannot complete OPAQUE (the record was a decoy).
		return c.finishLegacy(h, password, start)
	}
	sess, err := h.svc.LoginFinish(auth.LoginFinishInput{
		StateID: start.StateID, KE3: ke3, Source: src,
	})
	if err != nil {
		return nil, err
	}
	c.token = sess.Token
	c.device = sess.DeviceToken
	return sess, nil
}

func (c *testClient) finishLegacy(h *harness, password string, start *auth.LoginStartResult) (*auth.Session, error) {
	digest, err := legacy.BCryptRaw([]byte(password), start.LegacySalt, start.LegacyCost)
	if err != nil {
		return nil, err
	}
	proof := secure.HMAC(start.LegacyChallenge, []byte(digest))
	resp, err := c.conf.Deserializer()
	if err != nil {
		return nil, err
	}
	regResp, err := resp.RegistrationResponse(start.RegResponse)
	if err != nil {
		return nil, err
	}
	rec, _, err := c.reg.RegistrationFinalize(regResp, nil, c.serverIdentity(), c.opts())
	if err != nil {
		return nil, err
	}
	src := c.msgsource
	if src == "" {
		src = "src-" + c.ident
	}
	sess, err := h.svc.LoginFinish(auth.LoginFinishInput{
		StateID: start.StateID,
		Migration: &auth.MigrationProof{
			Proof: proof, Registration: rec, KSF: c.ksf(),
		},
		Source: src,
	})
	if err != nil {
		return nil, err
	}
	c.token = sess.Token
	c.device = sess.DeviceToken
	return sess, nil
}

// newTestClientProd uses the production KSF profile.
func newTestClientProd(t *testing.T, ident string) *testClient {
	c := newTestClient(t, ident)
	c.prodProfile = true
	return c
}
