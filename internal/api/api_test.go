package api_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bytemare/opaque"

	"opaqueauth/client"
	"opaqueauth/internal/api"
	"opaqueauth/internal/auth"
	"opaqueauth/internal/ident"
	"opaqueauth/internal/kms"
	"opaqueauth/internal/legacy"
	"opaqueauth/internal/pow"
	"opaqueauth/internal/ratelimit"
	"opaqueauth/internal/store"
	"opaqueauth/internal/suite"
)

var cheap = suite.KSFProfile{ID: "api-test-cheap", Time: 1, Memory: 8 * 1024, Threads: 1, Length: 64}

func init() { suite.RegisterProfile(cheap) }

type env struct {
	srv    *httptest.Server
	svc    *auth.Service
	store  *store.Store
	kms    *kms.MemoryProvider
	ctx    context.Context
	mailer *captureMailer
}

type captureMailer struct {
	lastTo    string
	lastToken string
	count     int
}

func (m *captureMailer) SendRecovery(to, token string) error {
	m.lastTo, m.lastToken = to, token
	m.count++
	return nil
}

func newEnv(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	prov := kms.NewMemoryProvider()
	prov.Set(kms.AppRoot, bytes32(7))
	prov.Set(kms.OPAQUEServerKeyMaterial, mustSKM(t))
	lim := ratelimit.New(ratelimit.DefaultPolicy())
	ch := pow.New(bytes32(9), 8, 10*time.Minute)
	svc, err := auth.New(auth.Config{Store: db, KMS: prov, Limiter: lim, Pow: ch, KSF: cheap})
	if err != nil {
		t.Fatal(err)
	}
	mailer := &captureMailer{}
	a := api.New(svc)
	a.Mailer = mailer
	srv := httptest.NewServer(a.Handler())
	t.Cleanup(srv.Close)
	return &env{srv: srv, svc: svc, store: db, kms: prov, ctx: context.Background(), mailer: mailer}
}

func (e *env) client(t *testing.T, id string) *client.Client {
	t.Helper()
	c, err := client.New(e.ctx, e.srv.URL, id)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	return c
}

func TestHTTPRegisterLoginLogout(t *testing.T) {
	e := newEnv(t)
	c := e.client(t, "Alice@Example.com")
	if err := c.Register(e.ctx, "a-good-password"); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := c.Logout(e.ctx); err != nil {
		t.Fatalf("logout: %v", err)
	}
	if err := c.Login(e.ctx, "a-good-password"); err != nil {
		t.Fatalf("login: %v", err)
	}
	c2 := e.client(t, "alice@example.com") // canonicalizes to the same account
	if err := c2.Login(e.ctx, "a-good-password"); err != nil {
		t.Fatalf("login with different case: %v", err)
	}
}

func TestHTTPWrongPasswordIsUniform(t *testing.T) {
	e := newEnv(t)
	reg := e.client(t, "bob@example.com")
	if err := reg.Register(e.ctx, "right-password"); err != nil {
		t.Fatal(err)
	}
	// Known user, wrong password.
	u1 := e.client(t, "bob@example.com")
	errKnown := u1.Login(e.ctx, "wrong")
	// Unknown user.
	u2 := e.client(t, "nobody@example.com")
	errUnknown := u2.Login(e.ctx, "wrong")
	if errKnown == nil || errUnknown == nil {
		t.Fatalf("expected failures, got known=%v unknown=%v", errKnown, errUnknown)
	}
	var ae1, ae2 *client.APIError
	if !errors.As(errKnown, &ae1) || !errors.As(errUnknown, &ae2) {
		t.Fatalf("expected APIError, got %T / %T", errKnown, errUnknown)
	}
	if ae1.Status != ae2.Status || ae1.Code != ae2.Code {
		t.Fatalf("failures distinguishable: known=%d/%s unknown=%d/%s",
			ae1.Status, ae1.Code, ae2.Status, ae2.Code)
	}
	if ae1.Status != http.StatusUnauthorized {
		t.Fatalf("unexpected status %d", ae1.Status)
	}
}

func TestHTTPMigrationOverTheWire(t *testing.T) {
	e := newEnv(t)
	const id = "legacy@example.com"
	const pw = "old-password-from-2019"

	// Seed a legacy row like the importer does.
	keys, err := loadKeys(e.kms)
	if err != nil {
		t.Fatal(err)
	}
	canonical, _ := ident.Canonicalize(id)
	acct := ident.AccountKey(keys.AccountPepper, canonical)
	credID := ident.CredentialID(keys.AccountPepper, acct)
	salt := bytesN(16, 3)
	digest, err := legacy.BCryptRaw([]byte(pw), salt, suite.LegacyDecoyCost)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := auth.SealLegacyDigest(mustRing(keys), acct, []byte(digest))
	if err != nil {
		t.Fatal(err)
	}
	if err := e.store.ImportLegacy(acct, credID, ident.Version, suite.ID, &store.Legacy{
		AccountKey: acct, Scheme: "bcrypt", Cost: suite.LegacyDecoyCost, Salt: salt, Hash: sealed,
	}); err != nil {
		t.Fatal(err)
	}

	c := e.client(t, id)
	if err := c.Login(e.ctx, pw); err != nil {
		t.Fatalf("migration login: %v", err)
	}
	// Second login is plain OPAQUE over HTTP.
	c2 := e.client(t, id)
	if err := c2.Login(e.ctx, pw); err != nil {
		t.Fatalf("post-migration login: %v", err)
	}
	// Legacy row is gone from the store.
	if _, err := e.store.GetLegacy(acct); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("legacy row survived: %v", err)
	}
}

func TestHTTPChangePassword(t *testing.T) {
	e := newEnv(t)
	c := e.client(t, "carol@example.com")
	if err := c.Register(e.ctx, "original-pw"); err != nil {
		t.Fatal(err)
	}
	if err := c.ChangePassword(e.ctx, "original-pw", "rotated-pw"); err != nil {
		t.Fatalf("change: %v", err)
	}
	// Old fails, new succeeds.
	if err := c.Login(e.ctx, "original-pw"); err == nil {
		t.Fatal("old password still works")
	}
	c2 := e.client(t, "carol@example.com")
	if err := c2.Login(e.ctx, "rotated-pw"); err != nil {
		t.Fatalf("new password: %v", err)
	}
}

func TestHTTPRecovery(t *testing.T) {
	e := newEnv(t)
	const id = "dana@example.com"
	c := e.client(t, id)
	if err := c.Register(e.ctx, "forgotten"); err != nil {
		t.Fatal(err)
	}
	// Recovery requires a contact; register one via a second account registration
	// is not possible (already exists), so store it directly with the service hook.
	keys, _ := loadKeys(e.kms)
	canonical, _ := ident.Canonicalize(id)
	acct := ident.AccountKey(keys.AccountPepper, canonical)
	if err := e.svc.SetRecoveryContact(acct, id); err != nil {
		t.Fatal(err)
	}
	// Request recovery over HTTP. The response must be a flat success.
	req, _ := http.NewRequest(http.MethodPost, e.srv.URL+"/v1/recover/start",
		strings.NewReader(`{"identifier":"`+id+`"}`))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("recover/start status %d", resp.StatusCode)
	}
	token := e.mailer.lastToken
	if token == "" {
		t.Fatal("no recovery token captured")
	}
	if e.mailer.lastTo != id {
		t.Fatalf("recovery mail sent to %q, want %q", e.mailer.lastTo, id)
	}

	const newPW = "replaced-password"
	// The client SDK has no recovery helper; exercise the endpoints directly
	// the way a recovery UI would.
	cc := e.client(t, id)
	_ = cc
	if err := recoverViaAPI(t, e, id, token, newPW); err != nil {
		t.Fatalf("recover: %v", err)
	}
	c3 := e.client(t, id)
	if err := c3.Login(e.ctx, newPW); err != nil {
		t.Fatalf("login with recovered password: %v", err)
	}
	if err := c3.Login(e.ctx, "forgotten"); err == nil {
		t.Fatal("old password works after recovery")
	}
}

func TestHTTPUnknownRecoveryIsIndistinguishable(t *testing.T) {
	e := newEnv(t)
	do := func(id string) int {
		req, _ := http.NewRequest(http.MethodPost, e.srv.URL+"/v1/recover/start",
			strings.NewReader(`{"identifier":"`+id+`"}`))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	a := do("exists@example.com")  // not registered
	b := do("alsonot@example.com") // also not
	if a != b || a != http.StatusOK {
		t.Fatalf("recovery responses differ: %d vs %d", a, b)
	}
}

func TestHTTPBodyLimit(t *testing.T) {
	e := newEnv(t)
	big := strings.Repeat("x", 2<<20)
	req, _ := http.NewRequest(http.MethodPost, e.srv.URL+"/v1/login/start",
		strings.NewReader(`{"identifier":"`+big+`"}`))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 == 2 {
		t.Fatalf("oversized body accepted with status %d", resp.StatusCode)
	}
}

// --- helpers ---

func bytes32(b byte) []byte { return bytesN(32, b) }
func bytesN(n int, b byte) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func mustSKM(t *testing.T) []byte {
	t.Helper()
	conf := suite.Configuration()
	seed := conf.GenerateOPRFSeed()
	sk, pk := conf.KeyGen()
	skm := &opaque.ServerKeyMaterial{
		PrivateKey: sk, PublicKeyBytes: pk.Encode(),
		OPRFGlobalSeed: seed, Identity: []byte(suite.ServerIdentity),
	}
	return skm.Encode()
}

// TestHTTPProofOfWorkUnlocksNewDevice is the end-to-end anti-lockout
// guarantee over HTTP: a victim on a new device, whose account budget has been
// drained by an attacker, is admitted after the client solves the challenge
// the server returns with 429. It exercises the real SDK retry path.
func TestHTTPProofOfWorkUnlocksNewDevice(t *testing.T) {
	e := newEnv(t)
	const id = "flooded-http@example.com"
	owner := e.client(t, id)
	if err := owner.Register(e.ctx, "real-password"); err != nil {
		t.Fatalf("register: %v", err)
	}

	// Drain the account failure budget from several distinct sources. The test
	// server sees one RemoteAddr, so we drive the limiter's source by setting
	// the trusted-edge header the API honours.
	for src := 0; src < 6; src++ {
		for i := 0; i < 5; i++ {
			att, err := client.New(e.ctx, e.srv.URL, id)
			if err != nil {
				t.Fatal(err)
			}
			att.HTTP = headerHTTP("bot-" + itoa(src))
			_ = att.Login(e.ctx, "wrong")
		}
	}

	// A new device from its own source is refused, then solves and retries.
	fresh, err := client.New(e.ctx, e.srv.URL, id)
	if err != nil {
		t.Fatal(err)
	}
	fresh.HTTP = headerHTTP("home")
	if err := fresh.Login(e.ctx, "real-password"); err != nil {
		t.Fatalf("client did not recover via proof-of-work: %v", err)
	}
	if fresh.Session == "" {
		t.Fatal("no session after PoW retry")
	}
}

func headerHTTP(src string) *http.Client {
	return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		r.Header.Set("X-Opaque-Source", src)
		return http.DefaultTransport.RoundTrip(r)
	})}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
