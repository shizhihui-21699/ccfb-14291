package auth_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/bytemare/opaque"
	"opaqueauth/internal/auth"

	"opaqueauth/internal/keyring"
	"opaqueauth/internal/keys"
	"opaqueauth/internal/kms"
	"opaqueauth/internal/legacy"
	"opaqueauth/internal/pow"
	"opaqueauth/internal/ratelimit"
	"opaqueauth/internal/store"
	"opaqueauth/internal/suite"
)

// cheapProfile is an Argon2id profile the tests can afford to run thousands of
// times. It is registered explicitly so that the production profile remains the
// default everywhere else.
var cheapProfile = suite.KSFProfile{
	ID: "test-argon2id-cheap", Time: 1, Memory: 8 * 1024, Threads: 1, Length: 64,
}

func init() { suite.RegisterProfile(cheapProfile) }

// harness is a fully wired in-process service for tests.
type harness struct {
	t     *testing.T
	svc   *auth.Service
	store *store.Store
	kms   *kms.MemoryProvider
	clock *testClock
	lim   *ratelimit.Limiter
	path  string
}

type testClock struct {
	now time.Time
}

func (c *testClock) Now() time.Time          { return c.now }
func (c *testClock) Advance(d time.Duration) { c.now = c.now.Add(d) }

// newHarness builds a service backed by a temporary SQLite file and an
// in-memory KMS. Provisioning is done the same way authctl does it, so the
// tests exercise the real key material format.
func newHarness(t *testing.T) *harness {
	t.Helper()
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "auth.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	prov := kms.NewMemoryProvider()
	root := make([]byte, 32)
	for i := range root {
		root[i] = byte(i + 1)
	}
	prov.Set(kms.AppRoot, root)
	skm, err := provisionServerKeyMaterial(t)
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	prov.Set(kms.OPAQUEServerKeyMaterial, skm)

	clk := &testClock{now: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	db.Now = clk.Now
	lim := ratelimit.New(ratelimit.DefaultPolicy())
	lim.SetClock(clk.Now)
	ch := pow.New(make([]byte, 32), 8, 10*time.Minute)
	ch.SetClock(clk.Now)

	svc, err := auth.New(auth.Config{
		Store: db, KMS: prov, Limiter: lim, Pow: ch, Now: clk.Now, KSF: cheapProfile,
	})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	return &harness{t: t, svc: svc, store: db, kms: prov, clock: clk, lim: lim, path: filepath.Join(dir, "auth.db")}
}

// storePath returns the database path for dump tests.
func (h *harness) storePath(t *testing.T) string { return h.path }

// loadKeys exposes the derived application keys to tests (the service keeps
// them private).
func loadKeys(h *harness) (*keys.Keys, error) { return keys.Load(h.kms) }

// newHarnessProd is newHarness wired with the production KSF profile, for
// latency and end-to-end tests that must reflect real parameters.
func newHarnessProd(t *testing.T) *harness {
	t.Helper()
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	prov := kms.NewMemoryProvider()
	prov.Set(kms.AppRoot, bytes32(3))
	prov.Set(kms.OPAQUEServerKeyMaterial, mustSKMProd(t))
	clk := &testClock{now: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	db.Now = clk.Now
	lim := ratelimit.New(ratelimit.DefaultPolicy())
	lim.SetClock(clk.Now)
	ch := pow.New(bytes32(9), 8, 10*time.Minute)
	ch.SetClock(clk.Now)
	svc, err := auth.New(auth.Config{
		Store: db, KMS: prov, Limiter: lim, Pow: ch, Now: clk.Now, KSF: suite.ProfileV1,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &harness{t: t, svc: svc, store: db, kms: prov, clock: clk, lim: lim, path: filepath.Join(dir, "auth.db")}
}

func mustSKMProd(t *testing.T) []byte {
	t.Helper()
	conf := suite.Configuration()
	seed := conf.GenerateOPRFSeed()
	sk, pk := conf.KeyGen()
	return (&opaque.ServerKeyMaterial{PrivateKey: sk, PublicKeyBytes: pk.Encode(),
		OPRFGlobalSeed: seed, Identity: []byte(suite.ServerIdentity)}).Encode()
}

func bytes32(b byte) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = b
	}
	return out
}

// mustRing builds a version-1 keyring from loaded keys.
func mustRing(k *keys.Keys) *keyring.Ring {
	r, err := keyring.New(1, k.LegacyVerifier, nil)
	if err != nil {
		panic(err)
	}
	return r
}

// legacyRawFn is the bcrypt helper for rotation tests.
func legacyRawFn(password string, salt []byte) (string, error) {
	return legacy.BCryptRaw([]byte(password), salt, suite.LegacyDecoyCost)
}
