package auth_test

import (
	"testing"
	"time"

	"opaqueauth/internal/auth"
	"opaqueauth/internal/ident"
	"opaqueauth/internal/keyring"
	"opaqueauth/internal/kms"
	"opaqueauth/internal/pow"
	"opaqueauth/internal/ratelimit"
	"opaqueauth/internal/store"
	"opaqueauth/internal/suite"
)

// TestLegacyKeyRotationDoesNotOrphanUsers is the point of the keyring: a KMS
// root rotation must not turn un-migrated users into unrecoverable accounts.
//
// The test seeds a legacy user under key version 1, rotates to version 2 with
// version 1 retained, and checks that (a) the user can still log in and migrate
// during the rollover window, and (b) after rewrap and retaining-key removal,
// the stored blob is under version 2 and the login still works.
func TestLegacyKeyRotationDoesNotOrphanUsers(t *testing.T) {
	v1 := bytesN(32, 0x11)
	v2 := bytesN(32, 0x22)

	dir := t.TempDir()
	db, err := store.Open(dir + "/auth.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	prov := kms.NewMemoryProvider()
	prov.Set(kms.AppRoot, bytesN(32, 3))
	prov.Set(kms.OPAQUEServerKeyMaterial, mustSKMProd(t))
	clk := &testClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	db.Now = clk.Now
	ring1, _ := keyring.New(1, v1, nil)
	lim := ratelimit.New(ratelimit.DefaultPolicy())
	lim.SetClock(clk.Now)
	ch := pow.New(bytesN(32, 9), 8, time.Minute)
	if _, err := auth.New(auth.Config{Store: db, KMS: prov, Limiter: lim, Pow: ch, Now: clk.Now, KSF: cheapProfile, LegacyRing: ring1}); err != nil {
		t.Fatal(err)
	}

	// Seed a legacy user with a digest sealed under v1.
	keys, _ := loadKeys(&harness{kms: prov})
	canonical, _ := ident.Canonicalize("rotate@example.com")
	acct := ident.AccountKey(keys.AccountPepper, canonical)
	credID := ident.CredentialID(keys.AccountPepper, acct)
	salt := bytesN(16, 5)
	digest, err := legacyRaw("rotation-password", salt)
	if err != nil {
		t.Fatal(err)
	}
	sealedV1, err := auth.SealLegacyDigest(ring1, acct, []byte(digest))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.ImportLegacy(acct, credID, ident.Version, suite.ID, &store.Legacy{
		AccountKey: acct, Scheme: "bcrypt", Cost: suite.LegacyDecoyCost, Salt: salt, Hash: sealedV1,
	}); err != nil {
		t.Fatal(err)
	}

	// Rotate: version 2 active, version 1 retained.
	ring2, err := keyring.New(2, v2, map[uint32][]byte{1: v1})
	if err != nil {
		t.Fatal(err)
	}
	svc2, err := auth.New(auth.Config{Store: db, KMS: prov, Limiter: lim, Pow: ch, Now: clk.Now, KSF: cheapProfile, LegacyRing: ring2})
	if err != nil {
		t.Fatal(err)
	}

	// During the window the user logs in and migrates; the old ciphertext is
	// read via the retained key.
	c := newTestClient(t, "rotate@example.com")
	if _, err := c.login(hFor(svc2, db, prov, clk), "rotation-password"); err != nil {
		t.Fatalf("login during rotation window: %v", err)
	}

	// A second, still-un-migrated user is rewrapped and must survive retiring v1.
	canonical2, _ := ident.Canonicalize("still-legacy@example.com")
	acct2 := ident.AccountKey(keys.AccountPepper, canonical2)
	sealedV1b, _ := auth.SealLegacyDigest(ring1, acct2, []byte(digest))
	if err := db.ImportLegacy(acct2, ident.CredentialID(keys.AccountPepper, acct2), ident.Version, suite.ID, &store.Legacy{
		AccountKey: acct2, Scheme: "bcrypt", Cost: suite.LegacyDecoyCost, Salt: salt, Hash: sealedV1b,
	}); err != nil {
		t.Fatal(err)
	}
	moved, err := ring2.Rewrap(auth.LegacyDigestAAD(acct2), sealedV1b)
	if err != nil {
		t.Fatalf("rewrap: %v", err)
	}
	if err := db.SetLegacyHash(acct2, moved); err != nil {
		t.Fatal(err)
	}
	// Now build a ring with v1 gone; the rewrapped row must still open.
	ring3, _ := keyring.New(2, v2, nil)
	if _, err := auth.OpenLegacyDigest(ring3, acct2, moved); err != nil {
		t.Fatalf("rewrapped ciphertext unreadable without v1: %v", err)
	}
	svc3, err := auth.New(auth.Config{Store: db, KMS: prov, Limiter: lim, Pow: ch, Now: clk.Now, KSF: cheapProfile, LegacyRing: ring3})
	if err != nil {
		t.Fatal(err)
	}
	c3 := newTestClient(t, "still-legacy@example.com")
	if _, err := c3.login(hFor(svc3, db, prov, clk), "rotation-password"); err != nil {
		t.Fatalf("login after v1 retirement: %v", err)
	}
}

func hFor(svc *auth.Service, db *store.Store, prov *kms.MemoryProvider, clk *testClock) *harness {
	return &harness{t: nil, svc: svc, store: db, kms: prov, clock: clk}
}

func legacyRaw(password string, salt []byte) (string, error) {
	return legacyRawFn(password, salt)
}

func bytesN(n int, b byte) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

// TestContactSurvivesRotation: recovery addresses use the same versioned ring,
// so a rotation during the migration window cannot silently drop them (which
// would strand users who both forgot their password and never migrated).
func TestContactSurvivesRotation(t *testing.T) {
	v1 := bytesN(32, 0x31)
	v2 := bytesN(32, 0x32)
	dir := t.TempDir()
	db, err := store.Open(dir + "/auth.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	prov := kms.NewMemoryProvider()
	prov.Set(kms.AppRoot, bytesN(32, 4))
	prov.Set(kms.OPAQUEServerKeyMaterial, mustSKMProd(t))
	clk := &testClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	db.Now = clk.Now
	lim := ratelimit.New(ratelimit.DefaultPolicy())
	lim.SetClock(clk.Now)
	ch := pow.New(bytesN(32, 9), 8, time.Minute)
	r1, _ := keyring.New(1, v1, nil)
	s1, err := auth.New(auth.Config{Store: db, KMS: prov, Limiter: lim, Pow: ch, Now: clk.Now, KSF: cheapProfile, LegacyRing: r1})
	if err != nil {
		t.Fatal(err)
	}
	keys, _ := loadKeys(&harness{kms: prov})
	canonical, _ := ident.Canonicalize("contact@example.com")
	acct := ident.AccountKey(keys.AccountPepper, canonical)
	// contacts has a foreign key to accounts; create the account first.
	c := newTestClient(t, "contact@example.com")
	if err := c.register(hFor(s1, db, prov, clk), "pw"); err != nil {
		t.Fatal(err)
	}
	if err := s1.SetRecoveryContact(acct, "person@example.net"); err != nil {
		t.Fatal(err)
	}
	r2, _ := keyring.New(2, v2, map[uint32][]byte{1: v1})
	s2, err := auth.New(auth.Config{Store: db, KMS: prov, Limiter: lim, Pow: ch, Now: clk.Now, KSF: cheapProfile, LegacyRing: r2})
	if err != nil {
		t.Fatal(err)
	}
	got, ok := s2.OpenContact(acct)
	if !ok || got != "person@example.net" {
		t.Fatalf("contact lost across rotation: %q ok=%v", got, ok)
	}

}
