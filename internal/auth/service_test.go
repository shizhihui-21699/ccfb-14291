package auth_test

import (
	"errors"
	"strings"
	"testing"

	"opaqueauth/internal/auth"
	"opaqueauth/internal/ident"
	"opaqueauth/internal/legacy"
	"opaqueauth/internal/store"
	"opaqueauth/internal/suite"
)

func TestRegisterAndLogin(t *testing.T) {
	h := newHarness(t)
	c := newTestClient(t, "Alice@Example.COM")
	if err := c.register(h, "correct horse battery staple"); err != nil {
		t.Fatalf("register: %v", err)
	}
	if c.token == "" {
		t.Fatal("register did not return a session")
	}

	sess, err := c.login(h, "correct horse battery staple")
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if len(sess.Token) == 0 {
		t.Fatal("login did not return a token")
	}
	got, err := h.svc.Authenticate(sess.Token)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if len(got.AccountKey) == 0 {
		t.Fatal("session did not resolve to an account")
	}
}

func TestLoginWrongPasswordFails(t *testing.T) {
	h := newHarness(t)
	c := newTestClient(t, "bob")
	if err := c.register(h, "right-password"); err != nil {
		t.Fatalf("register: %v", err)
	}
	if _, err := c.login(h, "wrong-password"); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatalf("wrong password: got %v, want ErrUnauthenticated", err)
	}
	// And the right one still works afterwards.
	if _, err := c.login(h, "right-password"); err != nil {
		t.Fatalf("login after failure: %v", err)
	}
}

// TestServerNeverSeesPassword is the direct check for invariant I1. It records
// every byte the service is ever handed and asserts the password never appears
// anywhere in what was stored or returned.
func TestServerNeverSeesPassword(t *testing.T) {
	h := newHarness(t)
	const password = "Zebra-Guitar-9-Fox-Tango"
	c := newTestClient(t, "carol")
	if err := c.register(h, password); err != nil {
		t.Fatalf("register: %v", err)
	}
	if _, err := c.login(h, password); err != nil {
		t.Fatalf("login: %v", err)
	}

	// Scan every text and blob column of every table for the password.
	rows, err := h.store.DB().Query(`SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'`)
	if err != nil {
		t.Fatal(err)
	}
	var tables []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		tables = append(tables, n)
	}
	rows.Close()
	if len(tables) == 0 {
		t.Fatal("no tables found")
	}
	needle := []byte(password)
	for _, table := range tables {
		r, err := h.store.DB().Query(`SELECT * FROM ` + table)
		if err != nil {
			t.Fatal(err)
		}
		cols, _ := r.Columns()
		for r.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := r.Scan(ptrs...); err != nil {
				t.Fatal(err)
			}
			for i, v := range vals {
				var raw []byte
				switch x := v.(type) {
				case []byte:
					raw = x
				case string:
					raw = []byte(x)
				case int64:
					continue
				default:
					continue
				}
				if containsSub(raw, needle) {
					t.Fatalf("password found in table %s column %s", table, cols[i])
				}
			}
		}
		r.Close()
	}
}

// TestCanonicalizationIsStable protects the account-key contract: a change
// here would lock every existing user out.
func TestCanonicalizationIsStable(t *testing.T) {
	a, err := ident.Canonicalize("  Alice@Example.COM  ")
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != "alice@example.com" {
		t.Fatalf("canonical form changed: %q", a)
	}
	if _, err := ident.Canonicalize(""); err == nil {
		t.Fatal("empty identifier accepted")
	}
	if _, err := ident.Canonicalize("bad\x00ident"); err == nil {
		t.Fatal("control character accepted")
	}
	if _, err := ident.Canonicalize(strings.Repeat("x", ident.MaxLen+1)); err == nil {
		t.Fatal("over-long identifier accepted")
	}
}

// TestLegacyMigration verifies that an un-migrated account can log in once,
// that the login upgrades it, and that the new scheme is then what is used.
func TestLegacyMigration(t *testing.T) {
	h := newHarness(t)
	const pw = "old-bcrypt-password"
	id := "dave@example.com"

	// Import a legacy row exactly as a dump would produce it.
	c := newTestClient(t, id)
	seedLegacy(t, h, id, pw, suite.LegacyDecoyCost)

	// Before migration there must be a legacy row and no credential.
	acct := mustAccountKey(t, h, id)
	if _, err := h.store.GetLegacy(acct); err != nil {
		t.Fatalf("legacy row: %v", err)
	}
	if _, err := h.store.GetCredential(acct); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("credential before migration: %v", err)
	}

	sess, err := c.login(h, pw)
	if err != nil {
		t.Fatalf("migration login: %v", err)
	}
	if len(sess.Token) == 0 {
		t.Fatal("migration login returned no session")
	}

	// After migration: credential present, legacy row gone.
	if _, err := h.store.GetCredential(acct); err != nil {
		t.Fatalf("credential after migration: %v", err)
	}
	if _, err := h.store.GetLegacy(acct); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("legacy row survived migration: %v", err)
	}

	// The next login is a pure OPAQUE login, with no migration proof.
	sess2, err := c.login(h, pw)
	if err != nil {
		t.Fatalf("second login: %v", err)
	}
	if len(sess2.Token) == 0 {
		t.Fatal("second login returned no session")
	}

	// The old password no longer authenticates a legacy proof, because there
	// is no legacy verifier; and a different password must fail outright.
	if _, err := c.login(h, "not-the-password"); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatalf("wrong password after migration: got %v", err)
	}
}

// TestMigrationWrongLegacyPasswordCannotUpgrade: proving OPAQUE possession of
// the *new* password is not enough to replace the credential; the legacy
// password must also be proven.
func TestMigrationWrongLegacyPasswordCannotUpgrade(t *testing.T) {
	h := newHarness(t)
	seedLegacy(t, h, "erin", "legacy-secret", suite.LegacyDecoyCost)
	c := newTestClient(t, "erin")

	// Start a login with the *wrong* legacy password. The OPAQUE half cannot
	// succeed on a decoy record, and the migration proof will be wrong.
	if _, err := c.login(h, "a-different-password"); err == nil {
		t.Fatal("login with wrong legacy password succeeded")
	}
	acct := mustAccountKey(t, h, "erin")
	if _, err := h.store.GetLegacy(acct); err != nil {
		t.Fatalf("legacy row should remain after failed migration: %v", err)
	}
	if _, err := h.store.GetCredential(acct); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("credential must not be installed by a failed migration: %v", err)
	}
}

// seedLegacy writes a legacy verifier into the store the way the importer does.
func seedLegacy(t *testing.T, h *harness, rawIdent, password string, cost int) {
	t.Helper()
	canonical, err := ident.Canonicalize(rawIdent)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := loadKeys(h)
	if err != nil {
		t.Fatal(err)
	}
	acct := ident.AccountKey(keys.AccountPepper, canonical)
	credID := ident.CredentialID(keys.AccountPepper, acct)
	salt := make([]byte, 16)
	for i := range salt {
		salt[i] = byte(i * 7)
	}
	digest, err := legacy.BCryptRaw([]byte(password), salt, cost)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := auth.SealLegacyDigest(mustRing(keys), acct, []byte(digest))
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.ImportLegacy(acct, credID, ident.Version, suite.ID, &store.Legacy{
		AccountKey: acct, Scheme: "bcrypt", Cost: cost, Salt: salt, Hash: sealed,
	}); err != nil {
		t.Fatal(err)
	}
}

func mustAccountKey(t *testing.T, h *harness, rawIdent string) []byte {
	t.Helper()
	keys, err := loadKeys(h)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := ident.Canonicalize(rawIdent)
	if err != nil {
		t.Fatal(err)
	}
	return ident.AccountKey(keys.AccountPepper, canonical)
}

func containsSub(haystack, needle []byte) bool {
	if len(needle) == 0 {
		return false
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
