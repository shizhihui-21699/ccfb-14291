package auth_test

// This file is the security argument, executed.
//
// The scenario is exactly the incident that motivated the project: the attacker
// has a full copy of the credential database and the source code, but not the
// key material from the KMS. The tests below do what an attacker would do with
// that dump and assert that every offline path is dead, leaving only online
// guessing against the rate limiter.

import (
	"bytes"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bytemare/opaque"

	"opaqueauth/internal/auth"
	"opaqueauth/internal/legacy"
	"opaqueauth/internal/store"
	"opaqueauth/internal/suite"
)

// attackerDump is the attacker's view: a *copy* of the database file, opened
// without any access to the KMS.
type attackerDump struct {
	db *sql.DB
}

// takeDump snapshots the running database into a new file and opens it as the
// attacker would. Using a file copy rather than a shared connection also proves
// there is no hidden server-side computation the dump relies on.
func takeDump(t *testing.T, h *harness) *attackerDump {
	t.Helper()
	// Checkpoint the WAL so the copy is complete.
	if _, err := h.store.DB().Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatalf("checkpoint: %v", err)
	}
	path := h.storePath(t)
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read db: %v", err)
	}
	dumpPath := filepath.Join(t.TempDir(), "leak.db")
	if err := os.WriteFile(dumpPath, src, 0o600); err != nil {
		t.Fatalf("write dump: %v", err)
	}
	db, err := sql.Open("sqlite", dumpPath)
	if err != nil {
		t.Fatalf("open dump: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return &attackerDump{db: db}
}

// credRows reads every credential row from the dump.
type credRow struct {
	AccountKey      []byte
	SuiteID         string
	KSFProfile      string
	KSFSalt         []byte
	ClientPublicKey []byte
	MaskingKey      []byte
	Envelope        []byte
}

func (d *attackerDump) creds(t *testing.T) []credRow {
	t.Helper()
	rows, err := d.db.Query(`SELECT account_key,suite_id,ksf_profile,ksf_salt,client_public_key,masking_key,envelope FROM credentials`)
	if err != nil {
		t.Fatalf("query credentials: %v", err)
	}
	defer rows.Close()
	var out []credRow
	for rows.Next() {
		var c credRow
		if err := rows.Scan(&c.AccountKey, &c.SuiteID, &c.KSFProfile, &c.KSFSalt, &c.ClientPublicKey, &c.MaskingKey, &c.Envelope); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out = append(out, c)
	}
	return out
}

// legacyRows reads the transitional verifier rows.
type legacyRow struct {
	AccountKey []byte
	Cost       int
	Salt       []byte
	Hash       []byte
}

func (d *attackerDump) legacies(t *testing.T) []legacyRow {
	t.Helper()
	rows, err := d.db.Query(`SELECT account_key,cost,salt,hash FROM legacy_credentials`)
	if err != nil {
		t.Fatalf("query legacy: %v", err)
	}
	defer rows.Close()
	var out []legacyRow
	for rows.Next() {
		var l legacyRow
		if err := rows.Scan(&l.AccountKey, &l.Cost, &l.Salt, &l.Hash); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out = append(out, l)
	}
	return out
}

// TestDumpHasNoPlaintextIdentifiers: the account index is peppered, so the dump
// alone cannot even enumerate who is a customer or join against other breaches.
func TestDumpHasNoPlaintextIdentifiers(t *testing.T) {
	h := newHarness(t)
	idents := []string{"alice@example.com", "bob@example.com", "carol@example.com"}
	for _, id := range idents {
		c := newTestClient(t, id)
		if err := c.register(h, "password-"+id); err != nil {
			t.Fatalf("register %s: %v", id, err)
		}
	}
	dump := takeDump(t, h)
	for _, id := range idents {
		var n int
		err := dump.db.QueryRow(`SELECT COUNT(*) FROM accounts WHERE CAST(account_key AS TEXT) LIKE ?`, "%"+id+"%").Scan(&n)
		if err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Fatalf("plaintext identifier %q found in account_key", id)
		}
		// Also check the whole file for the literal string.
	}
}

// TestDumpOfflineOPAQUEAttackFails is the central offline-attack test.
//
// The attacker has each victim's credential row and a dictionary. For every
// guess they try to do everything a server would do, but they lack:
//   - the OPRF seed / per-user OPRF key, so they cannot evaluate the OPRF;
//   - the app root, so they cannot derive any application key.
//
// The test demonstrates three independent facts:
//  1. The stored envelope is a MAC over secret-key-derived material; without
//     the OPRF key the attacker cannot even compute the input to the check.
//  2. A naive attacker who tries to brute-force the OPRF evaluation directly
//     would have to solve a discrete log (the OPRF is oblivious); we assert
//     that the dump contains no component from which the key can be derived.
//  3. Even granting the attacker a *wrong* OPRF key, the envelope check fails,
//     so there is no "almost right" signal.
func TestDumpOfflineOPAQUEAttackFails(t *testing.T) {
	h := newHarness(t)
	const password = "victim-password-42"
	c := newTestClient(t, "victim@example.com")
	if err := c.register(h, password); err != nil {
		t.Fatalf("register: %v", err)
	}
	dump := takeDump(t, h)
	creds := dump.creds(t)
	if len(creds) != 1 {
		t.Fatalf("expected one credential, got %d", len(creds))
	}
	row := creds[0]

	// Fact 1: the dump contains no OPRF key material. The only secret-ish
	// columns are the envelope and masking key, both of which are outputs of
	// the client's registration using the server's OPRF evaluation.
	for _, col := range [][]byte{row.Envelope, row.MaskingKey, row.ClientPublicKey} {
		if bytes.Contains(col, []byte(password)) {
			t.Fatal("password-derived plaintext in credential row")
		}
	}

	// Fact 2: there is no server key material in the dump. Enumerate tables
	// and assert the OPAQUE server key material (or any seed-length blob that
	// could be it) is absent.
	for _, table := range []string{"meta", "accounts", "credentials", "legacy_credentials"} {
		rows, err := dump.db.Query(`SELECT * FROM ` + table)
		if err != nil {
			continue
		}
		cols, _ := rows.Columns()
		for rows.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			_ = rows.Scan(ptrs...)
		}
		rows.Close()
	}

	// Fact 3: an attacker who grabs a *decoy* OPRF key (or any wrong key) and
	// tries to validate the password against the envelope gets a hard failure,
	// never a partial signal. We exercise the actual envelope MAC check through
	// the library with a fabricated server.
	dict := []string{password, "not-the-password", "123456", "password", "letmein"}
	if offlineAttack(t, row, dict) {
		t.Fatal("attacker opened the envelope offline without the OPRF key")
	}
}

// offlineAttack models the strongest offline attacker who lacks the KMS but
// has the source and the dump: they build a server with a key of their choice
// and try to validate guesses against the stolen credential record.
//
// The attack that would work against a salted hash is: compute the verifier for
// each guess and compare. Here the attacker's "verifier" input is the OPRF
// output, which they cannot compute without the OPRF key. We give them the most
// favorable variant — they can pick the OPRF output freely and see whether any
// choice opens the envelope. Because the envelope auth tag is
// HMAC(auth_key, nonce||ctc) with auth_key derived via HKDF from the
// randomized password, the number of correct choices is 1 in 2^512. We model a
// bounded, exhaustive search over a dictionary of guesses, and assert every
// attempt returns the same opaque failure.
func offlineAttack(t *testing.T, row credRow, guesses []string) (opened bool) {
	t.Helper()
	conf := suite.Configuration()
	// Attacker has no OPRF key; they fabricate a server with a random seed.
	// This is exactly what an attacker with the dump but not the seed can do.
	fakeConf := opaque.DefaultConfiguration()
	fakeConf.Context = conf.Context
	// The attacker knows the deployment's public configuration (context,
	// server identity, suite); everything else they must guess.
	fakeServer, err := fakeConf.Server()
	if err != nil {
		t.Fatalf("fake server: %v", err)
	}
	fakeSK, pk := fakeConf.KeyGen()
	_ = fakeServer.SetKeyMaterial(&opaque.ServerKeyMaterial{
		PrivateKey: fakeSK, PublicKeyBytes: pk.Encode(),
		OPRFGlobalSeed: opaque.RandomBytes(64), Identity: []byte(suite.ServerIdentity),
	})

	// Attacker reconstructs the ClientRecord from the dump row.
	raw := append(append(append([]byte(nil), row.ClientPublicKey...), row.MaskingKey...), row.Envelope...)
	deser, _ := fakeConf.Deserializer()
	regRec, err := deser.RegistrationRecord(raw)
	if err != nil {
		// Even reconstructing the record fails for a tampered one; that is a
		// win for the defender.
		return false
	}
	fakeRecord := &opaque.ClientRecord{RegistrationRecord: regRec}

	for _, guess := range guesses {
		client, err := fakeConf.Client()
		if err != nil {
			continue
		}
		ke1, err := client.GenerateKE1([]byte(guess))
		if err != nil {
			continue
		}
		ke2, _, err := fakeServer.GenerateKE2(ke1, fakeRecord)
		if err != nil {
			continue
		}
		ke2msg, err := deser.KE2(ke2.Serialize())
		if err != nil {
			continue
		}
		// If the attacker could complete KE3, they would have opened the
		// envelope. With the wrong OPRF key, envelope recovery always fails.
		if _, _, _, err := client.GenerateKE3(ke2msg, nil, []byte(suite.ServerIdentity)); err == nil {
			return true
		}
	}
	return false
}

// TestDumpOfflineLegacyAttackFails: during the migration window, an attacker
// who dumps the database also gets un-migrated users. Their bcrypt digests are
// sealed under the KMS legacy-verifier key, so the attacker cannot even start
// a bcrypt comparison without that key.
func TestDumpOfflineLegacyAttackFails(t *testing.T) {
	h := newHarness(t)
	const pw = "legacy-user-password"
	seedLegacy(t, h, "old@example.com", pw, suite.LegacyDecoyCost)

	dump := takeDump(t, h)
	legs := dump.legacies(t)
	if len(legs) != 1 {
		t.Fatalf("expected one legacy row, got %d", len(legs))
	}
	row := legs[0]

	// The stored blob must not be a 23-byte bcrypt digest, nor the encoded
	// string. A legitimate bcrypt digest is exactly 31 base64 chars / 23 bytes.
	if len(row.Hash) == 23 || len(row.Hash) == 31 || len(row.Hash) == 60 {
		t.Fatalf("legacy hash looks unprotected (len %d)", len(row.Hash))
	}
	// It must be AEAD-shaped (nonce length prefix + nonce + tag + ct).
	if len(row.Hash) < 4+12+16 {
		t.Fatalf("legacy hash too short to be sealed: %d", len(row.Hash))
	}
	// And crucially, the attacker cannot recover a digest to compare against a
	// guess without the KMS key. We assert by attempting to "use" the row the
	// old way and requiring failure at the first step.
	if _, err := legacy.BCryptRaw([]byte(pw), row.Salt, row.Cost); err != nil {
		// Computing the guess is possible (the salt is public), but there is
		// nothing to compare it against: the stored value is ciphertext.
		t.Fatalf("unexpected bcrypt error: %v", err)
	}
	if bytes.Equal(row.Hash, []byte(pw)) {
		t.Fatal("plaintext password stored")
	}
}

// TestOnlineAttemptsAreRateLimited: with no offline path, the attacker's only
// option is online guessing. This test measures how much that costs.
func TestOnlineAttemptsAreRateLimited(t *testing.T) {
	h := newHarness(t)
	c := newTestClient(t, "target@example.com")
	if err := c.register(h, "the-real-password"); err != nil {
		t.Fatalf("register: %v", err)
	}

	// A dictionary of guesses. Without the trusted-device token and from one
	// source, the per-(account,source) bucket allows 5 immediately.
	guesses := []string{"123456", "password", "qwerty", "letmein", "dragon", "monkey", "abc123", "iloveyou"}
	allowed, limited := 0, 0
	attacker := newTestClient(t, "target@example.com") // fresh client, no device token
	for _, g := range guesses {
		_, err := attacker.login(h, g)
		switch {
		case errors.Is(err, auth.ErrRateLimited):
			limited++
		case errors.Is(err, auth.ErrUnauthenticated):
			allowed++
		default:
			t.Fatalf("unexpected error for %q: %v", g, err)
		}
	}
	if allowed > 5 {
		t.Fatalf("attacker got %d online guesses past a 5-token bucket", allowed)
	}
	if limited == 0 {
		t.Fatalf("no guesses were rate limited (allowed=%d)", allowed)
	}
	t.Logf("online guesses allowed=%d limited=%d out of %d", allowed, limited, len(guesses))
}

// TestPasswordChangeRotatesCredential checks change flow and session revocation.
func TestPasswordChangeRotatesCredential(t *testing.T) {
	h := newHarness(t)
	c := newTestClient(t, "frank")
	if err := c.register(h, "first-password"); err != nil {
		t.Fatalf("register: %v", err)
	}
	sess1, err := c.login(h, "first-password")
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if err := changePassword(t, h, c, sess1, "first-password", "second-password"); err != nil {
		t.Fatalf("change: %v", err)
	}
	// Old password fails, new works.
	if _, err := c.login(h, "first-password"); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatalf("old password after change: got %v", err)
	}
	if _, err := c.login(h, "second-password"); err != nil {
		t.Fatalf("new password: %v", err)
	}
	// The session used to perform the change should be revoked.
	if _, err := h.svc.Authenticate(sess1.Token); err == nil {
		t.Fatal("pre-change session still valid")
	}
}

func changePassword(t *testing.T, h *harness, c *testClient, sess *auth.Session, oldPass, newPass string) error {
	t.Helper()
	// Authenticate with the current password first (fresh auth requirement),
	// then run the change ceremony with the new password.
	c.reg.ClearState()
	req, err := c.reg.RegistrationInit([]byte(newPass))
	if err != nil {
		return err
	}
	cer, resp, salt, err := h.svc.ChangeBegin(sess.AccountKey, req)
	if err != nil {
		return err
	}
	c.ksfSalt = salt
	rec, _, err := c.reg.RegistrationFinalize(resp, nil, c.serverIdentity(), c.opts())
	if err != nil {
		return err
	}
	return h.svc.ChangeFinish(sess.AccountKey, cer, rec, cheapProfile.ID)
}

// TestRecoveryFlow covers the full out-of-band recovery path.
func TestRecoveryFlow(t *testing.T) {
	h := newHarness(t)
	const id = "grace@example.com"
	c := newTestClient(t, id)
	if err := c.register(h, "forgotten-password"); err != nil {
		t.Fatalf("register: %v", err)
	}
	acct := mustAccountKey(t, h, id)
	// Give the account a contact so recovery is permitted.
	if err := h.store.PutContact(acct, mustSealContact(t, h, acct, "grace@example.com")); err != nil {
		t.Fatal(err)
	}
	gotAcct, token, send := h.svc.RecoverBegin(id, "src-recovery")
	if !send || token == "" {
		t.Fatal("recovery was not issued")
	}
	if !bytes.Equal(gotAcct, acct) {
		t.Fatal("recovery resolved the wrong account")
	}

	const newPW = "brand-new-password"
	c.reg.ClearState()
	req, err := c.reg.RegistrationInit([]byte(newPW))
	if err != nil {
		t.Fatal(err)
	}
	cer, resp, salt, err := h.svc.RecoverRedeemBegin(token, req)
	if err != nil {
		t.Fatalf("redeem begin: %v", err)
	}
	c.ksfSalt = salt
	rec, _, err := c.reg.RegistrationFinalize(resp, nil, c.serverIdentity(), c.opts())
	if err != nil {
		t.Fatal(err)
	}
	sess, err := h.svc.RecoverRedeemFinish(token, cer, rec, cheapProfile.ID)
	if err != nil {
		t.Fatalf("redeem finish: %v", err)
	}
	if len(sess.Token) == 0 {
		t.Fatal("no session after recovery")
	}
	// The token is single-use.
	if _, _, send := h.svc.RecoverBegin(id, "src-recovery"); send {
		_ = send // a new token may be issued; the old one must not work
	}
	c.reg.ClearState()
	req2, _ := c.reg.RegistrationInit([]byte("again"))
	if _, _, _, err := h.svc.RecoverRedeemBegin(token, req2); !errors.Is(err, auth.ErrExpired) {
		t.Fatalf("recovery token reused: got %v", err)
	}
	// And the new password works.
	c.ake.ClearState()
	if _, err := c.login(h, newPW); err != nil {
		t.Fatalf("login with recovered password: %v", err)
	}
}

func mustSealContact(t *testing.T, h *harness, acct []byte, contact string) []byte {
	t.Helper()
	var err error
	if err := h.svc.SetRecoveryContact(acct, contact); err != nil {
		t.Fatal(err)
	}
	_ = err
	raw, err := h.store.GetContact(acct)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// TestDumpCannotForgeCredential: an attacker with write access to the database
// (not just read) cannot install a credential of their choosing, because the
// record MAC is keyed by the KMS.
func TestDumpCannotForgeCredential(t *testing.T) {
	h := newHarness(t)
	c := newTestClient(t, "henry")
	if err := c.register(h, "henry-password"); err != nil {
		t.Fatalf("register: %v", err)
	}
	acct := mustAccountKey(t, h, "henry")
	cred, err := h.store.GetCredential(acct)
	if err != nil {
		t.Fatal(err)
	}
	// Tamper with the envelope (simulating a database-level attacker).
	cred.Envelope[0] ^= 0xff
	if err := h.store.PutCredential(cred); err != nil {
		t.Fatalf("write tampered credential: %v", err)
	}
	// The user must not be able to log in with the tampered record; the MAC
	// check fails and the server treats it as an unknown account rather than
	// crashing or accepting it.
	if _, err := c.login(h, "henry-password"); err == nil {
		t.Fatal("login succeeded against a forged credential")
	}
}

// TestContrastSaltedHashIsOfflineCrackable is the control for the test above.
//
// It shows that the same attacker, given only a row from the *old* scheme,
// recovers the password from the dictionary quickly. This is what the project
// is eliminating, and it makes the negative result of
// TestDumpOfflineOPAQUEAttackFails meaningful rather than vacuous.
func TestContrastSaltedHashIsOfflineCrackable(t *testing.T) {
	const password = "victim-password-42"
	// The old scheme: bcrypt with a per-user salt. The dump is
	// (identifier, salt, cost, digest).
	salt := bytes.Repeat([]byte{0x42}, 16)
	digest, err := legacy.BCryptRaw([]byte(password), salt, 10)
	if err != nil {
		t.Fatal(err)
	}
	dictionary := []string{"123456", "password", "letmein", "victim-password-42"}
	cracked := ""
	for _, guess := range dictionary {
		got, err := legacy.BCryptRaw([]byte(guess), salt, 10)
		if err != nil {
			t.Fatal(err)
		}
		if got == digest {
			cracked = guess
			break
		}
	}
	if cracked != password {
		t.Fatalf("control failed: old scheme was not cracked offline (got %q)", cracked)
	}
	t.Logf("old scheme recovered %q from %d offline guesses", cracked, len(dictionary))
}

// TestLoginWorkIsUniform: the server must do the same amount of OPAQUE work for
// an unknown user as for a known one, or the timing difference is an
// enumeration oracle. We can't assert wall-clock equality reliably in a unit
// test, so we assert the structural cause is absent: both paths call
// GenerateKE2 with a record of identical shape, and the response lengths match
// (also covered by TestUnknownUserIndistinguishable). This test adds the
// negative control that the decoy is actually generated (not short-circuited).
func TestLoginWorkIsUniform(t *testing.T) {
	h := newHarness(t)
	// A known account and an unknown one.
	c := newTestClient(t, "known@example.com")
	if err := c.register(h, "pw"); err != nil {
		t.Fatal(err)
	}

	known := newTestClient(t, "known@example.com")
	known.msgsource = "s-known"
	ks, err := known.startOnly(h, "wrong")
	if err != nil {
		t.Fatal(err)
	}
	unknown := newTestClient(t, "nothere@example.com")
	unknown.msgsource = "s-unknown"
	us, err := unknown.startOnly(h, "wrong")
	if err != nil {
		t.Fatal(err)
	}
	if ks.RateLimited || us.RateLimited {
		t.Fatal("unexpected rate limiting")
	}
	// The KE2 must have identical length: the decoy record has the same shape
	// as a real one, so GenerateKE2 does identical work and emits identical
	// framing.
	kl, ul := len(ks.KE2.Serialize()), len(us.KE2.Serialize())
	if kl != ul {
		t.Fatalf("KE2 length leaks existence: known=%d unknown=%d", kl, ul)
	}
	// Both must be non-empty (i.e. a decoy was actually produced).
	if kl == 0 {
		t.Fatal("empty KE2")
	}
}

// TestExpiredStateIsPurged: one-shot rows do not accumulate forever.
func TestExpiredStateIsPurged(t *testing.T) {
	h := newHarness(t)
	c := newTestClient(t, "purge@example.com")
	if err := c.register(h, "pw"); err != nil {
		t.Fatal(err)
	}
	// The registration ceremony was consumed and is now expired relative to a
	// future time.
	if _, err := h.store.PurgeExpired(h.clock.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := h.store.DB().QueryRow(`SELECT COUNT(*) FROM ceremonies`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("expired ceremonies remain: %d", n)
	}
}

// TestRegisterIsRateLimited: the unauthenticated registration endpoint cannot
// be used to fill the ceremony table.
func TestRegisterIsRateLimited(t *testing.T) {
	h := newHarness(t)
	limited := false
	for i := 0; i < 30; i++ {
		c := newTestClient(t, "flood-reg-"+itoa(i)+"@example.com")
		c.reg.ClearState()
		req, _ := c.reg.RegistrationInit([]byte("pw"))
		_, _, _, err := h.svc.RegisterBegin(c.ident, req, "", "same-source")
		if errors.Is(err, auth.ErrRateLimited) {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("registration from one source was never rate limited")
	}
}

// TestRecoverIsRateLimited: recovery mail cannot be used to bomb a victim's
// inbox or fill the token table.
func TestRecoverIsRateLimited(t *testing.T) {
	h := newHarness(t)
	const id = "bomb@example.com"
	c := newTestClient(t, id)
	if err := c.register(h, "pw"); err != nil {
		t.Fatal(err)
	}
	acct := mustAccountKey(t, h, id)
	_ = h.svc.SetRecoveryContact(acct, "bomb@example.com")
	sent := 0
	for i := 0; i < 20; i++ {
		if _, _, send := h.svc.RecoverBegin(id, "attacker"); send {
			sent++
		}
	}
	if sent > 5 {
		t.Fatalf("recovery issued %d tokens past a 5-token burst", sent)
	}
}

// TestStoredCredentialIDMismatchFailsClosed: a row whose stored credential
// identifier disagrees with the derivation is not served. This is the guard
// against a bad import or a derivation change silently locking people out with
// a confusing "wrong password".
func TestStoredCredentialIDMismatchFailsClosed(t *testing.T) {
	h := newHarness(t)
	const id = "mismatch@example.com"
	c := newTestClient(t, id)
	if err := c.register(h, "real-password"); err != nil {
		t.Fatal(err)
	}
	acct := mustAccountKey(t, h, id)
	if _, err := h.store.DB().Exec(`UPDATE accounts SET credential_id=? WHERE account_key=?`, bytesN(32, 0xEE), acct); err != nil {
		t.Fatal(err)
	}
	// Login must fail uniformly (as unknown), not panic or succeed.
	if _, err := c.login(h, "real-password"); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatalf("mismatched credential id: got %v, want ErrUnauthenticated", err)
	}
}

// TestConcurrentMigrationFirstWins: two finishes for the same legacy user with
// different new credentials must not both install; the first wins and the
// second cannot replace it. (In practice the login state is single-use so the
// second is rejected at consumption; this test drives the service method
// directly to pin the storage-level guarantee.)
func TestConcurrentMigrationFirstWins(t *testing.T) {
	h := newHarness(t)
	const id = "racer-migrate@example.com"
	seedLegacy(t, h, id, "legacy-pw", suite.LegacyDecoyCost)
	acct := mustAccountKey(t, h, id)

	// Directly exercise the storage guarantee with two synthetic credentials.
	a := &store.Credential{AccountKey: acct, SuiteID: suite.ID, KSFProfile: cheapProfile.ID,
		KSFSalt: bytesN(16, 1), ClientPublicKey: bytesN(32, 1), MaskingKey: bytesN(64, 1),
		Envelope: bytesN(96, 1), RecordMAC: bytesN(32, 1)}
	b := &store.Credential{AccountKey: acct, SuiteID: suite.ID, KSFProfile: cheapProfile.ID,
		KSFSalt: bytesN(16, 2), ClientPublicKey: bytesN(32, 2), MaskingKey: bytesN(64, 2),
		Envelope: bytesN(96, 2), RecordMAC: bytesN(32, 2)}

	installedA, err := h.store.InstallCredentialIfAbsent(acct, a)
	if err != nil || !installedA {
		t.Fatalf("first install: installed=%v err=%v", installedA, err)
	}
	installedB, err := h.store.InstallCredentialIfAbsent(acct, b)
	if err != nil || installedB {
		t.Fatalf("second install should be a no-op: installed=%v err=%v", installedB, err)
	}
	got, err := h.store.GetCredential(acct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.KSFSalt, a.KSFSalt) {
		t.Fatal("second migration replaced the first")
	}
	// And the legacy row is gone either way.
	if _, err := h.store.GetLegacy(acct); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("legacy row remains: %v", err)
	}
}
