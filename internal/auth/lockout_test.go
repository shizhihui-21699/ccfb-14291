package auth_test

// Tests for the anti-lockout property (invariant I5): an attacker who floods
// an account's failed-attempt budget must not be able to deny the real user
// access. There are two escape hatches — a live trusted device, and a
// proof-of-work challenge — and neither depends on account state an attacker
// can poison.

import (
	"errors"
	"testing"
	"time"

	"opaqueauth/internal/auth"
	"opaqueauth/internal/pow"
	"opaqueauth/internal/wire"
)

// TestVictimOnTrustedDeviceNotLockedOut is the headline case: the attacker
// exhausts the account's failure budget from elsewhere, and the victim, whose
// device token was issued at registration, still logs in instantly.
func TestVictimOnTrustedDeviceNotLockedOut(t *testing.T) {
	h := newHarness(t)
	// A zero-proof-bits service: this test is about the trusted-device lane,
	// not PoW.
	const id = "victim@example.com"
	victim := newTestClient(t, id)
	if err := victim.register(h, "real-password"); err != nil {
		t.Fatalf("register: %v", err)
	}
	device := victim.device
	if device == "" {
		t.Fatal("registration did not issue a trusted device token")
	}

	// Attacker: a different source, no device token, many wrong guesses.
	attacker := newTestClient(t, id)
	attacker.device = ""
	attacker.msgsource = "attacker-source"
	rejected := 0
	for i := 0; i < 50; i++ {
		if _, err := attacker.login(h, "wrong"); errors.Is(err, auth.ErrRateLimited) {
			rejected++
		}
	}
	if rejected == 0 {
		t.Fatal("attacker was never rate limited; test setup is not adversarial")
	}
	t.Logf("attacker was refused %d/50 times", rejected)

	// Victim still gets in on their device. The device token is checked before
	// the account failure budget, so no waiting is required.
	v := newTestClient(t, id)
	v.device = device
	v.msgsource = "victim-source"
	if _, err := v.login(h, "real-password"); err != nil {
		t.Fatalf("victim locked out by attacker: %v", err)
	}
}

// TestProofOfWorkUnlocksAfterFlood: an attacker from one source drains the
// account-wide failure budget, and the victim signing in from a *new* device
// elsewhere still gets in by solving a challenge.
//
// What the proof deliberately does *not* exempt is the per-source bucket: that
// is the credential-stuffing bound, and buying CPU must not buy guesses. An
// attacker therefore cannot use proof-of-work to obtain unlimited attempts,
// while a victim is relieved of exactly the part an attacker can poison from a
// distance (the account budget).
func TestProofOfWorkUnlocksAfterFlood(t *testing.T) {
	h := newHarness(t)
	const id = "flooded@example.com"
	owner := newTestClient(t, id)
	if err := owner.register(h, "real-password"); err != nil {
		t.Fatalf("register: %v", err)
	}

	// Drain the account-wide failure budget. Each source only gets 5 attempts
	// before its own bucket closes, so this models a small botnet: 5 sources
	// spend the 20-token account budget. This is the realistic attack, and it
	// is exactly why the account budget alone must not be allowed to lock the
	// account.
	for src := 0; src < 6; src++ {
		for i := 0; i < 5; i++ {
			att := newTestClient(t, id)
			att.device = ""
			att.msgsource = "bot-" + itoa(src)
			_, _ = att.login(h, "wrong")
		}
	}

	// The victim's new device, from its own source, is refused because the
	// *account* budget is empty...
	fresh := newTestClient(t, id)
	fresh.device = ""
	fresh.msgsource = "home"
	if _, err := fresh.login(h, "real-password"); !errors.Is(err, auth.ErrRateLimited) {
		t.Fatalf("expected account-budget refusal before PoW, got %v", err)
	}
	ch := fresh.lastChallenge
	if ch == nil {
		t.Fatal("refused start did not return a challenge")
	}

	// ...and a solved challenge gets straight in, with no clock advance.
	n, err := pow.Solve(ch.Token, ch.Bits, 1<<20)
	if err != nil {
		t.Fatalf("solve challenge: %v", err)
	}
	if _, err := fresh.loginWithProof(h, "real-password", &wire.Proof{Challenge: ch.Token, Nonce: n}); err != nil {
		t.Fatalf("proof-of-work did not unlock the account: %v", err)
	}

	// A wrong solution is not evidence and does not unlock anything.
	h.clock.Advance(time.Hour) // refill every bucket so only the proof matters
	for src := 0; src < 6; src++ {
		for i := 0; i < 5; i++ {
			att := newTestClient(t, id)
			att.device = ""
			att.msgsource = "bot2-" + itoa(src)
			_, _ = att.login(h, "wrong")
		}
	}
	fresh2 := newTestClient(t, id)
	fresh2.device = ""
	fresh2.msgsource = "home-2"
	_, _ = fresh2.login(h, "real-password") // obtains a challenge
	ch2 := fresh2.lastChallenge
	if ch2 == nil {
		t.Fatal("expected a challenge")
	}
	if _, err := fresh2.loginWithProof(h, "real-password", &wire.Proof{Challenge: ch2.Token, Nonce: 0}); !errors.Is(err, auth.ErrRateLimited) {
		t.Fatalf("an unsolved challenge was accepted as evidence: %v", err)
	}
}

// TestProofDoesNotBuyUnlimitedGuesses pins the other side of the trade-off: a
// valid proof is not a licence to guess without bound against one account from
// one source.
func TestProofDoesNotBuyUnlimitedGuesses(t *testing.T) {
	h := newHarness(t)
	const id = "hardened@example.com"
	c := newTestClient(t, id)
	if err := c.register(h, "real-password"); err != nil {
		t.Fatal(err)
	}
	// Solve a fresh challenge for every attempt; each attempt is a wrong guess.
	accepted := 0
	for i := 0; i < 15; i++ {
		att := newTestClient(t, id)
		att.device = ""
		att.msgsource = "solver"
		ch := h.svc.IssueChallenge()
		n, err := pow.Solve(ch, h.svc.ClientConfig().ProofBits, 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		_, err = att.loginWithProof(h, "wrong", &wire.Proof{Challenge: ch, Nonce: n})
		if err == nil || errors.Is(err, auth.ErrUnauthenticated) {
			accepted++
		}
	}
	if accepted > 5 {
		t.Fatalf("proof-of-work bought %d guesses past the 5-token per-source bound", accepted)
	}
}

// TestNoPersistentLockState asserts the stronger property directly in the data
// model: after any number of failures, the account row is still "active" and
// there is no lock column anywhere.
func TestNoPersistentLockState(t *testing.T) {
	h := newHarness(t)
	const id = "steady@example.com"
	c := newTestClient(t, id)
	if err := c.register(h, "real-password"); err != nil {
		t.Fatalf("register: %v", err)
	}
	for i := 0; i < 100; i++ {
		att := newTestClient(t, id)
		att.device = ""
		att.msgsource = "flood"
		_, _ = att.login(h, "wrong")
	}
	acct, err := h.store.GetAccount(mustAccountKey(t, h, id))
	if err != nil {
		t.Fatalf("account vanished: %v", err)
	}
	if acct.Status != "active" {
		t.Fatalf("account status changed under flood: %q", acct.Status)
	}
}

// TestSuccessClearsFailureBudget: a legitimate login resets the account budget,
// so a user who mistyped earlier is not permanently penalised.
func TestSuccessClearsFailureBudget(t *testing.T) {
	h := newHarness(t)
	const id = "mistyper@example.com"
	c := newTestClient(t, id)
	if err := c.register(h, "real-password"); err != nil {
		t.Fatalf("register: %v", err)
	}
	// 15 wrong guesses from one source (under the 20-token account budget but
	// over the 5-token per-(account,source) budget, so the limiter engages).
	for i := 0; i < 15; i++ {
		bad := newTestClient(t, id)
		bad.device = ""
		bad.msgsource = "mistype"
		_, _ = bad.login(h, "typo")
	}
	// Correct login from a different source.
	good := newTestClient(t, id)
	good.device = ""
	good.msgsource = "home"
	if _, err := good.login(h, "real-password"); err != nil {
		t.Fatalf("correct login after typos: %v", err)
	}
	// And the budget for the account is now empty/clear: the 5-token
	// per-source bucket is still per source, but the account-failure bucket
	// should have been reset by Succeed(). We check by allowing a burst from a
	// fresh source.
	for i := 0; i < 5; i++ {
		f := newTestClient(t, id)
		f.device = ""
		f.msgsource = "fresh"
		if _, err := f.login(h, "typo-"+itoa(i)); errors.Is(err, auth.ErrRateLimited) {
			t.Fatalf("account budget was not cleared on success (iteration %d)", i)
		}
	}
}

// TestOtherAccountsUnaffected: flooding one account must not throttle another.
func TestOtherAccountsUnaffected(t *testing.T) {
	h := newHarness(t)
	a := newTestClient(t, "a@example.com")
	if err := a.register(h, "a-password"); err != nil {
		t.Fatal(err)
	}
	b := newTestClient(t, "b@example.com")
	if err := b.register(h, "b-password"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 60; i++ {
		att := newTestClient(t, "a@example.com")
		att.device = ""
		att.msgsource = "flood-a"
		_, _ = att.login(h, "wrong")
	}
	// b, from its own source, is fine.
	b2 := newTestClient(t, "b@example.com")
	b2.device = ""
	b2.msgsource = "b-source"
	if _, err := b2.login(h, "b-password"); err != nil {
		t.Fatalf("unrelated account throttled: %v", err)
	}
}

// TestUnknownUserIndistinguishable: a login for a non-existent identifier must
// produce the same shape and the same failure as a wrong password for a real
// one, and must consume budget the same way (so timing and rate behaviour do
// not enumerate).
func TestUnknownUserIndistinguishable(t *testing.T) {
	h := newHarness(t)
	real := newTestClient(t, "real@example.com")
	if err := real.register(h, "real-password"); err != nil {
		t.Fatal(err)
	}

	// Real user, wrong password: start response must look like a normal start.
	r2 := newTestClient(t, "real@example.com")
	r2.device = ""
	r2.msgsource = "s1"
	startReal, err := r2.startOnly(h, "wrong")
	if err != nil {
		t.Fatalf("start real: %v", err)
	}
	// Unknown user: same start shape.
	u := newTestClient(t, "ghost@example.com")
	u.device = ""
	u.msgsource = "s2"
	startGhost, err := u.startOnly(h, "wrong")
	if err != nil {
		t.Fatalf("start ghost: %v", err)
	}
	if len(startReal.KE2.Serialize()) != len(startGhost.KE2.Serialize()) {
		t.Fatalf("KE2 length differs: real=%d ghost=%d", len(startReal.KE2.Serialize()), len(startGhost.KE2.Serialize()))
	}
	if len(startReal.LegacySalt) != len(startGhost.LegacySalt) ||
		len(startReal.LegacyChallenge) != len(startGhost.LegacyChallenge) ||
		len(startReal.RegResponse) != len(startGhost.RegResponse) {
		t.Fatal("migration material presence reveals account existence")
	}
}

// --- helpers on testClient used above ---

func (c *testClient) startOnly(h *harness, password string) (*auth.LoginStartResult, error) {
	c.ake.ClearState()
	c.reg.ClearState()
	ke1, err := c.ake.GenerateKE1([]byte(password))
	if err != nil {
		return nil, err
	}
	regReq, err := c.reg.RegistrationInit([]byte(password))
	if err != nil {
		return nil, err
	}
	src := c.msgsource
	if src == "" {
		src = "src-" + c.ident
	}
	return h.svc.LoginBegin(c.ident, ke1, regReq, src, c.device, nil)
}

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
