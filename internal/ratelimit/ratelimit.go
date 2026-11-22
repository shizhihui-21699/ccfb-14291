// Package ratelimit bounds online password guessing without giving an attacker
// a way to lock a victim out.
//
// The design is a two-tier token bucket evaluated per (account, source) and per
// source, plus a slow account-wide budget that only counts *failed* attempts
// and never produces a hard lock. The properties we need, and how each is
// obtained:
//
//  1. Bound guesses per account. A successful authentication resets the
//     account's failure counter, so a legitimate user who mistypes a few times
//     is never affected beyond a short delay. An attacker with no password can
//     only spend the account's slow failure budget, which is sized for
//     thousands of years of guessing at realistic rates (see docs).
//
//  2. No lockout by denial. There is no "account locked after N failures"
//     state. After the failure budget is spent, requests are refused with
//     HTTP 429 *unless* they carry a live trusted-device token or solve a
//     proof-of-work challenge. A victim on a known device is never locked out;
//     an attacker cannot cheaply flood the victim's budget either, because the
//     account-wide budget is charged only on real failed password checks, and
//     the per-source budget limits how fast any one source can spend it.
//     Even in the worst case, the effect on the victim is a proof-of-work
//     (sub-second on any device that could run Argon2id) or a wait, not
//     "account disabled". A valid proof is checked by the caller and passed
//     in as evidence=true, which skips the account bucket exactly like a
//     trusted device does.
//
//  3. Bound guesses per source / IP. This is what stops a single host from
//     spreading guesses across many accounts (credential stuffing).
//
//  4. Cheap rejection before expensive work. The bucket is consulted before
//     the OPAQUE server does its group operations and long before the client's
//     Argon2id runs, so the limiter is also the resource-exhaustion control.
//
// Nothing here writes to the database on the hot path; the limiter is
// in-memory per process. A multi-process deployment should back it with Redis
// or similar; the interface is intentionally narrow so that swap is local.
package ratelimit

import (
	"sync"
	"time"
)

// Decision is the outcome of an admission check.
type Decision struct {
	// Allow reports whether the request may proceed to password verification.
	Allow bool
	// RetryAfter is how long the caller should wait before retrying, when
	// Allow is false.
	RetryAfter time.Duration
	// Reason is a stable, non-sensitive code for metrics and audit.
	Reason string
	// Charge is the bucket that will be charged on a failed verification;
	// callers pass it back to Fail().
	Charge []string
}

// Policy configures the buckets. Rates are in tokens per second; Burst is the
// bucket depth.
type Policy struct {
	// AccountPerSource bounds tries against one account from one source.
	AccountPerSource Rate
	// Source bounds tries from one source across all accounts.
	Source Rate
	// AccountFailure bounds *failed* tries against one account across all
	// sources. It is deliberately much larger than any human needs, because it
	// is what an attacker must exhaust to mount an online dictionary attack,
	// and it does not lock the account: it only raises the cost of further
	// tries (proof-of-work or wait).
	AccountFailure Rate
	// Global bounds total tries per second across the whole service, a
	// safety valve against a botnet.
	Global Rate
}

// Rate is a token bucket shape.
type Rate struct {
	PerSecond float64
	Burst     float64
}

// DefaultPolicy returns the shipped policy.
//
// Rationale for the numbers (see docs/THREAT-MODEL.md for the derivation):
//
//   - AccountPerSource 5 burst / 0.2/s: a human mistyping a password on their
//     own device gets five fast tries, then one every five seconds.
//   - Source 20 burst / 2/s: one host can try ~20 accounts immediately, then
//     has to slow to 2/s, which makes stuffing a large leaked list from one
//     host unattractive.
//   - AccountFailure 20 burst / 1/60s: after 20 failures an account refuses
//     further *untrusted, unproven* tries until one token accrues (60 s), and
//     an attacker must keep waiting. 20 + t/60 failures per second is far below
//     what a targeted dictionary needs. Crucially it never disables the
//     account and a trusted device bypasses it entirely.
//   - Global 2000/s: headroom above expected peak.
func DefaultPolicy() Policy {
	return Policy{
		AccountPerSource: Rate{PerSecond: 0.2, Burst: 5},
		Source:           Rate{PerSecond: 2, Burst: 20},
		AccountFailure:   Rate{PerSecond: 1.0 / 60.0, Burst: 20},
		Global:           Rate{PerSecond: 2000, Burst: 4000},
	}
}

type bucket struct {
	tokens float64
	last   time.Time
}

// Limiter is a set of in-memory token buckets.
type Limiter struct {
	policy Policy
	now    func() time.Time

	mu       sync.Mutex
	buckets  map[string]*bucket
	lastGC   time.Time
	gcPeriod time.Duration
}

// New creates a Limiter.
func New(p Policy) *Limiter {
	return &Limiter{
		policy:   p,
		now:      time.Now,
		buckets:  make(map[string]*bucket),
		gcPeriod: 10 * time.Minute,
	}
}

// SetClock replaces the clock. Tests only.
func (l *Limiter) SetClock(now func() time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.now = now
}

// Admit checks the per-(account,source), per-source and global buckets. It does
// not consume anything: consumption happens in Fail(), and only for real
// failed password verifications. That asymmetry is what makes this a
// lockout-resistant design: a request that is refused or that succeeds costs
// the account nothing.
//
// isTrusted is evidence that the request should skip the account-level
// throttle: either a live trusted-device token or a valid proof-of-work
// solution. Source and global limits still apply, because they protect the
// service rather than a single account.
func (l *Limiter) Admit(accountKey, source string, isTrusted bool) Decision {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.maybeGC(now)

	if !l.peek("src:"+source, l.policy.Source, now) {
		return Decision{Allow: false, RetryAfter: l.policy.Source.refillDelay(), Reason: "source_rate"}
	}
	if !l.peek("global", l.policy.Global, now) {
		return Decision{Allow: false, RetryAfter: time.Second, Reason: "global_rate"}
	}
	if !l.peek("acct-src:"+accountKey+":"+source, l.policy.AccountPerSource, now) {
		return Decision{Allow: false, RetryAfter: l.policy.AccountPerSource.refillDelay(), Reason: "account_source_rate"}
	}
	if !isTrusted && !l.peek("acct-fail:"+accountKey, l.policy.AccountFailure, now) {
		return Decision{
			Allow:      false,
			RetryAfter: l.policy.AccountFailure.refillDelay(),
			Reason:     "account_failures",
			Charge:     []string{"acct-fail:" + accountKey},
		}
	}
	return Decision{
		Allow:  true,
		Charge: []string{"src:" + source, "global", "acct-src:" + accountKey + ":" + source, "acct-fail:" + accountKey},
	}
}

// Fail charges the buckets listed in a Decision after a failed password
// verification. Buckets are charged only now, so successes and rejected
// requests never consume a victim's budget.
func (l *Limiter) Fail(charge []string) {
	if len(charge) == 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	for _, name := range charge {
		b := l.bucketFor(name, l.rateFor(name), now)
		b.tokens -= 1
		if b.tokens < 0 {
			b.tokens = 0
		}
	}
}

// Succeed clears an account's failure budget. Called after a verified login so
// that a user who mistyped earlier starts from a clean slate; this is the other
// half of the no-lockout property.
func (l *Limiter) Succeed(accountKey string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.buckets, "acct-fail:"+accountKey)
}

func (l *Limiter) rateFor(name string) Rate {
	switch {
	case len(name) > 7 && name[:7] == "acct-fa":
		return l.policy.AccountFailure
	case len(name) > 4 && name[:4] == "acct":
		return l.policy.AccountPerSource
	case len(name) > 4 && name[:4] == "src:":
		return l.policy.Source
	default:
		return l.policy.Global
	}
}

// peek reports whether name has at least one token, refilling lazily.
func (l *Limiter) peek(name string, r Rate, now time.Time) bool {
	b := l.bucketFor(name, r, now)
	return b.tokens >= 1
}

// bucketFor returns the bucket for name, refilling it to now.
func (l *Limiter) bucketFor(name string, r Rate, now time.Time) *bucket {
	b, ok := l.buckets[name]
	if !ok {
		b = &bucket{tokens: r.Burst, last: now}
		l.buckets[name] = b
		return b
	}
	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * r.PerSecond
		if b.tokens > r.Burst {
			b.tokens = r.Burst
		}
		b.last = now
	}
	return b
}

// maybeGC drops buckets that have refilled completely, bounding memory.
func (l *Limiter) maybeGC(now time.Time) {
	if now.Sub(l.lastGC) < l.gcPeriod {
		return
	}
	l.lastGC = now
	for name, b := range l.buckets {
		full := l.rateFor(name).Burst
		if b.tokens >= full {
			delete(l.buckets, name)
		}
	}
}

// refillDelay is the time for one token at this rate.
func (r Rate) refillDelay() time.Duration {
	if r.PerSecond <= 0 {
		return time.Hour
	}
	d := time.Duration(float64(time.Second) / r.PerSecond)
	if d < time.Second {
		d = time.Second
	}
	return d
}

// Size returns the number of live buckets. Tests and metrics only.
func (l *Limiter) Size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

// AdmitKey checks a named bucket and, if it has a token, consumes one
// immediately. Unlike Admit/Fail, this charges on admission rather than on
// failure, which is the right shape for actions whose cost is incurred whether
// or not they succeed: sending a recovery e-mail, starting a registration,
// issuing a challenge.
func (l *Limiter) AdmitKey(name string, r Rate) (ok bool, retry time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.maybeGC(now)
	b := l.bucketFor(name, r, now)
	if b.tokens < 1 {
		return false, r.refillDelay()
	}
	b.tokens -= 1
	return true, 0
}

// NamedRate is a named token bucket shape used by AdmitKey.
type NamedRate struct {
	Name string
	Rate Rate
}
