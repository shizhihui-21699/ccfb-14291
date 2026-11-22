package ratelimit

import (
	"testing"
	"time"
)

func TestBurstThenRefill(t *testing.T) {
	l := New(Policy{
		AccountPerSource: Rate{PerSecond: 0.2, Burst: 5},
		Source:           Rate{PerSecond: 2, Burst: 20},
		AccountFailure:   Rate{PerSecond: 1.0 / 60.0, Burst: 20},
		Global:           Rate{PerSecond: 1000, Burst: 1000},
	})
	now := time.Unix(0, 0)
	l.SetClock(func() time.Time { return now })

	for i := 0; i < 5; i++ {
		d := l.Admit("acct", "src", false)
		if !d.Allow {
			t.Fatalf("burst attempt %d refused", i)
		}
		l.Fail(d.Charge)
	}
	if d := l.Admit("acct", "src", false); d.Allow {
		t.Fatal("sixth attempt allowed")
	}
	// After one refill interval (5 s at 0.2/s) one token is back.
	now = now.Add(5 * time.Second)
	if d := l.Admit("acct", "src", false); !d.Allow {
		t.Fatal("refill did not restore a token")
	}
}

func TestFailuresOnlyCountOnFail(t *testing.T) {
	l := New(DefaultPolicy())
	now := time.Unix(0, 0)
	l.SetClock(func() time.Time { return now })

	// Many admitted requests that succeed (Fail not called) must not consume
	// the account failure budget.
	for i := 0; i < 100; i++ {
		now = now.Add(time.Second)
		if d := l.Admit("acct", "srcA", false); !d.Allow {
			t.Fatalf("admitted request %d refused", i)
		}
		l.Succeed("acct")
	}
	if d := l.Admit("acct", "srcB", false); !d.Allow {
		t.Fatal("account budget consumed by successes")
	}
}

func TestTrustedSkipsAccountButNotSource(t *testing.T) {
	l := New(Policy{
		AccountPerSource: Rate{PerSecond: 0.2, Burst: 5},
		Source:           Rate{PerSecond: 2, Burst: 3},
		AccountFailure:   Rate{PerSecond: 1.0 / 60.0, Burst: 2},
		Global:           Rate{PerSecond: 1000, Burst: 1000},
	})
	now := time.Unix(0, 0)
	l.SetClock(func() time.Time { return now })

	// Exhaust the account failure budget.
	for i := 0; i < 2; i++ {
		d := l.Admit("acct", "a"+string(rune('0'+i)), false)
		l.Fail(d.Charge)
	}
	if d := l.Admit("acct", "c", false); d.Allow {
		t.Fatal("account budget should be exhausted")
	}
	// Trusted bypasses the account bucket.
	if d := l.Admit("acct", "d", true); !d.Allow {
		t.Fatal("trusted device was refused by the account bucket")
	}
	// But the per-source bucket still applies: exhaust it from "e" with failed
	// guesses, each of which is admitted (the account bucket is bypassed by the
	// trusted flag) but charged.
	exhausted := false
	for i := 0; i < 10; i++ {
		d := l.Admit("acct", "e", true)
		if !d.Allow {
			exhausted = true
			break
		}
		l.Fail(d.Charge)
	}
	if !exhausted {
		t.Fatal("source bucket was bypassed by trusted flag")
	}
}

func TestGCBoundsMemory(t *testing.T) {
	l := New(DefaultPolicy())
	now := time.Unix(0, 0)
	l.SetClock(func() time.Time { return now })
	for i := 0; i < 1000; i++ {
		l.Admit(string(rune(i)), "s", false)
	}
	before := l.Size()
	// Advance past the GC period and touch the limiter once.
	now = now.Add(11 * time.Minute)
	l.Admit("x", "y", false)
	if l.Size() >= before {
		t.Fatalf("GC did not reclaim buckets: %d -> %d", before, l.Size())
	}
}

func TestRetryAfterIsBounded(t *testing.T) {
	d := Rate{PerSecond: 0.2, Burst: 5}.refillDelay()
	if d != 5*time.Second {
		t.Fatalf("refillDelay = %v, want 5s", d)
	}
	if got := (Rate{PerSecond: 100, Burst: 1}).refillDelay(); got < time.Second {
		t.Fatalf("sub-second refillDelay = %v", got)
	}
}
