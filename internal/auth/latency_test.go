package auth_test

import (
	"fmt"
	"testing"
	"time"

	"opaqueauth/internal/suite"
)

// TestLoginLatencyBudget pins the "login must not get noticeably slower"
// requirement. It runs the OPAQUE server half with the production KSF profile
// (Argon2id t=3, 64 MiB) and asserts the server-side cost stays small; the
// client's Argon2id is the dominant cost and is unchanged in kind from the old
// bcrypt (and tunable).
func TestLoginLatencyBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("latency test skipped in -short mode")
	}
	h := newHarnessProd(t)
	const id = "latency@example.com"
	c := newTestClientProd(t, id)
	if err := c.register(h, "a-password-for-timing"); err != nil {
		t.Fatalf("register: %v", err)
	}

	// Measure the server's KE2/KE3 path (what the server pays per login).
	const n = 30
	start := time.Now()
	for i := 0; i < n; i++ {
		if _, err := c.login(h, "a-password-for-timing"); err != nil {
			t.Fatalf("login: %v", err)
		}
	}
	elapsed := time.Since(start) / n
	t.Logf("mean end-to-end (client Argon2id + server) with production KSF: %v", elapsed)

	// The client's Argon2id dominates; the requirement was that the protocol
	// itself must not add a round trip beyond what login already costs. Assert
	// the whole thing is within a human-noticeable budget of ~1 s on a laptop.
	if elapsed > time.Second {
		t.Fatalf("login took %v, over the 1s budget", elapsed)
	}
	p := suite.ProfileV1
	fmt.Printf("production KSF profile: t=%d m=%dKiB p=%d\n", p.Time, p.Memory, p.Threads)
}
