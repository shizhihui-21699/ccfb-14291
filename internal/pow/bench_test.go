package pow

import (
	"testing"
	"time"
)

// TestSolveTimeAtDefault pins the claim in docs/THREAT-MODEL.md that the
// default difficulty is a speed bump, not a barrier: solving one challenge
// takes well under a second.
func TestSolveTimeAtDefault(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	c := New([]byte("bench-key-32-bytes-000000000000000"), 18, time.Minute)
	tok := c.Issue()
	start := time.Now()
	n, err := Solve(tok, 18, 1<<32)
	if err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)
	if err := c.Verify(tok, n); err != nil {
		t.Fatal(err)
	}
	t.Logf("18-bit challenge solved in %v", elapsed)
	if elapsed > 2*time.Second {
		t.Fatalf("18-bit PoW took %v, slower than the documented budget", elapsed)
	}
}
