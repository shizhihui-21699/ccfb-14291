package pow

import (
	"testing"
	"time"
)

func TestIssueVerifyRoundTrip(t *testing.T) {
	c := New([]byte("a-32-byte-key-for-tests-12345678"), 8, time.Minute)
	now := time.Unix(1000, 0)
	c.SetClock(func() time.Time { return now })
	tok := c.Issue()
	n, err := Solve(tok, 8, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Verify(tok, n); err != nil {
		t.Fatalf("valid solution rejected: %v", err)
	}
	if err := c.Verify(tok, n+1); err == nil {
		t.Fatal("invalid solution accepted")
	}
}

func TestExpiry(t *testing.T) {
	c := New([]byte("k"), 4, time.Minute)
	now := time.Unix(1000, 0)
	c.SetClock(func() time.Time { return now })
	tok := c.Issue()
	n, _ := Solve(tok, 4, 1<<20)
	now = now.Add(2 * time.Minute)
	if err := c.Verify(tok, n); err == nil {
		t.Fatal("expired challenge accepted")
	}
}

func TestForgedChallengeRejected(t *testing.T) {
	c := New([]byte("k"), 4, time.Minute)
	// A challenge issued under a different key must not verify.
	other := New([]byte("other-key"), 4, time.Minute)
	tok := other.Issue()
	n, _ := Solve(tok, 4, 1<<20)
	if err := c.Verify(tok, n); err == nil {
		t.Fatal("challenge from another key accepted")
	}
	// Garbage must not panic.
	if err := c.Verify("not-base64!!", 0); err == nil {
		t.Fatal("garbage accepted")
	}
}

func TestLeadingZeroBits(t *testing.T) {
	cases := []struct {
		sum  []byte
		bits int
		want bool
	}{
		{[]byte{0x00, 0x00}, 12, true},
		{[]byte{0x00, 0x10}, 12, false},
		{[]byte{0xff}, 1, false},
		{[]byte{0x7f}, 1, true},
		{[]byte{0x00}, 8, true},
	}
	for _, c := range cases {
		if got := leadingZeroBits(c.sum, c.bits); got != c.want {
			t.Fatalf("leadingZeroBits(%x,%d) = %v, want %v", c.sum, c.bits, got, c.want)
		}
	}
}
