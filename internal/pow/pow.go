// Package pow implements a stateless, self-contained proof-of-work challenge.
//
// It is the anti-lockout escape hatch: when an account's failure budget is
// exhausted (which an attacker can deliberately cause, because identifiers are
// public), a legitimate user arriving on a new device can still authenticate
// by solving a challenge that costs a bounded amount of CPU. There is no
// account state to poison and no way for an attacker to make the challenge
// unsolvable; the only effect of a flood is that the *attacker* also pays the
// work for each of its own attempts.
//
// The challenge is a MAC over an issue-time and difficulty, so the server
// stores nothing between issue and verify. Verification accepts a challenge
// issued within a window and checks SHA-256(challenge || nonce) has the stated
// number of leading zero bits.
package pow

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"opaqueauth/internal/secure"
)

// ErrInvalid is returned for malformed, expired, or unsolved challenges.
var ErrInvalid = errors.New("pow: invalid or expired challenge")

// Challenger issues and verifies challenges.
type Challenger struct {
	key  []byte
	bits int
	ttl  time.Duration
	now  func() time.Time
}

// New returns a Challenger. key should be a dedicated 32-byte subkey.
func New(key []byte, bits int, ttl time.Duration) *Challenger {
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	return &Challenger{key: key, bits: bits, ttl: ttl, now: time.Now}
}

// SetClock replaces the clock. Tests only.
func (c *Challenger) SetClock(now func() time.Time) { c.now = now }

// Bits returns the configured difficulty.
func (c *Challenger) Bits() int { return c.bits }

// Issue returns a fresh challenge token.
func (c *Challenger) Issue() string {
	ts := uint64(c.now().Unix())
	var body [12]byte
	binary.BigEndian.PutUint64(body[0:8], ts)
	binary.BigEndian.PutUint32(body[8:12], uint32(c.bits))
	mac := secure.HMAC(c.key, []byte("pow/challenge/v1\x00"), body[:])
	raw := make([]byte, 0, 12+16)
	raw = append(raw, body[:]...)
	raw = append(raw, mac[:16]...)
	return base64.RawURLEncoding.EncodeToString(raw)
}

// Verify checks that challenge is ours, fresh, and that nonce solves it.
func (c *Challenger) Verify(challenge string, nonce uint64) error {
	raw, err := base64.RawURLEncoding.DecodeString(challenge)
	if err != nil || len(raw) != 28 {
		return ErrInvalid
	}
	body, gotMAC := raw[:12], raw[12:]
	wantMAC := secure.HMAC(c.key, []byte("pow/challenge/v1\x00"), body)
	if !secure.Equal(gotMAC, wantMAC[:16]) {
		return ErrInvalid
	}
	ts := int64(binary.BigEndian.Uint64(body[0:8]))
	bits := int(binary.BigEndian.Uint32(body[8:12]))
	if bits != c.bits {
		return ErrInvalid
	}
	issued := time.Unix(ts, 0)
	age := c.now().Sub(issued)
	if age < -time.Minute || age > c.ttl {
		return ErrInvalid
	}
	return c.checkSolution(challenge, nonce, bits)
}

func (c *Challenger) checkSolution(challenge string, nonce uint64, bits int) error {
	h := sha256.New()
	h.Write([]byte(challenge))
	var nb [8]byte
	binary.BigEndian.PutUint64(nb[:], nonce)
	h.Write(nb[:])
	sum := h.Sum(nil)
	if !leadingZeroBits(sum, bits) {
		return ErrInvalid
	}
	return nil
}

// Solve finds a nonce satisfying the challenge. Used by the client SDK and by
// tests; in a browser the client would implement the same loop.
func Solve(challenge string, bits int, maxIterations uint64) (uint64, error) {
	for n := uint64(0); n < maxIterations; n++ {
		h := sha256.New()
		h.Write([]byte(challenge))
		var nb [8]byte
		binary.BigEndian.PutUint64(nb[:], n)
		h.Write(nb[:])
		if leadingZeroBits(h.Sum(nil), bits) {
			return n, nil
		}
	}
	return 0, fmt.Errorf("pow: no solution within %d iterations", maxIterations)
}

func leadingZeroBits(sum []byte, bits int) bool {
	if bits < 0 || bits > len(sum)*8 {
		return false
	}
	full := bits / 8
	for i := 0; i < full; i++ {
		if sum[i] != 0 {
			return false
		}
	}
	rem := bits % 8
	if rem == 0 {
		return true
	}
	mask := byte(0xff << (8 - rem))
	return sum[full]&mask == 0
}
