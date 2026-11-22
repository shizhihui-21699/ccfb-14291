package legacy

import (
	"bytes"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// TestBCryptRawMatchesXCrypto is the compatibility contract. Migration depends
// on the client computing exactly the digest the old server stored; if this
// ever drifts, millions of users silently lose access.
func TestBCryptRawMatchesXCrypto(t *testing.T) {
	salts := [][]byte{
		bytes.Repeat([]byte{0x00}, 16),
		bytes.Repeat([]byte{0xff}, 16),
		{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},
	}
	passwords := []string{"", "a", "password", "correct horse battery staple", string(bytes.Repeat([]byte("x"), 72))}
	costs := []int{4, 5, 10}
	for _, salt := range salts {
		for _, pw := range passwords {
			for _, cost := range costs {
				raw, err := BCryptRaw([]byte(pw), salt, cost)
				if err != nil {
					t.Fatalf("BCryptRaw: %v", err)
				}
				encoded := Encode(salt, cost, raw)
				// The reference implementation must accept our encoding and
				// agree that the password matches.
				if err := bcrypt.CompareHashAndPassword([]byte(encoded), []byte(pw)); err != nil {
					t.Fatalf("x/crypto rejects our bcrypt encoding for pw=%q cost=%d: %v", pw, cost, err)
				}
				// And the reverse: take x/crypto's output, extract its salt,
				// and confirm our raw digest equals its digest.
				ref, err := bcrypt.GenerateFromPassword([]byte(pw), cost)
				if err != nil {
					t.Fatalf("reference hash: %v", err)
				}
				refSalt, refCost, err := SaltFromEncoded(string(ref))
				if err != nil {
					t.Fatalf("SaltFromEncoded: %v", err)
				}
				if refCost != cost {
					t.Fatalf("cost mismatch: %d != %d", refCost, cost)
				}
				got, err := BCryptRaw([]byte(pw), refSalt, refCost)
				if err != nil {
					t.Fatal(err)
				}
				if got != string(ref[29:]) {
					t.Fatalf("digest mismatch for pw=%q cost=%d:\n got %s\nwant %s", pw, cost, got, ref[29:])
				}
			}
		}
	}
}

func TestSaltFromEncodedRejectsMalformed(t *testing.T) {
	for _, s := range []string{"", "not-a-hash", "$2a$03$...", "$2a$32$abcdefghijklmnopqrstuv"} {
		if _, _, err := SaltFromEncoded(s); err == nil {
			t.Fatalf("accepted malformed hash %q", s)
		}
	}
}

func TestPasswordTooLong(t *testing.T) {
	if _, err := BCryptRaw(bytes.Repeat([]byte("a"), 73), bytes.Repeat([]byte{1}, 16), 4); err == nil {
		t.Fatal("accepted a password over bcrypt's 72-byte limit")
	}
}
