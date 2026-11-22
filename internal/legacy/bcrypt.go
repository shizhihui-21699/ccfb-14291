// Package legacy reimplements exactly the bcrypt construction used by the
// pre-migration password database, but taking the raw 16-byte salt instead of
// an encoded hash.
//
// Why this exists: migration must not send the plaintext password to the
// server. The client therefore needs to compute the same bcrypt output the
// server stored. Sending the stored hash to the client would hand out the
// verifier; sending only the salt and cost lets the client compute the
// password-equivalent locally and return a challenge-bound MAC instead. The
// server compares that MAC against one computed from its own stored verifier,
// so neither the password nor the verifier crosses the wire.
//
// The construction is reproduced from Provos & Mazières (USENIX 1999) and is
// kept byte-compatible with golang.org/x/crypto/bcrypt by the tests in
// bcrypt_test.go; do not "improve" it.
package legacy

import (
	"encoding/base64"
	"errors"
	"fmt"

	"golang.org/x/crypto/blowfish"
)

// Cost bounds accepted by bcrypt.
const (
	MinCost     = 4
	MaxCost     = 31
	DefaultCost = 10
)

// magicCipherData is "OrpheanBeholderScryDoubt".
var magicCipherData = []byte{
	0x4f, 0x72, 0x70, 0x68, 0x65, 0x61, 0x6e, 0x42,
	0x65, 0x68, 0x6f, 0x6c, 0x64, 0x65, 0x72, 0x53,
	0x63, 0x72, 0x79, 0x44, 0x6f, 0x75, 0x62, 0x74,
}

var bcEncoding = base64.NewEncoding("./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")

// ErrBadCost is returned for an out-of-range cost.
var ErrBadCost = errors.New("legacy: bcrypt cost out of range")

// ErrBadSalt is returned for a salt that is not 16 bytes.
var ErrBadSalt = errors.New("legacy: bcrypt salt must be 16 bytes")

// ErrLongPassword is returned for passwords over bcrypt's 72-byte limit.
var ErrLongPassword = errors.New("legacy: bcrypt password exceeds 72 bytes")

// BCryptRaw computes the 31-character bcrypt digest (the part after the last
// '$' in an encoded hash) for password with a raw 16-byte salt and the given
// cost. It is byte-identical to x/crypto/bcrypt's output.
func BCryptRaw(password, salt []byte, cost int) (string, error) {
	if len(salt) != 16 {
		return "", ErrBadSalt
	}
	if cost < MinCost || cost > MaxCost {
		return "", ErrBadCost
	}
	if len(password) > 72 {
		return "", ErrLongPassword
	}
	// Bcrypt uses the trailing NUL of the key string during key expansion.
	ckey := make([]byte, len(password)+1)
	copy(ckey, password)

	c, err := blowfish.NewSaltedCipher(ckey, salt)
	if err != nil {
		return "", err
	}
	for i := uint64(0); i < uint64(1)<<uint(cost); i++ {
		blowfish.ExpandKey(ckey, c)
		blowfish.ExpandKey(salt, c)
	}
	buf := make([]byte, len(magicCipherData))
	copy(buf, magicCipherData)
	for i := 0; i < 24; i += 8 {
		for j := 0; j < 64; j++ {
			c.Encrypt(buf[i:i+8], buf[i:i+8])
		}
	}
	// Bug-compatibility with the C implementations: only 23 of 24 bytes are
	// encoded, and bcrypt's base64 is unpadded.
	return trimPadding(bcEncoding.EncodeToString(buf[:23])), nil
}

// trimPadding strips base64 '=' padding, matching the bcrypt encoding.
func trimPadding(s string) string {
	for len(s) > 0 && s[len(s)-1] == '=' {
		s = s[:len(s)-1]
	}
	return s
}

// SaltFromEncoded extracts the raw 16-byte salt from a bcrypt encoded hash
// string ("$2a$12$...") and returns it with the cost.
func SaltFromEncoded(encoded string) (salt []byte, cost int, err error) {
	if len(encoded) != 60 || encoded[0] != '$' || encoded[3] != '$' || encoded[6] != '$' {
		return nil, 0, errors.New("legacy: malformed bcrypt hash")
	}
	if _, err := fmt.Sscanf(encoded[4:6], "%02d", &cost); err != nil {
		return nil, 0, errors.New("legacy: malformed bcrypt cost")
	}
	if cost < MinCost || cost > MaxCost {
		return nil, 0, ErrBadCost
	}
	// Append padding to decode bcrypt's unpadded 22-character salt.
	raw, err := bcEncoding.DecodeString(encoded[7:29] + "==")
	if err != nil {
		return nil, 0, fmt.Errorf("legacy: malformed bcrypt salt: %w", err)
	}
	if len(raw) != 16 {
		return nil, 0, errors.New("legacy: malformed bcrypt salt length")
	}
	return raw, cost, nil
}

// Encode reconstructs the canonical bcrypt string from a raw salt, cost and
// digest. Used by tests and by migration tooling that imports old dumps.
func Encode(salt []byte, cost int, digest string) string {
	encSalt := bcEncoding.EncodeToString(salt)[:22]
	return fmt.Sprintf("$2a$%02d$%s%s", cost, encSalt, digest)
}
