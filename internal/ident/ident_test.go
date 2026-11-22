package ident

import (
	"bytes"
	"testing"
)

// TestCanonicalizationFrozen is a regression guard. Changing the rule rewrites
// every account key and locks out every existing user, so it must be a
// deliberate, versioned, reviewed change.
func TestCanonicalizationFrozen(t *testing.T) {
	cases := map[string]string{
		"Alice@Example.COM":    "alice@example.com",
		"  bob@example.com  ":  "bob@example.com",
		"user+tag@Example.com": "user+tag@example.com",
		"MiXeD@CaSe":           "mixed@case",
		"ünïcode@exämple.com":  "ünïcode@exämple.com", // non-ASCII untouched
	}
	for in, want := range cases {
		got, err := Canonicalize(in)
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		if string(got) != want {
			t.Fatalf("%q -> %q, want %q", in, got, want)
		}
	}
}

func TestDerivationsAreDomainSeparated(t *testing.T) {
	pepper := bytes.Repeat([]byte{7}, 32)
	acct := AccountKey(pepper, []byte("alice"))
	cred := CredentialID(pepper, acct)
	fake := FakeCredentialID(pepper, acct)
	if bytes.Equal(acct, cred) || bytes.Equal(acct, fake) || bytes.Equal(cred, fake) {
		t.Fatal("derivations collide")
	}
	// Deterministic.
	if !bytes.Equal(acct, AccountKey(pepper, []byte("alice"))) {
		t.Fatal("AccountKey is not deterministic")
	}
	// Peppered: a different pepper yields a different account key, so a dump
	// without the pepper cannot match known identifiers.
	if bytes.Equal(acct, AccountKey(bytes.Repeat([]byte{8}, 32), []byte("alice"))) {
		t.Fatal("account key ignores the pepper")
	}
}
