package keyring

import (
	"bytes"
	"errors"
	"testing"
)

func TestRoundTripAndVersioning(t *testing.T) {
	oldKey := bytes.Repeat([]byte{1}, 32)
	newKey := bytes.Repeat([]byte{2}, 32)
	r, err := New(2, newKey, map[uint32][]byte{1: oldKey})
	if err != nil {
		t.Fatal(err)
	}
	ct, err := r.Seal([]byte("aad"), []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	ver, _, _, err := Split(ct)
	if err != nil {
		t.Fatal(err)
	}
	if ver != 2 {
		t.Fatalf("new ciphertext has version %d, want 2", ver)
	}
	pt, err := r.Open([]byte("aad"), ct)
	if err != nil || string(pt) != "secret" {
		t.Fatalf("open: %q %v", pt, err)
	}

	// An old-version ciphertext is still readable during the rollover window.
	old, _ := New(1, oldKey, nil)
	oldCT, _ := old.Seal([]byte("aad"), []byte("legacy-secret"))
	if !r.NeedsRewrap(oldCT) {
		t.Fatal("old ciphertext not flagged for rewrap")
	}
	pt, err = r.Open([]byte("aad"), oldCT)
	if err != nil || string(pt) != "legacy-secret" {
		t.Fatalf("open old: %q %v", pt, err)
	}
	// Rewrap moves it to the active version and still opens.
	moved, err := r.Rewrap([]byte("aad"), oldCT)
	if err != nil {
		t.Fatal(err)
	}
	if v, _, _, _ := Split(moved); v != 2 {
		t.Fatalf("rewrapped version = %d", v)
	}
	if r.NeedsRewrap(moved) {
		t.Fatal("rewrapped value still flagged")
	}
}

func TestAADBinding(t *testing.T) {
	r, _ := New(1, bytes.Repeat([]byte{3}, 32), nil)
	ct, _ := r.Seal([]byte("row-a"), []byte("value"))
	if _, err := r.Open([]byte("row-b"), ct); err == nil {
		t.Fatal("ciphertext opened under the wrong AAD")
	}
}

func TestUnknownVersion(t *testing.T) {
	r, _ := New(1, bytes.Repeat([]byte{3}, 32), nil)
	ct, _ := r.Seal(nil, []byte("value"))
	ct[3] = 9 // claim version 9
	if _, err := r.Open(nil, ct); !errors.Is(err, ErrUnknownVersion) {
		t.Fatalf("got %v, want ErrUnknownVersion", err)
	}
}

func TestTamperedVersionFailsClosed(t *testing.T) {
	r, _ := New(2, bytes.Repeat([]byte{4}, 32), map[uint32][]byte{1: bytes.Repeat([]byte{4}, 32)})
	ct, _ := r.Seal(nil, []byte("value"))
	ct[3] = 1 // switch to a version whose key is identical
	if _, err := r.Open(nil, ct); err == nil {
		t.Fatal("version byte was not bound into the AAD")
	}
}
