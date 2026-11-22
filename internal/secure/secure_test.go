package secure

import (
	"bytes"
	"testing"
)

func TestSealOpenAndAAD(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	s, err := Seal(key, []byte("aad"), []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := Open(key, []byte("aad"), s)
	if err != nil || string(pt) != "secret" {
		t.Fatalf("open: %q %v", pt, err)
	}
	if _, err := Open(key, []byte("other"), s); err == nil {
		t.Fatal("opened with wrong AAD")
	}
	s.CT[0] ^= 1
	if _, err := Open(key, []byte("aad"), s); err == nil {
		t.Fatal("opened tampered ciphertext")
	}
}

func TestLabelDomainSeparation(t *testing.T) {
	root := bytes.Repeat([]byte{2}, 32)
	a := Label(root, "a")
	b := Label(root, "b")
	if bytes.Equal(a, b) {
		t.Fatal("labels collide")
	}
	if !bytes.Equal(a, Label(root, "a")) {
		t.Fatal("label not deterministic")
	}
}
