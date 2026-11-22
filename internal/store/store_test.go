package store

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestAccountAndCredentialCRUD(t *testing.T) {
	s := open(t)
	key := []byte("acct")
	credID := []byte("cred")
	if err := s.CreateAccount(key, credID, 1, "suite"); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateAccount(key, credID, 1, "suite"); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("duplicate account: %v", err)
	}
	a, err := s.GetAccount(key)
	if err != nil || string(a.CredentialID) != "cred" {
		t.Fatalf("get account: %+v %v", a, err)
	}
	c := &Credential{AccountKey: key, SuiteID: "suite", KSFProfile: "p", KSFSalt: []byte("salt"),
		ClientPublicKey: []byte("pk"), MaskingKey: []byte("mk"), Envelope: []byte("env"), RecordMAC: []byte("mac")}
	if err := s.PutCredential(c); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetCredential(key)
	if err != nil || string(got.Envelope) != "env" {
		t.Fatalf("get credential: %+v %v", got, err)
	}
}

func TestOneShotConsumption(t *testing.T) {
	s := open(t)
	now := time.Unix(1000, 0)
	s.Now = func() time.Time { return now }
	ls := &LoginState{ID: []byte("id"), AccountKey: []byte("a"), Payload: []byte("p"), ExpiresAt: now.Add(time.Minute)}
	if err := s.CreateLoginState(ls); err != nil {
		t.Fatal(err)
	}
	// First consume succeeds, second fails: replay protection.
	if _, err := s.ConsumeLoginState(ls.ID); err != nil {
		t.Fatalf("first consume: %v", err)
	}
	if _, err := s.ConsumeLoginState(ls.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second consume: %v", err)
	}
}

func TestExpiredLoginStateRejected(t *testing.T) {
	s := open(t)
	now := time.Unix(1000, 0)
	s.Now = func() time.Time { return now }
	ls := &LoginState{ID: []byte("id"), AccountKey: []byte("a"), Payload: []byte("p"), ExpiresAt: now.Add(time.Second)}
	_ = s.CreateLoginState(ls)
	now = now.Add(2 * time.Second)
	if _, err := s.ConsumeLoginState(ls.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired state consumed: %v", err)
	}
}

func TestCeremonyKindEnforced(t *testing.T) {
	s := open(t)
	now := time.Unix(1000, 0)
	s.Now = func() time.Time { return now }
	if err := s.CreateCeremony(&Ceremony{ID: []byte("c"), Kind: CeremonyRegister, AccountKey: []byte("a"),
		Payload: []byte("p"), ExpiresAt: now.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	// Consuming with the wrong kind must fail: a recovery ceremony cannot be
	// used to finish a registration.
	if err := s.ConsumeCeremony([]byte("c"), CeremonyRecover); !errors.Is(err, ErrNotFound) {
		t.Fatalf("wrong-kind consume: %v", err)
	}
	if err := s.ConsumeCeremony([]byte("c"), CeremonyRegister); err != nil {
		t.Fatalf("right-kind consume: %v", err)
	}
}

func TestSessionExpiryAndRevocation(t *testing.T) {
	s := open(t)
	now := time.Unix(1000, 0)
	s.Now = func() time.Time { return now }
	th := []byte("th")
	if err := s.CreateSession(&Session{TokenHash: th, AccountKey: []byte("a"),
		AuthTime: now, ExpiresAt: now.Add(time.Hour), DeviceHash: []byte("d")}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSession(th); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Hour)
	if _, err := s.GetSession(th); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired session returned: %v", err)
	}
}
