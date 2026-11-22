package legacyimport

import (
	"errors"
	"strings"
	"testing"

	"github.com/bytemare/opaque"

	"opaqueauth/internal/ident"
	"opaqueauth/internal/keys"
	"opaqueauth/internal/kms"
	"opaqueauth/internal/legacy"
	"opaqueauth/internal/store"
	"opaqueauth/internal/suite"
)

func TestParseLines(t *testing.T) {
	salt := strings.Repeat("A", 16)
	digest, err := legacy.BCryptRaw([]byte("pw"), []byte(salt), 12)
	if err != nil {
		t.Fatal(err)
	}
	enc := legacy.Encode([]byte(salt), 12, digest)
	in := "# comment\n\nalice:" + enc + "\n"
	recs, err := ParseLines(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].Identifier != "alice" || recs[0].Cost != 12 {
		t.Fatalf("unexpected parse result: %+v", recs)
	}
}

func TestParseRejectsBadCost(t *testing.T) {
	salt := strings.Repeat("A", 16)
	digest, _ := legacy.BCryptRaw([]byte("pw"), []byte(salt), 4)
	enc := legacy.Encode([]byte(salt), 4, digest) // cost 4 is below policy floor
	if _, err := ParseLines(strings.NewReader("alice:" + enc)); err == nil {
		t.Fatal("accepted a bcrypt cost below the policy floor")
	}
}

func TestImportIdempotentAndUpdatable(t *testing.T) {
	db, err := store.Open(t.TempDir() + "/db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	k := testKeys(t)
	im := &Importer{Store: db, Keys: k}

	salt := []byte(strings.Repeat("B", 16))
	digest, _ := legacy.BCryptRaw([]byte("pw1"), salt, 12)
	recs := []Record{{Identifier: "u1", Scheme: "bcrypt", Cost: 12, Salt: salt, Digest: []byte(digest)}}

	st, err := im.Import(recs)
	if err != nil {
		t.Fatal(err)
	}
	if st.Imported != 1 {
		t.Fatalf("imported %d", st.Imported)
	}
	// Re-import with a new password: the legacy row must be updated, not
	// duplicated.
	digest2, _ := legacy.BCryptRaw([]byte("pw2"), salt, 12)
	recs[0].Digest = []byte(digest2)
	if _, err := im.Import(recs); err != nil {
		t.Fatal(err)
	}
	canonical, _ := ident.Canonicalize("u1")
	acct := ident.AccountKey(k.AccountPepper, canonical)
	leg, err := db.GetLegacy(acct)
	if err != nil {
		t.Fatal(err)
	}
	_ = leg
	stats, _ := db.Stats()
	if stats["legacy_credentials"] != 1 {
		t.Fatalf("expected one legacy row, got %d", stats["legacy_credentials"])
	}
}

func TestImportDoesNotResurrectMigrated(t *testing.T) {
	db, err := store.Open(t.TempDir() + "/db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	k := testKeys(t)
	im := &Importer{Store: db, Keys: k}

	salt := []byte(strings.Repeat("C", 16))
	digest, _ := legacy.BCryptRaw([]byte("pw"), salt, 12)
	recs := []Record{{Identifier: "u2", Scheme: "bcrypt", Cost: 12, Salt: salt, Digest: []byte(digest)}}
	if _, err := im.Import(recs); err != nil {
		t.Fatal(err)
	}
	canonical, _ := ident.Canonicalize("u2")
	acct := ident.AccountKey(k.AccountPepper, canonical)
	// Simulate migration by installing a credential.
	cred := &store.Credential{
		AccountKey: acct, SuiteID: suite.ID, KSFProfile: suite.ProfileV1.ID,
		KSFSalt: make([]byte, 16), ClientPublicKey: make([]byte, 32),
		MaskingKey: make([]byte, 64), Envelope: make([]byte, 96), RecordMAC: make([]byte, 32),
	}
	if err := db.PutCredential(cred); err != nil {
		t.Fatal(err)
	}
	st, err := im.Import(recs)
	if err != nil {
		t.Fatal(err)
	}
	if st.Migrated != 1 {
		t.Fatalf("expected the re-import to skip the migrated account, got %+v", st)
	}
	// And crucially, the legacy row must not exist.
	if _, err := db.GetLegacy(acct); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("legacy row resurrected: %v", err)
	}
}

func testKeys(t *testing.T) *keys.Keys {
	t.Helper()
	prov := kms.NewMemoryProvider()
	prov.Set(kms.AppRoot, bytesN(32, 5))
	conf := suite.Configuration()
	seed := conf.GenerateOPRFSeed()
	sk, pk := conf.KeyGen()
	prov.Set(kms.OPAQUEServerKeyMaterial, (&opaque.ServerKeyMaterial{
		PrivateKey: sk, PublicKeyBytes: pk.Encode(),
		OPRFGlobalSeed: seed, Identity: []byte(suite.ServerIdentity),
	}).Encode())
	k, err := keys.Load(prov)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func bytesN(n int, b byte) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
