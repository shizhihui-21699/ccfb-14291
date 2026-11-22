// Command authctl provisions key material, imports legacy password dumps, and
// reports on migration progress.
//
// Key provisioning is deliberately a separate command run by an operator with
// access to the secret store; the service process never generates its own root
// key, because a compromised service host must not be able to mint a new one
// (that would silently invalidate the whole user base).
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/bytemare/opaque"

	"opaqueauth/internal/auth"
	"opaqueauth/internal/ident"
	"opaqueauth/internal/keys"
	"opaqueauth/internal/kms"
	"opaqueauth/internal/legacy"
	"opaqueauth/internal/legacyimport"
	"opaqueauth/internal/secure"
	"opaqueauth/internal/store"
	"opaqueauth/internal/suite"
)

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "keygen":
		cmdKeygen(os.Args[2:])
	case "import-legacy":
		cmdImport(os.Args[2:])
	case "status":
		cmdStatus(os.Args[2:])
	case "make-invite":
		cmdMakeInvite(os.Args[2:])
	case "make-legacy-row":
		cmdMakeLegacyRow(os.Args[2:])
	case "rewrap-legacy":
		cmdRewrapLegacy(os.Args[2:])
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `usage: authctl <command> [flags]

  keygen        -out FILE            generate an app root and OPAQUE server key material
  import-legacy -db FILE -keys FILE -in FILE [-format csv|lines] [-dry-run]
  status        -db FILE -keys FILE
  make-invite   -invite-key HEX
  make-legacy-row -identifier NAME -password PASS
  rewrap-legacy -db FILE -keys FILE [-retain FILE]  re-encrypt legacy digests under the active key
`)
	os.Exit(2)
}

func cmdKeygen(args []string) {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("out", "", "output key file (created mode 0600)")
	force := fs.Bool("force", false, "overwrite an existing file")
	fs.Parse(args)
	if *out == "" {
		log.Fatal("authctl: -out is required")
	}
	if !*force {
		if _, err := os.Stat(*out); err == nil {
			log.Fatalf("authctl: %s exists; refusing to overwrite", *out)
		}
	}
	root := keys.GenerateRoot()
	enc, err := newServerKeyMaterial()
	if err != nil {
		log.Fatalf("authctl: %v", err)
	}
	doc := map[string]string{
		string(kms.AppRoot):                 hex.EncodeToString(root),
		string(kms.OPAQUEServerKeyMaterial): hex.EncodeToString(enc),
	}
	buf, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		log.Fatalf("authctl: %v", err)
	}
	if err := os.WriteFile(*out, buf, 0o600); err != nil {
		log.Fatalf("authctl: %v", err)
	}
	fmt.Printf("wrote %s (mode 0600). Store it in your secret manager; it must never be\n"+
		"backed up with the database, or the OPAQUE guarantee is lost.\n", *out)
}

func cmdImport(args []string) {
	fs := flag.NewFlagSet("import-legacy", flag.ExitOnError)
	dbPath := fs.String("db", "", "SQLite database path")
	keyFile := fs.String("keys", "", "key file")
	in := fs.String("in", "-", "input file ('-' for stdin)")
	format := fs.String("format", "lines", "csv or lines")
	dry := fs.Bool("dry-run", false, "validate without writing")
	fs.Parse(args)
	if *dbPath == "" || *keyFile == "" {
		log.Fatal("authctl: -db and -keys are required")
	}
	provider, err := kms.NewFileProvider(*keyFile)
	if err != nil {
		log.Fatalf("authctl: %v", err)
	}
	k, err := keys.Load(provider)
	if err != nil {
		log.Fatalf("authctl: %v", err)
	}
	db, err := store.Open(*dbPath)
	if err != nil {
		log.Fatalf("authctl: %v", err)
	}
	defer db.Close()

	r := os.Stdin
	if *in != "-" {
		f, err := os.Open(*in)
		if err != nil {
			log.Fatalf("authctl: %v", err)
		}
		defer f.Close()
		r = f
	}
	var recs []legacyimport.Record
	switch *format {
	case "csv":
		recs, err = legacyimport.ParseCSV(r)
	case "lines":
		recs, err = legacyimport.ParseLines(r)
	default:
		log.Fatalf("authctl: unknown -format %q", *format)
	}
	if err != nil {
		log.Fatalf("authctl: %v", err)
	}
	im := &legacyimport.Importer{Store: db, Keys: k, DryRun: *dry, OnSkip: func(id, reason string) {
		fmt.Printf("skip %s: %s\n", id, reason)
	}}
	st, err := im.Import(recs)
	if err != nil {
		log.Fatalf("authctl: %v", err)
	}
	for _, e := range st.Errors {
		fmt.Fprintf(os.Stderr, "error: %s\n", e)
	}
	fmt.Printf("total=%d imported=%d already-migrated=%d skipped=%d dry_run=%v\n",
		st.Total, st.Imported, st.Migrated, st.Skipped, *dry)
}

func cmdStatus(args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	dbPath := fs.String("db", "", "SQLite database path")
	keyFile := fs.String("keys", "", "key file")
	fs.Parse(args)
	if *dbPath == "" || *keyFile == "" {
		log.Fatal("authctl: -db and -keys are required")
	}
	db, err := store.Open(*dbPath)
	if err != nil {
		log.Fatalf("authctl: %v", err)
	}
	defer db.Close()
	st, err := db.Stats()
	if err != nil {
		log.Fatalf("authctl: %v", err)
	}
	accts := st["accounts"]
	legacyN := st["legacy_credentials"]
	migrated := accts - legacyN
	if migrated < 0 {
		migrated = 0
	}
	pct := 0.0
	if accts > 0 {
		pct = 100 * float64(migrated) / float64(accts)
	}
	fmt.Printf("accounts=%d migrated=%d legacy_remaining=%d (%.2f%% migrated)\n",
		accts, migrated, legacyN, pct)
	fmt.Printf("sessions=%d trusted_devices=%d recovery_tokens=%d\n",
		st["sessions"], st["trusted_devices"], st["recovery_tokens"])
}

func cmdMakeInvite(args []string) {
	fs := flag.NewFlagSet("make-invite", flag.ExitOnError)
	keyHex := fs.String("invite-key", "", "hex invite key")
	fs.Parse(args)
	if *keyHex == "" {
		log.Fatal("authctl: -invite-key is required")
	}
	key, err := hex.DecodeString(*keyHex)
	if err != nil {
		log.Fatalf("authctl: %v", err)
	}
	nonce := secure.Random(16)
	fmt.Printf("%s.%s\n", b64(nonce), b64(inviteMAC(key, nonce)))
}

// cmdMakeLegacyRow produces a bcrypt row for testing the import and migration
// without needing a real old database.
func cmdMakeLegacyRow(args []string) {
	fs := flag.NewFlagSet("make-legacy-row", flag.ExitOnError)
	id := fs.String("identifier", "", "identifier")
	pw := fs.String("password", "", "password")
	cost := fs.Int("cost", suite.LegacyDecoyCost, "bcrypt cost")
	fs.Parse(args)
	if *id == "" || *pw == "" {
		log.Fatal("authctl: -identifier and -password are required")
	}
	salt := secure.Random(16)
	digest, err := legacy.BCryptRaw([]byte(*pw), salt, *cost)
	if err != nil {
		log.Fatalf("authctl: %v", err)
	}
	fmt.Printf("%s:%s\n", *id, legacy.Encode(salt, *cost, digest))
}

// cmdRewrapLegacy re-encrypts every transitional legacy digest under the
// active key version. It must run to completion during a key rotation, before
// the old key is retired.
func cmdRewrapLegacy(args []string) {
	fs := flag.NewFlagSet("rewrap-legacy", flag.ExitOnError)
	dbPath := fs.String("db", "", "SQLite database path")
	keyFile := fs.String("keys", "", "key file holding the active key and any retained key(s)")
	fs.Parse(args)
	if *dbPath == "" || *keyFile == "" {
		log.Fatal("authctl: -db and -keys are required")
	}
	provider, err := kms.NewFileProvider(*keyFile)
	if err != nil {
		log.Fatal(err)
	}
	ring, err := buildRing(provider)
	if err != nil {
		log.Fatal(err)
	}
	db, err := store.Open(*dbPath)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	legs, err := db.AllLegacy()
	if err != nil {
		log.Fatal(err)
	}
	rewrapped := 0
	for _, l := range legs {
		if !ring.NeedsRewrap(l.Hash) {
			continue
		}
		moved, err := ring.Rewrap(auth.LegacyDigestAAD(l.AccountKey), l.Hash)
		if err != nil {
			log.Fatalf("authctl: rewrap %x: %v", l.AccountKey, err)
		}
		if err := db.SetLegacyHash(l.AccountKey, moved); err != nil {
			log.Fatal(err)
		}
		rewrapped++
	}
	fmt.Printf("rewrapped %d of %d legacy digests under key version %d\n", rewrapped, len(legs), ring.ActiveVersion())
}

// --- shared helpers ---

func newServerKeyMaterial() ([]byte, error) {
	conf := suite.Configuration()
	seed := conf.GenerateOPRFSeed()
	sk, pk := conf.KeyGen()
	skm := &opaque.ServerKeyMaterial{
		PrivateKey: sk, PublicKeyBytes: pk.Encode(),
		OPRFGlobalSeed: seed, Identity: []byte(suite.ServerIdentity),
	}
	enc := skm.Encode()
	if _, err := conf.DecodeServerKeyMaterial(enc); err != nil {
		return nil, err
	}
	return enc, nil
}

// inviteMAC is duplicated from cmd/authd by design: the issuer and verifier
// are separate trust domains, and the format is pinned here once.
func inviteMAC(key, nonce []byte) []byte {
	return secure.HMAC(key, []byte("invite/v1\x00"), nonce)
}

func b64(b []byte) string { return secure.B64(b) }

// ensure references used.
var _ = ident.Version
var _ = time.Now
