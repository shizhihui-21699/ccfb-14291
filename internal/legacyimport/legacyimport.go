// Package legacyimport turns a dump of the pre-migration password table into
// rows this service can serve.
//
// The important property: a dump row is (identifier, bcrypt encoded hash). We
// store the identifier only as a peppered account key, keep the public bcrypt
// salt and cost, and seal the 23-character digest under a KMS subkey. Before a
// user logs in for the first time, their verifier is therefore already not
// directly usable from a stolen database — the second layer behind OPAQUE for
// the un-migrated population.
package legacyimport

import (
	"bufio"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"strings"

	"opaqueauth/internal/auth"
	"opaqueauth/internal/ident"
	"opaqueauth/internal/keyring"
	"opaqueauth/internal/keys"
	"opaqueauth/internal/legacy"
	"opaqueauth/internal/secure"
	"opaqueauth/internal/store"
	"opaqueauth/internal/suite"
)

// Record is one parsed dump row.
type Record struct {
	Identifier string
	Scheme     string
	Cost       int
	Salt       []byte
	Digest     []byte
}

// ImportStats summarises an import run.
type ImportStats struct {
	Total    int
	Imported int
	Migrated int // skipped because the account already has an OPAQUE credential
	Skipped  int
	Errors   []string
}

// ParseCSV reads rows of "identifier,encoded_bcrypt_hash". A header row whose
// first field is "identifier" is allowed and skipped.
func ParseCSV(r io.Reader) ([]Record, error) {
	cr := csv.NewReader(bufio.NewReader(r))
	cr.FieldsPerRecord = 2
	cr.LazyQuotes = true
	var out []Record
	first := true
	for {
		row, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("legacyimport: %w", err)
		}
		if first {
			first = false
			if strings.EqualFold(strings.TrimSpace(row[0]), "identifier") {
				continue
			}
		}
		rec, err := parseRow(row[0], row[1])
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, nil
}

// ParseLines reads "identifier:encoded_bcrypt_hash" lines, which is convenient
// for piping from a SQL extract.
func ParseLines(r io.Reader) ([]Record, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	var out []Record
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		id, hash, ok := strings.Cut(line, ":")
		if !ok {
			return nil, fmt.Errorf("legacyimport: line %d: missing ':'", n)
		}
		rec, err := parseRow(id, hash)
		if err != nil {
			return nil, fmt.Errorf("legacyimport: line %d: %w", n, err)
		}
		out = append(out, rec)
	}
	return out, sc.Err()
}

func parseRow(id, encoded string) (Record, error) {
	id = strings.TrimSpace(id)
	encoded = strings.TrimSpace(encoded)
	if id == "" {
		return Record{}, errors.New("legacyimport: empty identifier")
	}
	salt, cost, err := legacy.SaltFromEncoded(encoded)
	if err != nil {
		return Record{}, fmt.Errorf("legacyimport: %q: %w", id, err)
	}
	if cost < suite.LegacyMinCost || cost > suite.LegacyMaxCost {
		return Record{}, fmt.Errorf("legacyimport: %q: bcrypt cost %d outside accepted range [%d,%d]", id, cost, suite.LegacyMinCost, suite.LegacyMaxCost)
	}
	return Record{
		Identifier: id,
		Scheme:     "bcrypt",
		Cost:       cost,
		Salt:       salt,
		Digest:     []byte(encoded[29:]),
	}, nil
}

// Importer writes parsed rows into a Store.
type Importer struct {
	Store *store.Store
	Keys  *keys.Keys
	// Ring wraps legacy digests; nil builds a version-1 ring from Keys.
	Ring *keyring.Ring
	// DryRun parses and validates but does not write.
	DryRun bool
	// OnSkip is called for each row that is skipped, with the reason.
	OnSkip func(identifier, reason string)
}

// Import writes recs. It is idempotent: re-running updates the legacy row of
// accounts that have not yet migrated, and leaves migrated accounts untouched.
func (im *Importer) Import(recs []Record) (ImportStats, error) {
	var st ImportStats
	st.Total = len(recs)
	for _, r := range recs {
		canonical, err := ident.Canonicalize(r.Identifier)
		if err != nil {
			st.Skipped++
			st.Errors = append(st.Errors, fmt.Sprintf("%q: %v", r.Identifier, err))
			continue
		}
		accountKey := ident.AccountKey(im.Keys.AccountPepper, canonical)
		credID := ident.CredentialID(im.Keys.AccountPepper, accountKey)
		if im.DryRun {
			st.Imported++
			continue
		}
		if _, err := im.Store.GetAccount(accountKey); err == nil {
			if _, cerr := im.Store.GetCredential(accountKey); cerr == nil {
				// Already migrated. Still call ImportLegacy, which deletes any
				// stale legacy row under the same transaction, so a re-import
				// can never leave a verifier behind.
				if err := im.Store.ImportLegacy(accountKey, credID, ident.Version, suite.ID, nil); err != nil {
					st.Skipped++
					st.Errors = append(st.Errors, fmt.Sprintf("%q: %v", r.Identifier, err))
					continue
				}
				st.Migrated++
				if im.OnSkip != nil {
					im.OnSkip(r.Identifier, "already migrated")
				}
				continue
			}
		}
		ring := im.Ring
		if ring == nil {
			ring, err = keyring.New(1, im.Keys.LegacyVerifier, nil)
			if err != nil {
				return st, err
			}
		}
		sealed, err := auth.SealLegacyDigest(ring, accountKey, r.Digest)
		if err != nil {
			return st, err
		}
		leg := &store.Legacy{
			AccountKey: accountKey, Scheme: r.Scheme, Cost: r.Cost,
			Salt: append([]byte(nil), r.Salt...), Hash: sealed,
		}
		if err := im.Store.ImportLegacy(accountKey, credID, ident.Version, suite.ID, leg); err != nil {
			st.Skipped++
			st.Errors = append(st.Errors, fmt.Sprintf("%q: %v", r.Identifier, err))
			continue
		}
		st.Imported++
	}
	secure.Zero(nil)
	return st, nil
}
