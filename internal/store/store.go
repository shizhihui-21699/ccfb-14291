// Package store is the persistence layer for the authentication service.
//
// Design rule that the whole security argument depends on: nothing stored here
// is sufficient, together with the database alone, to test a password guess.
// Concretely the database holds
//
//   - account rows keyed by a peppered hash of the identifier (no plaintext
//     identifiers, no way to enumerate the user table from the dump alone);
//   - OPAQUE credential files (client public key, masking key, envelope) plus
//     a MAC over them under a KMS key (integrity/row-swap defence);
//   - transitional bcrypt verifiers for not-yet-migrated users. This is the
//     one thing in the schema that *is* offline-checkable, which is exactly
//     why migration exists and why the legacy table is deleted row-by-row on
//     first successful migration and can be dropped at cut-off;
//   - transient ceremony/login state, sealed with AES-GCM under KMS keys;
//   - sessions and recovery tokens, stored only as HMACs.
//
// The OPRF seed and AKE private key are not here at all (see package kms).
package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("store: not found")

// ErrAlreadyExists is returned for duplicate inserts.
var ErrAlreadyExists = errors.New("store: already exists")

// Store is a SQLite-backed store.
type Store struct {
	db  *sql.DB
	Now func() time.Time
}

// Open opens (creating if needed) the SQLite database at path.
//
// WAL and synchronous=FULL are used so that a successful login is durable
// before the session token is returned: a crash must not resurrect a
// consumed migration ceremony or a used recovery token.
func Open(path string) (*Store, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=secure_delete(1)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open: %w", err)
	}
	// A single writer connection avoids SQLITE_BUSY storms and keeps
	// transaction ordering simple. Reads still use the WAL.
	db.SetMaxOpenConns(1)
	s := &Store{db: db, Now: time.Now}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// DB exposes the underlying handle for tests and admin tooling.
func (s *Store) DB() *sql.DB { return s.db }

func (s *Store) now() int64 { return s.Now().UnixMilli() }

const schema = `
CREATE TABLE IF NOT EXISTS meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS accounts (
  account_key   BLOB PRIMARY KEY,
  credential_id BLOB NOT NULL,          -- OPAQUE credential_identifier (not secret)
  ident_version INTEGER NOT NULL,
  suite_id      TEXT NOT NULL,
  status        TEXT NOT NULL,          -- active | disabled
  created_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS credentials (
  account_key       BLOB PRIMARY KEY REFERENCES accounts(account_key) ON DELETE CASCADE,
  suite_id          TEXT NOT NULL,
  ksf_profile       TEXT NOT NULL,
  ksf_salt          BLOB NOT NULL,
  client_public_key BLOB NOT NULL,
  masking_key       BLOB NOT NULL,
  envelope          BLOB NOT NULL,
  record_mac        BLOB NOT NULL,
  updated_at        INTEGER NOT NULL
);

-- Transitional. Rows disappear as users migrate. Dropping this table is the
-- cut-over step once the migration window closes.
CREATE TABLE IF NOT EXISTS legacy_credentials (
  account_key BLOB PRIMARY KEY REFERENCES accounts(account_key) ON DELETE CASCADE,
  scheme      TEXT NOT NULL,   -- 'bcrypt'
  cost        INTEGER NOT NULL,
  salt        BLOB NOT NULL,
  hash        BLOB NOT NULL,
  created_at  INTEGER NOT NULL
);

-- Short-lived multi-step ceremonies (registration, migration, recovery,
-- password change). payload is AEAD-sealed by the caller.
CREATE TABLE IF NOT EXISTS ceremonies (
  id          BLOB PRIMARY KEY,
  kind        TEXT NOT NULL,
  account_key BLOB NOT NULL,
  payload     BLOB NOT NULL,
  expires_at  INTEGER NOT NULL,
  consumed_at INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ceremonies_expiry ON ceremonies(expires_at);

CREATE TABLE IF NOT EXISTS login_states (
  id          BLOB PRIMARY KEY,
  account_key BLOB NOT NULL,
  payload     BLOB NOT NULL,
  expires_at  INTEGER NOT NULL,
  consumed_at INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS login_states_expiry ON login_states(expires_at);

CREATE TABLE IF NOT EXISTS sessions (
  token_hash  BLOB PRIMARY KEY,
  account_key BLOB NOT NULL,
  created_at  INTEGER NOT NULL,
  auth_time   INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL,
  last_seen   INTEGER NOT NULL,
  device_hash BLOB NOT NULL,
  revoked_at  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS sessions_account ON sessions(account_key);

CREATE TABLE IF NOT EXISTS recovery_tokens (
  token_hash  BLOB PRIMARY KEY,
  account_key BLOB NOT NULL,
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL,
  consumed_at INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS contacts (
  account_key  BLOB PRIMARY KEY REFERENCES accounts(account_key) ON DELETE CASCADE,
  sealed_email BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS trusted_devices (
  device_hash BLOB PRIMARY KEY,
  account_key BLOB NOT NULL,
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
  seq        INTEGER PRIMARY KEY AUTOINCREMENT,
  at         INTEGER NOT NULL,
  event      TEXT NOT NULL,
  detail     BLOB NOT NULL,
  prev_mac   BLOB NOT NULL,
  mac        BLOB NOT NULL
);
`

func (s *Store) migrate() error {
	if _, err := s.db.Exec(schema); err != nil {
		return fmt.Errorf("store: migrate: %w", err)
	}
	return nil
}

// SetMeta records a metadata value.
func (s *Store) SetMeta(key, value string) error {
	_, err := s.db.Exec(`INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	if err != nil {
		return fmt.Errorf("store: set meta: %w", err)
	}
	return nil
}

// Meta reads a metadata value.
func (s *Store) Meta(key string) (string, error) {
	var v string
	err := s.db.QueryRow(`SELECT value FROM meta WHERE key=?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("store: get meta: %w", err)
	}
	return v, nil
}

// Account is an account row. The identifier itself is not stored; it is an
// input to the peppered account key.
type Account struct {
	Key          []byte
	CredentialID []byte
	IdentVersion int
	SuiteID      string
	Status       string
	CreatedAt    time.Time
}

// CreateAccount inserts an account. The caller must already hold the drained
// per-identifier lock that makes account creation race-free.
func (s *Store) CreateAccount(key, credentialID []byte, identVersion int, suiteID string) error {
	_, err := s.db.Exec(`INSERT INTO accounts(account_key,credential_id,ident_version,suite_id,status,created_at) VALUES(?,?,?,?,?,?)`,
		key, credentialID, identVersion, suiteID, "active", s.now())
	if err != nil {
		if isConstraint(err) {
			return ErrAlreadyExists
		}
		return fmt.Errorf("store: create account: %w", err)
	}
	return nil
}

// GetAccount loads one account.
func (s *Store) GetAccount(key []byte) (*Account, error) {
	var a Account
	var created int64
	err := s.db.QueryRow(`SELECT account_key,credential_id,ident_version,suite_id,status,created_at FROM accounts WHERE account_key=?`, key).
		Scan(&a.Key, &a.CredentialID, &a.IdentVersion, &a.SuiteID, &a.Status, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: get account: %w", err)
	}
	a.CreatedAt = time.UnixMilli(created)
	return &a, nil
}

// SetAccountStatus updates the status.
func (s *Store) SetAccountStatus(key []byte, status string) error {
	_, err := s.db.Exec(`UPDATE accounts SET status=? WHERE account_key=?`, status, key)
	return err
}

// Credential is a stored OPAQUE credential file plus our metadata.
type Credential struct {
	AccountKey      []byte
	SuiteID         string
	KSFProfile      string
	KSFSalt         []byte
	ClientPublicKey []byte
	MaskingKey      []byte
	Envelope        []byte
	RecordMAC       []byte
	UpdatedAt       time.Time
}

// PutCredential inserts or replaces a credential.
func (s *Store) PutCredential(c *Credential) error {
	_, err := s.db.Exec(`INSERT INTO credentials(account_key,suite_id,ksf_profile,ksf_salt,client_public_key,masking_key,envelope,record_mac,updated_at)
		VALUES(?,?,?,?,?,?,?,?,?)
		ON CONFLICT(account_key) DO UPDATE SET
			suite_id=excluded.suite_id, ksf_profile=excluded.ksf_profile, ksf_salt=excluded.ksf_salt,
			client_public_key=excluded.client_public_key, masking_key=excluded.masking_key,
			envelope=excluded.envelope, record_mac=excluded.record_mac, updated_at=excluded.updated_at`,
		c.AccountKey, c.SuiteID, c.KSFProfile, c.KSFSalt, c.ClientPublicKey, c.MaskingKey, c.Envelope, c.RecordMAC, s.now())
	if err != nil {
		return fmt.Errorf("store: put credential: %w", err)
	}
	return nil
}

// GetCredential loads one credential.
func (s *Store) GetCredential(accountKey []byte) (*Credential, error) {
	var c Credential
	var updated int64
	err := s.db.QueryRow(`SELECT account_key,suite_id,ksf_profile,ksf_salt,client_public_key,masking_key,envelope,record_mac,updated_at
		FROM credentials WHERE account_key=?`, accountKey).
		Scan(&c.AccountKey, &c.SuiteID, &c.KSFProfile, &c.KSFSalt, &c.ClientPublicKey, &c.MaskingKey, &c.Envelope, &c.RecordMAC, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: get credential: %w", err)
	}
	c.UpdatedAt = time.UnixMilli(updated)
	return &c, nil
}

// DeleteCredential removes a credential (used by explicit reset paths).
func (s *Store) DeleteCredential(accountKey []byte) error {
	_, err := s.db.Exec(`DELETE FROM credentials WHERE account_key=?`, accountKey)
	return err
}

// Legacy is a transitional legacy verifier row.
type Legacy struct {
	AccountKey []byte
	Scheme     string
	Cost       int
	Salt       []byte
	Hash       []byte
}

// PutLegacy inserts a legacy verifier.
func (s *Store) PutLegacy(l *Legacy) error {
	_, err := s.db.Exec(`INSERT INTO legacy_credentials(account_key,scheme,cost,salt,hash,created_at) VALUES(?,?,?,?,?,?)
		ON CONFLICT(account_key) DO UPDATE SET scheme=excluded.scheme,cost=excluded.cost,salt=excluded.salt,hash=excluded.hash`,
		l.AccountKey, l.Scheme, l.Cost, l.Salt, l.Hash, s.now())
	if err != nil {
		return fmt.Errorf("store: put legacy: %w", err)
	}
	return nil
}

// GetLegacy loads a legacy verifier.
func (s *Store) GetLegacy(accountKey []byte) (*Legacy, error) {
	var l Legacy
	err := s.db.QueryRow(`SELECT account_key,scheme,cost,salt,hash FROM legacy_credentials WHERE account_key=?`, accountKey).
		Scan(&l.AccountKey, &l.Scheme, &l.Cost, &l.Salt, &l.Hash)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: get legacy: %w", err)
	}
	return &l, nil
}

// DeleteLegacy removes a legacy verifier. Called in the same transaction that
// installs the OPAQUE credential.
func (s *Store) DeleteLegacy(accountKey []byte) error {
	_, err := s.db.Exec(`DELETE FROM legacy_credentials WHERE account_key=?`, accountKey)
	return err
}

// Contact stores an encrypted recovery address.
func (s *Store) PutContact(accountKey []byte, sealedEmail []byte) error {
	_, err := s.db.Exec(`INSERT INTO contacts(account_key,sealed_email) VALUES(?,?)
		ON CONFLICT(account_key) DO UPDATE SET sealed_email=excluded.sealed_email`, accountKey, sealedEmail)
	if err != nil {
		return fmt.Errorf("store: put contact: %w", err)
	}
	return nil
}

// GetContact reads an encrypted recovery address.
func (s *Store) GetContact(accountKey []byte) ([]byte, error) {
	var sealed []byte
	err := s.db.QueryRow(`SELECT sealed_email FROM contacts WHERE account_key=?`, accountKey).Scan(&sealed)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: get contact: %w", err)
	}
	return sealed, nil
}

func isConstraint(err error) bool {
	// modernc/sqlite reports constraint violations in the message; keep this
	// loose so we do not depend on a driver-specific error type.
	msg := err.Error()
	return contains(msg, "UNIQUE constraint") || contains(msg, "constraint failed")
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
