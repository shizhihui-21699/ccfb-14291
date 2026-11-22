package store

import (
	"database/sql"
	"fmt"
)

// RegisterNew atomically creates an account and its first OPAQUE credential.
// It fails with ErrAlreadyExists if the account key is taken, which is how a
// losing racer in a concurrent registration is rejected.
func (s *Store) RegisterNew(accountKey, credentialID []byte, identVersion int, suiteID string, c *Credential) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("store: register: %w", err)
	}
	defer tx.Rollback()
	now := s.now()
	if _, err := tx.Exec(`INSERT INTO accounts(account_key,credential_id,ident_version,suite_id,status,created_at) VALUES(?,?,?,?,?,?)`,
		accountKey, credentialID, identVersion, suiteID, "active", now); err != nil {
		if isConstraint(err) {
			return ErrAlreadyExists
		}
		return fmt.Errorf("store: register: %w", err)
	}
	if _, err := tx.Exec(`INSERT INTO credentials(account_key,suite_id,ksf_profile,ksf_salt,client_public_key,masking_key,envelope,record_mac,updated_at)
		VALUES(?,?,?,?,?,?,?,?,?)`,
		accountKey, c.SuiteID, c.KSFProfile, c.KSFSalt, c.ClientPublicKey, c.MaskingKey, c.Envelope, c.RecordMAC, now); err != nil {
		return fmt.Errorf("store: register: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: register: %w", err)
	}
	return nil
}

// InstallCredentialIfAbsent installs a credential only if the account has
// none yet, atomically. It returns installed=false if a credential already
// exists. Migration uses this so that two concurrent successful finishes
// cannot race to replace each other; the first wins and the second falls back
// to a normal login.
func (s *Store) InstallCredentialIfAbsent(accountKey []byte, c *Credential) (installed bool, err error) {
	tx, err := s.db.Begin()
	if err != nil {
		return false, fmt.Errorf("store: install credential: %w", err)
	}
	defer tx.Rollback()
	var n int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM credentials WHERE account_key=?`, accountKey).Scan(&n); err != nil {
		return false, fmt.Errorf("store: install credential: %w", err)
	}
	if n > 0 {
		return false, nil
	}
	now := s.now()
	if _, err := tx.Exec(`INSERT INTO credentials(account_key,suite_id,ksf_profile,ksf_salt,client_public_key,masking_key,envelope,record_mac,updated_at)
		VALUES(?,?,?,?,?,?,?,?,?)`,
		accountKey, c.SuiteID, c.KSFProfile, c.KSFSalt, c.ClientPublicKey, c.MaskingKey, c.Envelope, c.RecordMAC, now); err != nil {
		return false, fmt.Errorf("store: install credential: %w", err)
	}
	if _, err := tx.Exec(`DELETE FROM legacy_credentials WHERE account_key=?`, accountKey); err != nil {
		return false, fmt.Errorf("store: install credential: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("store: install credential: %w", err)
	}
	return true, nil
}

// InstallCredential replaces the credential for an existing account, deletes
// any legacy verifier in the same transaction, and optionally revokes sessions
// and trusted devices.
//
// This is the single write that completes a migration or a password change; it
// is deliberately one transaction so that there is never a state in which both
// a legacy verifier and a new OPAQUE credential are live, nor a state where
// the legacy row survives the upgrade.
func (s *Store) InstallCredential(accountKey []byte, c *Credential, revokeSessions, clearDevices bool) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("store: install credential: %w", err)
	}
	defer tx.Rollback()
	now := s.now()
	res, err := tx.Exec(`UPDATE accounts SET suite_id=? WHERE account_key=?`, c.SuiteID, accountKey)
	if err != nil {
		return fmt.Errorf("store: install credential: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	if _, err := tx.Exec(`INSERT INTO credentials(account_key,suite_id,ksf_profile,ksf_salt,client_public_key,masking_key,envelope,record_mac,updated_at)
		VALUES(?,?,?,?,?,?,?,?,?)
		ON CONFLICT(account_key) DO UPDATE SET
			suite_id=excluded.suite_id, ksf_profile=excluded.ksf_profile, ksf_salt=excluded.ksf_salt,
			client_public_key=excluded.client_public_key, masking_key=excluded.masking_key,
			envelope=excluded.envelope, record_mac=excluded.record_mac, updated_at=excluded.updated_at`,
		accountKey, c.SuiteID, c.KSFProfile, c.KSFSalt, c.ClientPublicKey, c.MaskingKey, c.Envelope, c.RecordMAC, now); err != nil {
		return fmt.Errorf("store: install credential: %w", err)
	}
	if _, err := tx.Exec(`DELETE FROM legacy_credentials WHERE account_key=?`, accountKey); err != nil {
		return fmt.Errorf("store: install credential: %w", err)
	}
	if revokeSessions {
		if _, err := tx.Exec(`UPDATE sessions SET revoked_at=? WHERE account_key=? AND revoked_at=0`, now, accountKey); err != nil {
			return fmt.Errorf("store: install credential: %w", err)
		}
	}
	if clearDevices {
		if _, err := tx.Exec(`DELETE FROM trusted_devices WHERE account_key=?`, accountKey); err != nil {
			return fmt.Errorf("store: install credential: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: install credential: %w", err)
	}
	return nil
}

// ImportLegacy creates or updates an account that only has a legacy verifier.
//
// The import path is idempotent and never touches OPAQUE credentials, so it
// can be re-run and can run concurrently with live migration: a user who
// migrates while a re-import is in progress keeps the new credential (the
// legacy row is re-created but the credential is untouched), and the next
// login sees an up-to-date legacy verifier only if it still exists.
func (s *Store) ImportLegacy(accountKey, credentialID []byte, identVersion int, suiteID string, l *Legacy) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("store: import legacy: %w", err)
	}
	defer tx.Rollback()
	now := s.now()
	if _, err := tx.Exec(`INSERT INTO accounts(account_key,credential_id,ident_version,suite_id,status,created_at) VALUES(?,?,?,?,?,?)
		ON CONFLICT(account_key) DO NOTHING`, accountKey, credentialID, identVersion, suiteID, "active", now); err != nil {
		return fmt.Errorf("store: import legacy: %w", err)
	}
	// The credential row is the source of truth. If the account has already
	// migrated, a re-import must neither overwrite the legacy row nor leave an
	// old one behind: actively delete it, so a stale verifier can never
	// outlive the credential that replaced it.
	var hasCred int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM credentials WHERE account_key=?`, accountKey).Scan(&hasCred); err != nil {
		return fmt.Errorf("store: import legacy: %w", err)
	}
	if hasCred > 0 {
		if _, err := tx.Exec(`DELETE FROM legacy_credentials WHERE account_key=?`, accountKey); err != nil {
			return fmt.Errorf("store: import legacy: %w", err)
		}
	}
	if hasCred == 0 && l != nil {
		if _, err := tx.Exec(`INSERT INTO legacy_credentials(account_key,scheme,cost,salt,hash,created_at) VALUES(?,?,?,?,?,?)
			ON CONFLICT(account_key) DO UPDATE SET scheme=excluded.scheme,cost=excluded.cost,salt=excluded.salt,hash=excluded.hash`,
			accountKey, l.Scheme, l.Cost, l.Salt, l.Hash, now); err != nil {
			return fmt.Errorf("store: import legacy: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: import legacy: %w", err)
	}
	return nil
}

// ReplaceAfterRecovery installs a fully new credential after a recovery
// redemption: sessions and devices are revoked, the legacy row is removed.
func (s *Store) ReplaceAfterRecovery(accountKey []byte, c *Credential) error {
	return s.InstallCredential(accountKey, c, true, true)
}

// Stats returns row counts, used by admin tooling and tests.
func (s *Store) Stats() (map[string]int64, error) {
	out := make(map[string]int64)
	for _, table := range []string{"accounts", "credentials", "legacy_credentials", "sessions", "trusted_devices", "recovery_tokens"} {
		var n int64
		if err := s.db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil {
			if err == sql.ErrNoRows {
				continue
			}
			return nil, fmt.Errorf("store: stats %s: %w", table, err)
		}
		out[table] = n
	}
	return out, nil
}

// AllLegacy returns every transitional verifier row, for key rotation.
func (s *Store) AllLegacy() ([]Legacy, error) {
	rows, err := s.db.Query(`SELECT account_key,scheme,cost,salt,hash FROM legacy_credentials`)
	if err != nil {
		return nil, fmt.Errorf("store: all legacy: %w", err)
	}
	defer rows.Close()
	var out []Legacy
	for rows.Next() {
		var l Legacy
		if err := rows.Scan(&l.AccountKey, &l.Scheme, &l.Cost, &l.Salt, &l.Hash); err != nil {
			return nil, fmt.Errorf("store: all legacy: %w", err)
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// SetLegacyHash replaces the sealed digest for a row. Used only by rewrap.
func (s *Store) SetLegacyHash(accountKey, hash []byte) error {
	_, err := s.db.Exec(`UPDATE legacy_credentials SET hash=? WHERE account_key=?`, hash, accountKey)
	if err != nil {
		return fmt.Errorf("store: set legacy hash: %w", err)
	}
	return nil
}
