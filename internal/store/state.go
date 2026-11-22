package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Ceremony is a short-lived multi-step flow (register, migrate, recover,
// change). The payload is opaque to the store: the auth layer seals it with
// AES-GCM and binds it to the ID and kind.
type Ceremony struct {
	ID         []byte
	Kind       string
	AccountKey []byte
	Payload    []byte
	ExpiresAt  time.Time
	Consumed   bool
}

// CeremonyKind values.
const (
	CeremonyRegister = "register"
	CeremonyMigrate  = "migrate"
	CeremonyRecover  = "recover"
	CeremonyChange   = "change"
)

// CreateCeremony inserts a ceremony.
func (s *Store) CreateCeremony(c *Ceremony) error {
	_, err := s.db.Exec(`INSERT INTO ceremonies(id,kind,account_key,payload,expires_at) VALUES(?,?,?,?,?)`,
		c.ID, c.Kind, c.AccountKey, c.Payload, c.ExpiresAt.UnixMilli())
	if err != nil {
		if isConstraint(err) {
			return ErrAlreadyExists
		}
		return fmt.Errorf("store: create ceremony: %w", err)
	}
	return nil
}

// GetCeremony loads a ceremony without consuming it.
func (s *Store) GetCeremony(id []byte) (*Ceremony, error) {
	var c Ceremony
	var exp int64
	var consumed int64
	err := s.db.QueryRow(`SELECT id,kind,account_key,payload,expires_at,consumed_at FROM ceremonies WHERE id=?`, id).
		Scan(&c.ID, &c.Kind, &c.AccountKey, &c.Payload, &exp, &consumed)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: get ceremony: %w", err)
	}
	c.ExpiresAt = time.UnixMilli(exp)
	c.Consumed = consumed != 0
	return &c, nil
}

// ConsumeCeremony atomically marks a ceremony consumed. It returns ErrNotFound
// if the ceremony is missing, expired, already consumed, or of the wrong kind.
func (s *Store) ConsumeCeremony(id []byte, kind string) error {
	res, err := s.db.Exec(`UPDATE ceremonies SET consumed_at=? WHERE id=? AND kind=? AND consumed_at=0 AND expires_at>?`,
		s.now(), id, kind, s.now())
	if err != nil {
		return fmt.Errorf("store: consume ceremony: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: consume ceremony: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteExpiredCeremonies removes stale rows.
func (s *Store) DeleteExpiredCeremonies(before time.Time) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM ceremonies WHERE expires_at<?`, before.UnixMilli())
	if err != nil {
		return 0, fmt.Errorf("store: purge ceremonies: %w", err)
	}
	return res.RowsAffected()
}

// LoginState is an in-flight OPAQUE login (between KE1 and KE3).
type LoginState struct {
	ID         []byte
	AccountKey []byte
	Payload    []byte
	ExpiresAt  time.Time
}

// CreateLoginState inserts login state.
func (s *Store) CreateLoginState(l *LoginState) error {
	_, err := s.db.Exec(`INSERT INTO login_states(id,account_key,payload,expires_at) VALUES(?,?,?,?)`,
		l.ID, l.AccountKey, l.Payload, l.ExpiresAt.UnixMilli())
	if err != nil {
		if isConstraint(err) {
			return ErrAlreadyExists
		}
		return fmt.Errorf("store: create login state: %w", err)
	}
	return nil
}

// ConsumeLoginState atomically reads and deletes a login state. A login state
// is single-use: this is what prevents an attacker from replaying a completed
// KE1/KE2 exchange or from forcing a second KE3 against the same transcript.
func (s *Store) ConsumeLoginState(id []byte) (*LoginState, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("store: consume login state: %w", err)
	}
	defer tx.Rollback()
	var l LoginState
	var exp int64
	err = tx.QueryRow(`SELECT id,account_key,payload,expires_at FROM login_states WHERE id=? AND consumed_at=0 AND expires_at>?`, id, s.now()).
		Scan(&l.ID, &l.AccountKey, &l.Payload, &exp)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: consume login state: %w", err)
	}
	if _, err := tx.Exec(`DELETE FROM login_states WHERE id=?`, id); err != nil {
		return nil, fmt.Errorf("store: consume login state: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("store: consume login state: %w", err)
	}
	l.ExpiresAt = time.UnixMilli(exp)
	return &l, nil
}

// DeleteExpiredLoginStates removes stale rows.
func (s *Store) DeleteExpiredLoginStates(before time.Time) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM login_states WHERE expires_at<?`, before.UnixMilli())
	if err != nil {
		return 0, fmt.Errorf("store: purge login states: %w", err)
	}
	return res.RowsAffected()
}

// Session is an authenticated session.
type Session struct {
	TokenHash  []byte
	AccountKey []byte
	CreatedAt  time.Time
	AuthTime   time.Time
	ExpiresAt  time.Time
	LastSeen   time.Time
	DeviceHash []byte
	Revoked    bool
}

// CreateSession inserts a session.
func (s *Store) CreateSession(sess *Session) error {
	now := s.now()
	_, err := s.db.Exec(`INSERT INTO sessions(token_hash,account_key,created_at,auth_time,expires_at,last_seen,device_hash) VALUES(?,?,?,?,?,?,?)`,
		sess.TokenHash, sess.AccountKey, now, sess.AuthTime.UnixMilli(), sess.ExpiresAt.UnixMilli(), now, sess.DeviceHash)
	if err != nil {
		return fmt.Errorf("store: create session: %w", err)
	}
	return nil
}

// GetSession loads a live session by token hash.
func (s *Store) GetSession(tokenHash []byte) (*Session, error) {
	var sess Session
	var created, auth, exp, seen int64
	var revoked int64
	err := s.db.QueryRow(`SELECT token_hash,account_key,created_at,auth_time,expires_at,last_seen,device_hash,revoked_at FROM sessions WHERE token_hash=?`, tokenHash).
		Scan(&sess.TokenHash, &sess.AccountKey, &created, &auth, &exp, &seen, &sess.DeviceHash, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: get session: %w", err)
	}
	sess.CreatedAt = time.UnixMilli(created)
	sess.AuthTime = time.UnixMilli(auth)
	sess.ExpiresAt = time.UnixMilli(exp)
	sess.LastSeen = time.UnixMilli(seen)
	sess.Revoked = revoked != 0
	if sess.Revoked || sess.ExpiresAt.Before(s.Now()) {
		return nil, ErrNotFound
	}
	return &sess, nil
}

// TouchSession updates last_seen.
func (s *Store) TouchSession(tokenHash []byte) error {
	_, err := s.db.Exec(`UPDATE sessions SET last_seen=? WHERE token_hash=?`, s.now(), tokenHash)
	return err
}

// RevokeSession revokes one session.
func (s *Store) RevokeSession(tokenHash []byte) error {
	_, err := s.db.Exec(`UPDATE sessions SET revoked_at=? WHERE token_hash=? AND revoked_at=0`, s.now(), tokenHash)
	return err
}

// RevokeAccountSessions revokes every session for an account. Called on
// password change, recovery, and account disable.
func (s *Store) RevokeAccountSessions(accountKey []byte) (int64, error) {
	res, err := s.db.Exec(`UPDATE sessions SET revoked_at=? WHERE account_key=? AND revoked_at=0`, s.now(), accountKey)
	if err != nil {
		return 0, fmt.Errorf("store: revoke sessions: %w", err)
	}
	return res.RowsAffected()
}

// DeleteExpiredSessions removes stale rows.
func (s *Store) DeleteExpiredSessions(before time.Time) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM sessions WHERE expires_at<?`, before.UnixMilli())
	if err != nil {
		return 0, fmt.Errorf("store: purge sessions: %w", err)
	}
	return res.RowsAffected()
}

// RecoveryToken is a hashed single-use reset credential.
type RecoveryToken struct {
	TokenHash  []byte
	AccountKey []byte
	CreatedAt  time.Time
	ExpiresAt  time.Time
}

// CreateRecoveryToken inserts a recovery token.
func (s *Store) CreateRecoveryToken(r *RecoveryToken) error {
	_, err := s.db.Exec(`INSERT INTO recovery_tokens(token_hash,account_key,created_at,expires_at) VALUES(?,?,?,?)`,
		r.TokenHash, r.AccountKey, s.now(), r.ExpiresAt.UnixMilli())
	if err != nil {
		return fmt.Errorf("store: create recovery token: %w", err)
	}
	return nil
}

// GetRecoveryToken loads a live recovery token.
func (s *Store) GetRecoveryToken(tokenHash []byte) (*RecoveryToken, error) {
	var r RecoveryToken
	var created, exp int64
	var consumed int64
	err := s.db.QueryRow(`SELECT token_hash,account_key,created_at,expires_at,consumed_at FROM recovery_tokens WHERE token_hash=?`, tokenHash).
		Scan(&r.TokenHash, &r.AccountKey, &created, &exp, &consumed)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: get recovery token: %w", err)
	}
	r.CreatedAt = time.UnixMilli(created)
	r.ExpiresAt = time.UnixMilli(exp)
	if consumed != 0 || r.ExpiresAt.Before(s.Now()) {
		return nil, ErrNotFound
	}
	return &r, nil
}

// ConsumeRecoveryToken atomically consumes a token. Recovery redemption uses
// this so that two concurrent clicks can never both succeed.
func (s *Store) ConsumeRecoveryToken(tokenHash []byte) error {
	res, err := s.db.Exec(`UPDATE recovery_tokens SET consumed_at=? WHERE token_hash=? AND consumed_at=0 AND expires_at>?`,
		s.now(), tokenHash, s.now())
	if err != nil {
		return fmt.Errorf("store: consume recovery token: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// TrustedDevice records a device that has recently authenticated for an
// account. It is the anti-lockout priority lane: a request carrying a live
// trusted-device cookie is not subject to the per-account guess budget.
type TrustedDevice struct {
	AccountKey []byte
	DeviceHash []byte
	ExpiresAt  time.Time
}

// PutTrustedDevice upserts a trusted device.
func (s *Store) PutTrustedDevice(d *TrustedDevice) error {
	_, err := s.db.Exec(`INSERT INTO trusted_devices(device_hash,account_key,created_at,expires_at) VALUES(?,?,?,?)
		ON CONFLICT(device_hash) DO UPDATE SET account_key=excluded.account_key, expires_at=excluded.expires_at`,
		d.DeviceHash, d.AccountKey, s.now(), d.ExpiresAt.UnixMilli())
	if err != nil {
		return fmt.Errorf("store: put trusted device: %w", err)
	}
	return nil
}

// GetTrustedDevice checks a device for an account.
func (s *Store) GetTrustedDevice(accountKey, deviceHash []byte) (bool, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM trusted_devices WHERE account_key=? AND device_hash=? AND expires_at>?`,
		accountKey, deviceHash, s.now()).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("store: get trusted device: %w", err)
	}
	return n > 0, nil
}

// DeleteAccountTrustedDevices removes all trusted devices for an account,
// used on password change/reset so an old device cannot keep bypassing the
// guess budget.
func (s *Store) DeleteAccountTrustedDevices(accountKey []byte) error {
	_, err := s.db.Exec(`DELETE FROM trusted_devices WHERE account_key=?`, accountKey)
	return err
}

// Audit is one chained audit-log entry.
type Audit struct {
	Seq     int64
	At      time.Time
	Event   string
	Detail  []byte
	PrevMAC []byte
	MAC     []byte
}

// LastAudit returns the newest audit entry, or ErrNotFound.
func (s *Store) LastAudit() (*Audit, error) {
	var a Audit
	var at int64
	err := s.db.QueryRow(`SELECT seq,at,event,detail,prev_mac,mac FROM audit_log ORDER BY seq DESC LIMIT 1`).
		Scan(&a.Seq, &at, &a.Event, &a.Detail, &a.PrevMAC, &a.MAC)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: last audit: %w", err)
	}
	a.At = time.UnixMilli(at)
	return &a, nil
}

// AppendAudit adds an entry. The caller supplies the link MACs.
func (s *Store) AppendAudit(event string, detail, prevMAC, mac []byte, at time.Time) error {
	_, err := s.db.Exec(`INSERT INTO audit_log(at,event,detail,prev_mac,mac) VALUES(?,?,?,?,?)`,
		at.UnixMilli(), event, detail, prevMAC, mac)
	if err != nil {
		return fmt.Errorf("store: append audit: %w", err)
	}
	return nil
}

// PurgeExpired removes expired one-shot rows. It is safe to run concurrently
// with live traffic: every consumer re-checks expiry inside its transaction.
func (s *Store) PurgeExpired(now time.Time) (int64, error) {
	var total int64
	for _, q := range []string{
		`DELETE FROM ceremonies WHERE expires_at<?`,
		`DELETE FROM login_states WHERE expires_at<?`,
		`DELETE FROM sessions WHERE expires_at<?`,
		`DELETE FROM recovery_tokens WHERE expires_at<?`,
		`DELETE FROM trusted_devices WHERE expires_at<?`,
	} {
		res, err := s.db.Exec(q, now.UnixMilli())
		if err != nil {
			return total, fmt.Errorf("store: purge expired: %w", err)
		}
		n, _ := res.RowsAffected()
		total += n
	}
	return total, nil
}
