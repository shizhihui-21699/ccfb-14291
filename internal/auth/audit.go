package auth

import (
	"encoding/json"
	"fmt"

	"opaqueauth/internal/secure"
)

// audit appends a tamper-evident log entry. The chain is HMAC-keyed by a KMS
// subkey and links each entry to the previous one, so deleting or editing an
// entry is detectable by VerifyAuditChain. Account keys appear only as
// peppered base64 (they are already opaque).
func (s *Service) audit(event string, accountKey []byte) {
	detail, _ := json.Marshal(map[string]string{"account": secure.B64(accountKey)})
	var prevMAC []byte
	if prev, err := s.store.LastAudit(); err == nil {
		prevMAC = prev.MAC
	}
	mac := secure.HMAC(s.keys.Audit,
		[]byte("audit/v1\x00"), prevMAC, []byte(event), detail,
	)
	_ = s.store.AppendAudit(event, detail, prevMAC, mac, s.now())
}

// VerifyAuditChain checks the audit log's hash chain and every MAC.
func (s *Service) VerifyAuditChain() error {
	rows, err := s.store.DB().Query(`SELECT seq,event,detail,prev_mac,mac FROM audit_log ORDER BY seq`)
	if err != nil {
		return err
	}
	defer rows.Close()
	var prevMAC []byte
	for rows.Next() {
		var seq int64
		var event string
		var detail, pm, mac []byte
		if err := rows.Scan(&seq, &event, &detail, &pm, &mac); err != nil {
			return err
		}
		if !secure.Equal(pm, prevMAC) {
			return fmt.Errorf("audit: chain break at seq %d", seq)
		}
		want := secure.HMAC(s.keys.Audit, []byte("audit/v1\x00"), prevMAC, []byte(event), detail)
		if !secure.Equal(want, mac) {
			return fmt.Errorf("audit: bad MAC at seq %d", seq)
		}
		prevMAC = mac
	}
	return rows.Err()
}
