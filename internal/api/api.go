// Package api exposes the authentication service over HTTP.
//
// Transport: HTTP/1.1 and HTTP/2 over TLS 1.3 (RFC 8446) is required in
// production. TLS is not merely a confidentiality wrapper here: it protects the
// identifiers, which OPAQUE deliberately does not hide on the wire, from
// passive observers, and it binds the client's view of the server identity.
// The handlers never log request bodies.
//
// Error policy: every authentication failure returns the same status and body
// so that status codes cannot be used for account enumeration. Rate limiting
// also returns a shape of response that does not depend on account existence.
package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/bytemare/opaque/message"

	"opaqueauth/internal/auth"
	"opaqueauth/internal/secure"
	"opaqueauth/internal/wire"
)

// maxBody bounds request bodies. OPAQUE messages are a few hundred bytes; a
// megabyte allows padded transports without permitting memory abuse.
const maxBody = 1 << 20

// Server is the HTTP API.
type Server struct {
	svc *auth.Service
	mux *http.ServeMux
	// Mailer is called for recovery messages. It must not block the request
	// path; the default implementation drops messages.
	Mailer Mailer
	// LoginRatePerSource limits login/start calls per source before any
	// cryptography runs. Enforced by the service's Limiter as well; this is an
	// outer guard against body-parsing abuse.
}

// Mailer sends recovery mail. The service calls it only after it has issued a
// token, and only with the decrypted address on file; implementations must be
// asynchronous and must not log the token or the address.
type Mailer interface {
	SendRecovery(to, token string) error
}

// dropMailer discards mail, for tests and single-node demos.
type dropMailer struct{}

func (dropMailer) SendRecovery(string, string) error { return nil }

// New builds a Server.
func New(svc *auth.Service) *Server {
	s := &Server{svc: svc, mux: http.NewServeMux(), Mailer: dropMailer{}}
	s.mux.HandleFunc("GET /v1/config", s.handleConfig)
	s.mux.HandleFunc("POST /v1/register/start", s.handleRegisterStart)
	s.mux.HandleFunc("POST /v1/register/finish", s.handleRegisterFinish)
	s.mux.HandleFunc("POST /v1/login/start", s.handleLoginStart)
	s.mux.HandleFunc("POST /v1/login/finish", s.handleLoginFinish)
	s.mux.HandleFunc("POST /v1/change/start", s.handleChangeStart)
	s.mux.HandleFunc("POST /v1/change/finish", s.handleChangeFinish)
	s.mux.HandleFunc("POST /v1/recover/start", s.handleRecoverStart)
	s.mux.HandleFunc("POST /v1/recover/redeem/start", s.handleRecoverRedeemStart)
	s.mux.HandleFunc("POST /v1/recover/redeem/finish", s.handleRecoverRedeemFinish)
	s.mux.HandleFunc("POST /v1/logout", s.handleLogout)
	s.mux.HandleFunc("GET /v1/session", s.handleSession)
	s.mux.HandleFunc("GET /v1/challenge", s.handleChallenge)
	return s
}

// Handler returns the root HTTP handler.
func (s *Server) Handler() http.Handler { return s.mux }

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.mux.ServeHTTP(w, r) }

// source identifies the requesting origin for rate limiting. In production this
// MUST be the real client IP as seen past a trusted proxy; using a spoofable
// header would let an attacker rotate buckets freely.
func source(r *http.Request) string {
	if v := r.Header.Get("X-Opaque-Source"); v != "" {
		// Set by a trusted edge that overwrites any client-supplied value.
		return v
	}
	host := r.RemoteAddr
	if i := strings.LastIndexByte(host, ':'); i > 0 {
		host = host[:i]
	}
	return host
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	return ""
}

func deviceToken(r *http.Request) string {
	return r.Header.Get("X-Opaque-Device")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	body := http.MaxBytesReader(w, r.Body, maxBody)
	defer body.Close()
	dec := json.NewDecoder(body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil && !errors.Is(err, io.EOF) {
		writeJSON(w, http.StatusBadRequest, wire.ErrorBody{Code: "bad_request"})
		return false
	}
	return true
}

// fail maps an internal error to the single public authentication failure.
// Everything auth-related collapses to 401 with code "auth_failed".
func fail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, auth.ErrRateLimited):
		writeJSON(w, http.StatusTooManyRequests, wire.ErrorBody{Code: "rate_limited"})
	case errors.Is(err, auth.ErrExpired):
		writeJSON(w, http.StatusGone, wire.ErrorBody{Code: "expired"})
	case errors.Is(err, auth.ErrConflict):
		writeJSON(w, http.StatusConflict, wire.ErrorBody{Code: "unavailable"})
	case errors.Is(err, auth.ErrNotAllowed):
		writeJSON(w, http.StatusForbidden, wire.ErrorBody{Code: "not_allowed"})
	case errors.Is(err, auth.ErrBadRequest):
		writeJSON(w, http.StatusBadRequest, wire.ErrorBody{Code: "bad_request"})
	default:
		writeJSON(w, http.StatusUnauthorized, wire.ErrorBody{Code: "auth_failed"})
	}
}

// errAuth is used where a specific internal failure must stay generic.
var errAuth = auth.ErrUnauthenticated

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	cfg := s.svc.ClientConfig()
	writeJSON(w, http.StatusOK, wire.ServerConfigResponse{
		Suite:          cfg.Suite,
		ServerIdentity: cfg.ServerIdentity,
		Context:        cfg.Context,
		KSF:            cfg.KSF.ID,
		KSFTime:        cfg.KSF.Time,
		KSFMemory:      cfg.KSF.Memory,
		KSFThreads:     cfg.KSF.Threads,
		KSFKeyLen:      cfg.KSF.Length,
		ProofBits:      cfg.ProofBits,
	})
}

func (s *Server) handleChallenge(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, wire.Challenge{Token: s.svc.IssueChallenge(), Bits: s.svc.ClientConfig().ProofBits})
}

func (s *Server) handleRegisterStart(w http.ResponseWriter, r *http.Request) {
	var req wire.RegisterStartRequest
	if !readJSON(w, r, &req) {
		return
	}
	regReq, err := s.svc.DeserializeRegistrationRequest(req.RegistrationRequest)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, wire.ErrorBody{Code: "bad_request"})
		return
	}
	cerId, regResp, ksfSalt, err := s.svc.RegisterBegin(req.Identifier, regReq, req.InviteCode, source(r))
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, wire.RegisterStartResponse{
		Ceremony:             secure.B64(cerId),
		RegistrationResponse: regResp.Serialize(),
		KSF:                  s.svc.ClientConfig().KSF.ID,
		KSFSalt:              ksfSalt,
	})
}

func (s *Server) handleRegisterFinish(w http.ResponseWriter, r *http.Request) {
	var req wire.RegisterFinishRequest
	if !readJSON(w, r, &req) {
		return
	}
	cerId, err := secure.UnB64(req.Ceremony)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, wire.ErrorBody{Code: "bad_request"})
		return
	}
	rec, err := s.svc.DeserializeRegistrationRecord(req.RegistrationRecord)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, wire.ErrorBody{Code: "bad_request"})
		return
	}
	sess, err := s.svc.RegisterFinish(cerId, rec, req.KSF, req.Contact, req.DeviceLabel)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, wire.RegisterFinishResponse{
		Token: sess.Token, ExpiresAt: sess.ExpiresAt.Unix(),
	})
}

func (s *Server) handleLoginStart(w http.ResponseWriter, r *http.Request) {
	var req wire.LoginStartRequest
	if !readJSON(w, r, &req) {
		return
	}
	ke1, err := s.svc.DeserializeKE1(req.KE1)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, wire.ErrorBody{Code: "bad_request"})
		return
	}
	// racerRegistrationRequest is always built by the reference client so that
	// migration needs no second lookup. A caller that omits it still logs in;
	// it simply cannot migrate transparently on this attempt.
	regReq, _ := s.svc.DeserializeRegistrationRequest(req.RacerRegistrationRequest)
	res, err := s.svc.LoginBegin(req.Identifier, ke1, regReq, source(r), deviceToken(r), req.Proof)
	if err != nil {
		fail(w, err)
		return
	}
	if res.RateLimited {
		// Include a challenge so the client can prove work and retry. The
		// response is identical for any identifier, so it enumerates nothing.
		writeJSON(w, http.StatusTooManyRequests, wire.LoginStartResponse{
			Error: "rate_limited", RetryAfter: int(res.RetryAfter.Seconds()),
			ProofOfWork: res.Challenge,
		})
		return
	}
	writeJSON(w, http.StatusOK, wire.LoginStartResponse{
		Session:              secure.B64(res.StateID),
		KE2:                  res.KE2.Serialize(),
		KSF:                  res.KSF,
		KSFSalt:              res.KSFSalt,
		LegacySalt:           res.LegacySalt,
		LegacyCost:           res.LegacyCost,
		LegacyChallenge:      res.LegacyChallenge,
		RegistrationResponse: res.RegResponse,
	})
}

func (s *Server) handleLoginFinish(w http.ResponseWriter, r *http.Request) {
	var req wire.LoginFinishRequest
	if !readJSON(w, r, &req) {
		return
	}
	stateId, err := secure.UnB64(req.Session)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, wire.ErrorBody{Code: "bad_request"})
		return
	}
	var ke3 *message.KE3
	if len(req.KE3) > 0 {
		var err error
		ke3, err = s.svc.DeserializeKE3(req.KE3)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, wire.ErrorBody{Code: "bad_request"})
			return
		}
	}
	in := auth.LoginFinishInput{StateID: stateId, KE3: ke3, DeviceLabel: req.DeviceLabel, Source: source(r)}
	if req.Migration != nil {
		rec, err := s.svc.DeserializeRegistrationRecord(req.Migration.Registration)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, wire.ErrorBody{Code: "bad_request"})
			return
		}
		in.Migration = &auth.MigrationProof{Proof: req.Migration.Proof, Registration: rec, KSF: req.Migration.KSF}
	}
	sess, err := s.svc.LoginFinish(in)
	if err != nil {
		fail(w, err)
		return
	}
	w.Header().Set("X-Opaque-Device", sess.DeviceToken)
	writeJSON(w, http.StatusOK, wire.LoginFinishResponse{
		Token: sess.Token, ExpiresAt: sess.ExpiresAt.Unix(),
	})
}

func (s *Server) handleChangeStart(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.authSession(w, r, 15*time.Minute)
	if !ok {
		return
	}
	var req wire.ChangeStartRequest
	if !readJSON(w, r, &req) {
		return
	}
	regReq, err := s.svc.DeserializeRegistrationRequest(req.RegistrationRequest)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, wire.ErrorBody{Code: "bad_request"})
		return
	}
	cerId, regResp, ksfSalt, err := s.svc.ChangeBegin(sess.AccountKey, regReq)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, wire.ChangeStartResponse{
		Ceremony: secure.B64(cerId), RegistrationResponse: regResp.Serialize(),
		KSF: s.svc.ClientConfig().KSF.ID, KSFSalt: ksfSalt,
	})
}

func (s *Server) handleChangeFinish(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.authSession(w, r, 15*time.Minute)
	if !ok {
		return
	}
	var req wire.ChangeFinishRequest
	if !readJSON(w, r, &req) {
		return
	}
	cerId, err := secure.UnB64(req.Ceremony)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, wire.ErrorBody{Code: "bad_request"})
		return
	}
	rec, err := s.svc.DeserializeRegistrationRecord(req.RegistrationRecord)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, wire.ErrorBody{Code: "bad_request"})
		return
	}
	if err := s.svc.ChangeFinish(sess.AccountKey, cerId, rec, req.KSF); err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, wire.ChangeFinishResponse{OK: true})
}

func (s *Server) handleRecoverStart(w http.ResponseWriter, r *http.Request) {
	var req wire.RecoverStartRequest
	if !readJSON(w, r, &req) {
		return
	}
	acct, token, send := s.svc.RecoverBegin(req.Identifier, source(r))
	if send {
		if to, ok := s.svc.RecoveryContact(acct); ok {
			_ = s.Mailer.SendRecovery(to, token)
		}
	}
	// Identical response in every case.
	writeJSON(w, http.StatusOK, wire.RecoverStartResponse{OK: true})
}

func (s *Server) handleRecoverRedeemStart(w http.ResponseWriter, r *http.Request) {
	var req wire.RecoverRedeemStartRequest
	if !readJSON(w, r, &req) {
		return
	}
	regReq, err := s.svc.DeserializeRegistrationRequest(req.RegistrationRequest)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, wire.ErrorBody{Code: "bad_request"})
		return
	}
	cerId, regResp, ksfSalt, err := s.svc.RecoverRedeemBegin(req.Token, regReq)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, wire.RecoverRedeemStartResponse{
		Ceremony: secure.B64(cerId), RegistrationResponse: regResp.Serialize(),
		KSF: s.svc.ClientConfig().KSF.ID, KSFSalt: ksfSalt,
	})
}

func (s *Server) handleRecoverRedeemFinish(w http.ResponseWriter, r *http.Request) {
	var req wire.RecoverRedeemFinishRequest
	if !readJSON(w, r, &req) {
		return
	}
	cerId, err := secure.UnB64(req.Ceremony)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, wire.ErrorBody{Code: "bad_request"})
		return
	}
	rec, err := s.svc.DeserializeRegistrationRecord(req.RegistrationRecord)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, wire.ErrorBody{Code: "bad_request"})
		return
	}
	sess, err := s.svc.RecoverRedeemFinish(req.Token, cerId, rec, req.KSF)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, wire.RecoverRedeemFinishResponse{
		Token: sess.Token, ExpiresAt: sess.ExpiresAt.Unix(),
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	_ = s.svc.Logout(bearer(r))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.authSession(w, r, 0)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"account_id": secure.B64(sess.AccountKey),
		"expires_at": sess.ExpiresAt.Unix(),
	})
}

// authSession extracts and validates a bearer session. If maxAuthAge is
// non-zero it also requires a recent authentication.
func (s *Server) authSession(w http.ResponseWriter, r *http.Request, maxAuthAge time.Duration) (*auth.Session, bool) {
	sess, err := s.svc.Authenticate(bearer(r))
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, wire.ErrorBody{Code: "auth_failed"})
		return nil, false
	}
	if maxAuthAge > 0 && s.svc.RequiresReauth(sess, maxAuthAge) {
		writeJSON(w, http.StatusUnauthorized, wire.ErrorBody{Code: "reauth_required"})
		return nil, false
	}
	return sess, true
}
