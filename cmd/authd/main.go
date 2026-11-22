// Command authd runs the authentication service.
//
// It refuses to start without key material from the KMS, and it refuses to run
// over plaintext HTTP unless explicitly told this is a local development
// instance: OPAQUE hides the password, not the identifier, so the transport
// must be confidential.
package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/bytemare/opaque"

	"opaqueauth/internal/api"
	"opaqueauth/internal/auth"
	"opaqueauth/internal/keyring"
	"opaqueauth/internal/keys"
	"opaqueauth/internal/kms"
	"opaqueauth/internal/pow"
	"opaqueauth/internal/ratelimit"
	"opaqueauth/internal/store"
	"opaqueauth/internal/suite"
)

func main() {
	var (
		addr          = flag.String("addr", "127.0.0.1:8443", "listen address")
		dbPath        = flag.String("db", "auth.db", "SQLite database path")
		keyFile       = flag.String("keys", "", "path to the KMS key file (JSON, mode 0600)")
		certFile      = flag.String("tls-cert", "", "TLS certificate (PEM)")
		keyPEM        = flag.String("tls-key", "", "TLS private key (PEM)")
		devHTTP       = flag.Bool("dev-http", false, "serve plaintext HTTP (development only)")
		powBits       = flag.Int("pow-bits", 18, "proof-of-work difficulty in leading zero bits")
		requireInvite = flag.Bool("require-invite", false, "require an invite code for registration")
		inviteHex     = flag.String("invite-key", "", "hex key for invite-code HMACs (required with -require-invite)")
	)
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.LUTC)
	if *keyFile == "" {
		log.Fatalf("authd: -keys is required; the service will not run with database-only key material")
	}
	if !*devHTTP && (*certFile == "" || *keyPEM == "") {
		log.Fatalf("authd: TLS is required; pass -tls-cert and -tls-key, or -dev-http for a local instance")
	}
	if *requireInvite && *inviteHex == "" {
		log.Fatalf("authd: -require-invite needs -invite-key")
	}

	provider, err := kms.NewFileProvider(*keyFile)
	if err != nil {
		log.Fatalf("authd: %v", err)
	}

	db, err := store.Open(*dbPath)
	if err != nil {
		log.Fatalf("authd: %v", err)
	}
	defer db.Close()

	ring, err := loadLegacyRing(provider)
	if err != nil {
		log.Fatalf("authd: %v", err)
	}

	cfg := auth.Config{
		Store:         db,
		KMS:           provider,
		Limiter:       ratelimit.New(ratelimit.DefaultPolicy()),
		Pow:           pow.New(derivePowKey(provider), *powBits, 10*time.Minute),
		RequireInvite: *requireInvite,
		LegacyRing:    ring,
	}
	if *requireInvite {
		key, err := hex.DecodeString(*inviteHex)
		if err != nil {
			log.Fatalf("authd: -invite-key is not valid hex: %v", err)
		}
		cfg.InviteVerifier = func(code string) bool {
			// Invite codes are accepted if they are a valid HMAC under the
			// operator's key; the issuer generates them with cmd/authctl.
			return len(code) > 0 && verifyInvite(key, code)
		}
	}
	svc, err := auth.New(cfg)
	if err != nil {
		log.Fatalf("authd: %v", err)
	}
	if err := db.SetMeta("suite_id", suite.ID); err != nil {
		log.Fatalf("authd: %v", err)
	}

	// Background purge of expired one-shot rows. Consumers re-check expiry
	// transactionally, so this is housekeeping, not a correctness requirement.
	go func() {
		t := time.NewTicker(10 * time.Minute)
		defer t.Stop()
		for range t.C {
			if n, err := db.PurgeExpired(time.Now()); err == nil && n > 0 {
				log.Printf("authd: purged %d expired rows", n)
			}
		}
	}()

	srv := api.New(svc)
	srv.Mailer = api.NewFileMailer("recovery-mail.log")
	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    32 << 10,
		ErrorLog:          log.Default(),
	}

	errCh := make(chan error, 1)
	go func() {
		if *devHTTP {
			log.Printf("authd: serving plaintext HTTP on %s (development mode)", *addr)
			errCh <- httpSrv.ListenAndServe()
			return
		}
		httpSrv.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS13,
			// OPAQUE is not PKI-free at the transport layer: clients must
			// authenticate the server over TLS as well, so the default
			// certificate verification stays in force.
		}
		log.Printf("authd: serving HTTPS on %s", *addr)
		errCh <- httpSrv.ListenAndServeTLS(*certFile, *keyPEM)
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	select {
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("authd: %v", err)
		}
	case <-sigCh:
		log.Printf("authd: shutting down")
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(ctx)
	}
}

// loadLegacyRing builds the keyring for transitional bcrypt digests. If the
// key file carries a versioned key set it is used; otherwise a version-1 ring
// is derived from the app root, which is the single-key deployment.
func loadLegacyRing(p kms.Provider) (*keyring.Ring, error) {
	verRaw, err := p.Get(kms.Name("legacy.active.version"))
	if err != nil {
		// No explicit version: derive from the app root at version 1.
		k, err := keys.Load(p)
		if err != nil {
			return nil, err
		}
		return keyring.New(1, k.LegacyVerifier, nil)
	}
	keyRaw, err := p.Get(kms.Name("legacy.active.key"))
	if err != nil {
		return nil, fmt.Errorf("authd: legacy.active.version set but legacy.active.key missing")
	}
	key, err := hex.DecodeString(string(keyRaw))
	if err != nil {
		return nil, fmt.Errorf("authd: legacy.active.key is not hex")
	}
	var ver uint32
	if _, err := fmt.Sscanf(string(verRaw), "%d", &ver); err != nil {
		return nil, fmt.Errorf("authd: bad legacy.active.version %q", string(verRaw))
	}
	retained := map[uint32][]byte{}
	for v := uint32(1); v < ver; v++ {
		name := kms.Name(fmt.Sprintf("legacy.v%d", v))
		raw, err := p.Get(name)
		if err != nil {
			continue
		}
		k, err := hex.DecodeString(string(raw))
		if err != nil {
			return nil, fmt.Errorf("authd: %s is not hex", name)
		}
		retained[v] = k
	}
	return keyring.New(ver, key, retained)
}

// derivePowKey derives the PoW challenge key from the app root, so that
// challenges survive a restart and are not tied to a process key. It calls the
// same derivation the auth service uses so the two cannot drift.
func derivePowKey(p kms.Provider) []byte {
	k, err := keys.Load(p)
	if err != nil {
		log.Fatalf("authd: %v", err)
	}
	return k.ProofOfWork
}

// verifyInvite checks an invite code against the operator key. The code format
// is base64url(nonce) + "." + base64url(HMAC(key, nonce)).
func verifyInvite(key []byte, code string) bool {
	noncePart, macPart, ok := strings.Cut(code, ".")
	if !ok {
		return false
	}
	nonce, err := base64.RawURLEncoding.DecodeString(noncePart)
	if err != nil || len(nonce) != 16 {
		return false
	}
	want := hmacBytes(key, nonce)
	got, err := base64.RawURLEncoding.DecodeString(macPart)
	if err != nil {
		return false
	}
	return hmac.Equal(want, got)
}

// newServerKeyMaterial generates OPAQUE server key material for provisioning.
// Exposed through cmd/authctl rather than run automatically.
func newServerKeyMaterial() ([]byte, error) {
	conf := suite.Configuration()
	seed := conf.GenerateOPRFSeed()
	sk, pk := conf.KeyGen()
	if sk == nil || pk == nil {
		return nil, fmt.Errorf("authd: key generation failed")
	}
	skm := &opaque.ServerKeyMaterial{
		PrivateKey: sk, PublicKeyBytes: pk.Encode(),
		OPRFGlobalSeed: seed, Identity: []byte(suite.ServerIdentity),
	}
	enc := skm.Encode()
	// Validate what we are about to provision.
	if _, err := conf.DecodeServerKeyMaterial(enc); err != nil {
		return nil, err
	}
	return enc, nil
}

// hmacBytes keys the invite-code MAC.
func hmacBytes(key, nonce []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte("invite/v1\x00"))
	m.Write(nonce)
	return m.Sum(nil)
}
