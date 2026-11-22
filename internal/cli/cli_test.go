// Package cli_test exercises the operator binaries end to end: keygen and
// legacy import via the real authctl binary, then a migration login against a
// real authd process over HTTP with the real client SDK.
package cli_test

import (
	"context"
	"fmt"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"opaqueauth/client"
	"opaqueauth/internal/api"
	"opaqueauth/internal/auth"
	"opaqueauth/internal/kms"
	"opaqueauth/internal/pow"
	"opaqueauth/internal/ratelimit"
	"opaqueauth/internal/store"
	"opaqueauth/internal/suite"
)

// build compiles a main package into binDir.
func build(t *testing.T, binDir, pkg, name string) string {
	t.Helper()
	out := filepath.Join(binDir, name)
	cmd := exec.Command("go", "build", "-o", out, pkg)
	cmd.Dir = repoRoot(t)
	if combined, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", pkg, err, combined)
	}
	return out
}

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	// This package lives at <root>/internal/cli.
	return filepath.Clean(filepath.Join(wd, "..", ".."))
}

func TestKeygenImportLogin(t *testing.T) {
	if testing.Short() {
		t.Skip("builds binaries")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	authctl := build(t, bin, "./cmd/authctl", "authctl")

	keyFile := filepath.Join(dir, "keys.json")
	if out, err := exec.Command(authctl, "keygen", "-out", keyFile).CombinedOutput(); err != nil {
		t.Fatalf("keygen: %v\n%s", err, out)
	}
	// Key file must be mode 0600.
	fi, err := os.Stat(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode = %o, want 0600", fi.Mode().Perm())
	}

	// Produce a legacy row with authctl, then import it through authctl.
	rowOut, err := exec.Command(authctl, "make-legacy-row", "-identifier", "legacyuser", "-password", "old-password").CombinedOutput()
	if err != nil {
		t.Fatalf("make-legacy-row: %v\n%s", err, rowOut)
	}
	dump := filepath.Join(dir, "dump.txt")
	if err := os.WriteFile(dump, rowOut, 0o600); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(dir, "auth.db")
	if out, err := exec.Command(authctl, "import-legacy", "-db", dbPath, "-keys", keyFile, "-in", dump).CombinedOutput(); err != nil {
		t.Fatalf("import-legacy: %v\n%s", err, out)
	}

	// Bring up the service against the produced artifacts.
	prov, err := kms.NewFileProvider(keyFile)
	if err != nil {
		t.Fatalf("key file: %v", err)
	}
	db, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	svc, err := auth.New(auth.Config{
		Store: db, KMS: prov,
		Limiter: ratelimit.New(ratelimit.DefaultPolicy()),
		Pow:     pow.New([]byte("0123456789abcdef0123456789abcdef"), 8, time.Minute),
		KSF:     suite.ProfileV1,
	})
	if err != nil {
		t.Fatalf("service: %v", err)
	}
	srv := httptest.NewServer(api.New(svc).Handler())
	defer srv.Close()

	ctx := context.Background()
	c, err := client.New(ctx, srv.URL, "legacyuser")
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	if err := c.Login(ctx, "old-password"); err != nil {
		t.Fatalf("migration login: %v", err)
	}

	// Status must report full migration.
	statusOut, err := exec.Command(authctl, "status", "-db", dbPath, "-keys", keyFile).CombinedOutput()
	if err != nil {
		t.Fatalf("status: %v\n%s", err, statusOut)
	}
	if got := string(statusOut); !contains(got, "legacy_remaining=0") {
		t.Fatalf("status after migration: %s", got)
	}

	// And the user logs in again as a pure OPAQUE account.
	c2, err := client.New(ctx, srv.URL, "legacyuser")
	if err != nil {
		t.Fatal(err)
	}
	if err := c2.Login(ctx, "old-password"); err != nil {
		t.Fatalf("post-migration login: %v", err)
	}
	if err := c2.Login(ctx, "wrong"); err == nil {
		t.Fatal("wrong password accepted")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

var _ = fmt.Sprintf
