# opaqueauth — OPAQUE password authentication for an existing user base

A Go implementation of a login system in which **the server never learns the
password**, a stolen database **cannot be attacked offline**, and several
million existing bcrypt users **migrate transparently on their next login**.

The protocol is [OPAQUE](https://www.rfc-editor.org/rfc/rfc9807.html)
(RFC 9807), an augmented PAKE. The reasoning for choosing it over a stronger
password hash or SRP is in [`docs/DESIGN.md`](docs/DESIGN.md).

```
go test ./...        # unit, integration, and attack-simulation tests
```

## What problem this solves

A salted hash in a stolen database is an offline oracle: every guess can be
checked locally. In the prior incident that meant a batch crack. OPAQUE removes
the oracle from the server's stored data, *provided the OPRF key is not in the
database*. This project takes that condition seriously:

- the OPRF seed and AKE key live in a KMS/HSM, not the database, and the
  service refuses to start without them;
- transitional bcrypt digests are sealed under a KMS key as they are imported;
- account identifiers are peppered so a dump cannot even enumerate users;
- a write-capable attacker cannot forge a credential (KMS-keyed record MAC).

With a dump but no KMS key, the attacker must guess **online, per account**,
against a rate limiter that the legitimate user cannot be locked out of.

## Layout

| Path | Role |
|---|---|
| `internal/auth` | registration, login, migration, change, recovery, sessions; the security invariants live here |
| `internal/suite` | pinned OPAQUE ciphersuite, KSF profile, server identity |
| `internal/store` | SQLite persistence; nothing stored is offline-checkable |
| `internal/kms` | long-lived secret provider (file/HSM stand-in) |
| `internal/keyring` | versioned AEAD keys + rotation for sealed values |
| `internal/ratelimit` | lockout-resistant token buckets |
| `internal/pow` | stateless proof-of-work (anti-lockout escape hatch) |
| `internal/legacy` | byte-compatible bcrypt with a raw salt (for migration) |
| `internal/legacyimport` | dump parser/importer |
| `internal/api`, `client` | HTTP API and reference client |
| `cmd/authd`, `cmd/authctl` | server binary; provisioning/import/ops CLI |
| `docs/` | design rationale and threat model |

## Running it

```sh
# 1. Provision keys. Keep this file out of database backups; ideally put it in
#    a KMS/HSM. The service will not start without it.
go run ./cmd/authctl keygen -out keys.json

# 2. Import the legacy password dump ("identifier:bcrypt-hash" per line).
go run ./cmd/authctl import-legacy -db auth.db -keys keys.json -in old-dump.txt

# 3. Run the service (TLS required; -dev-http only for local work).
go run ./cmd/authd -addr :8443 -db auth.db -keys keys.json \
  -tls-cert cert.pem -tls-key key.pem

# 4. Watch the migration.
go run ./cmd/authctl status -db auth.db -keys keys.json
```

The API is documented in `internal/wire`. The client flow is
`client.Client`: `Register`, `Login` (transparently migrates), `ChangePassword`,
`Logout`.

## How migration avoids sending the password

Naive migration sends the password once more so the server can register it —
which defeats the purpose and cannot be done for a breach-hardened system.
Here, on a legacy user's next login:

1. the client sends KE1 *and* a `RegistrationRequest` for the same password;
2. the server replies with a decoy OPAQUE record plus the legacy salt, cost,
   and a random challenge (identical shape for every account);
3. the OPAQUE half cannot verify against the decoy, so the client computes
   `bcrypt(password, salt, cost)` **locally** and returns
   `HMAC(challenge, digest)`;
4. the server compares that against the same HMAC computed from its own
   KMS-sealed digest, then installs the new credential and deletes the legacy
   row in one transaction.

Neither the password nor the verifier ever crosses the network. The old
database never had to be re-hashed, and there is no forced reset.

## The tests that matter

Run with `go test ./internal/auth/ -v`. The attack simulation is
`internal/auth/leak_test.go`:

- `TestDumpOfflineOPAQUEAttackFails` — the attacker builds a server from the
  dump and a dictionary; envelope recovery always fails.
- `TestDumpOfflineLegacyAttackFails` — the transitional verifier is ciphertext,
  not a digest.
- `TestContrastSaltedHashIsOfflineCrackable` — the control: the *old* scheme is
  cracked from the same dictionary, so the negative results mean something.
- `TestDumpHasNoPlaintextIdentifiers`, `TestDumpCannotForgeCredential`.

Lockout resistance is `internal/auth/lockout_test.go`; migration correctness is
`TestLegacyMigration` and `TestLegacyKeyRotationDoesNotOrphanUsers`;
bcrypt compatibility is `internal/legacy/bcrypt_test.go`.

## Limitations, stated up front

- Single-server OPAQUE: a dump **plus the KMS key** is offline-crackable, as in
  any single-server aPAKE. Threshold OPRF is the documented upgrade path.
- A compromised running server can observe OPRF evaluations; OPAQUE protects
  stolen data, not a malicious server.
- Registration reveals whether a name is taken; mitigated with invites and
  rate limiting, not eliminated.
- SQLite is used for a self-contained, auditable implementation; the storage
  interface is narrow so a production database can replace it.

Full discussion in [`docs/DESIGN.md`](docs/DESIGN.md) and
[`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md).
