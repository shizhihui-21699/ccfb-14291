# Design and protocol rationale

This document explains what the system is, why each protocol choice was made,
and where the security argument is strongest and weakest. It is written to be
reviewed by a security engineer who has the code open beside it.

## 1. The requirement, restated precisely

The prior incident was a database breach in which salted password hashes were
recovered offline. The goal is a login design in which:

1. the server never receives, derives, or stores the plaintext password;
2. a database breach does not give an attacker a batch offline oracle — every
   guess must be made online, against a rate limiter, per account;
3. millions of existing users migrate without a forced reset and without the
   password ever being sent to the server;
4. password change and recovery are re-designed for the new model;
5. online guessing is bounded without giving anyone a lockout weapon;
6. login does not become noticeably slower;
7. the protocol is a public standard, with the reason stated.

## 2. Protocol choice: OPAQUE (RFC 9807)

### 2.1 Why not a better password hash

A salted hash (bcrypt, scrypt, Argon2id) is a *verifier*. Whoever holds the
stored value can test a guess against it locally. Argon2id raises the cost per
guess but does not change the shape of the attack: it is still an offline batch
attack, and it is exactly what happened to us. `TestContrastSaltedHashIsOfflineCrackable`
demonstrates the old scheme falling to a four-guess dictionary in milliseconds.

### 2.2 Why not SRP (RFC 2945)

SRP is an augmented PAKE and a genuine improvement over a verifier in the
*active* attacker model, but it stores `v = g^x` where `x` is derived from the
password. That value *is* a verifier: anyone who steals it can test guesses
locally by recomputing `g^x` for each candidate. SRP therefore fails
requirement 2 as stated. It is a historical standard and should not be chosen
for this threat model.

### 2.3 Why OPAQUE, and what it buys

OPAQUE is an aPAKE standardised in RFC 9807 (July 2025). Its registration
produces a server-side *credential file* containing a client public key, a
masking key, and an envelope. The envelope's authentication tag is a MAC over
material derived from `randomized_password`, which is derived from the output of
an oblivious PRF evaluated under a **server-held OPRF key**. The security
statement in RFC 9807 §10.11 is explicit:

> In OPAQUE, the OPRF key acts as the secret salt value that ensures the
> infeasibility of precomputation attacks. […] if the server does not sample
> the PRF seed with sufficiently high entropy, or if it is not kept hidden
> from an adversary, then any derivatives from the client's password may also
> be susceptible to an offline dictionary attack.

So the guarantee is conditional on the OPRF key being out of the dump. This
system makes that condition true by construction (see §4).

Because OPAQUE is a PAKE, it also gives mutual authentication and a shared
session key, so the login exchange doubles as key agreement; the session token
is issued only after the client's KE3 verifies.

Instantiation: Ristretto255 + SHA-512 for both OPRF and 3DH AKE, matching the
RFC's reference pairing and RFC 9497's `ristretto255-SHA512` OPRF suite.
Ristretto255 removes the cofactor and non-canonical-encoding pitfalls of raw
Curve25519 and has no invalid-curve ambiguity like NIST P-256.

### 2.4 What OPAQUE deliberately does *not* hide

- The **identifier** is visible to the server and, without TLS, on the wire.
  Hence HTTPS with TLS 1.3 is mandatory and the service refuses to start
  without it (unless explicitly in development mode).
- The **existence** of an account is visible to the registration endpoint and
  can be inferred at login if the implementation is careless. Our login path is
  shaped so that unknown, disabled, and not-yet-migrated accounts produce the
  same response (see §6).

## 3. Where the keys live, and why that is the crux

The OPAQUE guarantee reduces to: *the attacker must not get the OPRF key.* The
same is true of the transitional bcrypt digests — a raw digest in the dump is
offline-crackable, so it is sealed under a KMS key too.

Therefore:

- The **OPRF seed and AKE private key** are held in a `kms.Provider`
  (`internal/kms`). The production interface is meant to be backed by an
  HSM/cloud KMS so the bytes are never on the database host. The provided
  `FileProvider` reads a mode-0600 file provisioned out of band; the key file
  must never be included in a database backup. The service refuses to start
  without it. `TestDumpOfflineOPAQUEAttackFails` builds the attacker's
  fabricated server from the dump alone and shows envelope recovery always
  fails.
- The **app root** likewise lives in the KMS; every application subkey
  (account-index pepper, record MAC, session-token HMAC, legacy-digest key,
  PoW key, audit chain) is HKDF-derived from it with a distinct label, so
  leaking one yields nothing about another.

The KMS-resident record MAC also closes a *write* attack: an attacker who can
write to the database cannot swap in a credential of their choosing, because
the MAC covers account key, suite, profile, salt, public key, masking key, and
envelope (`TestDumpCannotForgeCredential`).

### 3.1 Key rotation

Because the guarantee depends on a KMS key, rotating that key must not orphan
users. Transitional values are wrapped in a **versioned keyring**
(`internal/keyring`): the key version is prefixed to the ciphertext and bound
into the AEAD associated data, old versions stay readable during the rollover
window, and `authctl rewrap-legacy` re-encrypts the legacy table under the new
version before the old key is retired. An OPAQUE credential itself needs no
rewrap: it is bound to the *OPRF seed*, so rotating the app root is transparent,
and rotating the OPRF seed requires re-registration (documented as a distinct,
heavier operation).

## 4. Threat model by attacker capability

| Attacker has | Can they test a password guess offline? | Why |
|---|---|---|
| Full DB dump, no KMS | No | OPRF key absent; legacy digests sealed under KMS key; indexes peppered |
| DB dump + KMS key | Yes, for that user | Inherent to any single-server aPAKE (RFC 9807 §10.11); mitigate with threshold OPRF |
| DB write, no KMS | No new login as victim | Record MAC is KMS-keyed; tampering is detected and treated as unknown account |
| Network (passive), no TLS | Learns identifiers, not passwords or verifiers | OPAQUE messages are public; TLS protects the identifier |
| Network (active), online | Bounded by rate limiter | Online guessing is the residual, intended attack surface |

The residual "DB dump + KMS key" row is the honest limit of a single-server
PAKE. Threshold OPRF (multiple parties each holding a share of the OPRF key)
is the standard answer and is an additive change to `kms.Provider` and the OPRF
evaluation call; it is called out in `docs/THREAT-MODEL.md`.

## 5. Migration

There are two populations: already-migrated (OPAQUE) and not-yet-migrated
(bcrypt). The migration has to happen *during login*, because there is no
other moment at which the password is present on the client.

### 5.1 Import

`internal/legacyimport` reads a dump of `(identifier, bcrypt hash)`. It keeps
the public salt and cost, and seals the 23-byte digest under the KMS legacy
key. After import, even an un-migrated user's verifier is not directly usable
from a dump. Re-import is idempotent and, under the same transaction, deletes
any stale legacy row for an account that already has a credential
(`TestImportDoesNotResurrectMigrated`).

### 5.2 Transparent upgrade on login, with no verifier on the wire

The naive migration ("send the password once to the server so it can compute
the OPRF") violates requirement 1 and requirement 3. Instead:

1. The client always sends, alongside KE1, a `RegistrationRequest` for the
   *same* password. This is harmless for an already-migrated account.
2. The server always returns the migration material, real or decoy: legacy
   salt, cost, and a random challenge. Presence and length are identical for
   every account, so the response does not reveal who is un-migrated.
3. If the account is OPAQUE, KE3 verifies and login completes normally.
4. If the account is legacy, the server sent a *decoy* OPAQUE record, so KE3
   cannot verify. The client then:
   - computes `raw = bcrypt(password, salt, cost)` **locally**;
   - sends `proof = HMAC-SHA256(challenge, raw)`, plus the RegistrationRecord
     for its new OPAQUE credential.
   The server recomputes the same HMAC from the digest in its own row (released
   only after unsealing under the KMS key) and compares. Neither the password
   nor the verifier crosses the wire; the challenge makes the proof
   non-replayable.
5. On success, `InstallCredential` replaces the credential **and** deletes the
   legacy row in one transaction, so there is never a state with both live.

This is why `internal/legacy` re-implements bcrypt byte-for-byte from a raw
salt: the client must produce exactly the digest the old server stored, but
must not be handed the digest. `TestBCryptRawMatchesXCrypto` pins the
compatibility against `golang.org/x/crypto/bcrypt` across salts, costs, and
lengths including the 72-byte boundary.

**Cut-over.** When the legacy table count reaches zero, drop it. Until then it
is the only offline-checkable artifact and it is sealed; monitoring its
shrinkage is the migration dashboard (`authctl status`).

## 6. Enumeration

RFC 9807 §10.9 requires decoy responses so that unknown users are
indistinguishable from known ones. Implemented as:

- Unknown, disabled, and un-migrated accounts all get a decoy record from
  `Configuration.GetFakeRecord`, producing a KE2 of identical length;
- the migration material is always present, with decoy salt/cost/challenge;
- login failures all return HTTP 401 with the same body; rate limiting returns
  the same shape for every identifier;
- recovery always returns `{"ok":true}` whether or not the account exists;
- the account index is peppered, so the dump itself does not enumerate the user
  table or join against other breaches.

Registration is necessarily an existence oracle (a taken name must be
refused); we mitigate with invitation (`-require-invite`) and rate limiting
rather than by lying, which would create duplicate accounts.

## 7. Rate limiting and the no-lockout property

`internal/ratelimit` is four token buckets:

- **per (account, source)**: 5 burst, 0.2/s — a human mistyping on their own
  device;
- **per source**: 20 burst, 2/s — the credential-stuffing bound;
- **per account, failures only**: 20 burst, 1/60 s — what an attacker must
  exhaust to guess online, charged *only on a real failed verification*;
- **global**: 2000/s — a safety valve.

Why this cannot be used to lock a victim out:

1. There is **no lock state**. After the account budget is spent, untrusted
   requests get a 429 with a challenge; the account row stays `active`.
2. A **live trusted-device token** skips the account bucket entirely. The token
   was issued at the victim's own last successful login, so the normal user is
   unaffected by an attacker's flood (`TestVictimOnTrustedDeviceNotLockedOut`).
3. A **solved proof-of-work** also skips the account bucket. It is stateless
   and self-verifying, so an attacker cannot pre-spend or poison it; the
   attacker pays the same CPU for its own attempts
   (`TestProofOfWorkUnlocksAfterFlood`).
4. The **per-source** bucket still applies to proof-of-work, because it is the
   anti-stuffing bound and must not be purchasable with CPU
   (`TestProofDoesNotBuyUnlimitedGuesses`).
5. Success **clears** the account failure budget, so a user who mistyped is not
   penalised afterwards (`TestSuccessClearsFailureBudget`).

The worst case for a victim on a brand-new device during a flood is: solve a
sub-second PoW, possibly wait out the 2/s source refill. Never "account
disabled".

Numbers: 20 initial + 1/60 s is ~1,440 guesses/day for a sustained attacker
against one account, and any real user login zeroes the counter. See
`docs/THREAT-MODEL.md` for the arithmetic.

## 8. Password change and recovery

- **Change** requires a session authenticated within 15 minutes, then runs a
  *registration* ceremony for the new password (the server can compute the
  OPRF response because the OPRF key is per-credential-identifier, which is
  stable). On completion every other session and all trusted devices are
  revoked in the same transaction (`TestPasswordChangeRotatesCredential`).
  Because it is a fresh OPAQUE registration, the old password is not needed to
  derive anything new — but the UI still asks for it, and `ChangePassword`
  proves it with a normal login first.
- **Recovery** is out of band: the user proves control of the address on file,
  receives a single-use token (stored only as an HMAC), and redeems it to run a
  *registration* for a new password — no old credential is needed. All sessions
  and devices are revoked. The token is consumed atomically and only after the
  new credential is installed, so a dropped ceremony does not burn the link
  (`TestRecoveryFlow`). The contact address is itself sealed under the keyring.

## 9. Performance

The server's per-login work is two group operations and symmetric crypto;
`TestLoginLatencyBudget` measures end-to-end login at ~29 ms with the
production Argon2id profile (t=3, 64 MiB) on the development machine. The
client's Argon2id (RFC 9106's SECOND RECOMMENDED option) dominates and is the
same order as the bcrypt it replaces.

Round trips, stated precisely: a naive "POST the password" login is one round
trip; OPAQUE login is two (`/login/start` returns KE2, `/login/finish` returns
the session), the minimum for an aPAKE with explicit client authentication.
So it adds one round trip, not zero. What costs nothing extra is **migration**:
the client's replacement `RegistrationRequest` is sent with KE1 and the
migration proof with KE3, so an un-migrated user upgrades within the same two
round trips as a normal login.

The KSF is deliberately not the FIRST RECOMMENDED 2 GiB option: the
database-only threat model does not depend on it (the OPRF key is out of the
database), and 2 GiB per login is unacceptable on phones. It becomes the
relevant layer only if the OPRF key also leaks.

## 10. Known limitations, stated plainly

- **Single-server OPRF.** "DB dump + KMS key" is offline-crackable, as in any
  single-server aPAKE. Threshold OPRF is the mitigation and is an additive
  change.
- **Compromised server process.** A fully compromised *running* server sees
  decrypted OPRF evaluations and could log them; OPAQUE does not defend
  against a malicious server, only against a stolen database. The
  no-logging rule and separate KMS are the mitigations.
- **KSF is unverifiable server-side.** A malicious client can claim a cheap
  profile; the server pins the advertised profile ID but cannot prove the
  stretch ran (RFC 9807 §10.8). This only affects that client's own offline
  resistance.
- **Registration enumeration** is inherent; mitigated, not eliminated.
- **Timing.** The failure paths are shaped to be equal, but the project does
  not claim constant-time across all network conditions; the OPAQUE group
  operations dominate and are constant-time in the library.
- **SQLite** is used for a self-contained, testable implementation. The
  storage interface is narrow (`internal/store`); a production deployment
  swaps the driver, not the logic.
