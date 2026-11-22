# Threat model and attack-cost arithmetic

This is the quantitative companion to `DESIGN.md`. It states the attacker
capabilities considered, what each can achieve, and the numbers behind the
rate-limit policy.

## 1. Assets

| Asset | Where it lives | Compromise consequence |
|---|---|---|
| Password | client process only | full account takeover |
| OPRF seed | KMS | turns DB dump into offline oracle |
| AKE private key | KMS | server impersonation to clients (with OPRF seed) |
| App root | KMS | all app subkeys (index pepper, MACs, audit) |
| Credential file | database | nothing alone; offline-checkable only with OPRF seed |
| Legacy bcrypt digest | database, AEAD-sealed | offline-checkable only with legacy key |
| Identifier | client + wire (TLS) | enumeration / correlation |
| Session token | client; HMAC only in DB | session hijack if stolen |

## 2. Attacker capabilities and outcomes

### A. Database read-only dump (the prior incident)

- Cannot enumerate users: `accounts.account_key` is
  `SHA-256(label || pepper || canonical_identifier)` and the pepper is in the
  KMS.
- Cannot test a password offline: the OPRF key is in the KMS; the envelope tag
  is a MAC over OPRF-derived material.
- Cannot test un-migrated users offline either: the bcrypt digest is sealed
  under a KMS key, so the row is ciphertext.
- **Cost to attack: one online login round trip per (account, guess)**, bounded
  per §4.

Tested by: `TestDumpHasNoPlaintextIdentifiers`,
`TestDumpOfflineOPAQUEAttackFails`, `TestDumpOfflineLegacyAttackFails`. The
control `TestContrastSaltedHashIsOfflineCrackable` shows the old scheme falling
immediately, so the negative results are not vacuous.

### B. Database write access

- Cannot install a chosen credential: `credentials.record_mac` is keyed by the
  KMS record key. A tampered row is rejected and treated as an unknown account.
- Cannot promote a user or read secrets: no plaintext secret is stored.

Tested by: `TestDumpCannotForgeCredential`.

### C. Database dump + KMS key (full key compromise)

- Can, in principle, evaluate the OPRF for guesses and check envelopes offline
  for every migrated user, and unseal legacy digests for the rest.
- This is the irreducible limit of a single-server aPAKE (RFC 9807 §10.11).
- Mitigation: **threshold OPRF** — split the OPRF key across independent
  parties so no single dump is sufficient. The `kms.Provider` boundary and the
  single `OPRF.Evaluate` call site are where that change lands.

### D. Online attacker

- The only remaining path. Bounded by §4; the migration window is the one
  period with a larger offline surface (legacy digests), and it is sealed and
  shrinking.

### E. Malicious/compromised server process

- Out of scope for OPAQUE: a server that runs the code can observe OPRF
  evaluations. Defences are operational (no request logging, least-privilege
  KMS policy, code integrity), not cryptographic.

## 3. Rate-limit arithmetic

Policy (`internal/ratelimit.DefaultPolicy`), token buckets refilling at the
stated rate:

| Bucket | Burst | Rate | Purpose |
|---|---|---|---|
| per (account, source) | 5 | 0.2/s | human mistyping |
| per source | 20 | 2/s | stuffing bound |
| per account, failures only | 20 | 1/60 s | online guessing bound |
| global | 4000 | 2000/s | DoS valve |

Guess throughput against a single account, sustained:

- Immediate: 20 (account bucket) from up to 4 sources (each source can spend 5
  on that account before its own 20-burst source bucket is the limit;
  in general the source bucket allows 20 across all accounts).
- Sustained: 1 per 60 s = **1,440/day**, and any successful login by the real
  user resets it to zero.
- A password with 40 bits of entropy (~12 random lowercase letters is ~56
  bits; a common user password is often < 30 bits) is far beyond 1,440/day
  when the attacker also has to distribute across sources without tripping the
  per-source bucket.

Compare the old scheme: a stolen bcrypt table is cracked at whatever rate the
attacker's GPUs allow — millions/second for weak passwords — with no per-account
limit at all.

Distributed attacker (many sources), against one account:

- Each source can contribute at most 5 to that account before the source
  bucket closes, and 20 total across accounts.
- The account-failure bucket is global across sources: 20 + 1/60 s. So sourcing
  many IPs does **not** multiply the per-account rate; it only avoids the
  per-(account,source) 5-cap on the first 20.

This asymmetry is deliberate: the per-account budget is the bound that matters
for one victim, so it must be global, not per-source.

## 4. The no-lockout proof sketch

Claim: an attacker who can send arbitrary requests cannot prevent the legitimate
user from authenticating, except by consuming shared capacity (source/global
buckets), which affects everyone equally and refills in seconds.

- The only per-account state an attacker can exhaust is the failure bucket.
- A request carrying a live trusted-device token skips that bucket.
- A request carrying a valid proof-of-work solution skips that bucket.
- Neither can be forged by the attacker without the victim's device token or
  actual CPU work; the PoW is stateless (HMAC over issue time + difficulty) and
  the attacker gains nothing by flooding challenges.
- Success clears the bucket.
- There is no code path that sets a persistent "locked" flag.

Tests: `TestVictimOnTrustedDeviceNotLockedOut`,
`TestProofOfWorkUnlocksAfterFlood`, `TestProofDoesNotBuyUnlimitedGuesses`,
`TestNoPersistentLockState`, `TestSuccessClearsFailureBudget`,
`TestOtherAccountsUnaffected`.

## 5. Proof-of-work parameters

Default 18 leading zero bits ≈ 262k hashes ≈ well under a second on any device
that can run Argon2id. It is a speed bump proportional to the attacker's flood,
not an entropy barrier. It is tuneable per deployment (`authd -pow-bits`).

## 6. Migration-window specifics

- During migration both `credentials` and `legacy_credentials` may hold a row
  for different users; never both for the same user (enforced transactionally).
- The legacy digest is sealed; a dump mid-window is therefore not a fresh
  offline oracle.
- `authctl status` reports the remaining legacy count; the cut-over is dropping
  the table at zero.
- Re-running the import is safe and cannot resurrect a legacy row for a
  migrated user (`TestImportDoesNotResurrectMigrated`).

## 7. What we are explicitly not defending against

- A user choosing a password already in the attacker's dictionary *and* the
  attacker having both the dump and the KMS key.
- Phishing of the password at the client.
- A compromised endpoint (malware reading the password before it is used).
- Quantum adversaries (Ristretto255 discrete log is not post-quantum; RFC 9807
  Appendix B discusses PQ AKE instantiations, not PQ OPRF).
