# ADR 0002: Key Custody, HSM Signing Abstraction, and External Checkpoint Anchoring

## Status
Accepted (Design specified; LocalKeyProvider implemented; External anchoring marked as residual risk pending M1/M2 streaming integrations).

## Context
In CYBERQ, the audit decision ledger relies on Ed25519 signatures over audit checkpoints (`AuditCheckpoint`) to provide cryptographic non-repudiation for Indian commercial bank regulators (CERT-In, RBI DAKSH, DPDP).

During threat modeling and white-box red team analysis (Round 1 / Step 0), we identified a critical key custody risk:
- **Threat:** If an adversary compromises the application runtime process or reads container environment variables, they can obtain `AUDIT_SIGNING_SEED`.
- **Exploitation:** With access to the raw signing key in application memory, an attacker with SQL write access could forge an alternate ledger history, recompute SHA-256 event chains from genesis, and sign valid checkpoints over the fabricated history.
- **Consequence:** An internal attacker could conceal an incident or tamper with regulatory clocks without detection by the local verifier alone.

## Decision
We establish a two-pillar defense-in-depth architecture:

### 1. KeyProvider HSM / KMS Abstraction
Decouple `AuditService` from raw private key material by introducing a `KeyProvider` interface:
```python
class KeyProvider(Protocol):
    def get_public_key_hex(self) -> str: ...
    def sign(self, message: bytes) -> bytes: ...
```
- **LocalKeyProvider:** Used for development, testing, and air-gapped single-node pilots with hash-locked seeds.
- **PKCS11KeyProvider / KMSKeyProvider (Production Target):** Interfaces with bank-approved Hardware Security Modules (HSM) or central key management systems via PKCS#11. The private key never enters the application runtime memory.

### 2. External Append-Only Anchoring (WORM / SIEM / Syslog)
Local cryptographic checkpoints are insufficient against a complete application host compromise if stored solely in the local database. CYBERQ checkpoints must be externally anchored:
- Immediately upon creation, each checkpoint is broadcast via append-only, TLS-encrypted RFC 5424 syslog to the bank's central immutable SIEM and/or Write-Once-Read-Many (WORM) storage.
- External regulators (e.g. RBI DAKSH filing receipt acknowledgements) serve as secondary external timestamp anchors.
- Any attempt by an insider to rewrite local database history after a checkpoint has been broadcast will result in a cryptographic fork detectable by offline verification tools comparing against external SIEM logs.

## Consequences
- **Positive:** Application compromise does not allow undetectable history rewrites once checkpoints are anchored externally.
- **Residual Risk:** Until Milestone M1/M2 provides live SIEM syslog export and HSM integration tests, key compromise remains an open residual risk in single-node demo deployments.
