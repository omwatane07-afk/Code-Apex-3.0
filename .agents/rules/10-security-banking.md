# Security rules (bank-grade, always on)

Assume the bank's security team will pen-test this product and audit its source. Meet OWASP ASVS Level 2 and the OWASP API Top 10 as the minimum bar.

## Identity and access
- Primary login: OIDC with the bank IdP. Break-glass local accounts: argon2id plus TOTP, disabled by default, every use raises a high-severity audit event and a notification.
- Roles: `analyst`, `compliance_approver`, `ciso`, `auditor`, `model_validator`, `admin`. Permissions are explicit allow-lists in one policy module (`iam/policy.py`). Deny by default.
- Separation of duties enforced in the domain layer: the person who prepares a filing packet or decision cannot approve it (maker-checker). `admin` can configure but cannot approve, file, or read incident content. `auditor` and `model_validator` are read-only.
- Sessions: server-side in Postgres, httpOnly, Secure, SameSite=Strict cookies, idle timeout 15 minutes, absolute timeout 8 hours (configurable), CSRF token on every state-changing request. Re-authenticate (step-up) for approve, file, accept-risk and role changes.

## Data handling
- Store incident metadata only. Never raw logs, never customer data.
- PII guard at the intake edge (`intake/pii_guard.py`): detect and redact Aadhaar (12 digits, validate with the Verhoeff checksum), PAN (`[A-Z]{5}[0-9]{4}[A-Z]`), card numbers (Luhn), IFSC plus account-number patterns, mobile numbers, email addresses. Redact before persistence. Count redactions and show the count in the UI. Test with a labelled corpus of fake values.
- Field-level envelope encryption for free-text incident narratives and evidence notes. Key access goes through a `KeyProvider` interface: file-based for dev, PKCS#11 (HSM) adapter stubbed with a documented contract.
- Retention is configurable per record class. Support legal hold. Never hard-code retention periods.

## Audit chain
- Table `audit_event` is append-only (revoke UPDATE and DELETE from the app role, add a trigger that raises on attempts).
- Each event stores `prev_hash` and `hash = SHA-256(canonical_json(event) || prev_hash)`. Every 1,000 events or 1 hour, write an Ed25519-signed checkpoint.
- `tools/verify-audit` verifies the chain and signatures offline from an export. Include a tamper test in CI.
- Log who, what, when, from where, before/after values (redacted), and the request ID.

## Network and API
- No outbound calls except to configured, allow-listed internal endpoints (SMTP, bank webhook receivers, OIDC IdP, syslog). Implement one egress client wrapper that blocks everything else, including redirects. Block private-range tricks and DNS rebinding on user-supplied URLs (SSRF guard).
- Inbound webhooks: HMAC-SHA256 over body plus timestamp, 5-minute replay window, per-source secret, idempotency key, size limit 256 KB, rate limit, optional mTLS. Rejects are audited, bodies are not logged.
- Strict CSP (`default-src 'self'`; no inline scripts; no external hosts), HSTS, `X-Content-Type-Options`, `Referrer-Policy: no-referrer`, `frame-ancestors 'none'`. Validate all input with Pydantic models that forbid extra fields. Parameterized queries only.
- Errors never leak stack traces or internals. Use stable error codes and request IDs.

## Reliability (CYBERQ is in the six-hour path)
- Durable timers in Postgres, processed with `FOR UPDATE SKIP LOCKED`; escalations are idempotent. Chaos test: kill the worker mid-escalation and restart; no escalation is missed or duplicated.
- Health endpoints: `/healthz` (process), `/readyz` (DB, worker heartbeat, NTP skew).
- Manual fallback: every incident can be exported as a printable checklist and filing worksheet that works with CYBERQ offline.
- Document RTO/RPO as design targets in `docs/ops/DR.md`. Never claim measured numbers you have not tested.

## Supply chain and release
- Lockfiles with hashes. CI fails on high or critical CVEs, secrets, or license violations.
- Every release produces: CycloneDX SBOM, signed images (cosign), checksums, a vulnerability scan report, the `make escrow` bundle, and a release note listing every changed dependency.
- No telemetry, no phone-home, no auto-update. Updates arrive as signed offline bundles.
- Maintain `SECURITY.md` (disclosure process, vulnerability fix SLAs) and `docs/security/PENTEST_PREP.md` (architecture, trust boundaries, test accounts, known limitations).

## No LLM at runtime in v1
Do not add model calls to the product. If a later ADR proposes one, it must be an on-prem model, never receive incident content without redaction, never take actions, and always be labelled as a draft.
