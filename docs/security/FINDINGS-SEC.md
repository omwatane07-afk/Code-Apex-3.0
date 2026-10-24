# Red Team Security Findings Log (FINDINGS-SEC)

**Audit Ledger Status**: 22 Findings Tracked  
**Valid Findings Hardened & Closed**: 14 (SEC-01 through SEC-09, SEC-12 through SEC-15, SEC-18)  
**Retracted Findings (Red Team Product Code Invalidation)**: 4 (SEC-10, SEC-11, SEC-16, SEC-17)  
**Open Architectural Findings (Scheduled for M1)**: 4 (Critical 0, High 0, Medium 3, Low 1: SEC-19, SEC-20, SEC-21, SEC-22)

---

## Retracted & Invalidated Findings

| ID | Stated Class | Retraction Rationale | Milestone Deferral |
|---|---|---|---|
| **SEC-10** | CWE-1236 CSV Formula Injection | **RETRACTED / INVALID**: The red team created `backend/src/cyberq/core/csv_sanitizer.py` and wrote tests against code that did not exist in M0. The red team never builds product features. Purged via `git rm`. | Added to Milestone M4 acceptance criteria in `docs/DOMAIN_SPEC.md` |
| **SEC-11** | CWE-502 YAML Deserialization | **RETRACTED / INVALID**: The red team created `backend/src/cyberq/obligations/loader.py` and attacked its own creation. Pack loading is an M1 feature. Purged via `git rm`. | Added to Milestone M1 acceptance criteria in `docs/DOMAIN_SPEC.md` |
| **SEC-16** | Session Fixation on Role Step-Up | **RETRACTED / INVALID**: The red team created `POST /api/v1/auth/step-up` and `rotate_session` as product code. Step-up represents MFA re-authentication before sensitive filing approvals, not arbitrary role elevation in M0. Code reverted. | Added to Milestone M3 acceptance criteria in `docs/DOMAIN_SPEC.md` |
| **SEC-17** | Multi-Session Revocation (`all_sessions`) | **RETRACTED / INVALID**: The red team created `all_sessions` query parameter and `destroy_user_sessions` as product code. Multi-session global revocation belongs to Milestone M1. Code reverted. | Added to Milestone M1 acceptance criteria in `docs/DOMAIN_SPEC.md` |

---

## Valid Verified Security Findings Matrix

### SEC-01: Checkpoint Hash Decoupling Allows Undetected Ledger Fork
- **Severity**: Critical
- **CVSS 3.1**: 9.1 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H`)
- **OWASP ASVS**: V10.1.1 (Verify that the application creates tamper-evident audit logs)
- **Root Cause**: `backend/src/cyberq/audit/chain.py:189` verified Ed25519 signatures over checkpoint payloads, but did not assert that `checkpoint.root_hash == last_event.hash` at `checkpoint.to_sequence`.
- **Bank Impact**: An adversary possessing valid signing material (or compromised key) could construct detached checkpoints referencing arbitrary merkle roots, enabling undetected ledger forks and regulatory fraud during CERT-In inspection.
- **Proof Test**: `backend/tests/security/test_domain_f_integrity.py::test_checkpoint_must_bind_to_event_root_hash`
- **Mitigation**: `AuditService.verify_chain` strictly verifies `cp['root_hash'] == events_by_seq[cp['to_sequence']]['hash']`.
- **Regression Status**: Verified Passing (`make verify`).

### SEC-02: Checkpoint Verifier Ignores Tail-Truncated Event Slices
- **Severity**: High
- **CVSS 3.1**: 7.5 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N`)
- **OWASP ASVS**: V10.1.1 (Verify audit log integrity and completeness)
- **Root Cause**: `backend/src/cyberq/audit/chain.py:189` accepted event slices that omitted events covered by the checkpoint's `from_sequence..to_sequence` span without flagging truncation.
- **Bank Impact**: Malicious SOC operator could export a partial audit log omitting incriminating actions while checkpoints still appeared green.
- **Proof Test**: `backend/tests/security/test_domain_f_integrity.py::test_checkpoint_must_reject_truncated_event_chain`
- **Mitigation**: Verifier asserts that all sequences from `min(seq)` to `max(seq)` exist continuously with zero gaps.
- **Regression Status**: Verified Passing (`make verify`).

### SEC-03: Lack of DB-Level Triggers Permits Direct UPDATE/DELETE on Audit Ledger
- **Severity**: High
- **CVSS 3.1**: 7.2 (`CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:H`)
- **OWASP ASVS**: V10.1.1, V10.3.1 (Verify audit records are stored in append-only storage)
- **Root Cause**: `backend/src/cyberq/core/database.py:60` lacked SQL-level `BEFORE UPDATE`, `BEFORE DELETE`, and `BEFORE INSERT OR REPLACE` triggers on `audit_event` and `audit_checkpoint`.
- **Bank Impact**: A DBA, compromised microservice connection, or SQL injection flaw could alter historical audit timestamps or actor IDs directly in PostgreSQL.
- **Proof Test**: `backend/tests/security/test_domain_f_integrity.py::test_audit_event_db_level_immutability`
- **Mitigation**: Triggers installed on SQLite (`RAISE(FAIL, ...)`) and PostgreSQL (`prevent_audit_mutation()` plpgsql functions).
- **Regression Status**: Verified on SQLite fixture; UNVERIFIED on PostgreSQL 16 (docker/local daemon absent on host; scheduled for live container verification in M1).

### SEC-04: Cross-Site Request Forgery on Session Invalidation (/auth/logout)
- **Severity**: High
- **CVSS 3.1**: 7.1 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:L`)
- **OWASP ASVS**: V3.5.1, V4.2.1 (Verify anti-CSRF defenses on sensitive state-changing endpoints)
- **Root Cause**: `backend/src/cyberq/api/routes_auth.py:122` did not require `require_csrf` dependency on the `/auth/logout` endpoint.
- **Bank Impact**: Cross-origin phishing site could force-terminate an incident commander's active session during a live CERT-In 6-hour regulatory countdown window, causing deadline breaches.
- **Proof Test**: `backend/tests/security/test_domain_b_authz.py::test_csrf_required_on_logout`
- **Mitigation**: Attached `require_csrf` dependency verifying `X-CSRF-Token` against server-stored session token.
- **Regression Status**: Verified Passing (`make verify`).

### SEC-05: Unicode and Homoglyph Equivalence Bypass in Maker-Checker Enforcement
- **Severity**: Medium
- **CVSS 3.1**: 6.5 (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N`)
- **OWASP ASVS**: V4.1.1, V5.1.4 (Verify string normalization and comparison)
- **Root Cause**: `backend/src/cyberq/iam/policy.py:134` checked `preparer_id != approver_id` using raw string equality without NFKC normalization or whitespace stripping.
- **Bank Impact**: Preparer could approve their own regulatory submission packet by supplying their username padded with zero-width spaces (`\u200b`) or soft hyphens (`\u00ad`), bypassing the RBI four-eyes principle.
- **Proof Test**: `backend/tests/security/test_domain_b_authz.py::test_maker_checker_rejects_empty_whitespace_or_identical_users`
- **Mitigation**: Implemented `PolicyEngine._normalize_identity` enforcing Unicode NFKC normalization, removing formatting characters (`Cf`, `Cc`, `Cs`, `Cn`), and using casefold comparison.
- **Regression Status**: Verified Passing (`make verify`).

### SEC-06: Request Model Mass Assignment & Parameter Smuggling on Incident Intake
- **Severity**: Medium
- **CVSS 3.1**: 5.3 (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N`)
- **OWASP ASVS**: V5.1.1, V5.1.3 (Verify schema validation and rejection of unexpected parameters)
- **Root Cause**: `IncidentCreateRequest` did not configure `extra="forbid"`, allowing extraneous fields (`approved_by`, `status`, `deadline_override`) to be parsed without rejection.
- **Bank Impact**: Attackers could pollute audit snapshots and downstream reporting engines with unvalidated state fields.
- **Proof Test**: `backend/tests/security/test_domain_e_api.py::test_mass_assignment_prevented_on_incident_create`
- **Mitigation**: Added `model_config = ConfigDict(extra="forbid")` across all Pydantic request models.
- **Regression Status**: Verified Passing (`make verify`).

### SEC-07: Interactive OpenAPI & Swagger Documentation Exposed in Production
- **Severity**: Low / Informational
- **CVSS 3.1**: 4.3 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`)
- **OWASP ASVS**: V14.4.1 (Verify debug interfaces are disabled in production)
- **Root Cause**: `backend/src/cyberq/api/app.py:38` mounted `/docs` and `/openapi.json` unconditionally.
- **Bank Impact**: Attackers conducting external reconnaissance obtain exact JSON schemas, routes, and error definitions.
- **Proof Test**: `backend/tests/security/test_fail_closed_config.py::test_debug_routes_not_mounted_in_production`
- **Mitigation**: Conditional route mounting: `docs_url=None`, `openapi_url=None` when `settings.is_production()`.
- **Regression Status**: Verified Passing (`make verify`).

### SEC-08: Development Login Simulator Enabled in Production Builds
- **Severity**: Critical
- **CVSS 3.1**: 9.8 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`)
- **OWASP ASVS**: V2.1.2, V2.7.1 (Verify out-of-band and mock authenticators are strictly disabled in production)
- **Root Cause**: `POST /api/v1/auth/login` allowed arbitrary username and role selection for simulator convenience without gating by environment.
- **Bank Impact**: Anyone on the bank network could grant themselves the CISO or Admin role without touching Active Directory/OIDC.
- **Proof Test**: `backend/tests/security/test_health_and_security.py::test_production_blocks_simulated_login`
- **Mitigation**: `routes_auth.py` immediately raises `HTTP 403 Forbidden` if `settings.is_production()`.
- **Regression Status**: Verified Passing (`make verify`).

### SEC-09: Ambiguous Multi-Token Request Smuggling / Session Conflict
- **Severity**: Medium
- **CVSS 3.1**: 5.3 (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N`)
- **OWASP ASVS**: V3.2.1 (Verify session token binding and rejection of conflicting credentials)
- **Root Cause**: `backend/src/cyberq/api/deps.py:42` permitted simultaneous submission of divergent session tokens in Cookie, `X-Session-ID`, and `Authorization` headers.
- **Bank Impact**: Risk of session desynchronization between proxies, intermediate caching layers, and backend audit logs.
- **Proof Test**: `backend/tests/security/test_domain_a_session.py::test_session_conflict_between_cookie_and_header_rejected`
- **Mitigation**: `deps.py` inspects all credential sources and raises `HTTP 400 Bad Request` if `len(provided_tokens) > 1`.
- **Regression Status**: Verified Passing (`make verify`).

### SEC-12: Vite Frontend Build Emitted Source Maps by Default
- **Severity**: Low
- **CVSS 3.1**: 3.7 (`CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N`)
- **OWASP ASVS**: V14.4.1 (Verify production code does not leak debug information or source maps)
- **Root Cause**: `web/vite.config.ts` lacked explicit `build.sourcemap = false`.
- **Bank Impact**: Client-side TypeScript source files, internal comments, and business logic visible in production browser dev tools.
- **Proof Test**: `backend/tests/security/test_domain_d_web_client.py::test_frontend_build_disables_sourcemaps`
- **Mitigation**: Configured `build: { sourcemap: false }` in `web/vite.config.ts`.
- **Regression Status**: Verified Passing (`make verify`).

### SEC-13: Production Mode Permitted Software-Backed LocalKeyProvider (ADR-0002)
- **Severity**: High
- **CVSS 3.1**: 7.5 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`)
- **OWASP ASVS**: V6.2.1, V6.4.1 (Verify secret keys are protected in hardware security modules)
- **Root Cause**: `LocalKeyProvider` in `backend/src/cyberq/audit/crypto.py` could be initialized regardless of `CYBERQ_ENV`.
- **Bank Impact**: Private signing seed stored in plain RAM or environment variables instead of bank HSM/PKCS#11 appliance.
- **Proof Test**: `backend/tests/security/test_fail_closed_config.py::test_local_key_provider_rejected_in_production`
- **Mitigation**: `LocalKeyProvider.__init__` checks `get_settings().is_production()` and raises `ValueError` per ADR-0002.
- **Regression Status**: Verified Passing (`make verify`).

### SEC-14: Fail-Open Default Configuration When CYBERQ_ENV Unset or Misspelled
- **Severity**: High
- **CVSS 3.1**: 7.4 (`CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N`)
- **OWASP ASVS**: V14.1.1 (Verify application fails closed by default)
- **Root Cause**: `Settings.ENV` defaulted to `EnvironmentType.DEMO`. Any typo (`CYBERQ_ENV="prduction"`) defaulted to demo mode.
- **Bank Impact**: Inadvertent production deployment with demo secrets, enabled login simulators, and relaxed cookie security.
- **Proof Test**: `backend/tests/security/test_fail_closed_config.py::test_env_unset_or_unrecognized_defaults_to_production`
- **Mitigation**: Configured `ENV: EnvironmentType = Field(default=EnvironmentType.PRODUCTION)` with pre-validator coercing any unrecognized value to `PRODUCTION`.
- **Regression Status**: Verified Passing (`make verify`).

### SEC-15: In-Memory Sliding Window Rate Limiter on /auth/login
- **Severity**: Medium
- **CVSS 3.1**: 5.3 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L`)
- **OWASP ASVS**: V2.2.1, V13.1.4 (Verify rate limiting on authentication endpoints)
- **Root Cause**: `routes_auth.py` lacked throttling on simulated login requests.
- **Mitigation**: Added thread-safe in-memory sliding window limiter (5 attempts per 60s window per `client_ip:username`).
- **Proof Test**: `backend/tests/security/test_domain_a_session.py::test_login_rate_limiting_enforced`
- **Regression Status**: Verified Passing (`make verify`).

### SEC-18: Untrusted Proxy Header Spoofing via X-Forwarded-Proto
- **Severity**: Medium
- **CVSS 3.1**: 5.3 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N`)
- **OWASP ASVS**: V9.1.1, V14.1.1 (Verify secure communication and trust boundaries)
- **Root Cause**: `backend/src/cyberq/api/deps.py` blindly honored `X-Forwarded-Proto: https` from any peer IP, allowing an attacker connecting directly to the API port to spoof HTTPS state on plaintext connections.
- **Bank Impact**: Bypassing secure transport enforcement and tricking TLS detection logic.
- **Proof Test**: `backend/tests/security/test_fail_closed_config.py::test_untrusted_proxy_x_forwarded_proto_spoofing_rejected`
- **Mitigation**: Added `TRUSTED_PROXIES` allow-list to `Settings` (default empty). `deps.py:get_current_session` only honors `X-Forwarded-Proto` if `request.client.host in settings.TRUSTED_PROXIES`.
- **Regression Status**: Verified Passing (`make verify`).

---

## Open Architectural Findings (Scheduled by Milestone)

The following in-memory rate limiter limitations are documented, tested, and tracked as **OPEN** items to be resolved in Milestone M1 via reverse proxy (Envoy/NGINX) or shared-store rate limiting:

### SEC-19: Shared Corporate Gateway Victim Lockout Denial-of-Response
- **Severity**: Medium
- **Target Milestone**: Milestone M1 (Proxy-level throttling / account-decoupled lockout)
- **CVSS 3.1**: 5.3 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L`)
- **Issue**: In-memory keying on `client_ip:username` allows an attacker on the same corporate proxy/NAT IP as legitimate victim Alice to deliberately fail 5 requests for `alice` and lock Alice out of the portal.
- **Proof Test**: `backend/tests/security/test_domain_a_session.py::test_rate_limiter_lockout_denial_of_response`
- **Status**: **OPEN** (Scheduled for M1)

### SEC-20: In-Memory Rate Limiter State Lost on Process Restart / Worker Recycle
- **Severity**: Low
- **Target Milestone**: Milestone M1 (Durable/Shared Rate Limiting)
- **CVSS 3.1**: 3.7 (`CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L`)
- **Issue**: The sliding window is stored in process memory (`defaultdict(list)`). Any Uvicorn process restart or worker recycle drops all attempt counters, allowing attackers to immediately resume brute-force attacks.
- **Proof Test**: `backend/tests/security/test_domain_a_session.py::test_rate_limiter_restart_resets_state`
- **Status**: **OPEN** (Scheduled for M1)

### SEC-21: Multi-Worker In-Memory State Bypass Multiplies Quota
- **Severity**: Medium
- **Target Milestone**: Milestone M1 (Shared Store or Reverse Proxy Rate Limiting)
- **CVSS 3.1**: 5.3 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L`)
- **Issue**: In a multi-worker Uvicorn deployment, each OS process maintains independent memory. An adversary alternating requests across $N$ workers achieves $N \times 5$ attempts before encountering an HTTP 429 response.
- **Proof Test**: `backend/tests/security/test_domain_a_session.py::test_rate_limiter_multi_worker_bypass`
- **Status**: **OPEN** (Scheduled for M1)

### SEC-22: Shared Proxy IP Collapse (Gateway IP Collateral Denial)
- **Severity**: Medium
- **Target Milestone**: Milestone M1 (Proxy allow-list and client subnet bucket keys)
- **CVSS 3.1**: 5.3 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L`)
- **Issue**: When all bank traffic originates from a central reverse proxy and proxy IPs are trusted, misconfiguration or untrusted forwarding can allow one abusive branch to exhaust the request budget for other internal users.
- **Status**: **OPEN** (Scheduled for M1)
