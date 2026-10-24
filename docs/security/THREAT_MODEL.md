# CYBERQ Threat Model & Attack Surface Map (Phase 0)

**Author:** Principal Red Team Lead  
**Scope:** CYBERQ Bank Incident-to-Board Platform  
**Target Standard:** OWASP ASVS Level 2 / RBI Cybersecurity Framework 2026 / DPDP Rules 2025  

---

## 1. System Overview & Critical Assets

CYBERQ sits directly in the six-hour regulatory reporting path for an Indian commercial bank. If this system fails or is compromised, the bank faces statutory fines (up to ₹250 crore under DPDP), supervisory enforcement from RBI, or falsification of regulatory compliance records.

### Critical Assets Inventory:
1. **Audit Chain & Checkpoints (`audit_event`, `audit_checkpoint`)**:
   - Cryptographic record of every incident trigger, filing approval, risk acceptance, and user action.
   - Integrity and non-repudiation are paramount.
2. **Obligation Clocks & Trigger State**:
   - Active countdown timers for CERT-In (6h), RBI DAKSH (6h), and DPDP (72h).
   - Tampering with trigger timestamps or states can cause missed filings or false claims of compliance.
3. **Filing Packets & Acknowledgement Records**:
   - Snapshot data submitted to regulatory portals and subsequent acknowledgement IDs.
   - Forgery of approver signatures or acknowledgement receipts undermines bank legal compliance.
4. **Decision Ledger & Board Packs**:
   - Executive decisions accepting or funding cyber risks, presented directly to the Board of Directors.
5. **Cryptographic Keys & Signing Seeds**:
   - Ed25519 checkpoint signing private keys, session HMAC signing keys, and future envelope encryption keys.
6. **Incident Narrative & Evidence Metadata**:
   - Free-text descriptions of ongoing cyberattacks, compromised assets, and attacker indicators.

---

## 2. Threat Actors & Capabilities

| Actor | Access / Capabilities | Motive |
|---|---|---|
| **External Outsider** | Network access to public ports (if exposed); web client access. | Breach perimeter, access incident data, cause denial of service. |
| **Compromised SOC Analyst** | Valid low-privilege `analyst` session; internal network access. | Hide evidence, manipulate incident creation, bypass maker-checker to approve own packets. |
| **Rogue / Compromised Approver** | Valid `compliance_approver` or `ciso` session. | Falsify regulatory filings, record false ack IDs, tamper with risk decisions. |
| **Rogue System Administrator** | Access to configuration and admin routes. | Abuse admin privileges to read sensitive incident narratives or alter audit records. |
| **Malicious SIEM / Vendor Feed** | Inbound webhook or syslog stream transmitter. | Inject forged incidents, trigger resource exhaustion, exploit parser flaws. |
| **Malicious Insider with Database Access** | Direct access to database connection / app DB role. | Directly edit or delete rows in `audit_event`, bypass application policy engine. |

---

## 3. Trust Boundaries & STRIDE Analysis

```
 [ External Client / Browser ] 
              |  (Boundary 1: HTTP / TLS / Cookies / CSP)
              v
 [ Reverse Proxy / FastAPI API Gateway ]
              |  (Boundary 2: Authentication & Central IAM Policy Engine)
              v
 [ CYBERQ Core Domain Services (Audit, Clocks, Incidents, IAM) ]
              |  (Boundary 3: Database & Cryptographic Signers)
              v
 [ PostgreSQL 16 Ledger / Ed25519 Key Provider ]
```

### STRIDE Assessment by Boundary:

| Boundary | Threat Class | Potential Abuse in CYBERQ |
|---|---|---|
| **Boundary 1: Client -> API** | **Spoofing** | Forging `X-Request-ID`, `X-Forwarded-For`, session token prediction. |
| | **Tampering** | Parameter tampering on request bodies, oversized payload DoS. |
| | **Repudiation** | Actions performed without client IP / user logging. |
| | **Information Disclosure** | Verbose error messages, `/openapi.json` exposed in production, CSP bypass. |
| | **Denial of Service** | Slowloris, unbounded queries, massive JSON payloads. |
| | **Elevation of Privilege** | CSRF to execute actions under another active session. |
| **Boundary 2: API -> Domain** | **Elevation of Privilege** | Bypassing `iam/policy.py`, role assumption, maker-checker bypass. |
| | **Tampering** | Mass assignment of internal fields (`approved_by`, `status`, `hash`). |
| **Boundary 3: Domain -> Storage** | **Tampering** | Direct `UPDATE` or `DELETE` on `audit_event` rows. |
| | **Repudiation** | Modifying previous hashes without breaking checkpoint verification. |

---

## 4. Ranked Abuse Cases (Tagged by Verification Status)

1. **AC-01: Unauthenticated Arbitrary Role Assumption in Production (Critical - SEC-08)**  
   *Classification:* `TESTED-ON-BUILT-CODE`  
   *Verified Impact:* An attacker on the network could bypass the bank's IdP and assume any administrative, approver, or CISO role by sending a crafted JSON body to `/api/v1/auth/login`.  
   *Verified Defense:* Disabled in production (`is_production()` raises 403 Forbidden). Proved in `test_health_and_security.py::test_production_blocks_simulated_login`.

2. **AC-02: Cryptographic Audit Chain Tampering & Undetected Ledger Forking (Critical - SEC-01 & SEC-02)**  
   *Classification:* `TESTED-ON-BUILT-CODE`  
   *Verified Impact:* An adversary could supply signed checkpoints with altered root hashes or truncate the audit event tail, creating diverging audit histories that passed offline verification.  
   *Verified Defense:* Checkpoint root hash strictly bound to `to_sequence` event hash and continuous event verification. Proved in `test_domain_f_integrity.py::test_checkpoint_must_bind_to_event_root_hash` and `test_checkpoint_must_reject_truncated_event_chain`.

3. **AC-03: Arbitrary Code Execution via YAML Deserialization in Obligation Loader (Critical)**  
   *Classification:* `NOT-TESTABLE-UNTIL-M1`  
   *Threat Narrative:* An attacker submitting a malicious obligation pack could attempt to execute arbitrary system commands via PyYAML object instantiation (`!!python/object/apply:os.system`). Obligation pack loader does not exist in M0. Deferred to M1 acceptance tests.

4. **AC-04: Database-Level Audit Row Erasure / Alteration (High - SEC-03)**  
   *Classification:* `TESTED-ON-BUILT-CODE`  
   *Verified Impact:* A malicious insider with app-role DB access could execute `UPDATE`, `DELETE`, or `INSERT OR REPLACE` to scrub incriminating incident events.  
   *Verified Defense:* Database statement-level `BEFORE TRUNCATE` triggers and row-level immutability triggers. Proved in `test_domain_f_integrity.py::test_audit_event_db_level_immutability`.

5. **AC-05: Maker-Checker Separation of Duties Bypass (High - SEC-05)**  
   *Classification:* `TESTED-ON-BUILT-CODE`  
   *Verified Impact:* A preparer could approve their own regulatory filing packet using Unicode invisibles (`\u200b`), case differences, or alternative formatting.  
   *Verified Defense:* Canonical 128-bit `uuid.UUID` identity comparison with defense-in-depth Unicode NFKC normalization and invisible character rejection. Proved in `test_domain_a_identity.py::test_maker_checker_canonical_server_uuid_comparison`.

6. **AC-06: CSV Formula Injection / DDE Command Execution in Exports (High)**  
   *Classification:* `NOT-TESTABLE-UNTIL-M4`  
   *Threat Narrative:* Malicious incident titles or metadata containing formula triggers (`=cmd|...`, `@SUM`) could attempt to execute commands on bank workstations when auditors open exported CSVs in Excel. CSV export engine does not exist in M0. Deferred to M4 acceptance tests.

7. **AC-07: Cross-Site Request Forgery (CSRF) on Sensitive State Operations (High - SEC-04)**  
   *Classification:* `TESTED-ON-BUILT-CODE`  
   *Verified Impact:* An attacker on an intranet page could force an authenticated analyst/approver browser to create incidents or terminate active sessions mid-incident.  
   *Verified Defense:* Mandatory cryptographically random anti-CSRF token on all state-changing methods (`POST`, `PUT`, `PATCH`, `DELETE`). Proved in `test_domain_d_web_client.py::test_csrf_enforced_across_all_state_changing_routes`.

8. **AC-08: Session Smuggling and Identifier Ambiguity (Medium - SEC-09)**  
   *Classification:* `TESTED-ON-BUILT-CODE`  
   *Verified Impact:* Presenting conflicting cookie and header session tokens could cause session desynchronization, cross-tenant cache contamination, or proxy smuggling.  
   *Verified Defense:* Strict multi-token detection rejecting ambiguous requests with HTTP 400 Bad Request. Proved in `test_domain_a_session.py::test_session_conflict_between_cookie_and_header_rejected`.

9. **AC-09: Broken Object-Level Authorization (BOLA / IDOR) and Cross-Role Leakage (Medium)**  
   *Classification:* `POLICY-FUNCTION-ONLY`  
   *Threat Narrative:* An admin or unauthenticated actor directly querying an incident could read sensitive incident narratives bypassing separation of duties. Central policy denies `ADMIN` role from `INCIDENT_READ`. Detailed per-incident item GET route does not exist in M0 (deferred to M1).

10. **AC-10: Production Reconnaissance via Exposed Schema & Source Maps (Medium - SEC-07 & SEC-12)**  
    *Classification:* `TESTED-ON-BUILT-CODE`  
    *Verified Impact:* Automated scanners could map internal parameters, API types, and frontend logic via `/openapi.json` and client `.js.map` files.  
    *Verified Defense:* Automated disabling of OpenAPI schema in production and Vite `build.sourcemap: false`. Proved in `test_fail_closed_config.py::test_debug_routes_not_mounted_in_production` and `test_domain_d_web_client.py::test_frontend_build_disables_sourcemaps`.

---

## 5. Attack Surface Map (Updated with Built Code Realities)

| Surface / Route | Method | Auth Required | Permitted Roles | Inputs | Data Touched | Defense Status & Proven Test |
|---|---|---|---|---|---|---|
| `/healthz` | GET | None | Public | None | Process status | `TESTED-ON-BUILT-CODE` ([test_health_and_security.py](file:///d:/Code%20Apex%203.0/backend/tests/test_health_and_security.py)) |
| `/readyz` | GET | None | Public | None | DB, NTP skew | `TESTED-ON-BUILT-CODE` ([test_health_and_security.py](file:///d:/Code%20Apex%203.0/backend/tests/test_health_and_security.py)) |
| `/api/v1/auth/login` | POST | None | Public | `username`, `role` | `app_user`, `user_session`, `audit_event` | `TESTED-ON-BUILT-CODE`: Disabled in prod; rate limited ([test_domain_a_session.py](file:///d:/Code%20Apex%203.0/backend/tests/security/test_domain_a_session.py)) |
| `/api/v1/auth/me` | GET | Session | All authenticated | Cookie / Session ID | `app_user`, `user_session` | `TESTED-ON-BUILT-CODE` ([test_domain_a_session.py](file:///d:/Code%20Apex%203.0/backend/tests/security/test_domain_a_session.py)) |
| `/api/v1/auth/step-up` | POST | Session + CSRF | Granted elevated roles | `target_role` | `user_session`, `audit_event` | `TESTED-ON-BUILT-CODE`: Session rotated ([test_domain_a_session.py](file:///d:/Code%20Apex%203.0/backend/tests/security/test_domain_a_session.py)) |
| `/api/v1/auth/logout` | POST | Session + CSRF | All authenticated | `all_sessions` query | `user_session`, `audit_event` | `TESTED-ON-BUILT-CODE`: Single & multi-device purge ([test_domain_a_session.py](file:///d:/Code%20Apex%203.0/backend/tests/security/test_domain_a_session.py)) |
| `/api/v1/audit/export` | GET | Session | `ciso`, `auditor`, `model_validator` | Session ID | `audit_event`, `audit_checkpoint` | `TESTED-ON-BUILT-CODE` ([test_iam_matrix.py](file:///d:/Code%20Apex%203.0/backend/tests/test_iam_matrix.py)) |
| `/api/v1/audit/verify` | GET | Session | `auditor`, `ciso`, `model_validator`, `admin` | Session ID | `audit_event`, `audit_checkpoint` | `TESTED-ON-BUILT-CODE` ([test_iam_matrix.py](file:///d:/Code%20Apex%203.0/backend/tests/test_iam_matrix.py)) |
| `/api/v1/incidents` | POST | Session + CSRF | `analyst` | `title`, `summary`, `severity` | Memory/Store, `audit_event` | `TESTED-ON-BUILT-CODE` ([test_domain_i_availability.py](file:///d:/Code%20Apex%203.0/backend/tests/security/test_domain_i_availability.py)) |
| `/api/v1/incidents` | GET | Session | `analyst`, `compliance_approver`, `ciso`, `auditor` | Session ID | Memory/Store | `TESTED-ON-BUILT-CODE` ([test_idor_bola.py](file:///d:/Code%20Apex%203.0/backend/tests/security/test_idor_bola.py)) |
| `/api/v1/incidents/{id}` | GET | Session | `analyst`, `compliance_approver`, `ciso`, `auditor` | Incident ID | Database | `NOT-TESTABLE-UNTIL-M1` (Deferred to Milestone M1) |
| `tools/verify-audit` | CLI | OS / File | Auditor | Export JSON file | None (Read-only) | `TESTED-ON-BUILT-CODE` ([test_audit.py](file:///d:/Code%20Apex%203.0/backend/tests/test_audit.py)) |
| Ingestion Webhooks | POST | HMAC Signature | SIEM / Vendor | JSON body | Intake buffer | `NOT-TESTABLE-UNTIL-M2` (Deferred to Milestone M2) |
| Statutory Clocks | Worker | Postgres Job | Background Worker | Due deadlines | Obligation state | `NOT-TESTABLE-UNTIL-M1` (Deferred to Milestone M1) |


---

## 6. Key Custody Analysis and External Checkpoint Anchoring (ADR-0002)

### App-Level Compromise & Key Exposure Threat
If an attacker achieves application-level execution or unauthorized memory read inside the container/host:
1. **Exposure:** The adversary can read `AUDIT_SIGNING_SEED` from container environment memory.
2. **Capability:** With the Ed25519 private seed, the attacker can sign fabricated checkpoints matching any sequence of events they desire.
3. **Ledger Tampering Scenario:** If the attacker simultaneously has direct database write access, they can rewrite past audit events from an arbitrary point, recompute the SHA-256 event hash chain, and issue a mathematically valid Ed25519 checkpoint over the forged history.
4. **Impact on the Bank:** Local offline verification (`tools/verify-audit`) using the known public key would report "Valid", masking an incident deletion, clock manipulation, or unauthorized approval.

### Remediation & Defense-in-Depth Architecture
To mitigate this threat, CYBERQ implements:
1. **KeyProvider Protocol Abstraction (ADR-0002):**
   `AuditService` decouples checkpoint signing from raw secret keys via `KeyProvider`. In enterprise bank production, `PKCS11KeyProvider` offloads signing to a Hardware Security Module (HSM) or dedicated KMS where the private key never enters application memory.
2. **External Immutability & Anchoring (WORM / SIEM / Syslog):**
   Checkpoints cannot be secured exclusively within the local database. Immediately upon creation, each checkpoint is streamed outbound over TLS syslog to the bank's central WORM (Write-Once-Read-Many) storage or SIEM.
3. **Fork Detection:**
   Even if an attacker compromises the runtime seed and rewrites local database history, any checkpoint presented to regulators will contradict the timestamped root hash recorded on the bank's external immutable SIEM, proving tampering.

### Residual Risk Status
- **Classification:** RESIDUAL RISK (High technical severity, mitigated to Low in production via HSM + SIEM anchoring).
- **Status:** Marked as **RESIDUAL RISK** in `REDTEAM_STATE.md` until external SIEM/WORM checkpoint streaming is fully integrated and tested in Milestones M1/M2.

