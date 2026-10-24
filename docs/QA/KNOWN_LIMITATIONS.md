# CYBERQ Known Limitations & Planned Capabilities

This document records architectural boundaries, intentional non-goals, and deferred milestones (P2/P3 items) for CYBERQ as of the pre-presentation freeze. Evaluators and auditors can verify these items against the codebase and `AGENTS.md`.

---

## 1. Intentional Architectural Non-Goals & Invariants

These behaviors are permanent architectural boundaries, not missing features:

1. **Zero Automated Regulatory Submissions**:
   - CYBERQ will **never** automatically submit reports or notices directly to external regulatory portals (CERT-In, RBI DAKSH, DPDP).
   - Invariant: A human compliance officer or incident commander must file the packet directly on the regulator's portal and record the official statutory acknowledgement reference ID.
2. **Zero Ingestion of Raw SIEM Logs or Customer PII**:
   - CYBERQ is an incident-to-board governance layer, not a SIEM or data lake.
   - All incident intake fields pass through the PII Guard before persistence, rejecting or masking PAN, Aadhaar, and credit card numbers.
3. **Air-Gapped Operation**:
   - Zero runtime network egress to external CDNs, SaaS, analytics, or LLM APIs.
   - All fonts (IBM Plex) and dependencies are strictly self-hosted within the repo bundle.
4. **Strict Separation of Duties**:
   - The `Admin` role oversees system configuration, health telemetry, and obligation pack verification, but has zero visibility into incident narratives and zero authority to approve filings.
   - The `Auditor` role possesses read-only access to immutable cryptographic audit chains (`/activity`) and cannot create or modify incidents.

---

## 2. Deferred Capabilities by Milestone (Honest Roadmap)

The UI explicitly denotes upcoming modules with honest "Planned" badges rather than presenting mock or simulated operational controls:

### M3: Statutory Filing Packets & Dual-Control Maker-Checker (Planned)
- **Status**: Route `/filings` renders architectural specification and packet templates.
- **Scope**:
  - Generation of deterministic filing bundles for CERT-In (Annexure-I format), RBI DAKSH reporting template, and DPDP Section 8/9 notices.
  - Dual-control maker-checker workflow: SOC Analyst prepares the packet, Compliance Officer / Commander signs and records acknowledgement ID.
  - Cryptographic packet hashing before and after regulator submission.

### M4: Auditable Decision Ledger & Quarterly Board Pack (Planned)
- **Status**: Route `/decisions` renders specification for M4 decision records.
- **Scope**:
  - Cryptographically chained CISO override and dispute resolution log.
  - Automated quarterly Board pack compilation in ReportLab PDF format.
  - Executive KPI rollups: statutory compliance percentage, mean time to acknowledge (MTTA), and statutory clock margins.

### M5: Scenario Exposure Engine & Model Risk Validation (Planned)
- **Scope**:
  - Rupee exposure modeling using NumPy and SciPy for scenario-level financial planning.
  - Tail-risk distribution modeling (Value-at-Risk / Expected Shortfall).
  - Dedicated `Model Validator` read-only interface for examining simulation assumptions and parameters.

### M6: Optimization Engine & Break-Glass Authentication (Planned)
- **Scope**:
  - Resource and mitigation optimizer built on PuLP with CBC solver.
  - Break-glass emergency access backed by Argon2id password hashing and PyOTP time-based one-time password (TOTP) verification.

---

## 3. Environment & Runtime Limitations

1. **PostgreSQL 16 Hardware Leases (M1 Status)**:
   - Status remains **`BUILT (AWAITING POSTGRESQL 16 GATE)`**.
   - 101 backend unit and integration tests pass with 92% coverage using SQLite in-memory for immediate developer velocity.
   - 4 concurrency-critical tests (`SELECT ... FOR UPDATE SKIP LOCKED`, DB-level immutability triggers, cross-process concurrent audit appends, and concurrent incident creation) are wired to skip cleanly unless `CYBERQ_TEST_PG_URL` is set to an active PostgreSQL 16 container.
2. **In-Memory Rate Limiting (SEC-19 through SEC-22)**:
   - The current rate limiter runs in-process. Under multi-worker deployments behind reverse proxies, quota distribution will transition to PostgreSQL row leases in M2/M3.
3. **NTP Skew Tolerance**:
   - The backend `/readyz` endpoint validates server clock skew against the local hardware reference. Clock drift exceeding 1.0 second immediately transitions the service to 503 Service Unavailable to preserve statutory clock integrity.
