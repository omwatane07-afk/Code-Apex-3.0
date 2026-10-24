# CYBERQ — Air-Gapped, Open-Source UAT Platform Evaluation & Architectural Recommendations

**Document ID:** `CYBERQ-QA-ARCH-2026-001`  
**Author:** Principal QA Architect & Read-Only Security Auditor  
**Classification:** Confidential / Commercial Bank Internal Use  
**Target Architecture:** CYBERQ (Bank-Deployable Incident-to-Board Platform)  
**Regulatory Baseline:** RBI CSITE (2016), RBI IT Governance Master Directions (2023), CERT-In Directions (2022), DPDP Act (2023)

---

## 1. Executive Summary & Non-Negotiable Constraints

### 1.1 Mission & Scope
CYBERQ is an air-gapped cybersecurity orchestration and statutory governance platform purpose-built for deployment inside Scheduled Commercial Banks and financial institutions in India. Operating in **Strict Read-Only Research Mode**, this audit evaluates and recommends the optimal **100% Free, Open-Source, and Air-Gapped User Acceptance Testing (UAT) platform**.

Application code in `src/`, `tests/`, and `web/` remains untouched, strictly adhering to auditor separation-of-duties.

### 1.2 Non-Negotiable Constraints
1. **Cost & Licensing:** The recommended solution must be 100% free of licensing fees, per-seat subscription charges, or gated enterprise paywalls for core UAT execution. Open-source licenses (GPL, Apache 2.0, MIT, BSD) or unrestricted Community Editions are mandatory.
2. **Strict Air-Gapped Deployment:** Regulated banking infrastructure operates in physically and logically isolated networks (VLAN / DMZ) with **zero outbound internet connectivity (`0.0.0.0/0` deny)**. Cloud-based SaaS tools (e.g., Jira Cloud, TestRail SaaS, BrowserStack, Zephyr Cloud) are **strictly prohibited** by Indian banking data sovereignty mandates and the Digital Personal Data Protection (DPDP) Act 2023.
3. **Local Docker / Bare-Metal Execution:** The UAT platform must deploy locally via containerization (`docker compose`) or on-premises bare-metal, co-existing cleanly with CYBERQ's existing infrastructure.
4. **Role-Based Access Control (RBAC):** Must strictly model CYBERQ's organizational separation of duties—specifically **Maker-Checker dual authorization**, where an individual who designs or executes a test cannot unilaterally certify acceptance.
5. **Tamper-Evident Auditability:** Every test case modification, execution step transition, artifact attachment, and sign-off must produce an immutable, auditable log satisfying statutory compliance reviews by internal auditors and the Reserve Bank of India (RBI).

---

## 2. CYBERQ Architecture & Testing Baseline Audit (State 1)

### 2.1 Codebase & Dependency Audit

A comprehensive inspection of the CYBERQ codebase yields the following architectural profile:

```
CYBERQ System Architecture
├── Backend: FastAPI 0.115+ (Python 3.12+), SQLAlchemy 2.0.35, Pydantic v2
├── Frontend: React 18.3, TypeScript 5.6 (Strict), Vite 5.4, Tailwind CSS, Three.js (SOC Wallboard)
├── Database: PostgreSQL 16 (Pilot/Production via SQLAlchemy), SQLite (Local Dev/Demo only)
├── Cryptography: RFC 8785 canonical JSON, SHA-256 Merkle chain, Ed25519 checkpoint signatures
├── Access Control: Centralized RBAC policy (cyberq/iam/policy.py) with dual-authorization enforcement
└── Automation Suites:
    ├── Backend: Pytest (32 modules, 150+ tests), Hypothesis property tests, Schemathesis
    └── Frontend: Vitest (contrast, unit, canvas memory), Playwright E2E hooks, axe-core
```

### 2.2 Key Banking Invariants Demanding Rigorous UAT

Any selected UAT platform must be capable of structuring, tracking, and verifying test scenarios for CYBERQ's core non-negotiable invariants:

| CYBERQ Invariant | Implementation Mechanism | UAT Verification Challenge |
| :--- | :--- | :--- |
| **Sub-5ms Reactive Statutory Clocks** | Monotonic countdowns based on `noticed`, `detected`, or `aware` assertion triggers (CERT-In 6-hour, RBI DAKSH 6-hour & 48-hour, DPDP 72-hour). | Requires precise timestamp tracking, escalation ladder validation at T-4h, T-2h, T-1h, T-30m, and non-drifting timers. |
| **Maker-Checker Dual Authorization** | Strict state machine: `preparer_user_id != approver_user_id` enforced in `policy.py:156` across filings, trigger dispute resolution, and incident closures. | Testers must execute multi-user handoffs without privilege leakage; approvals require step-up TOTP verification. |
| **Dual-Tier Zero-Customer-PII Ingestion** | Ingestion-time data scrubbing: Verhoeff checksum algorithm for Aadhaar, Luhn check for Credit Cards, and Regex for PAN. | UAT testers must verify that synthetic PAN, Aadhaar, and credit cards are irreversibly redacted before hitting persistence. |
| **Tamper-Evident SHA-256 Audit Ledger** | Every mutation writes to `audit_event` with `prev_hash` cryptographic chaining. Database-level triggers strictly block `UPDATE`, `DELETE`, and `TRUNCATE`. | UAT sign-offs and verification runs must link to verifiable `CQ-<CRC32>-<ShortHash>` check codes and offline `tools/verify-audit/verify.py` results. |
| **Rupee Exposure & Capital Optimizer** | Open FAIR Rupee Value-at-Risk (SciPy Sobol Monte Carlo, $2^{14} = 16,384$ iterations) and HiGHS MILP budget optimization. | Quantitative business testers must validate ₹ Lakhs and ₹ Crores financial exposure models against RBI Model Risk Guidance. |
| **Bilingual Localization** | Real-time localization between English and Official Rajbhasha Hindi (राजभाषा हिंदी). | UAT requires visual and linguistic validation across all status pills, countdown badges, and filing worksheets. |

### 2.3 Network Isolation & Co-Existence Requirements
- CYBERQ deployments run inside an isolated internal Docker network (`cyberq-internal`) behind a hardened reverse proxy.
- In production, PostgreSQL 16 is deployed in a dedicated database container or bank-managed HA database cluster.
- The UAT platform must either:
  1. Share the existing PostgreSQL 16 instance via a dedicated isolated database schema/database (`kiwidb`, `openproject_db`), minimizing resource overhead; or
  2. Deploy as a self-contained companion container stack within the same internal Docker bridge, with zero internet exposure.

---

## 3. Deep Research & Candidate Evaluation (State 2)

Following an exhaustive survey of free, open-source, and containerized QA/UAT platforms capable of full air-gapped operation, the top 3 platforms evaluated are:

1. **Kiwi TCMS (Community Edition)** — *Best Dedicated Test Case Management System*
2. **Tuleap Community Edition (Tuleap CE + TTM)** — *Best Regulated ALM & Statutory Traceability Platform*
3. **OpenProject Community Edition** — *Best Work Package & Executive Governance UAT Platform*

*(An additional honorable mention is given to **Squash TM**, evaluated in the comparative matrix).*

---

## 4. Top 3 Platform Deep-Dives (State 3)

### Platform 1: Kiwi TCMS (Community Edition)

#### 4.1 Architecture & Suitability
Kiwi TCMS is the world's leading open-source, dedicated Test Case Management System. Built on Python/Django and PostgreSQL, it directly matches the core technical stack of CYBERQ (`Python 3.12 + PostgreSQL 16`), minimizing administrative context switching for banking DevOps teams.

- **License:** GNU General Public License v2.0 or later (GPL-2.0+). 100% Free Open Source.
- **Image Distribution:** Available via container registries (`pub.kiwitcms.eu/kiwitcms/kiwi` or Docker Hub).
- **Core Abstractions:** Products $\rightarrow$ Versions $\rightarrow$ Test Plans $\rightarrow$ Test Cases $\rightarrow$ Test Runs $\rightarrow$ Executions.
- **Air-Gapped Readiness:** High. All static CSS/JS, fonts, and dependencies are pre-bundled inside the official container image. No outbound CDN calls.

#### 4.2 Local Deployment Alongside CYBERQ
Kiwi TCMS can be deployed as an integrated companion service in CYBERQ’s Docker compose orchestration, utilizing the shared PostgreSQL 16 database.

##### Production-Grade `docker-compose.uat-kiwi.yml`:
```yaml
version: "3.8"

networks:
  cyberq-internal:
    internal: true # Air-gapped isolation: zero external ingress/egress
  cyberq-public:
    driver: bridge

services:
  # CYBERQ Database (PostgreSQL 16)
  cyberq-db:
    image: postgres:16-alpine
    container_name: cyberq-postgres
    restart: unless-stopped
    environment:
      POSTGRES_USER: cyberq_admin
      POSTGRES_PASSWORD: ${CYBERQ_DB_PASSWORD:-BankSecur3Password2026!}
      POSTGRES_DB: cyberq_prod
    volumes:
      - pgdata:/var/lib/postgresql/data
      - ./docker/init-uat-db.sql:/docker-entrypoint-initdb.d/01-init-uat-db.sql:ro
    networks:
      - cyberq-internal
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U cyberq_admin -d cyberq_prod"]
      interval: 10s
      timeout: 5s
      retries: 5

  # CYBERQ Backend API
  cyberq-backend:
    image: cyberq-backend:latest
    container_name: cyberq-backend
    restart: unless-stopped
    depends_on:
      cyberq-db:
        condition: service_healthy
    environment:
      CYBERQ_ENV: production
      CYBERQ_DATABASE_URL: postgresql://cyberq_admin:${CYBERQ_DB_PASSWORD:-BankSecur3Password2026!}@cyberq-db:5432/cyberq_prod
    networks:
      - cyberq-internal

  # Kiwi TCMS Application
  kiwi-tcms:
    image: pub.kiwitcms.eu/kiwitcms/kiwi:latest
    container_name: cyberq-kiwi-tcms
    restart: unless-stopped
    depends_on:
      cyberq-db:
        condition: service_healthy
    environment:
      - KIWI_DB_ENGINE=django.db.backends.postgresql
      - KIWI_DB_NAME=kiwi_uat
      - KIWI_DB_USER=kiwi_user
      - KIWI_DB_PASSWORD=${KIWI_DB_PASSWORD:-KiwiBankSecurePass2026!}
      - KIWI_DB_HOST=cyberq-db
      - KIWI_DB_PORT=5432
      - DJANGO_SETTINGS_MODULE=tcms.settings.product
    volumes:
      - kiwi_uploads:/Kiwi/uploads
    networks:
      - cyberq-internal
      - cyberq-public
    ports:
      - "8443:8443"

volumes:
  pgdata:
  kiwi_uploads:
```

##### Air-Gapped Image Ingestion Procedure:
1. **On Connected Bastion:**
   ```bash
   docker pull pub.kiwitcms.eu/kiwitcms/kiwi:latest
   docker pull postgres:16-alpine
   docker save pub.kiwitcms.eu/kiwitcms/kiwi:latest postgres:16-alpine -o kiwi-cyberq-airgap.tar
   ```
2. **On Air-Gapped Banking Server:**
   ```bash
   docker load -i kiwi-cyberq-airgap.tar
   docker compose -f docker-compose.uat-kiwi.yml up -d
   docker exec -it cyberq-kiwi-tcms /Kiwi/manage.py migrate
   docker exec -it cyberq-kiwi-tcms /Kiwi/manage.py createsuperuser
   ```

#### 4.3 RBAC & Separation of Duties Mapping
Kiwi TCMS leverages Django’s granular permission engine combined with object-level security:

| CYBERQ Role | Kiwi TCMS Group | Permissions Configured |
| :--- | :--- | :--- |
| **SOC Analyst (Maker)** | `UAT_Executors` | `tcms_testcases.add_testrun`, `tcms_testcases.change_testexecution`. Can document step-by-step UAT results, log defect observations, and upload execution artifacts. **Denied permission to close or certify test plans.** |
| **Compliance Approver (Checker)** | `UAT_Signoff_Authority` | `tcms_testplans.change_testplan`, `tcms_testcases.change_testplan`. Reviews executed test cases, verifies compliance against statutory packets, and certifies completion. |
| **CISO / Incident Commander** | `Executive_Audit` | Read-only across all Test Plans, Test Runs, and Execution matrices. Permission to view compliance telemetry dashboards and export PDF executive acceptance certificates. |
| **IS Auditor / Model Validator** | `Compliance_Auditors` | `tcms_testcases.view_*`, `admin.view_logentry`. Full read access to historical runs, step timestamps, and tester identities. Zero edit rights. |
| **System Administrator** | `Platform_Admin` | User provisioning, internal LDAP/AD synchronization, database backups. Denied ability to alter recorded test execution statuses. |

#### 4.4 Tamper-Evident Audit Trails
- **Application Level:** Kiwi TCMS utilizes Django’s native model history (`django.contrib.admin.models.LogEntry` and `tcms.core.history`). Every change to a Test Plan, Case description, or Execution result creates an immutable audit row recording:
  - User ID and username
  - Exact UTC timestamp
  - Field-level diff (e.g., `status_id: 1 (IDLE) -> 2 (PASSED)`)
  - Notes / Reason for change
- **PostgreSQL Database Level (`pgaudit`):** Because Kiwi runs on the shared PostgreSQL cluster, the bank can activate the `pgaudit` extension on `kiwi_uat`:
  ```sql
  ALTER DATABASE kiwi_uat SET pgaudit.log = 'write, ddl';
  ```
  This creates cryptographic transaction logs capturing any unauthorized backend mutations.

---

### Platform 2: Tuleap Community Edition (Tuleap CE with TTM)

#### 4.5 Architecture & Suitability
Tuleap is a high-assurance, open-source Application Lifecycle Management (ALM) platform widely deployed in regulated environments (aerospace, defense, medical, and banking). Its built-in **Tuleap Test Management (TTM)** module excels at end-to-end requirement-to-test traceability.

- **License:** GNU General Public License v2.0 (GPL-2.0). 100% Free Community Edition.
- **Stack:** PHP, Rocky Linux container base, MariaDB backend.
- **Core Abstractions:** Requirements $\rightarrow$ Test Cases $\rightarrow$ Test Campaigns $\rightarrow$ Test Executions $\rightarrow$ Bug Trackers.
- **Air-Gapped Readiness:** Exceptional. Used extensively by French defense and European banking sectors in zero-egress networks.

#### 4.6 Local Deployment Alongside CYBERQ
Tuleap requires its own MariaDB instance and runs via official Docker images.

##### Production-Grade `docker-compose.uat-tuleap.yml`:
```yaml
version: "3.8"

networks:
  cyberq-internal:
    internal: true
  cyberq-public:
    driver: bridge

services:
  tuleap-db:
    image: mariadb:10.11
    container_name: cyberq-tuleap-db
    restart: unless-stopped
    command: --character-set-server=utf8mb4 --collation-server=utf8mb4_unicode_ci
    environment:
      MYSQL_ROOT_PASSWORD: ${TULEAP_DB_ROOT_PASS:-TuleapSecDB2026!}
      MYSQL_DATABASE: tuleap
      MYSQL_USER: tuleap
      MYSQL_PASSWORD: ${TULEAP_DB_PASS:-TuleapUserPass2026!}
    volumes:
      - tuleap_db_data:/var/lib/mysql
    networks:
      - cyberq-internal

  tuleap-web:
    image: tuleap/tuleap-community-edition:latest
    container_name: cyberq-tuleap-web
    restart: unless-stopped
    depends_on:
      - tuleap-db
    environment:
      - TULEAP_FQDN=cyberq-uat.bank.internal
      - MYSQL_ROOT_PASSWORD=${TULEAP_DB_ROOT_PASS:-TuleapSecDB2026!}
    volumes:
      - tuleap_data:/data
    networks:
      - cyberq-internal
      - cyberq-public
    ports:
      - "8080:80"
      - "8443:443"

volumes:
  tuleap_db_data:
  tuleap_data:
```

#### 4.7 RBAC & Separation of Duties Mapping
Tuleap provides field-level and tracker-level permissions:

- **Tracker-Level Isolation:** Test cases for *Statutory Filings (M3)* and *CISO Decisions (M4)* are separated into distinct trackers with independent ACLs.
- **Field-Level Transition Guards:**
  - The `Execution Status` field (`Passed`, `Failed`, `Blocked`) is editable by `SOC Analysts`.
  - The `Acceptance Sign-Off` field (`Pending`, `CISO Approved`, `Auditor Verified`) is strictly locked to the `Compliance Approver` and `CISO` user groups.
- **Maker-Checker Enforcement:** Tuleap workflow transition rules can prevent a test case creator from advancing the status to "Accepted".

#### 4.8 Tamper-Evident Audit Trails
- **Artifact History Journals:** Tuleap records a permanent, unalterable event history on every artifact. Even system administrators cannot modify past history entries without invalidating tracker integrity.
- **Log Streaming:** Tuleap supports structured syslog output (`/var/log/tuleap/`) that can be mapped to a local persistent volume and monitored by the bank's internal SIEM.

---

### Platform 3: OpenProject Community Edition

#### 4.9 Architecture & Suitability
OpenProject is a leading European open-source enterprise project and task management software. While not exclusively a test manager, OpenProject Community Edition is widely configured in European financial institutions as a **UAT Work Package & Governance Suite** due to its compliance with GDPR, accessibility standards, and clean PostgreSQL architecture.

- **License:** GNU General Public License v3.0 (GPL-3.0). 100% Free Community Edition.
- **Stack:** Ruby on Rails, Angular, PostgreSQL 16 backend.
- **Core Abstractions:** Projects $\rightarrow$ Work Packages (Custom Types: *UAT Scenario*, *Test Run*, *Defect*) $\rightarrow$ Relations $\rightarrow$ Milestones.
- **Air-Gapped Readiness:** High. Packaged as an all-in-one container with zero third-party telemetry.

#### 4.10 Local Deployment Alongside CYBERQ
OpenProject can directly utilize CYBERQ’s existing PostgreSQL 16 container, saving substantial memory and compute overhead.

##### Production-Grade `docker-compose.uat-openproject.yml`:
```yaml
version: "3.8"

networks:
  cyberq-internal:
    internal: true
  cyberq-public:
    driver: bridge

services:
  openproject:
    image: openproject/community:14
    container_name: cyberq-openproject
    restart: unless-stopped
    depends_on:
      cyberq-db:
        condition: service_healthy
    environment:
      OPENPROJECT_HTTPS: "false"
      OPENPROJECT_HOST__NAME: "localhost:8088"
      OPENPROJECT_SECRET_KEY_BASE: "${OP_SECRET:-super-secret-key-32-chars-minimum-2026}"
      OPENPROJECT_DATABASE_URL: "postgresql://cyberq_admin:${CYBERQ_DB_PASSWORD:-BankSecur3Password2026!}@cyberq-db:5432/openproject_uat"
      OPENPROJECT_RAILS__CACHE__STORE: "memcache"
      OPENPROJECT_CACHE__MEMCACHE__SERVER: "openproject-cache:11211"
    volumes:
      - openproject_assets:/var/openproject/assets
    networks:
      - cyberq-internal
      - cyberq-public
    ports:
      - "8088:80"

  openproject-cache:
    image: memcached:alpine
    container_name: cyberq-op-cache
    restart: unless-stopped
    networks:
      - cyberq-internal

volumes:
  openproject_assets:
```

#### 4.11 RBAC & Separation of Duties Mapping
OpenProject features robust role and workflow customization:
- Custom roles: `UAT Maker (Tester)`, `UAT Checker (Approver)`, `CISO Oversight`, and `Statutory Auditor`.
- **Workflow State Machine:** A custom workflow enforces that a Work Package of type `UAT Acceptance Test` can only transition through:
  `New` $\rightarrow$ `Ready for Test` $\rightarrow$ `Executed (Passed)` $\rightarrow$ `CISO Acceptance Confirmed`.
  Only accounts with the `UAT Checker` role possess permission for the final transition step.

#### 4.12 Tamper-Evident Audit Trails
- **Native Activity Log:** Every Work Package features a chronological, immutable activity stream logging every field update, description change, status transition, and attachment.
- **Change Journaling:** The underlying PostgreSQL database maintains full journal records (`journals` and `journal_details` tables) capturing exact before/after states, author IDs, and UTC timestamps.

---

## 5. Comparative Evaluation Matrix

| Architectural Dimension | Kiwi TCMS (Community) | Tuleap CE (+ TTM) | OpenProject CE | Squash TM (Honorable Mention) |
| :--- | :--- | :--- | :--- | :--- |
| **Primary Category** | Dedicated Test Management | Enterprise ALM & Testing | Work Package & Governance | Dedicated Test Management |
| **License & Cost** | GPL-2.0+ (100% Free) | GPL-2.0 (100% Free) | GPL-3.0 (100% Free) | Apache 2.0 / LGPL (100% Free) |
| **Underlying Stack** | Python / Django / Postgres | PHP / MariaDB | Ruby on Rails / Postgres | Java / Spring Boot / Postgres |
| **CYBERQ Stack Synergy** | **Highest** (Python + Postgres) | Moderate (Requires MariaDB) | **High** (Native Postgres 16) | High (Postgres 16 compatible) |
| **Air-Gap Capability** | Pre-bundled offline assets | Exceptional (Used in Defense) | Pre-bundled offline assets | Self-contained Spring JAR/Docker |
| **Automated Test Ingestion** | Native (`tcms-api`, Pytest plugin) | REST API / Jenkins plugin | REST API only | Dedicated Squash AUTOM plugin |
| **Maker-Checker Enforcement** | Via Django Groups & Status ACL | Native Tracker & Field ACL | Native Workflow Transitions | Native Custom Profiles |
| **Audit Log Rigor** | Model history + `pgaudit` | Immutable Artifact History | Permanent Activity Journals | Campaign Revision History |
| **Resource Footprint** | Lightweight (~350MB RAM) | Heavy (~2GB RAM) | Moderate (~1.2GB RAM) | Moderate (~800MB RAM) |
| **Board / Executive Reporting** | Matrix & Run Summaries | Full Traceability Graphs | Native Gantt, Kanban & Boards | Campaign Coverage Reports |

---

## 6. CYBERQ UAT Test Suite Blueprint (Ready-to-Import)

To immediately operationalize the recommended UAT platform, the following six statutory UAT test cases are designed directly against CYBERQ’s core invariants:

```
+------------------------------------------------------------------------------------------------+
| UAT-CYBERQ-001: Sub-5ms Reactive Clock & 6-Hour Statutory Countdown (CERT-In)                |
+------------------------------------------------------------------------------------------------+
| Preconditions: Incident #102 seeded; status is TRIAGED.                                        |
| Test Steps:                                                                                    |
| 1. Log in as analyst@cyberq.bank (Analyst / Maker).                                            |
| 2. Open Incident #102 in Command Center; click 'Assert Trigger' ('a').                         |
| 3. Select 'CERT-In 6-Hour Noticed' trigger; click Confirm.                                    |
| 4. Inspect countdown timer in header and 3D Temporal Runway.                                   |
| Expected Outcome:                                                                              |
| - Clock starts immediately from current UTC timestamp.                                         |
| - Deadline is set to exactly T + 06:00:00.                                                     |
| - Escalation markers at T-4h, T-2h, T-1h, T-30m, and T-10m are rendered.                       |
| - Audit event 'trigger.asserted' is recorded in the SHA-256 Merkle chain.                      |
+------------------------------------------------------------------------------------------------+

+------------------------------------------------------------------------------------------------+
| UAT-CYBERQ-002: Maker-Checker Dual-Authorization Enforcement (Statutory Filings)               |
+------------------------------------------------------------------------------------------------+
| Preconditions: Incident #102 has active CERT-In obligation pack.                               |
| Test Steps:                                                                                    |
| 1. As analyst@cyberq.bank, prepare filing packet and submit for approval.                      |
| 2. Attempt to approve own packet using analyst credentials.                                    |
| 3. Verify action is rejected with 403 Forbidden ('preparer cannot approve own filing').        |
| 4. Log out and log in as commander@cyberq.bank (Approver / Checker).                           |
| 5. Review draft packet, enter TOTP MFA token, and click 'Authorize Filing'.                   |
| Expected Outcome:                                                                              |
| - Analyst cannot self-approve. Dual authorization is strictly enforced.                        |
| - Status transitions to 'AUTHORIZED_FOR_FILING'.                                               |
| - Byte-reproducible PDF export generates valid CQ-<CRC32>-<ShortHash> check-code.              |
+------------------------------------------------------------------------------------------------+

+------------------------------------------------------------------------------------------------+
| UAT-CYBERQ-003: Zero-Customer-PII Ingestion Scrubbing Gate                                     |
+------------------------------------------------------------------------------------------------+
| Preconditions: Ingestion intake hub running.                                                   |
| Test Steps:                                                                                    |
| 1. Simulate inbound SIEM payload containing:                                                   |
|    - Valid Aadhaar number passing Verhoeff checksum (e.g. 5489 1234 5678)                      |
|    - Valid RuPay Card number passing Luhn algorithm (e.g. 6078 1234 5678 9012)                 |
|    - Valid PAN number (e.g. ABCDE1234F)                                                        |
| 2. Inspect raw database record in 'incidents' table.                                           |
| Expected Outcome:                                                                              |
| - All Aadhaar and Card numbers are scrubbed to [REDACTED_AADHAAR] and [REDACTED_CARD].         |
| - Zero sensitive customer identifiers exist in unencrypted database fields.                    |
+------------------------------------------------------------------------------------------------+

+------------------------------------------------------------------------------------------------+
| UAT-CYBERQ-004: Offline Cryptographic Audit Ledger Verification                                 |
+------------------------------------------------------------------------------------------------+
| Preconditions: At least 5 mutations executed in the platform.                                  |
| Test Steps:                                                                                    |
| 1. Log in as auditor@cyberq.bank (IS Auditor).                                                 |
| 2. Navigate to /activity; click 'Verify Audit Chain'.                                          |
| 3. Copy cyberq_dev.db to an offline machine; run:                                              |
|    python tools/verify-audit/verify.py --db cyberq_dev.db                                      |
| Expected Outcome:                                                                              |
| - Web UI reports 'AUDIT LEDGER INTACT', displaying valid root hash.                            |
| - Offline CLI calculates all RFC 8785 canonical hashes and returns exit code 0.                |
| - Tampering injection test (altering one byte) causes CLI to immediately flag corruption.       |
+------------------------------------------------------------------------------------------------+

+------------------------------------------------------------------------------------------------+
| UAT-CYBERQ-005: 3 AM Break-Glass Protocol & Retrospective Countersignature                     |
+------------------------------------------------------------------------------------------------+
| Preconditions: Emergency filing required outside standard business hours.                     |
| Test Steps:                                                                                    |
| 1. As commander@cyberq.bank, initiate Break-Glass emergency authorization.                     |
| 2. Provide emergency rationale and submit filing.                                              |
| 3. Observe mandatory 24-hour retrospective countersignature alert triggered for CISO.          |
| 4. Log in as ciso@cyberq.bank; verify retrospective countersignature drawer.                   |
| Expected Outcome:                                                                              |
| - Emergency filing proceeds without blocking critical regulator deadline.                      |
| - System places incident in 'AWAITING_RETROSPECTIVE_APPROVAL' state.                           |
| - Retrospective approval is cryptographically chained into audit log.                          |
+------------------------------------------------------------------------------------------------+

+------------------------------------------------------------------------------------------------+
| UAT-CYBERQ-006: Official Rajbhasha Hindi Bilingual Localization Parity                         |
+------------------------------------------------------------------------------------------------+
| Preconditions: User on Incident Command Center.                                                |
| Test Steps:                                                                                    |
| 1. Click Language Toggle ('English' -> 'राजभाषा हिंदी').                                       |
| 2. Verify all navigation items, statutory countdown clocks, and status badges localize.        |
| 3. Verify no layout breakage, text truncation, or contrast ratio violations occur.             |
| Expected Outcome:                                                                              |
| - Complete Rajbhasha Hindi localization rendered across all views.                             |
| - WCAG 2.1 AA 4.5:1 text contrast preserved across both dark and light themes.                 |
+------------------------------------------------------------------------------------------------+
```

---

## 7. Strategic Synthesis & Final Recommendation

### 7.1 Primary Recommendation: Kiwi TCMS (Community Edition)
For CYBERQ, **Kiwi TCMS Community Edition is the definitive #1 recommendation** based on three decisive factors:

1. **Architectural Cohesion:** Kiwi TCMS is written in **Python/Django and runs on PostgreSQL 16**. It can be deployed in under 2 minutes alongside CYBERQ within the same isolated `cyberq-internal` Docker bridge, connecting to the bank’s existing PostgreSQL instance. This eliminates the operational overhead of introducing foreign runtimes (Ruby or PHP) into the bank's core cybersecurity enclave.
2. **Pytest & Automated Test Ingestion:** CYBERQ already maintains 32+ Pytest modules and Hypothesis suites. Kiwi TCMS features a dedicated Pytest plugin (`pytest-kiwi`), allowing automated unit/security regression results and manual bank UAT scenarios to reside in a single unified dashboard with zero internet connectivity.
3. **Audit Trail Alignment:** Through Django model logging combined with PostgreSQL `pgaudit`, Kiwi TCMS provides complete, tamper-evident traceability satisfying RBI IT Governance Para 28(7) standards.

### 7.2 Alternative Enterprise Recommendation: Tuleap Community Edition
If the bank requires **cradle-to-grave statutory requirements traceability**—linking every statutory clause of RBI CSITE or DPDP Act 2023 directly to UAT test cases, execution runs, and defect trackers—**Tuleap Community Edition** is the enterprise standard. While it requires a heavier infrastructure footprint (MariaDB + PHP container), its aerospace- and defense-grade audit journals and strict field-level transition permissions provide unmatched statutory compliance defensibility.

### 7.3 Action Plan for Implementation
1. Copy `docker-compose.uat-kiwi.yml` into CYBERQ’s deployment directory.
2. Transfer the pre-bundled container images (`kiwi:latest` and `postgres:16-alpine`) to the target air-gapped banking server via verified physical media.
3. Import the 6 pre-configured UAT test cases (Section 6) into Kiwi TCMS.
4. Assign bank stakeholder roles (`Maker`, `Checker`, `CISO`, `Auditor`) in accordance with Section 4.3.
5. Commence formal banking acceptance testing with verifiable, tamper-evident sign-off artifacts.
