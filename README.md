# CYBERQ — Bank-Deployable Incident-to-Board Platform

[![Python](https://img.shields.io/badge/Python-3.12%2B-blue.svg)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115%2B-009688.svg)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18-61DAFB.svg)](https://react.dev)
[![TypeScript](https://img.shields.io/badge/TypeScript-Strict-3178C6.svg)](https://www.typescriptlang.org)
[![Compliance](https://img.shields.io/badge/Compliance-RBI%20CSITE%20%7C%20CERT--In%20%7C%20DPDP-darkgreen.svg)](#statutory-regulatory-scope)
[![Air-Gapped](https://img.shields.io/badge/Security-Air--Gapped%20%7C%20Zero--PII-red.svg)](#security--architectural-invariants)

> **CYBERQ** is an enterprise-grade, air-gapped cybersecurity orchestration and statutory governance platform purpose-built for deployment inside **Indian Commercial Banks**. It bridges the operational divide between SOC incident triage, mandatory regulatory reporting, and executive Board-level risk exposure.

---

## 1. The Core Idea: "Incident-to-Board"

When a cyber incident strikes an Indian commercial bank, teams face a high-stress dilemma:
1. **Clock Pressure:** Strict statutory deadlines (CERT-In 6-hour, RBI DAKSH 6-hour, DPDP 72-hour) demand rapid disclosure under legal penalty.
2. **Operational Chaos:** SOC analysts are overwhelmed triaging technical alerts, while compliance officers scramble to draft regulatory packets across disconnected portals.
3. **Executive & Board Disconnect:** Executive leadership and the Board of Directors lack visibility into rupee-denominated financial risk exposure and on-time regulatory compliance metrics.

### The CYBERQ Solution
CYBERQ deterministically transforms a single technical security incident into:
- **Correctly Timed, Human-Approved Filing Packets:** Standardized, versioned packets for **CERT-In**, **RBI (DAKSH)**, and **DPDP (DPBI)** with sub-5ms reactive statutory clocks and maker-checker dual authorization.
- **Cryptographic Audit Ledger & Board Governance:** Tamper-evident SHA-256 Merkle chain recording every triage decision, paired with automated **RBI Para 28(7) Quarterly Board Risk Packs**, quantitative **Rupee Value-at-Risk (VaR)** Monte Carlo simulations, and a **Mixed-Integer Linear Programming (MILP) Capital Optimizer**.

---

## 2. Key Features & Capabilities

### 🛡️ Enterprise Intake Hub & Safe Harbor
- **20+ Pre-Configured Enterprise Adapters:** Native support for Splunk, Microsoft Sentinel, IBM QRadar, CrowdStrike Falcon, Palo Alto Networks, Cisco Secure, F5 WAF, Imperva, and RFC 5424 / CEF Syslog.
- **HMAC-SHA256 & Webhook Idempotency:** Cryptographically verifies tool authenticity with a write-ahead dead-letter queue (`intake_dead_letter`) to prevent data loss.
- **MSSP Provisional Triage Safe Harbor:** Dedicated 30-minute grace window for managed security service providers to triage alerts before statutory clocks lock.
- **Tool Compliance Passports:** Tracks 22+ security tool integrations against **RBI Master Directions Para 59**, monitoring tool health, certificate expirations, and degraded states.

### ⏱️ Sub-5ms Reactive Statutory Clocks
- **Monotonic Statutory Countdown:** Clocks track incident assertion triggers (`noticed`, `detected`, `aware`) against statutory deadlines:
  - **CERT-In Directions 2022:** 6-hour mandatory initial filing.
  - **RBI CSITE / DAKSH Portal:** 6-hour preliminary notification; 48-hour comprehensive assessment.
  - **DPDP Act 2023:** 72-hour Data Protection Board of India (DPBI) and affected principal notification.
- **Escalation Ladder:** Proactive alert alerts at T-4h, T-2h, T-1h, T-30m, T-10m, and Breach via in-app alerts, enterprise webhooks, and SMTP.
- **3D Temporal Runway:** Interactive visual corridor and ambient SOC Wallboard (`/wall`) for crisis situation rooms.

### 📝 Maker-Checker Statutory Filing Engine
- **Dual-Authorization State Machine:** Strict maker-checker enforcement guarantees that no individual (including administrators) can both prepare and approve a filing packet.
- **Step-Up TOTP Multi-Factor Authentication:** Re-authenticates commanders before authorizing irreversible regulatory filing submissions.
- **Break-Glass 3 AM Protocol:** Allows single-operator emergency approval during out-of-hours crises, mandating a 24-hour retrospective countersignature.
- **Byte-Reproducible PDF Export:** Generates exact-match regulatory worksheets with dynamic watermarks and printable verification check-codes (`CQ-<CRC32>-<ShortHash>`).

### 🔒 Dual-Tier Privacy & RBAC Masking
- **Zero-Customer-PII Ingestion:** Real-time scrubbing of Indian sensitive data before persistence:
  - **Aadhaar:** Verhoeff checksum algorithm validation.
  - **Payment Cards:** Luhn checksum algorithm validation (Visa, Mastercard, RuPay, Amex).
  - **Income Tax PAN:** Regex structural pattern matching.
- **Infrastructure RBAC Masking:** Obfuscates internal IP addresses and server hostnames (`[REDACTED_BY_RBAC]`) for Analysts and Auditors; unmasking by the CISO requires audited justification and creates an immutable ledger event.

### 🤖 Multi-Agent Autonomous Review Loop
- **11-Phase Autonomous Investigation:** Coordinates specialized verification routines:
  `Plan` ➔ `Delegate` ➔ `Investigate` ➔ `Submit` ➔ `Team-Lead Review` ➔ `Cross-Examination` ➔ `Disagreement Resolution` ➔ `Revision` ➔ `Regression Check` ➔ `Quality Gate` ➔ `Final Approval`.
- **Deterministic Non-LLM Verification:** Rules, checksums, and regulatory invariants are evaluated deterministically without reliance on non-deterministic external LLMs.

### 📊 Rupee Exposure Engine & Capital Optimizer
- **Open FAIR Rupee Value-at-Risk (VaR):** SciPy Sobol Quasi-Monte Carlo ($2^{14} = 16,384$ iterations) with modified PERT distribution sampling, reporting expected loss and P10/P50/P90/P99 exposures in **₹ Lakhs and ₹ Crores**.
- **Model Risk Management (MRM) Compliance:** Manifest adhering to RBI draft Model Risk Guidance (inventory entry, sensitivity testing, Kolmogorov-Smirnov convergence validation).
- **MILP Capital Allocation Optimizer:** Solves cyber control budget allocation using SciPy's HiGHS solver, computing 10-point Pareto-optimal frontiers under prerequisite and mutual exclusivity constraints.

### 🏛️ Board Pack & Bilingual Localization
- **RBI Para 28(7) Quarterly Board Pack:** Automated generation of board-level governance dossiers tracking filing compliance rates, mean-time-to-classify, open risk decisions, and top threat vectors.
- **Official Bilingual UI:** Real-time toggling between **English** and **Official Rajbhasha Hindi** (राजभाषा हिंदी) across all navigation items, status pills, and audit descriptors.

---

## 3. Security & Architectural Invariants

| Invariant | Implementation Details |
| :--- | :--- |
| **Strictly Air-Gapped** | Zero runtime calls to external CDNs, Google Fonts, SaaS services, analytics, or cloud APIs. Self-contained IBM Plex fonts and offline assets. |
| **Tamper-Evident Ledger** | Every mutation creates an `audit_events` row linked via SHA-256 hash chains (`prev_hash`). Verified offline using `tools/verify-audit/verify.py`. |
| **Human-in-the-Loop** | Packets are never auto-dispatched to government portals. Authorized officers manually file on the regulator's portal and record official acknowledgement IDs. |
| **Fail-Closed Security** | If the clock source, database, or policy engine degrades, the platform defaults to Deny and displays clear manual emergency fallback procedures. |
| **Statutory IST Clocks** | Timestamps stored in UTC; displayed in Indian Standard Time (IST, UTC+05:30) with UTC hover tooltips. Skew alerts trigger if NTP drifts > 1 second. |

---

## 4. Repository Layout

```
Code-Apex-3.0-main/
├── backend/                        # FastAPI Enterprise Modular Monolith
│   ├── src/cyberq/
│   │   ├── api/                    # REST routes, auth, middleware, dependencies
│   │   ├── audit/                  # SHA-256 Merkle chain, checkpoints, verifier
│   │   ├── clocks/                 # Sub-5ms reactive statutory clocks & timers
│   │   ├── core/                   # Config, database, PII Guard, demo seeder
│   │   ├── exposure/               # Open FAIR Rupee Monte Carlo & MILP optimizer
│   │   ├── filings/                # CERT-In, RBI, DPDP packet generators & PDF
│   │   ├── governance/             # CISO Decision Register, Board Pack generator
│   │   ├── iam/                    # RBAC policy engine & session management
│   │   ├── incidents/              # Incident state machine & trigger assertions
│   │   └── intake/                 # 20+ tool parsers, CEF syslog, dead-letter queue
│   ├── tests/                      # Pytest suite, Hypothesis property tests, security audit
│   └── start_backend.bat           # Dedicated backend launcher
├── web/                            # React 18 + TypeScript Strict Frontend
│   ├── src/
│   │   ├── app/                    # Router, navigation shell, providers
│   │   ├── components/             # Reusable Radix UI & design system primitives
│   │   ├── features/               # Incidents, Clocks, Wallboard, Filings, Decisions
│   │   └── i18n/                   # English & Rajbhasha Hindi localization
│   ├── tests/                      # Vitest unit, contrast, and invariant tests
│   └── start_frontend.bat          # Dedicated frontend launcher
├── packs/obligations/              # Versioned statutory packs (CERT-In, RBI, DPDP)
├── tools/
│   ├── init_demo_db.py             # Database initialization and crisis demo seeder
│   ├── simulator/                  # SIEM / EDR webhook attack traffic simulator
│   └── verify-audit/               # Offline cryptographic audit verifier CLI
├── start.bat                       # Master 1-Click Platform Launcher (Windows)
├── run.bat                         # Quick launcher delegator
└── run.py                          # Cross-platform Python launcher
```

---

## 5. Quickstart & How to Run

### System Prerequisites
- **Operating System:** Windows 10/11, Windows Server 2019+, or Linux.
- **Python:** Version 3.12 or higher ([python.org](https://python.org)).
- **Node.js:** Version 18.x or 20.x LTS ([nodejs.org](https://nodejs.org)).

---

### Method 1: Master 1-Click Launcher (Windows Recommended)
Simply double-click:
```cmd
start.bat
```
*(or run `start.bat` from Command Prompt)*

**What `start.bat` handles automatically:**
1. Verifies Python 3.12+ and Node.js environments.
2. Checks and installs missing Python packages (`pip install -r requirements.txt`).
3. Checks and builds frontend dependencies (`npm install`).
4. Initializes the local SQLite demo database and seeds 22 Tool Passports and 3 active banking crisis incidents.
5. Launches the FastAPI backend (`http://127.0.0.1:8000`) in its own dedicated terminal.
6. Launches the Vite frontend dev server (`http://localhost:5173`) in its own dedicated terminal.
7. Opens your default web browser directly into the Incident Command Center.
8. Writes all diagnostic output to `logs/startup.log`.

---

### Method 2: Manual / Modular Launch

#### Step 1: Initialize Database & Seed Crisis Data
```cmd
python tools/init_demo_db.py
```

#### Step 2: Start the Backend Service
```cmd
backend\start_backend.bat
```
*Or via CLI:*
```bash
cd backend
set PYTHONPATH=src;..
set CYBERQ_ENV=demo
python -m uvicorn cyberq.api.app:app --host 127.0.0.1 --port 8000 --reload
```

#### Step 3: Start the Frontend Service
```cmd
web\start_frontend.bat
```
*Or via CLI:*
```bash
cd web
npm run dev
```

---

## 6. Access Endpoints & Demo Credentials

| Portal / View | Local URL | Description |
| :--- | :--- | :--- |
| **Command Center** | [http://localhost:5173](http://localhost:5173) | Main Incident Command Center & Regulatory Cockpit |
| **SOC Wallboard** | [http://localhost:5173/wall](http://localhost:5173/wall) | Dark-mode ambient 3D runway for SOC crisis displays |
| **Backend API Docs** | [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs) | Interactive OpenAPI / Swagger interface |
| **Health Check** | [http://127.0.0.1:8000/healthz](http://127.0.0.1:8000/healthz) | Liveness & cryptographic clock sync status |

### Pre-Seeded Demo Accounts (Click to Switch in UI)
- **CISO:** `ciso@cyberq.bank` — Executive risk approvals, IP unmasking, Board packs.
- **Incident Commander:** `commander@cyberq.bank` — Filing packet authorization, step-up MFA.
- **SOC Analyst:** `analyst@cyberq.bank` — Incident preparation, trigger assertions, triage.
- **IS Auditor:** `auditor@cyberq.bank` — Read-only cryptographic audit verification.

---

## 7. Verification & Quality Gates

Run the automated verification suite to validate system integrity:

```bash
# 1. Run Python Unit, Security & Hypothesis Property Tests
cd backend
python -m pytest tests/ -v

# 2. Run Strict Type Check
mypy --strict src

# 3. Run Linter & Security Flaw Scans
ruff check src

# 4. Run Frontend Unit & Contrast Tests
cd ../web
npm run test

# 5. Run Strict Frontend Production Bundle Gate
npm run build
```

---

## 8. Offline Cryptographic Audit Verification

To verify the audit log's cryptographic integrity independently on an offline inspection machine:

```bash
python tools/verify-audit/verify.py --db cyberq.db
```

The verifier recalculates the complete SHA-256 Merkle chain, validates RFC 8785 canonical hashes, and flags any modified, inserted, or reordered records.

---

## 9. Statutory Regulatory Scope

This repository encodes and enforces primary source requirements from:
1. **CERT-In Cyber Security Directions (No. 20(3)/2022-CERT-In):** Mandatory 6-hour cybersecurity incident reporting for specified incident categories.
2. **Reserve Bank of India (RBI) Cyber Security Framework for Commercial Banks (DBS.CO/CSITE/BC.11/33.01.001/2015-16):** Baseline cybersecurity controls, incident reporting via DAKSH portal, and technical exception tracking (Para 59).
3. **RBI Master Direction on Information Technology Governance, Risk, Controls and Assurance Practices (2023):** Para 28(7) Board-level reporting and oversight mechanisms.
4. **Digital Personal Data Protection Act (DPDP Act 2023) & Draft Rules:** 72-hour personal data breach notification to the Data Protection Board of India (DPBI) and affected data principals.

---

## 10. License & Deployment Notice

Confidential and proprietary. Built for evaluation, compliance pilot demonstrations, and deployment within scheduled commercial banks and regulated financial institutions.
