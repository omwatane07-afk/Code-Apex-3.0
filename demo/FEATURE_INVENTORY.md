# CYBERQ Feature Inventory & Provenance

This inventory documents all features in the CYBERQ codebase ahead of the live recorded demonstration. In strict compliance with the **Truth Only** ground rule, every feature is classified as **BUILT**, **PARTLY**, or **ROADMAP**, backed by an exact file path proof and instructions on how to trigger it.

---

## 1. Feature Register

| # | Feature Name | Status | Component & File Proof | Trigger Mechanism |
|---|---|---|---|---|
| **1** | **Server-Side Session Authentication** | **BUILT** | `backend/src/cyberq/api/routes_auth.py`<br>`backend/src/cyberq/iam/session.py` | `POST /api/v1/auth/login`. Sets HttpOnly `cyberq_session` cookie; zero tokens in `localStorage`. |
| **2** | **Five Bank Roles & Separation of Duties** | **BUILT** | `backend/src/cyberq/iam/policy.py`<br>`backend/src/cyberq/iam/models.py` | Role-based policy enforcement across all endpoints. Admin denied from approving; Admin & Auditor narratives masked. |
| **3** | **Incident Intake & Lifecycle** | **BUILT** | `backend/src/cyberq/api/routes_incidents.py`<br>`web/src/features/incidents/NewIncidentModal.tsx` | Press `n` or click `+ New incident` in Command Center; submit title, summary, severity. |
| **4** | **Ingestion PII Guard (Aadhaar, PAN, Cards)** | **BUILT** | `backend/src/cyberq/core/pii_guard.py`<br>`backend/tests/test_pii_corpus.py` | Input field pre-filter: Verhoeff algorithm on 12-digit numbers; ignores IPs, UUIDs, timestamps; audited override. |
| **5** | **Simultaneous Dual Triggers (Bank SOP)** | **BUILT** | `backend/src/cyberq/clocks/engine.py`<br>`web/src/features/incidents/AssertTriggerModal.tsx` | Press `a` or click `Assert Trigger`. Simultaneously asserts `noticed` (CERT-In) and `detected` (RBI DAKSH). |
| **6** | **Regulatory Clocks Engine & Worker** | **BUILT** | `backend/src/cyberq/clocks/engine.py`<br>`backend/src/cyberq/clocks/worker.py`<br>`packs/obligations/*.yaml` | Clocks compute monotonically: CERT-In 6h, RBI 6h, DPDP 72h. Worker uses `SELECT ... FOR UPDATE SKIP LOCKED`. |
| **7** | **Precautionary Applicability Maker-Checker** | **BUILT** | `backend/src/cyberq/incidents/service.py`<br>`web/src/features/incidents/AssertTriggerModal.tsx` | In trigger modal, answer "No personal data". Clock keeps running (`exempt_pending_approval`) until Approver signs. |
| **8** | **3D Statutory Depth Runway (Three.js)** | **BUILT** | `web/src/features/corridor/CorridorCanvas.tsx`<br>`web/src/features/corridor/CorridorView.tsx`<br>`web/src/features/corridor/ClockViewModel.ts` | Click `3D Depth runway` tab or toggle `3D corridor`. Camera presets `1: Now`, `2: Overview`, `3: Lane focus`; 2D fallback below 768px. |
| **9** | **Ambient SOC Telemetry Wallboard** | **BUILT** | `web/src/features/wallboard/WallboardView.tsx`<br>`docs/adr/0004-wallboard-dedicated-role-and-endpoint.md` | Navigate to `/wall` or press `g w`. Displays incident numbers and clocks only; zero titles, narratives, or names. |
| **10** | **Cryptographic Audit Chain & Offline Verifier** | **BUILT** | `backend/src/cyberq/audit/chain.py`<br>`web/src/features/activity/ActivityView.tsx`<br>`tools/verify-audit/verify.py` | Navigate to `/activity` or press `g a`; click "Verify audit chain" or run `python tools/verify-audit/verify.py --input <file>`. |
| **11** | **Day Ledger & Night Desk Operational Themes** | **BUILT** | `web/src/styles/tokens.css`<br>`web/src/app/App.tsx`<br>`web/tests/contrast.test.ts` | Click theme sun/moon icon in header. Tested WCAG AA contrast (Light: 13.8:1, Dark: 10.5:1). |
| **12** | **Air-Gapped Security Headers & Defense** | **BUILT** | `backend/src/cyberq/api/middleware.py`<br>`web/tests/security.spec.ts` | Strict CSP (`default-src 'self'`), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, self-hosted IBM Plex fonts. |
| **13** | **Fail-Closed Health & NTP Drift Telemetry** | **BUILT** | `backend/src/cyberq/api/health.py`<br>`web/src/features/admin/AdminView.tsx` | Navigate to `/admin` or press `g m`. Probes `/healthz` and `/readyz`. Returns 503 if NTP clock drift exceeds 1.0s. |
| **14** | **Statutory Filing Packets & Maker-Checker** | **ROADMAP** | `web/src/features/filings/FilingsView.tsx`<br>`AGENTS.md` | Navigate to `/filings` or press `g f`. Displays honest "Planned for M3" architectural roadmap (zero fake rows). |
| **15** | **Decision Ledger & Board Pack** | **ROADMAP** | `web/src/features/decisions/DecisionsView.tsx`<br>`AGENTS.md` | Navigate to `/decisions` or press `g d`. Displays honest "Planned for M4" architectural roadmap (zero fake rows). |
| **16** | **Rupee Exposure Engine (Open FAIR Monte Carlo)** | **ROADMAP** | `AGENTS.md` | Planned for M5. Rupee-denominated tail risk planning for the Board. |
| **17** | **PuLP / CBC Resource Optimizer** | **ROADMAP** | `AGENTS.md` | Planned for M6. Linear programming optimizer for incident response allocation. |
| **18** | **Air-Gapped Syslog / SIEM Webhook Intake** | **ROADMAP** | `AGENTS.md` | Planned for M2. Webhook intake and schema validation layer. |

---

## 2. Invariant & Non-Goal Adherence

1. **Zero Automated Regulatory Submissions**:
   - The platform generates filing bundles and statutory timing packets for CERT-In, RBI DAKSH, and DPDP.
   - It **never** auto-submits to regulator APIs; a human compliance officer files on the portal and records the statutory acknowledgement reference ID.
2. **Zero Customer PII in Database**:
   - PII Guard actively intercepts and strips or masks customer identification numbers before persistence.
3. **Zero External Runtime Calls**:
   - 100% air-gapped: no external CDNs, Google Fonts, SaaS telemetry, or cloud LLM APIs.
