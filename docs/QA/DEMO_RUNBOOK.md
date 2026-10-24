# CYBERQ Demo Presentation Runbook

Operating guide and rehearsal script for the CYBERQ Incident-to-Board layer presentation.

---

## 1. Stack Initialization & Pre-Flight Checks

Before presenting to evaluators, ensure clean state and verify background services.

### Environment Launch
Open PowerShell terminal and run:
```powershell
# Reset to clean demo scenarios (prohibited in production)
powershell -File .\make.ps1 demo-reset

# Start the unified backend and production-compiled frontend SPA
powershell -File .\make.ps1 dev
```
Verify the server starts at `http://127.0.0.1:8000`.

### Pre-Flight Verification Checklist
1. Open Chrome/Edge at `http://127.0.0.1:8000`.
2. Inspect Top Header: Verify amber badge says `DEMO` (not `PRODUCTION`).
3. Verify System Health: Check indicator shows `SYSTEM OPERATIONAL` with server time in UTC and IST.
4. Verify Initial Incident: Check incident `FIN-2026-0881` ("Core switch routing anomaly impacting RTGS settlement channel") is loaded.

---

## 2. Rehearsal Demo Script (Step-by-Step)

### Act 1: Incident Ingestion & PII Protection (2 minutes)
- **Narrative**: "CYBERQ deploys directly inside bank infrastructure air-gapped from external networks. When a high-severity security anomaly is detected, SOC analysts record the event without leaking raw customer PII or cardholder data."
- **Action**:
  - Click `+ New Incident` (or press `n`).
  - Enter Title: `FIN-2026-0882: External vendor credential exposure on code repository`.
  - Enter Summary: `Credentials for payment gateway integration discovered on public repository. Containment in progress.`
  - Attempting to paste an Aadhaar number triggers the banking Verhoeff pre-filter, warning the analyst immediately before storage.
  - Submit incident.
- **Key Regulatory Speaking Point**: Bank IT managers and RBI inspectors require strict PII minimization; CYBERQ sanitizes narratives at the boundary.

### Act 2: Statutory Trigger Assertion & Consequence Preview (2 minutes)
- **Narrative**: "Indian commercial banks face multiple overlapping statutory filing clocks once an incident is 'noticed' or 'detected'. CYBERQ implements deterministic clock math without client-side drift."
- **Action**:
  - Select the newly created incident.
  - Click `Assert Trigger` (or press `a`).
  - Select `Dual Triggers (CERT-In 6h + RBI 6h)` (or press `3`).
  - Highlight the server-side **Consequence Preview**: Showing CERT-In initial filing required in 6 hours, RBI cyber incident report in 6 hours, and DPDP personal data breach clock pending.
  - Complete the diagnostic checklist: confirm applicability.
  - Submit assertion.
- **Key Regulatory Speaking Point**: Dual triggers record two distinct immutable audit records at the same timestamp under RBI Paragraph 182 and CERT-In Directions 2022.

### Act 3: 3D Situational Corridor (3 minutes)
- **Narrative**: "During high-stress incidents, analysts suffer cognitive fatigue tracking multiple non-linear deadlines. CYBERQ's Three.js Situational Corridor projects regulatory deadlines into a hardware-accelerated depth runway."
- **Action**:
  - Click `3D Corridor` on the incident row.
  - Observe the continuous monotonic piecewise depth metric:
    - Imminent 6-hour CERT-In and RBI gates stand nearest in perspective.
    - DPDP 72-hour gate is rendered deeper along the temporal runway.
    - Unasserted or pending triggers are clearly labeled `Pending trigger` or `Not in force`, never showing false breached states.
  - Point out lateral lane offset separating simultaneous 6-hour deadlines cleanly without text collision.
  - Demonstrate responsive WebGL rendering with zero external CDN dependencies, self-hosted IBM Plex typography, and full keyboard/screen-reader mirror table parity.
  - Press `Esc` to return to the Command Center.

### Act 4: Ambient SOC Wallboard (1 minute)
- **Narrative**: "Banks run large display screens in open SOC rooms. Displaying incident titles or customer names on wallboards creates severe physical data leakage."
- **Action**:
  - Click `SOC Wallboard Display (/wall)` on the sidebar (or press `g w`).
  - Point out that the Wallboard view uses a dedicated restricted role (`Role.WALLBOARD`) that delivers strictly incident numbers, status, and running countdown clocks.
  - Zero titles, narratives, or analyst identities exist in the DOM or API payload.
  - Click `Return to Command Center` (or press `g i`).

### Act 5: Tamper-Evident Audit Chain & Verification (2 minutes)
- **Narrative**: "Every state change in CYBERQ writes an audit event in the same DB transaction. Audit events form an unbroken SHA-256 hash chain with Ed25519 signatures, verifiable offline by RBI inspectors or internal audit."
- **Action**:
  - Click `Activity` in the sidebar (or press `g a`).
  - View the real-time event ledger showing sequence numbers, timestamps, actor roles, before/after states, and SHA-256 hashes.
  - Click `Verify Audit Chain`.
  - The system executes cryptographic chain verification and displays `Chain Valid: All events cryptographically verified`, the root hash, and event count.
### Act 6: CISO Executive Governance, Risk Decisions & Board Readiness (3 minutes)
- **Narrative**: "Commercial bank CISOs carry personal accountability for regulatory compliance under RBI Master Directions. CYBERQ gives the CISO an executive cockpit for real-time statutory exposure, formal dual-control risk acceptance, and Board-ready reporting."
- **Action**:
  - Switch role in top header dropdown: select `CISO`.
  - Notice the header badge updates to `Viewing as: CISO (demo)` and the `CISO alerts: N` attention queue badge appears.
  - Review the **CISO Executive Governance Overview** card:
    - 4 real-time operational indicators: Active statutory clocks, Open risk decisions, Awaiting closure approval, and Critical/Major risks.
    - Click `1-Click Board summary preview` to display the executive summary modal aggregating cross-regulatory exposure, active clocks, and risk decisions.
  - Inspect an incident in the Command Center:
    - View the **CISO Executive Incident Controls** card.
    - Click `Change severity`: select new severity level and enter statutory rationale.
    - Click `Declare Major Incident`: enter statutory threshold justification. The incident receives a prominent `MAJOR INCIDENT` alert badge and executive banner.
    - Highlight **Maker-Checker Dual Control**: If the CISO opened the incident, the `Approve closure` button is strictly locked with a policy notice. Dual-control requires a separate commander or CISO sign-off.
  - Press `g d` (or click `Statutory Decision Ledger` in sidebar):
    - View recorded risk acceptance and compensating control decisions.
    - Click `Draft risk decision`: create a formal risk acceptance with compensating controls (e.g. 24x7 SOC manual queue review) and expiry date.
    - Note that countersignature requires a distinct approver (maker-checker rule strictly enforced by the backend policy engine).

---

## 3. Fallback & Troubleshooting Procedures

| Incident / Glitch | Immediate Remediation |
|---|---|
| WebGL fails or hardware acceleration disabled | System automatically displays the 2D Command Center fallback with high-contrast countdown dials. |
| Browser zoom / responsive glitch | Press `Ctrl+0` to reset browser zoom to 100%. |
| Accidental data entry during rehearsal | Run `powershell -File .\make.ps1 demo-reset` to restore clean state in 2 seconds. |
| Accidental 403 Forbidden | Ensure role is set appropriately (Analyst for creation, Approver for approval, Auditor/CISO for audit verification). |
