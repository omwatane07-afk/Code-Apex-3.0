# CYBERQ Demonstration Shot List: "02:00 AM Incident at the Bank"

A structured, 13-scene demonstration of CYBERQ designed for bank IT leadership, RBI supervisory evaluators, and security judges. Every scene adheres strictly to the working capabilities of the repository.

---

## Story Overview
*It is 02:00 AM inside the commercial bank’s Security Operations Center. A critical alert triggers on the primary datacenter core router. A SOC analyst, an incident commander, a compliance approver, and an IS auditor coordinate to triage the incident, bind statutory clocks, enforce zero-leakage safeguards, and preserve cryptographic evidence.*

---

## Scene 1: Authentication, Five Bank Roles & Separation of Duties
* **Status**: **BUILT**
* **Target Duration**: 35 seconds
* **Goal**: Demonstrate server-side session authentication across the five bank personas and prove that the Administrator role is strictly blocked from reading incident narratives and approving statutory filings.
* **Exact Clicks & Typing**:
  1. Open CYBERQ with SOC Analyst session (`aarav.sharma`). Observe incident narrative visible.
  2. Switch to Administrator session (`vikram.kulkarni`) via header role context.
  3. Observe incident title replaced with `[Narrative masked - Admin role cannot view incident details]`.
  4. Attempt to open trigger approval: confirm action is denied by policy engine.
* **Pass Check**:
  - Masked narrative placeholder text visible in incident detail.
  - Zero approval controls accessible to Admin role.
* **Caption**: *Admin cannot read investigative narratives or approve filings.* (9 words)
* **Narration**: *"CYBERQ enforces bank-grade separation of duties. Even full system administrators cannot read sensitive incident narratives or approve regulatory filings."*

---

## Scene 2: New Incident & Simultaneous Dual Statutory Triggers
* **Status**: **BUILT**
* **Target Duration**: 45 seconds
* **Goal**: Create a commercial banking incident and assert simultaneous statutory triggers for CERT-In (`noticed`) and RBI DAKSH (`detected`) with identical cryptographic timestamps.
* **Exact Clicks & Typing**:
  1. Press keyboard shortcut `n` to launch **New Incident** modal.
  2. Enter Title: `BGP Route Flapping on Primary Core Switch DC1-SW-01`.
  3. Enter Summary: `Intermittent packet drop detected on RTGS payment routing gateway.`.
  4. Select Severity: `Critical` and press Enter to create.
  5. Press shortcut `a` to open **Assert statutory clock trigger** modal.
  6. Confirm checkbox `Simultaneous CERT-In & RBI DAKSH trigger (bank standard)` is checked.
  7. Enter Evidence: `SIEM correlation rule #89201 triggered on interface flap`.
  8. Enter Rationale: `Primary payment gateway communication disrupted`.
  9. Click **Assert trigger**.
  10. Navigate to `/activity` to inspect the audit ledger.
* **Pass Check**:
  - Two distinct audit records appear for CERT-In (`noticed`) and RBI (`detected`) with identical ISO timestamps.
* **Caption**: *Simultaneous dual triggers bind CERT-In and RBI clocks at identical timestamps.* (10 words)
* **Narration**: *"Following bank incident commander SOP, CYBERQ simultaneously binds both CERT-In and RBI DAKSH statutory clocks with an immutable identical timestamp."*

---

## Scene 3: Active Countdown Clocks & Statutory Horizons
* **Status**: **BUILT**
* **Target Duration**: 30 seconds
* **Goal**: Demonstrate running real-time countdown clocks for CERT-In (6 hours), RBI DAKSH (6 hours), and DPDP (72 hours pending trigger).
* **Exact Clicks & Typing**:
  1. In Command Center, observe the top statutory clock strip.
  2. Hover over CERT-In 6-hour dial: verify local IST timestamp (`18 Oct 2026, 08:00 AM IST`) and UTC timestamp on hover.
  3. Hover over RBI cyber incident log dial: verify active synchronized 6-hour countdown.
  4. Inspect DPDP Data Protection Board dial: confirm honest `--:--:--` state with `Pending trigger` badge.
* **Pass Check**:
  - Green depleting SVG progress arcs ticking down each second.
  - DPDP correctly displays `Pending trigger` rather than a false breach.
* **Caption**: *Active statutory countdowns with hoverable IST and UTC deadlines.* (9 words)
* **Narration**: *"Live statutory countdown dials calculate depleting deadlines monotonically, while pending obligations like DPDP remain honestly marked as pending trigger."*

---

## Scene 4: Ingestion PII Guard & Audited Override
* **Status**: **BUILT**
* **Target Duration**: 45 seconds
* **Goal**: Show that PII Guard intercepts Aadhaar and card numbers while strictly ignoring technical artifacts (IPs, UUIDs, SHA hashes), with an audited confirmation override.
* **Exact Clicks & Typing**:
  1. Open **New Incident** modal.
  2. Paste text: `Alert on host 192.168.1.50 UUID 550e8400-e29b-41d4-a716-446655440000 hash a41893bf`.
  3. Observe: **Zero PII warnings** triggered (technical artifacts safely ignored).
  4. Paste invalid 12-digit number: `123456789012`. Observe: **No warning** (Verhoeff checksum fails).
  5. Paste valid Aadhaar test format: `2948-2948-2947`.
  6. Observe: Soft warning banner appears: `Potential 12-digit Aadhaar number detected`.
  7. Check `Confirm this is not personal data (audited override)`.
  8. Submit incident.
* **Pass Check**:
  - Soft warning displayed for valid Aadhaar only.
  - Submitting with checkbox records audited PII override event in `/activity`.
* **Caption**: *PII Guard flags real Aadhaar numbers while ignoring technical hashes.* (10 words)
* **Narration**: *"CYBERQ's PII Guard employs the Verhoeff algorithm to catch real personal data without generating false positives on IP addresses, hashes, or UUIDs."*

---

## Scene 5: Precautionary Rule & Clock Continuity
* **Status**: **BUILT**
* **Target Duration**: 35 seconds
* **Goal**: Prove that an analyst answering "No personal data" cannot unilaterally stop statutory countdowns.
* **Exact Clicks & Typing**:
  1. Select an incident and press `a` to open trigger modal.
  2. Under **Obligation applicability diagnostics**, question 1 (*"Is personal data involved?"*): click **No**.
  3. Question 2 (*"Is this incident reportable?"*): click **No**.
  4. Enter justification and click **Assert trigger**.
  5. Return to Command Center.
* **Pass Check**:
  - Status badge displays amber `Exempt pending approval`.
  - The statutory countdown clock **continues running**. Clocks do NOT stop.
* **Caption**: *Precautionary principle: answering 'No' keeps the statutory clock running.* (9 words)
* **Narration**: *"Under bank policy, a triage analyst cannot unilaterally stop a statutory clock. Answering 'no' keeps the countdown active until an approver confirms."*

---

## Scene 6: Dual-Control Maker-Checker Workflow
* **Status**: **BUILT**
* **Target Duration**: 40 seconds
* **Goal**: Demonstrate that the creator (maker) cannot approve an exemption, and a Compliance Approver (checker) must provide a written rationale.
* **Exact Clicks & Typing**:
  1. In the SOC Analyst session, attempt to approve the pending exemption on the incident.
  2. Observe: `Self-approval forbidden: maker cannot be checker` error toast.
  3. Switch session to Compliance Approver (`priya.deshmukh`).
  4. Open Exemption Review drawer.
  5. Enter mandatory justification: `Confirmed isolated BGP hardware failure with zero customer data impact.`.
  6. Click **Confirm Exemption**.
* **Pass Check**:
  - Obligation status transitions to `Exempt (Approved)` and clocks halt with full audit logging.
* **Caption**: *Dual-control maker-checker: makers cannot approve their own exemption requests.* (9 words)
* **Narration**: *"Dual-control maker-checker ensures regulatory integrity. The maker cannot approve their own exemption, requiring a senior approver's written sign-off."*

---

## Scene 7: 3D Depth Runway & Responsive 2D Fallback
* **Status**: **BUILT**
* **Target Duration**: 45 seconds
* **Goal**: Demonstrate the procedural Three.js 3D Statutory Runway, camera presets, collision-staggered billboards, and automatic 2D fallback on narrow viewports.
* **Exact Clicks & Typing**:
  1. In Command Center, click the **3D Depth runway** tab.
  2. Click camera preset **1: Now** (cockpit view). Observe CERT-In and RBI portal gates down the track.
  3. Click camera preset **2: Overview** (elevated 45-degree angle).
  4. Click camera preset **3: Lane focus** (tracking the active deadline).
  5. Observe: Coinciding 6h CERT-In and RBI billboards are vertically staggered by 20px (zero text overlap).
  6. Resize browser window width below 768px (or toggle 2D view).
  7. Observe: Procedural 3D canvas safely unmounts, presenting high-contrast 2D fallback cards.
* **Pass Check**:
  - Smooth WebGL rendering; zero billboard text collision.
  - Clean transition to 2D fallback below 768px with zero console warnings.
* **Caption**: *3D spatial runway tracks deadlines; falls back to 2D on mobile.* (11 words)
* **Narration**: *"The 3D Depth Runway maps time into physical distance with collision-free billboards, automatically falling back to 2D for mobile or low-spec displays."*

---

## Scene 8: Ambient SOC Wallboard (`/wall`) with Zero-Leakage Guarantee
* **Status**: **BUILT**
* **Target Duration**: 30 seconds
* **Goal**: Showcase the dedicated SOC Wallboard view, proving zero exposure of incident titles, descriptions, or personal names.
* **Exact Clicks & Typing**:
  1. Press keyboard shortcut `g w` (or navigate to `http://localhost:8000/wall`).
  2. Observe large high-contrast display with NTP stratum-1 calibration indicator.
  3. Inspect active cards: incident numbers (`INC-2026-0001`), severity badges, and countdown timers.
  4. Inspect page source / innerText: verify zero incident narratives, summaries, or user IDs exist in the DOM.
* **Pass Check**:
  - Only sanitized operational metrics rendered.
  - 100% sentence-case copy; zero leakage of confidential bank narratives.
* **Caption**: *Wallboard displays incident clocks with zero confidential narrative leakage.* (9 words)
* **Narration**: *"Designed for open floor dispatch, the SOC Wallboard displays operational counters while verifiably leaking zero incident titles, narratives, or personnel names."*

---

## Scene 9: Cryptographic Audit Ledger & Offline Tamper Detection
* **Status**: **BUILT**
* **Target Duration**: 50 seconds
* **Goal**: Demonstrate the IS Auditor read-only activity ledger, run offline verification passing on real data, and show immediate failure when a scratch copy is tampered with.
* **Exact Clicks & Typing**:
  1. Switch to IS Auditor session (`sunita.iyer`) and press `g a` to open `/activity`.
  2. Click **Verify audit chain**: observe green valid status showing SHA-256 chain and Ed25519 root signatures.
  3. Record terminal card: Run `python tools/verify-audit/verify.py --input scratch/audit_export.json`. Output displays `[VERIFIED]`.
  4. Tamper test (scratch copy only): Mutate one byte in a scratch audit JSON file.
  5. Run `python tools/verify-audit/verify.py --input scratch/audit_tampered.json`.
  6. Output displays red `[INTEGRITY VIOLATION] Hash mismatch on event #3`.
* **Pass Check**:
  - Live audit chain verifies passing in browser.
  - Offline CLI verifier passes on untampered log, and catches modified scratch record immediately.
* **Caption**: *Cryptographic SHA-256 hash chains detect offline log tampering instantly.* (9 words)
* **Narration**: *"Every state change is cryptographically chained. If an attacker or insider alters a single character in the audit log, offline verification immediately fails."*

---

## Scene 10: Operational Themes & Air-Gapped Security Headers
* **Status**: **BUILT**
* **Target Duration**: 35 seconds
* **Goal**: Demonstrate Day Ledger vs. Night Desk themes meeting WCAG AA contrast, and inspect air-gapped security headers.
* **Exact Clicks & Typing**:
  1. In Command Center, click the Sun/Moon toggle icon in the header.
  2. Transition between **Night Desk** (`#0B0F14`) and **Day Ledger** (`#F4F6F8`) themes.
  3. Open browser developer network inspector: verify all fonts are self-hosted IBM Plex (zero Google Fonts or CDN requests).
  4. Inspect response headers: `Content-Security-Policy: default-src 'self'`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`.
* **Pass Check**:
  - High-contrast readability in both themes (> 10:1 ratio).
  - Zero external HTTP requests; strict security headers present.
* **Caption**: *Self-hosted air-gapped security headers with WCAG AA Day/Night themes.* (9 words)
* **Narration**: *"CYBERQ runs entirely air-gapped with self-hosted fonts and strict security headers, paired with tested high-contrast Day Ledger and Night Desk themes."*

---

## Scene 11: Fail-Closed Architecture & Clock Skew Guard
* **Status**: **BUILT**
* **Target Duration**: 30 seconds
* **Goal**: Show that CYBERQ fails closed if the system clock drifts beyond 1.0 second or if the database is unreachable, displaying a clear manual fallback.
* **Exact Clicks & Typing**:
  1. Navigate to `/admin` (`g m`) to view real-time system telemetry.
  2. Observe: Server clock synchronized with measured drift of `0.05s` (safe below 1.0s limit).
  3. Record terminal card: Simulated endpoint probe when NTP skew exceeds 1.0 second.
  4. Backend `/readyz` probe immediately returns `503 Service Unavailable`.
  5. UI displays clear fallback banner: `Manual filing procedure activated per Bank SOP`.
* **Pass Check**:
  - Telemetry page shows active pack checksums and NTP calibration.
  - Skew > 1.0s triggers fail-closed manual fallback message.
* **Caption**: *Fail-closed design: NTP drift over 1 second triggers manual fallback.* (10 words)
* **Narration**: *"To protect statutory deadline accuracy, CYBERQ fails closed if clock drift exceeds one second, directing staff to manual filing runbooks."*

---

## Scene 12: Production Quality & Verification Gates
* **Status**: **BUILT**
* **Target Duration**: 40 seconds
* **Goal**: Display real, authenticated terminal card outputs proving 100% clean passes across the 9 verify gates and 19 Playwright browser tests.
* **Exact Clicks & Typing**:
  1. Open `demo/terminal_card.html?cmd=powershell -File make.ps1 verify&title=CYBERQ Quality Gates`.
  2. Display real captured output:
     - Ruff (0 errors), Mypy strict (24 files clean), Bandit (0 issues), Semgrep (10 custom rules, 0 findings), Gitleaks (0 leaks), Pip-audit (0 vulnerabilities), Npm-audit (0 vulnerabilities), Pytest (101 passed, 4 PG skipped, 92% coverage), Vitest (13 passed).
  3. Open `demo/terminal_card.html?cmd=powershell -File make.ps1 e2e&title=Playwright E2E Suite`.
  4. Display real captured output: 19 Playwright browser tests passed in 38 seconds.
* **Pass Check**:
  - Real timestamped outputs displayed in bank-grade terminal card.
  - Zero failed gates.
* **Caption**: *All 9 quality gates and 19 browser E2E tests pass.* (10 words)
* **Narration**: *"Every build passes nine automated supply-chain, security, and type gates, backed by nineteen comprehensive browser tests executing against the production build."*

---

## Scene 13: Honest Roadmap Capabilities (M2 to M6)
* **Status**: **ROADMAP**
* **Target Duration**: 45 seconds
* **Goal**: Provide an honest, unvarnished walkthrough of upcoming milestones without fake buttons or mock features.
* **Exact Clicks & Typing**:
  1. Press `g f` to navigate to **Statutory Filing Packets** (`/filings`).
  2. Observe honest roadmap card: `Planned for M3: Filing Packets and Maker-Checker`.
  3. Point out locked invariant: *"Never auto-submits to regulator portals; human compliance officer files and records acknowledgement reference ID."*
  4. Press `g d` to navigate to **Statutory Decision Ledger** (`/decisions`).
  5. Observe honest roadmap card: `Planned for M4: Decision Ledger and Board Pack` (ReportLab PDF generation, CISO dispute log).
  6. Highlight planned M5 (Rupee Open FAIR scenario exposure engine) and M6 (PuLP resource mitigation optimizer).
* **Pass Check**:
  - Plain, professional Roadmap cards rendered. Zero fake filing buttons or fabricated Board packs.
* **Caption**: *Honest roadmap: Filing packets in M3, Board pack in M4.* (10 words)
* **Narration**: *"CYBERQ demonstrates only working software. Upcoming milestones—including human-approved filing packets and quarterly Board packs—are clearly marked on our roadmap."*
