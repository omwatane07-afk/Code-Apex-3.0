# CYBERQ QA Bug Tracker

Tracked issues identified during pre-presentation QA audit.
Priorities:
- **P0**: Breaks or misleads the demo flow (Must fix tonight)
- **P1**: Visible defect or confusing behavior (Must fix tonight)
- **P2**: Visual polish, copy cleanup, or non-critical ergonomics (Fix tonight or document in Known Limitations)
- **P3**: Future enhancement (Document in Known Limitations)

---

## Active Defect Register

### BUG-001 [P0] Dead Sidebar Navigation Buttons & Missing Router Wiring
- **Component**: `web/src/app/App.tsx` (Sidebar nav)
- **Symptom**: Clicking on "Sources / Activity", "Decision Ledger", "Board Pack", or "Admin & Verification" in the left rail does nothing. Cursor changes but no state transition occurs.
- **Root Cause**: `<button title="Sources">`, `<button title="Decision Ledger">`, `<button title="Board Pack">`, and `<button title="Admin & Verification">` in `App.tsx` lacked `onClick` handlers, `aria-current` attributes, URL route synchronization, and view render branches.
- **Remediation**:
  1. Mapped routes: `/incidents` (Command Center), `/wall` (Wallboard), `/activity` (Activity & Audit Chain), `/decisions` (Decision Ledger), `/filings` (Board Pack / Filings), `/admin` (System & Pack Status).
  2. Implemented deep-linking and browser history support (`popstate` / `pushState`).
  3. Added `aria-current="page"`, visible active indicator rings, and accessible tooltips.
  4. Added `g` shortcut navigation (`g i`, `g w`, `g a`, `g d`, `g f`, `g m`).
  5. Implemented real views and honest "Planned" views:
     - `/activity`: `ActivityView.tsx` fetching `GET /api/v1/audit/export` with SHA-256 copy and "Verify audit chain" button invoking `GET /api/v1/audit/verify`.
     - `/decisions`: `DecisionsView.tsx` with honest M4 Planned roadmap and zero fake rows.
     - `/filings`: `FilingsView.tsx` with honest M3 Planned statutory notice roadmap and zero fake rows.
     - `/admin`: `AdminView.tsx` querying `/healthz`, `/readyz`, NTP drift (<1.0s), worker status, and obligation packs (`certin-directions-2022`, `rbi-cybersecurity-directions-2026`, `dpdp-rules-2025`).
- **Status**: RESOLVED
- **Verification**: `web/tests/qa_screens_and_navigation.spec.ts` passes; screenshots `05-activity-ledger.png`, `06-decisions-m4-planned.png`, `07-filings-m3-planned.png`, `08-admin-telemetry-packs.png`.

---

### BUG-002 [P0] 3D Runway Shows False "00:00:00 (breached)" for Pending/Unenforced Obligations
- **Component**: `web/src/features/corridor/ClockViewModel.ts`
- **Symptom**: When viewing an incident in the 3D Situational Corridor, obligations with `pending_trigger` status (e.g. DPDP 72h notice prior to trigger assertion or not in force) show `00:00:00 (breached)` on gate billboards.
- **Root Cause**:
  - In `determineVisualState()`: Condition `secondsRemaining <= 0` was evaluated when `deadline_at` is null (which defaulted `secondsRemaining` to 0), prematurely returning `"breached"`.
  - In `formatHms()`: `if (seconds <= 0) return "00:00:00 (breached)"` was executed unconditionally for null deadlines.
- **Remediation**:
  1. Added `pending` and `exempt` visual states to `ClockViewModel.ts`.
  2. `determineVisualState` explicitly checks `pending_trigger`, `not_in_force`, and null `deadlineAt`.
  3. `formatHms` returns `"Pending trigger"` or `"Not in force"` when appropriate.
  4. Assigned statutory horizon depths (6h / 72h) to pending gates so they sit properly along the runway rather than collapsing to the observer position.
- **Status**: RESOLVED
- **Verification**: `web/tests/corridor_depth.test.ts` (5/5 unit tests pass); screenshot `02-corridor-gate-geometry.png`.

---

### BUG-003 [P1] 3D Runway Gate Billboard Label Collision on Coinciding Deadlines
- **Component**: `web/src/features/corridor/CorridorCanvas.tsx`
- **Symptom**: When two statutory deadlines have identical or near-identical target times (e.g. CERT-In 6-hour initial notice and RBI 6-hour initial report), their 3D billboards share the exact same Z-depth, causing text and badge overlapping.
- **Root Cause**: Gate positions along the runway were calculated purely from `depthZ(deadline_at)`. No lateral lane offset or vertical staggering existed for proximate billboards.
- **Remediation**: In `CorridorCanvas.tsx`, added proximity detection in screen projection: if two billboards have $\Delta X < 130\text{px}$ and $\Delta Y < 48\text{px}$, apply a $\pm 20\text{px}$ vertical stagger.
- **Status**: RESOLVED
- **Verification**: `web/tests/qa_screens_and_navigation.spec.ts`; screenshot `02-corridor-gate-geometry.png` shows CERT-In and RBI labels clearly separated.

---

### BUG-004 [P1] Gate Geometry Contrast in Night Desk Mode
- **Component**: `web/src/features/corridor/CorridorCanvas.tsx`
- **Symptom**: Gate pillar geometry blended excessively into the dark background canvas (`#0b0f14`), making the physical structure difficult to discern in low ambient light.
- **Root Cause**: Materials used plain lines without physical mesh portals, beacons, or theme-adaptive ambient lighting.
- **Remediation**:
  1. Constructed full physical 3D mesh portals (twin vertical posts, top lintel beam, state-colored beacons).
  2. Added theme prop (`"light" | "dark"`) to `CorridorCanvas` and adapted fog, floor grid, and portal specular materials for high contrast under both themes.
- **Status**: RESOLVED
- **Verification**: Screenshots `01-command-center-night.png`, `02-corridor-gate-geometry.png`, and `03-command-center-day.png`.

---

### BUG-005 [P1] Top Header Displays "PRODUCTION" Badge in Demo Environment
- **Component**: `web/src/app/App.tsx` (Header)
- **Symptom**: Running the application for demonstration displayed a red "PRODUCTION" badge in the top bar, potentially alarming evaluators.
- **Root Cause**: `const isProd = import.meta.env.PROD || import.meta.env.MODE === "production"` checked Vite build-time environment rather than runtime environment reported by backend `/healthz`.
- **Remediation**: Header queries runtime environment from `GET /healthz`. When `environment === "demo"`, displays an amber `DEMO` badge; when `pilot`, displays `PILOT`.
- **Status**: RESOLVED
- **Verification**: Screenshots `01` through `08` display the amber `DEMO` badge.

---

### BUG-006 [P1] Test Incident Scenario "Aappa" and Lack of Demo Reset Routine
- **Component**: `web/src/app/App.tsx` & `make.ps1`
- **Symptom**: Pre-seeded incident title contained informal developer test strings ("Aappa / Code Apex Testing"). No single command existed to wipe and restore clean banking scenarios.
- **Root Cause**: Placeholder data was entered during initial development testing.
- **Remediation**:
  1. Replaced demo data with realistic commercial banking incident scenarios:
     - `INC-2026-0001`: "Core switch routing loop impacting RTGS settlement channel"
     - `INC-2026-0002`: "External vendor credential exposure on public code repository"
  2. Added `demo-reset` target in `make.ps1` that cleans transient state and strictly refuses to execute if `CYBERQ_ENV=production`.
- **Status**: RESOLVED
- **Verification**: `make.ps1 demo-reset` runs cleanly; incidents reflect realistic banking terminology.

---

### BUG-007 [P2] Technical Jargon in Corridor Subheader and Inconsistent Casing
- **Component**: `web/src/app/App.tsx`
- **Symptom**: Modal subheader displayed "Three.js procedural runway - hardware depth perspective".
- **Root Cause**: Developer debug copy remained in production components.
- **Remediation**: Replaced with sentence-case institutional copy: "Statutory deadline corridor (temporal depth perspective)".
- **Status**: RESOLVED
- **Verification**: Verified in DOM; screenshot `02-corridor-gate-geometry.png`.

---

### BUG-008 [P1] "Auditor view: On" Does Not Unlock Activity Ledger (/activity)
- **Component**: `web/src/app/App.tsx` & `web/src/features/activity/ActivityView.tsx`
- **Symptom**: Turning "Auditor view: On" in the top bar leaves `/activity` locked with "Separation of duties enforcement".
- **Root Cause**: The toggle set client boolean `isAuditor`, which was only used for narrative masking. `ActivityView.tsx` evaluates `userRole`, which remained `"analyst"`.
- **Remediation**:
  1. Removed confusing client-side "Auditor view" toggle from header.
  2. Enforced narrative masking strictly on real authenticated role (`userRole === "admin"` or `userRole === "auditor"`).
  3. Cleaned locked-page copy to plain sentence case without unverified claims.
  4. Added administrative verification probe mode for `admin` role.
- **Status**: RESOLVED
- **Verification**: `role_auditor.png` displays unbroken verified cryptographic hash chain (Events verified: 15, root hash `3f1da6b...`).

---

### BUG-009 [P1] Missing Role Switcher in Top Header & No Session Rotation
- **Component**: `web/src/app/App.tsx` & `backend/src/cyberq/api/routes_auth.py`
- **Symptom**: Top header has no control to switch roles, even though the page advises switching to auditor or CISO in the top header.
- **Root Cause**: `{(isDemoMode || !isProd) && ...}` was evaluated as false in production builds unless `?demo=1` was explicitly in query params. Changing the selector did not call `POST /api/v1/auth/login` to rotate the server session and CSRF token.
- **Remediation**:
  1. Render demo role switcher dropdown with visible badge `Viewing as: [Role] (demo)` whenever `CYBERQ_ENV` is `demo` or `dev`.
  2. Role change invokes `POST /api/v1/auth/login`, rotating server session ID and issuing a fresh CSRF token.
  3. Server strictly refuses demo login in production/pilot mode (`if not settings.is_demo(): raise HTTPException(403)`).
  4. Playwright E2E verifies zero role selector elements exist in production/pilot DOM (`test("production build: zero role selector elements exist in DOM")` passes in 1.1s).
- **Status**: RESOLVED
- **Verification**: `role_analyst.png`, `role_ciso.png`, `role_compliance.png`, `role_auditor.png`, `role_admin.png` show working role badge and sessions.

---

### BUG-010 [P1] CISO Role Lacks End-to-End Capabilities & Working Risk Decision Ledger
- **Component**: Backend IAM, API (`routes_incidents.py`, `routes_decisions.py`), and Frontend (`IncidentDetail.tsx`, `CisoOverviewCard.tsx`, `DecisionsView.tsx`)
- **Symptom**: CISO role cannot perform CISO-specific actions (severity changes, major incident declaration, closure approval with maker-checker), and `/decisions` was a static placeholder.
- **Root Cause**: CISO role had permissions in `policy.py` but lacked backend endpoints and UI controls.
- **Remediation**:
  1. Backend Endpoints Implemented with transactional audit logging:
     - `POST /api/v1/incidents/{id}/severity` (`Action.INCIDENT_SEVERITY_SET`)
     - `POST /api/v1/incidents/{id}/declare-major` (`Action.INCIDENT_MAJOR_DECLARE`)
     - `POST /api/v1/incidents/{id}/approve-closure` (`Action.INCIDENT_CLOSE_APPROVE`, maker-checker enforced: incident reporter cannot close)
     - `GET /api/v1/decisions`, `POST /api/v1/decisions` (`Action.DECISION_CREATE`, CISO only)
     - `POST /api/v1/decisions/{id}/countersign` (`Action.DECISION_APPROVE`, maker-checker enforced: decision maker cannot countersign)
     - `GET /api/v1/governance/board-preview` (`Action.BOARD_PACK_READ`)
     - `GET /api/v1/governance/ciso-alerts` (`Action.INCIDENT_READ`)
  2. Frontend Operational Wiring:
     - Header displays live `CISO alerts: N` attention queue badge.
     - Command Center displays `CisoOverviewCard` with active clocks, open decisions, pending closures, and 1-Click Board Preview modal.
     - Incident triage view displays `CISO Executive Incident Controls` (Change severity dialog, Declare Major dialog, and Maker-Checker Closure sign-off with reporter lock).
     - Statutory Decision Ledger (`/decisions`) allows drafting risk decisions, tracking status, and countersigning with maker-checker verification.
- **Status**: RESOLVED
- **Verification**: `backend/tests/test_ciso_and_decisions.py` (8/8 backend test cases pass); screenshots `role_ciso.png` and `role_ciso_decisions.png`.

