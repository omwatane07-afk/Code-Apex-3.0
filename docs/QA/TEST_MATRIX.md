# CYBERQ Comprehensive QA Test Matrix

Full verification matrix across routes, API endpoints, UI controls, keyboard flows, background workers, and role authorization policies.

---

## 1. Route Matrix

| Route | View Name | Roles Allowed | Keyboard Shortcut | Fallback / Redirection | Status |
|---|---|---|---|---|---|
| `/` or `/incidents` | Incident Command Center | Analyst, Approver, CISO, Auditor | `g i` | Default landing view | PASS |
| `/wall` | Ambient SOC Wallboard | Wallboard (Dedicated), Analyst, Approver, CISO | `g w` | Stripped view; 0 incident titles, 0 PII | PASS |
| `/activity` | Activity Ledger & Audit Chain | Auditor, CISO, Model Validator (Read+Verify); Admin (Verify) | `g a` | Denied/View-only for Analyst/Approver | PASS |
| `/decisions` | Statutory Decision Ledger | All authenticated roles | `g d` | Honest "Planned for M4" state | PASS |
| `/filings` | Filing Packets & Dispatches | All authenticated roles | `g f` | Honest "Planned for M3" state | PASS |
| `/admin` | Telemetry & Pack Status | Admin, CISO, Auditor | `g m` | Masked narratives; system health | PASS |

---

## 2. API Endpoints & Authorization Matrix

| Method | Endpoint | Allowed Roles | Forbidden Roles | Verification Check |
|---|---|---|---|---|
| `GET` | `/healthz` | Public (Unauthenticated) | None | Server time, environment (`demo`/`pilot`/`prod`), version |
| `GET` | `/readyz` | Public (Unauthenticated) | None | DB pool ping, NTP skew check (< 1.0s) |
| `POST` | `/api/v1/auth/login` | Public | None | Server-side session generation, CSRF token issue |
| `POST` | `/api/v1/auth/logout` | Authenticated | None | Session revocation, cookie invalidation |
| `GET` | `/api/v1/auth/me` | Authenticated | Unauthenticated | Returns user info, role, and active permissions |
| `GET` | `/api/v1/incidents` | Analyst, Approver, CISO, Auditor | Admin (Masked), Wallboard (Masked) | Returns incident list with statutory deadlines |
| `POST` | `/api/v1/incidents` | Analyst | Approver, CISO, Auditor, Admin | Incident intake with PII pre-filter & Verhoeff check |
| `POST` | `/api/v1/incidents/{id}/triggers` | Analyst, Approver | Auditor, Admin, Wallboard | Assert noticed/detected triggers; starts clocks |
| `POST` | `/api/v1/incidents/preview-trigger` | Analyst, Approver | None (Auth required) | Computes consequence preview server-side |
| `POST` | `/api/v1/incidents/simulation-speed` | Analyst, Approver, CISO | Forbidden in Prod (`CYBERQ_ENV=production`) | Accelerates clock for demo; audited event |
| `GET` | `/api/v1/audit/export` | CISO, Auditor, Model Validator | Analyst, Approver, Admin | Exports Ed25519-signed checkpoints and SHA-256 events |
| `GET` | `/api/v1/audit/verify` | Auditor, CISO, Model Validator, Admin | Analyst, Approver | Cryptographic hash chain verification across all events |
| `GET` | `/api/v1/wallboard/incidents` | Wallboard, Analyst, Approver, CISO | Unauthenticated | Sanitized incident numbers and clock counters only |

---

## 3. UI Controls & Interactive Elements

| Component | Control | Purpose | Target Action | Verification Criteria |
|---|---|---|---|---|
| Top Navigation Rail | Sidebar Buttons | Switch views | PushState + View swap | `aria-current="page"`, active ring styling |
| Header Bar | Environment Badge | Report environment | Display runtime mode | Shows `DEMO` in demo, `PILOT` in pilot, `PROD` in prod |
| Header Bar | Theme Switcher | Toggle dark/light | Toggles theme tokens | Meets 4.5:1 text and 3:1 UI contrast in both modes |
| Header Bar | Quick Filter | Filter incidents | Text matching on IDs/tags | Real-time filter without network call |
| Incident List | Incident Card | View incident details | Opens detail panel | Tabular numbers, countdown clocks, trigger badges |
| Incident Card | 3D Corridor Button | Open 3D Situational view | Opens WebGL canvas modal | Smooth 60fps runway; 0 memory leaks on 50 cycles |
| Incident Details | "Assert Trigger" Button | Assert noticed / detected | Opens Trigger Modal | Triggers start statutory countdowns (CERT-In / RBI) |
| Trigger Modal | Diagnostic Checklist | Maker-checker evaluation | Verifies applicability | Precautionary maker-checker; exempt pending approval |
| Corridor Modal | Close (`Esc`) | Dismiss 3D Corridor | Unmounts canvas cleanly | Disposes Three.js geometries, textures, materials |
| Activity View | "Verify Audit Chain" | Validate tamper-evident logs | Calls `/api/v1/audit/verify` | Displays valid status, root hash, event count |

---

## 4. Keyboard Navigation Shortcuts

| Shortcut | Scope | Expected Behavior |
|---|---|---|
| `g i` | Global | Navigate to Command Center (`/incidents`) |
| `g w` | Global | Navigate to Ambient Wallboard (`/wall`) |
| `g a` | Global | Navigate to Activity & Audit (`/activity`) |
| `g d` | Global | Navigate to Decision Ledger (`/decisions`) |
| `g f` | Global | Navigate to Filing Packets (`/filings`) |
| `g m` | Global | Navigate to Admin & Telemetry (`/admin`) |
| `n` | Command Center | Open New Incident creation modal |
| `a` | Command Center | Open Trigger Assertion modal for selected incident |
| `1` | Trigger Modal | Select "CERT-In 6-Hour Noticed" trigger |
| `2` | Trigger Modal | Select "RBI 6-Hour Detected" trigger |
| `3` | Trigger Modal | Select "Dual Triggers (CERT-In + RBI)" |
| `Ctrl+K` or `/` | Global | Focus Quick Filter search bar |
| `Esc` | Modal / Drawer | Dismiss active modal or return to command view |
| `?` | Global | Open keyboard shortcuts reference overlay |

---

## 5. Security & Invariant Gates

| Gate ID | Invariant | Enforcement Mechanism |
|---|---|---|
| SEC-01 | Air-gapped zero external egress | Strict CSP (`default-src 'self'`), zero CDNs, self-hosted fonts |
| SEC-02 | No client storage of auth tokens | HTTP-only server-side Postgres sessions; 0 tokens in web storage |
| SEC-03 | Deny-by-default RBAC | Centralized `policy.py`; verified via route-by-role test matrix |
| SEC-04 | Audit chain immutability | SHA-256 hash chaining + Ed25519 signing; offline verification tool |
| SEC-05 | PII pre-filtration | Verhoeff Aadhaar algorithm, phone/credit card regex, audited override |
| SEC-06 | Wallboard zero data leakage | Dedicated stripped endpoint & model; 0 titles, names, or narratives |
| SEC-07 | Production simulation lockout | `POST /simulation-speed` rejected with 403 when `CYBERQ_ENV=production` |
| SEC-08 | Monotonic clock depth | Linear-to-logarithmic piecewise monotonic depth calculation (`depthZ`) |
