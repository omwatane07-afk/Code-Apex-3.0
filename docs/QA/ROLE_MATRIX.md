# CYBERQ Role-Based Access Control (RBAC) & Separation of Duties Matrix

This document provides the authoritative mapping between Roles, UI Pages, API Endpoints, and Actions, with exact file and line references in the codebase.

---

## 1. Roles Definition

Defined in [`backend/src/cyberq/iam/policy.py`](file:///d:/Code%20Apex%203.0/backend/src/cyberq/iam/policy.py#L12-L19):

| Role Identifier | Display Name | Purpose & Separation of Duties |
|---|---|---|
| `analyst` | SOC Analyst (Maker) | Incident investigation, initial trigger assertion, narrative documentation. Cannot approve own actions or self-file. |
| `compliance_approver` | Compliance Approver (Checker) | Maker-checker approver for statutory filings, trigger dispute resolution, precautionary exemption confirmation. |
| `ciso` | Chief Information Security Officer | Executive risk governance, incident severity classification, major incident declaration, incident closure approval, risk decision drafting/countersigning, raw audit chain inspection, board pack generation. Cannot self-approve closures or self-countersign decisions. |
| `auditor` | Internal / IS Auditor | Read-only inspection of incidents, full raw cryptographic audit ledger read, offline cryptographic verification. Cannot create or edit incidents. |
| `model_validator` | Model Risk Validator | Model governance, exposure model validation, raw audit ledger read and verification. |
| `admin` | System Administrator | Telemetry inspection, service configuration, cryptographic verification probe. Strictly forbidden from viewing incident narratives, approving filings, or modifying audit data. |
| `wallboard` | SOC Telemetry Wallboard | Ambient public display restricted to incident numbers and countdown timers; strictly zero narrative or personal data. |

---

## 2. API Endpoint Authorization Matrix

Policy engine enforcement via `require_permission(Action)` in [`backend/src/cyberq/api/deps.py`](file:///d:/Code%20Apex%203.0/backend/src/cyberq/api/deps.py#L113-L125) and [`backend/src/cyberq/iam/policy.py`](file:///d:/Code%20Apex%203.0/backend/src/cyberq/iam/policy.py#L60-L124).

| API Endpoint | HTTP Method | Required Action | Analyst | Compliance | CISO | Auditor | Model Validator | Admin | Wallboard | Code Reference |
|---|---|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|---|
| `/healthz` | GET | *(public)* | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | [`health.py:35`](file:///d:/Code%20Apex%203.0/backend/src/cyberq/api/health.py#L35) |
| `/readyz` | GET | *(public)* | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | [`health.py:46`](file:///d:/Code%20Apex%203.0/backend/src/cyberq/api/health.py#L46) |
| `/api/v1/auth/login` | POST | *(dev/demo only)* | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | [`routes_auth.py:86`](file:///d:/Code%20Apex%203.0/backend/src/cyberq/api/routes_auth.py#L86) |
| `/api/v1/auth/me` | GET | *(authenticated)* | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | [`routes_auth.py:169`](file:///d:/Code%20Apex%203.0/backend/src/cyberq/api/routes_auth.py#L169) |
| `/api/v1/auth/logout` | POST | *(authenticated)* | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | [`routes_auth.py:184`](file:///d:/Code%20Apex%203.0/backend/src/cyberq/api/routes_auth.py#L184) |
| `/api/v1/audit/export` | GET | `audit:read` | DENY (403) | DENY (403) | ALLOW | ALLOW | ALLOW | DENY (403) | DENY (403) | [`routes_audit.py:34`](file:///d:/Code%20Apex%203.0/backend/src/cyberq/api/routes_audit.py#L34) |
| `/api/v1/audit/verify` | GET | `audit:verify` | DENY (403) | DENY (403) | ALLOW | ALLOW | ALLOW | ALLOW | DENY (403) | [`routes_audit.py:94`](file:///d:/Code%20Apex%203.0/backend/src/cyberq/api/routes_audit.py#L94) |
| `/api/v1/incidents` | POST | `incident:create` | ALLOW | DENY (403) | DENY (403) | DENY (403) | DENY (403) | DENY (403) | DENY (403) | [`routes_incidents.py:373`](file:///d:/Code%20Apex%203.0/backend/src/cyberq/api/routes_incidents.py#L373) |
| `/api/v1/incidents` | GET | `incident:read` | ALLOW | ALLOW | ALLOW | ALLOW | DENY (403) | DENY (403) | DENY (403) | [`routes_incidents.py:427`](file:///d:/Code%20Apex%203.0/backend/src/cyberq/api/routes_incidents.py#L427) |
| `/api/v1/incidents/{id}` | GET | `incident:read` | ALLOW | ALLOW | ALLOW | ALLOW | DENY (403) | DENY (403) | DENY (403) | [`routes_incidents.py:441`](file:///d:/Code%20Apex%203.0/backend/src/cyberq/api/routes_incidents.py#L441) |
| `/api/v1/incidents/{id}/transition` | POST | `incident:update` | ALLOW | ALLOW | ALLOW | DENY (403) | DENY (403) | DENY (403) | DENY (403) | [`routes_incidents.py:456`](file:///d:/Code%20Apex%203.0/backend/src/cyberq/api/routes_incidents.py#L456) |
| `/api/v1/incidents/{id}/triggers` | POST | `trigger:assert` | ALLOW | ALLOW | DENY (403) | DENY (403) | DENY (403) | DENY (403) | DENY (403) | [`routes_incidents.py:493`](file:///d:/Code%20Apex%203.0/backend/src/cyberq/api/routes_incidents.py#L493) |
| `/api/v1/incidents/{id}/triggers/{t_id}/dispute` | POST | `trigger:dispute_resolve` | DENY (403) | ALLOW | ALLOW | DENY (403) | DENY (403) | DENY (403) | DENY (403) | [`routes_incidents.py:569`](file:///d:/Code%20Apex%203.0/backend/src/cyberq/api/routes_incidents.py#L569) |
| `/api/v1/incidents/{id}/applicability` | POST | `trigger:assert` | ALLOW | ALLOW | DENY (403) | DENY (403) | DENY (403) | DENY (403) | DENY (403) | [`routes_incidents.py:631`](file:///d:/Code%20Apex%203.0/backend/src/cyberq/api/routes_incidents.py#L631) |
| `/api/v1/incidents/{id}/applicability/confirm-exemption` | POST | `trigger:dispute_resolve` | DENY (403) | ALLOW* | ALLOW* | DENY (403) | DENY (403) | DENY (403) | DENY (403) | [`routes_incidents.py:690`](file:///d:/Code%20Apex%203.0/backend/src/cyberq/api/routes_incidents.py#L690) |
| `/api/v1/incidents/{id}/severity` | POST | `incident:update` | DENY (403) | DENY (403) | ALLOW | DENY (403) | DENY (403) | DENY (403) | DENY (403) | New CISO endpoint |
| `/api/v1/incidents/{id}/declare-major` | POST | `incident:update` | DENY (403) | DENY (403) | ALLOW | DENY (403) | DENY (403) | DENY (403) | DENY (403) | New CISO endpoint |
| `/api/v1/incidents/{id}/approve-closure` | POST | `incident:update` | DENY (403) | DENY (403) | ALLOW* | DENY (403) | DENY (403) | DENY (403) | DENY (403) | New CISO endpoint (*maker-checker) |
| `/api/v1/decisions` | GET | `decision:create`/`read` | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | DENY (403) | DENY (403) | New Decision endpoint |
| `/api/v1/decisions` | POST | `decision:create` | DENY (403) | DENY (403) | ALLOW | DENY (403) | DENY (403) | DENY (403) | DENY (403) | New Decision endpoint |
| `/api/v1/decisions/{id}/countersign` | POST | `decision:approve` | DENY (403) | ALLOW* | ALLOW* | DENY (403) | DENY (403) | DENY (403) | DENY (403) | New Decision endpoint (*maker-checker) |
| `/api/v1/incidents/wallboard` | GET | `wallboard:read` | ALLOW | ALLOW | ALLOW | ALLOW | DENY (403) | DENY (403) | ALLOW | [`routes_incidents.py:242`](file:///d:/Code%20Apex%203.0/backend/src/cyberq/api/routes_incidents.py#L242) |

*\*Subject to strict maker-checker validation: preparer user ID != approver user ID ([`policy.py:156`](file:///d:/Code%20Apex%203.0/backend/src/cyberq/iam/policy.py#L156)).*

---

## 3. UI Page & Control Access Matrix

| UI Route | Analyst | Compliance Approver | CISO | Auditor | Admin |
|---|---|---|---|---|---|
| `/incidents` (Command Center) | Unmasked, New Incident modal (`n`), Assert Trigger modal (`a`) | Unmasked, Assert Trigger modal, Dispute / Confirm exemption | Unmasked, CISO Overview card, Severity Change, Declare Major, Approve Closure | Read-only unmasked view | Masked narratives (`[Narrative masked]`) |
| `/wall` (Wallboard) | Sanitized telemetry | Sanitized telemetry | Sanitized telemetry | Sanitized telemetry | Sanitized telemetry |
| `/activity` (Activity & Audit Chain) | LOCKED (Separation of duties card) | LOCKED (Separation of duties card) | UNLOCKED (Read events table + Verify button) | UNLOCKED (Read events table + Verify button) | VERIFY ONLY (Probe verification permitted; events table locked) |
| `/decisions` (Risk Decision Ledger) | View ledger (read-only) | View ledger + Countersign pending decisions | Full access: Draft new decisions + Countersign (maker-checker) | View ledger (read-only) | LOCKED |
| `/filings` (Filing Packets) | Planned for M3 | Planned for M3 | Planned for M3 | Planned for M3 | Planned for M3 |
| `/admin` (System & Pack Status) | Telemetry view | Telemetry view | Telemetry view | Telemetry view | Full Admin telemetry & config view |

---

## 4. Root Causes of Reported Issues

### P1: "Auditor view: On" leaves `/activity` locked
- **Mechanism**: The button in `App.tsx` toggled only local boolean state `isAuditor`, which was designed as a client-side display convenience for narrative masking in `IncidentDetail.tsx`.
- **Root Cause**: `ActivityView.tsx` evaluates `isRolePermitted = ["ciso", "auditor", "model_validator", "admin"].includes(userRole)`. Because `userRole` remained `"analyst"`, the page remained strictly locked by role.
- **Fix**: Remove misleading client "Auditor view" button. Role state is governed by authentic session context.

### P2: Header has no way to switch role
- **Mechanism**: In `App.tsx`: `{(isDemoMode || !isProd) && <select ...>}`.
- **Root Cause**: In production Vite builds (`npm run build`), `isProd` is `true`. `isDemoMode` checked `?demo=1`. Unless `?demo=1` was present in the query string, the selector was removed from the DOM. Furthermore, changing `<select>` did not invoke `POST /api/v1/auth/login` to rotate the server session cookie and CSRF token, and the backend role `compliance_approver` was misnamed as `compliance`.
- **Fix**: Wire dynamic runtime environment from `/healthz`. Render role switcher dropdown whenever in `demo` or `dev` environment, accompanied by a visible badge `"Viewing as: <Role> (demo)"`. Switching invokes `POST /api/v1/auth/login`, rotates the session, and updates state. In production, server strictly rejects `/auth/login` and frontend omits the switcher entirely.

### P3: CISO role incomplete end-to-end
- **Mechanism**: `Role.CISO` was defined in `policy.py` but lacked operational endpoints and dedicated UI components.
- **Root Cause**: Missing endpoints for incident severity override, major incident declaration, incident closure approval with maker-checker, and the Risk Decision Ledger under `/decisions`.
- **Fix**: Add dedicated CISO permissions and API endpoints with full transactional audit logging, build the CISO Overview card and action modals in Command Center, and build the operational Risk Decision Ledger under `/decisions`.
