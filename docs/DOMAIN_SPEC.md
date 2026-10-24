# CYBERQ domain spec and milestones

## Core concepts
- **Incident**: a security event the bank is handling. States: `new` > `triaged` > `confirmed` | `false_positive` > `contained` > `closed`.
- **Trigger**: an asserted moment that starts a regulator clock: `noticed`, `detected`, `aware`. Each assertion stores who, when, evidence and a reason. Triggers can be corrected only by appending a new assertion.
- **Obligation instance**: incident x obligation pack. States: `pending_trigger` > `running` > `due_soon` (under 2 h) > `critical` (under 30 min) > `filed` | `breached` | `not_applicable` | `disputed`. Deadline = trigger time + pack duration (UTC).
- **Escalation ladder** (configurable): T-4h, T-2h, T-1h, T-30m, T-10m, breach. Each rung notifies by role (SMTP, bank webhook, in-app). Idempotent.
- **Filing packet**: versioned snapshot of ordered fields for one obligation. Prepared by one person, approved by another (maker-checker), then recorded as filed with portal, timestamp, filer and acknowledgement ID. Immutable after approval; changes create a new version that needs re-approval.
- **Decision**: accept risk, remediate, fund, or defer, with rationale, owner, review date, linked incident or scenario, model version at the time, and maker-checker approval.
- **Scenario and exposure run** (M5): scenario-level FAIR-style Monte Carlo with an assumptions register. Planning and Board use only.
- **Model inventory entry** (M5): owner, developer, validator, approver, risk tier, intended use, upstream and downstream dependencies, key validation observations. These mirror the fields RBI's June 2026 draft model-risk guidance lists for an inventory; CYBERQ is itself a model the bank must validate.

## Main tables (Alembic migrations, UUID v7 keys)
`org_config, app_user, role_grant, source, source_secret, raw_event(redacted), incident, incident_trigger, obligation_pack_ref, obligation_instance, escalation, notification, filing_packet, filing_record, evidence_item, decision, audit_event, audit_checkpoint, assumption, scenario, simulation_run, model_inventory, validation_report, control, optimizer_run, job_lock`.

## API (OpenAPI 3.1, versioned `/api/v1`, generated TypeScript client)
`/incidents`, `/incidents/{id}/triggers`, `/incidents/{id}/obligations`, `/obligations/{id}/packets`, `/packets/{id}/approve`, `/packets/{id}/filed`, `/ingest/{source}` (signed), `/sources`, `/decisions`, `/board-packs`, `/scenarios`, `/runs`, `/model-inventory`, `/audit/verify`, `/admin/*`, `/healthz`, `/readyz`.

## Demo scenario (always labelled DEMO)
"Vendor-borne ransomware": a core-banking service provider is compromised through a misconfigured CI server. EDR and SIEM alerts arrive from the simulator; the analyst asserts `detected`; CERT-In and RBI clocks start; a customer-data exposure flag later asserts `aware` for DPDP; the compliance approver approves packets; the CISO records a decision; the Board pack shows on-time filing performance. Use a generic fictitious bank name.

## Milestones and acceptance tests

### M0 Foundations
Repo, Makefile targets, CI, Postgres, migrations, config, structlog, OIDC login (Keycloak in dev compose), role policy module, audit chain with checkpoints and `tools/verify-audit`, health endpoints, app shell with tokens, themes, i18n scaffold, ADR-0001.
Accept: tamper test fails verification after any row edit; unauthenticated and unauthorized requests are denied on every route (Schemathesis plus a route-by-role matrix test); CSP blocks an injected external script in an e2e test; both themes pass contrast tests.

### M1 Incident and clock engine
Obligation pack loader and production gate; incident CRUD; trigger assertions; deadline calculation; durable timers and escalations; Command Center, incident detail, clock strip; global multi-session revocation (all-sessions logout).
Accept: Hypothesis property tests (deadline monotonic in trigger time; identical results across restarts; disputed triggers keep the earlier deadline); worker killed mid-escalation then restarted produces no missed and no duplicate escalation; production mode refuses draft packs; obligation pack loader enforces safe YAML parsing rejecting PyYAML object execution tags (CWE-502); incident detail route (`GET /api/v1/incidents/{id}`) enforces strict IDOR/BOLA authorization denying Admin and unauthenticated access; global logout with `all_sessions=true` invalidates all active sessions for the user; unverified banner visible in dev; clock strip passes axe and screenshot review.

### M2 Intake
Normalized event schema (OCSF-inspired subset, versioned); signed webhook receiver; syslog CEF listener; CSV/JSON import; reference adapters for a SIEM alert, a cloud-SOC incident JSON, and a vulnerability-scan CSV; PII guard; idempotency, dedupe, dead-letter queue and replay; `tools/simulator`; Sources screen.
Accept: PII corpus of fake Aadhaar (valid Verhoeff), PAN, card (Luhn), account and mobile values leaves zero unredacted values in the database; replayed or stale webhooks rejected and audited; 1,000 events per minute for 10 minutes with p95 ingest under 500 ms on one node (k6); malformed events go to the dead-letter queue, not the void.

### M3 Filing packets and maker-checker
Packet generation from pack fields (or the generic labelled summary); versions; approve; record as filed; printable worksheet; notifications; manual-fallback export; step-up MFA re-authentication before sensitive filing approvals.
Accept: same-user approval impossible at the API and DB level; step-up MFA re-authentication required before sensitive filing approvals (rejecting approval actions without step-up proof even if active session exists); approved packet immutable; notifications idempotent; worksheet prints on A4 with no clipped fields; end-to-end test covers new incident to recorded filing in under 10 clicks.

### M4 Decision ledger and Board pack
Decisions with maker-checker for accept-risk; review-date reminders; quarterly Board pack (web and PDF) with on-time filing rate, time to classify, time to file, open decisions past review date, incident counts by type; auditor evidence export; Hindi catalogue for navigation and status labels.
Accept: every Board pack figure traces to source rows via a "show data" link; PDF is reproducible byte-for-byte from the same inputs modulo a stamped generation time; auditor role cannot see free-text narratives unless granted; CSV auditor evidence exports automatically sanitize formula trigger characters (=, +, -, @) with prepended single apostrophe to neutralize spreadsheet formula evaluation (CWE-1236).

### M5 Exposure engine and model governance
Assumptions register (distribution, source, owner, confidence, expiry); scenarios including third-party concentration; vectorized, seeded Monte Carlo; loss exceedance curve, expected loss, VaR and CVaR at configurable confidence; sensitivity; model inventory entry; validation pack export (intended use, conceptual soundness, input data and assumptions, sensitivity, outcomes analysis against labelled synthetic history, limitations); model version bump invalidates dependent decisions pending re-approval.
Accept: same seed gives identical results; closed-form check (Poisson frequency, lognormal severity) matches within tolerance; expired assumptions block runs; every run stores model version and input hash; UI always shows ranges, never a single bare number.

### M6 Optimizer and release hardening
PuLP/CBC ranking of discretionary spend with mandated controls as hard constraints and exclusion-delta explanations; Helm chart; compose pilot; offline bundle; SBOM; cosign; `make escrow` rebuild test; DR and ops runbooks; `PENTEST_PREP.md`; ASVS L2 checklist with evidence links; load, chaos and failover tests; final red-team loop.
Accept: bundle installs on a clean air-gapped VM from the docs alone; escrow bundle rebuilds and image digests match; no high or critical CVE; ZAP baseline clean; failover test shows no lost audit events.
