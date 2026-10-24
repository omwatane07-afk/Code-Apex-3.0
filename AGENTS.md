# CYBERQ: agent constitution

You are building CYBERQ for deployment inside an Indian commercial bank. Treat every decision as if a bank IT manager, an RBI inspector and a penetration tester will read it. This file is always in force. Details live in `docs/DOMAIN_SPEC.md` and `.agents/rules/`. To run the build, use the `/cyberq-loop` workflow.

## What we are building
A bank-deployable incident-to-board layer. One security incident becomes (1) correctly timed, human-approved filing packets for CERT-In, RBI (DAKSH) and DPDP, and (2) an auditable decision ledger and quarterly Board pack, later with a rupee exposure engine and a model-validation pack.

Users: SOC analyst (prepares), compliance/incident commander (approves and files), CISO (decides, Board pack), IS auditor (read-only evidence), model-risk validator (read-only), admin (config only, cannot approve).

## Non-goals (do not build, even if tempting)
- Not a SIEM. Never ingest raw logs. Never store customer PII or account data.
- Never auto-submit to any regulator. A human files on the regulator's portal and records the acknowledgement ID.
- No runtime calls to external networks, SaaS, CDNs, fonts, analytics or LLM APIs. Everything works air-gapped.
- No real-time per-alert Monte Carlo. Exposure is scenario-level, for planning and the Board.
- Do not invent regulatory text, form fields, clause numbers or deadlines. See `.agents/rules/30-regulatory-content.md`.

## Locked stack (change only through an ADR in `docs/adr/` plus human approval)
- Architecture: modular monolith. One API process, one worker process, one PostgreSQL 16. No Redis, Kafka or Celery in v1.
- Backend: Python 3.12, FastAPI, Pydantic v2, SQLAlchemy 2 (typed), Alembic, structlog, `cryptography`, Authlib (OIDC), pyotp and argon2-cffi (break-glass only), NumPy and SciPy (exposure), PuLP with CBC (optimizer, last milestone), ReportLab (PDF).
- Jobs and timers: Postgres-backed. Deadlines are rows. The worker claims due rows with `SELECT ... FOR UPDATE SKIP LOCKED`. Timers must survive restarts and double workers.
- Frontend: React 18, TypeScript strict, Vite, React Router, TanStack Query, Tailwind CSS, Radix UI primitives (shadcn-style, copied into the repo), react-hook-form with zod, Recharts. Self-hosted IBM Plex fonts.
- Tests: pytest, Hypothesis, Schemathesis, Vitest, Testing Library, Playwright, axe-core, k6.
- Quality and supply chain: ruff, mypy --strict, bandit, semgrep, pip-audit, gitleaks, syft (CycloneDX SBOM), trivy or grype, cosign. `uv` with a hash-locked lockfile. `npm ci --ignore-scripts`.
- Packaging: OCI images (ubi-micro or distroless, non-root arbitrary UID, read-only root filesystem), Docker Compose for single-node pilots, Helm chart for Kubernetes/OpenShift, offline install bundle with checksums and signature.
- Identity: OIDC against the bank IdP (AD FS, Entra or Keycloak). Keycloak runs in dev compose only. Server-side sessions in Postgres. No tokens in localStorage.

## Repository layout
```
backend/src/cyberq/{core,iam,intake,incidents,obligations,clocks,filings,ledger,audit,exposure,governance,reports}
backend/tests/   worker/ (entrypoint only; shares backend package)
web/src/{app,features,components,lib,i18n,styles}
packs/obligations/   versioned regulatory data (YAML), never hard-coded
deploy/{compose,helm,bundle}   tools/{simulator,verify-audit,escrow}
docs/{DOMAIN_SPEC.md,STATE.md,FINDINGS.md,BLOCKERS.md,adr/}
```

## Commands (create these in M0, keep them working forever)
`make dev` | `make verify` (lint, types, unit, property, security scans) | `make e2e` | `make a11y` | `make sbom` | `make bundle` | `make escrow` (source + deps + rebuild check)
`make verify` must pass before every commit.

## Engineering rules
1. Tests first for domain logic. Clock math, authorization, maker-checker and the audit chain need property or exhaustive tests and 100% branch coverage.
2. Authorization lives in one policy module. Deny by default. Never enforce security only in the UI.
3. Every state change writes an audit event in the same DB transaction. Audit events form a hash chain. `tools/verify-audit` verifies it offline.
4. Store time in UTC. Display IST with UTC on hover. Source of truth is server time. Warn loudly if NTP skew exceeds 1 second.
5. Fail closed. If the policy engine, DB or clock source is unavailable, deny and show a clear manual-fallback message.
6. Every new dependency needs an ADR: purpose, license (allowlist: MIT, BSD, Apache-2.0, ISC, MPL-2.0, EPL-2.0, PostgreSQL, OFL), maintenance health, alternatives. Prefer the standard library.
7. Small vertical slices, conventional commits, one concern per commit. Never leave the main branch red.
8. Config through environment and mounted files. No secrets in the repo, logs, images or tests.
9. Seed and demo data is clearly labelled `DEMO`. Production mode refuses to start with demo data or unverified obligation packs.
10. Write docs as you go: ADRs for decisions, `docs/STATE.md` for progress. If it is not in STATE.md, it did not happen.

## Global definition of done (per milestone)
All acceptance tests in `docs/DOMAIN_SPEC.md` for the milestone pass; `make verify`, `make e2e` and `make a11y` are green; no open finding of severity Medium or higher in `docs/FINDINGS.md`; STATE.md updated; a walkthrough artifact with screenshots exists.

## Stop and ask the human when
- A regulatory fact, form field or clause cannot be confirmed from a primary source.
- A dependency outside the locked stack seems necessary.
- The same failure repeats three times, or a milestone exceeds five loop iterations.
- A requirement conflicts with these rules. Write the conflict to `docs/BLOCKERS.md` and stop.
