# ADR-0001: technology stack

Status: proposed, awaiting human approval. Written from two viewpoints: a senior engineer who must ship and maintain this, and a bank IT manager who must approve, operate and defend it to an inspector. The bank's real approved-technology list is not known. Confirm items marked (verify) with the bank before M0 ends.

## Principles
1. Fewest moving parts that survive an audit. Each extra component is attack surface, an upgrade burden and a failure mode in a six-hour path.
2. Boring, widely supported, permissively licensed technology the bank's staff can learn.
3. Everything runs on-premises and air-gapped. No vendor-hosted dependency at runtime.
4. The bank must be able to rebuild and inspect the product (source or escrow).

## Decisions

| Area | Choice | Why the bank accepts it | Rejected, and why |
|---|---|---|---|
| Shape | Modular monolith plus one worker | One image to scan, sign, escrow and restore; simple DR | Microservices: more networks, secrets and failure modes with no scale need (an incident tool handles dozens of incidents, not millions) |
| Backend | Python 3.12, FastAPI, Pydantic v2 | Strong typing and validation at the edge, OpenAPI generated for free, mature numeric stack for the exposure engine | Java/Spring: the likelier bank house style and a valid alternative if the bank mandates it (verify); costs a second language for the Monte Carlo and optimizer code. Node: weaker numerics and larger dependency tree |
| Data | PostgreSQL 16 only | Open license, transactional, row-level controls, replication, familiar to bank DBAs | Oracle: licensing and portability; not v1 (verify the bank's DB standard). Mongo or Redis as primary store: weaker audit and consistency story |
| Timers and jobs | Deadline rows plus `FOR UPDATE SKIP LOCKED` worker | Timers share the same transaction and backup as the data; restart-safe; no broker to secure | Celery plus Redis or RabbitMQ: extra stateful services; lost-timer failure modes in exactly the path where missing a deadline is the product failure |
| Identity | OIDC to the bank IdP; server-side sessions | Reuses the bank's MFA and joiner/mover/leaver process | Own user store: a second password system to audit. JWTs in browser storage: theft risk |
| Frontend | React 18, TypeScript strict, Vite, Tailwind, Radix primitives | Largest talent pool; typed API client; accessible primitives; static bundle served by the API, so no Node at runtime | Server-rendered HTMX: smaller supply chain and a fair choice, but weaker for live clocks, keyboard-heavy tables and charts. Heavy UI kits: large trees, theming fights |
| Charts | Recharts | Adequate for loss-exceedance and trend charts, supports log axes | Full charting suites: size and licence risk |
| Reports | ReportLab (PDF), HTML print views | Pure Python, no headless browser in the image | Headless Chromium: large attack surface in the image |
| Crypto | `cryptography`, envelope encryption, KeyProvider interface | HSM-ready via PKCS#11 adapter (verify bank HSM) | Home-grown crypto: never |
| Packaging | OCI images, non-root arbitrary UID, read-only rootfs; Compose for pilots; Helm for Kubernetes and OpenShift | Works under OpenShift-style restricted policies (verify platform) | Bare-metal install scripts: drift and unauditable state |
| Supply chain | Hash-locked deps, SBOM, signed images, offline bundle, escrow rebuild | Maps directly to RBI expectations on vendor source, escrow and vulnerability-free certification | Floating versions and `latest` tags |
| Observability | structlog JSON, Prometheus metrics, optional OpenTelemetry to the bank collector, CEF/syslog of audit events to the bank SIEM | Plugs into the bank's existing monitoring; CYBERQ itself is monitored by the SOC | Vendor APM agents: phone-home risk |

## Consequences
- Python numeric libraries bring a larger native-wheel supply chain; mitigated by hash-locking, vendoring wheels in the offline bundle and scanning them.
- Single Postgres is a single point of failure; mitigated by streaming replication and a documented failover drill (M6). Design targets for RTO and RPO are written in `docs/ops/DR.md` and are targets until tested.
- If the bank mandates Java, the domain model, obligation packs, API contract and UI carry over; the backend would be re-implemented. Decide this before M1 if possible.

## Open questions for the bank (verify)
Approved OS and container platform; approved database; IdP and protocol; HSM or KMS in use; SIEM and ticketing product and the preferred integration method; email and chat relays for notifications; whether SaaS is acceptable (assumed no); internal pen-test and vendor-onboarding requirements.
