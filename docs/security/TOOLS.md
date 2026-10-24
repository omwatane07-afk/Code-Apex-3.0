# Red Team & Security Testing Tools Inventory

This document registers all offensive testing, fuzzing, scanning, and analysis tooling used during security reviews.  
**Rule of Engagement 6:** None of these tools are permitted into production runtime dependencies, container images, or the software bill of materials (SBOM).

---

## 1. Scope & Execution Guards
- **`tools/redteam/scope_guard.py`**: Mandatory runtime interceptor verifying that all network requests and DB targets match `tools/redteam/scope.json`. Enforces immediate abort and blocker escalation on any out-of-scope egress.
- **`tools/redteam/scope.json`**: Strictly defines allowed hosts (`localhost`, `127.0.0.1`, `testserver`, Docker Compose local network).

## 2. Test Harnesses & Automated Attack Suites
- **`pytest` & `pytest-asyncio`**: Test runner for executable security exploit test suites under `backend/tests/security/`.
- **`starlette.testclient.TestClient` / `httpx`**: HTTP in-memory driver simulating browser and external client requests against the ASGI application.
- **`hypothesis`**: Property-based fuzzing library for clock manipulation, input boundary testing, and deserialization attacks.
- **`schemathesis`**: Property-based API fuzzer testing OpenAPI endpoints against negative schemas and boundary values.
- **`bandit`**: AST-based static vulnerability scanner for Python.
- **`ruff`**: Static analysis engine covering security (`S`) and bugbear (`B`) lint rules.
- **`vitest`**: Frontend testing engine executing WCAG 2.1 AA mathematical contrast ratios and accessibility evaluations.

## 3. Sandboxed Database & Snapshot Strategy
- In-memory SQLite and dedicated disposable local PostgreSQL containers.
- State is rebuilt per test fixture (`@pytest.fixture(autouse=True)`), ensuring zero cross-test persistence or destructive side-effects.
