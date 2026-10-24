"""Executable security exploit tests for Domain D: Web Client, CSP, CSRF, and Clickjacking.

Covers:
- ATTACK D-01: CSRF enforcement on state-changing endpoints (OWASP CWE-352 / ASVS V3.5.1)
- ATTACK D-02: Strict CSP and security response headers (ASVS V13.1.1)
- ATTACK D-03: Clickjacking and framing defenses (ASVS V13.1.1)
- ATTACK D-04: Stored XSS payload defense in incident metadata (CWE-79 / ASVS V5.3.1)
- ATTACK D-05: Supply chain & leak defenses: disabled sourcemaps & zero token storage in web client

Rules of Engagement:
- Imports and enforces tools/redteam/scope_guard.py.
- Uses disposable local database fixtures via conftest.py.
"""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from tools.redteam.scope_guard import enforce_scope

from cyberq.api.app import app
from cyberq.iam.policy import Role

enforce_scope("localhost")

client = TestClient(app)


@pytest.fixture(autouse=True)
def clean_cookies():
    client.cookies.clear()
    yield
    client.cookies.clear()


def test_csrf_enforced_across_all_state_changing_routes(isolated_db):
    """ATTACK D-01: Cross-Site Request Forgery on state-changing endpoints.

    Attacker forces an authenticated victim browser to trigger state-changing actions
    (POST /incidents, POST /auth/logout) without providing a valid anti-CSRF token.
    All state-changing endpoints MUST reject requests lacking valid CSRF tokens with 403 (CWE-352).
    """
    # 1. Authenticate analyst
    res = client.post(
        "/api/v1/auth/login", json={"username": "csrf_analyst", "role": Role.ANALYST.value}
    )
    session_id = res.json()["session_id"]
    valid_csrf = res.json()["csrf_token"]

    incident_payload = {
        "title": "CSRF Exploit Attempt Incident",
        "summary": "Attempting to create incident without CSRF token",
        "severity": "high",
    }

    # Attack 1: POST /incidents without CSRF header
    res_no_csrf = client.post(
        "/api/v1/incidents",
        json=incident_payload,
        headers={"X-Session-ID": session_id},
    )
    assert res_no_csrf.status_code == 403, (
        f"VULNERABILITY: State-changing endpoint allowed request without CSRF token! Status: {res_no_csrf.status_code}"
    )

    # Attack 2: POST /incidents with forged/invalid CSRF header
    res_fake_csrf = client.post(
        "/api/v1/incidents",
        json=incident_payload,
        headers={"X-Session-ID": session_id, "X-CSRF-Token": "attacker_forged_csrf_token"},
    )
    assert res_fake_csrf.status_code == 403

    # Legitimate request with valid CSRF header succeeds
    res_valid = client.post(
        "/api/v1/incidents",
        json=incident_payload,
        headers={"X-Session-ID": session_id, "X-CSRF-Token": valid_csrf},
    )
    assert res_valid.status_code == 201

    # Attack 3: POST /auth/logout without CSRF header
    res_logout_no_csrf = client.post(
        "/api/v1/auth/logout",
        headers={"X-Session-ID": session_id},
    )
    assert res_logout_no_csrf.status_code == 403


def test_strict_csp_and_frame_protection_headers():
    """ATTACK D-02 & D-03: Strict Content Security Policy, Clickjacking, and framing defense.

    Verifies bank-grade security headers:
    - X-Frame-Options: DENY (anti-clickjacking)
    - Content-Security-Policy: default-src 'self', frame-ancestors 'none', script-src 'self'
    - No external CDNs, fonts, or inline script evaluation
    """
    res = client.get("/healthz")
    headers = res.headers

    # Anti-clickjacking
    assert headers.get("X-Frame-Options") == "DENY"
    assert "frame-ancestors 'none'" in headers.get("Content-Security-Policy", "")

    # Strict CSP
    csp = headers.get("Content-Security-Policy", "")
    assert "default-src 'self'" in csp
    assert "script-src 'self'" in csp
    assert "unsafe-eval" not in csp
    # Script src must NOT contain unsafe-inline
    script_part = [p for p in csp.split(";") if "script-src" in p]
    if script_part:
        assert "'unsafe-inline'" not in script_part[0]

    # Content type and referrer controls
    assert headers.get("X-Content-Type-Options") == "nosniff"
    assert headers.get("Referrer-Policy") == "no-referrer"
    assert "camera=()" in headers.get("Permissions-Policy", "")


def test_stored_xss_in_incident_narratives(isolated_db):
    """ATTACK D-04: Stored Cross-Site Scripting (XSS) via incident narrative.

    Attacker submits malicious HTML/JavaScript payloads in incident title and summary.
    The backend API must store data as plain strings and respond with application/json,
    never text/html, preventing browser script execution contexts (CWE-79).
    """
    res = client.post(
        "/api/v1/auth/login", json={"username": "xss_tester", "role": Role.ANALYST.value}
    )
    session_id = res.json()["session_id"]
    csrf_token = res.json()["csrf_token"]

    xss_payload = "<script>alert('xss_exploit')</script><img src=x onerror=alert(1)>"
    res_create = client.post(
        "/api/v1/incidents",
        json={"title": "XSS Incident Title", "summary": xss_payload, "severity": "high"},
        headers={"X-Session-ID": session_id, "X-CSRF-Token": csrf_token},
    )
    assert res_create.status_code == 201
    assert res_create.json()["id"]

    # Retrieve incident from built list route
    res_get = client.get(
        "/api/v1/incidents",
        headers={"X-Session-ID": session_id},
    )
    assert res_get.status_code == 200
    assert "application/json" in res_get.headers.get("Content-Type", "")
    items = res_get.json()
    assert any(item["summary"] == xss_payload for item in items)


def test_frontend_build_disables_sourcemaps():
    """ATTACK D-05a: Web client source map leakage prevention.

    Verifies web/vite.config.ts explicitly sets build.sourcemap = false to prevent
    exposing frontend source code, comments, and internal logic in production.
    """
    repo_root = Path(__file__).resolve().parent.parent.parent.parent
    vite_config_path = (repo_root / "web" / "vite.config.ts").resolve()
    assert vite_config_path.is_file()
    content = vite_config_path.read_text(encoding="utf-8")
    assert "sourcemap: false" in content or 'sourcemap: "hidden"' in content


def test_zero_token_storage_in_web_client():
    """ATTACK D-05b: No credential or session token storage in browser storage.

    AGENTS.md explicitly mandates: 'No tokens in localStorage. Server-side sessions in Postgres.'
    Verifies that web client code does not reference localStorage or sessionStorage for tokens.
    """
    repo_root = Path(__file__).resolve().parent.parent.parent.parent
    web_src_dir = (repo_root / "web" / "src").resolve()
    for source_file in web_src_dir.rglob("*.tsx"):
        content = source_file.read_text(encoding="utf-8")
        assert "localStorage.setItem" not in content
        assert "sessionStorage.setItem" not in content
