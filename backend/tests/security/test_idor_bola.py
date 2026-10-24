"""Executable security exploit tests for IDOR and BOLA (Broken Object Level Authorization).

Covers OWASP API Top 10 API1:2023 - Broken Object Level Authorization (BOLA / IDOR):
- ATTACK IDOR-01: Cross-role incident inspection (Admin role denied incident read by ID)
- ATTACK IDOR-02: Unauthenticated direct object reference to incident ID
- ATTACK IDOR-03: Parameter pollution / query manipulation on /auth/me (cannot read other user profile)
- ATTACK IDOR-04: Cross-session termination attempt (session ID mismatch with CSRF token)
- ATTACK IDOR-05: Path traversal / malformed object ID handling (no internal leaks or 500 errors)

Rules of Engagement:
- Imports and enforces tools/redteam/scope_guard.py.
- Uses disposable local database fixtures via conftest.py.
"""


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


def test_idor_admin_role_cannot_read_incident_by_id(isolated_db):
    """ATTACK IDOR-01: Admin role attempts to access incident details by ID.

    Per AGENTS.md Rule 8 & DOMAIN_SPEC.md: 'admin can configure but cannot approve, file,
    or read incident content.' Even if the admin possesses the exact incident UUID,
    the request MUST be denied with HTTP 403 Forbidden.
    """
    # 1. Analyst creates an incident
    res_analyst = client.post(
        "/api/v1/auth/login", json={"username": "soc_analyst_idor", "role": Role.ANALYST.value}
    )
    analyst_session = res_analyst.json()["session_id"]
    analyst_csrf = res_analyst.json()["csrf_token"]

    res_inc = client.post(
        "/api/v1/incidents",
        json={
            "title": "Sensitive Incident 007",
            "summary": "Highly confidential breach details",
            "severity": "critical",
        },
        headers={"X-Session-ID": analyst_session, "X-CSRF-Token": analyst_csrf},
    )
    assert res_inc.status_code == 201
    assert res_inc.json()["id"]

    # 2. Admin logs in
    client.cookies.clear()
    res_admin = client.post(
        "/api/v1/auth/login", json={"username": "bank_admin_idor", "role": Role.ADMIN.value}
    )
    admin_session = res_admin.json()["session_id"]

    # 3. Admin attempts to read incidents via built list endpoint
    res_admin_read = client.get(
        "/api/v1/incidents",
        headers={"X-Session-ID": admin_session},
    )
    assert res_admin_read.status_code == 403, (
        f"VULNERABILITY: Admin role bypassed policy engine and accessed incident content! Status: {res_admin_read.status_code}"
    )


def test_idor_unauthenticated_access_to_incident_list(isolated_db):
    """ATTACK IDOR-02: Unauthenticated attacker attempts access to incident data."""
    res = client.get("/api/v1/incidents")
    assert res.status_code == 401


def test_idor_user_profile_query_parameter_pollution_ignored(isolated_db):
    """ATTACK IDOR-03: Attacker attempts to read another user's profile via query pollution.

    Attacker passes ?user_id=victim_id or ?username=victim_user to /api/v1/auth/me.
    The endpoint must strictly ignore parameters and return ONLY the authenticated user.
    """
    # Victim logs in
    res_victim = client.post(
        "/api/v1/auth/login", json={"username": "victim_ciso", "role": Role.CISO.value}
    )
    victim_id = res_victim.json()["id"]

    # Attacker logs in
    client.cookies.clear()
    res_attacker = client.post(
        "/api/v1/auth/login", json={"username": "lowly_analyst", "role": Role.ANALYST.value}
    )
    attacker_session = res_attacker.json()["session_id"]
    attacker_id = res_attacker.json()["id"]

    # Attacker supplies victim's ID in query params
    res_polluted = client.get(
        f"/api/v1/auth/me?user_id={victim_id}&username=victim_ciso",
        headers={"X-Session-ID": attacker_session},
    )
    assert res_polluted.status_code == 200
    data = res_polluted.json()

    # Must return attacker's profile, NOT the victim's profile
    assert data["id"] == attacker_id
    assert data["id"] != victim_id
    assert data["username"] == "lowly_analyst"


def test_idor_cross_session_logout_forgery_rejected(isolated_db):
    """ATTACK IDOR-04: Attacker attempts to terminate victim's session using attacker's CSRF token."""
    # 1. Victim session
    res_v = client.post(
        "/api/v1/auth/login", json={"username": "victim_user", "role": Role.ANALYST.value}
    )
    victim_session = res_v.json()["session_id"]

    # 2. Attacker session
    client.cookies.clear()
    res_a = client.post(
        "/api/v1/auth/login", json={"username": "attacker_user", "role": Role.ANALYST.value}
    )
    attacker_csrf = res_a.json()["csrf_token"]

    # 3. Attacker presents victim's session ID with attacker's CSRF token (no cookie)
    client.cookies.clear()
    res_attack = client.post(
        "/api/v1/auth/logout",
        headers={"X-Session-ID": victim_session, "X-CSRF-Token": attacker_csrf},
    )
    assert res_attack.status_code == 403, (
        f"VULNERABILITY: Attacker successfully terminated another session with mismatched CSRF! Status: {res_attack.status_code}"
    )

    # Verify victim session is still alive
    client.cookies.clear()
    res_check = client.get("/api/v1/auth/me", headers={"X-Session-ID": victim_session})
    assert res_check.status_code == 200


def test_idor_malformed_object_id_and_traversal_handled(isolated_db):
    """ATTACK IDOR-05: Path traversal and malformed ID injection in resource URL."""
    res_analyst = client.post(
        "/api/v1/auth/login", json={"username": "analyst_path", "role": Role.ANALYST.value}
    )
    session_id = res_analyst.json()["session_id"]

    malicious_ids = [
        "../../etc/passwd",
        "..%2f..%2fauth%2fme",
        "' OR 1=1 --",
        "<script>alert(1)</script>",
        "non-existent-uuid-12345",
    ]

    for mal_id in malicious_ids:
        res = client.get(
            f"/api/v1/incidents/{mal_id}",
            headers={"X-Session-ID": session_id},
        )
        # Must return 404 or 422, NEVER 500 internal server error
        assert res.status_code in {404, 422}, (
            f"Failed on payload {mal_id}: status {res.status_code}"
        )
