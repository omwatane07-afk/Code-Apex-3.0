"""Executable security exploit tests for Domain E: Ingestion and API Surface.

Rules of Engagement:
- Imports and enforces tools/redteam/scope_guard.py.
- Uses disposable local database fixtures.
"""

from fastapi.testclient import TestClient
from tools.redteam.scope_guard import enforce_scope

from cyberq.api.app import app
from cyberq.iam.policy import Role

enforce_scope("localhost")

client = TestClient(app)


def test_mass_assignment_prevented_on_incident_create():
    """ATTACK E-01: Parameter pollution and Mass Assignment attack.

    Attacker attempts to inject unauthorized fields into incident creation:
    approved_by, status, is_triaged, deadline_override.
    Pydantic schema MUST forbid all extra fields (HTTP 422).
    """
    login_res = client.post(
        "/api/v1/auth/login",
        json={
            "username": "analyst_mass_assign",
            "role": Role.ANALYST.value,
        },
    )
    session_id = login_res.json()["session_id"]
    csrf_token = login_res.json()["csrf_token"]

    payload = {
        "title": "Legitimate Incident Title",
        "summary": "Detailed narrative of security event",
        "severity": "high",
        # Injected unauthorized parameters
        "approved_by": "attacker_user_id",
        "status": "approved",
        "override_clock_deadline": "2099-01-01T00:00:00Z",
    }

    res = client.post(
        "/api/v1/incidents",
        json=payload,
        headers={"X-Session-ID": session_id, "X-CSRF-Token": csrf_token},
    )
    assert res.status_code == 422, (
        f"VULNERABILITY CONFIRMED: Extra/unauthorized parameters were accepted! Status: {res.status_code}"
    )


def test_production_disables_openapi_and_docs():
    """ATTACK E-02: Information disclosure via API schema in production mode.

    In production mode, neither /docs nor /openapi.json may be exposed to callers.
    """
    import unittest.mock as mock

    from cyberq.api.app import create_app
    from cyberq.core.config import EnvironmentType, Settings

    prod_settings = Settings(
        ENV=EnvironmentType.PRODUCTION,
        SESSION_SECRET="production-secure-32-byte-secret-key-12345",
        AUDIT_SIGNING_SEED="fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
        COOKIE_SECURE=True,
    )

    with mock.patch("cyberq.api.app.settings", prod_settings):
        prod_app = create_app()
        prod_client = TestClient(prod_app)

        docs_res = prod_client.get("/docs")
        assert docs_res.status_code == 404, "VULNERABILITY: /docs exposed in production!"

        openapi_res = prod_client.get("/openapi.json")
        assert openapi_res.status_code == 404, "VULNERABILITY: /openapi.json exposed in production!"
