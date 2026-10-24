"""Executable security exploit tests for Domain I: Availability & Resource Abuse and Multi-Stage Attack Chains.

Rules of Engagement:
- Imports and enforces tools/redteam/scope_guard.py.
- Uses disposable local database fixtures via conftest.py.
"""

import pytest
from fastapi.testclient import TestClient
from tools.redteam.scope_guard import enforce_scope

from cyberq.api.app import app
from cyberq.api.routes_auth import clear_login_rate_limits
from cyberq.iam.policy import Role

enforce_scope("localhost")

client = TestClient(app)


@pytest.fixture(autouse=True)
def cleanup():
    clear_login_rate_limits()
    client.cookies.clear()
    yield
    clear_login_rate_limits()
    client.cookies.clear()


def test_oversized_payload_rejected_on_incident_intake(isolated_db):
    """ATTACK I-01: Oversized payload abuse / memory exhaustion on POST /api/v1/incidents.

    Attacker sends an excessive 2MB string in the incident title or summary.
    Pydantic schema max_length validator MUST reject the oversized field with HTTP 422 Unprocessable Content.
    """
    res = client.post(
        "/api/v1/auth/login",
        json={"username": "intake_analyst", "role": Role.ANALYST.value},
    )
    session_id = res.json()["session_id"]
    csrf_token = res.json()["csrf_token"]

    oversized_summary = "X" * (1024 * 1024)  # 1MB
    res_overflow = client.post(
        "/api/v1/incidents",
        json={"title": "Test Title", "summary": oversized_summary, "severity": "high"},
        headers={"X-Session-ID": session_id, "X-CSRF-Token": csrf_token},
    )
    assert res_overflow.status_code == 422
    assert "validation failed" in res_overflow.json()["message"].lower()



