"""Executable security exploit tests for Domain B: Authorization and Business Logic.

Rules of Engagement:
- Imports and enforces tools/redteam/scope_guard.py.
- Uses disposable local database fixtures.
"""

import pytest
from fastapi.testclient import TestClient
from tools.redteam.scope_guard import enforce_scope

from cyberq.api.app import app
from cyberq.iam.policy import PolicyEngine, Role

enforce_scope("localhost")

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_cookies():
    client.cookies.clear()
    yield
    client.cookies.clear()


def test_csrf_required_on_logout():
    """ATTACK B-01: Cross-Site Request Forgery on logout.

    An attacker on a malicious intranet webpage tricks a logged-in compliance officer's
    browser into issuing a POST /api/v1/auth/logout without a CSRF token.
    CYBERQ MUST require CSRF verification on all state-changing endpoints, including logout.
    """
    login_res = client.post(
        "/api/v1/auth/login",
        json={
            "username": "officer_csrf_victim",
            "role": Role.COMPLIANCE_APPROVER.value,
        },
    )
    session_id = login_res.json()["session_id"]

    # Attack: Submit POST /auth/logout without X-CSRF-Token header
    attack_res = client.post("/api/v1/auth/logout", headers={"X-Session-ID": session_id})
    assert attack_res.status_code == 403, (
        f"VULNERABILITY CONFIRMED: /auth/logout allowed unauthenticated/unprotected CSRF action! "
        f"Status: {attack_res.status_code}"
    )


def test_maker_checker_rejects_empty_whitespace_or_identical_users():
    """ATTACK B-02: Maker-checker boundary bypass attempts."""
    # Direct equality
    assert PolicyEngine.check_maker_checker("u-123", "u-123") is False
    # Case variation bypass attempt
    assert PolicyEngine.check_maker_checker("u-123", "U-123") is False
    # Zero-width character bypass attempt (\u200b)
    assert PolicyEngine.check_maker_checker("u-123\u200b", "u-123") is False
    # Non-breaking space (\u00a0) and unicode whitespace
    assert PolicyEngine.check_maker_checker("u-123\u00a0", "u-123") is False
    # Full-width unicode characters
    assert PolicyEngine.check_maker_checker("ｕｓｅｒ-1", "user-1") is False
    # Whitespace padding
    assert PolicyEngine.check_maker_checker("u-123 ", "u-123") is False
    assert PolicyEngine.check_maker_checker("   ", "u-123") is False
    # None or missing
    assert PolicyEngine.check_maker_checker("", "") is False


def test_malformed_oversized_session_id_rejected():
    """ATTACK B-03: Resource exhaustion / DB injection via massive session cookie."""
    oversized_session = "A" * 50000
    res = client.get("/api/v1/auth/me", headers={"X-Session-ID": oversized_session})
    # Should be rejected with 400 or 401 without crashing or slow querying
    assert res.status_code in {400, 401}
