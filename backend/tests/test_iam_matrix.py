"""Exhaustive Route-by-Role authorization matrix tests and maker-checker validation."""

import pytest
from fastapi.testclient import TestClient

from cyberq.api.app import app
from cyberq.core.database import Base, engine
from cyberq.iam.policy import PolicyEngine, Role

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    yield


def test_maker_checker_rule():
    # User cannot approve their own preparation
    assert PolicyEngine.check_maker_checker("user-1", "user-2") is True
    assert PolicyEngine.check_maker_checker("user-1", "user-1") is False
    assert PolicyEngine.check_maker_checker("", "user-2") is False


def test_unauthenticated_requests_denied():
    protected_routes = [
        ("GET", "/api/v1/auth/me"),
        ("GET", "/api/v1/audit/export"),
        ("GET", "/api/v1/audit/verify"),
        ("GET", "/api/v1/incidents"),
        ("POST", "/api/v1/incidents"),
    ]

    for method, path in protected_routes:
        if method == "GET":
            response = client.get(path)
        else:
            response = client.post(
                path, json={"title": "Test Title", "summary": "Detailed incident narrative"}
            )
        assert response.status_code == 401, (
            f"Expected 401 on unauthenticated {method} {path}, got {response.status_code}"
        )


def test_route_by_role_matrix():
    """Validates that each role gets precisely the expected HTTP status across API routes."""

    roles_to_test = [
        Role.ANALYST,
        Role.COMPLIANCE_APPROVER,
        Role.CISO,
        Role.AUDITOR,
        Role.MODEL_VALIDATOR,
        Role.ADMIN,
    ]

    for role in roles_to_test:
        # Log in to get session cookie and CSRF token
        login_res = client.post(
            "/api/v1/auth/login",
            json={
                "username": f"user_{role.value}",
                "role": role.value,
            },
        )
        assert login_res.status_code == 200
        user_info = login_res.json()
        csrf_token = user_info["csrf_token"]
        session_id = user_info["session_id"]

        headers = {
            "X-CSRF-Token": csrf_token,
            "X-Session-ID": session_id,
        }

        # 1. Incident Creation (Allowed ONLY to Analyst)
        post_inc = client.post(
            "/api/v1/incidents",
            json={"title": "Ransomware outbreak", "summary": "Core banking test infection summary"},
            headers=headers,
        )
        if role == Role.ANALYST:
            assert post_inc.status_code == 201, (
                f"Analyst should be permitted to create incidents, got {post_inc.status_code}"
            )
        else:
            assert post_inc.status_code == 403, (
                f"Role {role.value} must NOT be allowed to create incidents, got {post_inc.status_code}"
            )

        # 2. Audit Export (Allowed to CISO, Auditor, Model Validator; Forbidden to Analyst, Approver, Admin)
        export_res = client.get("/api/v1/audit/export", headers={"X-Session-ID": session_id})
        if role in {Role.CISO, Role.AUDITOR, Role.MODEL_VALIDATOR}:
            assert export_res.status_code == 200, (
                f"Role {role.value} should access audit export, got {export_res.status_code}"
            )
        else:
            assert export_res.status_code == 403, (
                f"Role {role.value} must NOT access audit export, got {export_res.status_code}"
            )

        # 3. Audit Verify (Allowed to Auditor, CISO, Model Validator, Admin; Forbidden to Analyst, Approver)
        verify_res = client.get("/api/v1/audit/verify", headers={"X-Session-ID": session_id})
        if role in {Role.AUDITOR, Role.CISO, Role.MODEL_VALIDATOR, Role.ADMIN}:
            assert verify_res.status_code == 200, (
                f"Role {role.value} should access audit verify, got {verify_res.status_code}"
            )
        else:
            assert verify_res.status_code == 403, (
                f"Role {role.value} must NOT access audit verify, got {verify_res.status_code}"
            )

        # Logout with CSRF token
        logout_res = client.post(
            "/api/v1/auth/logout",
            headers={"X-Session-ID": session_id, "X-CSRF-Token": csrf_token},
        )
        assert logout_res.status_code == 200


def test_csrf_token_enforcement_on_post():
    # Login as analyst
    login_res = client.post(
        "/api/v1/auth/login",
        json={
            "username": "analyst_csrf_test",
            "role": Role.ANALYST.value,
        },
    )
    session_id = login_res.json()["session_id"]

    # Try POST with valid session but WITHOUT CSRF header
    bad_res = client.post(
        "/api/v1/incidents",
        json={"title": "Ransomware outbreak", "summary": "Core banking test infection summary"},
        headers={"X-Session-ID": session_id},
    )
    assert bad_res.status_code == 403
    assert "CSRF" in bad_res.json()["message"]
