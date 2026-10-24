"""Executable security exploit tests for Domain A: Identity and Session.

Rules of Engagement:
- Imports and enforces tools/redteam/scope_guard.py.
- Uses disposable local database fixtures via conftest.py.
"""

import unittest.mock as mock
import uuid

from fastapi.testclient import TestClient
from tools.redteam.scope_guard import enforce_scope

from cyberq.api.app import app
from cyberq.core.config import EnvironmentType, Settings
from cyberq.iam.policy import PolicyEngine, Role

enforce_scope("localhost")

client = TestClient(app)


def test_production_blocks_simulated_login():
    """ATTACK A-01 / SEC-08: Unauthenticated role assumption in production.

    In production environments, POST /api/v1/auth/login simulator MUST be blocked (HTTP 403)
    to prevent clients from self-assigning arbitrary roles like 'ciso' or 'admin'.
    """
    prod_settings = Settings(
        ENV=EnvironmentType.PRODUCTION,
        SESSION_SECRET="production-secure-32-byte-secret-key-12345",
        AUDIT_SIGNING_SEED="fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
        COOKIE_SECURE=True,
    )
    with mock.patch("cyberq.api.routes_auth.settings", prod_settings):
        res = client.post(
            "/api/v1/auth/login",
            json={
                "username": "attacker",
                "role": Role.CISO.value,
            },
        )
        assert res.status_code == 403, (
            f"CRITICAL VULNERABILITY: Simulated login allowed in production mode! Status: {res.status_code}"
        )
        assert "disabled in production" in res.json()["detail"]


def test_username_creation_rejects_invisible_and_non_nfkc_characters():
    """ATTACK A-02: Username injection with invisible, control, and non-NFKC characters.

    An attacker attempts to create usernames containing zero-width spaces (\u200b),
    non-breaking spaces (\u00a0), or full-width characters (\uff41) to confuse auditors
    and spoof identities.
    """
    malformed_usernames = [
        "officer\u200b",  # Zero-width space (Cf)
        "officer\u00a0one",  # Non-breaking space (Z)
        "\uff41\uff42\uff43",  # Full-width 'abc' (non-NFKC)
        "officer\x00null",  # Null byte / control character (Cc)
        "officer<script>",  # Special characters outside bank allowlist
        "officer name",  # Spaces
        "a",  # Below min length (3)
    ]
    for bad_name in malformed_usernames:
        res = client.post(
            "/api/v1/auth/login",
            json={
                "username": bad_name,
                "role": Role.ANALYST.value,
            },
        )
        assert res.status_code == 422, (
            f"VULNERABILITY: Malformed username '{repr(bad_name)}' was accepted! Status: {res.status_code}"
        )


def test_maker_checker_canonical_server_uuid_comparison():
    """ATTACK A-03: Maker-checker boundary evaluation on server-issued UUIDs.

    Ensures maker-checker compares immutable server-issued user UUIDs,
    detecting duplicate users regardless of hexadecimal formatting, casing, or hyphens.
    """
    user_uuid = uuid.uuid4()
    different_uuid = uuid.uuid4()

    # Different users: approval allowed
    assert PolicyEngine.check_maker_checker(str(user_uuid), str(different_uuid)) is True

    # Same user with standard string: rejected
    assert PolicyEngine.check_maker_checker(str(user_uuid), str(user_uuid)) is False

    # Same user with uppercase UUID: rejected
    assert PolicyEngine.check_maker_checker(str(user_uuid).upper(), str(user_uuid).lower()) is False

    # Same user with zero-width character injected: rejected
    assert PolicyEngine.check_maker_checker(f"{str(user_uuid)}\u200b", str(user_uuid)) is False

    # None or missing user: rejected
    assert PolicyEngine.check_maker_checker("", str(user_uuid)) is False
    assert PolicyEngine.check_maker_checker(str(user_uuid), "") is False
