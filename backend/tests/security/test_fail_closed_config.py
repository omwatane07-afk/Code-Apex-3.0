"""Executable tests proving fail-closed configuration and production hardening.

Enforces:
1. Unset, empty, or misspelled CYBERQ_ENV defaults strictly to production.
2. In production, LocalKeyProvider fails to initialize (HSM required).
3. In production, header-based session tokens are rejected (HTTP 403).
4. In production, insecure transport is rejected (HTTP 403).
5. In production, OpenAPI and Swagger debug documentation routes are not mounted.
"""

from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from tools.redteam.scope_guard import enforce_scope

from cyberq.api.app import create_app
from cyberq.audit.crypto import LocalKeyProvider
from cyberq.core.config import EnvironmentType, Settings
from cyberq.iam.models import User
from cyberq.iam.policy import Role
from cyberq.iam.session import SessionManager

enforce_scope("localhost")


def test_env_unset_or_unrecognized_defaults_to_production(monkeypatch):
    """Prove that unset, empty, or misspelled CYBERQ_ENV defaults to EnvironmentType.PRODUCTION."""
    # 1. Unrecognized misspelled value via kwarg
    s1 = Settings(
        ENV="prduction",
        SESSION_SECRET="a" * 32,
        AUDIT_SIGNING_SEED="f" * 64,
    )
    assert s1.ENV == EnvironmentType.PRODUCTION
    assert s1.is_production() is True

    # 2. Empty string via kwarg
    s2 = Settings(
        ENV="",
        SESSION_SECRET="a" * 32,
        AUDIT_SIGNING_SEED="f" * 64,
    )
    assert s2.ENV == EnvironmentType.PRODUCTION

    # 3. Capitalized or whitespace-padded string
    s3 = Settings(
        ENV="  Production  ",
        SESSION_SECRET="a" * 32,
        AUDIT_SIGNING_SEED="f" * 64,
    )
    assert s3.ENV == EnvironmentType.PRODUCTION

    # 4. Via environment variable CYBERQ_ENV
    monkeypatch.setenv("CYBERQ_ENV", "invalid_random_string")
    monkeypatch.setenv("CYBERQ_SESSION_SECRET", "b" * 32)
    monkeypatch.setenv("CYBERQ_AUDIT_SIGNING_SEED", "e" * 64)
    s4 = Settings()
    assert s4.ENV == EnvironmentType.PRODUCTION
    assert s4.is_production() is True

    # 5. Explicit demo or pilot
    s_demo = Settings(ENV="demo")
    assert s_demo.ENV == EnvironmentType.DEMO
    assert s_demo.is_production() is False


def test_local_key_provider_rejected_in_production():
    """Prove that LocalKeyProvider raises ValueError when CYBERQ_ENV is production."""
    prod_settings = Settings(
        ENV="production",
        SESSION_SECRET="prod-session-secret-must-be-very-long-32-chars",
        AUDIT_SIGNING_SEED="1" * 64,
    )
    with patch("cyberq.core.config.get_settings", return_value=prod_settings):
        with pytest.raises(
            ValueError,
            match="LocalKeyProvider is strictly forbidden in production mode",
        ):
            LocalKeyProvider("1" * 64)


def test_header_based_tokens_rejected_in_production(isolated_db):
    """Prove that header-based session tokens return HTTP 403 in production mode."""
    prod_settings = Settings(
        ENV="production",
        SESSION_SECRET="prod-session-secret-must-be-very-long-32-chars",
        AUDIT_SIGNING_SEED="1" * 64,
    )

    TestingSessionLocal = isolated_db
    db = TestingSessionLocal()
    try:
        user = User(
            username="prod_user",
            email="prod_user@bank.internal",
            full_name="Prod User",
            is_active=True,
        )
        db.add(user)
        db.commit()
        session = SessionManager.create_session(db, user, Role.ANALYST)

        with patch("cyberq.api.deps.settings", prod_settings):
            app = create_app()
            client = TestClient(app, base_url="https://testserver")

            # Attempt 1: Present X-Session-ID header in production
            res_hdr = client.get(
                "/api/v1/auth/me",
                headers={"X-Session-ID": session.id, "X-Forwarded-Proto": "https"},
            )
            assert res_hdr.status_code == 403
            assert "header-based authentication tokens are strictly forbidden" in res_hdr.json()["detail"].lower()

            # Attempt 2: Present Authorization Bearer header in production
            res_bearer = client.get(
                "/api/v1/auth/me",
                headers={"Authorization": f"Bearer {session.id}", "X-Forwarded-Proto": "https"},
            )
            assert res_bearer.status_code == 403
            assert "header-based authentication tokens are strictly forbidden" in res_bearer.json()["detail"].lower()
    finally:
        db.close()


def test_insecure_transport_rejected_in_production(isolated_db):
    """Prove that insecure non-HTTPS requests return HTTP 403 in production mode."""
    prod_settings = Settings(
        ENV="production",
        SESSION_SECRET="prod-session-secret-must-be-very-long-32-chars",
        AUDIT_SIGNING_SEED="1" * 64,
    )

    TestingSessionLocal = isolated_db
    db = TestingSessionLocal()
    try:
        user = User(
            username="prod_cookie_user",
            email="prod_cookie_user@bank.internal",
            full_name="Prod Cookie User",
            is_active=True,
        )
        db.add(user)
        db.commit()
        session = SessionManager.create_session(db, user, Role.ANALYST)

        with patch("cyberq.api.deps.settings", prod_settings):
            app = create_app()
            client = TestClient(app, base_url="http://testserver")
            client.cookies.set("cyberq_session", session.id)

            # Request over plain http with no https forwarded proto
            res = client.get(
                "/api/v1/auth/me",
                headers={"X-Forwarded-Proto": "http"},
            )
            assert res.status_code == 403
            assert "insecure transport" in res.json()["detail"].lower()
    finally:
        db.close()


def test_untrusted_proxy_x_forwarded_proto_spoofing_rejected(isolated_db):
    """ATTACK G-05: Untrusted proxy X-Forwarded-Proto spoofing rejection.

    An attacker on the external network sends plain HTTP with X-Forwarded-Proto: https.
    CYBERQ MUST verify that the immediate peer is in TRUSTED_PROXIES before honoring
    the forwarded protocol header. Requests from untrusted proxies MUST be rejected (403).
    """
    prod_settings = Settings(
        ENV="production",
        SESSION_SECRET="prod-session-secret-must-be-very-long-32-chars",
        AUDIT_SIGNING_SEED="1" * 64,
        TRUSTED_PROXIES=["10.0.0.1"],  # 'testserver' is untrusted
    )

    TestingSessionLocal = isolated_db
    db = TestingSessionLocal()
    try:
        user = User(
            username="spoof_victim",
            email="spoof_victim@bank.internal",
            full_name="Spoof Victim",
            is_active=True,
        )
        db.add(user)
        db.commit()
        session = SessionManager.create_session(db, user, Role.ANALYST)

        with patch("cyberq.api.deps.settings", prod_settings):
            app = create_app()
            client = TestClient(app, base_url="http://testserver")
            client.cookies.set("cyberq_session", session.id)

            # Attack: Attempt to spoof HTTPS via header from untrusted proxy
            res = client.get(
                "/api/v1/auth/me",
                headers={"X-Forwarded-Proto": "https"},
            )
            assert res.status_code == 403
            assert "insecure transport" in res.json()["detail"].lower()
    finally:
        db.close()


def test_debug_routes_not_mounted_in_production():
    """Prove that Swagger /docs and /openapi.json are not mounted when CYBERQ_ENV is production."""
    prod_settings = Settings(
        ENV="production",
        SESSION_SECRET="prod-session-secret-must-be-very-long-32-chars",
        AUDIT_SIGNING_SEED="1" * 64,
    )
    with patch("cyberq.api.app.settings", prod_settings):
        app = create_app()
        client = TestClient(app)

        res_docs = client.get("/docs")
        assert res_docs.status_code == 404

        res_openapi = client.get("/openapi.json")
        assert res_openapi.status_code == 404
