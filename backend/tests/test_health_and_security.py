"""Tests for health check endpoints and HTTP security headers."""

from fastapi.testclient import TestClient

from cyberq.api.app import app

client = TestClient(app)


def test_healthz_endpoint():
    response = client.get("/healthz")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "version" in data
    assert "environment" in data
    assert "server_time_utc" in data


def test_readyz_endpoint():
    response = client.get("/readyz")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ready"
    assert data["database"] == "connected"
    assert data["ntp_skew_seconds"] <= 1.0


def test_security_headers_and_csp():
    response = client.get("/healthz")
    headers = response.headers

    # 1. Content-Security-Policy
    assert "Content-Security-Policy" in headers
    csp = headers["Content-Security-Policy"]
    assert "default-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "https://" not in csp  # No external CDN allowlist

    # 2. Strict Security Headers
    assert headers.get("X-Content-Type-Options") == "nosniff"
    assert headers.get("X-Frame-Options") == "DENY"
    assert headers.get("Referrer-Policy") == "no-referrer"
    assert "X-Request-ID" in headers
    assert len(headers["X-Request-ID"]) > 0


def test_custom_request_id_propagation():
    custom_id = "test-req-99999"
    response = client.get("/healthz", headers={"X-Request-ID": custom_id})
    assert response.headers.get("X-Request-ID") == custom_id


def test_production_mode_refuses_default_secrets():
    import pytest

    from cyberq.core.config import EnvironmentType, Settings

    # Production mode with default dev secret must raise validation error
    with pytest.raises(
        ValueError,
        match="Production mode requires an explicitly configured, non-default SESSION_SECRET",
    ):
        Settings(ENV=EnvironmentType.PRODUCTION)
