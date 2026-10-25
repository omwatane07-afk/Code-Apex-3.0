"""Tests for Dynamic Crisis Incident Simulation API endpoint."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from cyberq.api.app import app
from cyberq.core.database import Base, get_db, install_audit_immutability_triggers
from cyberq.iam.policy import Role


@pytest.fixture
def test_client_and_db():
    test_engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=test_engine)
    install_audit_immutability_triggers(test_engine)
    TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

    def _get_test_db():
        db = TestingSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = _get_test_db
    client = TestClient(app)
    try:
        yield client
    finally:
        app.dependency_overrides.clear()


def test_simulate_random_incident_success(test_client_and_db):
    """Verifies that POST /api/v1/incidents/simulate-random generates a valid incident with obligations."""
    client = test_client_and_db

    # Authenticate as Analyst (has INCIDENT_CREATE permission)
    login_res = client.post(
        "/api/v1/auth/login",
        json={"username": "analyst-01", "role": Role.ANALYST.value, "full_name": "Lead SOC Analyst"},
    )
    assert login_res.status_code == 200

    # Call simulation endpoint
    res = client.post("/api/v1/incidents/simulate-random")
    assert res.status_code == 200, res.text
    data = res.json()

    assert "id" in data
    assert data["incident_number"].startswith("INC-2026-")
    assert len(data["title"]) > 5
    assert len(data["summary"]) > 10
    assert data["severity"] in ("critical", "high", "medium", "low")
    assert data["status"] == "new"

    # Verify obligations were created
    regulators = [o["regulator"] for o in data["obligations"]]
    assert "CERT-In" in regulators
    assert "RBI" in regulators
    assert "DPDP" in regulators


def test_simulate_multiple_unique_incidents(test_client_and_db):
    """Verifies that consecutive simulation calls generate uniquely sequenced incidents."""
    client = test_client_and_db

    login_res = client.post(
        "/api/v1/auth/login",
        json={"username": "analyst-01", "role": Role.ANALYST.value, "full_name": "Lead SOC Analyst"},
    )
    assert login_res.status_code == 200

    res1 = client.post("/api/v1/incidents/simulate-random")
    res2 = client.post("/api/v1/incidents/simulate-random")

    assert res1.status_code == 200
    assert res2.status_code == 200

    inc1 = res1.json()
    inc2 = res2.json()

    assert inc1["id"] != inc2["id"]
    assert inc1["incident_number"] != inc2["incident_number"]
