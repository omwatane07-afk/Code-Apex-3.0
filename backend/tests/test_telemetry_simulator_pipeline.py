"""Tests for STATE 1: Telemetry Simulator & Zero-PII Boundary Scrubbing."""

from datetime import UTC, datetime
import json

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from cyberq.audit.chain import AuditService
from cyberq.core.database import Base
from cyberq.core.pii_guard import PIIGuard, validate_luhn, validate_verhoeff
from cyberq.intake.models import ToolCompliancePassport
from cyberq.intake.service import IntakePipelineService
from cyberq.intake.simulator import (
    TelemetrySimulator,
    generate_synthetic_aadhaar,
    generate_synthetic_card,
    generate_synthetic_pan,
)

TEST_SEED = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"


@pytest.fixture
def db_session() -> Session:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    session_factory = sessionmaker(bind=engine)
    session = session_factory()
    yield session
    session.close()


def test_synthetic_pii_mathematical_validity() -> None:
    """Verifies that synthetic Aadhaar passes Verhoeff, Card passes Luhn, and PAN matches regex."""
    for i in range(10):
        # 1. Aadhaar
        aadhaar = generate_synthetic_aadhaar(i, format_style=0)
        digits = "".join(filter(str.isdigit, aadhaar))
        assert len(digits) == 12
        assert validate_verhoeff(digits) is True
        assert digits[0] in "23456789"

        # 2. Card
        card = generate_synthetic_card(i, format_style=0)
        card_digits = "".join(filter(str.isdigit, card))
        assert len(card_digits) == 16
        assert validate_luhn(card_digits) is True

        # 3. PAN
        pan = generate_synthetic_pan(i)
        assert len(pan) == 10
        findings = PIIGuard.scan(pan)
        assert any(f["type"] == "PAN" for f in findings)


def test_telemetry_simulator_webhook_generation() -> None:
    """Verifies generation of CrowdStrike, Splunk, Palo Alto CEF, and Imperva webhooks."""
    sim = TelemetrySimulator(seed=101)

    # CrowdStrike
    tool, body, headers = sim.generate_crowdstrike_event(cve="CVE-2024-3400", include_pii=True)
    assert tool == "crowdstrike"
    data = json.loads(body.decode("utf-8"))
    assert "CS-DETECTION" in data["composite_id"]
    assert "Mimikatz" in data["event"]["CommandLine"]

    # Splunk
    tool, body, headers = sim.generate_splunk_event(cve="CVE-2023-4966", include_pii=True)
    assert tool == "splunk"
    data = json.loads(body.decode("utf-8"))
    assert "SPLUNK-ALERT" in data["result"]["sid"]

    # Palo Alto CEF
    tool, body, headers = sim.generate_palo_alto_cef(cve="CVE-2024-3400", include_pii=True)
    assert tool == "palo_alto_cef"
    assert body.startswith(b"CEF:0|Palo Alto Networks")

    # Imperva DAM
    tool, body, headers = sim.generate_imperva_dam_alert(include_pii=True)
    assert tool == "imperva"
    data = json.loads(body.decode("utf-8"))
    assert "IMP-DAM" in data["alertId"]


def test_zero_pii_boundary_scrubbing_and_incident_creation(db_session: Session) -> None:
    """Verifies that telemetry with synthetic PII is scrubbed before database persistence."""
    audit = AuditService(TEST_SEED)
    intake_svc = IntakePipelineService(audit)
    sim = TelemetrySimulator(seed=202)

    # 1. Ingest CrowdStrike event with PII
    _, raw_body, headers = sim.generate_crowdstrike_event(
        cve="CVE-2024-3400",
        target_asset="RTGS-SWITCH-01",
        include_pii=True,
    )
    raw_text = raw_body.decode("utf-8")
    assert any(token in raw_text for token in ("--filter-user-aadhaar", "--export-card", "--pan"))

    event, incident = intake_svc.ingest_webhook(
        session=db_session,
        tool_identifier="crowdstrike",
        raw_body=raw_body,
        headers=headers,
        client_ip="10.14.2.55",
    )
    db_session.commit()

    assert incident is not None
    assert incident.severity in ("high", "critical")
    # Assert Zero-PII gate: raw numbers must NOT exist in the incident summary
    for finding in PIIGuard.scan(raw_text):
        match_val = finding["match"]
        assert match_val not in incident.summary, f"Raw PII '{match_val}' leaked into incident.summary!"
    assert "[REDACTED_" in incident.summary

    # 2. Ingest Splunk alert with PII
    _, raw_body_spl, headers_spl = sim.generate_splunk_event(
        cve="CVE-2023-4966",
        target_asset="CBS-CORE-DB",
        include_pii=True,
    )
    event_spl, incident_spl = intake_svc.ingest_webhook(
        session=db_session,
        tool_identifier="splunk",
        raw_body=raw_body_spl,
        headers=headers_spl,
        client_ip="10.0.1.20",
    )
    db_session.commit()
    assert incident_spl is not None
    assert "[REDACTED_" in incident_spl.summary


def test_telemetry_batch_simulation_and_ingestion(db_session: Session) -> None:
    """Verifies high-volume batch simulation and automated incident intake."""
    audit = AuditService(TEST_SEED)
    intake_svc = IntakePipelineService(audit)
    sim = TelemetrySimulator(seed=777)

    results = sim.simulate_and_ingest(
        session=db_session,
        intake_service=intake_svc,
        count=8,
        pii_rate=0.75,
    )
    assert len(results) == 8
    created_incidents = [inc for _, inc in results if inc is not None]
    assert len(created_incidents) >= 4  # High/critical threats trigger incidents
