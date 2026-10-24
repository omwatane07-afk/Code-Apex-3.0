"""Tests for UNIT 3: Milestone M2.5 - Multi-Agent Verification Loop Wiring."""

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from cyberq.api.app import app
from cyberq.audit.chain import AuditService
from cyberq.audit.models import AuditEvent
from cyberq.core.database import Base
from cyberq.intake.models import NormalizedSecurityEvent
from cyberq.verification.engine import VerificationTeamEngine
from cyberq.verification.models import VerificationVerdict

TEST_SEED = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"


@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


def test_11_phase_live_verification_loop_pass(db_session):
    """Verify live intake payload executes through all 11 review phases to reach PASS."""
    svc = AuditService(TEST_SEED)
    engine = VerificationTeamEngine()

    from datetime import UTC, datetime

    event = NormalizedSecurityEvent(
        event_id="EVT-LIVE-001",
        source_tool="Splunk Enterprise Security",
        vendor="Splunk",
        category="SIEM",
        timestamp=datetime.now(UTC),
        source_ip="10.14.2.55",
        destination_ip="172.16.0.4",
        cve_ids=["CVE-2024-21413"],
        signature_id="SPLUNK-LATERAL-WMI",
        event_name="WMI Process Execution Anomaly",
        severity="critical",
        raw_message="WMI command execution on RTGS gateway",
        certin_advisories=["CIVN-2024-0089: Critical Outlook NTLM Credential Theft & RCE"],
        is_telemetry_unverified=False,
    )

    inv = engine.run_live_intake_verification(
        event=event,
        audit=svc,
        db_session=db_session,
    )
    db_session.commit()

    # 1. Verification Verdict is PASS
    assert inv["final_verdict"] == VerificationVerdict.PASS.value
    assert "CIVN-2024-0089" in inv["title"] or "EVT-LIVE-001" in inv["title"]

    # 2. Check that timeline includes all required phases
    logged_phases = {
        tl["phase"]
        for tl in engine.timeline_events
        if tl["investigation_id"] == inv["id"]
    }
    assert len(logged_phases) == 11

    # 3. Canonical Evidence record created with valid SHA-256 tamper hash
    assert inv["evidence_count"] == 1
    evidence_id = f"EVD-{event.event_id[:10]}"
    assert evidence_id in engine.evidence_store
    assert len(engine.evidence_store[evidence_id]["tamper_hash"]) == 64

    # 4. Audit Event persisted in database
    audit_ev = db_session.query(AuditEvent).filter_by(action="verification:investigation_completed").first()
    assert audit_ev is not None
    assert audit_ev.entity_id == inv["id"]
    assert audit_ev.after_state["verdict"] == "PASS"


def test_11_phase_live_verification_loop_unverified_telemetry_conditional(db_session):
    """Verify expired tool VAPT triggers CONDITIONAL verdict and Quality Gate warning."""
    svc = AuditService(TEST_SEED)
    engine = VerificationTeamEngine()

    from datetime import UTC, datetime

    event = NormalizedSecurityEvent(
        event_id="EVT-LIVE-002",
        source_tool="CrowdStrike Falcon Cluster",
        vendor="CrowdStrike",
        category="EDR/XDR",
        timestamp=datetime.now(UTC),
        signature_id="FALCON-DETECT-99",
        event_name="Cobalt Strike Beacon",
        severity="critical",
        raw_message="Beaconing to external C2 server",
        is_telemetry_unverified=True,  # VAPT Expired under RBI Para 90
    )

    inv = engine.run_live_intake_verification(
        event=event,
        audit=svc,
        db_session=db_session,
    )
    db_session.commit()

    # Verdict is CONDITIONAL
    assert inv["final_verdict"] == VerificationVerdict.CONDITIONAL.value
    assert "RBI Para 90" in inv["summary"]
    assert inv["quality_gate"]["unverified_evidence_count"] == 1


def test_api_verify_live_endpoint():
    """Verify FastAPI endpoint POST /api/v1/verification/verify-live."""
    client = TestClient(app)
    payload = {
        "event_id": "EVT-API-001",
        "source_tool": "Palo Alto Networks NGFW",
        "vendor": "Palo Alto Networks",
        "category": "Firewall",
        "severity": "high",
        "cve_ids": ["CVE-2024-3400"],
        "certin_advisories": ["CIVN-2024-0131: Palo Alto PAN-OS Command Injection"],
        "is_telemetry_unverified": False,
        "raw_message": "Command injection attempt blocked on port 443",
    }
    response = client.post("/api/v1/verification/verify-live", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["final_verdict"] == "PASS"
    assert data["event_id"] == "EVT-API-001"
