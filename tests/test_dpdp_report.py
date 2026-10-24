"""Tests for DPDP Rule 7 Breach Notification report pipeline, 72h countdown timer, and RBAC."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from cyberq.api.app import app
from cyberq.audit.chain import AuditService
from cyberq.audit.models import AuditEvent
from cyberq.core.database import Base, get_db, install_audit_immutability_triggers
from cyberq.governance.dpdp import (
    AudienceType,
    DpdpBreachReportData,
    DpdpReportService,
    evaluate_72h_timer,
)
from cyberq.iam.policy import Role
from cyberq.incidents.models import Incident, IncidentTrigger, StatutoryTriggerType

TEST_SEED = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"


@pytest.fixture(scope="session")
def test_client() -> TestClient:
    return TestClient(app)


@pytest.fixture
def isolated_db_session():
    """In-memory SQLite session with triggers and app dependency override."""
    test_engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=test_engine)
    install_audit_immutability_triggers(test_engine)
    TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)
    session = TestingSession()

    def _get_test_db():
        db = TestingSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = _get_test_db
    yield session
    session.close()
    app.dependency_overrides.pop(get_db, None)


def _login(test_client: TestClient, role: Role, username: str | None = None) -> dict[str, str]:
    test_client.cookies.clear()
    uname = username or f"user_{role.value}"
    res = test_client.post(
        "/api/v1/auth/login",
        json={"username": uname, "role": role.value},
    )
    assert res.status_code == 200, res.text
    data = res.json()
    return {
        "X-CSRF-Token": data["csrf_token"],
    }


def _create_test_dpdp_incident(
    session: Session,
    incident_number: str = "INC-2026-DPDP-01",
    aware_hours_ago: float = 2.0,
) -> Incident:
    now = datetime.now(UTC)
    aware_time = now - timedelta(hours=aware_hours_ago)

    incident = Incident(
        incident_number=incident_number,
        title="Unauthorized ISO-8583 Message Broker Query Burst",
        summary="Suspicious test script querying ISO-8583 broker with elevated API token.",
        severity="critical",
        status="contained",
        created_at=aware_time,
        created_by_id="analyst-01",
    )
    session.add(incident)
    session.flush()

    trigger = IncidentTrigger(
        incident_id=incident.id,
        trigger_type=StatutoryTriggerType.AWARE.value,
        occurred_at=aware_time,
        recorded_at=aware_time,
        asserted_by_id="analyst-01",
        evidence_summary="SOC log correlation alerted on message broker credential stuffing",
        rationale="Bank became aware of personal data breach risk at message broker gateway",
    )
    session.add(trigger)
    session.commit()
    return incident


# ============================================================================
# STATE 2: 72-HOUR COUNTDOWN TIMER TESTS
# ============================================================================


def test_dpdp_72h_timer_running() -> None:
    """Verifies that an incident aware 10h ago has 62h remaining and RUNNING status."""
    now = datetime(2026, 10, 24, 12, 0, tzinfo=UTC)
    aware_time = now - timedelta(hours=10)

    timer_status = evaluate_72h_timer(became_aware_at=aware_time, now=now)

    assert timer_status.status == "RUNNING"
    assert timer_status.is_expired is False
    assert timer_status.should_auto_trigger is False
    assert timer_status.hours_remaining == 62.0
    assert timer_status.deadline_at_utc == aware_time + timedelta(hours=72)
    assert len(timer_status.became_aware_ist) > 10
    assert len(timer_status.deadline_72h_ist) > 10


def test_dpdp_72h_timer_due_soon() -> None:
    """Verifies that an incident aware 65h ago has 7h remaining and DUE_SOON status."""
    now = datetime(2026, 10, 24, 12, 0, tzinfo=UTC)
    aware_time = now - timedelta(hours=65)

    timer_status = evaluate_72h_timer(became_aware_at=aware_time, now=now)

    assert timer_status.status == "DUE_SOON"
    assert timer_status.is_expired is False
    assert timer_status.hours_remaining == 7.0


def test_dpdp_72h_timer_critical() -> None:
    """Verifies that an incident aware 70h ago has 2h remaining and CRITICAL status."""
    now = datetime(2026, 10, 24, 12, 0, tzinfo=UTC)
    aware_time = now - timedelta(hours=70)

    timer_status = evaluate_72h_timer(became_aware_at=aware_time, now=now)

    assert timer_status.status == "CRITICAL"
    assert timer_status.is_expired is False
    assert timer_status.hours_remaining == 2.0


def test_dpdp_72h_timer_breached_and_triggers_report() -> None:
    """Verifies that an incident aware 73h ago is expired and triggers report generation."""
    now = datetime(2026, 10, 24, 12, 0, tzinfo=UTC)
    aware_time = now - timedelta(hours=73)

    timer_status = evaluate_72h_timer(became_aware_at=aware_time, now=now)

    assert timer_status.status == "BREACHED"
    assert timer_status.is_expired is True
    assert timer_status.should_auto_trigger is True
    assert timer_status.hours_remaining == -1.0


# ============================================================================
# STATE 1 & 3: TEMPLATE DATA BINDING & DYNAMIC AUDIENCE SECTIONS
# ============================================================================


def test_dpdp_data_binding_and_verification_code(isolated_db_session: Session) -> None:
    """Verifies data binding maps incident fields into DpdpBreachReportData."""
    incident = _create_test_dpdp_incident(isolated_db_session, "INC-2026-DPDP-02")

    report_data = DpdpReportService.bind_incident_data(
        incident=incident,
        target_audience=AudienceType.INTERNAL,
        actor_name="Maya Sundaram",
        actor_role="ciso",
    )

    assert isinstance(report_data, DpdpBreachReportData)
    assert report_data.incident_id == "INC-2026-DPDP-02"
    assert report_data.target_audience == AudienceType.INTERNAL
    assert report_data.include_internal_sections is True
    assert report_data.verification_code.startswith("CQ-DPDP-")
    assert "Apex Bank" in report_data.bank_legal_name
    assert "Switch Gateway" in report_data.affected_systems
    assert "ISO-8583" in report_data.breach_nature


def test_dpdp_template_dynamic_sections_internal_vs_dpb(isolated_db_session: Session) -> None:
    """Verifies Sections 7–10 and checklist are present in 'internal' and excluded from 'dpb'."""
    incident = _create_test_dpdp_incident(isolated_db_session, "INC-2026-DPDP-03")

    # 1. Internal CISO Review
    internal_data = DpdpReportService.bind_incident_data(
        incident=incident,
        target_audience=AudienceType.INTERNAL,
    )
    internal_html = DpdpReportService.render_html(internal_data)

    assert "1. Data Fiduciary Details" in internal_html
    assert "2. Breach Identification (DPDP Lens)" in internal_html
    assert "3. Initial Intimation to DPB" in internal_html
    assert "4. Detailed Report to DPB" in internal_html
    assert "5. Notification to Affected Data Principals" in internal_html
    assert "6. Regulatory Interplay Note" in internal_html

    # Internal-only sections MUST be included
    assert "7. DPDP Evidence &amp; Production Register" in internal_html
    assert "8. RBI Forensic Clearance Requirement" in internal_html
    assert "9. Penalty Exposure (Head-Team Briefing)" in internal_html
    assert "10. Sign-off" in internal_html
    assert "Pre-submission Checklist (CISO)" in internal_html

    # 2. DPB Submission
    dpb_data = DpdpReportService.bind_incident_data(
        incident=incident,
        target_audience=AudienceType.DPB,
    )
    dpb_html = DpdpReportService.render_html(dpb_data)

    assert "1. Data Fiduciary Details" in dpb_html
    assert "2. Breach Identification (DPDP Lens)" in dpb_html
    assert "3. Initial Intimation to DPB" in dpb_html
    assert "4. Detailed Report to DPB" in dpb_html
    assert "5. Notification to Affected Data Principals" in dpb_html
    assert "6. Regulatory Interplay Note" in dpb_html

    # Internal-only sections MUST be excluded from DPB submission
    assert "7. DPDP Evidence &amp; Production Register" not in dpb_html
    assert "8. RBI Forensic Clearance Requirement" not in dpb_html
    assert "9. Penalty Exposure (Head-Team Briefing)" not in dpb_html
    assert "10. Sign-off" not in dpb_html
    assert "Pre-submission Checklist (CISO)" not in dpb_html


def test_dpdp_pdf_generation_bytes_and_sealing(isolated_db_session: Session) -> None:
    """Verifies PDF generation returns valid bytes and writes immutable audit seal."""
    audit = AuditService(TEST_SEED)
    incident = _create_test_dpdp_incident(isolated_db_session, "INC-2026-DPDP-04")

    pdf_bytes, pdf_sha256, verification_code, report_data = (
        DpdpReportService.generate_and_seal_dpdp_report(
            session=isolated_db_session,
            incident=incident,
            audit=audit,
            actor_id="ciso-user",
            actor_role="ciso",
            target_audience=AudienceType.INTERNAL,
        )
    )
    isolated_db_session.commit()

    assert pdf_bytes.startswith(b"%PDF")
    assert hashlib.sha256(pdf_bytes).hexdigest() == pdf_sha256
    assert verification_code.startswith("CQ-DPDP-")

    # Verify audit trail event recorded
    audit_event = isolated_db_session.scalar(
        select(AuditEvent)
        .where(AuditEvent.entity_id == incident.id)
        .where(AuditEvent.action == "report:dpdp_sealed")
    )
    assert audit_event is not None
    assert audit_event.after_state["verification_code"] == verification_code
    assert audit_event.after_state["packet_hash"] == pdf_sha256
    assert audit_event.after_state["target_audience"] == "internal"


# ============================================================================
# STATE 2 & 3: EMERGENCY TRIGGER & RBAC ENDPOINT TESTS
# ============================================================================


def test_emergency_trigger_endpoint_as_ciso(
    test_client: TestClient, isolated_db_session: Session
) -> None:
    """Verifies that CISO can trigger manual emergency report generation."""
    incident = _create_test_dpdp_incident(isolated_db_session, "INC-2026-DPDP-05")
    headers = _login(test_client, Role.CISO, "ciso_maya")

    res = test_client.post(
        f"/api/v1/incidents/{incident.id}/dpdp-report/trigger",
        headers=headers,
        json={"reason": "Urgent emergency board briefing requested by CRO", "target_audience": "internal"},
    )
    assert res.status_code == 200, res.text
    data = res.json()

    assert data["status"] == "triggered"
    assert data["incident_id"] == incident.id
    assert data["incident_number"] == "INC-2026-DPDP-05"
    assert data["trigger_type"] == "emergency_manual"
    assert data["verification_code"].startswith("CQ-DPDP-")
    assert len(data["packet_hash"]) == 64
    assert data["timer_status"]["status"] in {"RUNNING", "DUE_SOON", "CRITICAL", "BREACHED"}


def test_emergency_trigger_endpoint_as_dpo(
    test_client: TestClient, isolated_db_session: Session
) -> None:
    """Verifies that DPO can trigger manual emergency DPDP report generation."""
    incident = _create_test_dpdp_incident(isolated_db_session, "INC-2026-DPDP-06")
    headers = _login(test_client, Role.DPO, "dpo_kavita")

    res = test_client.post(
        f"/api/v1/incidents/{incident.id}/dpdp-report/trigger",
        headers=headers,
        json={"reason": "Preparation for DPB 72-hour filing", "target_audience": "dpb"},
    )
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["status"] == "triggered"


def test_download_endpoint_ciso_allowed_internal(
    test_client: TestClient, isolated_db_session: Session
) -> None:
    """Verifies that CISO can download full internal DPDP report PDF."""
    incident = _create_test_dpdp_incident(isolated_db_session, "INC-2026-DPDP-07")
    headers = _login(test_client, Role.CISO, "ciso_maya")

    res = test_client.get(
        f"/api/v1/incidents/{incident.id}/dpdp-report/download?audience=internal",
        headers=headers,
    )
    assert res.status_code == 200, res.text
    assert res.headers["content-type"] == "application/pdf"
    assert "attachment" in res.headers["content-disposition"]
    assert res.headers["X-Statutory-Verification-Code"].startswith("CQ-DPDP-")
    assert res.headers["X-Audience"] == "internal"
    assert res.headers["X-Internal-Sections-Included"] == "True"
    assert res.content.startswith(b"%PDF")


def test_download_endpoint_dpo_allowed_dpb(
    test_client: TestClient, isolated_db_session: Session
) -> None:
    """Verifies that DPO can download DPB-filtered report PDF."""
    incident = _create_test_dpdp_incident(isolated_db_session, "INC-2026-DPDP-08")
    headers = _login(test_client, Role.DPO, "dpo_kavita")

    res = test_client.get(
        f"/api/v1/incidents/{incident.id}/dpdp-report/download?audience=dpb",
        headers=headers,
    )
    assert res.status_code == 200, res.text
    assert res.headers["content-type"] == "application/pdf"
    assert res.headers["X-Audience"] == "dpb"
    assert res.headers["X-Internal-Sections-Included"] == "False"
    assert res.content.startswith(b"%PDF")


def test_download_endpoint_compliance_approver_allowed(
    test_client: TestClient, isolated_db_session: Session
) -> None:
    """Verifies that Compliance Approver can download DPDP report PDF."""
    incident = _create_test_dpdp_incident(isolated_db_session, "INC-2026-DPDP-09")
    headers = _login(test_client, Role.COMPLIANCE_APPROVER, "approver_suresh")

    res = test_client.get(
        f"/api/v1/incidents/{incident.id}/dpdp-report/download",
        headers=headers,
    )
    assert res.status_code == 200, res.text
    assert res.headers["content-type"] == "application/pdf"


def test_download_endpoint_l1_analyst_strictly_forbidden(
    test_client: TestClient, isolated_db_session: Session
) -> None:
    """Verifies that L1 Analyst is strictly blocked with HTTP 403 Forbidden."""
    incident = _create_test_dpdp_incident(isolated_db_session, "INC-2026-DPDP-10")
    headers = _login(test_client, Role.ANALYST, "analyst_arjun")

    res = test_client.get(
        f"/api/v1/incidents/{incident.id}/dpdp-report/download",
        headers=headers,
    )
    assert res.status_code == 403, "L1 Analyst must receive HTTP 403 Forbidden"


def test_download_endpoint_unauthenticated_rejected(
    test_client: TestClient, isolated_db_session: Session
) -> None:
    """Verifies that unauthenticated request is rejected with HTTP 401 Unauthorized."""
    incident = _create_test_dpdp_incident(isolated_db_session, "INC-2026-DPDP-11")
    test_client.cookies.clear()

    res = test_client.get(f"/api/v1/incidents/{incident.id}/dpdp-report/download")
    assert res.status_code == 401, "Unauthenticated request must receive HTTP 401 Unauthorized"


def test_download_endpoint_nonexistent_incident_returns_404(
    test_client: TestClient, isolated_db_session: Session
) -> None:
    """Verifies that requesting non-existent incident returns HTTP 404 Not Found."""
    headers = _login(test_client, Role.CISO, "ciso_maya")

    res = test_client.get(
        "/api/v1/incidents/NONEXISTENT-INC-9999/dpdp-report/download",
        headers=headers,
    )
    assert res.status_code == 404, "Nonexistent incident must return HTTP 404 Not Found"
