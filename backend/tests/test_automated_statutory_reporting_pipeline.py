"""Tests for STATE 3: Automated Statutory Reporting, RFC 8785 Canonical Ledger Sealing, & Maker-Checker."""

from datetime import UTC, datetime

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

try:
    import pyotp
except ImportError:
    import sys
    from pathlib import Path

    _src = str(Path(__file__).resolve().parent.parent / "src")
    if _src not in sys.path:
        sys.path.insert(0, _src)
    import pyotp

from cyberq.audit.chain import AuditService, canonical_json
from cyberq.core.database import Base
from cyberq.exposure.engine import ExposureEngine
from cyberq.governance.board_pack import generate_quarterly_board_pack_data
from cyberq.governance.reporting import StatutoryReportingPipeline
from cyberq.iam.policy import Role
from cyberq.incidents.models import Incident

TEST_SEED = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"


@pytest.fixture
def db_session() -> Session:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    session_factory = sessionmaker(bind=engine)
    session = session_factory()
    yield session
    session.close()


def test_statutory_reporting_pipeline_payload_drafting(db_session: Session) -> None:
    """Verifies that CERT-In and RBI DAKSH payloads are drafted and enriched with exposure and CVE context."""
    audit = AuditService(TEST_SEED)
    pipeline = StatutoryReportingPipeline(audit)

    inc = Incident(
        id="inc-stat-01",
        incident_number="INC-2026-0888",
        title="Command injection exploit CVE-2024-3400 on RTGS Switch",
        summary="Suspicious lateral movement detected targeting Core Banking Solution (CBS)",
        severity="critical",
        created_by_id="analyst-maker",
    )
    db_session.add(inc)
    db_session.commit()

    exposure = ExposureEngine.simulate_from_incident(inc, session=db_session, audit=audit)

    # 1. CERT-In Draft
    certin_doc = pipeline.draft_certin_payload(inc, exposure)
    assert certin_doc["regulator"] == "CERT-In"
    assert certin_doc["statutory_deadline_hours"] == 6
    assert "CVE-2024-3400" in certin_doc["incident_details"]["cve_references"]
    assert certin_doc["quantitative_exposure_context"]["p90_var_crores"] == exposure.p90_crores

    # 2. RBI DAKSH Draft
    rbi_doc = pipeline.draft_rbi_daksh_payload(inc, exposure)
    assert rbi_doc["regulator"] == "RBI"
    assert rbi_doc["supervisory_incident_data"]["cbs_rtgs_swift_impacted"] is True
    assert float(rbi_doc["supervisory_incident_data"]["estimated_financial_loss_inr_lakhs"]) > 0.0


def test_end_to_end_rfc8785_canonical_sealing_and_maker_checker(db_session: Session) -> None:
    """Verifies end-to-end sealing into audit ledger and strict Maker-Checker dual authorization."""
    audit = AuditService(TEST_SEED)
    pipeline = StatutoryReportingPipeline(audit)

    inc = Incident(
        id="inc-stat-02",
        incident_number="INC-2026-0889",
        title="Unauthorized Database Dump on CBS Oracle RAC",
        summary="Mass exfiltration alert matched CVE-2023-4966",
        severity="critical",
        created_by_id="analyst-maker",
    )
    db_session.add(inc)
    db_session.commit()

    # 1. Maker prepares and seals packet (Status: Draft)
    bundle_draft = pipeline.generate_and_seal_statutory_reports(
        session=db_session,
        incident=inc,
        preparer_id="analyst-maker-01",
        preparer_role=Role.ANALYST.value,
    )
    assert bundle_draft["certin_packet"]["status"] == "draft"
    assert bundle_draft["rbi_daksh_packet"]["status"] == "draft"
    assert len(bundle_draft["certin_packet"]["packet_hash"]) == 64
    assert bundle_draft["exposure_var"]["p90_crores"] > 0.0

    # 2. Maker attempting to approve own reports fails (Maker-Checker violation)
    totp_secret = pyotp.random_base32()
    totp_code = pyotp.TOTP(totp_secret).now()

    with pytest.raises(ValueError, match="Maker-Checker violation"):
        pipeline.generate_and_seal_statutory_reports(
            session=db_session,
            incident=inc,
            preparer_id="analyst-maker-01",
            preparer_role=Role.ANALYST.value,
            approver_id="analyst-maker-01",  # Same user!
            approver_role=Role.COMPLIANCE_APPROVER.value,
            otp_code=totp_code,
            totp_secret=totp_secret,
        )

    # 3. Authorized Checker (Compliance Approver) with valid Step-Up TOTP approves and advances state
    bundle_approved = pipeline.generate_and_seal_statutory_reports(
        session=db_session,
        incident=inc,
        preparer_id="analyst-maker-01",
        preparer_role=Role.ANALYST.value,
        approver_id="compliance-approver-02",  # Distinct user
        approver_role=Role.COMPLIANCE_APPROVER.value,
        otp_code=totp_code,
        totp_secret=totp_secret,
    )
    assert bundle_approved["certin_packet"]["status"] == "approved"
    assert bundle_approved["rbi_daksh_packet"]["status"] == "approved"
    assert bundle_approved["certin_packet"]["is_approved"] is True
    assert bundle_approved["certin_packet"]["approval_signature"] is not None
    assert bundle_approved["maker_checker_workflow"]["is_dual_authorized"] is True


def test_board_pack_integration_with_live_exposure_result(db_session: Session) -> None:
    """Verifies that generate_quarterly_board_pack_data consumes live ExposureResult metrics."""
    audit = AuditService(TEST_SEED)
    inc = Incident(
        id="inc-bp-01",
        incident_number="INC-2026-0777",
        title="Ransomware attempt on Payment Switch",
        summary="RTGS switch isolation",
        severity="critical",
        created_by_id="analyst-maker",
    )
    db_session.add(inc)
    db_session.commit()

    exposure = ExposureEngine.simulate_from_incident(inc, session=db_session, audit=audit)

    pack_data = generate_quarterly_board_pack_data(
        session=db_session,
        quarter="Q1 FY2026-27",
        lang="bilingual",
        audit=audit,
        exposure_result=exposure,
    )
    assert pack_data["report_type"] == "RBI_PARA_28_7_BOARD_RISK_PACK"
    assert pack_data["rupee_exposure_var"]["p50_expected_loss_lakhs"] == exposure.p50_lakhs
    assert pack_data["rupee_exposure_var"]["p90_var_lakhs"] == exposure.p90_lakhs
    assert pack_data["rupee_exposure_var"]["p90_var_crores"] == exposure.p90_crores
    assert len(pack_data["pack_hash"]) == 64
