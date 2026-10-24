from collections.abc import Generator
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

from cyberq.audit.chain import AuditService
from cyberq.core.database import Base
from cyberq.filings.generator import (
    generate_certin_packet,
    generate_dpdp_packet,
    generate_rbi_daksh_packet,
)
from cyberq.filings.mfa import validate_break_glass_eligibility, verify_totp_code
from cyberq.filings.models import FilingPacket
from cyberq.filings.pdf import generate_filing_pdf
from cyberq.filings.service import FilingService
from cyberq.iam.policy import Role
from cyberq.incidents.models import Incident

TEST_SEED = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"


@pytest.fixture
def db_session() -> Generator[Session, None, None]:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    session_factory = sessionmaker(bind=engine)
    session = session_factory()
    yield session
    session.close()


def test_statutory_packet_generators() -> None:
    """Verify structured packet generation for CERT-In, RBI DAKSH, and DPDP."""
    now = datetime.now(UTC)

    # 1. CERT-In
    certin = generate_certin_packet("INC-2026-0001", "Ransomware Alert", "Malware on switch", "critical", now)
    assert certin["regulator"] == "CERT-In"
    assert certin["statutory_deadline_hours"] == 6
    assert "Malicious code attacks" in certin["incident_details"]["incident_classification"]

    # 2. RBI DAKSH
    rbi = generate_rbi_daksh_packet("INC-2026-0001", "Ransomware Alert", "Malware on switch", "critical", now)
    assert rbi["regulator"] == "RBI"
    assert rbi["platform"] == "DAKSH (https://daksh.rbi.org.in)"
    assert rbi["statutory_deadline_hours"] == 6

    # 3. DPDP Board
    dpdp = generate_dpdp_packet("INC-2026-0001", "Customer account probe", now)
    assert dpdp["regulator"] == "DPDP"
    assert dpdp["statutory_deadline_hours"] == 72
    assert dpdp["breach_assessment_aggregate_only"]["customer_pii_ingested"] is False


def test_maker_checker_enforcement_and_step_up_mfa(db_session: Session) -> None:
    """Verify Maker-Checker separation and Step-Up MFA TOTP verification on approval."""
    svc = AuditService(TEST_SEED)
    filing_svc = FilingService(svc)

    inc = Incident(
        id="inc-filing-1",
        incident_number="INC-2026-0050",
        title="Unauthorized lateral movement",
        summary="Lateral movement detected on payment switch",
        severity="critical",
        created_by_id="analyst-maker",
    )
    db_session.add(inc)
    db_session.commit()

    # 1. Maker prepares packet
    packet = filing_svc.prepare_packet(
        session=db_session,
        incident_id=inc.id,
        pack_id="certin-directions-2022",
        regulator="CERT-In",
        prepared_by_id="analyst-maker",
        prepared_by_role=Role.ANALYST.value,
    )
    db_session.commit()
    assert packet.status == "draft"
    assert len(packet.packet_hash) == 64

    # 2. Maker attempting to approve own packet fails (Maker-Checker violation)
    totp_secret = pyotp.random_base32()
    totp_code = pyotp.TOTP(totp_secret).now()

    with pytest.raises(ValueError, match="Maker-Checker violation"):
        filing_svc.approve_packet(
            session=db_session,
            packet_id=packet.id,
            approver_id="analyst-maker",
            approver_role=Role.COMPLIANCE_APPROVER.value,
            otp_code=totp_code,
            totp_secret=totp_secret,
        )

    # 3. Wrong TOTP code fails
    with pytest.raises(PermissionError, match="Invalid TOTP verification code"):
        filing_svc.approve_packet(
            session=db_session,
            packet_id=packet.id,
            approver_id="compliance-checker",
            approver_role=Role.COMPLIANCE_APPROVER.value,
            otp_code="000000",
            totp_secret=totp_secret,
        )

    # 4. Valid checker with valid TOTP succeeds
    approved = filing_svc.approve_packet(
        session=db_session,
        packet_id=packet.id,
        approver_id="compliance-checker",
        approver_role=Role.COMPLIANCE_APPROVER.value,
        otp_code=totp_code,
        totp_secret=totp_secret,
    )
    db_session.commit()
    assert approved.status == "approved"
    assert approved.approval_signature is not None


def test_break_glass_protocol_and_countersignature(db_session: Session) -> None:
    """Verify 3 AM Break-Glass override eligibility, reason validation, and retrospective countersignature."""
    svc = AuditService(TEST_SEED)
    filing_svc = FilingService(svc)

    inc = Incident(
        id="inc-filing-bg",
        incident_number="INC-2026-0051",
        title="Payment gateway disruption",
        summary="Payment switch anomaly",
        severity="critical",
        created_by_id="analyst-maker",
    )
    db_session.add(inc)
    db_session.commit()

    packet = filing_svc.prepare_packet(
        session=db_session,
        incident_id=inc.id,
        pack_id="rbi-cybersecurity-directions-2026",
        regulator="RBI",
        prepared_by_id="analyst-maker",
        prepared_by_role=Role.ANALYST.value,
    )
    db_session.commit()

    # 1. Break-Glass reason under 20 chars rejected
    with pytest.raises(ValueError, match="at least 20 characters"):
        filing_svc.approve_packet(
            session=db_session,
            packet_id=packet.id,
            approver_id="compliance-checker",
            approver_role=Role.COMPLIANCE_APPROVER.value,
            is_break_glass=True,
            break_glass_reason="Emergency override",
            elapsed_minutes=40.0,
            remaining_minutes=45.0,
        )

    # 2. Break-Glass outside eligible timeline rejected (e.g. 5m elapsed, 300m remaining)
    with pytest.raises(ValueError, match="Break-Glass rejected"):
        filing_svc.approve_packet(
            session=db_session,
            packet_id=packet.id,
            approver_id="compliance-checker",
            approver_role=Role.COMPLIANCE_APPROVER.value,
            is_break_glass=True,
            break_glass_reason="Emergency override due to offline SMS gateway failure in operations",
            elapsed_minutes=5.0,
            remaining_minutes=320.0,
        )

    # 3. Valid Break-Glass approval succeeds (40m elapsed, 50m remaining)
    approved_bg = filing_svc.approve_packet(
        session=db_session,
        packet_id=packet.id,
        approver_id="compliance-checker",
        approver_role=Role.COMPLIANCE_APPROVER.value,
        is_break_glass=True,
        break_glass_reason="MFA hardware token battery drained at 3 AM; urgent RBI Para 182 deadline approaching",
        elapsed_minutes=40.0,
        remaining_minutes=50.0,
    )
    db_session.commit()
    assert approved_bg.is_break_glass is True
    assert approved_bg.break_glass_countersigned_by_id is None

    # 4. Approver attempting to countersign own Break-Glass fails
    with pytest.raises(ValueError, match="Countersignature violation"):
        filing_svc.countersign_break_glass(
            session=db_session,
            packet_id=packet.id,
            countersigner_id="compliance-checker",
            countersigner_role=Role.CISO.value,
            countersigner_dept="Office of the CISO",
            approver_dept="Compliance & Regulatory Affairs",
        )

    # 5. Same department countersignature fails (Department separation)
    with pytest.raises(ValueError, match="Department separation violation"):
        filing_svc.countersign_break_glass(
            session=db_session,
            packet_id=packet.id,
            countersigner_id="compliance-peer",
            countersigner_role=Role.COMPLIANCE_APPROVER.value,
            countersigner_dept="Compliance & Regulatory Affairs",
            approver_dept="Compliance & Regulatory Affairs",
        )

    # 6. Valid independent countersignature succeeds
    countersigned = filing_svc.countersign_break_glass(
        session=db_session,
        packet_id=packet.id,
        countersigner_id="ciso-executive",
        countersigner_role=Role.CISO.value,
        countersigner_dept="Office of the CISO",
        approver_dept="Compliance & Regulatory Affairs",
    )
    db_session.commit()
    assert countersigned.break_glass_countersigned_by_id == "ciso-executive"


def test_portal_outage_fallback_and_acknowledgement(db_session: Session) -> None:
    """Verify regulator portal downtime fallback and human receipt acknowledgement recording."""
    svc = AuditService(TEST_SEED)
    filing_svc = FilingService(svc)

    inc = Incident(
        id="inc-filing-portal",
        incident_number="INC-2026-0052",
        title="Core banking API latency",
        summary="API latency",
        severity="medium",
        created_by_id="analyst-maker",
    )
    db_session.add(inc)
    db_session.commit()

    packet = filing_svc.prepare_packet(
        session=db_session,
        incident_id=inc.id,
        pack_id="certin-directions-2022",
        regulator="CERT-In",
        prepared_by_id="analyst-maker",
        prepared_by_role=Role.ANALYST.value,
    )
    # Approve packet
    totp_secret = pyotp.random_base32()
    totp_code = pyotp.TOTP(totp_secret).now()
    filing_svc.approve_packet(
        session=db_session,
        packet_id=packet.id,
        approver_id="compliance-checker",
        approver_role=Role.COMPLIANCE_APPROVER.value,
        otp_code=totp_code,
        totp_secret=totp_secret,
    )
    db_session.commit()

    # 1. Record portal outage (504 Gateway Timeout on CERT-In portal)
    outage_pkt = filing_svc.record_portal_outage(
        session=db_session,
        packet_id=packet.id,
        filer_id="compliance-checker",
        filer_role=Role.COMPLIANCE_APPROVER.value,
        outage_notes="CERT-In portal returning HTTP 504 Gateway Timeout at Hour 5.2. Timely readiness sealed.",
    )
    db_session.commit()
    assert outage_pkt.status == "portal_outage_fallback"
    assert outage_pkt.portal_outage_sealed is True

    # 2. Human later files on backup channel and records official acknowledgement receipt
    filed_pkt = filing_svc.record_acknowledgement(
        session=db_session,
        packet_id=packet.id,
        filer_id="compliance-checker",
        filer_role=Role.COMPLIANCE_APPROVER.value,
        acknowledgement_ref="CERTIN-INC-2026-9812",
        portal_name="CERT-In Statutory Portal",
    )
    db_session.commit()
    assert filed_pkt.status == "filed"
    assert filed_pkt.acknowledgement_ref == "CERTIN-INC-2026-9812"


def test_byte_reproducible_pdf_generation() -> None:
    """Verify ReportLab PDF generation with watermark, CRC32 check-code, and byte-reproducibility."""
    packet_data = {
        "regulator": "CERT-In",
        "instrument": "CERT-In Directions (28 April 2022)",
        "internal_incident_id": "INC-2026-0001",
        "summary": "Core switch packet drop anomaly",
    }
    packet_hash = "a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0"

    # Generate twice with identical fixed SOURCE_DATE_EPOCH
    pdf1 = generate_filing_pdf(packet_data, packet_hash, "INC-2026-0001", "Compliance Approver", source_date_epoch=1767225600)
    pdf2 = generate_filing_pdf(packet_data, packet_hash, "INC-2026-0001", "Compliance Approver", source_date_epoch=1767225600)

    # Byte-for-byte reproducibility
    assert len(pdf1) > 1000
    assert pdf1 == pdf2
    assert b"STATUTORY FILING VERIFICATION CODE: CQ-" in pdf1
    assert b"%PDF" in pdf1[:10]
