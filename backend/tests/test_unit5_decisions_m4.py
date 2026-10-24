"""Unit 5: Milestone M4 — Governance Decisions, Board Pack & Bilingual Localization Tests."""

from datetime import UTC, datetime, timedelta
import uuid

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from cyberq.audit.chain import AuditService
from cyberq.core.database import Base
from cyberq.governance.board_pack import (
    generate_board_pack_pdf,
    generate_quarterly_board_pack_data,
)
from cyberq.governance.localization import (
    get_bilingual_label,
    get_token,
    localize_dict,
)
from cyberq.governance.models import Para59Exception, RiskDecision
from cyberq.iam.models import User, UserSession
from cyberq.iam.policy import Action, AuthContext, PolicyEngine, Role
from cyberq.incidents.models import Incident


@pytest.fixture
def db_session() -> Session:
    """In-memory SQLite database session fixture."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    session_factory = sessionmaker(bind=engine)
    session = session_factory()

    # Seed test users
    ciso_user = User(
        id="ciso-user-01",
        username="ciso",
        email="ciso@bank.co.in",
        full_name="Chief Information Security Officer",
        is_active=True,
    )
    compliance_user = User(
        id="compliance-user-01",
        username="approver",
        email="approver@bank.co.in",
        full_name="Chief Compliance Approver",
        is_active=True,
    )
    session.add_all([ciso_user, compliance_user])
    session.commit()

    yield session
    session.close()


def test_bilingual_localization() -> None:
    """Verifies statutory English and Rajbhasha Hindi translations and bilingual labeling."""
    # Regulator tokens
    assert get_token("rbi", "en") == "Reserve Bank of India (RBI)"
    assert "भारतीय रिज़र्व बैंक" in get_token("rbi", "hi")
    assert "सर्ट-इन" in get_token("cert-in", "hi")
    assert "डीपीडीपी" in get_token("dpdp", "hi")

    # Risk Decisions
    assert get_token("ACCEPT", "hi") == "जोखिम स्वीकृति"
    assert get_token("MITIGATE", "hi") == "जोखिम शमन"
    assert get_token("TRANSFER", "hi") == "जोखिम अंतरण"
    assert get_token("AVOID", "hi") == "जोखिम परिहार"

    # Bilingual combined labels
    bilingual_accept = get_bilingual_label("ACCEPT")
    assert "Risk Acceptance" in bilingual_accept
    assert "जोखिम स्वीकृति" in bilingual_accept

    # Localize dictionary
    data = {
        "status": "active",
        "regulator": "rbi",
        "nested": {"decision": "mitigate"},
    }
    localized_hi = localize_dict(data, "hi")
    assert localized_hi["status"] == "सक्रिय"
    assert "भारतीय रिज़र्व बैंक" in localized_hi["regulator"]
    assert localized_hi["nested"]["decision"] == "जोखिम शमन"


def test_risk_decision_maker_checker_enforcement(db_session: Session) -> None:
    """Verifies that decision creation and countersignature strictly enforce Maker-Checker dual control."""
    test_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    audit = AuditService(test_key)
    now = datetime.now(UTC)

    # 1. CISO creates risk decision
    dec = RiskDecision(
        decision_number="DEC-2026-0001",
        decision_type="Risk Acceptance",
        status="awaiting_countersignature",
        rationale="Temporary operational deferral of secondary backup MFA check",
        compensating_controls="Compensating isolated VLAN, biometric console access, enhanced session logging",
        owner="IT Infrastructure & Cloud Ops",
        expiry_date=now + timedelta(days=30),
        created_by_id="ciso-user-01",
        created_at=now,
    )
    db_session.add(dec)
    db_session.commit()

    # 2. Maker attempts to countersign own decision -> REJECTED
    is_allowed_maker = PolicyEngine.check_maker_checker(dec.created_by_id, "ciso-user-01")
    assert not is_allowed_maker, "Maker must NOT be allowed to countersign own decision"

    # 3. Independent compliance approver countersigns -> ACCEPTED
    is_allowed_checker = PolicyEngine.check_maker_checker(dec.created_by_id, "compliance-user-01")
    assert is_allowed_checker, "Independent checker must be permitted to countersign"

    dec.status = "active"
    dec.countersigned_by_id = "compliance-user-01"
    dec.countersigned_at = now
    dec.countersign_notes = "Compensating VLAN and console biometrics verified and approved"
    db_session.commit()

    db_session.refresh(dec)
    assert dec.status == "active"
    assert dec.countersigned_by_id == "compliance-user-01"


def test_para59_exceptions_lifecycle_and_warning_badges(db_session: Session) -> None:
    """Verifies RBI Para 59 exception creation, 15-day warning countdown, and quarterly review."""
    now = datetime.now(UTC)

    # 1. Normal active exception (60 days out)
    exc_active = Para59Exception(
        exception_number="EXC-2026-0001",
        asset_or_system="Core Banking CBS-01",
        control_reference="RBI Para 59.2 - Session Timeout & Access Isolation",
        rationale="Core batch settlement job requires 4-hour extended session",
        compensating_controls="Hardened console bastion, air-gapped terminal, audit logging",
        owner="CBS Core Ops",
        risk_level="high",
        status="active",
        issue_date=now,
        expiry_date=now + timedelta(days=60),
        created_by_id="ciso-user-01",
    )

    # 2. Expiring soon exception (8 days out <= 15 days)
    exc_expiring = Para59Exception(
        exception_number="EXC-2026-0002",
        asset_or_system="Splunk-Indexer-02",
        control_reference="RBI Para 59.4 - Log Storage Key Rotation",
        rationale="Legacy indexer awaiting hardware HSM module replacement",
        compensating_controls="Strict egress firewall, daily file integrity monitoring",
        owner="SOC Lead",
        risk_level="critical",
        status="active",
        issue_date=now - timedelta(days=82),
        expiry_date=now + timedelta(days=8),
        created_by_id="ciso-user-01",
    )

    # 3. Expired exception (-2 days)
    exc_expired = Para59Exception(
        exception_number="EXC-2026-0003",
        asset_or_system="ATM Switch Gateway 4",
        control_reference="RBI Para 59.7 - TLS 1.3 Upgrade",
        rationale="Vendor firmware upgrade pending",
        compensating_controls="IPSec tunnel encapsulation",
        owner="Switch Ops",
        risk_level="high",
        status="active",
        issue_date=now - timedelta(days=95),
        expiry_date=now - timedelta(days=2),
        created_by_id="ciso-user-01",
    )

    db_session.add_all([exc_active, exc_expiring, exc_expired])
    db_session.commit()

    # Verify computed countdown status
    assert exc_active.computed_status(now) == "active"
    assert exc_active.days_remaining(now) >= 59

    assert exc_expiring.computed_status(now) == "expiring_soon"
    assert exc_expiring.days_remaining(now) == 8

    assert exc_expired.computed_status(now) == "expired"
    assert exc_expired.days_remaining(now) < 0

    # 4. Perform quarterly review / renewal
    exc_expiring.status = "active"
    exc_expiring.expiry_date = now + timedelta(days=90)
    exc_expiring.last_reviewed_at = now
    exc_expiring.reviewed_by_id = "compliance-user-01"
    exc_expiring.review_notes = "HSM procurement approved; 90-day extension granted."
    db_session.commit()

    db_session.refresh(exc_expiring)
    assert exc_expiring.computed_status(now) == "active"
    assert exc_expiring.days_remaining(now) >= 89
    assert exc_expiring.reviewed_by_id == "compliance-user-01"


def test_quarterly_board_pack_generation(db_session: Session) -> None:
    """Verifies canonical JSON generation, SHA-256 seal, and bilingual support for RBI Para 28(7) Board Pack."""
    now = datetime.now(UTC)

    # Add sample incident
    inc = Incident(
        id=str(uuid.uuid4()),
        incident_number="INC-2026-0089",
        title="Unauthorized credential brute-force on API gateway",
        summary="High frequency auth attempts detected on internet perimeter",
        severity="high",
        status="contained",
        created_at=now - timedelta(hours=1),
        created_by_id="ciso-user-01",
    )
    db_session.add(inc)
    db_session.commit()

    test_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    audit = AuditService(test_key)

    # Generate English Pack
    pack_en = generate_quarterly_board_pack_data(
        session=db_session,
        quarter="Q1 FY2026-27",
        lang="en",
        audit=audit,
        actor_id="ciso-user-01",
        actor_role="ciso",
    )

    assert pack_en["quarter"] == "Q1 FY2026-27"
    assert "pack_hash" in pack_en
    assert len(pack_en["pack_hash"]) == 64
    assert pack_en["incidents_summary"]["total"] >= 1
    assert pack_en["rupee_exposure_var"]["p90_var_crores"] > 0
    assert "Quarterly cybersecurity posture evaluation" in pack_en["executive_summary"]

    # Generate Hindi Pack
    pack_hi = generate_quarterly_board_pack_data(
        session=db_session,
        quarter="Q1 FY2026-27",
        lang="hi",
        audit=None,
    )
    assert "त्रैमासिक साइबर सुरक्षा स्थिति मूल्यांकन" in pack_hi["executive_summary"]
    assert "pack_hash" in pack_hi


def test_board_pack_byte_reproducible_pdf(db_session: Session) -> None:
    """Verifies that generate_board_pack_pdf produces byte-for-byte identical output given identical input."""
    pack_data = generate_quarterly_board_pack_data(
        session=db_session,
        quarter="Q1 FY2026-27",
        lang="en",
    )

    # Generate two PDFs with the same fixed epoch
    pdf1 = generate_board_pack_pdf(pack_data, source_date_epoch=1700000000)
    pdf2 = generate_board_pack_pdf(pack_data, source_date_epoch=1700000000)

    # 1. Byte-for-byte reproducibility
    assert pdf1 == pdf2, "Board pack PDF must be 100% byte-reproducible across runs"

    # 2. Check structure
    assert pdf1.startswith(b"%PDF-"), "Must be a valid PDF"
    assert b"CYBERQ BANK HYPERSCALE RISK GOVERNANCE" in pdf1
    assert b"CQ-BP-" in pdf1, "Must contain printable check-code"
    assert b"STRICTLY CONFIDENTIAL" in pdf1, "Must contain dynamic watermark"
