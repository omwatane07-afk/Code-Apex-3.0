"""Comprehensive security regression test suite for Phase 1 remediation.

Validates:
1. Broken Function Level Authorization (BFLA) on filings and admin endpoints
2. TOTP Step-Up MFA replay protection and cache management
3. 24-hour Break-Glass retrospective countersignature enforcement
4. Ingestion PII Guard evasion defenses (case-insensitive PAN, delimiter evasions, nested structures)
5. Oversized webhook payload rejection (DoS defense)
6. Maker-Checker non-bypassability
"""

from datetime import UTC, datetime, timedelta
import uuid

try:
    import pyotp
except ImportError:
    import sys
    from pathlib import Path

    _src = str(Path(__file__).resolve().parent.parent / "src")
    if _src not in sys.path:
        sys.path.insert(0, _src)
    import pyotp
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from cyberq.api.app import app
from cyberq.audit.chain import AuditService
from cyberq.core.config import get_settings
from cyberq.core.pii_guard import PIIGuard, validate_verhoeff
from cyberq.filings.mfa import TOTPReplayProtection, clear_totp_replay_cache, verify_totp_code
from cyberq.filings.service import FilingService
from cyberq.iam.models import User
from cyberq.iam.policy import Role
from cyberq.iam.session import SessionManager
from cyberq.incidents.models import Incident

settings = get_settings()


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


def create_authenticated_session(db: Session, username: str, role: Role) -> tuple[User, str]:
    user = User(
        id=str(uuid.uuid4()),
        username=username,
        email=f"{username}@bank.internal",
        full_name=username.title(),
        is_active=True,
    )
    db.add(user)
    db.flush()
    session = SessionManager.create_session(db, user, role)
    return user, session.id


# ===========================================================================
# 1. BFLA / RBAC Tests on Filings & Admin Routes
# ===========================================================================


def test_unauthenticated_filings_listing_denied(client: TestClient) -> None:
    """GET /api/v1/filings must reject unauthenticated requests."""
    client.cookies.clear()
    res = client.get("/api/v1/filings")
    assert res.status_code in (401, 403)


def test_unauthenticated_filings_pdf_denied(client: TestClient) -> None:
    """GET /api/v1/filings/{packet_id}/pdf must reject unauthenticated requests."""
    client.cookies.clear()
    res = client.get("/api/v1/filings/fake-packet-uuid/pdf")
    assert res.status_code in (401, 403)


def test_unauthenticated_admin_seed_denied(client: TestClient) -> None:
    """POST /api/v1/admin/seed-demo must reject unauthenticated callers."""
    client.cookies.clear()
    res = client.post("/api/v1/admin/seed-demo")
    assert res.status_code in (401, 403)


def test_analyst_cannot_invoke_admin_seed(
    client: TestClient,
    isolated_db: sessionmaker[Session],
) -> None:
    """ANALYST role must be denied access to admin seed-demo."""
    db = isolated_db()
    try:
        _, session_id = create_authenticated_session(db, "analyst_sec_01", Role.ANALYST)
        client.cookies.set("cyberq_session", session_id)

        res = client.post(
            "/api/v1/admin/seed-demo",
            headers={"X-Session-ID": session_id},
        )
        assert res.status_code == 403
        assert (
            "Forbidden" in res.text
            or "not permitted" in res.text
            or "not authorized" in res.text
        )
    finally:
        db.close()


# ===========================================================================
# 2. TOTP Step-Up MFA Replay Protection
# ===========================================================================


def test_totp_token_replay_rejected() -> None:
    """Consuming the same valid TOTP code twice within the validity window must fail."""
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    valid_code = totp.now()

    cache = TOTPReplayProtection(window_seconds=60)

    # First verification must succeed
    assert verify_totp_code(secret, valid_code, replay_cache=cache) is True

    # Replaying the identical code must be blocked
    assert verify_totp_code(secret, valid_code, replay_cache=cache) is False

    # After clearing the cache, fresh code from another secret works
    clear_totp_replay_cache()


# ===========================================================================
# 3. Break-Glass 24-Hour Retrospective Countersignature Enforcement
# ===========================================================================


def test_expired_break_glass_packet_filing_blocked(
    isolated_db: sessionmaker[Session],
) -> None:
    """A packet approved under Break-Glass cannot be filed if the 24h countersignature window expired."""
    db = isolated_db()
    try:
        audit_svc = AuditService(settings.AUDIT_SIGNING_SEED)
        filing_svc = FilingService(audit_svc)

        preparer, _ = create_authenticated_session(db, "analyst_prep", Role.ANALYST)
        approver, _ = create_authenticated_session(
            db, "compliance_approv", Role.COMPLIANCE_APPROVER
        )

        incident = Incident(
            id="inc-sec-bg-01",
            incident_number="INC-2026-9001",
            title="Active Crisis Ransomware",
            summary="Core Switch Offline",
            severity="critical",
            status="new",
            created_by_id=preparer.id,
        )
        db.add(incident)
        db.flush()

        packet = filing_svc.prepare_packet(
            session=db,
            incident_id=incident.id,
            pack_id="certin-directions-2022",
            regulator="CERT-In",
            prepared_by_id=preparer.id,
            prepared_by_role=Role.ANALYST.value,
        )

        # Approve under emergency Break-Glass protocol
        approved_packet = filing_svc.approve_packet(
            session=db,
            packet_id=packet.id,
            approver_id=approver.id,
            approver_role=Role.COMPLIANCE_APPROVER.value,
            is_break_glass=True,
            break_glass_reason="Critical midnight ransomware outbreak requiring immediate filing override",
            elapsed_minutes=45.0,
            remaining_minutes=25.0,
        )
        assert approved_packet.is_break_glass is True

        # Simulate 25 hours elapsed without countersignature
        approved_packet.break_glass_countersignature_required_by = (
            datetime.now(UTC) - timedelta(hours=1)
        )
        db.flush()

        # Attempting to record acknowledgement without countersignature after expiry must fail
        with pytest.raises(
            ValueError,
            match="Emergency Break-Glass approval expired without required 24-hour retrospective countersignature",
        ):
            filing_svc.record_acknowledgement(
                session=db,
                packet_id=approved_packet.id,
                filer_id=approver.id,
                filer_role=Role.COMPLIANCE_APPROVER.value,
                acknowledgement_ref="CERTIN-ACK-EXPIRED-TEST",
            )
    finally:
        db.close()


# ===========================================================================
# 4. Maker-Checker Separation Invariant
# ===========================================================================


def test_maker_checker_cannot_approve_own_filing(
    isolated_db: sessionmaker[Session],
) -> None:
    """The user who prepared a filing packet cannot approve it under any circumstances."""
    db = isolated_db()
    try:
        audit_svc = AuditService(settings.AUDIT_SIGNING_SEED)
        filing_svc = FilingService(audit_svc)

        maker, _ = create_authenticated_session(db, "maker_checker_user", Role.ANALYST)

        incident = Incident(
            id="inc-sec-mc-01",
            incident_number="INC-2026-9002",
            title="Unauthorized Database Probe",
            summary="Telemetry anomaly",
            severity="high",
            status="new",
            created_by_id=maker.id,
        )
        db.add(incident)
        db.flush()

        packet = filing_svc.prepare_packet(
            session=db,
            incident_id=incident.id,
            pack_id="rbi-cybersecurity-directions-2026",
            regulator="RBI",
            prepared_by_id=maker.id,
            prepared_by_role=Role.ANALYST.value,
        )

        secret = pyotp.random_base32()
        code = pyotp.TOTP(secret).now()

        # The same user attempting to approve their own packet must fail
        with pytest.raises(ValueError, match="Maker-Checker violation"):
            filing_svc.approve_packet(
                session=db,
                packet_id=packet.id,
                approver_id=maker.id,
                approver_role=Role.COMPLIANCE_APPROVER.value,
                otp_code=code,
                totp_secret=secret,
            )
    finally:
        db.close()


# ===========================================================================
# 5. PII Guard Evasion & Deep Object Sanitization
# ===========================================================================


def test_pii_pan_case_insensitivity_and_separators() -> None:
    """PAN regex must detect lowercase PANs and hyphen/space delimited PANs."""
    pan_variations = [
        "ABCDE1234F",
        "abcde1234f",
        "ABCDE-1234-F",
        "abcde 1234 f",
    ]
    for pan in pan_variations:
        text = f"Customer audit query mentions PAN {pan} on system."
        redacted = PIIGuard.redact(text)
        assert "[REDACTED_PAN]" in redacted, f"Failed to redact variation: {pan}"


def test_pii_aadhaar_delimiter_evasion() -> None:
    """Aadhaar detection must catch numbers with colons, commas, slashes, or zero-width spaces."""
    valid_aadhaar = "999941057058"
    assert validate_verhoeff(valid_aadhaar) is True

    evasions = [
        f"{valid_aadhaar[:4]}:{valid_aadhaar[4:8]}:{valid_aadhaar[8:]}",
        f"{valid_aadhaar[:4]},{valid_aadhaar[4:8]},{valid_aadhaar[8:]}",
        f"{valid_aadhaar[:4]}/{valid_aadhaar[4:8]}/{valid_aadhaar[8:]}",
        f"{valid_aadhaar[:4]}\u200b{valid_aadhaar[4:8]}\u200b{valid_aadhaar[8:]}",
    ]
    for ev in evasions:
        text = f"Aadhaar candidate: {ev} found in trace."
        redacted = PIIGuard.redact(text)
        assert "[REDACTED_AADHAAR]" in redacted, f"Failed to redact evasion: {ev}"


def test_pii_nested_json_redaction() -> None:
    """Nested dictionaries and lists must be recursively sanitized."""
    valid_aadhaar = "999941057058"
    formatted_aadhaar = f"{valid_aadhaar[:4]} {valid_aadhaar[4:8]} {valid_aadhaar[8:]}"

    complex_payload = {
        "event_id": "EVT-101",
        "metadata": {
            "query": "SELECT * WHERE pan='ABCDE1234F'",
            "tags": ["soc", f"Customer Aadhaar: {formatted_aadhaar}"],
        },
        "records": [
            {"card": "4532 0150 1234 5671"},
        ],
    }
    redacted = PIIGuard.redact_nested(complex_payload)
    assert "[REDACTED_PAN]" in redacted["metadata"]["query"]
    assert "[REDACTED_AADHAAR]" in redacted["metadata"]["tags"][1]
    assert "[REDACTED_CARD]" in redacted["records"][0]["card"]


# ===========================================================================
# 6. Webhook Oversized Payload DoS Protection
# ===========================================================================


def test_oversized_webhook_payload_rejected(client: TestClient) -> None:
    """Incoming webhooks exceeding 2MB must be rejected with HTTP 413."""
    oversized_bytes = b"X" * (2 * 1024 * 1024 + 1024)
    res = client.post(
        "/api/v1/intake/webhook/tool-siem-splunk",
        content=oversized_bytes,
        headers={"Content-Type": "application/octet-stream"},
    )
    assert res.status_code == 413
    assert "exceeds maximum allowable limit" in res.text
