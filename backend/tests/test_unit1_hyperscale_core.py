"""Tests for UNIT 1: Hyperscale Core Upgrades.

Covers:
1. Dual-curve KeyProvider (Ed25519 and ECDSA P-256).
2. RFC 6962 Merkle tree construction, inclusion proofs, and selective disclosure verification.
3. Two-tier sharded audit chain with per-stream sequence and advisory locks.
4. Schema-level RBAC for internal infrastructure IP/hostname traceability.
5. 30-minute MSSP Provisional Triage safe-harbor window and dual Maker-Checker stand-down.
"""

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from cyberq.audit.chain import AuditService
from cyberq.audit.crypto import LocalKeyProvider, verify_signature
from cyberq.audit.merkle import (
    build_merkle_tree,
    generate_merkle_proof,
    verify_merkle_proof,
)
from cyberq.audit.models import AuditEvent
from cyberq.clocks.engine import ClockStatus, calculate_provisional_triage
from cyberq.core.database import Base
from cyberq.iam.policy import Action, PolicyEngine, Role
from cyberq.incidents.models import Incident, IncidentTrigger
from cyberq.incidents.service import (
    mask_incident_for_role,
    stand_down_provisional_triage,
    unmask_incident_traceability,
)

TEST_SEED = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"


@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


def test_dual_curve_key_provider_ed25519_and_p256():
    """Verify LocalKeyProvider creates valid signatures across Ed25519 and ECDSA P-256."""
    msg = b"CYBERQ Audit Checkpoint v1"

    # 1. Ed25519
    ed_provider = LocalKeyProvider(TEST_SEED, algorithm="Ed25519")
    assert ed_provider.algorithm == "Ed25519"
    ed_sig = ed_provider.sign(msg)
    assert len(ed_sig) == 64
    assert verify_signature(msg, ed_sig, ed_provider.get_public_key_hex(), "Ed25519") is True
    assert verify_signature(b"tampered", ed_sig, ed_provider.get_public_key_hex(), "Ed25519") is False

    # 2. ECDSA P-256
    p256_provider = LocalKeyProvider(TEST_SEED, algorithm="ECDSA_P256")
    assert p256_provider.algorithm == "ECDSA_P256"
    p256_sig = p256_provider.sign(msg)
    assert len(p256_sig) > 60  # DER-encoded ECDSA signature
    assert verify_signature(msg, p256_sig, p256_provider.get_public_key_hex(), "ECDSA_P256") is True
    assert verify_signature(b"tampered", p256_sig, p256_provider.get_public_key_hex(), "ECDSA_P256") is False


def test_merkle_tree_rfc_6962_and_selective_disclosure():
    """Verify RFC 6962 Merkle tree leaf domain separation and selective disclosure inclusion proofs."""
    leaves = [
        b"event-hash-1-aaaa",
        b"event-hash-2-bbbb",
        b"event-hash-3-cccc",
        b"event-hash-4-dddd",
        b"event-hash-5-eeee",
    ]
    root_hex, layers = build_merkle_tree(leaves)
    assert len(root_hex) == 64

    # Verify proof for each individual leaf
    for idx, leaf in enumerate(leaves):
        proof = generate_merkle_proof(idx, leaves)
        assert len(proof) > 0
        # Valid proof against true root
        assert verify_merkle_proof(leaf, proof, root_hex) is True
        # Proof fails against tampered leaf
        assert verify_merkle_proof(b"tampered-leaf", proof, root_hex) is False
        # Proof fails against wrong root
        assert verify_merkle_proof(leaf, proof, "0" * 64) is False


def test_sharded_audit_chain_and_selective_disclosure_verification(db_session):
    """Verify per-incident stream sharding and selective disclosure checkpoint verification."""
    svc = AuditService(TEST_SEED, algorithm="ECDSA_P256")

    # Record events across two different incident streams
    e1 = svc.record_event(
        session=db_session,
        actor_id="u-1",
        actor_role="analyst",
        action="incident:create",
        entity_type="incident",
        entity_id="INC-001",
        stream_id="INC-001",
        after_state={"title": "Ransomware on ATM gateway"},
    )
    e2 = svc.record_event(
        session=db_session,
        actor_id="u-2",
        actor_role="analyst",
        action="incident:create",
        entity_type="incident",
        entity_id="INC-002",
        stream_id="INC-002",
        after_state={"title": "Core banking slow response"},
    )
    e3 = svc.record_event(
        session=db_session,
        actor_id="u-1",
        actor_role="analyst",
        action="trigger:assert",
        entity_type="incident_trigger",
        entity_id="trg-1",
        stream_id="INC-001",
        after_state={"trigger": "noticed"},
    )
    db_session.commit()

    # Stream sequences
    assert e1.stream_sequence_number == 1
    assert e2.stream_sequence_number == 1
    assert e3.stream_sequence_number == 2
    assert e3.stream_prev_hash == e1.hash

    # Global sequences
    assert e1.sequence_number == 1
    assert e2.sequence_number == 2
    assert e3.sequence_number == 3

    # Create checkpoint covering events 1..3 with ECDSA P-256
    cp = svc.create_checkpoint(db_session, from_sequence=1, to_sequence=3)
    db_session.commit()
    assert cp.merkle_root is not None
    assert cp.algorithm == "ECDSA_P256"

    # Test full chain offline verification
    events_data = [e.to_canonical_dict() for e in [e1, e2, e3]]
    for idx, e in enumerate([e1, e2, e3]):
        events_data[idx]["hash"] = e.hash
    cp_data = [cp.to_canonical_dict()]
    cp_data[0]["signature"] = cp.signature
    cp_data[0]["merkle_root"] = cp.merkle_root
    cp_data[0]["algorithm"] = cp.algorithm

    valid, reason = AuditService.verify_chain(events_data, cp_data, svc.public_key_hex)
    assert valid is True, reason

    # Test RBI CSITE Selective Disclosure: Prove e1 without revealing e2 or e3
    leaves = [ev["hash"].encode("ascii") for ev in events_data]
    proof_e1 = generate_merkle_proof(0, leaves)

    sd_valid, sd_reason = AuditService.verify_selective_disclosure(
        event_hash=e1.hash,
        proof=proof_e1,
        checkpoint=cp_data[0],
        public_key_hex=svc.public_key_hex,
    )
    assert sd_valid is True, sd_reason


def test_ip_hostname_rbac_masking_and_unmasking(db_session):
    """Verify SBI Traceability directive: field-level IP masking by role and auditable unmasking."""
    svc = AuditService(TEST_SEED)

    raw_incident = {
        "incident_number": "INC-2026-0099",
        "title": "Unauthorized lateral movement",
        "summary": "Lateral movement from compromised gateway",
        "server_ips": ["10.14.2.55", "172.16.0.4"],
        "hostnames": ["rtgs-gw-01.bank.internal", "db-prod-core.bank.internal"],
    }

    # 1. Analyst receives masked IPs
    masked_analyst = mask_incident_for_role(raw_incident, Role.ANALYST.value)
    assert masked_analyst["server_ips"] == ["[REDACTED_BY_RBAC]", "[REDACTED_BY_RBAC]"]
    assert masked_analyst["hostnames"] == ["[REDACTED_BY_RBAC]", "[REDACTED_BY_RBAC]"]

    # 2. Auditor receives masked IPs + masked summary
    masked_auditor = mask_incident_for_role(raw_incident, Role.AUDITOR.value)
    assert masked_auditor["server_ips"] == ["[REDACTED_BY_RBAC]", "[REDACTED_BY_RBAC]"]
    assert masked_auditor["summary"] == "[REDACTED_FOR_AUDIT]"

    # 3. Admin receives redacted narratives and IPs
    masked_admin = mask_incident_for_role(raw_incident, Role.ADMIN.value)
    assert masked_admin["server_ips"] == ["[REDACTED_FOR_ADMIN]", "[REDACTED_FOR_ADMIN]"]
    assert "[REDACTED_FOR_ADMIN" in masked_admin["summary"]

    # 4. CISO receives raw IPs directly
    masked_ciso = mask_incident_for_role(raw_incident, Role.CISO.value, unmask_ips=True)
    assert masked_ciso["server_ips"] == ["10.14.2.55", "172.16.0.4"]

    # 5. Persisted Incident unmasking service emits IP_TRACEABILITY_UNMASKED audit event
    inc = Incident(
        id="inc-test-uuid",
        incident_number="INC-2026-0099",
        title="Unauthorized lateral movement",
        summary="Lateral movement from compromised gateway",
        severity="critical",
        created_by_id="analyst-1",
    )
    db_session.add(inc)
    db_session.commit()

    # Analyst attempting unmasking raises PermissionError
    with pytest.raises(PermissionError):
        unmask_incident_traceability(
            session=db_session,
            audit=svc,
            incident_id=inc.id,
            actor_id="analyst-1",
            actor_role=Role.ANALYST.value,
        )

    # CISO unmasking succeeds and records audit event in the same transaction
    unmasked = unmask_incident_traceability(
        session=db_session,
        audit=svc,
        incident_id=inc.id,
        actor_id="ciso-1",
        actor_role=Role.CISO.value,
    )
    db_session.commit()
    assert unmasked["incident_number"] == "INC-2026-0099"

    # Verify audit event written
    audit_event = db_session.query(AuditEvent).filter_by(action="IP_TRACEABILITY_UNMASKED").first()
    assert audit_event is not None
    assert audit_event.actor_role == Role.CISO.value
    assert audit_event.entity_id == inc.id


def test_provisional_triage_30m_safe_harbor_and_stand_down(db_session):
    """Verify 30-minute MSSP Provisional Triage Safe-Harbor math and Maker-Checker stand-down."""
    svc = AuditService(TEST_SEED)
    now = datetime.now(UTC)

    # 1. Calculation within 30m is active
    first_signal = now - timedelta(minutes=10)
    is_active, expires_at, remaining = calculate_provisional_triage(first_signal, now, 30)
    assert is_active is True
    assert remaining.total_seconds() > 0

    # 2. Calculation after 30m is expired
    stale_signal = now - timedelta(minutes=35)
    is_active_stale, _, remaining_stale = calculate_provisional_triage(stale_signal, now, 30)
    assert is_active_stale is False
    assert remaining_stale.total_seconds() == 0

    # 3. Create incident for stand-down test
    inc = Incident(
        id="inc-provisional-1",
        incident_number="INC-2026-0100",
        title="Automated SIEM alert: Port scan anomaly",
        summary="Automated sensor detected unusual ping sweep",
        severity="low",
        status="new",
        created_by_id="analyst-1",
    )
    db_session.add(inc)
    db_session.commit()

    # Maker cannot approve their own stand-down (Maker-Checker violation)
    with pytest.raises(ValueError, match="Maker-Checker violation"):
        stand_down_provisional_triage(
            session=db_session,
            audit=svc,
            incident_id=inc.id,
            maker_id="analyst-1",
            checker_id="analyst-1",
            checker_role=Role.COMPLIANCE_APPROVER.value,
            reason_code="Correlated with scheduled vulnerability scan from approved scanner IP",
        )

    # ReasonCode under 20 chars is rejected
    with pytest.raises(ValueError, match="at least 20 characters"):
        stand_down_provisional_triage(
            session=db_session,
            audit=svc,
            incident_id=inc.id,
            maker_id="analyst-1",
            checker_id="compliance-2",
            checker_role=Role.COMPLIANCE_APPROVER.value,
            reason_code="False positive",
        )

    # Valid stand-down succeeds
    stood_down_inc = stand_down_provisional_triage(
        session=db_session,
        audit=svc,
        incident_id=inc.id,
        maker_id="analyst-1",
        checker_id="compliance-2",
        checker_role=Role.COMPLIANCE_APPROVER.value,
        reason_code="Correlated with approved scheduled vulnerability scan from Infosec scanner IP",
    )
    db_session.commit()
    assert stood_down_inc.status == "false_positive"

    # Audit event logged
    audit_ev = db_session.query(AuditEvent).filter_by(action="incident:provisional_triage_stand_down").first()
    assert audit_ev is not None
    assert audit_ev.actor_id == "compliance-2"
