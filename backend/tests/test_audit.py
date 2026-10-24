"""Tests for the tamper-evident audit chain and offline verification."""

import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from cyberq.audit.chain import GENESIS_HASH, AuditService
from cyberq.audit.models import AuditEvent
from cyberq.core.database import Base

TEST_SEED = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"


@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


def test_audit_chain_creation_and_integrity(db_session):
    svc = AuditService(TEST_SEED)

    # 1. Record three events
    e1 = svc.record_event(
        session=db_session,
        actor_id="user-1",
        actor_role="analyst",
        action="incident:create",
        entity_type="incident",
        entity_id="inc-100",
        after_state={"title": "Ransomware detected"},
    )
    assert e1.sequence_number == 1
    assert e1.prev_hash == GENESIS_HASH
    assert len(e1.hash) == 64

    e2 = svc.record_event(
        session=db_session,
        actor_id="user-2",
        actor_role="compliance_approver",
        action="packet:approve",
        entity_type="filing_packet",
        entity_id="pkt-200",
        after_state={"status": "approved"},
    )
    assert e2.sequence_number == 2
    assert e2.prev_hash == e1.hash

    e3 = svc.record_event(
        session=db_session,
        actor_id="user-3",
        actor_role="ciso",
        action="decision:approve",
        entity_type="decision",
        entity_id="dec-300",
    )
    assert e3.sequence_number == 3
    assert e3.prev_hash == e2.hash

    db_session.commit()

    # 2. Create checkpoint
    cp = svc.create_checkpoint(db_session)
    assert cp is not None
    assert cp.from_sequence == 1
    assert cp.to_sequence == 3
    assert cp.root_hash == e3.hash
    assert len(cp.signature) == 128
    db_session.commit()

    # 3. Export to canonical dict format
    events_data = [e.to_canonical_dict() for e in [e1, e2, e3]]
    for idx, e in enumerate([e1, e2, e3]):
        events_data[idx]["hash"] = e.hash

    cp_data = [cp.to_canonical_dict()]
    cp_data[0]["signature"] = cp.signature

    # 4. Verify valid chain
    valid, reason = AuditService.verify_chain(events_data, cp_data, svc.public_key_hex)
    assert valid is True
    assert "valid" in reason.lower()


def test_tamper_detection_fails_verification_on_row_edit(db_session, tmp_path):
    svc = AuditService(TEST_SEED)

    svc.record_event(
        session=db_session,
        actor_id="user-1",
        actor_role="analyst",
        action="incident:create",
        entity_type="incident",
        entity_id="inc-100",
        after_state={"amount": 1000},
    )
    svc.record_event(
        session=db_session,
        actor_id="user-2",
        actor_role="ciso",
        action="decision:approve",
        entity_type="decision",
        entity_id="dec-100",
    )
    db_session.commit()
    cp = svc.create_checkpoint(db_session)
    db_session.commit()

    events = db_session.query(AuditEvent).all()
    events_data = [e.to_canonical_dict() for e in events]
    for idx, e in enumerate(events):
        events_data[idx]["hash"] = e.hash

    cp_data = [cp.to_canonical_dict()]
    cp_data[0]["signature"] = cp.signature

    # Tamper 1: Alter after_state payload
    tampered_payload = copy.deepcopy(events_data)
    tampered_payload[0]["after_state"] = {"amount": 9999999}
    valid, reason = AuditService.verify_chain(tampered_payload, cp_data, svc.public_key_hex)
    assert valid is False
    assert "Tampered event" in reason

    # Tamper 2: Alter actor_role
    tampered_role = copy.deepcopy(events_data)
    tampered_role[0]["actor_role"] = "admin"
    valid, reason = AuditService.verify_chain(tampered_role, cp_data, svc.public_key_hex)
    assert valid is False
    assert "Tampered event" in reason

    # Tamper 3: Alter prev_hash link
    tampered_prev = copy.deepcopy(events_data)
    tampered_prev[1]["prev_hash"] = (
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    )
    valid, reason = AuditService.verify_chain(tampered_prev, cp_data, svc.public_key_hex)
    assert valid is False
    assert "Broken hash chain" in reason

    # Tamper 4: Checkpoint signature tampering
    tampered_cp = copy.deepcopy(cp_data)
    tampered_cp[0]["signature"] = "00" * 64
    valid, reason = AuditService.verify_chain(events_data, tampered_cp, svc.public_key_hex)
    assert valid is False
    assert "Invalid Ed25519 signature" in reason


def test_verify_audit_cli_tool(db_session, tmp_path):
    svc = AuditService(TEST_SEED)

    e1 = svc.record_event(
        session=db_session,
        actor_id="user-1",
        actor_role="analyst",
        action="incident:create",
        entity_type="incident",
        entity_id="inc-101",
    )
    db_session.commit()
    cp = svc.create_checkpoint(db_session)
    db_session.commit()

    events_data = [e1.to_canonical_dict()]
    events_data[0]["hash"] = e1.hash
    cp_data = [cp.to_canonical_dict()]
    cp_data[0]["signature"] = cp.signature

    # Valid export file
    valid_file = tmp_path / "valid_audit.json"
    valid_file.write_text(
        json.dumps(
            {
                "public_key": svc.public_key_hex,
                "events": events_data,
                "checkpoints": cp_data,
            }
        )
    )

    cli_script = (
        Path(__file__).resolve().parent.parent.parent / "tools" / "verify-audit" / "verify.py"
    )

    # Test valid exit code 0
    res_valid = subprocess.run(
        [sys.executable, str(cli_script), "-i", str(valid_file)], capture_output=True, text=True
    )
    assert res_valid.returncode == 0
    assert "[VERIFIED]" in res_valid.stdout

    # Tamper the file and test exit code 1
    events_data[0]["actor_id"] = "hacker"
    tampered_file = tmp_path / "tampered_audit.json"
    tampered_file.write_text(
        json.dumps(
            {
                "public_key": svc.public_key_hex,
                "events": events_data,
                "checkpoints": cp_data,
            }
        )
    )

    res_tampered = subprocess.run(
        [sys.executable, str(cli_script), "-i", str(tampered_file)], capture_output=True, text=True
    )
    assert res_tampered.returncode == 1
    assert "[INTEGRITY VIOLATION]" in res_tampered.stderr
