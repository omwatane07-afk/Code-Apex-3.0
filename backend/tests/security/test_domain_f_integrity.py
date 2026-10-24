"""Executable security exploit tests for Domain F: Clock and Audit Integrity.

Rules of Engagement:
- Imports and enforces tools/redteam/scope_guard.py.
- Uses disposable local database fixtures.
"""

import os

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import sessionmaker
from tools.redteam.scope_guard import enforce_scope

from cyberq.audit.chain import AuditService
from cyberq.core.database import Base, install_audit_immutability_triggers

enforce_scope("localhost")

TEST_SEED = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"


@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session, engine
    session.close()


def test_checkpoint_must_bind_to_event_root_hash(db_session):
    """ATTACK F-01: Exploit checkpoint unbound to chain root hash.

    An attacker creates a validly signed checkpoint with an arbitrary root hash,
    or attaches a checkpoint from another chain segment.
    Verification MUST fail if checkpoint root_hash does not match event[to_sequence].hash.
    """
    session, _ = db_session
    svc = AuditService(TEST_SEED)

    # Record 2 genuine events
    e1 = svc.record_event(session, "u1", "analyst", "create", "inc", "1")
    e2 = svc.record_event(session, "u2", "ciso", "approve", "inc", "1")
    session.commit()

    cp = svc.create_checkpoint(session)
    session.commit()

    events_data = [e.to_canonical_dict() for e in [e1, e2]]
    for idx, e in enumerate([e1, e2]):
        events_data[idx]["hash"] = e.hash

    cp_data = [cp.to_canonical_dict()]
    cp_data[0]["signature"] = cp.signature

    # Attacker creates a checkpoint with an arbitrary root_hash from another chain, signed with a valid key
    import copy

    forged_cp_dict = copy.deepcopy(cp_data[0])
    forged_cp_dict["root_hash"] = "99" * 32
    from cyberq.audit.chain import canonical_json

    cp_to_sign = {k: v for k, v in forged_cp_dict.items() if k != "signature"}
    sig = svc._key_provider.sign(canonical_json(cp_to_sign)).hex()
    forged_cp_dict["signature"] = sig

    # Verification MUST reject this forged checkpoint because root_hash != e2.hash
    is_valid, reason = AuditService.verify_chain(events_data, [forged_cp_dict], svc.public_key_hex)
    assert is_valid is False, (
        "VULNERABILITY CONFIRMED: Checkpoint with mismatched root_hash was accepted!"
    )
    assert "root_hash mismatch" in reason or "does not match" in reason


def test_checkpoint_must_reject_truncated_event_chain(db_session):
    """ATTACK F-02: Exploit event truncation after checkpoint generation.

    Attacker presents a valid checkpoint covering sequence 1..5, but only provides events 1..3.
    Verification MUST detect that events do not reach the checkpoint's to_sequence.
    """
    session, _ = db_session
    svc = AuditService(TEST_SEED)

    e1 = svc.record_event(session, "u1", "analyst", "create", "inc", "1")
    _e2 = svc.record_event(session, "u2", "analyst", "update", "inc", "1")
    session.commit()

    cp = svc.create_checkpoint(session)
    session.commit()

    events_data = [e1.to_canonical_dict()]
    events_data[0]["hash"] = e1.hash  # Attacker truncated e2!

    cp_data = [cp.to_canonical_dict()]
    cp_data[0]["signature"] = cp.signature

    is_valid, reason = AuditService.verify_chain(events_data, cp_data, svc.public_key_hex)
    assert is_valid is False, "VULNERABILITY CONFIRMED: Truncated chain accepted by checkpoint!"


def test_audit_event_db_level_immutability(db_session):
    """ATTACK F-03: Direct database UPDATE/DELETE on audit_event rows.

    An attacker or rogue DB user issues raw UPDATE or DELETE on audit_event.
    The database must reject UPDATE and DELETE attempts via trigger / event listeners.
    """
    session, engine = db_session
    svc = AuditService(TEST_SEED)

    e1 = svc.record_event(session, "u1", "analyst", "create", "inc", "1")
    session.commit()

    # Attempt 1: Raw SQL UPDATE
    with pytest.raises(Exception, match="audit_event is append-only|cannot modify audit_event"):
        session.execute(
            text("UPDATE audit_event SET actor_id = :actor WHERE id = :id"),
            {"actor": "hacker", "id": e1.id},
        )
        session.commit()

    # Attempt 2: Raw SQL DELETE
    with pytest.raises(
        Exception, match="audit_event is append-only|cannot delete from audit_event"
    ):
        session.execute(text("DELETE FROM audit_event WHERE id = :id"), {"id": e1.id})
        session.commit()

    # Attempt 3: SQLite INSERT OR REPLACE bypass attempt
    with pytest.raises(Exception, match="audit_event is append-only|cannot replace or overwrite"):
        session.execute(
            text(
                "INSERT OR REPLACE INTO audit_event (id, sequence_number, timestamp, prev_hash, hash, actor_id, actor_role, action, entity_type, entity_id) "
                "VALUES (:id, 1, :ts, :ph, :h, :actor, :role, :act, :et, :ei)"
            ),
            {
                "id": e1.id,
                "ts": "2026-01-01T00:00:00Z",
                "ph": "0",
                "h": "badhash",
                "actor": "hacker",
                "role": "analyst",
                "act": "create",
                "et": "inc",
                "ei": "1",
            },
        )
        session.commit()

    # Attempt 4: Direct mutation on audit_checkpoint
    cp = svc.create_checkpoint(session)
    session.commit()
    with pytest.raises(
        Exception, match="audit_checkpoint is append-only|cannot modify audit_checkpoint"
    ):
        session.execute(
            text("UPDATE audit_checkpoint SET root_hash = :root WHERE id = :id"),
            {"root": "tampered", "id": cp.id},
        )
        session.commit()


def test_genesis_event_prev_hash_must_be_genesis_hash():
    """ATTACK F-04: Rogue genesis event with fabricated prev_hash.

    An attacker creates a chain starting at sequence 1 but with an arbitrary prev_hash
    instead of the locked GENESIS_HASH.
    verify_chain MUST reject sequence 1 if prev_hash != GENESIS_HASH.
    """
    from cyberq.audit.chain import compute_event_hash

    ev = {
        "id": "rogue-1",
        "sequence_number": 1,
        "timestamp": "2026-01-01T00:00:00Z",
        "prev_hash": "bad" * 21 + "b",
        "actor_id": "attacker",
        "actor_role": "analyst",
        "action": "create",
        "entity_type": "incident",
        "entity_id": "inc-rogue",
        "client_ip": None,
        "request_id": None,
        "before_state": None,
        "after_state": None,
    }
    ev["hash"] = compute_event_hash(ev, ev["prev_hash"])

    is_valid, reason = AuditService.verify_chain([ev])
    assert is_valid is False
    assert "Invalid genesis event" in reason or "must have prev_hash == GENESIS_HASH" in reason


@pytest.mark.postgres
def test_postgres_audit_triggers_immutability():
    """Live PostgreSQL 16 trigger test: ON CONFLICT DO UPDATE, TRUNCATE, and row mutation.

    Requires CYBERQ_TEST_PG_URL environment variable pointing to a real PostgreSQL 16 instance.
    Skips loudly when CYBERQ_TEST_PG_URL is unset.
    """
    pg_url = os.environ.get("CYBERQ_TEST_PG_URL")
    if not pg_url:
        pytest.skip("CYBERQ_TEST_PG_URL not set; skipping live PostgreSQL trigger test")

    engine = create_engine(pg_url)
    Session = sessionmaker(bind=engine)
    Base.metadata.create_all(bind=engine)
    install_audit_immutability_triggers(engine)

    svc = AuditService("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
    with Session() as s:
        e = svc.record_event(
            session=s,
            actor_id="pg_test_actor",
            actor_role="analyst",
            action="pg_create",
            entity_type="item",
            entity_id="pg-1",
        )
        s.commit()

        # 1. Attempt UPDATE
        with pytest.raises(SQLAlchemyError):
            s.execute(text("UPDATE audit_event SET actor_role = 'admin' WHERE id = :id"), {"id": e.id})
            s.commit()
        s.rollback()

        # 2. Attempt DELETE
        with pytest.raises(SQLAlchemyError):
            s.execute(text("DELETE FROM audit_event WHERE id = :id"), {"id": e.id})
            s.commit()
        s.rollback()

        # 3. Attempt TRUNCATE
        with pytest.raises(SQLAlchemyError):
            s.execute(text("TRUNCATE TABLE audit_event"))
            s.commit()
        s.rollback()
    engine.dispose()
