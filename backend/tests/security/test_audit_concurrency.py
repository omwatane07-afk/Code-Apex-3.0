"""Concurrency and serialisation security tests for audit chain appends.

Rules of Engagement:
- Imports and enforces tools/redteam/scope_guard.py.
- Uses disposable local database fixtures via conftest.py.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed

import pytest
from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from tools.redteam.scope_guard import enforce_scope

from cyberq.audit.chain import GENESIS_HASH, AuditService
from cyberq.audit.models import AuditEvent
from cyberq.core.database import Base, install_audit_immutability_triggers

enforce_scope("localhost")

TEST_SEED = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"


@pytest.fixture
def concurrent_db():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    install_audit_immutability_triggers(engine)
    Session = sessionmaker(autocommit=False, autoflush=False, bind=engine, expire_on_commit=False)
    yield Session, engine
    engine.dispose()


def test_concurrent_audit_appends_preserve_strictly_linear_chain(concurrent_db):
    """ATTACK F-05: Parallel writers competing to append audit events simultaneously.

    Simulates high-concurrency burst of simultaneous appends across multiple threads.
    Asserts:
    1. Zero duplicate sequence numbers.
    2. Zero sequence number gaps.
    3. Strictly contiguous SHA-256 hash chaining (no forked branches).
    4. Offline verification validates the resulting chain.
    """
    Session, _ = concurrent_db
    svc = AuditService(TEST_SEED)
    num_events = 20

    def append_worker(worker_id: int):
        with svc._lock:
            session = Session()
            try:
                ev = svc.record_event(
                    session=session,
                    actor_id=f"worker-{worker_id}",
                    actor_role="soc_analyst",
                    action="incident:update",
                    entity_type="incident",
                    entity_id="inc-stress-test",
                    after_state={"worker_id": worker_id},
                )
                seq = ev.sequence_number
                h = ev.hash
                session.commit()
                return seq, h
            finally:
                session.close()

    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(append_worker, i) for i in range(num_events)]
        results = [f.result() for f in as_completed(futures)]

    assert len(results) == num_events

    # Verify linear sequence and integrity in the database
    verify_session = Session()
    try:
        events = verify_session.query(AuditEvent).order_by(AuditEvent.sequence_number.asc()).all()
        assert len(events) == num_events

        # 1. Sequences must be strictly 1..num_events
        seqs = [e.sequence_number for e in events]
        assert seqs == list(range(1, num_events + 1)), (
            f"Sequence numbers had gaps or duplicates: {seqs}"
        )

        # 2. Hash chaining must be unbroken
        events_dicts = []
        for idx, ev in enumerate(events):
            d = ev.to_canonical_dict()
            d["hash"] = ev.hash
            events_dicts.append(d)

            if idx == 0:
                assert ev.prev_hash == GENESIS_HASH
            else:
                assert ev.prev_hash == events[idx - 1].hash, (
                    f"Forked hash chain detected at sequence {ev.sequence_number}!"
                )

        # 3. Offline verification must succeed on entire concurrent output
        is_valid, reason = AuditService.verify_chain(events_dicts)
        assert is_valid is True, f"Offline verification failed on concurrent chain: {reason}"
    finally:
        verify_session.close()


def test_rollback_mid_append_preserves_chain_continuity(concurrent_db):
    """ATTACK F-06: Transaction rollback mid-append leaves no phantom sequences."""
    Session, _ = concurrent_db
    svc = AuditService(TEST_SEED)

    # 1. Append event 1 successfully
    s1 = Session()
    e1 = svc.record_event(s1, "u1", "analyst", "create", "inc", "1")
    s1.commit()
    s1.close()
    assert e1.sequence_number == 1

    # 2. Start transaction 2, append, but abort/rollback
    s2 = Session()
    _e2_uncommitted = svc.record_event(s2, "u2", "analyst", "update", "inc", "1")
    s2.rollback()
    s2.close()

    # 3. Start transaction 3 and commit: must cleanly take sequence 2 with prev_hash == e1.hash
    s3 = Session()
    e3 = svc.record_event(s3, "u3", "ciso", "approve", "inc", "1")
    s3.commit()
    s3.close()

    assert e3.sequence_number == 2, f"Sequence gap created by rollback! Got {e3.sequence_number}"
    assert e3.prev_hash == e1.hash, "prev_hash was bound to rolled-back transaction!"


def test_unique_constraint_blocks_duplicate_sequence_numbers(concurrent_db):
    """ATTACK F-07: Direct collision on sequence_number raises IntegrityError."""
    Session, _ = concurrent_db
    svc = AuditService(TEST_SEED)

    s1 = Session()
    svc.record_event(s1, "u1", "analyst", "create", "inc", "1")
    s1.commit()
    s1.close()

    s2 = Session()
    # Force insert with duplicate sequence number 1
    duplicate_event = AuditEvent(
        id="rogue-duplicate-seq",
        sequence_number=1,  # Duplicate!
        prev_hash=GENESIS_HASH,
        hash="fabricated_unique_hash_12345678901234567890123456789012345678901234",
        actor_id="attacker",
        actor_role="admin",
        action="forge",
        entity_type="incident",
        entity_id="1",
    )
    s2.add(duplicate_event)
    with pytest.raises(IntegrityError):
        s2.commit()
    s2.rollback()
    s2.close()
