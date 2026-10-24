"""Executable tests proving audit chain concurrency, rollback isolation, and crash recovery.

Enforces:
1. Multi-session concurrency: Sequence numbers strictly monotonic without gaps or duplicates
   even when written by separate AuditService instances (bypassing in-process locks).
2. Mid-append rollback isolation: A transaction aborted/rolled back mid-append leaves no
   phantom sequence numbers, leaves no corrupt hash pointers, and the subsequent append
   seamlessly maintains unbroken cryptographic continuity.
3. Abrupt worker kill recovery: A worker killed mid-flight (simulating node crash / SIGKILL)
   leaves the database in a consistent, fully recoverable state where subsequent appends
   continue the chain with zero corruption.
"""

import multiprocessing
import os
import tempfile

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from tools.redteam.scope_guard import enforce_scope

from cyberq.audit.chain import GENESIS_HASH, AuditService
from cyberq.audit.models import AuditEvent
from cyberq.core.database import Base, install_audit_immutability_triggers

enforce_scope("localhost")

TEST_SEED = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"


@pytest.fixture
def temp_db_file():
    """Provides a temporary on-disk SQLite database file for multi-process/session tests."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    db_url = f"sqlite:///{db_path}"
    engine = create_engine(db_url, connect_args={"timeout": 30.0})
    Base.metadata.create_all(bind=engine)
    install_audit_immutability_triggers(engine)
    engine.dispose()

    yield db_url, db_path

    if os.path.exists(db_path):
        try:
            os.remove(db_path)
        except OSError:
            pass


def _worker_append_task(db_url: str, actor_id: str, count: int):
    """Worker task run in an isolated process to append events."""
    engine = create_engine(db_url, connect_args={"timeout": 30.0})
    Session = sessionmaker(bind=engine)
    # Each process has its own AuditService instance; in-process RLock does not synchronize them
    svc = AuditService(TEST_SEED)

    for i in range(count):
        with Session() as session:
            svc.record_event(
                session=session,
                actor_id=actor_id,
                actor_role="analyst",
                action="incident:update",
                entity_type="incident",
                entity_id=f"inc-{actor_id}-{i}",
            )
            session.commit()
    engine.dispose()


def test_audit_rollback_mid_append_preserves_chain_integrity(temp_db_file):
    """ATTACK F-04: Mid-append transaction rollback recovery.

    Prove that if an append transaction is aborted and rolled back:
    1. No dangling sequence number or orphan hash is committed.
    2. The subsequent transaction receives the correct contiguous sequence number.
    3. The chain hash pointer remains strictly monotonic and verify_chain passes.
    """
    db_url, _ = temp_db_file
    engine = create_engine(db_url, connect_args={"timeout": 30.0})
    Session = sessionmaker(bind=engine)

    svc1 = AuditService(TEST_SEED)
    svc2 = AuditService(TEST_SEED)

    # 1. First event succeeds
    with Session() as s1:
        e1 = svc1.record_event(
            session=s1,
            actor_id="actor_1",
            actor_role="analyst",
            action="incident:create",
            entity_type="incident",
            entity_id="inc-1",
        )
        s1.commit()
        assert e1.sequence_number == 1
        assert e1.prev_hash == GENESIS_HASH

    # 2. Second event starts in session A but encounters an unhandled exception and rolls back
    with pytest.raises(RuntimeError, match="Simulated application crash mid-append"):
        with Session() as s_fail:
            svc1.record_event(
                session=s_fail,
                actor_id="actor_failing",
                actor_role="analyst",
                action="incident:modify",
                entity_type="incident",
                entity_id="inc-1",
            )
            # Intentionally simulate error before commit
            raise RuntimeError("Simulated application crash mid-append")

    # 3. Third event runs in an independent session B and commits
    with Session() as s2:
        e2 = svc2.record_event(
            session=s2,
            actor_id="actor_2",
            actor_role="ciso",
            action="incident:approve",
            entity_type="incident",
            entity_id="inc-1",
        )
        s2.commit()

        # e2 MUST be sequence 2 (no gap from the aborted transaction)
        assert e2.sequence_number == 2
        # e2 MUST link directly to e1.hash
        assert e2.prev_hash == e1.hash

    # 4. Verify full chain from DB
    with Session() as s_verify:
        events = s_verify.execute(select(AuditEvent).order_by(AuditEvent.sequence_number)).scalars().all()
        assert len(events) == 2
        assert [e.sequence_number for e in events] == [1, 2]
        events_dicts = [{**e.to_canonical_dict(), "hash": e.hash} for e in events]
        is_valid, reason = AuditService.verify_chain(events_dicts, [], svc1.public_key_hex)
        assert is_valid is True, f"Chain corrupted after rollback: {reason}"
    engine.dispose()


def _crashed_worker(db_url: str):
    """Simulates a worker process that inserts uncommitted data and terminates abruptly."""
    engine = create_engine(db_url, connect_args={"timeout": 30.0})
    Session = sessionmaker(bind=engine)
    svc = AuditService(TEST_SEED)
    session = Session()
    svc.record_event(
        session=session,
        actor_id="crashed_worker",
        actor_role="worker",
        action="task:execute",
        entity_type="task",
        entity_id="task-001",
    )
    # Intentionally do not commit or close; exit process immediately
    os._exit(42)


def test_abrupt_worker_kill_leaves_chain_recoverable(temp_db_file):
    """ATTACK F-05: Worker process kill / abrupt crash recovery.

    Prove that if a worker process crashes abruptly (simulated via os._exit / SIGKILL):
    1. Uncommitted data is discarded by the database engine.
    2. A subsequent worker process can append new events without deadlocks or sequence collisions.
    3. The chain remains fully verifiable.
    """
    db_url, _ = temp_db_file
    engine = create_engine(db_url, connect_args={"timeout": 30.0})
    Session = sessionmaker(bind=engine)
    svc = AuditService(TEST_SEED)

    # 1. Normal event 1
    with Session() as s:
        e1 = svc.record_event(
            session=s,
            actor_id="primary",
            actor_role="admin",
            action="init",
            entity_type="system",
            entity_id="sys-1",
        )
        s.commit()
        assert e1.sequence_number == 1

    # 2. Spawn worker that abruptly exits via os._exit
    proc = multiprocessing.Process(target=_crashed_worker, args=(db_url,))
    proc.start()
    proc.join(timeout=10.0)
    assert proc.exitcode == 42, "Worker should have terminated with exit code 42"

    # 3. Main process continues writing events
    with Session() as s:
        e2 = svc.record_event(
            session=s,
            actor_id="recovery_worker",
            actor_role="admin",
            action="resume",
            entity_type="system",
            entity_id="sys-1",
        )
        s.commit()
        assert e2.sequence_number == 2
        assert e2.prev_hash == e1.hash

    # 4. Verify chain integrity
    with Session() as s:
        events = s.execute(select(AuditEvent).order_by(AuditEvent.sequence_number)).scalars().all()
        assert len(events) == 2
        events_dicts = [{**e.to_canonical_dict(), "hash": e.hash} for e in events]
        is_valid, reason = AuditService.verify_chain(events_dicts, [], svc.public_key_hex)
        assert is_valid is True, f"Chain corrupted after worker crash: {reason}"
    engine.dispose()


def test_multi_session_monotonic_sequence_integrity(temp_db_file):
    """ATTACK F-06: Multi-session sequential appending integrity.

    Verifies that multiple independent DB sessions appending to the audit ledger
    maintain strictly monotonic sequence numbers without gaps or collisions.
    """
    db_url, _ = temp_db_file
    engine = create_engine(db_url, connect_args={"timeout": 30.0})
    Session = sessionmaker(bind=engine)

    total_events = 20
    svc_list = [AuditService(TEST_SEED) for _ in range(total_events)]

    for i in range(total_events):
        with Session() as s:
            svc_list[i].record_event(
                session=s,
                actor_id=f"actor_{i%3}",
                actor_role="analyst",
                action=f"action_{i}",
                entity_type="item",
                entity_id=f"id_{i}",
            )
            s.commit()

    # Verify all sequence numbers are strictly 1..20
    with Session() as s:
        events = s.execute(select(AuditEvent).order_by(AuditEvent.sequence_number)).scalars().all()
        assert len(events) == total_events
        seqs = [e.sequence_number for e in events]
        assert seqs == list(range(1, total_events + 1)), f"Non-monotonic sequence numbers: {seqs}"

        events_dicts = [{**e.to_canonical_dict(), "hash": e.hash} for e in events]
        is_valid, reason = AuditService.verify_chain(events_dicts, [], svc_list[0].public_key_hex)
        assert is_valid is True, f"Chain verification failed: {reason}"
    engine.dispose()


@pytest.mark.postgres
def test_postgres_cross_process_audit_concurrency():
    """Live PostgreSQL 16 cross-process concurrency serialization test.

    Spawns two real OS worker processes appending concurrently to the audit ledger
    on PostgreSQL 16, verifying gapless sequence monotonicity and cryptographic integrity.
    Requires CYBERQ_TEST_PG_URL. Skips loudly when unset.
    """
    pg_url = os.environ.get("CYBERQ_TEST_PG_URL")
    if not pg_url:
        pytest.skip("CYBERQ_TEST_PG_URL not set; skipping live PostgreSQL concurrency test")

    engine = create_engine(pg_url)
    Base.metadata.create_all(bind=engine)
    install_audit_immutability_triggers(engine)
    engine.dispose()

    events_per_worker = 15
    p1 = multiprocessing.Process(target=_worker_append_task, args=(pg_url, "pg_worker_1", events_per_worker))
    p2 = multiprocessing.Process(target=_worker_append_task, args=(pg_url, "pg_worker_2", events_per_worker))

    p1.start()
    p2.start()
    p1.join(timeout=30)
    p2.join(timeout=30)

    assert p1.exitcode == 0, f"Worker 1 failed with exit code {p1.exitcode}"
    assert p2.exitcode == 0, f"Worker 2 failed with exit code {p2.exitcode}"

    engine = create_engine(pg_url)
    Session = sessionmaker(bind=engine)
    with Session() as s:
        events = s.execute(select(AuditEvent).order_by(AuditEvent.sequence_number)).scalars().all()
        assert len(events) == events_per_worker * 2
        seqs = [e.sequence_number for e in events]
        assert seqs == list(range(1, (events_per_worker * 2) + 1))
        events_dicts = [{**e.to_canonical_dict(), "hash": e.hash} for e in events]
        svc = AuditService(TEST_SEED)
        is_valid, reason = AuditService.verify_chain(events_dicts, [], svc.public_key_hex)
        assert is_valid is True, f"PostgreSQL chain verification failed: {reason}"
    engine.dispose()
