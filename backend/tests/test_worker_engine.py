"""Tests for Worker Engine, SKIP LOCKED leases, catch-up escalations, and outbox."""

import os
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from cyberq.audit.chain import AuditService
from cyberq.clocks.models import Escalation, NotificationOutbox, ObligationInstance
from cyberq.clocks.worker import (
    claim_due_obligations,
    get_worker_health,
    process_obligation_escalations,
    record_worker_heartbeat,
)
from cyberq.core.database import Base
from cyberq.incidents.service import assert_trigger, create_incident


def test_worker_catch_up_missed_rungs_flagged_late(isolated_db):
    """If worker was down, on startup it fires missed rungs chronologically and flags is_late=True."""
    audit = AuditService("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")

    with isolated_db() as db:
        # Create incident
        inc = create_incident(
            session=db,
            audit=audit,
            title="Downtime Test Incident",
            summary="Testing worker catch up behavior after service restart",
            severity="critical",
            actor_id="analyst-1",
            actor_role="analyst",
        )
        db.commit()

        # Assert trigger 5 hours in the past
        now = datetime.now(UTC)
        past_5h = now - timedelta(hours=5)

        assert_trigger(
            session=db,
            audit=audit,
            incident_id=inc.id,
            trigger_type="noticed",  # 6 hour CERT-In deadline
            occurred_at=past_5h,
            evidence_summary="Log forensic proof",
            rationale="Noticed during audit review",
            actor_id="analyst-1",
            actor_role="analyst",
        )
        db.commit()

        # Find the certin obligation
        obl = db.scalar(
            select(ObligationInstance).where(
                ObligationInstance.incident_id == inc.id,
                ObligationInstance.pack_id == "certin-directions-2022",
            )
        )
        assert obl is not None
        # Deadline was at past_5h + 6h = now + 1h
        # Rungs past: t-4h (occurred at past_3h), t-2h (occurred at past_1h)
        # Next upcoming: t-1h (at now)

        # Worker claims and processes
        escalations = process_obligation_escalations(
            session=db,
            audit=audit,
            obligation=obl,
            worker_id="worker-test-1",
            now=now,
        )
        db.commit()

        # Check that missed rungs (t-4h, t-2h) are flagged late
        by_rung = {e.rung: e for e in escalations}
        assert by_rung["t_minus_4h"].is_late is True
        assert by_rung["t_minus_2h"].is_late is True
        if "t_minus_1h" in by_rung:
            assert by_rung["t_minus_1h"].is_late is False

        # Check outbox notifications created
        outbox_items = db.execute(select(NotificationOutbox)).scalars().all()
        assert len(outbox_items) >= 2
        for item in outbox_items:
            assert item.status == "pending"
            assert item.recipient_role == "compliance_approver"


def test_notification_outbox_idempotency(isolated_db):
    """Unique constraint (obligation_instance_id, rung) prevents duplicate escalation rows."""
    with isolated_db() as db:
        # Manually create obligation
        obl = ObligationInstance(
            incident_id="fake-inc-id",
            pack_id="certin-directions-2022",
            regulator="CERT-In",
            status="running",
        )
        db.add(obl)
        db.flush()

        # Add first escalation
        e1 = Escalation(
            obligation_instance_id=obl.id,
            rung="t_minus_2h",
            triggered_at=datetime.now(UTC),
        )
        db.add(e1)
        db.commit()

        # Attempt to insert identical rung for same obligation
        from sqlalchemy.exc import IntegrityError

        db.add(
            Escalation(
                obligation_instance_id=obl.id,
                rung="t_minus_2h",
                triggered_at=datetime.now(UTC),
            )
        )
        with pytest.raises(IntegrityError):
            db.commit()


def test_worker_heartbeat_and_freshness(isolated_db):
    """Worker records heartbeat and freshness is properly evaluated."""
    with isolated_db() as db:
        # Initially no heartbeat
        ok, msg = get_worker_health(db)
        assert ok is False
        assert msg == "no_heartbeat_recorded"

        # Record heartbeat
        hb = record_worker_heartbeat(db, worker_id="worker-node-1", pid=12345, hostname="bank-srv-01")
        db.commit()

        ok, msg = get_worker_health(db, max_staleness_seconds=30.0)
        assert ok is True
        assert msg == "healthy"

        # Simulate staleness
        hb.last_heartbeat_at = datetime.now(UTC) - timedelta(seconds=45)
        db.commit()

        ok, msg = get_worker_health(db, max_staleness_seconds=30.0)
        assert ok is False
        assert "stale_heartbeat" in msg


@pytest.mark.postgres
def test_postgres_skip_locked_concurrent_worker_leases():
    """Verify SKIP LOCKED concurrency behavior on live PostgreSQL 16."""
    pg_url = os.environ.get("CYBERQ_TEST_PG_URL")
    if not pg_url:
        pytest.skip("CYBERQ_TEST_PG_URL unset")

    engine = create_engine(pg_url)
    Base.metadata.create_all(bind=engine)
    SessionClass = sessionmaker(bind=engine)

    with SessionClass() as s1, SessionClass() as s2:
        now = datetime.now(UTC)
        # Create an obligation due now
        obl = ObligationInstance(
            incident_id="pg-test-inc",
            pack_id="certin-directions-2022",
            regulator="CERT-In",
            status="running",
            next_due_at=now - timedelta(minutes=1),
        )
        s1.add(obl)
        s1.commit()

        # Worker 1 claims it
        claimed_w1 = claim_due_obligations(s1, worker_id="worker-1", now=now)
        assert len(claimed_w1) == 1
        assert claimed_w1[0].locked_by == "worker-1"

        # Worker 2 simultaneously queries: SKIP LOCKED should return 0 items
        claimed_w2 = claim_due_obligations(s2, worker_id="worker-2", now=now)
        assert len(claimed_w2) == 0

        # Clean up
        s1.rollback()
        s2.rollback()
