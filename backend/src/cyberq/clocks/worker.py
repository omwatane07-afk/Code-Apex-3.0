"""Background worker engine for statutory regulatory clocks.

Implements:
1. Postgres SELECT ... FOR UPDATE SKIP LOCKED lease claims.
2. Chronological escalation evaluations with late catch-up tracking (is_late=True).
3. Transactional notification outbox insertions.
4. Cryptographic audit chain logging on every escalation in the same DB transaction.
5. Heartbeat recording for /readyz liveness evaluation.
"""

import os
import socket
from datetime import UTC, datetime, timedelta

from sqlalchemy import or_, select, text
from sqlalchemy.orm import Session

from cyberq.audit.chain import AuditService
from cyberq.clocks.engine import RUNG_OFFSETS
from cyberq.clocks.models import (
    Escalation,
    NotificationOutbox,
    ObligationInstance,
    WorkerHeartbeat,
)


def emit_clock_wakeup(session: Session) -> None:
    """Emits reactive sub-5ms NOTIFY to waking background clock workers on Postgres."""
    bind = session.get_bind()
    if bind and bind.dialect.name == "postgresql":
        session.execute(text("NOTIFY cyberq_clock_wakeup"))


def claim_due_obligations(
    session: Session,
    worker_id: str,
    now: datetime | None = None,
    lease_seconds: int = 60,
    limit: int = 10,
) -> list[ObligationInstance]:
    """Claims up to `limit` due obligations using FOR UPDATE SKIP LOCKED on Postgres."""
    if now is None:
        now = datetime.now(UTC)

    bind = session.get_bind()
    is_pg = bind is not None and bind.dialect.name == "postgresql"

    stmt = (
        select(ObligationInstance)
        .where(
            ObligationInstance.status.in_(["running", "due_soon", "critical"]),
            ObligationInstance.next_due_at <= now,
            or_(
                ObligationInstance.locked_until.is_(None),
                ObligationInstance.locked_until < now,
            ),
        )
        .order_by(ObligationInstance.next_due_at.asc())
        .limit(limit)
    )

    if is_pg:
        stmt = stmt.with_for_update(skip_locked=True)

    obligations = list(session.execute(stmt).scalars().all())
    locked_until = now + timedelta(seconds=lease_seconds)

    for obl in obligations:
        obl.locked_until = locked_until
        obl.locked_by = worker_id

    session.flush()
    return obligations


def _as_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def process_obligation_escalations(
    session: Session,
    audit: AuditService,
    obligation: ObligationInstance,
    worker_id: str,
    now: datetime | None = None,
) -> list[Escalation]:
    """Processes overdue escalation rungs chronologically and generates outbox notifications."""
    if now is None:
        now = datetime.now(UTC)
    else:
        now = _as_utc(now)

    if not obligation.active_deadline_at:
        return []

    active_deadline = _as_utc(obligation.active_deadline_at)

    # Get already triggered rungs for this obligation
    fired_rungs_query = select(Escalation.rung).where(
        Escalation.obligation_instance_id == obligation.id
    )
    fired_rungs = set(session.execute(fired_rungs_query).scalars().all())

    new_escalations: list[Escalation] = []

    # Evaluate each rung in order
    for rung, offset in RUNG_OFFSETS:
        scheduled_at = active_deadline - offset
        if now >= scheduled_at and rung.value not in fired_rungs:
            # Rung is overdue or just reached
            is_late = (now - scheduled_at) > timedelta(minutes=5)
            escalation = Escalation(
                obligation_instance_id=obligation.id,
                rung=rung.value,
                triggered_at=now,
                is_late=is_late,
            )
            session.add(escalation)
            session.flush()

            # Insert into notification outbox
            outbox_item = NotificationOutbox(
                escalation_id=escalation.id,
                recipient_role="compliance_approver",
                channel="in_app",
                status="pending",
                created_at=now,
                payload={
                    "obligation_id": obligation.id,
                    "regulator": obligation.regulator,
                    "rung": rung.value,
                    "is_late": is_late,
                    "deadline_at": obligation.active_deadline_at.isoformat(),
                },
            )
            session.add(outbox_item)
            session.flush()

            # Audit event in same transaction
            audit.record_event(
                session=session,
                actor_id=f"worker:{worker_id}",
                actor_role="system_worker",
                action="escalation:fire",
                entity_type="escalation",
                entity_id=escalation.id,
                after_state={
                    "obligation_id": obligation.id,
                    "rung": rung.value,
                    "is_late": is_late,
                },
            )

            fired_rungs.add(rung.value)
            new_escalations.append(escalation)

    # Calculate next upcoming rung
    next_due: datetime | None = None
    for rung, offset in RUNG_OFFSETS:
        scheduled_at = active_deadline - offset
        if rung.value not in fired_rungs and scheduled_at > now:
            if next_due is None or scheduled_at < next_due:
                next_due = scheduled_at

    obligation.next_due_at = next_due

    # Update active status
    if now >= active_deadline:
        obligation.status = "breached"
    elif active_deadline - now <= timedelta(hours=1):
        obligation.status = "critical"
    elif active_deadline - now <= timedelta(hours=2):
        obligation.status = "due_soon"
    else:
        obligation.status = "running"

    # Release lease
    obligation.locked_until = None
    obligation.locked_by = None
    session.flush()

    return new_escalations


def record_worker_heartbeat(
    session: Session,
    worker_id: str = "default_worker",
    pid: int | None = None,
    hostname: str | None = None,
) -> WorkerHeartbeat:
    """Record heartbeat for worker process."""
    now = datetime.now(UTC)
    pid = pid or os.getpid()
    hostname = hostname or socket.gethostname()

    hb = session.get(WorkerHeartbeat, worker_id)
    if hb:
        hb.last_heartbeat_at = now
        hb.worker_pid = pid
        hb.hostname = hostname
    else:
        hb = WorkerHeartbeat(
            id=worker_id,
            last_heartbeat_at=now,
            worker_pid=pid,
            hostname=hostname,
        )
        session.add(hb)

    session.flush()
    return hb


def get_worker_health(
    session: Session,
    max_staleness_seconds: float = 30.0,
) -> tuple[bool, str]:
    """Inspects worker heartbeat freshness."""
    stmt = select(WorkerHeartbeat).order_by(WorkerHeartbeat.last_heartbeat_at.desc()).limit(1)
    hb = session.execute(stmt).scalar_one_or_none()

    if not hb:
        return False, "no_heartbeat_recorded"

    now = datetime.now(UTC)
    hb_time = _as_utc(hb.last_heartbeat_at)
    delta_seconds = (now - hb_time).total_seconds()
    if delta_seconds > max_staleness_seconds:
        return False, f"stale_heartbeat_{delta_seconds:.1f}s"

    return True, "healthy"
