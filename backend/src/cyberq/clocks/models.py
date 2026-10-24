"""SQLAlchemy 2 typed models for regulatory obligation instances, escalations, outbox, and worker heartbeat."""

import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    Boolean,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from cyberq.core.database import Base, UTCDateTime

if TYPE_CHECKING:
    from cyberq.incidents.models import Incident


def utc_now() -> datetime:
    return datetime.now(UTC)


class ObligationInstance(Base):
    """Active instance of a regulatory deadline obligation attached to an incident."""

    __tablename__ = "obligation_instance"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    incident_id: Mapped[str] = mapped_column(String(36), ForeignKey("incident.id"), index=True)
    pack_id: Mapped[str] = mapped_column(String(64), index=True)
    regulator: Mapped[str] = mapped_column(String(32), index=True)
    status: Mapped[str] = mapped_column(
        String(32), default="pending_trigger", index=True
    )  # pending_trigger, running, due_soon, critical, breached, filed, not_applicable, disputed
    deadline_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    disputed_deadline_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    active_deadline_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    next_due_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True, index=True)
    escalation_level: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    locked_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    filed_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    filed_by_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    acknowledgement_id: Mapped[str | None] = mapped_column(String(128), nullable=True)

    # Applicability assessment state
    applicability_status: Mapped[str] = mapped_column(
        String(32), default="assumed_applicable", index=True
    )  # assumed_applicable, applicable, pending_approval, not_applicable
    applicability_assessed_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    applicability_assessed_by_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    applicability_rationale: Mapped[str | None] = mapped_column(Text, nullable=True)
    applicability_answers: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    applicability_pending_rationale: Mapped[str | None] = mapped_column(Text, nullable=True)

    incident: Mapped["Incident"] = relationship(back_populates="obligations")
    escalations: Mapped[list["Escalation"]] = relationship(
        back_populates="obligation_instance", cascade="all, delete-orphan"
    )


class Escalation(Base):
    """Records each threshold rung reached by an obligation."""

    __tablename__ = "escalation"
    __table_args__ = (
        UniqueConstraint("obligation_instance_id", "rung", name="uq_obligation_rung"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    obligation_instance_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("obligation_instance.id"), index=True
    )
    rung: Mapped[str] = mapped_column(String(32))
    triggered_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utc_now)
    is_late: Mapped[bool] = mapped_column(Boolean, default=False)

    obligation_instance: Mapped["ObligationInstance"] = relationship(back_populates="escalations")
    outbox_items: Mapped[list["NotificationOutbox"]] = relationship(
        back_populates="escalation", cascade="all, delete-orphan"
    )


class NotificationOutbox(Base):
    """Postgres-backed transactional outbox for audit-tied escalation notifications."""

    __tablename__ = "notification_outbox"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    escalation_id: Mapped[str] = mapped_column(String(36), ForeignKey("escalation.id"), index=True)
    recipient_role: Mapped[str] = mapped_column(String(32))
    channel: Mapped[str] = mapped_column(String(32), default="in_app")
    status: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    next_attempt_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utc_now)
    payload: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)

    escalation: Mapped["Escalation"] = relationship(back_populates="outbox_items")


class WorkerHeartbeat(Base):
    """Worker process liveness record inspected by /readyz."""

    __tablename__ = "worker_heartbeat"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    last_heartbeat_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utc_now)
    worker_pid: Mapped[int] = mapped_column(Integer)
    hostname: Mapped[str] = mapped_column(String(128))
