"""SQLAlchemy 2 typed models for security incidents and trigger assertions."""

import uuid
from datetime import UTC, datetime
from enum import StrEnum

from sqlalchemy import (
    Boolean,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from cyberq.clocks.models import ObligationInstance
from cyberq.core.database import Base, UTCDateTime


class StatutoryTriggerType(StrEnum):
    """Statutory incident trigger types asserted to bind regulatory clocks."""

    NOTICED = "noticed"  # CERT-In 6h clock (noticed or notified)
    DETECTED = "detected"  # RBI DAKSH 6h clock (detected by technical controls or SOC)
    AWARE = "aware"  # DPDP 72h clock (becoming aware of personal data breach)


def utc_now() -> datetime:
    return datetime.now(UTC)


class Incident(Base):
    """Core security incident entity."""

    __tablename__ = "incident"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    incident_number: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    title: Mapped[str] = mapped_column(String(255))
    summary: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(16))  # low, medium, high, critical
    status: Mapped[str] = mapped_column(
        String(32), default="new", index=True
    )  # new, triaged, confirmed, false_positive, contained, closed
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utc_now, onupdate=utc_now)
    created_by_id: Mapped[str] = mapped_column(String(36), ForeignKey("app_user.id"), index=True)
    is_major: Mapped[bool] = mapped_column(Boolean, default=False)
    major_declared_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    major_declared_by_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("app_user.id"), nullable=True)
    major_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    closed_by_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("app_user.id"), nullable=True)
    closed_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    closure_notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    triggers: Mapped[list["IncidentTrigger"]] = relationship(
        back_populates="incident", cascade="all, delete-orphan", order_by="IncidentTrigger.occurred_at"
    )
    obligations: Mapped[list[ObligationInstance]] = relationship(
        back_populates="incident", cascade="all, delete-orphan"
    )


class IncidentTrigger(Base):
    """Immutable trigger assertions binding statutory regulatory clocks."""

    __tablename__ = "incident_trigger"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    incident_id: Mapped[str] = mapped_column(String(36), ForeignKey("incident.id"), index=True)
    trigger_type: Mapped[str] = mapped_column(String(32))  # noticed, detected, aware
    occurred_at: Mapped[datetime] = mapped_column(UTCDateTime)
    recorded_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utc_now)
    asserted_by_id: Mapped[str] = mapped_column(String(36), ForeignKey("app_user.id"))
    evidence_summary: Mapped[str] = mapped_column(Text)
    rationale: Mapped[str] = mapped_column(Text)
    is_disputed: Mapped[bool] = mapped_column(Boolean, default=False)
    dispute_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    disputed_by_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("app_user.id"), nullable=True)
    disputed_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    counter_occurred_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)

    incident: Mapped["Incident"] = relationship(back_populates="triggers")


class IncidentSequence(Base):
    """Annual counter table for race-safe sequential incident numbers."""

    __tablename__ = "incident_sequence"

    year: Mapped[int] = mapped_column(Integer, primary_key=True)
    current_val: Mapped[int] = mapped_column(Integer, default=0)

