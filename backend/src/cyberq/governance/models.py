"""SQLAlchemy 2 typed models for risk decisions, Para 59 exceptions, and board governance."""

import uuid
from datetime import UTC, datetime

from sqlalchemy import (
    ForeignKey,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from cyberq.core.database import Base, UTCDateTime


def utc_now() -> datetime:
    return datetime.now(UTC)


class RiskDecision(Base):
    """Statutory risk decision ledger entry subject to dual-control maker-checker."""

    __tablename__ = "risk_decision"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    decision_number: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    incident_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("incident.id"), nullable=True, index=True
    )
    decision_type: Mapped[str] = mapped_column(String(64))  # ACCEPT, MITIGATE, TRANSFER, AVOID, etc.
    status: Mapped[str] = mapped_column(
        String(32), default="draft", index=True
    )  # draft, awaiting_countersignature, active, expired, revoked
    rationale: Mapped[str] = mapped_column(Text)
    compensating_controls: Mapped[str] = mapped_column(Text)
    owner: Mapped[str] = mapped_column(String(128))
    expiry_date: Mapped[datetime] = mapped_column(UTCDateTime)
    created_by_id: Mapped[str] = mapped_column(String(36), ForeignKey("app_user.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utc_now)
    countersigned_by_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("app_user.id"), nullable=True
    )
    countersigned_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    countersign_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utc_now, onupdate=utc_now)

    incident: Mapped["Incident | None"] = relationship()  # type: ignore[name-defined] # noqa: F821


class Para59Exception(Base):
    """RBI Master Directions Para 59 Exceptions Register.
    
    Tracks cybersecurity policy and technical control exceptions, compensating
    controls, expiry dates, and mandatory quarterly review cycles.
    """

    __tablename__ = "para59_exception"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    exception_number: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    asset_or_system: Mapped[str] = mapped_column(String(256), index=True)
    control_reference: Mapped[str] = mapped_column(String(256), index=True)
    rationale: Mapped[str] = mapped_column(Text)
    compensating_controls: Mapped[str] = mapped_column(Text)
    owner: Mapped[str] = mapped_column(String(128))
    risk_level: Mapped[str] = mapped_column(String(32), default="high")  # low, medium, high, critical
    status: Mapped[str] = mapped_column(
        String(32), default="active", index=True
    )  # active, expiring_soon, expired, remediated, revoked
    issue_date: Mapped[datetime] = mapped_column(UTCDateTime, default=utc_now)
    expiry_date: Mapped[datetime] = mapped_column(UTCDateTime, index=True)
    last_reviewed_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    reviewed_by_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("app_user.id"), nullable=True
    )
    review_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by_id: Mapped[str] = mapped_column(String(36), ForeignKey("app_user.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utc_now, onupdate=utc_now)

    def days_remaining(self, now: datetime | None = None) -> int:
        cur = now or datetime.now(UTC)
        if self.expiry_date.tzinfo is None:
            exp = self.expiry_date.replace(tzinfo=UTC)
        else:
            exp = self.expiry_date
        return (exp - cur).days

    def computed_status(self, now: datetime | None = None) -> str:
        if self.status in ("remediated", "revoked"):
            return self.status
        days = self.days_remaining(now)
        if days < 0:
            return "expired"
        elif days <= 15:
            return "expiring_soon"
        return "active"
