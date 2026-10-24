"""SQLAlchemy 2 typed models for versioned statutory filing packets."""

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import JSON

from cyberq.core.database import Base, UTCDateTime


def utc_now() -> datetime:
    return datetime.now(UTC)


class FilingPacket(Base):
    """Versioned, immutable filing packet for CERT-In, RBI DAKSH, and DPDP."""

    __tablename__ = "filing_packet"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    incident_id: Mapped[str] = mapped_column(String(36), ForeignKey("incident.id"), index=True)
    pack_id: Mapped[str] = mapped_column(String(64), index=True)
    regulator: Mapped[str] = mapped_column(String(32))  # CERT-In, RBI, DPDP
    version: Mapped[int] = mapped_column(Integer, default=1)
    status: Mapped[str] = mapped_column(
        String(32), default="draft", index=True
    )  # draft, approved, filed, portal_outage_fallback

    # Ordered statutory fields and canonical hash
    packet_data: Mapped[dict[str, Any]] = mapped_column(JSON)
    packet_hash: Mapped[str] = mapped_column(String(64))  # SHA-256 JCS canonical hash

    # Maker (Preparation)
    prepared_by_id: Mapped[str] = mapped_column(String(36), ForeignKey("app_user.id"))
    prepared_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utc_now)

    # Checker (Approval)
    approved_by_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("app_user.id"), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    approval_signature: Mapped[str | None] = mapped_column(String(256), nullable=True)

    # 3 AM Break-Glass Protocol
    is_break_glass: Mapped[bool] = mapped_column(Boolean, default=False)
    break_glass_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    break_glass_countersigned_by_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("app_user.id"), nullable=True
    )
    break_glass_countersigned_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    break_glass_countersignature_required_by: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)

    # Filing Record (Human submission acknowledgment)
    filed_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    filed_by_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("app_user.id"), nullable=True)
    acknowledgement_ref: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Portal Outage Fallback
    portal_outage_sealed: Mapped[bool] = mapped_column(Boolean, default=False)
    portal_outage_notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utc_now, onupdate=utc_now)
