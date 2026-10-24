"""SQLAlchemy 2 and Pydantic models for the High-Throughput Intake and Dead-Letter Queue."""

import uuid
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict
from sqlalchemy import (
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import JSON

from cyberq.core.database import Base, UTCDateTime


def utc_now() -> datetime:
    return datetime.now(UTC)


class IntakeDeadLetter(Base):
    """Write-Ahead Dead-Letter Queue for malformed, tampered, or schema-drifted security events.

    In banking environments, telemetry is never dropped into the void. Malformed inputs
    are scrubbed of PII and persisted here for audit investigation and Scenario E alerts.
    """

    __tablename__ = "intake_dead_letter"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    received_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utc_now, index=True)
    source_tool: Mapped[str] = mapped_column(String(64), index=True)
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    headers: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    raw_payload_redacted: Mapped[str] = mapped_column(Text)
    error_reason: Mapped[str] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(32), default="unresolved")  # unresolved, replayed, dismissed


class ToolCompliancePassport(Base):
    """Third-Party Tool Compliance Passport (RBI Cybersecurity Directions Paras 90, 92, 126-135).

    Tracks the STQC / CERT-In empanelled auditor VAPT certificate status, PAdES signature hash,
    and CycloneDX SBOM digest. Expired tools transition to DEGRADED trust.
    """

    __tablename__ = "tool_compliance_passport"

    tool_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tool_name: Mapped[str] = mapped_column(String(128))
    vendor: Mapped[str] = mapped_column(String(64))
    category: Mapped[str] = mapped_column(String(64))  # SIEM, EDR, Firewall, DAM, IAM, WAF
    stqc_certificate_ref: Mapped[str] = mapped_column(String(64))
    auditor_name: Mapped[str] = mapped_column(String(128))
    vapt_valid_from: Mapped[datetime] = mapped_column(UTCDateTime)
    vapt_valid_until: Mapped[datetime] = mapped_column(UTCDateTime, index=True)
    pades_signature_hash: Mapped[str] = mapped_column(String(64))
    cyclonedx_sbom_digest: Mapped[str] = mapped_column(String(64))
    trust_status: Mapped[str] = mapped_column(String(32), default="VALID")  # VALID, DEGRADED, EXPIRED
    para59_exception_ref: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utc_now, onupdate=utc_now)


class NormalizedSecurityEvent(BaseModel):
    """Canonical internal event schema for all 20+ ingested security tools."""

    model_config = ConfigDict(frozen=True)

    event_id: str
    source_tool: str
    vendor: str
    category: str
    timestamp: datetime
    source_ip: str | None = None
    destination_ip: str | None = None
    source_hostname: str | None = None
    destination_hostname: str | None = None
    cve_ids: list[str] = []
    signature_id: str
    event_name: str
    severity: str  # low, medium, high, critical
    raw_message: str
    certin_advisories: list[str] = []
    is_telemetry_unverified: bool = False
    attributes: dict[str, Any] = {}
