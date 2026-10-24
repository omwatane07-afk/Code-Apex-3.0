"""SQLAlchemy 2 typed models for the tamper-evident audit chain and checkpoints."""

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    Integer,
    String,
)
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import JSON

from cyberq.core.database import Base


def utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


class AuditEvent(Base):
    """Append-only audit event representing every state change or critical security action."""

    __tablename__ = "audit_event"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    sequence_number: Mapped[int] = mapped_column(Integer, unique=True, index=True)
    timestamp: Mapped[str] = mapped_column(String(36), default=utc_now_iso)
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)

    # Sharding / Multi-stream fields (Hyperscale Tier-1)
    stream_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True, default=None)
    stream_sequence_number: Mapped[int | None] = mapped_column(Integer, nullable=True, default=None)
    stream_prev_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, default=None)

    # Actor information
    actor_id: Mapped[str] = mapped_column(String(64))
    actor_role: Mapped[str] = mapped_column(String(32))
    client_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    request_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Action and target
    action: Mapped[str] = mapped_column(String(64))
    entity_type: Mapped[str] = mapped_column(String(64))
    entity_id: Mapped[str] = mapped_column(String(64))

    # State capture (redacted of PII/secrets)
    before_state: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    after_state: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)

    def to_canonical_dict(self) -> dict[str, Any]:
        """Returns the dictionary payload used for hashing (excluding the hash itself)."""
        d: dict[str, Any] = {
            "id": self.id,
            "sequence_number": self.sequence_number,
            "timestamp": str(self.timestamp),
            "prev_hash": self.prev_hash,
            "actor_id": self.actor_id,
            "actor_role": self.actor_role,
            "client_ip": self.client_ip,
            "request_id": self.request_id,
            "action": self.action,
            "entity_type": self.entity_type,
            "entity_id": self.entity_id,
            "before_state": self.before_state,
            "after_state": self.after_state,
        }
        if self.stream_id is not None:
            d["stream_id"] = self.stream_id
        if self.stream_sequence_number is not None:
            d["stream_sequence_number"] = self.stream_sequence_number
        if self.stream_prev_hash is not None:
            d["stream_prev_hash"] = self.stream_prev_hash
        return d


class AuditCheckpoint(Base):
    """Cryptographically signed periodic checkpoint covering a segment of the audit chain."""

    __tablename__ = "audit_checkpoint"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    sequence_number: Mapped[int] = mapped_column(Integer, unique=True, index=True)
    timestamp: Mapped[str] = mapped_column(String(36), default=utc_now_iso)
    from_sequence: Mapped[int] = mapped_column(Integer)
    to_sequence: Mapped[int] = mapped_column(Integer)
    from_event_id: Mapped[str] = mapped_column(String(36))
    to_event_id: Mapped[str] = mapped_column(String(36))
    root_hash: Mapped[str] = mapped_column(String(64))
    signature: Mapped[str] = mapped_column(String(256))
    signer_public_key: Mapped[str] = mapped_column(String(130))

    # Hyperscale Merkle & Algorithm fields
    merkle_root: Mapped[str | None] = mapped_column(String(64), nullable=True, default=None)
    algorithm: Mapped[str] = mapped_column(String(32), default="Ed25519")

    def to_canonical_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "id": self.id,
            "sequence_number": self.sequence_number,
            "timestamp": str(self.timestamp),
            "from_sequence": self.from_sequence,
            "to_sequence": self.to_sequence,
            "from_event_id": self.from_event_id,
            "to_event_id": self.to_event_id,
            "root_hash": self.root_hash,
            "signer_public_key": self.signer_public_key,
        }
        if self.merkle_root is not None:
            d["merkle_root"] = self.merkle_root
        if self.algorithm != "Ed25519":
            d["algorithm"] = self.algorithm
        return d
